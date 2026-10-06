#include "greatest.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "firc/app.h"
#include "firc/dnspipeline.h"
#include "firc/dnsproxy.h"
#include "firc/events.h"
#include "firc/listen.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/system.h"

/* One port per test binary, never reused: 18086 is test_auth.c's. */
#define TEST_PORT 18087

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    firc_config_t cfg;
    firc_dnsproxy_t *proxy;
    firc_dns_pipeline_t *pipeline;
    firc_app_t *app;
    firc_system_ctx_t ctx;
    char dir[64];
    char conf[128];
    char groups[128];
    pthread_t thread;
} harness_t;

static void *loop_thread(void *ud) {
    harness_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

static firc_dns_verdict_t pass_hook(firc_dns_msg_t *msg, const firc_ip_t *client,
                                    const char *network, firc_dns_resolver_t resolver, void *ud) {
    (void)msg;
    (void)client;
    (void)network;
    (void)resolver;
    (void)ud;
    return FIRC_DNS_PASS;
}

/* A harness whose DNS proxy listens on `dns_addr`:`dns_port` (NULL keeps [::]:3553) and whose WebUI asks for `web_port` first. */
static harness_t *harness_start_full(const char *dns_addr, uint16_t dns_port, const char *web_addr,
                                     uint16_t web_port, bool conf_writable) {
    harness_t *h = calloc(1, sizeof(*h));
    if (h == NULL) { return NULL; }
    firc_log_set_level(FIRC_LOG_INFO);
    firc_config_init_defaults(&h->cfg);
    snprintf(h->dir, sizeof(h->dir), "/tmp/firc_settings_api_XXXXXX");
    if (mkdtemp(h->dir) == NULL) { return NULL; }
    snprintf(h->conf, sizeof(h->conf), "%s/firc.conf", h->dir);
    snprintf(h->groups, sizeof(h->groups), "%s/groups.yaml", h->dir);
    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    firc_dnsproxy_config_t pcfg = {.listen_addr = "127.0.0.1", .listen_port = 1,
                                   .upstream_addr = "127.0.0.1", .upstream_port = 53,
                                   .timeout_ms = 1000, .max_concurrent = 4, .max_idle_conns = 2};
    if (firc_dnsproxy_create(&pcfg, h->loop, pass_hook, NULL, &h->proxy) != FIRC_OK) { return NULL; }
    if (firc_strset(&h->cfg.app.http_web.host.address, web_addr) != FIRC_OK) { return NULL; }
    if (strcmp(web_addr, "127.0.0.1") != 0 && firc_strset(&h->cfg.app.link[0], "lo") != FIRC_OK) { return NULL; }
    h->cfg.app.http_web.host.port = web_port;
    if (dns_addr != NULL) {
        if (firc_strset(&h->cfg.app.dns_proxy.host.address, dns_addr) != FIRC_OK) { return NULL; }
        h->cfg.app.dns_proxy.host.port = dns_port;
    }
    h->pipeline = firc_dns_pipeline_create();
    if (h->pipeline == NULL) { return NULL; }
    firc_app_deps_t deps = {.cfg = &h->cfg, .proxy = h->proxy, .pipeline = h->pipeline};
    h->app = firc_app_create(&deps);
    if (h->app == NULL) { return NULL; }
    h->ctx.app = h->app;
    h->ctx.config_path = conf_writable ? h->conf : "/nonexistent/firc.conf";
    h->ctx.config_version = "0.7.0";
    if (firc_httpd_create(h->loop, &h->tcp) != FIRC_OK) { return NULL; }
    firc_system_register_routes(h->tcp, &h->ctx);
    const uint16_t ports[] = {web_port, TEST_PORT};
    size_t n_ports = web_port == TEST_PORT ? 1 : 2;
    if (firc_system_listen_web(&h->ctx, h->tcp, ports, n_ports) != FIRC_OK) { return NULL; }
    pthread_create(&h->thread, NULL, loop_thread, h);
    return h;
}

static harness_t *harness_start_dns(const char *dns_addr, uint16_t dns_port) {
    return harness_start_full(dns_addr, dns_port, "127.0.0.1", TEST_PORT, true);
}

static harness_t *harness_start(void) { return harness_start_dns(NULL, 0); }

static void harness_stop(harness_t *h) {
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->tcp);
    firc_app_destroy(h->app);
    firc_dns_pipeline_destroy(h->pipeline);
    firc_dnsproxy_destroy(h->proxy);
    firc_loop_destroy(h->loop);
    firc_config_clear(&h->cfg);
    unlink(h->conf);
    unlink(h->groups);
    rmdir(h->dir);
    firc_log_set_level(FIRC_LOG_INFO);
    free(h);
}

static int connect_tcp(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { return fd; }
        struct timespec ts = {0, 10000000};
        nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

static ssize_t recv_response(int fd, char *buf, size_t cap) {
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t total = 0;
    char *body_start = NULL;
    long content_length = -1;
    for (;;) {
        if (total >= cap - 1) { break; }
        ssize_t n = recv(fd, buf + total, cap - 1 - total, 0);
        if (n <= 0) { break; }
        total += (size_t)n;
        buf[total] = '\0';
        if (!body_start) {
            char *marker = strstr(buf, "\r\n\r\n");
            if (marker) {
                body_start = marker + 4;
                char *cl = strstr(buf, "Content-Length:");
                if (cl && cl < marker) { content_length = strtol(cl + 15, NULL, 10); }
            }
        }
        if (body_start && content_length >= 0) {
            size_t body_have = (size_t)(buf + total - body_start);
            if ((long)body_have >= content_length) { break; }
        }
    }
    return (ssize_t)total;
}

static int do_request(const char *method, const char *path, const char *body, cJSON **out_json) {
    int fd = connect_tcp(TEST_PORT);
    if (fd < 0) { return -1; }
    char req[8192];
    size_t body_len = body ? strlen(body) : 0;
    snprintf(req, sizeof(req),
             "%s %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             method, path, body_len, body ? body : "");
    if (send(fd, req, strlen(req), 0) <= 0) {
        close(fd);
        return -1;
    }
    char resp[32768];
    ssize_t got = recv_response(fd, resp, sizeof(resp));
    close(fd);
    if (got <= 0) { return -1; }
    int status = 0;
    sscanf(resp, "HTTP/1.1 %d", &status);
    if (out_json) {
        const char *marker = strstr(resp, "\r\n\r\n");
        *out_json = marker && marker[4] ? cJSON_Parse(marker + 4) : NULL;
    }
    return status;
}

static const cJSON *item(const cJSON *obj, const char *key) {
    return cJSON_GetObjectItemCaseSensitive(obj, key);
}

static bool strings_are(const cJSON *arr, const char *const *want, size_t n) {
    if (!cJSON_IsArray(arr) || (size_t)cJSON_GetArraySize(arr) != n) { return false; }
    for (size_t i = 0; i < n; i++) {
        const cJSON *e = cJSON_GetArrayItem(arr, (int)i);
        if (!cJSON_IsString(e) || strcmp(e->valuestring, want[i]) != 0) { return false; }
    }
    return true;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    char *buf = calloc(1, 65536);
    size_t n = buf != NULL ? fread(buf, 1, 65535, f) : 0;
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static const char *const NONE[] = {NULL};

TEST get_carries_the_boot_of_this_run(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    const cJSON *boot = item(out, "boot");
    ASSERT(cJSON_IsString(boot));
    ASSERT(boot->valuestring[0] != '\0');
    ASSERT_STR_EQ(firc_event_boot(), boot->valuestring);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a setting answered in the wrong unit, as decimal instead of hex, or a number as a string. */
TEST get_answers_every_setting_typed(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT(out != NULL);
    const cJSON *s = item(out, "settings"), *c = item(out, "classes");
    ASSERT_EQ(26, cJSON_GetArraySize(s));
    ASSERT_EQ(NULL, item(s, "app.httpWeb.enabled"));
    ASSERT_EQ(5000, (int)item(s, "app.dnsProxy.timeout")->valuedouble);
    ASSERT_EQ(300, (int)item(s, "app.addressPool.ttlClamp")->valuedouble);
    ASSERT_EQ(24, (int)item(s, "app.addressPool.idleWindow")->valuedouble);
    ASSERT_EQ(60, (int)item(s, "app.dnsProxy.unmatchedTtl")->valuedouble);
    ASSERT_STR_EQ("0x66697263", item(s, "app.netfilter.startMarkTableIndex")->valuestring);
    ASSERT(cJSON_IsNumber(item(s, "app.dnsProxy.upstream.port")));
    ASSERT_EQ(53, (int)item(s, "app.dnsProxy.upstream.port")->valuedouble);
    ASSERT_STR_EQ("127.0.0.1", item(s, "app.dnsProxy.upstream.address")->valuestring);
    ASSERT_EQ(NULL, item(s, "app.dnsProxy.disableFakePTR"));
    ASSERT_EQ(NULL, item(c, "app.dnsProxy.disableFakePTR"));
    ASSERT_STR_EQ("", item(s, "app.addressPool.v6.pool")->valuestring);
    static const char *const br0[] = {"br0"};
    ASSERT(strings_are(item(s, "app.link"), br0, 1));
    ASSERT_STR_EQ("live", item(c, "app.logLevel")->valuestring);
    ASSERT_STR_EQ("live", item(c, "app.dnsProxy.upstream.address")->valuestring);
    ASSERT_STR_EQ("live", item(c, "app.dnsProxy.unmatchedTtl")->valuestring);
    ASSERT_STR_EQ("restart", item(c, "app.link")->valuestring);
    ASSERT_STR_EQ("restart", item(c, "app.dnsProxy.timeout")->valuestring);
    int live = 0;
    const cJSON *e;
    cJSON_ArrayForEach(e, c) { live += strcmp(e->valuestring, "live") == 0; }
    ASSERT_EQ(6, live);
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a valid key applied before the bad one in the same PUT is reached. */
TEST a_put_with_one_bad_key_writes_nothing(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static const char before[] = "configVersion: 0.7.0\n# written by hand\n";
    FILE *f = fopen(h->conf, "w");
    ASSERT(f != NULL);
    fputs(before, f);
    fclose(f);

    cJSON *out = NULL;
    ASSERT_EQ(400, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.logLevel\":\"debug\","
                              "\"app.dnsProxy.upstream.port\":70000}}",
                              &out));
    ASSERT(out != NULL);
    ASSERT_STR_EQ("app.dnsProxy.upstream.port", item(out, "field")->valuestring);
    ASSERT(item(out, "error")->valuestring[0] != '\0');
    cJSON_Delete(out);

    char *text = slurp(h->conf);
    ASSERT(text != NULL);
    ASSERT_STR_EQ(before, text);
    free(text);
    ASSERT_EQ(FIRC_LOG_INFO, firc_log_level());
    ASSERT_STR_EQ("info", firc_app_saved_settings(h->app)->log_level);
    harness_stop(h);
    PASS();
}

/* Checks a PUT of `body` is a 400 naming `field`; called through CHECK_CALL. */
static enum greatest_test_res expect_refusal(const char *body, const char *field) {
    cJSON *out = NULL;
    int status = do_request("PUT", "/api/v1/system/settings", body, &out);
    const cJSON *f = out != NULL ? item(out, "field") : NULL;
    bool ok = status == 400 && cJSON_IsString(f) && strcmp(f->valuestring, field) == 0;
    cJSON_Delete(out);
    if (!ok) { fprintf(stderr, "expected 400 on %s for %s, got %d\n", field, body, status); }
    ASSERTm(field, ok);
    PASS();
}

/* Catches: an unknown key ignored, or the key table searched by prefix. */
TEST an_unknown_key_is_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.httpWeb.enabled\":false}}", "app.httpWeb.enabled"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.nope\":1}}", "app.nope"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.dnsProxy.disableFakePTR\":true}}", "app.dnsProxy.disableFakePTR"));
    harness_stop(h);
    PASS();
}

/* Catches: the PUT validating by rules of its own instead of the loader's. */
TEST the_put_refuses_what_the_loader_refuses(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.addressPool.v4.chunk\":12}}", "app.addressPool.v4.chunk"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.logLevel\":\"loud\"}}", "app.logLevel"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.netfilter.iptables.chainPrefix\":\"\"}}",
                   "app.netfilter.iptables.chainPrefix"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.dnsProxy.upstream.address\":\"dns.example\"}}",
                   "app.dnsProxy.upstream.address"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.httpWeb.host.port\":3553}}", "app.httpWeb.host.port"));
    harness_stop(h);
    PASS();
}

/* Catches: null read as 0, a string coerced, hex without 0x read as decimal, or a fraction cut. */
TEST a_wrongly_typed_value_names_its_field(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.dnsProxy.timeout\":null}}", "app.dnsProxy.timeout"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.dnsProxy.upstream.port\":\"53\"}}",
                   "app.dnsProxy.upstream.port"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.netfilter.startMarkTableIndex\":\"66697263\"}}",
                   "app.netfilter.startMarkTableIndex"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.link\":\"br0\"}}", "app.link"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.dnsProxy.maxIdleConns\":1.5}}", "app.dnsProxy.maxIdleConns"));
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.dnsProxy.disableDropAAAA\":1}}", "app.dnsProxy.disableDropAAAA"));
    ASSERT(access(h->conf, F_OK) != 0);
    harness_stop(h);
    PASS();
}

/* Catches: a body that is not {"settings": {...}} taken as an empty change. */
TEST a_body_without_settings_is_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(400, do_request("PUT", "/api/v1/system/settings", "{\"logLevel\":\"debug\"}", &out));
    ASSERT(out != NULL && item(out, "field") == NULL);
    cJSON_Delete(out);
    ASSERT_EQ(400, do_request("PUT", "/api/v1/system/settings", "not json", NULL));
    harness_stop(h);
    PASS();
}

/* Catches: a live key not applied, a restart key applied, or groups.yaml written. */
TEST a_live_put_changes_the_upstream_and_the_log_level(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.dnsProxy.upstream.address\":\"9.9.9.9\","
                              "\"app.logLevel\":\"debug\",\"app.addressPool.maxNames\":4096}}",
                              &out));
    static const char *const applied[] = {"app.dnsProxy.upstream.address", "app.logLevel"};
    static const char *const pending[] = {"app.addressPool.maxNames"};
    ASSERT(strings_are(item(out, "applied"), applied, 2));
    ASSERT(strings_are(item(out, "pendingRestart"), pending, 1));
    cJSON_Delete(out);

    uint16_t port = 0;
    ASSERT_STR_EQ("9.9.9.9", firc_dnsproxy_upstream(h->proxy, &port));
    ASSERT_EQ(53, port);
    ASSERT_EQ(FIRC_LOG_DEBUG, firc_log_level());
    ASSERT_EQ(65536u, firc_app_running_settings(h->app)->fakeip.max_names);
    char *text = slurp(h->conf);
    ASSERT(text != NULL);
    ASSERT(strstr(text, "maxNames: 4096\n") != NULL);
    ASSERT(strstr(text, "logLevel: debug\n") != NULL);
    free(text);
    ASSERT(access(h->groups, F_OK) != 0);

    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT_EQ(4096, (int)item(item(out, "settings"), "app.addressPool.maxNames")->valuedouble);
    ASSERT(strings_are(item(out, "pendingRestart"), pending, 1));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* "example.com" answered with one A record at `ttl`, which no group owns. */
static firc_dns_msg_t *unmatched_response(uint32_t ttl) {
    uint8_t b[128] = {0};
    b[1] = 0x42;
    b[2] = 0x81; b[3] = 0x80;
    b[5] = 1;
    b[7] = 1;
    size_t p = 12;
    static const char *const labels[] = {"example", "com"};
    for (size_t i = 0; i < 2; i++) {
        size_t l = strlen(labels[i]);
        b[p++] = (uint8_t)l;
        memcpy(b + p, labels[i], l);
        p += l;
    }
    b[p++] = 0;
    b[p++] = 0x00; b[p++] = FIRC_DNS_TYPE_A;
    b[p++] = 0x00; b[p++] = 0x01;
    b[p++] = 0xc0; b[p++] = 0x0c;
    b[p++] = 0x00; b[p++] = FIRC_DNS_TYPE_A;
    b[p++] = 0x00; b[p++] = 0x01;
    b[p++] = (uint8_t)(ttl >> 24); b[p++] = (uint8_t)(ttl >> 16);
    b[p++] = (uint8_t)(ttl >> 8); b[p++] = (uint8_t)ttl;
    b[p++] = 0x00; b[p++] = 0x04;
    b[p++] = 93; b[p++] = 184; b[p++] = 216; b[p++] = 34;
    firc_dns_msg_t *m = NULL;
    return firc_dns_msg_parse(b, p, &m) == FIRC_OK ? m : NULL;
}

/* Catches: unmatchedTtl marked restart, or reported applied without reaching the pipeline. */
TEST a_live_put_applies_unmatched_ttl(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.dnsProxy.unmatchedTtl\":90}}", &out));
    static const char *const applied[] = {"app.dnsProxy.unmatchedTtl"};
    ASSERT(strings_are(item(out, "applied"), applied, 1));
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);
    ASSERT_EQ_FMT((long long)(90 * FIRC_DURATION_SEC),
                  (long long)firc_app_running_settings(h->app)->dns_proxy.unmatched_ttl, "%lld");
    char *text = slurp(h->conf);
    ASSERT(text != NULL);
    ASSERT(strstr(text, "unmatchedTtl: 1m30s\n") != NULL);
    free(text);

    firc_dns_msg_t *msg = unmatched_response(3600);
    ASSERT(msg != NULL);
    ASSERT_EQ_FMTm("the PUT's value reached the pipeline, not just the running config",
                   (int)FIRC_DNS_RETIMED,
                   (int)firc_dns_pipeline_handle_message(h->pipeline, msg, 1000, NULL, NULL), "%d");
    ASSERT_EQ_FMT(90u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    harness_stop(h);
    PASS();
}

/* Catches: pendingRestart listing only this save's keys, or a PUT resetting keys it did not name. */
TEST pending_restart_is_the_whole_list_after_each_save(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.addressPool.maxNames\":4096}}", NULL));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.logLevel\":\"warn\"}}", &out));
    static const char *const applied[] = {"app.logLevel"};
    static const char *const pending[] = {"app.addressPool.maxNames"};
    ASSERT(strings_are(item(out, "applied"), applied, 1));
    ASSERT(strings_are(item(out, "pendingRestart"), pending, 1));
    cJSON_Delete(out);
    ASSERT_EQ(4096u, firc_app_saved_settings(h->app)->fakeip.max_names);
    harness_stop(h);
    PASS();
}

/* Catches: a value equal to the saved one reported applied or written. */
TEST a_value_equal_to_the_saved_one_is_not_a_change(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.logLevel\":\"info\"}}", &out));
    ASSERT(strings_are(item(out, "applied"), NONE, 0));
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);
    ASSERT(access(h->conf, F_OK) != 0);
    harness_stop(h);
    PASS();
}

/* Holds a socket of `type` on 127.0.0.1 at a kernel-picked port (listening for a stream); -1 on failure. */
static int bind_loopback(int type, uint16_t port, uint16_t *bound) {
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) { return -1; }
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    socklen_t len = sizeof(sa);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        (type == SOCK_STREAM && listen(fd, 1) != 0) ||
        getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        close(fd);
        return -1;
    }
    *bound = ntohs(sa.sin_port);
    return fd;
}

static int hold(int type, uint16_t *port) {
    int other = type == SOCK_STREAM ? SOCK_DGRAM : SOCK_STREAM;
    for (int attempt = 0; attempt < 64; attempt++) {
        int fd = bind_loopback(type, 0, port);
        if (fd < 0) { return -1; }
        uint16_t same = 0;
        int probe = bind_loopback(other, *port, &same);
        if (probe >= 0) {
            close(probe);
            return fd;
        }
        close(fd);
    }
    return -1;
}

static const char BEFORE[] = "configVersion: 0.7.0\n# written by hand\n";

static bool conf_is_untouched(const harness_t *h) {
    char *text = slurp(h->conf);
    bool same = text != NULL && strcmp(text, BEFORE) == 0;
    free(text);
    return same;
}

static void write_before(const harness_t *h) {
    FILE *f = fopen(h->conf, "w");
    if (f != NULL) {
        fputs(BEFORE, f);
        fclose(f);
    }
}

/* Catches: a WebUI port another program holds saved, so the restart cannot bind it. */
TEST a_web_port_another_program_holds_is_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    write_before(h);
    uint16_t port = 0;
    int held = hold(SOCK_STREAM, &port);
    ASSERT(held >= 0);
    char body[160];
    snprintf(body, sizeof(body), "{\"settings\":{\"app.httpWeb.host.port\":%u}}", port);

    cJSON *out = NULL;
    ASSERT_EQ(400, do_request("PUT", "/api/v1/system/settings", body, &out));
    ASSERT(out != NULL);
    ASSERT_STR_EQ("app.httpWeb.host.port", item(out, "field")->valuestring);
    char want[64];
    snprintf(want, sizeof(want), "%u is already in use on this router", port);
    ASSERT_STR_EQ(want, item(out, "error")->valuestring);
    cJSON_Delete(out);
    ASSERT(conf_is_untouched(h));
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);

    close(held);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings", body, &out));
    static const char *const pending[] = {"app.httpWeb.host.port"};
    ASSERT(strings_are(item(out, "pendingRestart"), pending, 1));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: the DNS port not probed, or probed over TCP only. */
TEST a_dns_port_held_over_udp_is_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    write_before(h);
    uint16_t port = 0;
    int held = hold(SOCK_DGRAM, &port);
    ASSERT(held >= 0);
    char body[160];
    snprintf(body, sizeof(body),
             "{\"settings\":{\"app.dnsProxy.host.address\":\"127.0.0.1\",\"app.dnsProxy.host.port\":%u}}",
             port);
    CHECK_CALL(expect_refusal(body, "app.dnsProxy.host.port"));
    ASSERT(conf_is_untouched(h));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);

    close(held);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings", body, &out));
    static const char *const pending[] = {"app.dnsProxy.host.address", "app.dnsProxy.host.port"};
    ASSERT(strings_are(item(out, "pendingRestart"), pending, 2));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: EADDRNOTAVAIL blamed on the port, or the address not probed. */
TEST an_address_not_on_the_router_names_the_address(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.httpWeb.host.address\":\"192.0.2.1\"}}",
                              "app.httpWeb.host.address"));
    ASSERT(access(h->conf, F_OK) != 0);
    harness_stop(h);
    PASS();
}

/* Catches: an address the kernel refuses (EINVAL) blamed on the port. */
TEST an_address_the_kernel_cannot_bind_names_the_address(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.httpWeb.host.address\":\"fe80::1\"}}",
                              "app.httpWeb.host.address"));
    ASSERT(access(h->conf, F_OK) != 0);
    harness_stop(h);
    PASS();
}

/* Catches: the WebUI's own running port compared against the saved copy and refused. */
TEST the_running_web_socket_is_not_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    uint16_t other = 0;
    int held = hold(SOCK_STREAM, &other);
    ASSERT(held >= 0);
    close(held);
    char body[160];
    snprintf(body, sizeof(body), "{\"settings\":{\"app.httpWeb.host.port\":%u}}", other);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings", body, NULL));

    cJSON *out = NULL;
    snprintf(body, sizeof(body), "{\"settings\":{\"app.httpWeb.host.port\":%u}}", TEST_PORT);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings", body, &out));
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: the proxy's own running port refused as busy. */
TEST the_running_dns_socket_is_not_refused(void) {
    uint16_t port = 0;
    int held = hold(SOCK_STREAM, &port);
    ASSERT(held >= 0);
    harness_t *h = harness_start_dns("127.0.0.1", port);
    ASSERT(h != NULL);
    uint16_t other = 0;
    int spare = hold(SOCK_STREAM, &other);
    ASSERT(spare >= 0);
    close(spare);
    char body[160];
    snprintf(body, sizeof(body), "{\"settings\":{\"app.dnsProxy.host.port\":%u}}", other);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings", body, NULL));

    cJSON *out = NULL;
    snprintf(body, sizeof(body), "{\"settings\":{\"app.dnsProxy.host.port\":%u}}", port);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings", body, &out));
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);
    harness_stop(h);
    close(held);
    PASS();
}

/* Catches: the WebUI's own-port allowance applied to the DNS proxy. */
TEST a_dns_move_on_its_own_port_that_another_program_holds_is_refused(void) {
    uint16_t port = 0;
    int held = hold(SOCK_STREAM, &port);
    ASSERT(held >= 0);
    harness_t *h = harness_start_dns("127.0.0.2", port);
    ASSERT(h != NULL);
    write_before(h);
    CHECK_CALL(expect_refusal("{\"settings\":{\"app.dnsProxy.host.address\":\"0.0.0.0\"}}",
                              "app.dnsProxy.host.port"));
    ASSERT(conf_is_untouched(h));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);
    harness_stop(h);
    close(held);
    PASS();
}

/* Catches: a new address on the WebUI's own port refused as busy. */
TEST a_move_on_the_running_web_port_is_not_refused_as_busy(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.httpWeb.host.address\":\"0.0.0.0\"}}", &out));
    static const char *const pending[] = {"app.httpWeb.host.address"};
    ASSERT(strings_are(item(out, "pendingRestart"), pending, 1));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a unit converted wrongly on the way in, or hex parsed as decimal. */
TEST durations_and_the_mark_index_round_trip_in_their_units(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.dnsProxy.timeout\":2500,"
                              "\"app.addressPool.ttlClamp\":90,\"app.addressPool.idleWindow\":36,"
                              "\"app.netfilter.startMarkTableIndex\":\"0x3E8\"}}",
                              NULL));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    const cJSON *s = item(out, "settings");
    ASSERT_EQ(2500, (int)item(s, "app.dnsProxy.timeout")->valuedouble);
    ASSERT_EQ(90, (int)item(s, "app.addressPool.ttlClamp")->valuedouble);
    ASSERT_EQ(36, (int)item(s, "app.addressPool.idleWindow")->valuedouble);
    ASSERT_STR_EQ("0x3e8", item(s, "app.netfilter.startMarkTableIndex")->valuestring);
    cJSON_Delete(out);
    char *text = slurp(h->conf);
    ASSERT(text != NULL);
    ASSERT(strstr(text, "timeout: 2.5s\n") != NULL);
    ASSERT(strstr(text, "ttlClamp: 1m30s\n") != NULL);
    ASSERT(strstr(text, "idleWindow: 36h0m0s\n") != NULL);
    ASSERT(strstr(text, "startMarkTableIndex: 1000\n") != NULL);
    free(text);
    harness_stop(h);
    PASS();
}

TEST numeric_settings_round_trip_whole_through_the_api_and_the_file(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/system/settings",
                              "{\"settings\":{\"app.addressPool.maxNames\":16909060,"
                              "\"app.dnsProxy.maxConcurrent\":16909061,"
                              "\"app.dnsProxy.maxIdleConns\":16909062,"
                              "\"app.dnsProxy.upstream.port\":258,"
                              "\"app.addressPool.v4.chunk\":26,"
                              "\"app.netfilter.startMarkTableIndex\":\"0x1020304\"}}",
                              NULL));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    const cJSON *s = item(out, "settings");
    ASSERT_EQ(16909060.0, item(s, "app.addressPool.maxNames")->valuedouble);
    ASSERT_EQ(16909061.0, item(s, "app.dnsProxy.maxConcurrent")->valuedouble);
    ASSERT_EQ(16909062.0, item(s, "app.dnsProxy.maxIdleConns")->valuedouble);
    ASSERT_EQ(258.0, item(s, "app.dnsProxy.upstream.port")->valuedouble);
    ASSERT_EQ(26.0, item(s, "app.addressPool.v4.chunk")->valuedouble);
    ASSERT_STR_EQ("0x1020304", item(s, "app.netfilter.startMarkTableIndex")->valuestring);
    cJSON_Delete(out);
    char *text = slurp(h->conf);
    ASSERT(text != NULL);
    ASSERT(strstr(text, "maxNames: 16909060\n") != NULL);
    ASSERT(strstr(text, "maxConcurrent: 16909061\n") != NULL);
    ASSERT(strstr(text, "maxIdleConns: 16909062\n") != NULL);
    ASSERT(strstr(text, "port: 258\n") != NULL);
    ASSERT(strstr(text, "chunk: 26\n") != NULL);
    ASSERT(strstr(text, "startMarkTableIndex: 16909060\n") != NULL);
    free(text);
    harness_stop(h);
    PASS();
}

/* Installs `body` as a stand-in for S99firc, the script the restart route runs. */
static void stand_in(harness_t *h, char *script, size_t cap, const char *body) {
    snprintf(script, cap, "%s/S99stand-in", h->dir);
    FILE *f = fopen(script, "w");
    if (f != NULL) {
        fputs(body, f);
        fclose(f);
    }
    chmod(script, 0755);
    h->ctx.init_script = script;
}

static const char RECORDER[] =
    "#!/bin/sh\n"
    "d=$(dirname \"$0\")\n"
    "echo \"$1\" > \"$d/restarted.tmp\" && mv \"$d/restarted.tmp\" \"$d/restarted\"\n";

/* Catches: a restart answered without running the script, or with the wrong argument. */
TEST restart_answers_202_then_runs_the_script(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char script[160], marker[160];
    stand_in(h, script, sizeof(script), RECORDER);
    snprintf(marker, sizeof(marker), "%s/restarted", h->dir);
    cJSON *out = NULL;
    ASSERT_EQ(202, do_request("POST", "/api/v1/system/restart", NULL, &out));
    ASSERT(cJSON_IsTrue(item(out, "restarting")));
    cJSON_Delete(out);
    char *text = NULL;
    for (int i = 0; i < 300 && text == NULL; i++) {
        text = slurp(marker);
        if (text == NULL) {
            struct timespec ts = {0, 10 * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
    ASSERT(text != NULL);
    ASSERT_STR_EQ("restart\n", text);
    free(text);
    unlink(marker);
    unlink(script);
    harness_stop(h);
    PASS();
}

/* Catches: a second restart starting a second script while the first is stopping the daemon. */
TEST a_second_restart_is_refused_while_one_is_under_way(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char script[160], marker[160];
    stand_in(h, script, sizeof(script), RECORDER);
    snprintf(marker, sizeof(marker), "%s/restarted", h->dir);
    ASSERT_EQ(202, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    ASSERT_EQ(409, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    for (int i = 0; i < 300 && access(marker, F_OK) != 0; i++) {
        struct timespec ts = {0, 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
    unlink(marker);
    unlink(script);
    harness_stop(h);
    PASS();
}

/* Catches: the in-flight flag left set when the script could not start. */
TEST a_restart_that_could_not_start_can_be_asked_again(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    h->ctx.init_script = "/nonexistent-firc/S99firc";
    ASSERT_EQ(202, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    int status = 409;
    for (int i = 0; i < 200 && status == 409; i++) {
        status = do_request("POST", "/api/v1/system/restart", NULL, NULL);
        if (status == 409) {
            struct timespec ts = {0, 10 * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
    ASSERT_EQ(202, status);
    harness_stop(h);
    PASS();
}

/* Catches: a restart whose script never stopped the daemon answering 409 for ever. */
TEST a_restart_that_did_not_stop_the_daemon_lapses(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char script[160];
    stand_in(h, script, sizeof(script), "#!/bin/sh\nexit 0\n");
    h->ctx.restart_timeout_ms = 300;
    ASSERT_EQ(202, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    ASSERT_EQm("inside the timeout", 409, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    struct timespec ts = {0, 400 * 1000000L};
    nanosleep(&ts, NULL);
    ASSERT_EQm("past it", 202, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    harness_stop(h);
    unlink(script);
    PASS();
}

TEST get_says_no_restart_is_under_way_at_rest(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT(cJSON_IsFalse(item(out, "restarting")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST get_says_a_restart_is_under_way_after_the_post(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char script[160];
    stand_in(h, script, sizeof(script), "#!/bin/sh\nexit 0\n");
    h->ctx.restart_timeout_ms = 60000;
    ASSERT_EQ(202, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT(cJSON_IsTrue(item(out, "restarting")));
    cJSON_Delete(out);
    harness_stop(h);
    unlink(script);
    PASS();
}

TEST get_drops_restart_pending_when_the_script_cannot_start(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    h->ctx.init_script = "/nonexistent-firc/S99firc";
    ASSERT_EQ(202, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    bool pending = true;
    for (int i = 0; i < 200 && pending; i++) {
        cJSON *out = NULL;
        ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
        pending = cJSON_IsTrue(item(out, "restarting"));
        cJSON_Delete(out);
        if (pending) {
            struct timespec ts = {0, 10 * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
    ASSERT(!pending);
    harness_stop(h);
    PASS();
}

TEST get_drops_restart_pending_when_the_timeout_lapses(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char script[160];
    stand_in(h, script, sizeof(script), "#!/bin/sh\nexit 0\n");
    h->ctx.restart_timeout_ms = 200;
    ASSERT_EQ(202, do_request("POST", "/api/v1/system/restart", NULL, NULL));
    struct timespec ts = {0, 400 * 1000000L};
    nanosleep(&ts, NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT(cJSON_IsFalse(item(out, "restarting")));
    cJSON_Delete(out);
    harness_stop(h);
    unlink(script);
    PASS();
}


/* Catches: a candidate list that drops the configured port, keeps the DNS proxy's, or loses the order. */
TEST web_ports_start_with_the_configured_one_and_skip_the_dns_port(void) {
    uint16_t out[FIRC_WEB_PORTS_MAX];
    const uint16_t a[] = {8080, 666, 1666, 2666, 9999};
    ASSERT_EQ(5, firc_web_ports(8080, 999, out));
    ASSERT_MEM_EQ(a, out, sizeof(a));
    const uint16_t b[] = {999, 666, 1666, 2666, 9999};
    ASSERT_EQ(5, firc_web_ports(999, 3553, out));
    ASSERT_MEM_EQ(b, out, sizeof(b));
    const uint16_t c[] = {8443, 666, 999, 1666, 2666, 9999};
    ASSERT_EQ(6, firc_web_ports(8443, 3553, out));
    ASSERT_MEM_EQ(c, out, sizeof(c));
    PASS();
}

static bool has_line(const char *text, const char *line) {
    return text != NULL && strstr(text, line) != NULL;
}

/* Catches: a busy WebUI port left without a WebUI, the new port not saved, or saved but reported pending. */
TEST a_busy_web_port_moves_to_the_next_and_is_saved(void) {
    uint16_t busy = 0;
    int held = hold(SOCK_STREAM, &busy);
    ASSERT(held >= 0);
    harness_t *h = harness_start_full(NULL, 0, "127.0.0.1", busy, true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    const cJSON *web = item(out, "webUi");
    ASSERT_EQ(TEST_PORT, item(web, "port")->valueint);
    ASSERT_EQ(busy, item(web, "movedFrom")->valueint);
    ASSERT_STR_EQ("127.0.0.1", item(web, "lanAddress")->valuestring);
    ASSERT_EQ(TEST_PORT, item(item(out, "settings"), "app.httpWeb.host.port")->valueint);
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);
    char *text = slurp(h->conf);
    ASSERT(has_line(text, "port: 18087\n"));
    free(text);
    harness_stop(h);
    close(held);
    PASS();
}

/* Catches: a free port rewritten into firc.conf, or a move reported where there was none. */
TEST a_free_web_port_stays_and_writes_nothing(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    const cJSON *web = item(out, "webUi");
    ASSERT_EQ(TEST_PORT, item(web, "port")->valueint);
    ASSERT_EQ(0, item(web, "movedFrom")->valueint);
    cJSON_Delete(out);
    ASSERT(access(h->conf, F_OK) != 0);
    harness_stop(h);
    PASS();
}

static enum greatest_test_res any_address_reports_the_lan_interface(const char *addr) {
    harness_t *h = harness_start_full(NULL, 0, addr, TEST_PORT, true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT_STR_EQ("127.0.0.1", item(item(out, "webUi"), "lanAddress")->valuestring);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a WebUI on every address reported as that address instead of the LAN interface's. */
TEST a_web_ui_on_any_address_reports_the_lan_interface(void) {
    CHECK_CALL(any_address_reports_the_lan_interface("[::]"));
    CHECK_CALL(any_address_reports_the_lan_interface("0.0.0.0"));
    CHECK_CALL(any_address_reports_the_lan_interface("[::ffff:0.0.0.0]"));
    PASS();
}

/* Catches: a move whose firc.conf write failed left saved on the busy port, so every later PUT is refused. */
TEST a_move_that_could_not_be_saved_still_counts_as_saved(void) {
    uint16_t busy = 0;
    int held = hold(SOCK_STREAM, &busy);
    ASSERT(held >= 0);
    harness_t *h = harness_start_full(NULL, 0, "127.0.0.1", busy, false);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/settings", NULL, &out));
    ASSERT_EQ(TEST_PORT, item(item(out, "settings"), "app.httpWeb.host.port")->valueint);
    ASSERT(strings_are(item(out, "pendingRestart"), NONE, 0));
    cJSON_Delete(out);
    harness_stop(h);
    close(held);
    PASS();
}

/* Catches: every candidate busy reported as listening, or a port saved that nothing listens on. */
TEST every_web_port_busy_leaves_no_web_ui_and_writes_nothing(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    uint16_t busy = 0;
    int held = hold(SOCK_STREAM, &busy);
    ASSERT(held >= 0);
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_httpd_t *other = NULL;
    ASSERT_EQ(FIRC_OK, firc_httpd_create(loop, &other));
    firc_system_ctx_t ctx = h->ctx;
    const uint16_t ports[] = {busy, TEST_PORT};
    ASSERT(firc_system_listen_web(&ctx, other, ports, 2) != FIRC_OK);
    ASSERT_EQ(0, ctx.web_port);
    ASSERT_EQ(0, ctx.web_moved_from);
    ASSERT(access(h->conf, F_OK) != 0);
    firc_httpd_destroy(other);
    firc_loop_destroy(loop);
    close(held);
    harness_stop(h);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(get_answers_every_setting_typed);
    RUN_TEST(web_ports_start_with_the_configured_one_and_skip_the_dns_port);
    RUN_TEST(a_busy_web_port_moves_to_the_next_and_is_saved);
    RUN_TEST(a_free_web_port_stays_and_writes_nothing);
    RUN_TEST(a_web_ui_on_any_address_reports_the_lan_interface);
    RUN_TEST(a_move_that_could_not_be_saved_still_counts_as_saved);
    RUN_TEST(every_web_port_busy_leaves_no_web_ui_and_writes_nothing);
    RUN_TEST(get_carries_the_boot_of_this_run);
    RUN_TEST(a_put_with_one_bad_key_writes_nothing);
    RUN_TEST(an_unknown_key_is_refused);
    RUN_TEST(the_put_refuses_what_the_loader_refuses);
    RUN_TEST(a_wrongly_typed_value_names_its_field);
    RUN_TEST(a_body_without_settings_is_refused);
    RUN_TEST(a_live_put_changes_the_upstream_and_the_log_level);
    RUN_TEST(a_live_put_applies_unmatched_ttl);
    RUN_TEST(pending_restart_is_the_whole_list_after_each_save);
    RUN_TEST(a_value_equal_to_the_saved_one_is_not_a_change);
    RUN_TEST(a_web_port_another_program_holds_is_refused);
    RUN_TEST(a_dns_port_held_over_udp_is_refused);
    RUN_TEST(an_address_not_on_the_router_names_the_address);
    RUN_TEST(an_address_the_kernel_cannot_bind_names_the_address);
    RUN_TEST(the_running_web_socket_is_not_refused);
    RUN_TEST(the_running_dns_socket_is_not_refused);
    RUN_TEST(a_dns_move_on_its_own_port_that_another_program_holds_is_refused);
    RUN_TEST(a_move_on_the_running_web_port_is_not_refused_as_busy);
    RUN_TEST(durations_and_the_mark_index_round_trip_in_their_units);
    RUN_TEST(numeric_settings_round_trip_whole_through_the_api_and_the_file);
    RUN_TEST(restart_answers_202_then_runs_the_script);
    RUN_TEST(a_second_restart_is_refused_while_one_is_under_way);
    RUN_TEST(a_restart_that_could_not_start_can_be_asked_again);
    RUN_TEST(a_restart_that_did_not_stop_the_daemon_lapses);
    RUN_TEST(get_says_no_restart_is_under_way_at_rest);
    RUN_TEST(get_says_a_restart_is_under_way_after_the_post);
    RUN_TEST(get_drops_restart_pending_when_the_script_cannot_start);
    RUN_TEST(get_drops_restart_pending_when_the_timeout_lapses);
    GREATEST_MAIN_END();
}
