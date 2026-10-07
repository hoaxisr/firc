#include "greatest.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <sys/time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "firc/app.h"
#include "firc/events.h"
#include "firc/keenetic_policy.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/system.h"

static void *g_policies;

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    firc_config_t cfg;
    firc_app_t *app;
    firc_system_ctx_t ctx;
    char config_path[64];
    pthread_t thread;
} harness_t;

static void *loop_thread(void *ud) {
    harness_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

#define TEST_PORT 18082

static harness_t *harness_start(bool with_config_path) {
    harness_t *h = calloc(1, sizeof(*h));
    firc_config_init_defaults(&h->cfg);
    firc_app_deps_t deps = {.cfg = &h->cfg};
    h->app = firc_app_create(&deps);
    h->ctx.app = h->app;
    h->ctx.policies = g_policies;
    if (with_config_path) {
        snprintf(h->config_path, sizeof(h->config_path), "/tmp/firc_system_test_XXXXXX");
        int fd = mkstemp(h->config_path);
        if (fd >= 0) { close(fd); }
        h->ctx.config_path = h->config_path;
        h->ctx.config_version = "0.1";
    }

    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    if (firc_httpd_create(h->loop, &h->tcp) != FIRC_OK) { return NULL; }
    firc_system_register_routes(h->tcp, &h->ctx);
    if (firc_httpd_listen_tcp(h->tcp, "127.0.0.1", TEST_PORT) != FIRC_OK) { return NULL; }

    pthread_create(&h->thread, NULL, loop_thread, h);
    return h;
}

static void harness_stop(harness_t *h) {
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->tcp);
    firc_loop_destroy(h->loop);
    firc_app_destroy(h->app);
    firc_config_clear(&h->cfg);
    if (h->config_path[0]) { unlink(h->config_path); }
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

static int status_code_of(const char *resp) {
    int code = 0;
    sscanf(resp, "HTTP/1.1 %d", &code);
    return code;
}

static const char *body_of(const char *resp) {
    const char *marker = strstr(resp, "\r\n\r\n");
    return marker ? marker + 4 : "";
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
    char resp[16384];
    ssize_t got = recv_response(fd, resp, sizeof(resp));
    close(fd);
    if (got <= 0) { return -1; }
    int status = status_code_of(resp);
    if (out_json) {
        const char *b = body_of(resp);
        *out_json = b[0] ? cJSON_Parse(b) : NULL;
    }
    return status;
}

/* Catches: the events route answering anything but the daemon's journal. */
TEST the_events_route_answers_what_the_daemon_said(void) {
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    firc_event_reset_for_test();
    firc_log_set_level(FIRC_LOG_INFO);
    FIRC_INFO("a line the ui should see");
    FIRC_ERROR("and a \"quoted\" \\ one");

    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/events", NULL, &out));
    cJSON *events = cJSON_GetObjectItemCaseSensitive(out, "events");
    ASSERT(cJSON_IsArray(events));
    ASSERT_EQ_FMT(2, cJSON_GetArraySize(events), "%d");
    cJSON *first = cJSON_GetArrayItem(events, 0);
    ASSERT_STR_EQ("log", cJSON_GetObjectItemCaseSensitive(first, "kind")->valuestring);
    ASSERT_STR_EQ("a line the ui should see",
                  cJSON_GetObjectItemCaseSensitive(first, "message")->valuestring);
    ASSERT_STR_EQ("info", cJSON_GetObjectItemCaseSensitive(first, "level")->valuestring);
    ASSERTm("an event carries its time",
            cJSON_GetObjectItemCaseSensitive(first, "at")->valuedouble > 0);
    cJSON *second = cJSON_GetArrayItem(events, 1);
    ASSERT_STR_EQm("escaping survives the round trip", "and a \"quoted\" \\ one",
                   cJSON_GetObjectItemCaseSensitive(second, "message")->valuestring);
    ASSERT_STR_EQ("error", cJSON_GetObjectItemCaseSensitive(second, "level")->valuestring);
    double next = cJSON_GetObjectItemCaseSensitive(out, "next")->valuedouble;
    ASSERTm("the cursor is the newest event",
            next == cJSON_GetObjectItemCaseSensitive(second, "seq")->valuedouble);
    ASSERT_EQ_FMT(0.0, cJSON_GetObjectItemCaseSensitive(out, "dropped")->valuedouble, "%f");
    ASSERT_STR_EQ("info", cJSON_GetObjectItemCaseSensitive(out, "level")->valuestring);
    cJSON *boot = cJSON_GetObjectItemCaseSensitive(out, "boot");
    ASSERTm("the answer names the run", cJSON_IsString(boot) && boot->valuestring[0] != '\0');
    char boot_was[64];
    snprintf(boot_was, sizeof(boot_was), "%s", boot->valuestring);
    cJSON_Delete(out);

    char path[64];
    snprintf(path, sizeof(path), "/api/v1/system/events?since=%llu", (unsigned long long)next);
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQ_FMT(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "events")), "%d");
    ASSERT_STR_EQm("and the same run on every poll", boot_was,
                   cJSON_GetObjectItemCaseSensitive(out, "boot")->valuestring);
    cJSON_Delete(out);

    ASSERT_EQ(400, do_request("GET", "/api/v1/system/events?since=yesterday", NULL, &out));
    cJSON_Delete(out);
    ASSERT_EQm("the old route is gone", 404, do_request("GET", "/api/v1/system/log", NULL, &out));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: the resolvers route missing, or not answering an object with a list. */
TEST the_resolvers_route_answers_a_list(void) {
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/resolvers", NULL, &out));
    ASSERT(cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(out, "resolvers")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

static const firc_nfcommit_health_t *g_health;

void __real_firc_app_netfilter_health(const firc_app_t *app, firc_nfcommit_health_t *out);
void __wrap_firc_app_netfilter_health(const firc_app_t *app, firc_nfcommit_health_t *out);
void __wrap_firc_app_netfilter_health(const firc_app_t *app, firc_nfcommit_health_t *out) {
    if (g_health != NULL) {
        *out = *g_health;
        return;
    }
    __real_firc_app_netfilter_health(app, out);
}

/* Catches: the route missing, an error on a healthy committer, or a failing one read as ok. */
TEST the_netfilter_route_says_whether_the_committer_is_failing(void) {
    g_health = NULL;
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/netfilter", NULL, &out));
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(out, "ok")));
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "error"));
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "since"));
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "firstWritePending"));
    cJSON_Delete(out);
    harness_stop(h);

    static const firc_nfcommit_health_t failing = {.failing = true, .err = FIRC_ERR_IO, .since = 1790000000};
    g_health = &failing;
    h = harness_start(false);
    ASSERT(h != NULL);
    out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/netfilter", NULL, &out));
    g_health = NULL;
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(out, "ok")));
    cJSON *err = cJSON_GetObjectItemCaseSensitive(out, "error");
    ASSERT(cJSON_IsString(err));
    ASSERT_STR_EQ("i/o error", err->valuestring);
    cJSON *since = cJSON_GetObjectItemCaseSensitive(out, "since");
    ASSERT(cJSON_IsNumber(since));
    ASSERT_EQ_FMT(1790000000.0, since->valuedouble, "%.0f");
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "firstWritePending"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a pending first write read as ok, the flag missing, or an error invented for it. */
TEST the_netfilter_route_says_the_first_write_is_pending(void) {
    static const firc_nfcommit_health_t pending = {.first_pending = true};
    g_health = &pending;
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/netfilter", NULL, &out));
    g_health = NULL;
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(out, "ok")));
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(out, "firstWritePending")));
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "error"));
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "since"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST list_interfaces_includes_blackhole_first(void) {
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    h->cfg.app.show_all_interfaces = true;

    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/interfaces", NULL, &out));
    cJSON *ifaces = cJSON_GetObjectItemCaseSensitive(out, "interfaces");
    ASSERT(cJSON_IsArray(ifaces));
    ASSERT(cJSON_GetArraySize(ifaces) >= 1);
    cJSON *first = cJSON_GetArrayItem(ifaces, 0);
    ASSERT_STR_EQ("blackhole", cJSON_GetObjectItemCaseSensitive(first, "id")->valuestring);
    ASSERT(cJSON_GetObjectItemCaseSensitive(first, "name") == NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST save_config_writes_file(void) {
    harness_t *h = harness_start(true);
    ASSERT(h != NULL);
    ASSERT_EQ(200, do_request("POST", "/api/v1/system/config/save", NULL, NULL));

    firc_config_t reloaded;
    firc_config_init_defaults(&reloaded);
    ASSERT_EQ(FIRC_OK, firc_config_load_file(&reloaded, h->config_path));
    firc_config_clear(&reloaded);
    harness_stop(h);
    PASS();
}

TEST save_config_noop_without_path(void) {
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    ASSERT_EQ(200, do_request("POST", "/api/v1/system/config/save", NULL, NULL));
    harness_stop(h);
    PASS();
}

TEST netfilterd_hook_ok_and_bad_json(void) {
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    ASSERT_EQ(200, do_request("POST", "/api/v1/system/hooks/netfilterd",
                             "{\"type\":\"iptables\",\"table\":\"nat\"}", NULL));
    ASSERT_EQ(400, do_request("POST", "/api/v1/system/hooks/netfilterd", "not json", NULL));
    harness_stop(h);
    PASS();
}

/* Catches: a dns event field missing or misnamed, v6 formatted wrong, or a group without one. */
TEST a_dns_event_is_answered_with_every_field(void) {
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    firc_event_reset_for_test();
    firc_event_t e;
    memset(&e, 0, sizeof(e));
    e.kind = FIRC_EVENT_DNS;
    e.at = 1790000000;
    e.u.dns.client = (firc_ip_t){{192, 168, 1, 42}, 4};
    snprintf(e.u.dns.name, sizeof(e.u.dns.name), "youtube.com");
    e.u.dns.qtype = 28;
    e.u.dns.decision = FIRC_DNS_ISSUED;
    snprintf(e.u.dns.group_id, sizeof(e.u.dns.group_id), "d663876a");
    snprintf(e.u.dns.group_name, sizeof(e.u.dns.group_name), "media");
    e.u.dns.fake = (firc_ip_t){{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 5}, 16};
    e.u.dns.reals[0] = (firc_ip_t){{0x2a, 0, 0x14, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16};
    e.u.dns.n_reals = 1;
    e.u.dns.resolver = FIRC_DNS_RESOLVER_FALLBACK_SINK;
    firc_event_put(&e);
    firc_event_t bare;
    memset(&bare, 0, sizeof(bare));
    bare.kind = FIRC_EVENT_DNS;
    bare.u.dns.client = (firc_ip_t){{192, 168, 1, 42}, 4};
    snprintf(bare.u.dns.name, sizeof(bare.u.dns.name), "ya.ru");
    bare.u.dns.qtype = 1;
    bare.u.dns.rcode = 3;
    bare.u.dns.decision = FIRC_DNS_NO_MATCH;
    firc_event_put(&bare);

    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/events", NULL, &out));
    cJSON *events = cJSON_GetObjectItemCaseSensitive(out, "events");
    ASSERT_EQ_FMT(2, cJSON_GetArraySize(events), "%d");
    cJSON *d = cJSON_GetArrayItem(events, 0);
    ASSERT_STR_EQ("dns", cJSON_GetObjectItemCaseSensitive(d, "kind")->valuestring);
    ASSERT_STR_EQ("192.168.1.42", cJSON_GetObjectItemCaseSensitive(d, "client")->valuestring);
    ASSERT_STR_EQ("youtube.com", cJSON_GetObjectItemCaseSensitive(d, "name")->valuestring);
    ASSERT_STR_EQ("AAAA", cJSON_GetObjectItemCaseSensitive(d, "qtype")->valuestring);
    ASSERT_STR_EQ("NOERROR", cJSON_GetObjectItemCaseSensitive(d, "rcode")->valuestring);
    ASSERT_STR_EQ("issued", cJSON_GetObjectItemCaseSensitive(d, "decision")->valuestring);
    ASSERT_STR_EQ("fallback_sink", cJSON_GetObjectItemCaseSensitive(d, "resolver")->valuestring);
    cJSON *g = cJSON_GetObjectItemCaseSensitive(d, "group");
    ASSERT_STR_EQ("d663876a", cJSON_GetObjectItemCaseSensitive(g, "id")->valuestring);
    ASSERT_STR_EQ("media", cJSON_GetObjectItemCaseSensitive(g, "name")->valuestring);
    ASSERT_STR_EQ("fd00::1:5", cJSON_GetObjectItemCaseSensitive(d, "fake")->valuestring);
    cJSON *reals = cJSON_GetObjectItemCaseSensitive(d, "reals");
    ASSERT_EQ_FMT(1, cJSON_GetArraySize(reals), "%d");
    ASSERT_STR_EQ("2a00:1450::1", cJSON_GetArrayItem(reals, 0)->valuestring);

    cJSON *b = cJSON_GetArrayItem(events, 1);
    ASSERT_STR_EQ("no-match", cJSON_GetObjectItemCaseSensitive(b, "decision")->valuestring);
    ASSERT_STR_EQ("upstream", cJSON_GetObjectItemCaseSensitive(b, "resolver")->valuestring);
    ASSERT_STR_EQ("NXDOMAIN", cJSON_GetObjectItemCaseSensitive(b, "rcode")->valuestring);
    ASSERT_STR_EQ("A", cJSON_GetObjectItemCaseSensitive(b, "qtype")->valuestring);
    ASSERTm("no group object without a group", cJSON_GetObjectItemCaseSensitive(b, "group") == NULL);
    ASSERTm("no fake without one", cJSON_GetObjectItemCaseSensitive(b, "fake") == NULL);
    ASSERT_EQ_FMT(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(b, "reals")), "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST every_resolver_source_has_its_name(void) {
    static const char *want[] = {"upstream",         "group",          "fallback_unreachable", "fallback_timeout",
                                 "fallback_servfail", "fallback_refused", "fallback_sink",       "health_skip"};
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    firc_event_reset_for_test();
    for (unsigned i = 0; i < 9; i++) {
        firc_event_t e;
        memset(&e, 0, sizeof(e));
        e.kind = FIRC_EVENT_DNS;
        e.u.dns.client = (firc_ip_t){{192, 168, 1, 42}, 4};
        snprintf(e.u.dns.name, sizeof(e.u.dns.name), "n%u.test", i);
        e.u.dns.resolver = (uint8_t)(i < 8 ? i : 200);
        firc_event_put(&e);
    }
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/events", NULL, &out));
    cJSON *events = cJSON_GetObjectItemCaseSensitive(out, "events");
    ASSERT_EQ_FMT(9, cJSON_GetArraySize(events), "%d");
    for (int i = 0; i < 9; i++) {
        cJSON *r = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(events, i), "resolver");
        ASSERT(cJSON_IsString(r));
        ASSERT_STR_EQ(i < 8 ? want[i] : "upstream", r->valuestring);
    }
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a bypass field missing or misnamed, a port without a protocol, or `last` wrong. */
TEST a_bypass_event_is_answered_with_every_field(void) {
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    firc_event_reset_for_test();
    firc_event_t e;
    memset(&e, 0, sizeof(e));
    e.kind = FIRC_EVENT_BYPASS;
    e.at = 1790000041;
    e.u.bypass.client = (firc_ip_t){{192, 168, 1, 42}, 4};
    e.u.bypass.dst = (firc_ip_t){{142, 250, 1, 1}, 4};
    e.u.bypass.dst_port = 443;
    e.u.bypass.proto = 17;
    e.u.bypass.how = FIRC_BYPASS_BY_ADDR;
    snprintf(e.u.bypass.name, sizeof(e.u.bypass.name), "youtube.com");
    snprintf(e.u.bypass.group_id, sizeof(e.u.bypass.group_id), "d663876a");
    snprintf(e.u.bypass.group_name, sizeof(e.u.bypass.group_name), "media");
    e.u.bypass.last_decision = FIRC_DNS_ISSUED;
    e.u.bypass.last_at = 1790000003;
    e.u.bypass.last_fake = (firc_ip_t){{198, 18, 0, 5}, 4};
    e.u.bypass.repeats = 0;
    firc_event_put(&e);

    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/events", NULL, &out));
    cJSON *events = cJSON_GetObjectItemCaseSensitive(out, "events");
    ASSERT_EQ_FMT(1, cJSON_GetArraySize(events), "%d");
    cJSON *b = cJSON_GetArrayItem(events, 0);
    ASSERT_STR_EQ("bypass", cJSON_GetObjectItemCaseSensitive(b, "kind")->valuestring);
    ASSERT_EQ_FMT(1790000041.0, cJSON_GetObjectItemCaseSensitive(b, "at")->valuedouble, "%f");
    ASSERT_STR_EQ("192.168.1.42", cJSON_GetObjectItemCaseSensitive(b, "client")->valuestring);
    ASSERT_STR_EQ("142.250.1.1", cJSON_GetObjectItemCaseSensitive(b, "dst")->valuestring);
    ASSERT_EQ_FMT(443, cJSON_GetObjectItemCaseSensitive(b, "port")->valueint, "%d");
    ASSERT_STR_EQ("udp", cJSON_GetObjectItemCaseSensitive(b, "proto")->valuestring);
    ASSERT_STR_EQ("addr", cJSON_GetObjectItemCaseSensitive(b, "how")->valuestring);
    ASSERT_STR_EQ("youtube.com", cJSON_GetObjectItemCaseSensitive(b, "name")->valuestring);
    cJSON *g = cJSON_GetObjectItemCaseSensitive(b, "group");
    ASSERT_STR_EQ("d663876a", cJSON_GetObjectItemCaseSensitive(g, "id")->valuestring);
    ASSERT_STR_EQ("media", cJSON_GetObjectItemCaseSensitive(g, "name")->valuestring);
    cJSON *last = cJSON_GetObjectItemCaseSensitive(b, "last");
    ASSERT(last != NULL);
    ASSERT_STR_EQ("issued", cJSON_GetObjectItemCaseSensitive(last, "decision")->valuestring);
    ASSERT_EQ_FMT(1790000003.0, cJSON_GetObjectItemCaseSensitive(last, "at")->valuedouble, "%f");
    ASSERT_STR_EQ("198.18.0.5", cJSON_GetObjectItemCaseSensitive(last, "fake")->valuestring);
    ASSERT_EQ_FMT(0, cJSON_GetObjectItemCaseSensitive(b, "repeats")->valueint, "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a port printed for a protocol without one, or `last` printed with no recalled answer. */
TEST a_bypass_event_without_a_last_answer_has_no_last(void) {
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    firc_event_reset_for_test();
    firc_event_t e;
    memset(&e, 0, sizeof(e));
    e.kind = FIRC_EVENT_BYPASS;
    e.at = 1790000041;
    e.u.bypass.client = (firc_ip_t){{192, 168, 1, 42}, 4};
    e.u.bypass.dst = (firc_ip_t){{142, 250, 1, 1}, 4};
    e.u.bypass.dst_port = 0;
    e.u.bypass.proto = 17;
    e.u.bypass.how = FIRC_BYPASS_BY_ADDR;
    snprintf(e.u.bypass.name, sizeof(e.u.bypass.name), "youtube.com");
    e.u.bypass.last_decision = FIRC_BYPASS_NOT_ASKED;
    e.u.bypass.repeats = 3;
    firc_event_put(&e);

    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/events", NULL, &out));
    cJSON *b = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(out, "events"), 0);
    ASSERTm("port omitted when the protocol has none",
            cJSON_GetObjectItemCaseSensitive(b, "port") == NULL);
    ASSERTm("no group without one", cJSON_GetObjectItemCaseSensitive(b, "group") == NULL);
    ASSERTm("no last answer without one recalled",
            cJSON_GetObjectItemCaseSensitive(b, "last") == NULL);
    ASSERT_EQ_FMT(3, cJSON_GetObjectItemCaseSensitive(b, "repeats")->valueint, "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* catches: a tunnel device hidden from group pickers unless every interface is shown, or any tunvless-like name let through */
TEST tunnel_devices_are_listed_without_show_all(void) {
    ASSERT(firc_iface_listed_for_test("tunvless0", 0, false));
    ASSERT(firc_iface_listed_for_test("tunvless12", IFF_UP, false));
    ASSERT_FALSE(firc_iface_listed_for_test("tunvless", 0, false));
    ASSERT_FALSE(firc_iface_listed_for_test("tunvlessx", 0, false));
    ASSERT_FALSE(firc_iface_listed_for_test("tunvless1a", 0, false));
    ASSERT_FALSE(firc_iface_listed_for_test("eth0", IFF_UP, false));
    ASSERT(firc_iface_listed_for_test("ppp0", IFF_POINTOPOINT, false));
    ASSERT(firc_iface_listed_for_test("eth0", 0, true));
    PASS();
}

TEST ignored_interfaces_list(void) {
#ifdef FIRC_ENTWARE_KN
    ASSERT(firc_iface_is_ignored_for_test("ra0"));
    ASSERT(firc_iface_is_ignored_for_test("ra15"));
    ASSERT(firc_iface_is_ignored_for_test("ezcfg0"));
    ASSERT(!firc_iface_is_ignored_for_test("br0"));
    ASSERT(!firc_iface_is_ignored_for_test("ra16"));
#else
    ASSERT(!firc_iface_is_ignored_for_test("ra0"));
    ASSERT(!firc_iface_is_ignored_for_test("ezcfg0"));
    ASSERT(!firc_iface_is_ignored_for_test("br0"));
#endif
    PASS();
}

/* Catches: the hosts route missing, its body wrong, or not answered from the daemon's resolver. */
TEST the_hosts_route_answers_the_refreshers_table(void) {
    g_policies = NULL;
    harness_t *h = harness_start(false);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/hosts", NULL, &out));
    const cJSON *hosts = cJSON_GetObjectItemCaseSensitive(out, "hosts");
    ASSERTm("no resolver (off Keenetic): a list", cJSON_IsArray(hosts));
    ASSERT_EQ_FMT(0, cJSON_GetArraySize(hosts), "%d");
    cJSON_Delete(out);
    harness_stop(h);

    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    g_policies = p;
    h = harness_start(false);
    ASSERT(h != NULL);
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/hosts", NULL, &out));
    ASSERT_EQ_FMTm("before the first read: empty", 0,
                   cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "hosts")), "%d");
    cJSON_Delete(out);

    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[{\"mac\":\"AA:BB:CC:DD:EE:01\",\"name\":\"TV\","
                                                "\"hostname\":\"tv\",\"ip\":\"192.168.1.5\",\"ip6\":[\"fd00::5\"],"
                                                "\"policy\":\"Policy0\",\"active\":true,\"registered\":true}]}",
                                                NULL, &m));
    firc_kn_policies_swap(p, m);
    ASSERT_EQ(200, do_request("GET", "/api/v1/system/hosts", NULL, &out));
    hosts = cJSON_GetObjectItemCaseSensitive(out, "hosts");
    ASSERT_EQ_FMT(1, cJSON_GetArraySize(hosts), "%d");
    const cJSON *tv = cJSON_GetArrayItem(hosts, 0);
    ASSERT_STR_EQ("aa:bb:cc:dd:ee:01", cJSON_GetObjectItemCaseSensitive(tv, "mac")->valuestring);
    ASSERT_STR_EQ("TV", cJSON_GetObjectItemCaseSensitive(tv, "name")->valuestring);
    ASSERT_STR_EQ("192.168.1.5", cJSON_GetObjectItemCaseSensitive(tv, "ip")->valuestring);
    ASSERT_STR_EQ("fd00::5", cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(tv, "ip6"), 0)->valuestring);
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(tv, "active")));
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(tv, "registered")));
    ASSERT_STR_EQ("Policy0", cJSON_GetObjectItemCaseSensitive(tv, "policy")->valuestring);
    cJSON_Delete(out);
    harness_stop(h);
    firc_kn_policies_stop(p);
    g_policies = NULL;
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_events_route_answers_what_the_daemon_said);
    RUN_TEST(the_resolvers_route_answers_a_list);
    RUN_TEST(list_interfaces_includes_blackhole_first);
    RUN_TEST(save_config_writes_file);
    RUN_TEST(save_config_noop_without_path);
    RUN_TEST(netfilterd_hook_ok_and_bad_json);
    RUN_TEST(a_dns_event_is_answered_with_every_field);
    RUN_TEST(every_resolver_source_has_its_name);
    RUN_TEST(a_bypass_event_is_answered_with_every_field);
    RUN_TEST(a_bypass_event_without_a_last_answer_has_no_last);
    RUN_TEST(ignored_interfaces_list);
    RUN_TEST(tunnel_devices_are_listed_without_show_all);
    RUN_TEST(the_hosts_route_answers_the_refreshers_table);
    RUN_TEST(the_netfilter_route_says_whether_the_committer_is_failing);
    RUN_TEST(the_netfilter_route_says_the_first_write_is_pending);
    GREATEST_MAIN_END();
}
