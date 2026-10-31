#include "greatest.h"
#include "fake_conntrack.h"
#include "fake_iptables.h"
#include "fake_rtnl.h"
#include "firc/netfilter_cleaner.h"
#include "firc/ruleset.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "firc/app.h"
#include "firc/conntrack.h"
#include "firc/dnspipeline.h"
#include "firc/dnsproxy.h"
#include "firc/events.h"
#include "firc/mark.h"
#include "firc/fakeip.h"
#include "firc/groups.h"
#include "firc/loop.h"
#include "firc/resolveroute.h"
#include "firc/rtnl.h"

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    firc_config_t cfg;
    firc_dns_pipeline_t *pipeline;
    firc_fakeip_t *pool;
    firc_app_t *app;
    firc_groups_ctx_t ctx;
    firc_resolve_router_t *router;
    firc_dnsproxy_t *proxy;
    pthread_t thread;
    firc_fake_ipt_t *fipt;
    firc_ipt_t *ipt;
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    fake_ct_t *ctk;
    firc_ct_t *ct;
} harness_t;

static void *loop_thread(void *ud) {
    harness_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

#define TEST_PORT 18081

static harness_t *live_harness;

#define TEST_WALL_S 1792485000

static int64_t fixed_wall_s(void) { return TEST_WALL_S; }

static firc_dns_verdict_t pass_hook(firc_dns_msg_t *msg, const firc_ip_t *client, const char *network,
                                    firc_dns_resolver_t resolver, void *ud) {
    (void)msg;
    (void)client;
    (void)network;
    (void)resolver;
    (void)ud;
    return FIRC_DNS_PASS;
}

static harness_t *harness_start_with_kernels(bool kernels);
static harness_t *harness_start(void) { return harness_start_with_kernels(false); }

static harness_t *harness_start_with_kernels(bool kernels) {
    harness_t *h = calloc(1, sizeof(*h));
    firc_config_init_defaults(&h->cfg);
    h->pipeline = firc_dns_pipeline_create();
    firc_fakeip_cfg_t pc = {0};
    pc.v4.base.len = 4; pc.v4.base.b[0] = 198; pc.v4.base.b[1] = 18; pc.v4.pool_cidr = 15; pc.v4.chunk_cidr = 24;
    pc.v6.base.len = 16; pc.v6.base.b[0] = 0xfd; pc.v6.base.b[1] = 0x37; pc.v6.pool_cidr = 48; pc.v6.chunk_cidr = 64;
    pc.max_names = 64; pc.idle_secs = 86400; pc.clamp_secs = 300;
    if (firc_fakeip_new(&pc, &h->pool) != FIRC_OK) { abort(); }
    firc_dns_pipeline_set_pool(h->pipeline, h->pool, 300);
    h->router = firc_resolve_router_new(h->pipeline);
    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    firc_dnsproxy_config_t pcfg = {.listen_addr = "127.0.0.1", .listen_port = 1,
                                   .upstream_addr = "127.0.0.1", .upstream_port = 53,
                                   .timeout_ms = 1000, .max_concurrent = 4, .max_idle_conns = 2};
    if (firc_dnsproxy_create(&pcfg, h->loop, pass_hook, NULL, &h->proxy) != FIRC_OK) { return NULL; }
    firc_app_deps_t deps = {.cfg = &h->cfg, .pipeline = h->pipeline, .pool = h->pool, .router = h->router,
                            .proxy = h->proxy, .wall_s = fixed_wall_s};
    if (kernels) {
        h->fipt = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
        h->ipt = firc_ipt_new(firc_fake_ipt_as_xt(h->fipt), "FIRC_");
        firc_netfilter_register_base_chains(h->ipt, NULL);
        h->kernel = fake_rtnl_start(&h->rtnl);
        if (h->kernel == NULL) { return NULL; }
        fake_rtnl_set_link_flags(h->kernel, 0x1 | 0x10);
        deps.ipt4 = h->ipt;
        deps.rtnl = h->rtnl;
        h->ctk = fake_ct_start(&h->ct);
        if (h->ctk == NULL) { return NULL; }
        deps.ct = h->ct;
    }
    h->app = firc_app_create(&deps);
    if (kernels) { firc_app_set_running(h->app, true); }
    h->ctx.app = h->app;
    h->ctx.config_path = NULL;
    h->ctx.config_version = NULL;

    if (firc_httpd_create(h->loop, &h->tcp) != FIRC_OK) { return NULL; }
    firc_groups_register_routes(h->tcp, &h->ctx);
    if (firc_httpd_listen_tcp(h->tcp, "127.0.0.1", TEST_PORT) != FIRC_OK) { return NULL; }

    pthread_create(&h->thread, NULL, loop_thread, h);
    live_harness = h;
    return h;
}

static void harness_stop(harness_t *h) {
    if (h == live_harness) { live_harness = NULL; }
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->tcp);
    firc_app_destroy(h->app);
    firc_dnsproxy_destroy(h->proxy);
    firc_loop_destroy(h->loop);
    firc_resolve_router_free(h->router);
    if (h->ct) { firc_ct_close(h->ct); }
    if (h->ctk) { fake_ct_stop(h->ctk); }
    if (h->rtnl) { firc_rtnl_close(h->rtnl); }
    if (h->kernel) { fake_rtnl_stop(h->kernel); }
    if (h->ipt) { firc_ipt_free(h->ipt); }
    firc_dns_pipeline_destroy(h->pipeline);
    firc_fakeip_free(h->pool);
    firc_config_clear(&h->cfg);
    free(h);
}

static size_t wire_name(const char *domain, uint8_t *buf, size_t cap) {
    size_t out = 0;
    const char *label = domain;
    while (*label) {
        const char *dot = strchr(label, '.');
        size_t label_len = dot ? (size_t)(dot - label) : strlen(label);
        if (out + 1 + label_len + 1 > cap) { return 0; }
        buf[out++] = (uint8_t)label_len;
        memcpy(buf + out, label, label_len);
        out += label_len;
        label += label_len;
        if (*label == '.') { label++; }
    }
    if (out + 1 > cap) { return 0; }
    buf[out++] = 0;
    return out;
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

/* Sends one request on a new connection; returns the status and, if asked, the parsed body to free. */
static int do_request(const char *method, const char *path, const char *body, cJSON **out_json) {
    int fd = connect_tcp(TEST_PORT);
    if (fd < 0) { return -1; }
    char req[8192];
    size_t body_len = body ? strlen(body) : 0;
    int n = snprintf(req, sizeof(req),
                     "%s %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     method, path, body_len, body ? body : "");
    (void)n;
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

static const char *jstr(cJSON *obj, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

static const char *or_none(const char *s) { return s != NULL ? s : "(none)"; }

static bool jbool(cJSON *obj, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsTrue(v);
}

TEST get_groups_starts_empty(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    cJSON *groups = cJSON_GetObjectItemCaseSensitive(out, "groups");
    ASSERT(cJSON_IsArray(groups));
    ASSERT_EQ(0, cJSON_GetArraySize(groups));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST create_group_defaults_enable(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"g1\",\"color\":\"#ABCDEF\",\"interface\":\"eth0\"}", &out));
    ASSERT_STR_EQ("g1", jstr(out, "name"));
    ASSERT(cJSON_GetObjectItemCaseSensitive(out, "color") == NULL);
    ASSERT_STR_EQ("eth0", jstr(out, "interface"));
    ASSERT(jbool(out, "enable"));
    cJSON *rules = cJSON_GetObjectItemCaseSensitive(out, "rules");
    ASSERT(cJSON_IsArray(rules));
    ASSERT_EQ(0, cJSON_GetArraySize(rules));
    ASSERT(jstr(out, "id") != NULL);
    ASSERT_EQ(8u, strlen(jstr(out, "id")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST get_group_unknown_and_invalid_id(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT_EQ(400, do_request("GET", "/api/v1/groups/nothex!", NULL, NULL));
    ASSERT_EQ(404, do_request("GET", "/api/v1/groups/deadbeef", NULL, NULL));
    harness_stop(h);
    PASS();
}

/* Catches: a PUT without rules dropping them, or a field of theirs, from the group. */
TEST put_group_updates_fields_and_keeps_rules_when_absent(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *created = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"g1\",\"interface\":\"eth0\","
                             "\"rules\":[{\"type\":\"domain\",\"rule\":\"example.com\","
                             "\"enable\":true,\"comment\":\"kept\"}]}",
                             &created));
    char id[9];
    snprintf(id, sizeof(id), "%s", jstr(created, "id"));
    cJSON *rules0 = cJSON_GetObjectItemCaseSensitive(created, "rules");
    const char *rule_id = jstr(cJSON_GetArrayItem(rules0, 0), "id");
    char rule_id_buf[9];
    snprintf(rule_id_buf, sizeof(rule_id_buf), "%s", rule_id);
    cJSON_Delete(created);

    char path[64];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", id);
    cJSON *updated = NULL;
    ASSERT_EQ(200,
             do_request("PUT", path, "{\"name\":\"g1-renamed\",\"interface\":\"eth1\"}",
                       &updated));
    ASSERT_STR_EQ("g1-renamed", jstr(updated, "name"));
    ASSERT_STR_EQ("eth1", jstr(updated, "interface"));
    cJSON *rules1 = cJSON_GetObjectItemCaseSensitive(updated, "rules");
    ASSERT_EQ(1, cJSON_GetArraySize(rules1));
    ASSERT_STR_EQ(rule_id_buf, jstr(cJSON_GetArrayItem(rules1, 0), "id"));
    ASSERT_STR_EQm("the comment is carried with the rule", "kept", or_none(jstr(cJSON_GetArrayItem(rules1, 0), "comment")));
    cJSON_Delete(updated);
    harness_stop(h);
    PASS();
}

/* Catches: a device selector lost through the API, or an empty entry accepted. */
TEST a_groups_device_selector_round_trips_through_the_api(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"kids\",\"interface\":\"eth0\","
                             "\"devices\":{\"allow\":[\"192.168.1.0/24\",\"policy:Kids\"],\"deny\":[\"192.168.1.5\"]}}",
                             &out));
    cJSON *dev = cJSON_GetObjectItemCaseSensitive(out, "devices");
    ASSERT(cJSON_IsObject(dev));
    cJSON *allow = cJSON_GetObjectItemCaseSensitive(dev, "allow");
    ASSERT_EQ(2, cJSON_GetArraySize(allow));
    ASSERT_STR_EQ("policy:Kids", cJSON_GetArrayItem(allow, 1)->valuestring);
    ASSERT_EQ(1, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(dev, "deny")));
    cJSON_Delete(out);

    ASSERT_EQ(400, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"bad\",\"interface\":\"eth0\","
                             "\"devices\":{\"allow\":[\"the-tv\"]}}",
                             &out));
    cJSON_Delete(out);
    ASSERT_EQm("an entry that is not a string is refused, not dropped", 400,
               do_request("POST", "/api/v1/groups",
                          "{\"name\":\"bad\",\"interface\":\"eth0\","
                          "\"devices\":{\"allow\":[1, true]}}",
                          &out));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

static int selector_of(cJSON *group, const char *list, const char *want_first) {
    cJSON *dev = cJSON_GetObjectItemCaseSensitive(group, "devices");
    cJSON *arr = dev ? cJSON_GetObjectItemCaseSensitive(dev, list) : NULL;
    if (!cJSON_IsArray(arr)) { return -1; }
    int n = cJSON_GetArraySize(arr);
    if (want_first != NULL && (n == 0 || strcmp(cJSON_GetArrayItem(arr, 0)->valuestring, want_first) != 0)) {
        return -2;
    }
    return n;
}

/* Catches: a PUT without the key widening a selector group to everyone, or null not clearing it. */
TEST a_put_replaces_keeps_or_clears_the_selector(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"kids\",\"interface\":\"eth0\","
                             "\"devices\":{\"allow\":[\"10.0.0.1\"]}}",
                             &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", path,
                             "{\"name\":\"kids\",\"interface\":\"eth0\","
                             "\"devices\":{\"allow\":[\"10.0.0.2\"],\"deny\":[\"10.0.0.3\"]}}",
                             &out));
    ASSERT_EQ_FMTm("the response carries the new selector", 1, selector_of(out, "allow", "10.0.0.2"), "%d");
    ASSERT_EQ_FMT(1, selector_of(out, "deny", "10.0.0.3"), "%d");
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQ_FMTm("and so does the group", 1, selector_of(out, "allow", "10.0.0.2"), "%d");
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"kids renamed\",\"interface\":\"eth0\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQ_FMTm("no devices key: the selector is kept", 1, selector_of(out, "allow", "10.0.0.2"), "%d");
    ASSERT_EQ_FMT(1, selector_of(out, "deny", "10.0.0.3"), "%d");
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"kids\",\"interface\":\"eth0\",\"devices\":null}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQ_FMTm("devices null: everyone again", 0, selector_of(out, "allow", NULL), "%d");
    ASSERT_EQ_FMT(0, selector_of(out, "deny", NULL), "%d");
    cJSON_Delete(out);

    ASSERT_EQm("a bad entry on PUT is a 400", 400,
               do_request("PUT", path, "{\"name\":\"kids\",\"interface\":\"eth0\",\"devices\":{\"deny\":[\"nope\"]}}", &out));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a MAC entry stored with upper case or '-', which the saver then writes. */
TEST the_api_stores_and_answers_a_mac_entry_canonical(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3d\",\"name\":\"kids\",\"interface\":\"eth0\","
                              "\"devices\":{\"allow\":[\"mac:AA-BB-CC-DD-EE-0F\"],\"deny\":[\"mac:AA-BB-CC-DD-EE-10\"]}}",
                              &out));
    ASSERT_EQ_FMT(1, selector_of(out, "allow", "mac:aa:bb:cc:dd:ee:0f"), "%d");
    ASSERT_EQ_FMTm("deny is canonicalised too", 1, selector_of(out, "deny", "mac:aa:bb:cc:dd:ee:10"), "%d");
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/0a1b2c3d", NULL, &out));
    ASSERT_EQ_FMTm("and so does the group", 1, selector_of(out, "allow", "mac:aa:bb:cc:dd:ee:0f"), "%d");
    ASSERT_EQ_FMT(1, selector_of(out, "deny", "mac:aa:bb:cc:dd:ee:10"), "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a bad device entry refused without naming the field and group, or a refused batch applied. */
TEST a_bad_device_entry_is_refused_naming_the_field_and_the_group(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(400, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3d\",\"name\":\"kids\",\"interface\":\"eth0\","
                              "\"devices\":{\"allow\":[\"mac:aa:bb\"]}}",
                              &out));
    ASSERTm("the 400 names a field (the old body has none)", jstr(out, "field") != NULL);
    ASSERT_STR_EQ("devices.allow", jstr(out, "field"));
    ASSERT_STR_EQ("0a1b2c3d", jstr(out, "group"));
    ASSERT(strstr(jstr(out, "error"), "mac:aa:bb") != NULL);
    ASSERT(strstr(jstr(out, "error"), "MAC") != NULL);
    cJSON_Delete(out);

    ASSERT_EQ(400, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3d\",\"name\":\"kids\",\"interface\":\"eth0\","
                              "\"devices\":{\"deny\":[\"the-tv\"]}}",
                              &out));
    ASSERT_STR_EQ("devices.deny", jstr(out, "field"));
    ASSERT(strstr(jstr(out, "error"), "the-tv") != NULL);
    cJSON_Delete(out);

    ASSERT_EQ(400, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3d\",\"name\":\"kids\",\"interface\":\"eth0\",\"devices\":\"all\"}", &out));
    ASSERT_STR_EQ("devices", jstr(out, "field"));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"id\":\"0a1b2c3d\",\"name\":\"kids\",\"interface\":\"eth0\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(400, do_request("PUT", "/api/v1/groups",
                              "{\"groups\":[{\"id\":\"0a1b2c3d\",\"name\":\"kids\",\"interface\":\"eth0\"},"
                              "{\"id\":\"0a1b2c3f\",\"name\":\"tv\",\"interface\":\"eth0\","
                              "\"devices\":{\"deny\":[\"mac:00:00:00:00:00:00\"]}}]}",
                              &out));
    ASSERT_STR_EQ("0a1b2c3f", jstr(out, "group"));
    ASSERT_STR_EQ("devices.deny", jstr(out, "field"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    ASSERT_EQm("the refused batch changed nothing", 1, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "groups")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

static firc_ruleset_t *only_group(harness_t *h) {
    return firc_app_user_group_count(h->app) == 1 ? firc_app_user_group_at(h->app, 0) : NULL;
}

static char *saved_groups_of(harness_t *h) {
    firc_group_t *gp = (firc_group_t *)firc_ruleset_group(only_group(h));
    firc_config_t c = h->cfg;
    c.groups = &gp;
    c.n_groups = 1;
    char *out = NULL;
    size_t len = 0;
    return firc_config_save_buffer_part(&c, "0.0.0", FIRC_CFG_GROUPS, &out, &len) == FIRC_OK ? out : NULL;
}

TEST a_put_moves_a_live_group_between_list_lengths_both_ways(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"nwg0\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"g\",\"interface\":[\"nwg3\",\"nwg4\",\"nwg5\"]}", &out));
    cJSON_Delete(out);
    const firc_group_t *g = firc_ruleset_group(only_group(h));
    ASSERT_EQ_FMT((size_t)3, firc_group_n_ifaces(g), "%zu");
    ASSERT_STR_EQ("nwg3", firc_group_iface_at(g, 0));
    ASSERT_STR_EQ("nwg4", firc_group_iface_at(g, 1));
    ASSERT_STR_EQ("nwg5", firc_group_iface_at(g, 2));
    char *yaml = saved_groups_of(h);
    ASSERT(yaml != NULL);
    ASSERT(strstr(yaml, "interface:\n  - nwg3\n  - nwg4\n  - nwg5\n") != NULL);
    free(yaml);

    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"g\",\"interface\":[\"nwg6\"]}", &out));
    ASSERT_STR_EQ("nwg6", jstr(out, "interface"));
    cJSON_Delete(out);
    g = firc_ruleset_group(only_group(h));
    ASSERT_EQ_FMT((size_t)1, firc_group_n_ifaces(g), "%zu");
    ASSERT_STR_EQ("nwg6", firc_group_iface_at(g, 0));
    ASSERT_STR_EQ("", firc_group_iface_at(g, 1));
    yaml = saved_groups_of(h);
    ASSERT(yaml != NULL);
    ASSERT(strstr(yaml, "interface: nwg6\n") != NULL);
    ASSERT_EQ(NULL, strstr(yaml, "nwg4"));
    free(yaml);
    harness_stop(h);
    PASS();
}

/* Catches: a refused PUT taking the group out of netfilter before the body was checked. */
TEST a_refused_put_leaves_the_group_in_the_kernel(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    firc_ruleset_t *rs = only_group(h);
    ASSERT(rs != NULL);
    ASSERTm("the group is live", firc_ruleset_runtime_enabled(rs));
    size_t chains_before = fake_rtnl_count(h->kernel, 33 , 0);

    ASSERT_EQ(400, do_request("PUT", path, "{\"name\":\"g\",\"interface\":\"lo\",\"devices\":{\"allow\":[\"the-tv\"]}}", &out));
    cJSON_Delete(out);
    ASSERTm("still live", firc_ruleset_runtime_enabled(rs));
    ASSERT_EQ_FMTm("and its ip rule was never touched", chains_before, fake_rtnl_count(h->kernel, 33, 0), "%zu");
    harness_stop(h);
    PASS();
}

/* The mark the daemon installed for the group's ip rule, read back from the kernel. */
static uint32_t installed_group_mark(harness_t *h) {
    fake_rtnl_msg_t msgs[64];
    size_t n = fake_rtnl_messages(h->kernel, msgs, 64);
    for (size_t i = 0; i < n; i++) {
        if (msgs[i].type == 32  && (msgs[i].mark & FIRC_MARK_GROUP_MASK) != 0) {
            return msgs[i].mark & FIRC_MARK_GROUP_MASK;
        }
    }
    return 0;
}

/* Catches: a rename flushing the flows of a group that still routes them the same way. */
TEST renaming_a_group_keeps_the_flows_it_is_steering(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    uint32_t mark = installed_group_mark(h);
    ASSERTm("the group got a mark", mark != 0);
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, reply[4] = {198, 18, 0, 5};
    fake_ct_add(h->ctk, AF_INET, src, dst, reply, mark | FIRC_MARK_HANDLED);

    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"renamed\",\"interface\":\"lo\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("the kernel was not asked to drop anything", (size_t)0, fake_ct_deletes(h->ctk), "%zu");
    ASSERT_EQ_FMTm("the flow is still running", (size_t)1, fake_ct_remaining(h->ctk), "%zu");
    harness_stop(h);
    PASS();
}

/* Catches: a deleted group's flows kept. */
TEST deleting_a_group_drops_the_flows_it_was_steering(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    uint32_t mark = installed_group_mark(h);
    ASSERTm("the group got a mark", mark != 0);
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, ours[4] = {198, 18, 0, 5};
    fake_ct_add(h->ctk, AF_INET, src, dst, ours, mark | FIRC_MARK_HANDLED);

    ASSERT_EQ(200, do_request("DELETE", path, NULL, &out));
    cJSON_Delete(out);
    ASSERTm("the group's flow went with it", fake_ct_deleted(h->ctk, ours, 4));
    harness_stop(h);
    PASS();
}

/* Catches: a rule with an unknown type or an unusable pattern stored instead of refused. */
TEST a_rule_the_daemon_cannot_use_is_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("a subnet that is not a prefix", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"nonsense\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("...nor is a bare hostname", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"example.com\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a prefix longer than the family allows", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/33\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a prefix with a sign is not a prefix", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/-0\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("...nor with a plus", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/+8\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("...nor with a space", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/ 8\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("the same for subnet6", 400,
                   do_request("POST", path, "{\"type\":\"subnet6\",\"rule\":\"fd00::/-0\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a subnet6 that is not one", 400,
                   do_request("POST", path, "{\"type\":\"subnet6\",\"rule\":\"10.0.0.0/8\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a regex that does not compile", 400,
                   do_request("POST", path, "{\"type\":\"regex\",\"rule\":\"^[a-z\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a type nobody implements", 400,
                   do_request("POST", path, "{\"type\":\"telepathy\",\"rule\":\"example.com\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("an empty pattern", 400,
                   do_request("POST", path, "{\"type\":\"domain\",\"rule\":\"\"}", &out), "%d");
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("and nothing was stored", 0, (int)cJSON_GetArraySize(
                       cJSON_GetObjectItem((do_request("GET", path, NULL, &out), out), "rules")), "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: proto or ports stored when invalid, echoed when unset, or refused without the reason. */
TEST proto_and_ports_are_kept_or_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMT(200, do_request("POST", path,
                                  "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/8\",\"enable\":true,\"proto\":\"udp\",\"ports\":\"53,1000-2000\"}",
                                  &out), "%d");
    ASSERT_STR_EQ("udp", jstr(out, "proto"));
    ASSERT_STR_EQ("53,1000-2000", jstr(out, "ports"));
    char rule_path[160];
    snprintf(rule_path, sizeof(rule_path), "%s/%s", path, jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMT(200, do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.1.0.0/16\",\"enable\":true}", &out), "%d");
    ASSERTm("a rule without them has neither key", cJSON_GetObjectItem(out, "proto") == NULL);
    ASSERTm("a rule without them has neither key", cJSON_GetObjectItem(out, "ports") == NULL);
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("ports without a protocol", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/8\",\"ports\":\"53\"}", &out), "%d");
    ASSERT(strstr(jstr(out, "error"), "ports need a protocol (tcp or udp)") != NULL);
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a protocol on a name rule", 400,
                   do_request("POST", path, "{\"type\":\"domain\",\"rule\":\"example.com\",\"proto\":\"udp\"}", &out), "%d");
    ASSERT(strstr(jstr(out, "error"), "proto and ports apply to subnet and subnet6 rules only") != NULL);
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a protocol nobody routes by", 400,
                   do_request("POST", path, "{\"type\":\"subnet6\",\"rule\":\"fd00::/8\",\"proto\":\"icmp\"}", &out), "%d");
    ASSERT(strstr(jstr(out, "error"), "proto is tcp or udp") != NULL);
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a port list iptables would take but the grammar does not", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/8\",\"proto\":\"tcp\",\"ports\":\"53:443\"}", &out), "%d");
    ASSERT(strstr(jstr(out, "error"), "ports are a comma-separated list") != NULL);
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("a number is not a port list: read as absent it would mark every port", 400,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/8\",\"proto\":\"udp\",\"ports\":53}", &out), "%d");
    ASSERT(strstr(jstr(out, "error"), "proto and ports are strings") != NULL);
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("the same for proto, and on PUT", 400,
                   do_request("PUT", rule_path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/8\",\"enable\":true,\"proto\":17}", &out), "%d");
    ASSERT(strstr(jstr(out, "error"), "proto and ports are strings") != NULL);
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("null is absent", 200,
                   do_request("POST", path, "{\"type\":\"subnet\",\"rule\":\"10.2.0.0/16\",\"enable\":true,\"proto\":null,\"ports\":null}", &out), "%d");
    ASSERT(cJSON_GetObjectItem(out, "proto") == NULL);
    cJSON_Delete(out);

    ASSERT_EQ_FMT(400, do_request("PUT", rule_path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/8\",\"enable\":true,\"ports\":\"53\"}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", rule_path, NULL, &out));
    ASSERT_STR_EQ("udp", jstr(out, "proto"));
    ASSERT_STR_EQ("53,1000-2000", jstr(out, "ports"));
    cJSON_Delete(out);
    char group_path[96];
    snprintf(group_path, sizeof(group_path), "%.*s", (int)(strrchr(path, '/') - path), path);
    ASSERT_EQ_FMT(200, do_request("PUT", group_path, "{\"name\":\"g2\",\"interface\":\"lo\",\"enable\":false}", &out), "%d");
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", rule_path, NULL, &out));
    ASSERT_STR_EQm("kept across a group PUT without rules", "udp", jstr(out, "proto"));
    ASSERT_STR_EQ("53,1000-2000", jstr(out, "ports"));
    cJSON_Delete(out);
    ASSERT_EQ_FMT(200, do_request("PUT", rule_path, "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/8\",\"enable\":true}", &out), "%d");
    ASSERT(cJSON_GetObjectItem(out, "proto") == NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

static void make_rules_path(const char *group_name, char *path, size_t cap) {
    cJSON *out = NULL;
    char body[128];
    snprintf(body, sizeof(body), "{\"name\":\"%s\",\"interface\":\"lo\"}", group_name);
    if (do_request("POST", "/api/v1/groups", body, &out) != 200) { abort(); }
    snprintf(path, cap, "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);
}

/* Catches: a comment lost, altered or left untrimmed through the API, or a key answered for a rule without one. */
TEST a_rules_comment_round_trips_through_the_api(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true,"
                                  "\"comment\":\"Meta: \xc2\xab" "CDN\xc2\xbb #1 \\\\ \\\"x\\\"\"}",
                                  &out), "%d");
    ASSERT_STR_EQ("Meta: \xc2\xab" "CDN\xc2\xbb #1 \\ \"x\"", or_none(jstr(out, "comment")));
    char rule_path[160];
    snprintf(rule_path, sizeof(rule_path), "%s/%s", path, jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", rule_path, NULL, &out));
    ASSERT_STR_EQ("Meta: \xc2\xab" "CDN\xc2\xbb #1 \\ \"x\"", or_none(jstr(out, "comment")));
    cJSON_Delete(out);

    ASSERT_EQ_FMT(200, do_request("POST", path, "{\"type\":\"domain\",\"rule\":\"example.org\",\"enable\":true}", &out),
                  "%d");
    ASSERTm("a rule without one has no key", cJSON_GetObjectItem(out, "comment") == NULL);
    cJSON_Delete(out);
    ASSERT_EQ_FMT(200, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.net\",\"enable\":true,\"comment\":\"  pad  \"}",
                                  &out), "%d");
    ASSERT_STR_EQm("spaces around it are trimmed", "pad", or_none(jstr(out, "comment")));
    cJSON_Delete(out);
    ASSERT_EQ_FMT(200, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.info\",\"enable\":true,\"comment\":\"   \"}",
                                  &out), "%d");
    ASSERTm("nothing but spaces is no comment", cJSON_GetObjectItem(out, "comment") == NULL);
    cJSON_Delete(out);

    ASSERT_EQ_FMT(200, do_request("PUT", rule_path, "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true}", &out),
                  "%d");
    ASSERTm("a PUT replaces the rule whole, comment included", cJSON_GetObjectItem(out, "comment") == NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

static const char *stored_marker(harness_t *h, size_t i) {
    return firc_ruleset_group(only_group(h))->rules[i]->autolist;
}

static void seed_marker(harness_t *h, size_t i, const char *host) {
    if (firc_strset(&firc_ruleset_group_mut(only_group(h))->rules[i]->autolist, host) != FIRC_OK) { abort(); }
}

static void add_rule_via_post(const char *path, const char *rule, bool enable, char *id, size_t cap) {
    cJSON *out = NULL;
    char body[160];
    snprintf(body, sizeof(body), "{\"type\":\"domain\",\"rule\":\"%s\",\"enable\":%s}", rule, enable ? "true" : "false");
    if (do_request("POST", path, body, &out) != 200) { abort(); }
    snprintf(id, cap, "%s", jstr(out, "id"));
    cJSON_Delete(out);
}

static void group_id_of(harness_t *h, char *id) {
    firc_id_format(firc_ruleset_group(only_group(h))->id, id);
}

static bool stored_by_domain(harness_t *h, size_t i) {
    return firc_ruleset_group(only_group(h))->rules[i]->autolist_by_domain;
}

static void seed_by_domain(harness_t *h, size_t i, const char *host) {
    seed_marker(h, i, host);
    firc_ruleset_group_mut(only_group(h))->rules[i]->autolist_by_domain = true;
}

TEST put_routes_carry_the_by_domain_flag(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true,"
                                  "\"autolistByDomain\":true}", &out), "%d");
    ASSERTm("the answer carries no flag", cJSON_GetObjectItem(out, "autolistByDomain") == NULL);
    char id[FIRC_ID_STR_LEN];
    snprintf(id, sizeof(id), "%s", jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_FALSE(stored_by_domain(h, 0));
    seed_by_domain(h, 0, "a.example.com");
    char rule_path[160];
    snprintf(rule_path, sizeof(rule_path), "%s/%s", path, id);
    ASSERT_EQ_FMT(200, do_request("PUT", rule_path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true,"
                                  "\"autolistByDomain\":false}", &out), "%d");
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItem(out, "autolistByDomain")));
    cJSON_Delete(out);
    ASSERTm("PUT rule", stored_by_domain(h, 0));
    char body[512];
    snprintf(body, sizeof(body),
             "{\"rules\":[{\"id\":\"%s\",\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true}]}", id);
    ASSERT_EQ_FMT(200, do_request("PUT", path, body, &out), "%d");
    cJSON_Delete(out);
    ASSERTm("PUT rules", stored_by_domain(h, 0));
    char gid[FIRC_ID_STR_LEN];
    group_id_of(h, gid);
    char gpath[96];
    snprintf(gpath, sizeof(gpath), "/api/v1/groups/%s", gid);
    snprintf(body, sizeof(body),
             "{\"id\":\"%s\",\"name\":\"g\",\"interface\":\"lo\",\"enable\":true,\"rules\":[{\"id\":\"%s\","
             "\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true}]}",
             gid, id);
    ASSERT_EQ_FMT(200, do_request("PUT", gpath, body, &out), "%d");
    cJSON_Delete(out);
    ASSERTm("PUT group with rules", stored_by_domain(h, 0));
    snprintf(body, sizeof(body), "{\"id\":\"%s\",\"name\":\"g2\",\"interface\":\"lo\",\"enable\":true}", gid);
    ASSERT_EQ_FMT(200, do_request("PUT", gpath, body, &out), "%d");
    cJSON_Delete(out);
    ASSERTm("PUT group without rules", stored_by_domain(h, 0));
    snprintf(body, sizeof(body),
             "{\"groups\":[{\"id\":\"%s\",\"name\":\"g2\",\"interface\":\"lo\",\"enable\":true,\"rules\":["
             "{\"id\":\"%s\",\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true}]}]}",
             gid, id);
    ASSERT_EQ_FMT(200, do_request("PUT", "/api/v1/groups", body, &out), "%d");
    cJSON_Delete(out);
    ASSERTm("PUT groups", stored_by_domain(h, 0));
    ASSERT_STR_EQ("a.example.com", or_none(stored_marker(h, 0)));
    ASSERT_EQ_FMT(200, do_request("PUT", rule_path, "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":false}",
                                  &out), "%d");
    cJSON_Delete(out);
    ASSERTm("the flag goes with the marker", !stored_by_domain(h, 0) && stored_marker(h, 0) == NULL);
    harness_stop(h);
    PASS();
}

TEST request_autolist_field_is_ignored(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true,"
                                  "\"autolist\":\"x.test\"}", &out), "%d");
    ASSERTm("the answer carries no marker", cJSON_GetObjectItem(out, "autolist") == NULL);
    cJSON_Delete(out);
    ASSERT(stored_marker(h, 0) == NULL);
    ASSERT_EQ_FMT(200, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.net\",\"enable\":true,\"autolist\":5}", &out),
                  "%d");
    cJSON_Delete(out);
    ASSERT(stored_marker(h, 1) == NULL);
    seed_marker(h, 0, "www.example.com");
    char rule_path[160];
    char id[FIRC_ID_STR_LEN];
    firc_id_format(firc_ruleset_group(only_group(h))->rules[0]->id, id);
    snprintf(rule_path, sizeof(rule_path), "%s/%s", path, id);
    ASSERT_EQ(200, do_request("GET", rule_path, NULL, &out));
    ASSERT_STR_EQ("www.example.com", or_none(jstr(out, "autolist")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST put_rule_switch_off_drops_marker(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    char id[FIRC_ID_STR_LEN];
    add_rule_via_post(path, "example.com", true, id, sizeof(id));
    seed_marker(h, 0, "x.test");
    char rule_path[160];
    snprintf(rule_path, sizeof(rule_path), "%s/%s", path, id);
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("PUT", rule_path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":false,"
                                  "\"autolist\":\"x.test\"}", &out), "%d");
    ASSERTm("the answer carries no marker", cJSON_GetObjectItem(out, "autolist") == NULL);
    cJSON_Delete(out);
    ASSERT(stored_marker(h, 0) == NULL);
    harness_stop(h);
    PASS();
}

TEST put_rule_same_keeps_marker(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    char id[FIRC_ID_STR_LEN];
    add_rule_via_post(path, "example.com", true, id, sizeof(id));
    seed_marker(h, 0, "x.test");
    char rule_path[160];
    snprintf(rule_path, sizeof(rule_path), "%s/%s", path, id);
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("PUT", rule_path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true,"
                                  "\"autolist\":\"other.test\"}", &out), "%d");
    ASSERT_STR_EQ("x.test", or_none(jstr(out, "autolist")));
    cJSON_Delete(out);
    ASSERT_STR_EQ("x.test", or_none(stored_marker(h, 0)));
    harness_stop(h);
    PASS();
}

TEST put_rules_edit_pattern_drops_marker(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    char id0[FIRC_ID_STR_LEN];
    char id1[FIRC_ID_STR_LEN];
    add_rule_via_post(path, "example.com", true, id0, sizeof(id0));
    add_rule_via_post(path, "example.net", true, id1, sizeof(id1));
    seed_marker(h, 0, "a.test");
    seed_marker(h, 1, "b.test");
    char body[512];
    snprintf(body, sizeof(body),
             "{\"rules\":[{\"id\":\"%s\",\"type\":\"domain\",\"rule\":\"example.org\",\"enable\":true,"
             "\"autolist\":\"a.test\"},{\"id\":\"%s\",\"type\":\"domain\",\"rule\":\"example.net\",\"enable\":true}]}",
             id0, id1);
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("PUT", path, body, &out), "%d");
    cJSON_Delete(out);
    ASSERT(stored_marker(h, 0) == NULL);
    ASSERT_STR_EQ("b.test", or_none(stored_marker(h, 1)));
    harness_stop(h);
    PASS();
}

TEST put_group_untouched_rules_keep_markers(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    char id[FIRC_ID_STR_LEN];
    add_rule_via_post(path, "example.com", true, id, sizeof(id));
    seed_marker(h, 0, "x.test");
    char gid[FIRC_ID_STR_LEN];
    group_id_of(h, gid);
    char gpath[96];
    snprintf(gpath, sizeof(gpath), "/api/v1/groups/%s", gid);
    char body[512];
    snprintf(body, sizeof(body),
             "{\"id\":\"%s\",\"name\":\"g\",\"interface\":\"lo\",\"enable\":true,\"rules\":[{\"id\":\"%s\","
             "\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true,\"autolist\":\"y.test\"}]}",
             gid, id);
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("PUT", gpath, body, &out), "%d");
    cJSON_Delete(out);
    ASSERT_STR_EQ("x.test", or_none(stored_marker(h, 0)));
    snprintf(body, sizeof(body), "{\"id\":\"%s\",\"name\":\"g2\",\"interface\":\"lo\",\"enable\":true}", gid);
    ASSERT_EQ_FMT(200, do_request("PUT", gpath, body, &out), "%d");
    cJSON_Delete(out);
    ASSERT_STR_EQ("x.test", or_none(stored_marker(h, 0)));
    snprintf(body, sizeof(body),
             "{\"id\":\"%s\",\"name\":\"g2\",\"interface\":\"lo\",\"enable\":true,\"rules\":[{\"id\":\"%s\","
             "\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":false}]}",
             gid, id);
    ASSERT_EQ_FMT(200, do_request("PUT", gpath, body, &out), "%d");
    cJSON_Delete(out);
    ASSERT(stored_marker(h, 0) == NULL);
    harness_stop(h);
    PASS();
}

TEST put_groups_switch_drops_marker(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    char id0[FIRC_ID_STR_LEN];
    char id1[FIRC_ID_STR_LEN];
    add_rule_via_post(path, "example.com", true, id0, sizeof(id0));
    add_rule_via_post(path, "example.net", true, id1, sizeof(id1));
    seed_marker(h, 0, "a.test");
    seed_marker(h, 1, "b.test");
    char gid[FIRC_ID_STR_LEN];
    group_id_of(h, gid);
    char body[768];
    snprintf(body, sizeof(body),
             "{\"groups\":[{\"id\":\"%s\",\"name\":\"g\",\"interface\":\"lo\",\"enable\":true,\"rules\":["
             "{\"id\":\"%s\",\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":false,\"autolist\":\"a.test\"},"
             "{\"id\":\"%s\",\"type\":\"domain\",\"rule\":\"example.net\",\"enable\":true}]}]}",
             gid, id0, id1);
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("PUT", "/api/v1/groups", body, &out), "%d");
    cJSON_Delete(out);
    ASSERT(stored_marker(h, 0) == NULL);
    ASSERT_STR_EQ("b.test", or_none(stored_marker(h, 1)));
    harness_stop(h);
    PASS();
}

/* Catches: a comment of two lines (newline, U+2028, U+2029), past 256 bytes, with a C1 control, not UTF-8 or not a string stored, or refused unnamed. */
TEST a_comment_with_a_newline_or_257_bytes_is_400(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    cJSON *out = NULL;
    ASSERT_EQ_FMT(400, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":\"a\\nb\"}", &out), "%d");
    ASSERT_STR_EQ("rule \"example.com\" (type \"domain\"): comment holds a control character", or_none(jstr(out, "error")));
    cJSON_Delete(out);
    ASSERT_EQ_FMT(400, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":\"a\\u0085b\"}", &out), "%d");
    ASSERT_STR_EQ("rule \"example.com\" (type \"domain\"): comment holds a control character", or_none(jstr(out, "error")));
    cJSON_Delete(out);
    ASSERT_EQ_FMT(400, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":\"a\\u2028b\"}", &out), "%d");
    ASSERT_STR_EQ("rule \"example.com\" (type \"domain\"): comment holds a line or paragraph separator",
                  or_none(jstr(out, "error")));
    cJSON_Delete(out);
    ASSERT_EQ_FMT(400, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":\"a\xe2\x80\xa9\"}", &out), "%d");
    ASSERT_STR_EQ("rule \"example.com\" (type \"domain\"): comment holds a line or paragraph separator",
                  or_none(jstr(out, "error")));
    cJSON_Delete(out);
    ASSERT_EQ_FMT(400, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":\"a\xff\"}", &out), "%d");
    ASSERT_STR_EQ("rule \"example.com\" (type \"domain\"): comment is not valid UTF-8", or_none(jstr(out, "error")));
    cJSON_Delete(out);
    ASSERT_EQ_FMT(400, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":7}", &out), "%d");
    ASSERT_STR_EQ("rule \"example.com\" (type \"domain\"): comment is a string", or_none(jstr(out, "error")));
    cJSON_Delete(out);

    char long_comment[300] = "";
    for (int i = 0; i < 127; i++) { strcat(long_comment, "\xd1\x8f"); }
    strcat(long_comment, "a\xd1\x8f");
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"groups\":[{\"name\":\"work\",\"interface\":\"lo\","
             "\"rules\":[{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":\"%s\"}]}]}",
             long_comment);
    ASSERT_EQ_FMT(400, do_request("PUT", "/api/v1/groups", body, &out), "%d");
    ASSERT_STR_EQ("group \"work\", rule \"example.com\" (type \"domain\"): comment is longer than 256 bytes",
                  or_none(jstr(out, "error")));
    cJSON_Delete(out);
    snprintf(body, sizeof(body),
             "{\"name\":\"work\",\"interface\":\"lo\","
             "\"rules\":[{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":\"%s\"}]}",
             long_comment);
    ASSERT_EQ_FMT(400, do_request("POST", "/api/v1/groups", body, &out), "%d");
    ASSERT_STR_EQ("group \"work\", rule \"example.com\" (type \"domain\"): comment is longer than 256 bytes",
                  or_none(jstr(out, "error")));
    cJSON_Delete(out);
    snprintf(body, sizeof(body), "{\"rules\":[{\"type\":\"domain\",\"rule\":\"example.com\",\"comment\":\"%s\"}]}",
             long_comment);
    ASSERT_EQ_FMT(400, do_request("PUT", path, body, &out), "%d");
    ASSERT_STR_EQ("group \"g\", rule \"example.com\" (type \"domain\"): comment is longer than 256 bytes",
                  or_none(jstr(out, "error")));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQm("a refused bulk PUT stored no rule", 0, cJSON_GetArraySize(cJSON_GetObjectItem(out, "rules")));
    cJSON_Delete(out);

    ASSERT_EQ_FMT(200, do_request("POST", path,
                                  "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true,\"comment\":\"old\"}",
                                  &out), "%d");
    char rule_path[160];
    snprintf(rule_path, sizeof(rule_path), "%s/%s", path, jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ_FMT(400, do_request("PUT", rule_path,
                                  "{\"type\":\"domain\",\"rule\":\"example.net\",\"enable\":false,\"comment\":\"a\\tb\"}",
                                  &out), "%d");
    ASSERT_STR_EQ("rule \"example.net\" (type \"domain\"): comment holds a control character", or_none(jstr(out, "error")));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", rule_path, NULL, &out));
    ASSERT_STR_EQm("a refused PUT leaves the rule whole", "example.com", or_none(jstr(out, "rule")));
    ASSERT_STR_EQ("old", or_none(jstr(out, "comment")));
    ASSERT(jbool(out, "enable"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: the 256-byte limit counted in characters, off by one, or a comment at it cut. */
TEST a_comment_of_exactly_256_bytes_is_kept(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[96];
    make_rules_path("g", path, sizeof(path));
    char comment[300] = "";
    for (int i = 0; i < 128; i++) { strcat(comment, "\xd1\x8f"); }
    char body[1024];
    snprintf(body, sizeof(body), "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true,\"comment\":\"%s\"}", comment);
    cJSON *out = NULL;
    ASSERT_EQ_FMT(200, do_request("POST", path, body, &out), "%d");
    ASSERT_STR_EQ(comment, or_none(jstr(out, "comment")));
    cJSON_Delete(out);
    snprintf(body, sizeof(body), "{\"type\":\"domain\",\"rule\":\"example.org\",\"enable\":true,\"comment\":\"  %s  \"}",
             comment);
    ASSERT_EQ_FMTm("the limit is measured after the trim", 200, do_request("POST", path, body, &out), "%d");
    ASSERT_STR_EQ(comment, or_none(jstr(out, "comment")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a refused Save that does not say which rule in which group was wrong. */
TEST an_unusable_rule_names_the_group_and_the_rule(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ_FMTm("the save is refused", 400,
                   do_request("PUT", "/api/v1/groups",
                              "{\"groups\":[{\"name\":\"work\",\"interface\":\"lo\","
                              "\"rules\":[{\"type\":\"domain\",\"rule\":\"example.com\"}]},"
                              "{\"name\":\"media\",\"interface\":\"lo\","
                              "\"rules\":[{\"type\":\"domain\",\"rule\":\"ok.example.com\"},"
                              "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/33\"}]}]}",
                              &out),
                   "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("it names the group the operator has to open", strstr(msg, "media") != NULL);
    ASSERTm("it names the rule inside it", strstr(msg, "10.0.0.0/33") != NULL);
    ASSERTm("and still says what is wrong with it", strstr(msg, "prefix") != NULL);
    ASSERTm("without pointing at the group that was fine", strstr(msg, "work") == NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a refusal on a rule endpoint that does not name the rule. */
TEST an_unusable_rule_on_the_rule_endpoint_names_the_rule(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("refused", 400,
                   do_request("POST", path, "{\"type\":\"subnet6\",\"rule\":\"fd00::/-0\"}", &out), "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("the pattern that was refused is in the message",
            strstr(msg, "fd00::/-0") != NULL);
    ASSERTm("and the reason survives next to it", strstr(msg, "IPv6") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: an empty pattern refused without naming its position in the group. */
TEST an_empty_pattern_is_named_by_its_position(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ_FMTm("the save is refused", 400,
                   do_request("PUT", "/api/v1/groups",
                              "{\"groups\":[{\"name\":\"media\",\"interface\":\"lo\","
                              "\"rules\":[{\"type\":\"domain\",\"rule\":\"a.example.com\"},"
                              "{\"type\":\"domain\",\"rule\":\"b.example.com\"},"
                              "{\"type\":\"domain\",\"rule\":\"\"}]}]}",
                              &out),
                   "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("the position is the third rule, 1-based", strstr(msg, "rule 3") != NULL);
    ASSERTm("in the group that holds it", strstr(msg, "media") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST the_bulk_rules_put_names_the_group_and_the_rule(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"name\":\"media\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("the whole request is refused", 400,
                   do_request("PUT", path,
                              "{\"rules\":[{\"type\":\"domain\",\"rule\":\"ok.example.com\"},"
                              "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/33\"}]}",
                              &out),
                   "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("it names the rule", strstr(msg, "10.0.0.0/33") != NULL);
    ASSERTm("and says what is wrong with it", strstr(msg, "prefix") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: an in-place rule replace refused with the wrong position or pattern. */
TEST replacing_one_rule_with_an_unusable_one_names_it(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char rules[96];
    snprintf(rules, sizeof(rules), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", rules, "{\"type\":\"domain\",\"rule\":\"a.example.com\"}", &out));
    char one[160];
    snprintf(one, sizeof(one), "%s/%s", rules, jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("refused", 400,
                   do_request("PUT", one, "{\"type\":\"regex\",\"rule\":\"^[a-z\"}", &out), "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("the pattern that was refused is named", strstr(msg, "^[a-z") != NULL);
    ASSERTm("and the reason is still there", strstr(msg, "compile") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a refusal on a PUT without "name" naming no group. */
TEST a_put_that_omits_the_name_still_names_the_group(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"name\":\"media\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("refused", 400,
                   do_request("PUT", path,
                              "{\"interface\":\"lo\",\"rules\":[{\"type\":\"subnet\",\"rule\":\"10.0.0.0/33\"}]}",
                              &out),
                   "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("the stored name is the one reported", strstr(msg, "media") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a long type cut in the middle of a UTF-8 sequence in the refusal. */
TEST a_long_type_is_cut_at_a_character_boundary(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char rules[96];
    snprintf(rules, sizeof(rules), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);

    char type[128] = "";
    for (int i = 0; i < 10; i++) { strcat(type, "\xe4\xb8\xad"); }
    char body[256];
    snprintf(body, sizeof(body), "{\"type\":\"%s\",\"rule\":\"x.example.com\"}", type);
    ASSERT_EQ_FMTm("refused", 400, do_request("POST", rules, body, &out), "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    for (const unsigned char *p = (const unsigned char *)msg; *p != '\0';) {
        unsigned extra = 0;
        if (*p < 0x80) { extra = 0; }
        else if ((*p & 0xe0) == 0xc0) { extra = 1; }
        else if ((*p & 0xf0) == 0xe0) { extra = 2; }
        else if ((*p & 0xf8) == 0xf0) { extra = 3; }
        else { FAILm("a continuation byte where a character should start"); }
        p++;
        for (unsigned k = 0; k < extra; k++) {
            if ((*p & 0xc0) != 0x80) { FAILm("the type was cut mid-sequence"); }
            p++;
        }
    }
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST a_long_name_is_cut_at_a_character_boundary(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    char name[128] = "x";
    for (int i = 0; i < 30; i++) { strcat(name, "\xd1\x8f"); }
    char body[512];
    snprintf(body, sizeof(body),
             "{\"name\":\"%s\",\"interface\":\"lo\","
             "\"rules\":[{\"type\":\"subnet\",\"rule\":\"10.0.0.0/33\"}]}",
             name);
    ASSERT_EQ_FMTm("refused", 400, do_request("POST", "/api/v1/groups", body, &out), "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    for (const unsigned char *p = (const unsigned char *)msg; *p != '\0';) {
        unsigned extra = 0;
        if (*p < 0x80) { extra = 0; }
        else if ((*p & 0xe0) == 0xc0) { extra = 1; }
        else if ((*p & 0xf0) == 0xe0) { extra = 2; }
        else if ((*p & 0xf8) == 0xf0) { extra = 3; }
        else { FAILm("a continuation byte where a character should start"); }
        p++;
        for (unsigned k = 0; k < extra; k++) {
            if ((*p & 0xc0) != 0x80) { FAILm("a character was cut mid-sequence"); }
            p++;
        }
    }
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: an appended empty pattern named by any row but the one it would become. */
TEST appending_an_empty_pattern_is_named_by_the_row_it_would_become(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char rules[96];
    snprintf(rules, sizeof(rules), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", rules, "{\"type\":\"domain\",\"rule\":\"a.example.com\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", rules, "{\"type\":\"domain\",\"rule\":\"b.example.com\"}", &out));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("refused", 400,
                   do_request("POST", rules, "{\"type\":\"domain\",\"rule\":\"\"}", &out), "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("two rules are there, so this one would be the third",
            strstr(msg, "rule 3") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST replacing_a_rule_with_an_empty_pattern_names_the_row_replaced(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char rules[96];
    snprintf(rules, sizeof(rules), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", rules, "{\"type\":\"domain\",\"rule\":\"a.example.com\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", rules, "{\"type\":\"domain\",\"rule\":\"b.example.com\"}", &out));
    char second[160];
    snprintf(second, sizeof(second), "%s/%s", rules, jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("refused", 400,
                   do_request("PUT", second, "{\"type\":\"domain\",\"rule\":\"\"}", &out), "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("the second row is the one being replaced", strstr(msg, "rule 2") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a pattern cut to fit the message without a mark that it was cut. */
TEST a_pattern_too_long_to_quote_whole_is_marked_as_cut(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    char pattern[400];
    memset(pattern, 'a', sizeof(pattern) - 1);
    pattern[sizeof(pattern) - 1] = '\0';
    pattern[0] = '[';
    char body[600];
    snprintf(body, sizeof(body), "{\"type\":\"regex\",\"rule\":\"%s\"}", pattern);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char rules[96];
    snprintf(rules, sizeof(rules), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("refused", 400, do_request("POST", rules, body, &out), "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("the cut is visible", strstr(msg, "...") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: an unknown type refused without echoing the type that was sent. */
TEST an_unknown_type_is_echoed_back(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char rules[96];
    snprintf(rules, sizeof(rules), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);

    ASSERT_EQ_FMTm("refused", 400,
                   do_request("POST", rules, "{\"type\":\"Domain\",\"rule\":\"x.example.com\"}", &out),
                   "%d");
    const char *msg = jstr(out, "error");
    ASSERT(msg != NULL);
    ASSERTm("the type that was rejected is shown", strstr(msg, "Domain") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST the_rules_the_daemon_can_use_are_still_accepted(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s/rules", jstr(out, "id"));
    cJSON_Delete(out);

    const char *ok[] = {
        "{\"type\":\"subnet\",\"rule\":\"10.0.0.0/8\"}",
        "{\"type\":\"subnet\",\"rule\":\"0.0.0.0/0\"}",
        "{\"type\":\"subnet\",\"rule\":\"192.168.1.5\"}",
        "{\"type\":\"subnet6\",\"rule\":\"fd00::/8\"}",
        "{\"type\":\"regex\",\"rule\":\"^.*\\\\.example\\\\.com$\"}",
        "{\"type\":\"domain\",\"rule\":\"example.com\"}",
        "{\"type\":\"namespace\",\"rule\":\"example.com\"}",
        "{\"type\":\"wildcard\",\"rule\":\"*.example.com\"}",
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        int code = do_request("POST", path, ok[i], &out);
        cJSON_Delete(out);
        ASSERT_EQ_FMTm(ok[i], 200, code, "%d");
    }
    harness_stop(h);
    PASS();
}

/* Catches: a PUT that stops when rtnetlink refuses its teardown. */
TEST a_put_whose_teardown_was_refused_still_brings_the_group_up(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    firc_ruleset_t *rs = only_group(h);
    ASSERT(rs != NULL && firc_ruleset_runtime_enabled(rs));

    fake_rtnl_fail_next(h->kernel, 1 );
    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"g2\",\"interface\":\"lo\"}", &out));
    cJSON_Delete(out);
    ASSERT_FALSEm("the PUT met the refusal", fake_rtnl_failure_armed(h->kernel));
    ASSERTm("the group is up", firc_ruleset_runtime_enabled(rs));
    harness_stop(h);
    PASS();
}

/* Catches: the bulk PUT dropping a selector when the key is absent, or keeping it on null. */
TEST the_bulk_put_keeps_or_clears_a_selector_like_the_single_put(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"kids\",\"interface\":\"eth0\",\"devices\":{\"allow\":[\"10.0.0.1\"]}}", &out));
    char id[16];
    snprintf(id, sizeof(id), "%s", jstr(out, "id"));
    cJSON_Delete(out);
    char body[256];
    snprintf(body, sizeof(body), "{\"groups\":[{\"id\":\"%s\",\"name\":\"kids\",\"interface\":\"eth0\"}]}", id);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups", body, &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    cJSON *g = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(out, "groups"), 0);
    ASSERT_EQ_FMTm("kept without the key", 1, selector_of(g, "allow", "10.0.0.1"), "%d");
    cJSON_Delete(out);
    snprintf(body, sizeof(body), "{\"groups\":[{\"id\":\"%s\",\"name\":\"kids\",\"interface\":\"eth0\",\"devices\":null}]}", id);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups", body, &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    g = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(out, "groups"), 0);
    ASSERT_EQ_FMTm("cleared on null", 0, selector_of(g, "allow", NULL), "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST put_group_id_mismatch_is_400(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *created = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g1\"}", &created));
    char id[9];
    snprintf(id, sizeof(id), "%s", jstr(created, "id"));
    cJSON_Delete(created);

    char path[64];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", id);
    ASSERT_EQ(400, do_request("PUT", path, "{\"name\":\"x\",\"id\":\"deadbeef\"}", NULL));
    harness_stop(h);
    PASS();
}

TEST delete_group_removes_it(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *created = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g1\"}", &created));
    char id[9];
    snprintf(id, sizeof(id), "%s", jstr(created, "id"));
    cJSON_Delete(created);

    char path[64];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", id);
    ASSERT_EQ(200, do_request("DELETE", path, NULL, NULL));
    ASSERT_EQ(404, do_request("GET", path, NULL, NULL));
    harness_stop(h);
    PASS();
}

TEST put_groups_bulk_replace_reuses_ids_and_validates(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);

    ASSERT_EQ(400, do_request("PUT", "/api/v1/groups", "{}", NULL));

    cJSON *g1 = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"g1\",\"rules\":[{\"type\":\"domain\","
                             "\"rule\":\"example.com\",\"enable\":true}]}",
                             &g1));
    char g1_id[9];
    snprintf(g1_id, sizeof(g1_id), "%s", jstr(g1, "id"));
    char r1_id[9];
    snprintf(r1_id, sizeof(r1_id), "%s", jstr(cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(g1, "rules"), 0), "id"));
    cJSON_Delete(g1);

    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g2\"}", NULL));

    char body[512];
    snprintf(body, sizeof(body),
            "{\"groups\":[{\"id\":\"%s\",\"name\":\"g1-kept\",\"rules\":[{\"id\":\"%s\","
            "\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true}]},{\"name\":\"g3-new\"}]}",
            g1_id, r1_id);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups", body, &out));
    cJSON *groups = cJSON_GetObjectItemCaseSensitive(out, "groups");
    ASSERT_EQ(2, cJSON_GetArraySize(groups));
    ASSERT_STR_EQ("g1-kept", jstr(cJSON_GetArrayItem(groups, 0), "name"));
    ASSERT_STR_EQ(g1_id, jstr(cJSON_GetArrayItem(groups, 0), "id"));
    cJSON *kept_rules = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(groups, 0), "rules");
    ASSERT_STR_EQ(r1_id, jstr(cJSON_GetArrayItem(kept_rules, 0), "id"));
    ASSERT_STR_EQ("g3-new", jstr(cJSON_GetArrayItem(groups, 1), "name"));
    cJSON_Delete(out);

    cJSON *listed = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &listed));
    ASSERT_EQ(2, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(listed, "groups")));
    cJSON_Delete(listed);

    harness_stop(h);
    PASS();
}

TEST rule_crud_roundtrip(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *g = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g1\"}", &g));
    char gid[9];
    snprintf(gid, sizeof(gid), "%s", jstr(g, "id"));
    cJSON_Delete(g);

    char rules_path[64];
    snprintf(rules_path, sizeof(rules_path), "/api/v1/groups/%s/rules", gid);

    cJSON *created = NULL;
    ASSERT_EQ(200, do_request("POST", rules_path,
                             "{\"type\":\"domain\",\"rule\":\"example.com\",\"enable\":true}",
                             &created));
    ASSERT_STR_EQ("example.com", jstr(created, "rule"));
    ASSERT(cJSON_GetObjectItemCaseSensitive(created, "name") == NULL);
    char rid[9];
    snprintf(rid, sizeof(rid), "%s", jstr(created, "id"));
    cJSON_Delete(created);

    char rule_path[80];
    snprintf(rule_path, sizeof(rule_path), "%s/%s", rules_path, rid);

    cJSON *got = NULL;
    ASSERT_EQ(200, do_request("GET", rule_path, NULL, &got));
    ASSERT_STR_EQ("example.com", jstr(got, "rule"));
    cJSON_Delete(got);

    cJSON *updated = NULL;
    ASSERT_EQ(200, do_request("PUT", rule_path,
                             "{\"type\":\"domain\",\"rule\":\"example.org\","
                             "\"enable\":false}",
                             &updated));
    ASSERT_STR_EQ("example.org", jstr(updated, "rule"));
    ASSERT_STR_EQ(rid, jstr(updated, "id"));
    ASSERT(!jbool(updated, "enable"));
    cJSON_Delete(updated);

    char bogus_path[96];
    snprintf(bogus_path, sizeof(bogus_path), "%s/deadbeef", rules_path);
    ASSERT_EQ(404, do_request("GET", bogus_path, NULL, NULL));

    ASSERT_EQ(200, do_request("DELETE", rule_path, NULL, NULL));
    cJSON *after = NULL;
    ASSERT_EQ(200, do_request("GET", rules_path, NULL, &after));
    ASSERT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(after, "rules")));
    cJSON_Delete(after);

    harness_stop(h);
    PASS();
}

TEST put_rules_strict_id_validation(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *g = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"g1\",\"rules\":[{\"type\":\"domain\","
                             "\"rule\":\"example.com\",\"enable\":true}]}",
                             &g));
    char gid[9];
    snprintf(gid, sizeof(gid), "%s", jstr(g, "id"));
    char rid[9];
    snprintf(rid, sizeof(rid), "%s", jstr(cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(g, "rules"), 0), "id"));
    cJSON_Delete(g);

    char rules_path[64];
    snprintf(rules_path, sizeof(rules_path), "/api/v1/groups/%s/rules", gid);

    ASSERT_EQ(400, do_request("PUT", rules_path, "{}", NULL));

    ASSERT_EQ(404, do_request("PUT", rules_path,
                             "{\"rules\":[{\"id\":\"deadbeef\",\"type\":\"domain\","
                             "\"rule\":\"x.com\",\"enable\":true}]}",
                             NULL));

    char body[256];
    snprintf(body, sizeof(body),
            "{\"rules\":[{\"id\":\"%s\",\"type\":\"domain\",\"rule\":\"example.net\","
            "\"enable\":true}]}",
            rid);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", rules_path, body, &out));
    cJSON *rules = cJSON_GetObjectItemCaseSensitive(out, "rules");
    ASSERT_EQ(1, cJSON_GetArraySize(rules));
    ASSERT_STR_EQ(rid, jstr(cJSON_GetArrayItem(rules, 0), "id"));
    ASSERT_STR_EQ("example.net", jstr(cJSON_GetArrayItem(rules, 0), "rule"));
    cJSON_Delete(out);

    harness_stop(h);
    PASS();
}

/* Catches: a PUT rule array the next POST writes past the end of, or an append that loses rules. */
TEST rules_put_then_posted_to_keep_every_rule(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *g = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g1\"}", &g));
    char gid[9];
    snprintf(gid, sizeof(gid), "%s", jstr(g, "id"));
    cJSON_Delete(g);
    char rules_path[64];
    snprintf(rules_path, sizeof(rules_path), "/api/v1/groups/%s/rules", gid);

    ASSERT_EQ(200, do_request("PUT", rules_path,
                             "{\"rules\":[{\"type\":\"domain\",\"rule\":\"a.com\",\"enable\":true},"
                             "{\"type\":\"domain\",\"rule\":\"b.com\",\"enable\":true},"
                             "{\"type\":\"domain\",\"rule\":\"c.com\",\"enable\":true}]}",
                             NULL));
    static const char *const posted[6] = {"d.com", "e.com", "f.com", "g.com", "h.com", "i.com"};
    for (int i = 0; i < 6; i++) {
        char body[96];
        snprintf(body, sizeof(body), "{\"type\":\"domain\",\"rule\":\"%s\",\"enable\":true}", posted[i]);
        ASSERT_EQ(200, do_request("POST", rules_path, body, NULL));
    }

    cJSON *after = NULL;
    ASSERT_EQ(200, do_request("GET", rules_path, NULL, &after));
    cJSON *rules = cJSON_GetObjectItemCaseSensitive(after, "rules");
    static const char *const want[9] = {"a.com", "b.com", "c.com", "d.com", "e.com",
                                        "f.com", "g.com", "h.com", "i.com"};
    ASSERT_EQ(9, cJSON_GetArraySize(rules));
    for (int i = 0; i < 9; i++) { ASSERT_STR_EQ(want[i], jstr(cJSON_GetArrayItem(rules, i), "rule")); }
    cJSON_Delete(after);

    harness_stop(h);
    PASS();
}

TEST rule_created_via_http_is_dns_matchable(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);

    cJSON *g = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"g1\",\"interface\":\"eth0\","
                             "\"rules\":[{\"type\":\"domain\","
                             "\"rule\":\"example.com\",\"enable\":true}]}",
                             &g));
    firc_id_t group_id;
    ASSERT_EQ(FIRC_OK, firc_id_parse(jstr(g, "id"), &group_id));
    cJSON_Delete(g);

    uint8_t name[FIRC_DNS_MAX_NAME + 1];
    size_t name_len = wire_name("example.com", name, sizeof(name));
    ASSERT(name_len > 0);
    uint8_t addr[4] = {93, 184, 216, 34};

    firc_dns_rr_t *rr = calloc(1, sizeof(*rr));
    memcpy(rr->name, name, name_len);
    rr->name_len = name_len;
    rr->rtype = FIRC_DNS_TYPE_A;
    rr->rclass = 1;
    rr->ttl = 9999;
    rr->rdata = malloc(4);
    memcpy(rr->rdata, addr, 4);
    rr->rdata_len = 4;

    firc_dns_question_t q = {{0}, 0, 0, 0};
    memcpy(q.name, name, name_len);
    q.name_len = name_len;
    q.qtype = FIRC_DNS_TYPE_A;
    q.qclass = 1;

    firc_dns_msg_t msg = {0};
    msg.questions = &q;
    msg.n_questions = 1;
    msg.answers = rr;
    msg.n_answers = 1;

    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(h->pipeline, &msg, 0, NULL, NULL));
    ASSERT_EQ_FMT((size_t)1, msg.n_answers, "%zu");
    ASSERT(memcmp(msg.answers[0].rdata, addr, 4) != 0);
    ASSERT(msg.answers[0].name_len == name_len && memcmp(msg.answers[0].name, name, name_len) == 0);
    ASSERT_EQ_FMTm("with the TTL clamped to the pool's", 300u, (unsigned)msg.answers[0].ttl, "%u");
    char gid[FIRC_ID_STR_LEN];
    firc_id_format(group_id, gid);
    firc_ip_t issued = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(h->pool, "example.com", gid, 0, &issued, NULL));
    ASSERT_MEM_EQm("the same address, issued under the group the rule was created in",
                   issued.b, msg.answers[0].rdata, 4);
    for (size_t i = 0; i < msg.n_answers; i++) { free(msg.answers[i].rdata); }
    free(msg.answers);

    harness_stop(h);
    PASS();
}

/* Catches: a disabled group's resolver block listing servers it does not use, or losing its source. */
TEST a_disabled_groups_resolver_lists_no_servers(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3e\",\"name\":\"nl\",\"interface\":\"lo\",\"enable\":false,"
                              "\"resolve\":{\"tunnel\":true,\"server\":\"9.9.9.9\"}}",
                              &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/0a1b2c3e", NULL, &out));
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(out, "enable")));
    cJSON *rv = cJSON_GetObjectItemCaseSensitive(out, "resolver");
    ASSERT_STR_EQ("group", cJSON_GetObjectItemCaseSensitive(rv, "source")->valuestring);
    ASSERT_EQm("disabled: no servers", 0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(rv, "servers")));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3e", "{\"name\":\"nl\",\"interface\":\"lo\",\"enable\":true}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/0a1b2c3e", NULL, &out));
    rv = cJSON_GetObjectItemCaseSensitive(out, "resolver");
    cJSON *servers = cJSON_GetObjectItemCaseSensitive(rv, "servers");
    ASSERT_EQm("enabled: its server", 1, cJSON_GetArraySize(servers));
    ASSERT_STR_EQ("9.9.9.9", cJSON_GetArrayItem(servers, 0)->valuestring);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: `resolve` not answered, defaulted wrongly, dropped by a PUT, or its resolver block wrong. */
TEST a_groups_resolve_round_trips_and_its_resolver_is_shown(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"nwg0\"}", &out));
    cJSON *res = cJSON_GetObjectItemCaseSensitive(out, "resolve");
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(res, "tunnel")));
    ASSERT_STR_EQ("", cJSON_GetObjectItemCaseSensitive(res, "server")->valuestring);
    cJSON *rv = cJSON_GetObjectItemCaseSensitive(out, "resolver");
    ASSERT_STR_EQ("none", cJSON_GetObjectItemCaseSensitive(rv, "source")->valuestring);
    ASSERT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(rv, "servers")));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d",
                              "{\"name\":\"nl\",\"interface\":\"nwg0\",\"resolve\":{\"tunnel\":true,\"server\":\"[2620:fe::fe]:853\"}}",
                              &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"name\":\"renamed\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/0a1b2c3d", NULL, &out));
    res = cJSON_GetObjectItemCaseSensitive(out, "resolve");
    ASSERT_STR_EQ("[2620:fe::fe]:853", cJSON_GetObjectItemCaseSensitive(res, "server")->valuestring);
    rv = cJSON_GetObjectItemCaseSensitive(out, "resolver");
    ASSERT_STR_EQ("group", cJSON_GetObjectItemCaseSensitive(rv, "source")->valuestring);
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"resolve\":{\"tunnel\":false}}", &out));
    res = cJSON_GetObjectItemCaseSensitive(out, "resolve");
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(res, "tunnel")));
    ASSERT_STR_EQ("", cJSON_GetObjectItemCaseSensitive(res, "server")->valuestring);
    ASSERT_STR_EQ("off", cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(out, "resolver"), "source")->valuestring);
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"resolve\":{\"server\":\"1.1.1.1\"}}", &out));
    res = cJSON_GetObjectItemCaseSensitive(out, "resolve");
    ASSERTm("a missing tunnel key defaults to true, even though it was false",
            cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(res, "tunnel")));
    ASSERT_STR_EQ("1.1.1.1", cJSON_GetObjectItemCaseSensitive(res, "server")->valuestring);
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"resolve\":{\"server\":\"\"}}", &out));
    res = cJSON_GetObjectItemCaseSensitive(out, "resolve");
    ASSERT_STR_EQm("an explicit empty server clears it", "", cJSON_GetObjectItemCaseSensitive(res, "server")->valuestring);
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d",
                              "{\"resolve\":{\"tunnel\":false,\"server\":\"9.9.9.9\"}}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"resolve\":null}", &out));
    res = cJSON_GetObjectItemCaseSensitive(out, "resolve");
    ASSERTm("null resets tunnel to true", cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(res, "tunnel")));
    ASSERT_STR_EQm("null resets server to empty", "", cJSON_GetObjectItemCaseSensitive(res, "server")->valuestring);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a list of servers refused or rewritten by the API, or a bad list or a pool entry after the first let through. */
TEST a_resolve_server_list_is_kept_verbatim_and_a_bad_one_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"nwg0\","
                              "\"resolve\":{\"server\":\"1.1.1.1, 9.9.9.9\"}}",
                              &out));
    ASSERT_STR_EQ("1.1.1.1, 9.9.9.9",
                  cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(out, "resolve"), "server")->valuestring);
    cJSON_Delete(out);

    struct { const char *server; const char *named; } bad[] = {
        {"1.1.1.1, dns.google", "\"dns.google\" is not an address literal"},
        {"1.1.1.1,,9.9.9.9", "has an empty entry"},
        {"1.1.1.1,", "has an empty entry"},
        {"1.1.1.1,1.0.0.1,9.9.9.9,8.8.8.8,8.8.4.4", "names more than 4 servers"},
        {"9.9.9.9, 9.9.9.9:53", "names \"9.9.9.9:53\" twice"},
        {"9.9.9.9, 198.19.0.53", "resolve.server \"198.19.0.53\" is inside firc's address pool"},
        {"2620:fe::fe, 2620:fe::9, 2606:4700::1111, 198.19.0.53", "resolve.server \"198.19.0.53\" is inside"},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char body[256];
        snprintf(body, sizeof(body), "{\"resolve\":{\"server\":\"%s\"}}", bad[i].server);
        ASSERT_EQm(bad[i].server, 400, do_request("PUT", "/api/v1/groups/0a1b2c3d", body, &out));
        ASSERT_STR_EQm(bad[i].server, "resolve.server", jstr(out, "field"));
        ASSERTm(jstr(out, "error"), strstr(jstr(out, "error"), bad[i].named) != NULL);
        cJSON_Delete(out);
    }
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/0a1b2c3d", NULL, &out));
    ASSERT_STR_EQm("the refused PUTs changed nothing", "1.1.1.1, 9.9.9.9",
                   cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(out, "resolve"), "server")->valuestring);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a sink or pool resolve server accepted, or refused without naming the field and group. */
TEST a_bad_resolve_server_is_refused_naming_the_field_and_the_group(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    const char *bad[] = {"127.0.0.1", "0.0.0.0", "::1", "dns.google", "9.9.9.9:0", "198.19.0.53"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char body[256];
        snprintf(body, sizeof(body),
                 "{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"nwg0\",\"resolve\":{\"server\":\"%s\"}}", bad[i]);
        cJSON *out = NULL;
        ASSERT_EQm(bad[i], 400, do_request("POST", "/api/v1/groups", body, &out));
        ASSERT_STR_EQm(bad[i], "resolve.server", jstr(out, "field"));
        ASSERT_STR_EQm(bad[i], "0a1b2c3d", jstr(out, "group"));
        ASSERTm(bad[i], strstr(jstr(out, "error"), bad[i]) != NULL);
        cJSON_Delete(out);
    }
    cJSON *out = NULL;
    ASSERT_EQ(400, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3e\",\"name\":\"x\",\"interface\":\"nwg0\",\"resolve\":{\"tunnel\":\"yes\"}}", &out));
    ASSERT_STR_EQ("resolve.tunnel", jstr(out, "field"));
    cJSON_Delete(out);
    ASSERT_EQ(400, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3e\",\"name\":\"x\",\"interface\":\"nwg0\",\"resolve\":\"9.9.9.9\"}", &out));
    ASSERT_STR_EQ("resolve", jstr(out, "field"));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"nwg0\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(400, do_request("PUT", "/api/v1/groups",
                              "{\"groups\":[{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"nwg0\"},"
                              "{\"id\":\"0a1b2c3f\",\"name\":\"de\",\"interface\":\"nwg1\",\"resolve\":{\"server\":\"127.0.0.2\"}}]}",
                              &out));
    ASSERT_STR_EQ("0a1b2c3f", jstr(out, "group"));
    ASSERT_STR_EQ("resolve.server", jstr(out, "field"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    ASSERT_EQm("the refused batch changed nothing", 1, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "groups")));
    cJSON_Delete(out);

    ASSERT_EQ(400, do_request("PUT", "/api/v1/groups",
                              "{\"groups\":[{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"nwg0\"},"
                              "{\"id\":\"0a1b2c3f\",\"name\":\"de\",\"interface\":\"nwg1\",\"resolve\":{\"server\":\"198.19.0.53\"}}]}",
                              &out));
    ASSERT_STR_EQ("0a1b2c3f", jstr(out, "group"));
    ASSERT_STR_EQ("resolve.server", jstr(out, "field"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    ASSERT_EQm("the refused batch (pool address) changed nothing", 1,
              cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "groups")));
    cJSON_Delete(out);

    ASSERT_EQ(400, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"resolve\":{\"server\":\"::\"}}", &out));
    ASSERT_STR_EQ("resolve.server", jstr(out, "field"));
    cJSON_Delete(out);

    ASSERT_EQ(400, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"resolve\":{\"server\":\"198.19.0.53\"}}", &out));
    ASSERT_STR_EQ("resolve.server", jstr(out, "field"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/0a1b2c3d", NULL, &out));
    ASSERT_STR_EQm("the refused single PUT (pool address) changed nothing", "",
                   cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(out, "resolve"), "server")->valuestring);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a refused POST without an id naming the random id the daemon made. */
TEST a_post_with_no_id_names_no_group_in_its_refusal(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(400, do_request("POST", "/api/v1/groups",
                              "{\"name\":\"nl\",\"interface\":\"nwg0\",\"resolve\":{\"server\":\"127.0.0.1\"}}", &out));
    ASSERT_STR_EQ("resolve.server", jstr(out, "field"));
    ASSERT_STR_EQm("no id the client never supplied is echoed back", "", jstr(out, "group"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST a_put_group_keeps_its_route_marked(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3d\",\"name\":\"g\",\"interface\":\"lo\",\"resolve\":{\"server\":\"9.9.9.9\"}}", &out));
    cJSON_Delete(out);
    uint32_t field = installed_group_mark(h);
    ASSERTm("the group got a mark", field != 0);
    firc_id_t id;
    ASSERT_EQ(FIRC_OK, firc_id_parse("0a1b2c3d", &id));
    firc_resolve_route_t r;
    ASSERT(firc_resolve_router_route(h->router, id, &r));
    ASSERT_EQ(field | FIRC_MARK_HANDLED, r.mark);

    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"name\":\"renamed\",\"interface\":\"lo\"}", &out));
    cJSON_Delete(out);
    ASSERT(firc_resolve_router_route(h->router, id, &r));
    ASSERTm("the route carries the mark after the PUT's enable", r.mark != 0);
    ASSERT_EQ(installed_group_mark(h) | FIRC_MARK_HANDLED, r.mark);
    ASSERT_STR_EQ("renamed", r.group_name);
    harness_stop(h);
    PASS();
}

static bool has_key(cJSON *obj, const char *key) {
    return cJSON_GetObjectItemCaseSensitive(obj, key) != NULL;
}

static uint64_t route_gen(harness_t *h, const char *id_str) {
    firc_id_t id;
    firc_resolve_route_t r;
    if (firc_id_parse(id_str, &id) != FIRC_OK || !firc_resolve_router_route(h->router, id, &r)) { return 0; }
    return r.gen;
}

static void plant_health(harness_t *h, const char *id_str, const firc_dnsproxy_health_t *hl) {
    firc_id_t id;
    if (firc_id_parse(id_str, &id) != FIRC_OK) { abort(); }
    firc_dnsproxy_set_group_health_for_test(h->proxy, id, route_gen(h, id_str), hl);
}

static cJSON *group_health(const char *id_str, cJSON **out) {
    char path[64];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", id_str);
    if (do_request("GET", path, NULL, out) != 200) { return NULL; }
    return cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(*out, "resolver"), "health");
}

static double jnum(cJSON *obj, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsNumber(v) ? v->valuedouble : -1;
}

static const firc_dnsproxy_health_t failing = {.total = 37, .fallbacks = 4, .last_ago_ms = 60000, .has_last = true,
                                               .reason = FIRC_DNS_RESOLVER_FALLBACK_TIMEOUT, .resting = true,
                                               .since_ago_ms = 120000};

/* Catches: health read for a group whose resolver is off or has no servers, so old fallbacks still warn. */
TEST group_json_health_zeros_when_off(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"lo\",\"resolve\":{\"server\":\"9.9.9.9\"}}",
                              &out));
    cJSON_Delete(out);
    plant_health(h, "0a1b2c3d", &failing);
    cJSON *hl = group_health("0a1b2c3d", &out);
    ASSERT_EQm("usable: the planted record is read", 4, jnum(hl, "fallbacks"));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/0a1b2c3d", "{\"resolve\":{\"tunnel\":false}}", &out));
    cJSON_Delete(out);
    const char *ids[] = {"0a1b2c3d", "0a1b2c3e"};
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3e\",\"name\":\"bare\",\"interface\":\"lo\"}", &out));
    cJSON_Delete(out);
    for (size_t i = 0; i < 2; i++) {
        plant_health(h, ids[i], &failing);
        hl = group_health(ids[i], &out);
        ASSERT(hl != NULL);
        ASSERT_EQm(ids[i], 600, jnum(hl, "window"));
        ASSERT_EQm(ids[i], 0, jnum(hl, "total"));
        ASSERT_EQm(ids[i], 0, jnum(hl, "fallbacks"));
        ASSERT_EQm(ids[i], 0, jnum(hl, "last"));
        ASSERT_STR_EQm(ids[i], "", or_none(jstr(hl, "reason")));
        ASSERT_FALSEm(ids[i], jbool(hl, "resting"));
        ASSERT(cJSON_IsBool(cJSON_GetObjectItemCaseSensitive(hl, "resting")));
        ASSERT_EQm(ids[i], 0, jnum(hl, "since"));
        cJSON_Delete(out);
    }
    harness_stop(h);
    PASS();
}

/* Catches: last/since not wall clock minus the age, the window or reason wrong, or a stale reason shown. */
TEST group_json_health_wall_times(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"lo\",\"resolve\":{\"server\":\"9.9.9.9\"}}",
                              &out));
    cJSON_Delete(out);
    ASSERTm("the route is published with a generation", route_gen(h, "0a1b2c3d") != 0);
    plant_health(h, "0a1b2c3d", &failing);
    cJSON *hl = group_health("0a1b2c3d", &out);
    ASSERT(hl != NULL);
    ASSERT_EQ(600, jnum(hl, "window"));
    ASSERT_EQ(37, jnum(hl, "total"));
    ASSERT_EQ(4, jnum(hl, "fallbacks"));
    ASSERT_EQ(1792484940, jnum(hl, "last"));
    ASSERT_STR_EQ("fallback_timeout", or_none(jstr(hl, "reason")));
    ASSERT(jbool(hl, "resting"));
    ASSERT_EQ(1792484880, jnum(hl, "since"));
    cJSON_Delete(out);

    firc_dnsproxy_health_t quiet = {.total = 5, .last_ago_ms = 60000, .has_last = false,
                                    .reason = FIRC_DNS_RESOLVER_HEALTH_SKIP, .resting = false, .since_ago_ms = 120000};
    plant_health(h, "0a1b2c3d", &quiet);
    hl = group_health("0a1b2c3d", &out);
    ASSERT(hl != NULL);
    ASSERT_EQ(5, jnum(hl, "total"));
    ASSERT_EQ(0, jnum(hl, "fallbacks"));
    ASSERT_EQm("no fallback in the window: no time", 0, jnum(hl, "last"));
    ASSERT_STR_EQm("no fallback in the window: no reason", "", or_none(jstr(hl, "reason")));
    ASSERT_FALSE(jbool(hl, "resting"));
    ASSERT_EQm("not resting: no since", 0, jnum(hl, "since"));
    cJSON_Delete(out);

    quiet.has_last = true;
    quiet.reason = FIRC_DNS_RESOLVER_HEALTH_SKIP;
    quiet.last_ago_ms = 1500;
    plant_health(h, "0a1b2c3d", &quiet);
    hl = group_health("0a1b2c3d", &out);
    ASSERT_STR_EQ("health_skip", or_none(jstr(hl, "reason")));
    ASSERT_EQm("the age counts in whole seconds", 1792484999, jnum(hl, "last"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: the since-start fallbacks key left beside health. */
TEST group_json_has_no_fallbacks_key(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"id\":\"0a1b2c3d\",\"name\":\"nl\",\"interface\":\"nwg0\"}", &out));
    cJSON *rv = cJSON_GetObjectItemCaseSensitive(out, "resolver");
    ASSERT_FALSE(has_key(rv, "fallbacks"));
    ASSERT(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(rv, "health")));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    rv = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(out, "groups"), 0), "resolver");
    ASSERT_FALSE(has_key(rv, "fallbacks"));
    ASSERT(cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(rv, "health")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a missing live field, a live group with a reason, or GET and POST disagreeing. */
TEST every_group_body_says_whether_it_is_live(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"up\",\"interface\":\"lo\"}", &out));
    ASSERT(jbool(out, "live"));
    ASSERT_FALSEm("a live group carries no reason", has_key(out, "liveReason"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"nowhere\",\"interface\":\"\"}", &out));
    ASSERT(has_key(out, "live") && !jbool(out, "live"));
    ASSERT_STR_EQ("no-interface", jstr(out, "liveReason"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"off\",\"interface\":\"lo\",\"enable\":false}", &out));
    ASSERT_STR_EQ("disabled", jstr(out, "liveReason"));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(out, "groups");
    ASSERT_EQ(3, cJSON_GetArraySize(arr));
    ASSERT(jbool(cJSON_GetArrayItem(arr, 0), "live"));
    ASSERT_STR_EQ("no-interface", jstr(cJSON_GetArrayItem(arr, 1), "liveReason"));
    ASSERT_STR_EQ("disabled", jstr(cJSON_GetArrayItem(arr, 2), "liveReason"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a group body reading a missing or down interface as live, or not following link-up. */
TEST a_group_body_reads_its_interface_link(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"gone\",\"interface\":\"fircabsent0\"}", &out));
    ASSERT_FALSEm("a missing interface is not live", jbool(out, "live"));
    ASSERT_STR_EQ("no-interface", jstr(out, "liveReason"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"up\",\"interface\":\"lo\"}", &out));
    ASSERT(jbool(out, "live"));
    cJSON_Delete(out);

    fake_rtnl_set_link_flags(h->kernel, 0x10);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(out, "groups");
    ASSERT_EQ(2, cJSON_GetArraySize(arr));
    ASSERT_STR_EQ("no-interface", jstr(cJSON_GetArrayItem(arr, 0), "liveReason"));
    ASSERT_FALSEm("a down link is not live", jbool(cJSON_GetArrayItem(arr, 1), "live"));
    ASSERT_STR_EQ("no-interface", jstr(cJSON_GetArrayItem(arr, 1), "liveReason"));
    cJSON_Delete(out);

    fake_rtnl_set_link_flags(h->kernel, 0x1 | 0x10);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    arr = cJSON_GetObjectItemCaseSensitive(out, "groups");
    ASSERT_STR_EQ("no-interface", jstr(cJSON_GetArrayItem(arr, 0), "liveReason"));
    ASSERTm("up again: live", jbool(cJSON_GetArrayItem(arr, 1), "live"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a Save with one failed group answering 500, or a group's field wrong. */
TEST a_save_whose_second_group_fails_answers_200_group_by_group(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    fake_rtnl_fail_after_of(h->kernel, 32 , 1 , 2);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups",
                              "{\"groups\":[{\"name\":\"a\",\"interface\":\"lo\"},"
                              "{\"name\":\"b\",\"interface\":\"lo\"},"
                              "{\"name\":\"c\",\"interface\":\"lo\"}]}",
                              &out));
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(out, "groups");
    ASSERT_EQ(3, cJSON_GetArraySize(arr));
    ASSERT(jbool(cJSON_GetArrayItem(arr, 0), "live"));
    ASSERT_FALSE(jbool(cJSON_GetArrayItem(arr, 1), "live"));
    ASSERT_STR_EQ("not-enabled", jstr(cJSON_GetArrayItem(arr, 1), "liveReason"));
    ASSERT(jbool(cJSON_GetArrayItem(arr, 2), "live"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a failed POST answering the bare error, or keeping the group. */
TEST a_post_that_cannot_come_up_answers_500_naming_the_step(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    fake_rtnl_fail_next_of(h->kernel, 32 , 1 );
    cJSON *out = NULL;
    ASSERT_EQ(500, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char want[FIRC_APP_WHY_MAX];
    snprintf(want, sizeof(want), "group \"g\": ip rule: %s", firc_err_str(firc_err_from_errno(1)));
    ASSERT_STR_EQ(want, jstr(out, "error"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    ASSERT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "groups")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a DELETE answering a teardown error, or keeping the group. */
TEST a_delete_whose_teardown_failed_answers_200(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    fake_rtnl_fail_next_of(h->kernel, 33 , 1 );
    ASSERT_EQ(200, do_request("DELETE", path, NULL, NULL));
    ASSERT_EQ(404, do_request("GET", path, NULL, NULL));
    harness_stop(h);
    PASS();
}

static struct rlimit g_saved_nofile;

static bool no_more_fds(void) {
    if (getrlimit(RLIMIT_NOFILE, &g_saved_nofile) != 0) { return false; }
    int probe = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (probe < 0) { return false; }
    close(probe);
    struct rlimit low = {(rlim_t)probe, g_saved_nofile.rlim_max};
    if (setrlimit(RLIMIT_NOFILE, &low) != 0) { return false; }
    int again = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (again >= 0) { close(again); }
    return again < 0;
}

static int request_without_fds(const char *method, const char *path, const char *body) {
    int fd = connect_tcp(TEST_PORT);
    if (fd < 0) { return -1; }
    char req[2048];
    snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: x\r\nContent-Length: %zu\r\nConnection: close\r\n", method,
             path, strlen(body));
    if (send(fd, req, strlen(req), 0) <= 0) {
        close(fd);
        return -1;
    }
    struct timespec ts = {0, 100000000};
    nanosleep(&ts, NULL);
    if (!no_more_fds()) {
        setrlimit(RLIMIT_NOFILE, &g_saved_nofile);
        close(fd);
        return -1;
    }
    snprintf(req, sizeof(req), "\r\n%s", body);
    ssize_t sent = send(fd, req, strlen(req), 0);
    char resp[4096];
    ssize_t got = sent > 0 ? recv_response(fd, resp, sizeof(resp)) : -1;
    setrlimit(RLIMIT_NOFILE, &g_saved_nofile);
    close(fd);
    return got > 0 ? status_code_of(resp) : -1;
}

/* Catches: a new group or rule given the zero id when no random bytes can be read, or answered 400. */
TEST an_id_that_cannot_be_drawn_answers_500(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"eth0\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s/rules", jstr(out, "id"));
    char group_path[96];
    snprintf(group_path, sizeof(group_path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    const char *rule = "{\"type\":\"domain\",\"rule\":\"a.example\",\"enable\":true}";
    ASSERT_EQm("POST group", 500, request_without_fds("POST", "/api/v1/groups", "{\"name\":\"h\",\"interface\":\"eth0\"}"));
    ASSERT_EQm("PUT groups", 500,
               request_without_fds("PUT", "/api/v1/groups", "{\"groups\":[{\"name\":\"h\",\"interface\":\"eth0\"}]}"));
    ASSERT_EQm("POST rule", 500, request_without_fds("POST", path, rule));
    ASSERT_EQm("PUT rules", 500, request_without_fds("PUT", path, "{\"rules\":[{\"type\":\"domain\",\"rule\":\"a.example\"}]}"));
    ASSERT_EQm("PUT group with a new rule", 500,
               request_without_fds("PUT", group_path, "{\"name\":\"g\",\"rules\":[{\"type\":\"domain\",\"rule\":\"b.example\"}]}"));
    ASSERT_EQ(200, do_request("GET", group_path, NULL, &out));
    ASSERT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "rules")));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    ASSERT_EQ(1, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "groups")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a ?save=true whose write failed answered 200, or the change it carried not applied. */
TEST a_save_that_cannot_be_written_answers_500(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    h->ctx.config_path = "/nonexistent-firc-dir/firc.conf";
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"eth0\"}", &out));
    char group[96], rules_base[96], rules[112];
    snprintf(group, sizeof(group), "/api/v1/groups/%s?save=true", jstr(out, "id"));
    snprintf(rules_base, sizeof(rules_base), "/api/v1/groups/%s/rules", jstr(out, "id"));
    snprintf(rules, sizeof(rules), "%s?save=true", rules_base);
    cJSON_Delete(out);
    const char *rule = "{\"type\":\"domain\",\"rule\":\"a.example\",\"enable\":true}";

    ASSERT_EQm("POST rule", 500, do_request("POST", rules, rule, &out));
    ASSERT(strstr(jstr(out, "error"), "not saved") != NULL);
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", rules_base, NULL, &out));
    cJSON *list = cJSON_GetObjectItemCaseSensitive(out, "rules");
    ASSERTm("the rule is applied all the same", cJSON_GetArraySize(list) == 1);
    char one[160];
    snprintf(one, sizeof(one), "%s/%s?save=true", rules_base, jstr(cJSON_GetArrayItem(list, 0), "id"));
    cJSON_Delete(out);

    ASSERT_EQm("PUT rule", 500, do_request("PUT", one, rule, NULL));
    ASSERT_EQm("DELETE rule", 500, do_request("DELETE", one, NULL, NULL));
    ASSERT_EQm("PUT rules", 500, do_request("PUT", rules, "{\"rules\":[]}", NULL));
    ASSERT_EQm("PUT group", 500, do_request("PUT", group, "{\"name\":\"g2\",\"interface\":\"eth0\"}", NULL));
    ASSERT_EQm("POST group", 500,
               do_request("POST", "/api/v1/groups?save=true", "{\"name\":\"h\",\"interface\":\"eth0\"}", NULL));
    ASSERT_EQm("DELETE group", 500, do_request("DELETE", group, NULL, NULL));
    ASSERT_EQm("PUT groups", 500,
               do_request("PUT", "/api/v1/groups?save=true", "{\"groups\":[{\"name\":\"k\",\"interface\":\"eth0\"}]}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    cJSON *groups = cJSON_GetObjectItemCaseSensitive(out, "groups");
    ASSERT_EQ(1, cJSON_GetArraySize(groups));
    ASSERT_STR_EQ("k", jstr(cJSON_GetArrayItem(groups, 0), "name"));
    cJSON_Delete(out);
    ASSERT_EQm("no save asked, nothing to fail", 200,
               do_request("PUT", "/api/v1/groups", "{\"groups\":[]}", NULL));
    harness_stop(h);
    PASS();
}

/* Stops a harness a failed assertion left running, or its port stays bound for later tests. */
static void stop_live_harness(void *ud) {
    (void)ud;
    if (live_harness != NULL) { harness_stop(live_harness); }
}

TEST the_api_takes_and_answers_an_interface_list(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":[\"nwg0\",\"nwg1\"]}", &out));
    cJSON *ifs = cJSON_GetObjectItemCaseSensitive(out, "interface");
    ASSERT(cJSON_IsArray(ifs));
    ASSERT_EQ(2, cJSON_GetArraySize(ifs));
    ASSERT_STR_EQ("nwg0", cJSON_GetArrayItem(ifs, 0)->valuestring);
    ASSERT_STR_EQ("nwg1", cJSON_GetArrayItem(ifs, 1)->valuestring);
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"h\",\"interface\":[\"nwg2\"]}", &out));
    ASSERT_STR_EQ("nwg2", jstr(out, "interface"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST the_api_refuses_a_bad_interface_list_naming_the_field(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static const char *const bodies[] = {
        "{\"name\":\"g\",\"interface\":[]}",
        "{\"name\":\"g\",\"interface\":[\"nwg0\",\"nwg0\"]}",
        "{\"name\":\"g\",\"interface\":[\"a0\",\"a1\",\"a2\",\"a3\",\"a4\"]}",
        "{\"name\":\"g\",\"interface\":[\"blackhole\",\"nwg0\"]}",
        "{\"name\":\"g\",\"interface\":[\"nwg0\",7]}",
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
        cJSON *out = NULL;
        ASSERT_EQm(bodies[i], 400, do_request("POST", "/api/v1/groups", bodies[i], &out));
        ASSERT_STR_EQm(bodies[i], "interface", jstr(out, "field"));
        cJSON_Delete(out);
    }
    harness_stop(h);
    PASS();
}

/* Catches: block shown for a routing group, or a block group's answer not stored or not shown. */
TEST a_block_groups_answer_round_trips_and_is_shown(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"b\",\"interface\":\"block\",\"block\":\"nxdomain\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_STR_EQ("nxdomain", jstr(out, "block"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"r\",\"interface\":\"nwg0\"}", &out));
    ASSERT(cJSON_GetObjectItemCaseSensitive(out, "block") == NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: group_move_into leaving block out, so any other edit resets the answer. */
TEST an_update_keeps_the_answer(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"b\",\"interface\":\"block\",\"block\":\"nxdomain\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"renamed\",\"interface\":\"block\"}", &out));
    ASSERT_STR_EQ("nxdomain", jstr(out, "block"));
    cJSON_Delete(out);
    ASSERT_EQ(FIRC_BLOCK_NXDOMAIN, firc_ruleset_group(only_group(h))->block);
    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"renamed\",\"interface\":\"block\",\"block\":\"null\"}", &out));
    ASSERT_STR_EQ("null", jstr(out, "block"));
    cJSON_Delete(out);
    ASSERT_EQ(FIRC_BLOCK_NULL, firc_ruleset_group(only_group(h))->block);
    harness_stop(h);
    PASS();
}

/* Catches: a stale block key on a group that routes failing the save, or being stored. */
TEST a_block_key_on_a_routing_group_is_ignored_by_the_api(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"nwg0\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"g\",\"interface\":\"nwg0\",\"block\":\"refused\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT(cJSON_GetObjectItemCaseSensitive(out, "block") == NULL);
    cJSON_Delete(out);
    ASSERT_EQ(FIRC_BLOCK_NULL, firc_ruleset_group(only_group(h))->block);
    harness_stop(h);
    PASS();
}

/* Catches: a bad answer stored, or block allowed inside an interface list through the API. */
TEST the_api_refuses_a_bad_block_answer_and_block_in_a_list(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static const char *const bodies[] = {
        "{\"name\":\"g\",\"interface\":\"block\",\"block\":\"nxdomian\"}",
        "{\"name\":\"g\",\"interface\":\"block\",\"block\":7}",
        "{\"name\":\"g\",\"interface\":\"block\",\"block\":[\"nxdomain\"]}",
    };
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++) {
        cJSON *out = NULL;
        ASSERT_EQm(bodies[i], 400, do_request("POST", "/api/v1/groups", bodies[i], &out));
        ASSERT_STR_EQm(bodies[i], "block", jstr(out, "field"));
        cJSON_Delete(out);
    }
    cJSON *out = NULL;
    ASSERT_EQ(400, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":[\"block\",\"nwg0\"]}", &out));
    ASSERT_STR_EQ("interface", jstr(out, "field"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

static firc_err_t g_move_up_answer;
static int g_move_up_calls;
static firc_id_t g_move_up_id;
static firc_err_t stub_move_up(void *ud, firc_id_t id) {
    (void)ud;
    g_move_up_id = id;
    g_move_up_calls++;
    return g_move_up_answer;
}
static bool stub_view(void *ud, const char *name, firc_if_view_t *out) {
    (void)ud;
    if (strcmp(name, "nwg4") == 0) {
        out->state = FIRC_IF_ALIVE;
        out->since_unix = 7;
        snprintf(out->error, sizeof(out->error), "junk");
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->state = strcmp(name, "nwg1") == 0 ? FIRC_IF_DEAD : FIRC_IF_ALIVE;
    out->since_unix = 1790000000;
    snprintf(out->error, sizeof(out->error), "%s", strcmp(name, "nwg1") == 0 ? "timed out" : "");
    return true;
}

TEST a_list_group_answers_its_active_entry_and_entry_states(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_app_ifaces_t hooks = {.view = stub_view, .move_up = stub_move_up};
    firc_app_set_ifaces(h->app, &hooks);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":[\"nwg1\",\"nwg2\",\"nwg4\"]}", &out));
    ASSERT_STR_EQ("nwg1", jstr(out, "active"));
    cJSON *ifs = cJSON_GetObjectItemCaseSensitive(out, "interfaces");
    ASSERT_EQ(3, cJSON_GetArraySize(ifs));
    ASSERT_STR_EQ("nwg1", jstr(cJSON_GetArrayItem(ifs, 0), "name"));
    ASSERT_STR_EQ("dead", jstr(cJSON_GetArrayItem(ifs, 0), "state"));
    ASSERT_STR_EQ("timed out", jstr(cJSON_GetArrayItem(ifs, 0), "error"));
    ASSERT_EQ(1790000000.0, cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(ifs, 0), "since")->valuedouble);
    ASSERT_STR_EQ("nwg2", jstr(cJSON_GetArrayItem(ifs, 1), "name"));
    ASSERT_STR_EQ("alive", jstr(cJSON_GetArrayItem(ifs, 1), "state"));
    ASSERT_STR_EQ("", jstr(cJSON_GetArrayItem(ifs, 1), "error"));
    ASSERT_STR_EQ("nwg4", jstr(cJSON_GetArrayItem(ifs, 2), "name"));
    ASSERT_STR_EQ("unknown", jstr(cJSON_GetArrayItem(ifs, 2), "state"));
    ASSERT_STR_EQ("", jstr(cJSON_GetArrayItem(ifs, 2), "error"));
    ASSERT_EQ(0.0, cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(ifs, 2), "since")->valuedouble);
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"h\",\"interface\":\"nwg3\"}", &out));
    ASSERT_STR_EQ("nwg3", jstr(out, "active"));
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "interfaces"));
    cJSON_Delete(out);
    firc_app_set_ifaces(h->app, NULL);
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups", NULL, &out));
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(out, "groups");
    ifs = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(arr, 0), "interfaces");
    ASSERT_EQ(3, cJSON_GetArraySize(ifs));
    ASSERT_STR_EQm("no watcher: every entry unknown", "unknown", jstr(cJSON_GetArrayItem(ifs, 0), "state"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

static unsigned listed_links(const char *name) {
    if (strcmp(name, "up0") == 0) { return 7; }
    if (strcmp(name, "up1") == 0) { return 8; }
    return 0;
}

TEST a_group_moved_to_its_second_entry_answers_it_as_active(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    firc_rtnl_set_nametoindex_for_test(listed_links);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0000ac03\",\"name\":\"g\",\"interface\":[\"up0\",\"up1\"]}", &out));
    ASSERT(jbool(out, "live"));
    ASSERT_STR_EQ("up0", jstr(out, "active"));
    cJSON_Delete(out);
    firc_id_t id;
    ASSERT_EQ(FIRC_OK, firc_id_parse("0000ac03", &id));
    ASSERT_EQ(FIRC_OK, firc_app_move_group(h->app, id, 1, false));
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/0000ac03", NULL, &out));
    firc_rtnl_set_nametoindex_for_test(NULL);
    ASSERT_STR_EQ("up1", jstr(out, "active"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

static int move_up_status(const char *id, char *error, size_t cap) {
    char path[64];
    snprintf(path, sizeof(path), "/api/v1/groups/%s/move-up", id);
    cJSON *out = NULL;
    int status = do_request("POST", path, NULL, &out);
    const char *e = jstr(out, "error");
    snprintf(error, cap, "%s", e != NULL ? e : "");
    cJSON_Delete(out);
    return status;
}

TEST move_up_asks_the_watcher_for_the_group_and_names_each_refusal(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    firc_rtnl_set_nametoindex_for_test(listed_links);
    firc_app_ifaces_t hooks = {.view = stub_view, .move_up = stub_move_up};
    firc_app_set_ifaces(h->app, &hooks);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0000ac01\",\"name\":\"g\",\"interface\":[\"up0\",\"up1\"]}", &out));
    ASSERT(jbool(out, "live"));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"id\":\"0000ac02\",\"name\":\"h\",\"interface\":\"up0\"}", &out));
    cJSON_Delete(out);
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"0000ac04\",\"name\":\"off\",\"interface\":[\"up0\",\"up1\"],\"enable\":false}",
                              &out));
    cJSON_Delete(out);
    firc_id_t want;
    ASSERT_EQ(FIRC_OK, firc_id_parse("0000ac01", &want));
    char error[128];

    g_move_up_calls = 0;
    memset(&g_move_up_id, 0, sizeof(g_move_up_id));
    g_move_up_answer = FIRC_OK;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups/0000ac01/move-up", NULL, &out));
    ASSERT_STR_EQ("0000ac01", jstr(out, "id"));
    cJSON_Delete(out);
    ASSERT_EQ(1, g_move_up_calls);
    ASSERTm("the watcher is asked to move this group", firc_id_equal(want, g_move_up_id));

    g_move_up_answer = FIRC_ERR_STATE;
    ASSERT_EQ(409, move_up_status("0000ac01", error, sizeof(error)));
    ASSERT_STR_EQ("up0 is not alive", error);
    g_move_up_answer = FIRC_ERR_AGAIN;
    ASSERT_EQ(409, move_up_status("0000ac01", error, sizeof(error)));
    ASSERT_STR_EQ("the group is not routed", error);
    g_move_up_answer = FIRC_ERR_NOENT;
    ASSERT_EQ(409, move_up_status("0000ac01", error, sizeof(error)));
    ASSERT_STR_EQ("no check runs for the group", error);
    g_move_up_answer = FIRC_ERR_NOMEM;
    ASSERT_EQ(500, move_up_status("0000ac01", error, sizeof(error)));

    g_move_up_calls = 0;
    g_move_up_answer = FIRC_OK;
    ASSERT_EQ(409, move_up_status("0000ac04", error, sizeof(error)));
    ASSERT_STR_EQ("the group is not routed", error);
    ASSERT_EQ(404, move_up_status("0000ac09", error, sizeof(error)));
    ASSERT_EQ(400, move_up_status("nothex!", error, sizeof(error)));
    ASSERT_EQ(400, move_up_status("0000ac02", error, sizeof(error)));
    ASSERT_STR_EQ("the group names one interface", error);
    ASSERT_EQm("a refused request never reaches the watcher", 0, g_move_up_calls);

    firc_app_set_ifaces(h->app, NULL);
    ASSERT_EQ(409, move_up_status("0000ac01", error, sizeof(error)));
    ASSERT_STR_EQ("no check runs for the group", error);
    firc_rtnl_set_nametoindex_for_test(NULL);
    harness_stop(h);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(stop_live_harness, NULL);
    RUN_TEST(get_groups_starts_empty);
    RUN_TEST(the_api_takes_and_answers_an_interface_list);
    RUN_TEST(a_put_moves_a_live_group_between_list_lengths_both_ways);
    RUN_TEST(the_api_refuses_a_bad_interface_list_naming_the_field);
    RUN_TEST(a_block_groups_answer_round_trips_and_is_shown);
    RUN_TEST(an_update_keeps_the_answer);
    RUN_TEST(a_block_key_on_a_routing_group_is_ignored_by_the_api);
    RUN_TEST(the_api_refuses_a_bad_block_answer_and_block_in_a_list);
    RUN_TEST(a_list_group_answers_its_active_entry_and_entry_states);
    RUN_TEST(a_group_moved_to_its_second_entry_answers_it_as_active);
    RUN_TEST(move_up_asks_the_watcher_for_the_group_and_names_each_refusal);
    RUN_TEST(create_group_defaults_enable);
    RUN_TEST(get_group_unknown_and_invalid_id);
    RUN_TEST(put_group_updates_fields_and_keeps_rules_when_absent);
    RUN_TEST(a_groups_device_selector_round_trips_through_the_api);
    RUN_TEST(a_put_replaces_keeps_or_clears_the_selector);
    RUN_TEST(the_api_stores_and_answers_a_mac_entry_canonical);
    RUN_TEST(a_bad_device_entry_is_refused_naming_the_field_and_the_group);
    RUN_TEST(a_refused_put_leaves_the_group_in_the_kernel);
    RUN_TEST(a_rule_the_daemon_cannot_use_is_refused);
    RUN_TEST(proto_and_ports_are_kept_or_refused);
    RUN_TEST(a_rules_comment_round_trips_through_the_api);
    RUN_TEST(request_autolist_field_is_ignored);
    RUN_TEST(put_rule_switch_off_drops_marker);
    RUN_TEST(put_rule_same_keeps_marker);
    RUN_TEST(put_rules_edit_pattern_drops_marker);
    RUN_TEST(put_group_untouched_rules_keep_markers);
    RUN_TEST(put_groups_switch_drops_marker);
    RUN_TEST(put_routes_carry_the_by_domain_flag);
    RUN_TEST(a_comment_with_a_newline_or_257_bytes_is_400);
    RUN_TEST(a_comment_of_exactly_256_bytes_is_kept);
    RUN_TEST(an_unusable_rule_names_the_group_and_the_rule);
    RUN_TEST(an_unusable_rule_on_the_rule_endpoint_names_the_rule);
    RUN_TEST(an_empty_pattern_is_named_by_its_position);
    RUN_TEST(the_bulk_rules_put_names_the_group_and_the_rule);
    RUN_TEST(replacing_one_rule_with_an_unusable_one_names_it);
    RUN_TEST(a_put_that_omits_the_name_still_names_the_group);
    RUN_TEST(a_long_name_is_cut_at_a_character_boundary);
    RUN_TEST(a_long_type_is_cut_at_a_character_boundary);
    RUN_TEST(appending_an_empty_pattern_is_named_by_the_row_it_would_become);
    RUN_TEST(replacing_a_rule_with_an_empty_pattern_names_the_row_replaced);
    RUN_TEST(a_pattern_too_long_to_quote_whole_is_marked_as_cut);
    RUN_TEST(an_unknown_type_is_echoed_back);
    RUN_TEST(the_rules_the_daemon_can_use_are_still_accepted);
    RUN_TEST(renaming_a_group_keeps_the_flows_it_is_steering);
    RUN_TEST(deleting_a_group_drops_the_flows_it_was_steering);
    RUN_TEST(a_put_whose_teardown_was_refused_still_brings_the_group_up);
    RUN_TEST(the_bulk_put_keeps_or_clears_a_selector_like_the_single_put);
    RUN_TEST(put_group_id_mismatch_is_400);
    RUN_TEST(delete_group_removes_it);
    RUN_TEST(put_groups_bulk_replace_reuses_ids_and_validates);
    RUN_TEST(rule_crud_roundtrip);
    RUN_TEST(put_rules_strict_id_validation);
    RUN_TEST(rules_put_then_posted_to_keep_every_rule);
    RUN_TEST(rule_created_via_http_is_dns_matchable);
    RUN_TEST(a_groups_resolve_round_trips_and_its_resolver_is_shown);
    RUN_TEST(a_disabled_groups_resolver_lists_no_servers);
    RUN_TEST(a_resolve_server_list_is_kept_verbatim_and_a_bad_one_refused);
    RUN_TEST(a_bad_resolve_server_is_refused_naming_the_field_and_the_group);
    RUN_TEST(a_post_with_no_id_names_no_group_in_its_refusal);
    RUN_TEST(a_put_group_keeps_its_route_marked);
    RUN_TEST(group_json_health_zeros_when_off);
    RUN_TEST(group_json_health_wall_times);
    RUN_TEST(group_json_has_no_fallbacks_key);
    RUN_TEST(every_group_body_says_whether_it_is_live);
    RUN_TEST(a_group_body_reads_its_interface_link);
    RUN_TEST(a_save_whose_second_group_fails_answers_200_group_by_group);
    RUN_TEST(a_post_that_cannot_come_up_answers_500_naming_the_step);
    RUN_TEST(a_delete_whose_teardown_failed_answers_200);
    RUN_TEST(an_id_that_cannot_be_drawn_answers_500);
    RUN_TEST(a_save_that_cannot_be_written_answers_500);
    GREATEST_MAIN_END();
}
