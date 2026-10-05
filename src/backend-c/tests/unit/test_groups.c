#include "greatest.h"
#include "fake_conntrack.h"
#include "fake_iptables.h"
#include "fake_rtnl.h"
#include "firc/netfilter_cleaner.h"
#include "firc/ruleset.h"

#include <arpa/inet.h>
#include <pthread.h>
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
#include "firc/mark.h"
#include "firc/fakeip.h"
#include "firc/groups.h"
#include "firc/loop.h"
#include "firc/resolveroute.h"

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    firc_config_t cfg;
    firc_dns_pipeline_t *pipeline;
    firc_fakeip_t *pool;
    firc_app_t *app;
    firc_groups_ctx_t ctx;
    firc_resolve_router_t *router;
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
    firc_app_deps_t deps = {.cfg = &h->cfg, .pipeline = h->pipeline, .pool = h->pool, .router = h->router};
    if (kernels) {
        h->fipt = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
        h->ipt = firc_ipt_new(firc_fake_ipt_as_executable(h->fipt));
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

    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
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
    firc_loop_destroy(h->loop);
    firc_app_destroy(h->app);
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

TEST put_group_updates_fields_and_keeps_rules_when_absent(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *created = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                             "{\"name\":\"g1\",\"interface\":\"eth0\","
                             "\"rules\":[{\"type\":\"domain\",\"rule\":\"example.com\","
                             "\"enable\":true}]}",
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

/* Catches: an interface change keeping flows that the old interface still carries. */
TEST pointing_a_group_at_another_interface_drops_its_flows(void) {
    harness_t *h = harness_start_with_kernels(true);
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g\",\"interface\":\"lo\"}", &out));
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", jstr(out, "id"));
    cJSON_Delete(out);
    uint32_t mark = installed_group_mark(h);
    ASSERTm("the group got a mark", mark != 0);
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5};
    const uint8_t ours[4] = {198, 18, 0, 5}, theirs[4] = {8, 8, 8, 8};
    fake_ct_add(h->ctk, AF_INET, src, dst, ours, mark | FIRC_MARK_HANDLED);
    fake_ct_add(h->ctk, AF_INET, src, dst, theirs, 0);

    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"g\",\"interface\":\"eth0\"}", &out));
    cJSON_Delete(out);
    ASSERTm("the group's flow went", fake_ct_deleted(h->ctk, ours, 4));
    ASSERTm("nobody else's did", !fake_ct_deleted(h->ctk, theirs, 4));
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
    ASSERT_EQ(0, cJSON_GetObjectItemCaseSensitive(rv, "fallbacks")->valueint);
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

/* Stops a harness a failed assertion left running, or its port stays bound for later tests. */
static void stop_live_harness(void *ud) {
    (void)ud;
    if (live_harness != NULL) { harness_stop(live_harness); }
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(stop_live_harness, NULL);
    RUN_TEST(get_groups_starts_empty);
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
    RUN_TEST(pointing_a_group_at_another_interface_drops_its_flows);
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
    RUN_TEST(a_bad_resolve_server_is_refused_naming_the_field_and_the_group);
    RUN_TEST(a_post_with_no_id_names_no_group_in_its_refusal);
    RUN_TEST(a_put_group_keeps_its_route_marked);
    RUN_TEST(every_group_body_says_whether_it_is_live);
    RUN_TEST(a_group_body_reads_its_interface_link);
    RUN_TEST(a_save_whose_second_group_fails_answers_200_group_by_group);
    RUN_TEST(a_post_that_cannot_come_up_answers_500_naming_the_step);
    RUN_TEST(a_delete_whose_teardown_failed_answers_200);
    GREATEST_MAIN_END();
}
