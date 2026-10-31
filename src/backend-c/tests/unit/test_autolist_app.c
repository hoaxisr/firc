#include "greatest.h"

#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "fake_iptables.h"
#include "fake_nflog.h"
#include "firc/autolistcand.h"
#include "firc/autolistprobes.h"
#include "firc/autolistrules.h"
#include "firc/dnspipeline.h"
#include "firc/log.h"
#include "firc/netfilter_cleaner.h"
#include "firc/system.h"
#include "firc/yamlio.h"

static uint16_t g_tcp_port;

typedef struct {
    firc_config_t cfg;
    firc_fakeip_t *pool;
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
    firc_dns_pipeline_t *pipeline;
    firc_app_t *app;
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    firc_system_ctx_t system_ctx;
    pthread_t th;
} rig_t;

static fake_nflog_t *g_kernel[6];

static firc_nflog_t *fake_open(uint16_t group, uint16_t copy_range) {
    int w = group - FIRC_AUTOLIST_GROUP_HELLO;
    if (w < 0 || w > 5) { return NULL; }
    fake_nflog_stop(g_kernel[w]);
    int fd = -1;
    g_kernel[w] = fake_nflog_start(&fd);
    if (g_kernel[w] == NULL) { return NULL; }
    return firc_nflog_open_fd(fd, group, copy_range);
}

static void kernels_stop(void) {
    for (int w = 0; w < 6; w++) {
        fake_nflog_stop(g_kernel[w]);
        g_kernel[w] = NULL;
    }
}

static _Atomic int64_t g_now;
static int64_t fake_wall(void) { return atomic_load(&g_now); }

typedef struct {
    char host[FIRC_AUTOLIST_NAME_MAX];
    firc_autolist_result_t result;
} plan_t;

static pthread_mutex_t g_probed_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_probed[64][FIRC_AUTOLIST_NAME_MAX];
static size_t g_n_probed;
static plan_t g_plan[8];
static size_t g_n_plan;
static _Atomic bool g_gate_closed;
static _Atomic int g_running, g_max_running;

static void plan(const char *host, uint8_t verdict, uint8_t why, bool short_body, uint32_t bytes) {
    pthread_mutex_lock(&g_probed_mu);
    size_t i = 0;
    while (i < g_n_plan && strcmp(g_plan[i].host, host) != 0) { i++; }
    if (i == g_n_plan && g_n_plan < 8) { g_n_plan++; }
    if (i < 8) {
        memset(&g_plan[i], 0, sizeof(g_plan[i]));
        snprintf(g_plan[i].host, sizeof(g_plan[i].host), "%s", host);
        g_plan[i].result.verdict = verdict;
        g_plan[i].result.why = why;
        g_plan[i].result.short_body = short_body;
        g_plan[i].result.bytes = bytes;
    }
    pthread_mutex_unlock(&g_probed_mu);
}

static void plan_wan_unreachable(const char *host) {
    plan(host, FIRC_AUTOLIST_UNKNOWN, 0, false, 0);
    pthread_mutex_lock(&g_probed_mu);
    for (size_t i = 0; i < g_n_plan; i++) {
        if (strcmp(g_plan[i].host, host) == 0) { g_plan[i].result.wan_unreachable = true; }
    }
    pthread_mutex_unlock(&g_probed_mu);
}

static char g_wan_url[513];
static bool g_wan_204;
static firc_autolist_net_t g_pools[FIRC_AUTOLIST_POOLS];
static size_t g_n_pools;

static void fake_probe(const char *host, const firc_autolist_check_opts_t *o, _Atomic bool *stop,
                       firc_autolist_result_t *out) {
    pthread_mutex_lock(&g_probed_mu);
    snprintf(g_wan_url, sizeof(g_wan_url), "%s", o->wan_url);
    g_wan_204 = o->wan_expects_204;
    memcpy(g_pools, o->pools, sizeof(g_pools));
    g_n_pools = o->n_pools;
    pthread_mutex_unlock(&g_probed_mu);
    int now_running = atomic_fetch_add(&g_running, 1) + 1;
    int seen = atomic_load(&g_max_running);
    while (now_running > seen && !atomic_compare_exchange_weak(&g_max_running, &seen, now_running)) {}
    while (atomic_load(&g_gate_closed) && !atomic_load(stop)) { nanosleep(&(struct timespec){0, 1000000}, NULL); }
    pthread_mutex_lock(&g_probed_mu);
    if (g_n_probed < 64) { snprintf(g_probed[g_n_probed++], FIRC_AUTOLIST_NAME_MAX, "%s", host); }
    bool planned = false;
    for (size_t i = 0; i < g_n_plan && !planned; i++) {
        if (strcmp(g_plan[i].host, host) == 0) {
            *out = g_plan[i].result;
            planned = true;
        }
    }
    pthread_mutex_unlock(&g_probed_mu);
    if (!planned) {
        out->verdict = strcmp(host, "www.up.example") == 0 ? FIRC_AUTOLIST_REACHABLE : FIRC_AUTOLIST_BLOCKED;
        out->why = out->verdict == FIRC_AUTOLIST_BLOCKED ? FIRC_AL_WHY_NO_ANSWER : 0;
    }
    snprintf(out->error, sizeof(out->error), "fake");
    atomic_fetch_sub(&g_running, 1);
}

static bool probed(const char *host) {
    bool found = false;
    pthread_mutex_lock(&g_probed_mu);
    for (size_t i = 0; i < g_n_probed; i++) { found = found || strcmp(g_probed[i], host) == 0; }
    pthread_mutex_unlock(&g_probed_mu);
    return found;
}

static size_t n_probed(void) {
    pthread_mutex_lock(&g_probed_mu);
    size_t n = g_n_probed;
    pthread_mutex_unlock(&g_probed_mu);
    return n;
}

static void *loop_thread(void *ud) {
    firc_loop_run((firc_loop_t *)ud);
    return NULL;
}

typedef struct {
    const char *mode;
    const char *app_extra;
    const char *iface;
    const char *group_extra;
    int marked;
    int threshold;
    const char *app_more;
    const char *conf_path;
    const char *groups;
    const uint8_t *pool4;
    bool no_check_url;
} setup_t;

static const char RULES[] =
    "    rules:\n"
    "      - {id: 00000001, type: namespace, rule: up.example, enable: true, autolist: www.up.example}\n"
    "      - {id: 00000002, type: namespace, rule: down.example, enable: true, autolist: down.example}\n"
    "      - {id: 00000003, type: namespace, rule: hand.example, enable: true}\n"
    "      - {id: 00000004, type: namespace, rule: off.example, enable: false, autolist: off.example}\n";

static bool rig_up_with(rig_t *r, const setup_t *su) {
    static int nth = 0;
    g_tcp_port = (uint16_t)(18399 + ++nth);
    memset(r, 0, sizeof(*r));
    g_n_probed = 0;
    g_n_plan = 0;
    atomic_store(&g_gate_closed, false);
    atomic_store(&g_running, 0);
    atomic_store(&g_max_running, 0);
    atomic_store(&g_now, 1800000000);
    static char config[16384];
    int used = snprintf(config, sizeof(config),
             "configVersion: 0.99.0\n"
             "app:\n"
             "  link: [br0]\n"
             "%s"
             "  autolist: {enabled: true, group: 0a0b0c0d, mode: %s, failThreshold: %d, recheck: true, "
             "recheckInterval: 1h%s}\n",
             su->app_more != NULL ? su->app_more : "", su->mode != NULL ? su->mode : "candidates",
             su->threshold != 0 ? su->threshold : 2, su->app_extra != NULL ? su->app_extra : "");
    if (su->groups != NULL && used > 0 && (size_t)used < sizeof(config)) {
        used += snprintf(config + used, sizeof(config) - (size_t)used, "%s", su->groups);
    } else if (used > 0 && (size_t)used < sizeof(config)) {
        used += snprintf(config + used, sizeof(config) - (size_t)used,
                         "groups:\n"
                         "  - id: 0a0b0c0d\n"
                         "    name: Autolist\n"
                         "    interface: %s\n"
                         "    enable: true\n"
                         "%s%s",
                         su->iface != NULL ? su->iface : "nwg9", su->group_extra != NULL ? su->group_extra : "",
                         RULES);
    }
    for (int i = 0; i < su->marked && used > 0 && (size_t)used < sizeof(config); i++) {
        used += snprintf(config + used, sizeof(config) - (size_t)used,
                         "      - {id: %08x, type: namespace, rule: r%d.example, enable: true, autolist: r%d.example}\n",
                         0x100 + i, i, i);
    }
    if (firc_config_init_defaults(&r->cfg) != FIRC_OK) { return false; }
    if (firc_config_load_buffer(&r->cfg, config, strlen(config)) != FIRC_OK) { return false; }
    if (su->no_check_url && firc_strset(&r->cfg.app.check.url, "") != FIRC_OK) { return false; }
    firc_fakeip_cfg_t pc = {0};
    pc.v4.base.len = 4; pc.v4.base.b[0] = 198; pc.v4.base.b[1] = 18;
    pc.v4.pool_cidr = 15; pc.v4.chunk_cidr = 24;
    if (su->pool4 != NULL) {
        memcpy(pc.v4.base.b, su->pool4, 4);
        pc.v4.pool_cidr = 16;
    }
    pc.v6.base.len = 16; pc.v6.base.b[0] = 0xfd; pc.v6.base.b[1] = 0x37;
    pc.v6.pool_cidr = 48; pc.v6.chunk_cidr = 64;
    pc.max_names = 64; pc.idle_secs = 86400; pc.clamp_secs = 300;
    if (firc_fakeip_new(&pc, &r->pool) != FIRC_OK) { return false; }
    r->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    r->ipt = firc_ipt_new(firc_fake_ipt_as_xt(r->fake), "FIRC_");
    firc_netfilter_register_base_chains(r->ipt, NULL);
    r->pipeline = firc_dns_pipeline_create();
    if (firc_loop_create(&r->loop) != FIRC_OK) { return false; }
    firc_app_deps_t deps = {.cfg = &r->cfg, .ipt4 = r->ipt, .pool = r->pool, .loop = r->loop,
                            .pipeline = r->pipeline, .nflog_open = fake_open, .wall_s = fake_wall,
                            .config_path = su->conf_path};
    r->app = firc_app_create(&deps);
    if (r->app == NULL) { return false; }
    if (firc_app_republish_dns_snapshot(r->app) != FIRC_OK) { return false; }
    firc_app_set_autolist_probe_for_test(r->app, fake_probe);
    if (firc_app_autolist_apply(r->app) != FIRC_OK) { return false; }
    if (firc_httpd_create(r->loop, &r->tcp) != FIRC_OK) { return false; }
    r->system_ctx.app = r->app;
    firc_system_register_routes(r->tcp, &r->system_ctx);
    if (firc_httpd_listen_tcp(r->tcp, "127.0.0.1", g_tcp_port) != FIRC_OK) { return false; }
    return pthread_create(&r->th, NULL, loop_thread, r->loop) == 0;
}

static bool rig_up(rig_t *r) {
    setup_t su = {0};
    return rig_up_with(r, &su);
}

static void rig_stop_loop(rig_t *r) {
    firc_loop_stop(r->loop);
    pthread_join(r->th, NULL);
}

static void rig_down(rig_t *r) {
    firc_httpd_destroy(r->tcp);
    firc_app_destroy(r->app);
    kernels_stop();
    firc_ipt_free(r->ipt);
    firc_fakeip_free(r->pool);
    firc_loop_destroy(r->loop);
    firc_dns_pipeline_destroy(r->pipeline);
    firc_config_clear(&r->cfg);
}

static int request_body(const char *method, const char *path, const char *body, char *out, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(g_tcp_port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    bool connected = false;
    for (int i = 0; i < 100 && !connected; i++) {
        connected = connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
        if (!connected) {
            struct timespec ts = {0, 10000000};
            nanosleep(&ts, NULL);
        }
    }
    if (!connected) {
        close(fd);
        return -1;
    }
    char req[1024];
    int n = body != NULL ? snprintf(req, sizeof(req),
                                    "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: "
                                    "application/json\r\nContent-Length: %zu\r\n\r\n%s",
                                    method, path, strlen(body), body)
                         : snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                                    method, path);
    if (write(fd, req, (size_t)n) != n) {
        close(fd);
        return -1;
    }
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t total = 0;
    for (;;) {
        ssize_t got = read(fd, out + total, cap - 1 - total);
        if (got <= 0) { break; }
        total += (size_t)got;
        if (total >= cap - 1) { break; }
    }
    close(fd);
    out[total] = '\0';
    int code = 0;
    sscanf(out, "HTTP/1.1 %d", &code);
    return code;
}

static int request(const char *method, const char *path, char *out, size_t cap) {
    return request_body(method, path, NULL, out, cap);
}

static char g_buf[1 << 18];

static cJSON *status(void) {
    if (request("GET", "/api/v1/system/autolist", g_buf, sizeof(g_buf)) != 200) { return NULL; }
    const char *json = strstr(g_buf, "\r\n\r\n");
    return json != NULL ? cJSON_Parse(json + 4) : NULL;
}

static const cJSON *candidate(const cJSON *st, const char *domain) {
    const cJSON *c;
    cJSON_ArrayForEach(c, cJSON_GetObjectItemCaseSensitive(st, "candidates")) {
        const cJSON *d = cJSON_GetObjectItemCaseSensitive(c, "domain");
        if (cJSON_IsString(d) && strcmp(d->valuestring, domain) == 0) { return c; }
    }
    return NULL;
}

static const char *str_of(const cJSON *o, const char *key) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    return cJSON_IsString(v) ? v->valuestring : "";
}

static double num_of(const cJSON *o, const char *key) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    return cJSON_IsNumber(v) ? v->valuedouble : -1;
}

static const cJSON *probes_of(const cJSON *st) { return cJSON_GetObjectItemCaseSensitive(st, "probes"); }

typedef bool (*pred_fn)(const cJSON *st, const void *arg);

static cJSON *wait_status(pred_fn pred, const void *arg) {
    for (int i = 0; i < 300; i++) {
        cJSON *st = status();
        if (st != NULL && pred(st, arg)) { return st; }
        cJSON_Delete(st);
        nanosleep(&(struct timespec){0, 10000000}, NULL);
    }
    return status();
}

typedef struct {
    const char *domain;
    const char *state;
} cand_want_t;

static bool has_candidate(const cJSON *st, const void *arg) {
    const cand_want_t *w = arg;
    const cJSON *c = candidate(st, w->domain);
    return c != NULL && (w->state == NULL || strcmp(str_of(c, "state"), w->state) == 0);
}

static bool failures_are(const cJSON *st, const void *arg) { return num_of(st, "failures") == *(const double *)arg; }

static bool probes_used(const cJSON *st, const void *arg) {
    return num_of(probes_of(st), "usedHour") == *(const double *)arg;
}

static bool has_bypassed(const cJSON *st, const void *arg) {
    (void)arg;
    return cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(st, "bypassed")) > 0;
}

static const cJSON *result_of(const cJSON *st, const char *host) {
    const cJSON *r;
    cJSON_ArrayForEach(r, cJSON_GetObjectItemCaseSensitive(probes_of(st), "results")) {
        if (strcmp(str_of(r, "host"), host) == 0) { return r; }
    }
    return NULL;
}

static bool has_result(const cJSON *st, const void *arg) { return result_of(st, arg) != NULL; }

static bool check_done(const cJSON *st, const void *arg) {
    (void)arg;
    return cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(st, "checking")) && num_of(st, "checkedAt") > 0;
}

static bool running_host(const cJSON *st, const void *arg) {
    const cJSON *run = cJSON_GetObjectItemCaseSensitive(probes_of(st), "running");
    return cJSON_IsString(run) && strcmp(run->valuestring, arg) == 0;
}

static const uint8_t CLIENT[4] = {192, 168, 1, 10};
static const uint8_t OTHER[4] = {192, 168, 1, 99};
static const uint8_t SERVER[4] = {203, 0, 113, 7};

typedef struct {
    firc_app_t *app;
    const uint8_t *client;
    const char *name;
    int n;
    _Atomic bool done;
} hint_job_t;

static void hint_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    hint_job_t *j = ud;
    firc_ip_t client = {{0}, 4}, server = {{0}, 4};
    memcpy(client.b, j->client, 4);
    memcpy(server.b, SERVER, 4);
    if (j->n == 0) { firc_app_autolist_hint_for_test(j->app, &client, j->name, &server, 1); }
    for (int i = 0; i < j->n; i++) {
        char name[64];
        snprintf(name, sizeof(name), "n%d.example", i);
        firc_app_autolist_hint_for_test(j->app, &client, name, &server, 1);
    }
    atomic_store(&j->done, true);
}

static bool hint_n(rig_t *r, const uint8_t *client, const char *name, int n) {
    hint_job_t j = {.app = r->app, .client = client, .name = name, .n = n};
    atomic_init(&j.done, false);
    if (firc_loop_post(r->loop, hint_on_loop, &j) != FIRC_OK) { return false; }
    for (int i = 0; i < 2000 && !atomic_load(&j.done); i++) { nanosleep(&(struct timespec){0, 1000000}, NULL); }
    return atomic_load(&j.done);
}

static bool hint(rig_t *r, const uint8_t *client, const char *name) { return hint_n(r, client, name, 0); }

static void barrier_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    atomic_store((_Atomic bool *)ud, true);
}

static bool barrier(rig_t *r) {
    for (int round = 0; round < 2; round++) {
        _Atomic bool done;
        atomic_init(&done, false);
        if (firc_loop_post(r->loop, barrier_on_loop, &done) != FIRC_OK) { return false; }
        for (int i = 0; i < 2000 && !atomic_load(&done); i++) { nanosleep(&(struct timespec){0, 1000000}, NULL); }
        if (!atomic_load(&done)) { return false; }
    }
    return true;
}

static bool push(rig_t *r, int which, const uint8_t *pkt, size_t len) {
    _Alignas(4) uint8_t dg[2400];
    size_t dg_len = fake_nflog_msg(dg, pkt, len);
    return fake_nflog_send(g_kernel[which], dg, dg_len) && barrier(r);
}

static void set_ports(uint8_t *pkt, uint16_t sport, uint16_t dport) {
    pkt[20] = (uint8_t)(sport >> 8);
    pkt[21] = (uint8_t)sport;
    pkt[22] = (uint8_t)(dport >> 8);
    pkt[23] = (uint8_t)dport;
}

static void put_ack(uint8_t *pkt, uint32_t ack) {
    pkt[28] = (uint8_t)(ack >> 24);
    pkt[29] = (uint8_t)(ack >> 16);
    pkt[30] = (uint8_t)(ack >> 8);
    pkt[31] = (uint8_t)ack;
}

static bool hello(rig_t *r, const uint8_t *client, uint16_t port, const char *sni) {
    uint8_t rec[1024], pkt[1200];
    size_t rec_len = fake_nflog_hello(rec, sni);
    size_t len = fake_nflog_packet(pkt, client, SERVER, 443, rec, rec_len);
    set_ports(pkt, port, 443);
    pkt[27] = 7;
    put_ack(pkt, 1000);
    return push(r, 0, pkt, len);
}

static bool reply(rig_t *r, const uint8_t *client, int which, uint16_t port, uint8_t flags) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, SERVER, client, port, none, 0);
    set_ports(pkt, 443, port);
    pkt[33] = flags;
    return push(r, which, pkt, len);
}

static bool fin(rig_t *r, const uint8_t *client, uint16_t port, uint32_t ack) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, client, SERVER, 443, none, 0);
    set_ports(pkt, port, 443);
    put_ack(pkt, ack);
    pkt[33] = 0x11;
    return push(r, 3, pkt, len);
}

static bool syn(rig_t *r, const uint8_t *client, uint16_t port) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, client, SERVER, 443, none, 0);
    set_ports(pkt, port, 443);
    pkt[27] = 6;
    pkt[33] = 0x02;
    return push(r, 5, pkt, len);
}

static bool resets(rig_t *r, const uint8_t *client, const char *host, uint16_t port) {
    for (uint16_t p = port; p < port + 2; p++) {
        if (!hello(r, client, p, host) || !reply(r, client, 1, p, 0x14)) { return false; }
    }
    return true;
}

static bool fail_twice(rig_t *r, const char *host, uint16_t port) {
    return hint(r, CLIENT, host) && resets(r, CLIENT, host, port);
}

static const firc_group_t *target(firc_app_t *app) {
    firc_id_t gid;
    if (firc_id_parse("0a0b0c0d", &gid) != FIRC_OK) { return NULL; }
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, gid);
    return rs != NULL ? firc_ruleset_group(rs) : NULL;
}

static const firc_rule_t *rule_of(firc_app_t *app, const char *text) {
    const firc_group_t *g = target(app);
    for (size_t i = 0; g != NULL && i < g->n_rules; i++) {
        if (strcmp(g->rules[i]->rule, text) == 0) { return g->rules[i]; }
    }
    return NULL;
}

static size_t rules_named(firc_app_t *app, const char *text) {
    const firc_group_t *g = target(app);
    size_t n = 0;
    for (size_t i = 0; g != NULL && i < g->n_rules; i++) { n += strcmp(g->rules[i]->rule, text) == 0; }
    return n;
}

static int probe_host(const char *host) {
    char body[300];
    snprintf(body, sizeof(body), "{\"host\":\"%s\"}", host);
    return request_body("POST", "/api/v1/system/autolist/probe", body, g_buf, sizeof(g_buf));
}

TEST candidates_mode_adds_nothing(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(fail_twice(&r, "blocked.example.com", 50001));
    cand_want_t want = {"example.com", "candidate"};
    cJSON *st = wait_status(has_candidate, &want);
    const cJSON *c = candidate(st, "example.com");
    ASSERTm("a host failing twice is proposed under its registrable domain", c != NULL);
    ASSERT_STR_EQ("candidate", str_of(c, "state"));
    ASSERT_STR_EQ("blocked.example.com", str_of(c, "host"));
    ASSERT_STR_EQ("reset", str_of(c, "why"));
    ASSERT_EQ(2, (int)num_of(c, "fails"));
    ASSERT_STR_EQ("192.168.1.10",
                  cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(c, "clients"), 0)->valuestring);
    ASSERT_EQ(1800000000, (int64_t)num_of(c, "lastAt"));
    ASSERT_STR_EQ("candidates", str_of(st, "mode"));
    ASSERT_STR_EQ("0a0b0c0d", str_of(st, "group"));
    ASSERT_EQ(2, (int)num_of(st, "failuresDay"));
    ASSERT_EQ(0, (int)num_of(st, "addedHour"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(NULL, rule_of(r.app, "example.com"));
    rig_down(&r);
    PASS();
}

TEST add_mode_adds_through_the_helper(void) {
    rig_t r;
    setup_t su = {.mode = "add"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(fail_twice(&r, "blocked.example.com", 50001));
    cand_want_t want = {"example.com", "added"};
    cJSON *st = wait_status(has_candidate, &want);
    ASSERT_STR_EQ("added", str_of(candidate(st, "example.com"), "state"));
    ASSERT_EQ(1, (int)num_of(st, "addedHour"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    const firc_rule_t *rule = rule_of(r.app, "example.com");
    ASSERT(rule != NULL);
    ASSERT(rule->enable);
    ASSERT_STR_EQ("namespace", rule->type);
    ASSERT_STR_EQ("blocked.example.com", rule->autolist);
    rig_down(&r);
    PASS();
}

TEST candidate_add_route_adds_once(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(fail_twice(&r, "blocked.example.com", 50001));
    cand_want_t want = {"example.com", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &want));
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/candidates/example.com/add", g_buf, sizeof(g_buf)));
    ASSERTm(g_buf, strstr(g_buf, "\"state\":\"added\"") != NULL);
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/candidates/example.com/add", g_buf, sizeof(g_buf)));
    ASSERT_EQ(404, request("POST", "/api/v1/system/autolist/candidates/nothing.example/add", g_buf, sizeof(g_buf)));
    rig_stop_loop(&r);
    ASSERT_EQ(1u, rules_named(r.app, "example.com"));
    ASSERT_STR_EQ("blocked.example.com", rule_of(r.app, "example.com")->autolist);
    rig_down(&r);
    PASS();
}

TEST dismiss_hides_for_a_day(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(fail_twice(&r, "blocked.example.com", 50001));
    cand_want_t want = {"example.com", NULL};
    cJSON_Delete(wait_status(has_candidate, &want));
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/candidates/example.com/dismiss", g_buf, sizeof(g_buf)));
    ASSERT_EQ(404, request("POST", "/api/v1/system/autolist/candidates/example.com/dismiss", g_buf, sizeof(g_buf)));
    ASSERT(fail_twice(&r, "blocked.example.com", 50011));
    double four = 4;
    cJSON *st = wait_status(failures_are, &four);
    ASSERT_EQ(4, (int)num_of(st, "failures"));
    ASSERTm("dismissed within the day", candidate(st, "example.com") == NULL);
    cJSON_Delete(st);
    atomic_fetch_add(&g_now, FIRC_AUTOLIST_DISMISS_SECS);
    ASSERT(fail_twice(&r, "blocked.example.com", 50021));
    st = wait_status(has_candidate, &want);
    ASSERTm("back after a day", candidate(st, "example.com") != NULL);
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST uncovered_client_stores_no_hint(void) {
    rig_t r;
    setup_t su = {.group_extra = "    devices: {allow: [192.168.1.10]}\n"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(hint(&r, CLIENT, "blocked.example.com"));
    atomic_fetch_add(&g_now, 1);
    ASSERT(hint_n(&r, OTHER, NULL, FIRC_AUTOLIST_HINTS));
    ASSERT(resets(&r, CLIENT, "blocked.example.com", 50001));
    double two = 2;
    cJSON *st = wait_status(failures_are, &two);
    ASSERTm("an uncovered device's hints pushed the covered one out", candidate(st, "example.com") != NULL);
    ASSERT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(st, "bypassed")));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST a_device_that_never_asked_is_counted_apart(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(resets(&r, CLIENT, "doh.example.com", 50001));
    cJSON *st = wait_status(has_bypassed, NULL);
    const cJSON *b = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(st, "bypassed"), 0);
    ASSERT(b != NULL);
    ASSERT_STR_EQ("192.168.1.10", str_of(b, "client"));
    ASSERT_EQ(2, (int)num_of(b, "fails"));
    ASSERT_EQ(NULL, candidate(st, "example.com"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST freeze_probe_makes_candidate(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    plan("frozen.example.net", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_FREEZE, false, 16384);
    ASSERT_EQ(400, probe_host("not a host"));
    ASSERTm(g_buf, strstr(g_buf, "not a host name") != NULL);
    ASSERT_EQ(400, request_body("POST", "/api/v1/system/autolist/probe", "{}", g_buf, sizeof(g_buf)));
    ASSERT_EQ(202, probe_host("frozen.example.net"));
    cand_want_t want = {"example.net", "candidate"};
    cJSON *st = wait_status(has_candidate, &want);
    const cJSON *c = candidate(st, "example.net");
    ASSERT(c != NULL);
    ASSERT_STR_EQ("freeze", str_of(c, "why"));
    ASSERT_STR_EQ("frozen.example.net", str_of(c, "host"));
    const cJSON *res = result_of(st, "frozen.example.net");
    ASSERT(res != NULL);
    ASSERT_STR_EQ("blocked", str_of(res, "verdict"));
    ASSERT_STR_EQ("freeze", str_of(res, "why"));
    ASSERT_EQ(16384, (int)num_of(res, "bytes"));
    ASSERT_STR_EQ("fake", str_of(res, "error"));
    ASSERT_EQ(1800000000, (int64_t)num_of(res, "at"));
    ASSERT_EQ(1, (int)num_of(probes_of(st), "usedHour"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(NULL, rule_of(r.app, "example.net"));
    rig_down(&r);
    PASS();
}

TEST recheck_open_switches_off_keeps_marker(void) {
    rig_t r;
    setup_t su = {.mode = "add"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(fail_twice(&r, "www.up.example", 50001));
    cand_want_t want = {"up.example", "added"};
    cJSON_Delete(wait_status(has_candidate, &want));
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    cJSON *st = wait_status(check_done, NULL);
    ASSERT_EQ(1, (int)num_of(st, "switchedOff"));
    ASSERT_STR_EQ("off", str_of(candidate(st, "up.example"), "state"));
    ASSERT_STR_EQ("open", str_of(result_of(st, "www.up.example"), "verdict"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERTm("the host the domain was added for is what is checked", probed("www.up.example"));
    ASSERT(probed("down.example"));
    ASSERTm("a rule added by hand is never checked", !probed("hand.example"));
    ASSERTm("a rule already off is not checked", !probed("off.example"));
    ASSERT_FALSE(rule_of(r.app, "up.example")->enable);
    ASSERT(rule_of(r.app, "down.example")->enable);
    ASSERT(rule_of(r.app, "hand.example")->enable);
    ASSERT_STR_EQm("it keeps its mark, so it can come back", "www.up.example", rule_of(r.app, "up.example")->autolist);
    rig_down(&r);
    PASS();
}

TEST recheck_short_keeps_freeze_rule(void) {
    rig_t r;
    setup_t su = {.mode = "add"};
    ASSERT(rig_up_with(&r, &su));
    plan("frozen.example.net", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_FREEZE, false, 16384);
    ASSERT_EQ(202, probe_host("frozen.example.net"));
    cand_want_t frozen = {"example.net", "added"};
    cJSON_Delete(wait_status(has_candidate, &frozen));
    ASSERT(fail_twice(&r, "www.rst.example.org", 50001));
    cand_want_t reset = {"example.org", "added"};
    cJSON_Delete(wait_status(has_candidate, &reset));
    plan("frozen.example.net", FIRC_AUTOLIST_REACHABLE, 0, true, 900);
    plan("www.rst.example.org", FIRC_AUTOLIST_REACHABLE, 0, true, 900);
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    cJSON *st = wait_status(check_done, NULL);
    ASSERT_EQ(2, (int)num_of(st, "switchedOff"));
    ASSERT_STR_EQ("short", str_of(result_of(st, "frozen.example.net"), "verdict"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERTm("a short body says nothing about a freeze", rule_of(r.app, "example.net")->enable);
    ASSERTm("a short body clears a reset", !rule_of(r.app, "example.org")->enable);
    ASSERT_FALSE(rule_of(r.app, "up.example")->enable);
    rig_down(&r);
    PASS();
}

TEST check_iface_in_group_is_refused(void) {
    rig_t r;
    setup_t su = {.app_extra = ", checkInterface: nwg9"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT_EQ(409, probe_host("x.example"));
    ASSERTm(g_buf, strstr(g_buf, "the check interface belongs to the group") != NULL);
    ASSERT_EQ(409, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    ASSERTm(g_buf, strstr(g_buf, "the check interface belongs to the group") != NULL);
    cJSON *st = status();
    ASSERT(st != NULL);
    ASSERT_EQ(0, (int)num_of(probes_of(st), "usedHour"));
    ASSERT_EQ(0, (int)num_of(probes_of(st), "queued"));
    ASSERT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(probes_of(st), "results")));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(0u, n_probed());
    rig_down(&r);
    PASS();
}

static bool queued_is(const cJSON *st, const void *arg) {
    return num_of(probes_of(st), "queued") == *(const double *)arg;
}

TEST recheck_rotates_past_32_rules(void) {
    rig_t r;
    setup_t su = {.marked = 40};
    ASSERT(rig_up_with(&r, &su));
    atomic_store(&g_gate_closed, true);
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    double first = 31;
    cJSON *st = wait_status(queued_is, &first);
    ASSERTm("one run queues at most 32 hosts, one of them running", num_of(probes_of(st), "queued") == 31);
    cJSON_Delete(st);
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    double second = 41;
    st = wait_status(queued_is, &second);
    ASSERTm("the next run starts where the last one stopped", num_of(probes_of(st), "queued") == 41);
    cJSON_Delete(st);
    atomic_store(&g_gate_closed, false);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST recheck_leaves_room_for_a_user_probe(void) {
    rig_t r;
    setup_t su = {.marked = 70};
    ASSERT(rig_up_with(&r, &su));
    atomic_store(&g_gate_closed, true);
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    }
    double full = FIRC_AUTOLIST_PROBES_QUEUE;
    cJSON_Delete(wait_status(queued_is, &full));
    ASSERT_EQ(202, probe_host("x.example"));
    char host[64];
    for (int i = 0; i < FIRC_AUTOLIST_PROBES_QUEUE - 1; i++) {
        snprintf(host, sizeof(host), "u%d.example", i);
        ASSERT_EQ(202, probe_host(host));
    }
    ASSERT_EQ(429, probe_host("one-more.example"));
    ASSERTm(g_buf, strstr(g_buf, "the check queue is full") != NULL);
    atomic_store(&g_gate_closed, false);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST nomination_of_an_added_domain_is_not_probed(void) {
    rig_t r;
    setup_t su = {.mode = "add"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(fail_twice(&r, "slow.example.com", 50001));
    cand_want_t added = {"example.com", "added"};
    cJSON_Delete(wait_status(has_candidate, &added));
    for (uint16_t port = 50011; port <= 50012; port++) {
        ASSERT(hello(&r, CLIENT, port, "slow.example.com"));
        ASSERT(reply(&r, CLIENT, 2, port, 0x10));
        atomic_fetch_add(&g_now, 11);
        ASSERT(fin(&r, CLIENT, port, 1000 + 16384));
    }
    cJSON *st = status();
    ASSERT(st != NULL);
    ASSERT_EQ(0, (int)num_of(probes_of(st), "queued"));
    ASSERT_STR_EQ("added", str_of(candidate(st, "example.com"), "state"));
    ASSERT_EQ(0, (int)num_of(candidate(st, "example.com"), "notes"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST candidate_add_over_a_hand_rule_is_refused(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(fail_twice(&r, "www.hand.example", 50001));
    cand_want_t want = {"hand.example", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &want));
    ASSERT_EQ(409, request("POST", "/api/v1/system/autolist/candidates/hand.example/add", g_buf, sizeof(g_buf)));
    ASSERTm(g_buf, strstr(g_buf, "the domain is already a rule of the group") != NULL);
    cJSON *st = status();
    ASSERT_STR_EQ("candidate", str_of(candidate(st, "hand.example"), "state"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(NULL, rule_of(r.app, "hand.example")->autolist);
    ASSERT_EQ(1u, rules_named(r.app, "hand.example"));
    rig_down(&r);
    PASS();
}

TEST evicted_recheck_does_not_stick_checking(void) {
    rig_t r;
    setup_t su = {.marked = 70};
    ASSERT(rig_up_with(&r, &su));
    atomic_store(&g_gate_closed, true);
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    double first = 31;
    cJSON_Delete(wait_status(queued_is, &first));
    char host[64];
    for (int i = 0; i < FIRC_AUTOLIST_PROBES_QUEUE; i++) {
        snprintf(host, sizeof(host), "u%d.example", i);
        ASSERT_EQ(202, probe_host(host));
    }
    cJSON *st = status();
    ASSERT(st != NULL);
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(st, "checking")));
    cJSON_Delete(st);
    atomic_fetch_add(&g_now, 60);
    atomic_store(&g_gate_closed, false);
    st = wait_status(check_done, NULL);
    ASSERTm("no recheck is left once the requests pushed them out",
            cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(st, "checking")));
    ASSERT_EQ(1800000060, (int64_t)num_of(st, "checkedAt"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST add_mode_over_a_hand_rule_stays_candidate(void) {
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL) | O_NONBLOCK);
    fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL) | O_NONBLOCK);
    firc_log_set_output_floor(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    rig_t r;
    setup_t su = {.mode = "add"};
    bool up = rig_up_with(&r, &su);
    bool failed = up && fail_twice(&r, "www.hand.example", 50001);
    cand_want_t want = {"hand.example", NULL};
    cJSON *st = failed ? wait_status(has_candidate, &want) : NULL;
    char state[32] = "";
    double added = -2;
    if (st != NULL) {
        snprintf(state, sizeof(state), "%s", str_of(candidate(st, "hand.example"), "state"));
        added = num_of(st, "addedHour");
    }
    cJSON_Delete(st);
    if (up) { rig_stop_loop(&r); }
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    static char log[1 << 16];
    ssize_t n = read(fds[0], log, sizeof(log) - 1);
    log[n > 0 ? n : 0] = '\0';
    close(fds[0]);
    close(fds[1]);
    bool hand = up && rule_of(r.app, "hand.example") != NULL && rule_of(r.app, "hand.example")->autolist == NULL;
    size_t rules = up ? rules_named(r.app, "hand.example") : 0;
    if (up) { rig_down(&r); }
    ASSERT(up && failed);
    ASSERT_STR_EQ("candidate", state);
    ASSERT_EQ(0, (int)added);
    ASSERT(hand);
    ASSERT_EQ(1u, rules);
    const char *line = "autolist: hand.example is already a rule of group \"Autolist\"";
    const char *at = strstr(log, line);
    ASSERTm(log, at != NULL);
    ASSERTm(log, strstr(at + 1, line) == NULL);
    PASS();
}

typedef struct {
    rig_t *r;
    _Atomic bool done;
} toggle_job_t;

static void toggle_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    toggle_job_t *j = ud;
    j->r->cfg.app.autolist.enabled = false;
    (void)firc_app_autolist_apply(j->r->app);
    j->r->cfg.app.autolist.enabled = true;
    (void)firc_app_autolist_apply(j->r->app);
    atomic_store(&j->done, true);
}

TEST disable_enable_during_probe_keeps_one_thread(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    atomic_store(&g_gate_closed, true);
    ASSERT_EQ(202, probe_host("a.example"));
    cJSON_Delete(wait_status(running_host, "a.example"));
    toggle_job_t j = {.r = &r};
    atomic_init(&j.done, false);
    ASSERT_EQ(FIRC_OK, firc_loop_post(r.loop, toggle_on_loop, &j));
    for (int i = 0; i < 2000 && !atomic_load(&j.done); i++) { nanosleep(&(struct timespec){0, 1000000}, NULL); }
    ASSERT(atomic_load(&j.done));
    atomic_store(&g_gate_closed, false);
    ASSERT_EQ(202, probe_host("b.example"));
    cJSON *st = wait_status(has_result, "b.example");
    ASSERT(result_of(st, "b.example") != NULL);
    ASSERTm("the old generation's result is dropped", result_of(st, "a.example") == NULL);
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(st, "running")));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(1, atomic_load(&g_max_running));
    rig_down(&r);
    PASS();
}

TEST probe_route_429_when_budget_spent(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char host[64];
    for (int i = 0; i < FIRC_AUTOLIST_PROBES_PER_HOUR; i++) {
        snprintf(host, sizeof(host), "h%d.example", i);
        ASSERT_EQ(202, probe_host(host));
    }
    double thirty = FIRC_AUTOLIST_PROBES_PER_HOUR;
    cJSON_Delete(wait_status(probes_used, &thirty));
    ASSERT_EQ(429, probe_host("h0.example"));
    ASSERTm(g_buf, strstr(g_buf, "this host was checked within 10 minutes") != NULL);
    ASSERT_EQ(429, probe_host("fresh.example"));
    ASSERTm(g_buf, strstr(g_buf, "the hour's 30 checks are spent") != NULL);
    rig_stop_loop(&r);
    ASSERT_EQ((size_t)FIRC_AUTOLIST_PROBES_PER_HOUR, n_probed());
    rig_down(&r);
    PASS();
}

typedef struct {
    firc_app_t *app;
    _Atomic bool done;
} apply_job_t;

static void apply_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    apply_job_t *j = ud;
    (void)firc_app_autolist_apply(j->app);
    (void)firc_app_autolist_apply(j->app);
    atomic_store(&j->done, true);
}

TEST reload_during_probe_keeps_one_thread(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    atomic_store(&g_gate_closed, true);
    ASSERT_EQ(202, probe_host("a.example"));
    cJSON_Delete(wait_status(running_host, "a.example"));
    apply_job_t j = {.app = r.app};
    atomic_init(&j.done, false);
    ASSERT_EQ(FIRC_OK, firc_loop_post(r.loop, apply_on_loop, &j));
    for (int i = 0; i < 2000 && !atomic_load(&j.done); i++) { nanosleep(&(struct timespec){0, 1000000}, NULL); }
    ASSERT(atomic_load(&j.done));
    ASSERT_EQ(202, probe_host("b.example"));
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    nanosleep(&(struct timespec){0, 50000000}, NULL);
    ASSERT_EQ(1, atomic_load(&g_running));
    atomic_store(&g_gate_closed, false);
    cJSON *st = wait_status(check_done, NULL);
    ASSERT(result_of(st, "a.example") != NULL);
    ASSERT(result_of(st, "b.example") != NULL);
    ASSERT(result_of(st, "down.example") != NULL);
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(1, atomic_load(&g_max_running));
    rig_down(&r);
    PASS();
}

TEST nomination_shows_checking_candidate(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(hint(&r, CLIENT, "slow.example.com"));
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(&r, CLIENT, port, "slow.example.com"));
        ASSERT(reply(&r, CLIENT, 2, port, 0x10));
        atomic_fetch_add(&g_now, 11);
        ASSERT(fin(&r, CLIENT, port, 1000 + 16384));
    }
    cand_want_t want = {"example.com", "checking"};
    cJSON *st = wait_status(has_candidate, &want);
    const cJSON *c = candidate(st, "example.com");
    ASSERT(c != NULL);
    ASSERT_STR_EQ("checking", str_of(c, "state"));
    ASSERT_STR_EQ("freeze", str_of(c, "why"));
    ASSERT_STR_EQ("slow.example.com", str_of(c, "host"));
    ASSERT_EQ(FIRC_AUTOLIST_NOTES, (int)num_of(c, "notes"));
    ASSERT_EQ(0, (int)num_of(c, "fails"));
    ASSERT_EQ(1, (int)num_of(probes_of(st), "queued"));
    cJSON_Delete(st);
    ASSERT_EQ(202, probe_host("a.example"));
    st = wait_status(has_result, "a.example");
    ASSERT_EQ(1, (int)num_of(probes_of(st), "queued"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERTm("a nomination waits for the two-minute tick, not the end of another probe",
            n_probed() == 1 && !probed("slow.example.com"));
    rig_down(&r);
    PASS();
}

TEST syn_nomination_shows_checking_candidate(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(syn(&r, CLIENT, port));
        atomic_fetch_add(&g_now, 3);
        ASSERT(syn(&r, CLIENT, port));
    }
    cand_want_t want = {"example.com", "checking"};
    cJSON *st = wait_status(has_candidate, &want);
    const cJSON *c = candidate(st, "example.com");
    ASSERT(c != NULL);
    ASSERT_STR_EQ("checking", str_of(c, "state"));
    ASSERT_STR_EQ("silent.example.com", str_of(c, "host"));
    ASSERT_STR_EQ("no-connect", str_of(c, "why"));
    ASSERT_EQ(0, (int)num_of(c, "notes"));
    ASSERT_EQ(1, (int)num_of(probes_of(st), "queued"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST recheck_goes_through_the_budget(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    cJSON *st = wait_status(check_done, NULL);
    ASSERT_EQ(2, (int)num_of(probes_of(st), "usedHour"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(1, atomic_load(&g_max_running));
    ASSERT_EQ(2u, n_probed());
    rig_down(&r);
    PASS();
}

TEST list_group_takes_the_rule(void) {
    rig_t r;
    setup_t su = {.mode = "add", .group_extra = "    list:\n      url: 'https://example.invalid/l.txt'\n"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(fail_twice(&r, "blocked.example.com", 50001));
    cand_want_t want = {"example.com", "added"};
    cJSON_Delete(wait_status(has_candidate, &want));
    rig_stop_loop(&r);
    ASSERT(target(r.app)->list != NULL);
    ASSERT(rule_of(r.app, "example.com") != NULL);
    rig_down(&r);
    PASS();
}

TEST block_group_is_not_running(void) {
    rig_t r;
    setup_t su = {.iface = "block"};
    ASSERT(rig_up_with(&r, &su));
    cJSON *st = status();
    ASSERT(st != NULL);
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(st, "running")));
    ASSERT_STR_EQ("the group blocks by DNS: nothing to route its names into", str_of(st, "whyOff"));
    cJSON_Delete(st);
    ASSERT_EQ(409, probe_host("x.example"));
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST add_mode_logs_the_write(void) {
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL) | O_NONBLOCK);
    fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL) | O_NONBLOCK);
    firc_log_set_output_floor(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    rig_t r;
    setup_t su = {.mode = "add"};
    bool up = rig_up_with(&r, &su);
    bool failed = up && fail_twice(&r, "blocked.example.com", 50001);
    cand_want_t want = {"example.com", "added"};
    if (failed) { cJSON_Delete(wait_status(has_candidate, &want)); }
    if (up) { rig_stop_loop(&r); }
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    static char log[1 << 16];
    ssize_t n = read(fds[0], log, sizeof(log) - 1);
    log[n > 0 ? n : 0] = '\0';
    close(fds[0]);
    close(fds[1]);
    if (up) { rig_down(&r); }
    ASSERT(up && failed);
    ASSERTm(log, strstr(log, "autolist: example.com added to group \"Autolist\" for blocked.example.com: 2 failures, "
                             "a reset before the server answered") != NULL);
    PASS();
}

TEST open_probe_clears_a_checking_candidate(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(hint(&r, CLIENT, "slow.example.com"));
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(&r, CLIENT, port, "slow.example.com"));
        ASSERT(reply(&r, CLIENT, 2, port, 0x10));
        atomic_fetch_add(&g_now, 11);
        ASSERT(fin(&r, CLIENT, port, 1000 + 16384));
    }
    cand_want_t checking = {"example.com", "checking"};
    cJSON_Delete(wait_status(has_candidate, &checking));
    plan("slow.example.com", FIRC_AUTOLIST_REACHABLE, 0, false, 70000);
    ASSERT_EQ(202, probe_host("slow.example.com"));
    cJSON *st = wait_status(has_result, "slow.example.com");
    ASSERTm("a nomination the probe found open leaves no candidate", candidate(st, "example.com") == NULL);
    cJSON_Delete(st);
    ASSERT(fail_twice(&r, "slow.example.com", 50011));
    cand_want_t back = {"example.com", "candidate"};
    st = wait_status(has_candidate, &back);
    ASSERTm("forgotten, not dismissed: a real failure proposes it again", candidate(st, "example.com") != NULL);
    cJSON_Delete(st);
    ASSERT(fail_twice(&r, "www.rst.example.org", 50021));
    cand_want_t reset = {"example.org", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &reset));
    plan("www.rst.example.org", FIRC_AUTOLIST_REACHABLE, 0, false, 70000);
    ASSERT_EQ(202, probe_host("www.rst.example.org"));
    st = wait_status(has_result, "www.rst.example.org");
    ASSERT_STR_EQm("a failure candidate stays after an open probe", "candidate",
                   str_of(candidate(st, "example.org"), "state"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST a_check_while_the_list_is_off_is_refused(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    rig_stop_loop(&r);
    r.cfg.app.autolist.enabled = false;
    ASSERT_EQ(FIRC_OK, firc_app_autolist_apply(r.app));
    ASSERT_EQ(FIRC_ERR_STATE, firc_app_autolist_recheck_now(r.app));
    rig_down(&r);
    PASS();
}

static _Atomic bool *g_saved_stop;
static int g_done_calls;

static void stop_saving_probe(const char *host, const firc_autolist_check_opts_t *o, _Atomic bool *stop,
                              firc_autolist_result_t *out) {
    (void)host;
    (void)o;
    g_saved_stop = stop;
    out->verdict = FIRC_AUTOLIST_BLOCKED;
}

static firc_err_t deliver_inline_then_stop(firc_loop_t *loop, firc_post_cb cb, void *ud, firc_post_drop_cb drop) {
    (void)loop;
    (void)drop;
    cb(NULL, ud);
    atomic_store(g_saved_stop, true);
    return FIRC_OK;
}

static void count_done(void *ud, uint64_t gen, const firc_autolist_probe_t *probes, size_t n) {
    (void)ud;
    (void)gen;
    (void)probes;
    (void)n;
    g_done_calls++;
}

TEST test_check_result_freed_once(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_autolist_probe_t p = {.result.verdict = FIRC_AUTOLIST_UNKNOWN};
    snprintf(p.host, sizeof(p.host), "a.example");
    firc_autolist_check_opts_t o = {0};
    g_saved_stop = NULL;
    g_done_calls = 0;
    firc_autolist_check_set_post_for_test(deliver_inline_then_stop);
    firc_autolist_check_t *c = firc_autolist_check_start(loop, &o, &p, 1, 1, stop_saving_probe, count_done, NULL);
    ASSERT(c != NULL);
    while (__atomic_load_n(&g_done_calls, __ATOMIC_ACQUIRE) == 0) { nanosleep(&(struct timespec){0, 1000000}, NULL); }
    firc_autolist_check_free(c);
    firc_autolist_check_set_post_for_test(NULL);
    firc_loop_destroy(loop);
    ASSERT_EQ(1, g_done_calls);
    PASS();
}

static bool fail_once(rig_t *r, const char *host, uint16_t port) {
    return hint(r, CLIENT, host) && hello(r, CLIENT, port, host) && reply(r, CLIENT, 1, port, 0x14);
}

static bool syn_flow(rig_t *r, uint16_t port) {
    if (!syn(r, CLIENT, port)) { return false; }
    atomic_fetch_add(&g_now, 3);
    return syn(r, CLIENT, port);
}

TEST no_connect_probe_makes_candidate(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50001));
    ASSERT(syn_flow(&r, 50002));
    cand_want_t checking = {"example.com", "checking"};
    cJSON_Delete(wait_status(has_candidate, &checking));
    plan("silent.example.com", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT_EQ(202, probe_host("silent.example.com"));
    cand_want_t want = {"example.com", "candidate"};
    cJSON *st = wait_status(has_candidate, &want);
    const cJSON *c = candidate(st, "example.com");
    ASSERT(c != NULL);
    ASSERT_STR_EQ("candidate", str_of(c, "state"));
    ASSERT_STR_EQ("no-connect", str_of(c, "why"));
    ASSERT_STR_EQ("silent.example.com", str_of(c, "host"));
    ASSERT_STR_EQ("no-connect", str_of(result_of(st, "silent.example.com"), "why"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(NULL, rule_of(r.app, "example.com"));
    rig_down(&r);
    PASS();
}

TEST no_connect_probe_adds_in_add_mode(void) {
    rig_t r;
    setup_t su = {.mode = "add"};
    ASSERT(rig_up_with(&r, &su));
    plan("silent.example.com", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT_EQ(202, probe_host("silent.example.com"));
    cand_want_t want = {"example.com", "added"};
    cJSON *st = wait_status(has_candidate, &want);
    ASSERT_STR_EQ("no-connect", str_of(candidate(st, "example.com"), "why"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    const firc_rule_t *rule = rule_of(r.app, "example.com");
    ASSERT(rule != NULL);
    ASSERT_STR_EQ("silent.example.com", rule->autolist);
    ASSERT_FALSEm("a host listing is not a domain listing", rule->autolist_by_domain);
    rig_down(&r);
    PASS();
}

TEST domain_listing_marks_most_failed_host(void) {
    rig_t r;
    setup_t su = {.mode = "add", .threshold = 3};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(fail_once(&r, "b.many.example", 50001));
    ASSERT(fail_once(&r, "b.many.example", 50002));
    ASSERT(fail_once(&r, "a.many.example", 50003));
    cand_want_t want = {"many.example", "added"};
    cJSON *st = wait_status(has_candidate, &want);
    const cJSON *c = candidate(st, "many.example");
    ASSERT(c != NULL);
    ASSERT_STR_EQ("b.many.example", str_of(c, "host"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    const firc_rule_t *rule = rule_of(r.app, "many.example");
    ASSERT(rule != NULL);
    ASSERT_STR_EQ("namespace", rule->type);
    ASSERT_STR_EQm("the host that failed most, not the last", "b.many.example", rule->autolist);
    ASSERT(rule->autolist_by_domain);
    rig_down(&r);
    PASS();
}

TEST syn_domain_nomination_lists_by_domain(void) {
    rig_t r;
    setup_t su = {.mode = "add"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(hint(&r, CLIENT, "www.many.example"));
    ASSERT(hint(&r, CLIENT, "i.many.example"));
    ASSERT(syn_flow(&r, 50001));
    ASSERT(syn_flow(&r, 50002));
    cand_want_t checking = {"many.example", "checking"};
    cJSON *st = wait_status(has_candidate, &checking);
    ASSERT_STR_EQ("many.example", str_of(candidate(st, "many.example"), "host"));
    cJSON_Delete(st);
    plan("many.example", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT_EQ(202, probe_host("many.example"));
    cand_want_t added = {"many.example", "added"};
    cJSON_Delete(wait_status(has_candidate, &added));
    rig_stop_loop(&r);
    const firc_rule_t *rule = rule_of(r.app, "many.example");
    ASSERT(rule != NULL);
    ASSERT_STR_EQ("many.example", rule->autolist);
    ASSERT(rule->autolist_by_domain);
    rig_down(&r);
    PASS();
}

static char *saved_groups(const char *dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/groups.yaml", dir);
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    static char buf[16384];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    char *at = strstr(buf, "groups:");
    return at;
}

static void remove_tree(const char *path) {
    struct stat sb;
    if (lstat(path, &sb) != 0) { return; }
    if (S_ISDIR(sb.st_mode)) {
        DIR *d = opendir(path);
        struct dirent *e;
        while (d != NULL && (e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) { continue; }
            char sub[1024];
            snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
            remove_tree(sub);
        }
        if (d != NULL) { closedir(d); }
        rmdir(path);
        return;
    }
    unlink(path);
}

static enum greatest_test_res short_after_domain_listing_in(const char *dir) {
    char conf[512];
    snprintf(conf, sizeof(conf), "%s/firc.conf", dir);
    rig_t r;
    setup_t su = {.mode = "add", .conf_path = conf};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(fail_once(&r, "a.many.example", 50001));
    ASSERT(fail_once(&r, "b.many.example", 50002));
    cand_want_t want = {"many.example", "added"};
    cJSON_Delete(wait_status(has_candidate, &want));
    rig_stop_loop(&r);
    rig_down(&r);
    char *groups = saved_groups(dir);
    ASSERT(groups != NULL);
    setup_t again = {.mode = "add", .groups = groups};
    ASSERT(rig_up_with(&r, &again));
    const firc_rule_t *loaded = rule_of(r.app, "many.example");
    ASSERT(loaded != NULL);
    ASSERT(loaded->autolist_by_domain);
    plan(loaded->autolist, FIRC_AUTOLIST_REACHABLE, 0, true, 900);
    plan("down.example", FIRC_AUTOLIST_REACHABLE, 0, true, 900);
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", g_buf, sizeof(g_buf)));
    cJSON *st = wait_status(check_done, NULL);
    ASSERT_EQ(2, (int)num_of(st, "switchedOff"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERTm("one host's short page says nothing of the domain", rule_of(r.app, "many.example")->enable);
    ASSERTm("a short page still clears a host listing", !rule_of(r.app, "down.example")->enable);
    rig_down(&r);
    PASS();
}

TEST short_after_domain_listing_keeps_rule(void) {
    char dir[] = "/tmp/firc_al_app_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    enum greatest_test_res res = short_after_domain_listing_in(dir);
    remove_tree(dir);
    struct stat sb;
    ASSERTm("the temporary directory is gone", lstat(dir, &sb) != 0);
    return res;
}

static bool wan_warning_is(const cJSON *st, const void *arg) {
    return strcmp(str_of(st, "wanWarning"), (const char *)arg) == 0;
}

TEST wan_unreachable_warns_until_a_check_passes(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    cJSON *st = status();
    ASSERT(st != NULL);
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(st, "wanWarning"));
    cJSON_Delete(st);
    plan_wan_unreachable("dead.example.com");
    ASSERT_EQ(202, probe_host("dead.example.com"));
    const char *text = "the check interface has no route: the WAN check cannot pass";
    st = wait_status(wan_warning_is, text);
    ASSERT_STR_EQ(text, str_of(st, "wanWarning"));
    cJSON_Delete(st);
    plan("other.example.com", FIRC_AUTOLIST_UNKNOWN, 0, false, 0);
    ASSERT_EQ(202, probe_host("other.example.com"));
    st = wait_status(has_result, "other.example.com");
    ASSERT_STR_EQm("an unknown verdict proves no route", text, str_of(st, "wanWarning"));
    cJSON_Delete(st);
    plan("silent.example.com", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT_EQ(202, probe_host("silent.example.com"));
    st = wait_status(has_result, "silent.example.com");
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(st, "wanWarning"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

static bool ambiguous_is(const cJSON *st, const void *arg) {
    return num_of(st, "ambiguousDay") == *(const double *)arg;
}

TEST status_counts_ambiguous_flows(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    cJSON *st = status();
    ASSERT_EQ(0, (int)num_of(st, "ambiguousDay"));
    cJSON_Delete(st);
    ASSERT(hint(&r, CLIENT, "a.one.example"));
    ASSERT(hint(&r, CLIENT, "b.two.example"));
    ASSERT(syn_flow(&r, 50001));
    double one = 1;
    st = wait_status(ambiguous_is, &one);
    ASSERT_EQ(1, (int)num_of(st, "ambiguousDay"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST probe_checks_wan_through_check_urls(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT_EQ(202, probe_host("a.example"));
    cJSON_Delete(wait_status(has_result, "a.example"));
    rig_stop_loop(&r);
    ASSERT_STR_EQ("http://cp.cloudflare.com/generate_204", g_wan_url);
    ASSERTm("check.url answers 204", g_wan_204);
    rig_down(&r);
    setup_t su = {.app_more = "  check: {url: 'http://c.test/204', wanUrl: 'http://w.test/'}\n"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT_EQ(202, probe_host("a.example"));
    cJSON_Delete(wait_status(has_result, "a.example"));
    rig_stop_loop(&r);
    ASSERT_STR_EQ("http://w.test/", g_wan_url);
    ASSERT_FALSEm("wanUrl answers any status", g_wan_204);
    rig_down(&r);
    PASS();
}

typedef struct {
    firc_app_t *app;
    _Atomic bool done;
} tick_job_t;

static void tick_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    tick_job_t *j = ud;
    firc_app_autolist_tick_for_test(j->app);
    atomic_store(&j->done, true);
}

static bool tick(rig_t *r) {
    tick_job_t j = {.app = r->app};
    atomic_init(&j.done, false);
    if (firc_loop_post(r->loop, tick_on_loop, &j) != FIRC_OK) { return false; }
    for (int i = 0; i < 2000 && !atomic_load(&j.done); i++) { nanosleep(&(struct timespec){0, 1000000}, NULL); }
    return atomic_load(&j.done);
}

static bool probed_times(const char *host) {
    size_t n = 0;
    pthread_mutex_lock(&g_probed_mu);
    for (size_t i = 0; i < g_n_probed; i++) { n += strcmp(g_probed[i], host) == 0; }
    pthread_mutex_unlock(&g_probed_mu);
    return n == 1;
}

TEST tick_probes_a_nomination_once(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50001));
    ASSERT(syn_flow(&r, 50002));
    cand_want_t checking = {"example.com", "checking"};
    cJSON_Delete(wait_status(has_candidate, &checking));
    plan("silent.example.com", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT(tick(&r));
    cand_want_t want = {"example.com", "candidate"};
    cJSON *st = wait_status(has_candidate, &want);
    ASSERT_STR_EQ("candidate", str_of(candidate(st, "example.com"), "state"));
    ASSERT_STR_EQ("no-connect", str_of(candidate(st, "example.com"), "why"));
    ASSERT_EQ(0, (int)num_of(probes_of(st), "queued"));
    cJSON_Delete(st);
    ASSERT(tick(&r));
    ASSERT(barrier(&r));
    rig_stop_loop(&r);
    ASSERTm("the nomination is probed once, by the tick", probed_times("silent.example.com") && n_probed() == 1);
    rig_down(&r);
    PASS();
}

TEST unknown_probe_after_no_connect_leaves_nothing(void) {
    rig_t r;
    setup_t su = {.mode = "add"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50001));
    ASSERT(syn_flow(&r, 50002));
    cand_want_t checking = {"example.com", "checking"};
    cJSON_Delete(wait_status(has_candidate, &checking));
    plan("silent.example.com", FIRC_AUTOLIST_UNKNOWN, 0, false, 0);
    ASSERT(tick(&r));
    cJSON *st = wait_status(has_result, "silent.example.com");
    ASSERT_STR_EQ("unknown", str_of(result_of(st, "silent.example.com"), "verdict"));
    ASSERTm("an unknown verdict proposes nothing", candidate(st, "example.com") == NULL);
    ASSERT_EQ(0, (int)num_of(st, "addedHour"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ(NULL, rule_of(r.app, "example.com"));
    rig_down(&r);
    PASS();
}

TEST evicted_domain_candidate_still_lists_by_domain(void) {
    rig_t r;
    setup_t su = {.threshold = 1};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(hint(&r, CLIENT, "www.many.example"));
    ASSERT(hint(&r, CLIENT, "i.many.example"));
    ASSERT(syn_flow(&r, 50001));
    cand_want_t checking = {"many.example", "checking"};
    cJSON_Delete(wait_status(has_candidate, &checking));
    char host[64];
    for (int i = 0; i < FIRC_AUTOLIST_CANDIDATES; i++) {
        atomic_fetch_add(&g_now, 1);
        snprintf(host, sizeof(host), "www.d%d.example", i);
        ASSERT(fail_once(&r, host, (uint16_t)(51000 + i)));
    }
    cJSON *st = status();
    ASSERTm("the domain's candidate was pushed out", candidate(st, "many.example") == NULL);
    cJSON_Delete(st);
    plan("many.example", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT(tick(&r));
    cand_want_t want = {"many.example", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &want));
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/candidates/many.example/add", g_buf, sizeof(g_buf)));
    rig_stop_loop(&r);
    const firc_rule_t *rule = rule_of(r.app, "many.example");
    ASSERT(rule != NULL);
    ASSERTm("the queued probe kept the domain flag", rule->autolist_by_domain);
    rig_down(&r);
    PASS();
}

TEST host_listing_clears_the_domain_flag(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(fail_once(&r, "a.many.example", 50001));
    ASSERT(fail_once(&r, "b.many.example", 50002));
    cand_want_t want = {"many.example", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &want));
    ASSERT(fail_once(&r, "c.many.example", 50003));
    ASSERT(fail_once(&r, "c.many.example", 50004));
    cJSON *st = status();
    ASSERT_STR_EQ("c.many.example", str_of(candidate(st, "many.example"), "host"));
    cJSON_Delete(st);
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/candidates/many.example/add", g_buf, sizeof(g_buf)));
    rig_stop_loop(&r);
    const firc_rule_t *rule = rule_of(r.app, "many.example");
    ASSERT(rule != NULL);
    ASSERT_STR_EQ("c.many.example", rule->autolist);
    ASSERTm("the latest listing was by host", !rule->autolist_by_domain);
    rig_down(&r);
    PASS();
}

static bool candidate_last_at(const cJSON *st, const void *arg) {
    const cJSON *c = candidate(st, "example.com");
    return c != NULL && num_of(c, "lastAt") == *(const double *)arg;
}

TEST a_confirmed_candidate_is_not_probed_again(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50001));
    ASSERT(syn_flow(&r, 50002));
    cand_want_t checking = {"example.com", "checking"};
    cJSON_Delete(wait_status(has_candidate, &checking));
    plan("silent.example.com", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT(tick(&r));
    cand_want_t want = {"example.com", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &want));
    atomic_fetch_add(&g_now, 30);
    ASSERT(syn_flow(&r, 50003));
    ASSERT(syn_flow(&r, 50004));
    ASSERT(syn_flow(&r, 50005));
    double seen_at = (double)(1800000000 + 6 + 30 + 3 + 3);
    cJSON *st = wait_status(candidate_last_at, &seen_at);
    const cJSON *c = candidate(st, "example.com");
    ASSERT(c != NULL);
    ASSERTm("the nomination still refreshes the candidate", num_of(c, "lastAt") == seen_at);
    ASSERT_STR_EQ("candidate", str_of(c, "state"));
    ASSERT_EQ(0, (int)num_of(probes_of(st), "queued"));
    ASSERT_EQ(1, (int)num_of(probes_of(st), "usedHour"));
    cJSON_Delete(st);
    ASSERT(tick(&r));
    ASSERT(barrier(&r));
    rig_stop_loop(&r);
    ASSERTm("the confirmed host is probed once", probed_times("silent.example.com") && n_probed() == 1);
    rig_down(&r);
    PASS();
}

static bool candidate_state_at(const cJSON *st, const void *arg) {
    const cJSON *c = candidate(st, "example.com");
    return c != NULL && num_of(c, "lastAt") == *(const double *)arg && strcmp(str_of(c, "state"), "checking") == 0;
}

TEST a_confirmed_candidate_checked_again_by_hand_stays_checking(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50001));
    ASSERT(syn_flow(&r, 50002));
    cand_want_t checking = {"example.com", "checking"};
    cJSON_Delete(wait_status(has_candidate, &checking));
    plan("silent.example.com", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT(tick(&r));
    cand_want_t want = {"example.com", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &want));
    atomic_fetch_add(&g_now, FIRC_AUTOLIST_PROBE_HOST_SECS + 1);
    atomic_store(&g_gate_closed, true);
    ASSERT_EQ(202, probe_host("silent.example.com"));
    cJSON_Delete(wait_status(running_host, "silent.example.com"));
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50003));
    ASSERT(syn_flow(&r, 50004));
    double seen_at = (double)atomic_load(&g_now);
    cJSON *st = wait_status(candidate_state_at, &seen_at);
    const cJSON *c = candidate(st, "example.com");
    ASSERT(c != NULL);
    ASSERT_EQ(seen_at, num_of(c, "lastAt"));
    ASSERTm("a check the user asked for keeps the row checking", strcmp(str_of(c, "state"), "checking") == 0);
    cJSON_Delete(st);
    atomic_store(&g_gate_closed, false);
    cJSON_Delete(wait_status(has_candidate, &want));
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST an_unknown_candidate_is_probed_again(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(fail_once(&r, "silent.example.com", 50011));
    ASSERT(fail_once(&r, "silent.example.com", 50012));
    cand_want_t want = {"example.com", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &want));
    plan("silent.example.com", FIRC_AUTOLIST_UNKNOWN, 0, false, 0);
    ASSERT_EQ(202, probe_host("silent.example.com"));
    cJSON_Delete(wait_status(has_result, "silent.example.com"));
    cJSON *before = status();
    double listed_at = num_of(candidate(before, "example.com"), "lastAt");
    cJSON_Delete(before);
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50001));
    ASSERT(syn_flow(&r, 50002));
    ASSERT(barrier(&r));
    cJSON *cached = status();
    ASSERTm("an unknown verdict in its hour neither queues nor refreshes the row",
            num_of(candidate(cached, "example.com"), "lastAt") == listed_at &&
                num_of(probes_of(cached), "queued") == 0);
    cJSON_Delete(cached);
    atomic_fetch_add(&g_now, FIRC_AUTOLIST_CACHE_UNKNOWN_SECS + 1);
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50003));
    ASSERT(syn_flow(&r, 50004));
    cand_want_t checking = {"example.com", "checking"};
    cJSON *st = wait_status(has_candidate, &checking);
    ASSERT_STR_EQ("checking", str_of(candidate(st, "example.com"), "state"));
    ASSERT_EQ(1, (int)num_of(probes_of(st), "queued"));
    cJSON_Delete(st);
    rig_stop_loop(&r);
    rig_down(&r);
    PASS();
}

TEST syns_into_the_configured_pool_are_not_watched(void) {
    static const uint8_t pool[4] = {203, 0, 0, 0};
    rig_t r;
    setup_t su = {.pool4 = pool};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(hint(&r, CLIENT, "silent.example.com"));
    ASSERT(syn_flow(&r, 50001));
    ASSERT(syn_flow(&r, 50002));
    ASSERT_EQ(202, probe_host("a.example"));
    cJSON *st = wait_status(has_result, "a.example");
    ASSERTm("no flow to the pool is counted", candidate(st, "example.com") == NULL);
    cJSON_Delete(st);
    rig_stop_loop(&r);
    ASSERT_EQ((size_t)2, g_n_pools);
    ASSERT_EQ(203, g_pools[0].base.b[0]);
    ASSERT_EQ(16, g_pools[0].prefix);
    ASSERT_EQ(0xfd, g_pools[1].base.b[0]);
    ASSERT_EQ(48, g_pools[1].prefix);
    rig_down(&r);
    PASS();
}

TEST an_empty_check_url_is_said_once(void) {
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL) | O_NONBLOCK);
    fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL) | O_NONBLOCK);
    firc_log_set_output_floor(FIRC_LOG_WARN);
    firc_log_set_fd(fds[1]);
    rig_t r;
    setup_t su = {.no_check_url = true};
    bool up = rig_up_with(&r, &su);
    bool probed_twice = up && probe_host("a.example") == 202;
    if (probed_twice) { cJSON_Delete(wait_status(has_result, "a.example")); }
    probed_twice = probed_twice && probe_host("b.example") == 202;
    if (probed_twice) { cJSON_Delete(wait_status(has_result, "b.example")); }
    if (up) { rig_stop_loop(&r); }
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    static char log[1 << 16];
    ssize_t n = read(fds[0], log, sizeof(log) - 1);
    log[n > 0 ? n : 0] = '\0';
    close(fds[0]);
    close(fds[1]);
    if (up) { rig_down(&r); }
    ASSERT(up && probed_twice);
    ASSERT_STR_EQ("", g_wan_url);
    static const char said[] = "autolist: app.check.url and app.check.wanUrl are both empty";
    const char *at = strstr(log, said);
    ASSERTm(log, at != NULL);
    ASSERTm("said once per start", strstr(at + 1, said) == NULL);
    PASS();
}

TEST a_rule_switched_on_again_takes_the_new_marker(void) {
    rig_t r;
    setup_t su = {.mode = "add"};
    ASSERT(rig_up_with(&r, &su));
    ASSERT(fail_once(&r, "a.off.example", 50001));
    ASSERT(fail_once(&r, "b.off.example", 50002));
    cand_want_t want = {"off.example", "added"};
    cJSON_Delete(wait_status(has_candidate, &want));
    rig_stop_loop(&r);
    const firc_rule_t *rule = rule_of(r.app, "off.example");
    ASSERT(rule != NULL);
    ASSERT(rule->enable);
    ASSERT(rule->autolist_by_domain);
    ASSERT_STR_EQ("a.off.example", rule->autolist);
    ASSERT_EQ((size_t)1, rules_named(r.app, "off.example"));
    rig_down(&r);
    PASS();
}

TEST a_user_probe_of_one_host_clears_the_domain_flag(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT(fail_once(&r, "a.many.example", 50001));
    ASSERT(fail_once(&r, "b.many.example", 50002));
    cand_want_t want = {"many.example", "candidate"};
    cJSON_Delete(wait_status(has_candidate, &want));
    plan("c.many.example", FIRC_AUTOLIST_BLOCKED, FIRC_AL_WHY_NO_CONNECT, false, 0);
    ASSERT_EQ(202, probe_host("c.many.example"));
    cJSON_Delete(wait_status(has_result, "c.many.example"));
    cJSON_Delete(wait_status(has_candidate, &want));
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/candidates/many.example/add", g_buf, sizeof(g_buf)));
    rig_stop_loop(&r);
    const firc_rule_t *rule = rule_of(r.app, "many.example");
    ASSERT(rule != NULL);
    ASSERT_STR_EQ("c.many.example", rule->autolist);
    ASSERT_FALSEm("the probe of one host is a host listing", rule->autolist_by_domain);
    rig_down(&r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(candidates_mode_adds_nothing);
    RUN_TEST(add_mode_adds_through_the_helper);
    RUN_TEST(candidate_add_route_adds_once);
    RUN_TEST(dismiss_hides_for_a_day);
    RUN_TEST(uncovered_client_stores_no_hint);
    RUN_TEST(a_device_that_never_asked_is_counted_apart);
    RUN_TEST(freeze_probe_makes_candidate);
    RUN_TEST(recheck_open_switches_off_keeps_marker);
    RUN_TEST(recheck_short_keeps_freeze_rule);
    RUN_TEST(check_iface_in_group_is_refused);
    RUN_TEST(recheck_rotates_past_32_rules);
    RUN_TEST(recheck_leaves_room_for_a_user_probe);
    RUN_TEST(nomination_of_an_added_domain_is_not_probed);
    RUN_TEST(candidate_add_over_a_hand_rule_is_refused);
    RUN_TEST(disable_enable_during_probe_keeps_one_thread);
    RUN_TEST(probe_route_429_when_budget_spent);
    RUN_TEST(reload_during_probe_keeps_one_thread);
    RUN_TEST(nomination_shows_checking_candidate);
    RUN_TEST(syn_nomination_shows_checking_candidate);
    RUN_TEST(recheck_goes_through_the_budget);
    RUN_TEST(list_group_takes_the_rule);
    RUN_TEST(block_group_is_not_running);
    RUN_TEST(add_mode_logs_the_write);
    RUN_TEST(open_probe_clears_a_checking_candidate);
    RUN_TEST(a_check_while_the_list_is_off_is_refused);
    RUN_TEST(test_check_result_freed_once);
    RUN_TEST(evicted_recheck_does_not_stick_checking);
    RUN_TEST(add_mode_over_a_hand_rule_stays_candidate);
    RUN_TEST(no_connect_probe_makes_candidate);
    RUN_TEST(no_connect_probe_adds_in_add_mode);
    RUN_TEST(domain_listing_marks_most_failed_host);
    RUN_TEST(short_after_domain_listing_keeps_rule);
    RUN_TEST(syn_domain_nomination_lists_by_domain);
    RUN_TEST(wan_unreachable_warns_until_a_check_passes);
    RUN_TEST(status_counts_ambiguous_flows);
    RUN_TEST(probe_checks_wan_through_check_urls);
    RUN_TEST(tick_probes_a_nomination_once);
    RUN_TEST(unknown_probe_after_no_connect_leaves_nothing);
    RUN_TEST(evicted_domain_candidate_still_lists_by_domain);
    RUN_TEST(host_listing_clears_the_domain_flag);
    RUN_TEST(a_confirmed_candidate_is_not_probed_again);
    RUN_TEST(a_confirmed_candidate_checked_again_by_hand_stays_checking);
    RUN_TEST(an_unknown_candidate_is_probed_again);
    RUN_TEST(syns_into_the_configured_pool_are_not_watched);
    RUN_TEST(an_empty_check_url_is_said_once);
    RUN_TEST(a_rule_switched_on_again_takes_the_new_marker);
    RUN_TEST(a_user_probe_of_one_host_clears_the_domain_flag);
    GREATEST_MAIN_END();
}
