#include "greatest.h"

#include <errno.h>
#include <stdio.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fake_conntrack.h"
#include "fake_iptables.h"
#include "fake_nflog.h"
#include "fake_rtnl.h"
#include "firc/ruleset.h"

#include "firc/app.h"
#include "firc/resolveroute.h"
#include "firc/conntrack.h"
#include "firc/fakeip.h"
#include "firc/mark.h"
#include "firc/iptables.h"
#include "firc/netfilter_cleaner.h"
#include "firc/port_remap.h"
#include "firc/log.h"
#include "firc/dnspipeline.h"
#include "firc/events.h"
#include "firc/recall.h"
#include "firc/rulesnap.h"
#include "firc/taprules.h"
#include <net/if.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>

static firc_group_t *make_group(const char *name, bool enable) {
    firc_group_t *g = firc_group_new();
    g->id = firc_id_random();
    firc_strset(&g->name, name);
    firc_strset(&g->iface, "eth0");
    g->enable = enable;
    return g;
}

static firc_rule_t *make_rule(void) {
    firc_rule_t *r = firc_rule_new();
    r->id = firc_id_random();
    firc_strset(&r->type, "domain");
    firc_strset(&r->rule, "example.com");
    r->enable = true;
    return r;
}

TEST create_wraps_preexisting_groups(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_config_add_group(&cfg, make_group("g1", false));
    firc_config_add_group(&cfg, make_group("g2", false));

    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);
    ASSERT(app != NULL);

    ASSERT_EQ(2u, firc_app_user_group_count(app));
    ASSERT_STR_EQ("g1", firc_ruleset_group(firc_app_user_group_at(app, 0))->name);
    ASSERT_STR_EQ("g2", firc_ruleset_group(firc_app_user_group_at(app, 1))->name);

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

TEST add_group_rejects_duplicate_id(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);

    firc_group_t *g1 = make_group("g1", false);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(app, g1));

    firc_group_t *dup = make_group("dup", false);
    dup->id = g1->id;
    ASSERT_EQ(FIRC_ERR_EXIST, firc_app_add_group(app, dup));
    ASSERT_EQ(1u, firc_app_user_group_count(app));
    ASSERT_EQ(1u, cfg.n_groups);

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

TEST add_group_rejects_duplicate_rule_id(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);

    firc_group_t *g = make_group("g", false);
    firc_rule_t *r1 = make_rule();
    firc_rule_t *r2 = make_rule();
    r2->id = r1->id;
    firc_group_add_rule(g, r1);
    firc_group_add_rule(g, r2);

    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_add_group(app, g));
    ASSERT_EQ(0u, firc_app_user_group_count(app));
    ASSERT_EQ(0u, cfg.n_groups);

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

TEST add_group_while_not_running_does_not_touch_netfilter(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);

    firc_group_t *g = make_group("g", true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(app, g));
    ASSERT_EQ(1u, firc_app_user_group_count(app));
    ASSERT(!firc_ruleset_runtime_enabled(firc_app_user_group_at(app, 0)));

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

TEST add_group_while_running_rolls_back_on_failure(void) {
    if (geteuid() == 0) { SKIPm("would write real rules as root"); }
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);

    firc_ipt_executable_t *exe4 = firc_ipt_executable_real_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt4 = firc_ipt_new(exe4);
    firc_rtnl_t *rtnl = firc_rtnl_open();
    ASSERT(ipt4 != NULL && rtnl != NULL);

    firc_app_deps_t deps = {.cfg = &cfg, .ipt4 = ipt4, .rtnl = rtnl};
    firc_app_t *app = firc_app_create(&deps);
    firc_app_set_running(app, true);

    firc_group_t *g = make_group("g", true);
    firc_err_t err = firc_app_add_group(app, g);
    ASSERT(err != FIRC_OK);
    ASSERT_EQ(0u, firc_app_user_group_count(app));
    ASSERT_EQ(0u, cfg.n_groups);

    firc_app_destroy(app);
    firc_ipt_free(ipt4);
    firc_rtnl_close(rtnl);
    firc_config_clear(&cfg);
    PASS();
}

TEST clear_groups_empties_both_lists(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);

    firc_app_add_group(app, make_group("a", false));
    firc_app_add_group(app, make_group("b", false));
    ASSERT_EQ(2u, firc_app_user_group_count(app));

    firc_app_clear_groups(app);
    ASSERT_EQ(0u, firc_app_user_group_count(app));
    ASSERT_EQ(0u, cfg.n_groups);

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

typedef struct {
    firc_config_t cfg;
    firc_fakeip_t *pool;
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
    firc_fake_ipt_t *fake6;
    firc_ipt_t *ipt6;
    firc_port_remap_t *remap;
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    fake_ct_t *ctk;
    firc_ct_t *ct;
    firc_dns_pipeline_t *pipeline;
    firc_resolve_router_t *router;
    firc_app_t *app;
} locked_app_t;

/* Fake nflog kernels, [0] new connections and [1] hellos: a real bind needs CAP_NET_ADMIN. */
static fake_nflog_t *g_tap_kernel[2];

static int tap_slot(uint16_t group) { return group == FIRC_TAP_GROUP_NEW ? 0 : 1; }

static firc_nflog_t *tap_fake_open(uint16_t group, uint16_t copy_range) {
    int w = tap_slot(group);
    fake_nflog_stop(g_tap_kernel[w]);
    int fd = -1;
    g_tap_kernel[w] = fake_nflog_start(&fd);
    if (g_tap_kernel[w] == NULL) { return NULL; }
    return firc_nflog_open_fd(fd, group, copy_range);
}

static int g_iface_there = -1;
static unsigned test_iface_index(const char *name) {
    if (g_iface_there >= 0) { return g_iface_there ? 1u : 0u; }
    return if_nametoindex(name);
}

static int64_t g_capture_seconds;

static firc_dnsproxy_t *g_app_proxy;
static uint64_t (*g_app_mono)(void);
static char g_proxy_sentinel_byte;
#define PROXY_SENTINEL ((firc_dnsproxy_t *)(void *)&g_proxy_sentinel_byte)

typedef struct {
    firc_id_t ids[16];
    size_t n;
} id_log_t;

static id_log_t g_closed, g_forgot;

static void id_log_add(id_log_t *l, firc_id_t id) {
    if (l->n < sizeof(l->ids) / sizeof(l->ids[0])) { l->ids[l->n++] = id; }
}

static size_t id_log_count(const id_log_t *l, firc_id_t id) {
    size_t c = 0;
    for (size_t i = 0; i < l->n; i++) { c += firc_id_equal(l->ids[i], id) ? 1u : 0u; }
    return c;
}

void __real_firc_dnsproxy_close_group_pools(firc_dnsproxy_t *p, firc_id_t group_id);
void __real_firc_dnsproxy_forget_group(firc_dnsproxy_t *p, firc_id_t group_id);
void __wrap_firc_dnsproxy_close_group_pools(firc_dnsproxy_t *p, firc_id_t group_id);
void __wrap_firc_dnsproxy_forget_group(firc_dnsproxy_t *p, firc_id_t group_id);

void __wrap_firc_dnsproxy_close_group_pools(firc_dnsproxy_t *p, firc_id_t group_id) {
    if (p == PROXY_SENTINEL) {
        id_log_add(&g_closed, group_id);
        return;
    }
    __real_firc_dnsproxy_close_group_pools(p, group_id);
}

void __wrap_firc_dnsproxy_forget_group(firc_dnsproxy_t *p, firc_id_t group_id) {
    if (p == PROXY_SENTINEL) {
        id_log_add(&g_forgot, group_id);
        return;
    }
    __real_firc_dnsproxy_forget_group(p, group_id);
}

static bool locked_app_up_ex(locked_app_t *l, firc_loop_t *loop,
                             firc_nflog_t *(*nflog_open)(uint16_t, uint16_t), bool committer);
static bool locked_app_up_full(locked_app_t *l, firc_loop_t *loop,
                               firc_nflog_t *(*nflog_open)(uint16_t, uint16_t));

static bool locked_app_up_with_loop(locked_app_t *l, firc_loop_t *loop) {
    return locked_app_up_full(l, loop, tap_fake_open);
}

static bool locked_app_up(locked_app_t *l) {
    return locked_app_up_full(l, NULL, tap_fake_open);
}

/* The harness plus a DNS pipeline and a loop nothing runs, so a test can fill its queue. */
static bool locked_app_up_ex(locked_app_t *l, firc_loop_t *loop,
                             firc_nflog_t *(*nflog_open)(uint16_t, uint16_t), bool committer) {
    memset(l, 0, sizeof(*l));
    firc_event_reset_for_test();
    firc_config_init_defaults(&l->cfg);
    {
        firc_fakeip_cfg_t pc = {0};
        pc.v4.base.len = 4; pc.v4.base.b[0] = 198; pc.v4.base.b[1] = 18;
        pc.v4.pool_cidr = 15; pc.v4.chunk_cidr = 24;
        pc.v6.base.len = 16; pc.v6.base.b[0] = 0xfd; pc.v6.base.b[1] = 0x37;
        pc.v6.pool_cidr = 48; pc.v6.chunk_cidr = 64;
        pc.max_names = 64; pc.idle_secs = 86400; pc.clamp_secs = 300;
        if (firc_fakeip_new(&pc, &l->pool) != FIRC_OK) { return false; }
    }
    l->pipeline = firc_dns_pipeline_create();
    if (l->pipeline == NULL) { return false; }
    l->router = firc_resolve_router_new(l->pipeline);
    if (l->router == NULL) { return false; }
    l->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    l->ipt = firc_ipt_new(firc_fake_ipt_as_executable(l->fake));
    l->fake6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    l->ipt6 = firc_ipt_new(firc_fake_ipt_as_executable(l->fake6));
    firc_netfilter_register_base_chains(l->ipt, l->ipt6);
    l->kernel = fake_rtnl_start(&l->rtnl);
    if (l->kernel == NULL) { return false; }
    l->ctk = fake_ct_start(&l->ct);
    if (l->ctk == NULL) { return false; }
    firc_app_deps_t deps = {.cfg = &l->cfg,
                            .ipt4 = l->ipt,
                            .ipt6 = l->ipt6,
                            .rtnl = l->rtnl,
                            .ct = l->ct,
                            .pipeline = l->pipeline,
                            .router = l->router,
                            .proxy = g_app_proxy,
                            .pool = l->pool,
                            .loop = loop,
                            .nflog_open = nflog_open,
                            .iface_index = test_iface_index,
                            .capture_seconds = g_capture_seconds,
                            .mono_ms = g_app_mono};
    l->app = firc_app_create(&deps);
    l->remap = firc_port_remap_new(l->cfg.app.netfilter.iptables.chain_prefix, 53, 3553, NULL, 0,
                                  l->ipt, NULL);
    if (firc_port_remap_enable(l->remap) != FIRC_OK) { return false; }
    firc_fake_ipt_reset(l->fake);
    static const char *pre[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *rules[1] = {pre};
    size_t lens[1] = {4};
    firc_fake_ipt_set_initial_rules(l->fake, "nat", "PREROUTING", rules, lens, 1);
    firc_app_set_port_remap(l->app, l->remap);
    return !committer || firc_app_start_netfilter_committer(l->app) == FIRC_OK;
}

static bool locked_app_up_full(locked_app_t *l, firc_loop_t *loop,
                               firc_nflog_t *(*nflog_open)(uint16_t, uint16_t)) {
    return locked_app_up_ex(l, loop, nflog_open, true);
}

/* The harness with no committer: enable and teardown write their chains on the calling thread. */
static bool locked_app_up_no_committer(locked_app_t *l) {
    return locked_app_up_ex(l, NULL, tap_fake_open, false);
}

/* Everything but the app, for the test that destroys the app itself. */
static void locked_app_down_rest(locked_app_t *l) {
    g_iface_there = -1;
    g_capture_seconds = 0;
    g_app_proxy = NULL;
    g_app_mono = NULL;
    for (int w = 0; w < 2; w++) {
        fake_nflog_stop(g_tap_kernel[w]);
        g_tap_kernel[w] = NULL;
    }
    firc_ct_close(l->ct);
    fake_ct_stop(l->ctk);
    firc_port_remap_free(l->remap);
    firc_rtnl_close(l->rtnl);
    fake_rtnl_stop(l->kernel);
    firc_ipt_free(l->ipt);
    firc_ipt_free(l->ipt6);
    firc_resolve_router_free(l->router);
    firc_dns_pipeline_destroy(l->pipeline);
    firc_fakeip_free(l->pool);
    firc_config_clear(&l->cfg);
}

static void locked_app_down(locked_app_t *l) {
    firc_app_destroy(l->app);
    l->app = NULL;
    locked_app_down_rest(l);
}

static void sleep_ms(long ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool pass_landed(const locked_app_t *l) {
    return firc_fake_ipt_chain_exists(l->fake, "nat", "FIRC_DNSOR");
}

static void *drain_loop(void *ud);

/* Capture state belongs to the loop thread, so tests run the loop on this thread, never a second one. */
static void stop_the_loop(firc_loop_t *loop, void *ud) {
    (void)ud;
    firc_loop_stop(loop);
}

/* Call once per loop: firc_loop_stop is final, and a second run dispatches nothing. */
static bool run_loop_for(firc_loop_t *loop, uint64_t ms) {
    int id = 0;
    if (firc_loop_add_timer(loop, ms, 0, stop_the_loop, loop, &id) != FIRC_OK) { return false; }
    return firc_loop_run(loop) == FIRC_OK;
}

static bool tap_chain_there(const locked_app_t *l) {
    return firc_fake_ipt_chain_exists(l->fake, "mangle", "FIRC_TAP");
}

static bool tap_chain_there6(const locked_app_t *l) {
    return firc_fake_ipt_chain_exists(l->fake6, "mangle", "FIRC_TAP");
}

static bool wait_for_chain(const locked_app_t *l, bool want) {
    for (int i = 0; i < 500; i++) {
        if (tap_chain_there(l) == want) { return true; }
        sleep_ms(10);
    }
    return tap_chain_there(l) == want;
}

/* The first rule the capture staged, joined, for asserting on */
static bool tap_rule_text(const locked_app_t *l, char *out, size_t cap) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    out[0] = '\0';
    firc_app_nf_enter(l->app);
    char *s = NULL;
    if (firc_fake_ipt_get_rules(l->fake, "mangle", "FIRC_TAP", &rules, &n) && n > 0) {
        s = firc_ipt_rule_string(rules[0]);
    }
    firc_app_nf_leave(l->app);
    if (s == NULL) { return false; }
    snprintf(out, cap, "%s", s);
    free(s);
    return true;
}

static bool running(const locked_app_t *l) {
    firc_capture_status_t st;
    firc_app_capture_status(l->app, &st);
    return st.running;
}

static firc_event_t g_events[256];

static size_t journal(uint64_t since) {
    uint64_t next = 0, dropped = 0;
    return firc_event_read(since, g_events, sizeof(g_events) / sizeof(g_events[0]), &next,
                           &dropped);
}

static bool journal_says(uint64_t since, const char *needle) {
    size_t n = journal(since);
    for (size_t i = 0; i < n; i++) {
        if (g_events[i].kind == FIRC_EVENT_LOG && strstr(g_events[i].u.log.text, needle) != NULL) {
            return true;
        }
    }
    return false;
}

/* The last seq in the journal, for reading only what comes after it */
static uint64_t journal_mark(void) {
    size_t n = journal(0);
    return n > 0 ? g_events[n - 1].seq : 0;
}

/* The bypass events past `since`, copied to `out` (at most `cap`) */
static size_t journal_bypasses(uint64_t since, firc_event_bypass_t *out, size_t cap) {
    size_t n = journal(since), k = 0;
    for (size_t i = 0; i < n; i++) {
        if (g_events[i].kind != FIRC_EVENT_BYPASS) { continue; }
        if (k < cap) { out[k] = g_events[i].u.bypass; }
        k++;
    }
    return k;
}

static const uint8_t k_client[] = {192, 168, 1, 42};
static const uint8_t k_real[] = {104, 21, 0, 5};

/* A ClientHello naming `sni` from `client`, as the kernel copies it to the hello socket */
static bool send_hello(const uint8_t *client, const uint8_t *dst, const char *sni) {
    uint8_t rec[1024], pkt[1200], dg[1400];
    size_t rl = fake_nflog_hello(rec, sni);
    size_t pl = fake_nflog_packet(pkt, client, dst, 443, rec, rl);
    return g_tap_kernel[1] != NULL &&
           fake_nflog_send(g_tap_kernel[1], dg, fake_nflog_msg(dg, pkt, pl));
}

/* A new connection's headers, as the kernel copies them to the new-connection socket */
static bool send_new(const uint8_t *client, const uint8_t *dst, uint16_t port) {
    static const uint8_t no_payload[1];
    uint8_t pkt[64], dg[256];
    size_t pl = fake_nflog_packet(pkt, client, dst, port, no_payload, 0);
    return g_tap_kernel[0] != NULL &&
           fake_nflog_send(g_tap_kernel[0], dg, fake_nflog_msg(dg, pkt, pl));
}

/* How many bypass events the journal holds past `since` from `client` */
static size_t bypasses_from(uint64_t since, const uint8_t *client) {
    firc_event_bypass_t b[16];
    size_t n = journal_bypasses(since, b, 16), k = 0;
    for (size_t i = 0; i < n && i < 16; i++) {
        if (b[i].client.len == 4 && memcmp(b[i].client.b, client, 4) == 0) { k++; }
    }
    return k;
}

/* Catches: a firmware table rewrite removing the capture rules with no pass putting them back. */
TEST a_capture_survives_the_firmware_rewriting_the_table(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERTm("the capture's rules reached the kernel", wait_for_chain(&l, true));
    bool six = tap_chain_there6(&l);
    for (int i = 0; i < 500 && !six; i++) {
        sleep_ms(10);
        six = tap_chain_there6(&l);
    }
    ASSERTm("both families, not just the first", six);

    char rule[512];
    ASSERT(tap_rule_text(&l, rule, sizeof(rule)));
    ASSERTm("the rule captures what arrives on the LAN interface", strstr(rule, "-i br0 ") != NULL);

    firc_fake_ipt_reset(l.fake);
    ASSERT_FALSE(tap_chain_there(&l));
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    ASSERTm("the pass that follows puts them back, with nobody asking", wait_for_chain(&l, true));

    firc_fake_ipt_reset(l.fake);
    firc_fake_ipt_fail_next_restore(l.fake, FIRC_ERR_IO);
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    sleep_ms(200);
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    ASSERTm("a pass that follows a failed one stages the capture again", wait_for_chain(&l, true));

    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERTm("and stopping it takes them away", wait_for_chain(&l, false));

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT(wait_for_chain(&l, true));
    firc_fake_ipt_reset(l.fake);
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    sleep_ms(300);
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    sleep_ms(400);
    ASSERT_FALSEm("a capture stopped after a wipe does not come back", tap_chain_there(&l));
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    sleep_ms(300);
    ASSERT_FALSEm("and it stays gone", tap_chain_there(&l));

    firc_app_nf_enter(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(l.app, NULL, false));
    firc_app_nf_leave(l.app);
    ASSERT_FALSEm("an incremental pass does not resurrect a stopped capture", tap_chain_there(&l));

    locked_app_down(&l);
    PASS();
}

/* Catches: a capture judging by the config on disk instead of the groups the daemon holds. */
TEST a_group_the_api_made_is_what_the_capture_judges_by(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));

    firc_group_t *g = make_group("media", true);
    firc_group_add_rule(g, make_rule());
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    uint64_t since = journal_mark();
    ASSERT(send_hello(k_client, k_real, "example.com"));
    ASSERT(run_loop_for(loop, 300));

    firc_event_bypass_t b[4];
    ASSERT_EQ_FMTm("the packet became one bypass event", (size_t)1,
                   journal_bypasses(since, b, 4), "%zu");
    ASSERT_STR_EQ("example.com", b[0].name);
    ASSERT_STR_EQ("media", b[0].group_name);
    ASSERT_EQ_FMTm("by the SNI: firc recalls nothing behind that address", FIRC_BYPASS_BY_SNI,
                   (int)b[0].how, "%d");

    since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERTm("and the capture accounts for what it read",
            journal_says(since, "1 packet read, 1 bypass reported"));

    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: a capture reading only one socket (new connections by address, hellos by SNI). */
TEST a_capture_reads_both_sockets(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));

    firc_group_t *g = make_group("media", true);
    firc_group_add_rule(g, make_rule());
    firc_rule_t *other = firc_rule_new();
    other->id = firc_id_random();
    firc_strset(&other->type, "domain");
    firc_strset(&other->rule, "video.example.net");
    other->enable = true;
    firc_group_add_rule(g, other);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));

    firc_recall_t *recall = firc_dns_pipeline_recall(l.pipeline);
    ASSERT(recall != NULL);
    firc_ip_t real = {0};
    real.len = 4;
    memcpy(real.b, k_real, 4);
    char gid[FIRC_ID_STR_LEN];
    firc_id_format(g->id, gid);
    firc_recall_real(recall, &real, "example.com", gid, (int64_t)time(NULL));

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    uint16_t bound = 0;
    ASSERT(g_tap_kernel[0] != NULL && g_tap_kernel[1] != NULL);
    ASSERT(fake_nflog_is_bound(g_tap_kernel[0], &bound));
    ASSERT_EQ_FMT(FIRC_TAP_GROUP_NEW, (int)bound, "%d");
    ASSERT(fake_nflog_is_bound(g_tap_kernel[1], &bound));
    ASSERT_EQ_FMT(FIRC_TAP_GROUP_HELLO, (int)bound, "%d");

    uint64_t since = journal_mark();
    ASSERT(send_new(k_client, k_real, 443));
    static const uint8_t elsewhere[] = {151, 101, 1, 1};
    ASSERT(send_hello(k_client, elsewhere, "video.example.net"));
    ASSERT(run_loop_for(loop, 300));

    firc_event_bypass_t b[4];
    size_t n = journal_bypasses(since, b, 4);
    ASSERT_EQ_FMTm("one event from each socket", (size_t)2, n, "%zu");
    bool by_addr = false, by_sni = false;
    for (size_t i = 0; i < n; i++) {
        if (b[i].how == FIRC_BYPASS_BY_ADDR && strcmp(b[i].name, "example.com") == 0) {
            by_addr = true;
        }
        if (b[i].how == FIRC_BYPASS_BY_SNI && strcmp(b[i].name, "video.example.net") == 0) {
            by_sni = true;
        }
    }
    ASSERTm("the new connection, by the address firc recalled", by_addr);
    ASSERTm("the hello, by its SNI", by_sni);

    since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERTm("2 packets read", journal_says(since, "2 packets read, 2 bypasses reported"));
    ASSERT_FALSEm("a recall that held an address is not called cold",
                  journal_says(since, "recorded no real address"));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

static int g_policy_calls;

static bool policy_has_42(const char *policy, const firc_ip_t *client, void *ud) {
    (void)ud;
    g_policy_calls++;
    return strcmp(policy, "vpn") == 0 && client->len == 4 && client->b[3] == 42;
}

static firc_group_t *policy_group(void) {
    firc_group_t *g = make_group("media", true);
    g->devices.allow = calloc(1, sizeof(char *));
    if (g->devices.allow != NULL) {
        g->devices.allow[0] = strdup("policy:vpn");
        g->devices.n_allow = 1;
    }
    firc_group_add_rule(g, make_rule());
    return g;
}

TEST a_policy_scoped_group_is_judged_with_the_daemons_resolvers(void) {
    static const uint8_t other[] = {192, 168, 1, 43};

    {
        firc_loop_t *loop = NULL;
        ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
        locked_app_t l;
        ASSERT(locked_app_up_with_loop(&l, loop));
        ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, policy_group()));
        ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
        uint64_t since = journal_mark();
        ASSERT(send_hello(k_client, k_real, "example.com"));
        ASSERT(run_loop_for(loop, 300));
        ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
        ASSERTm("the hello was read", journal_says(since, "1 packet read"));
        ASSERT_EQ_FMTm("with no resolver the policy covers nobody", (size_t)0,
                       bypasses_from(since, k_client), "%zu");
        locked_app_down(&l);
        firc_loop_destroy(loop);
    }

    {
        firc_loop_t *loop = NULL;
        ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
        locked_app_t l;
        ASSERT(locked_app_up_with_loop(&l, loop));
        g_policy_calls = 0;
        firc_app_set_policy_resolver(l.app, policy_has_42, NULL, NULL);
        firc_dns_pipeline_set_policy_resolver(l.pipeline, policy_has_42, NULL, NULL);
        ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, policy_group()));

        ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
        uint64_t since = journal_mark();
        ASSERT(send_hello(k_client, k_real, "example.com"));
        ASSERT(send_hello(other, k_real, "example.com"));
        ASSERT(run_loop_for(loop, 300));
        ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
        ASSERTm("both hellos were read", journal_says(since, "2 packets read"));
        ASSERT_EQ_FMTm("the client the policy covers is the bypass", (size_t)1,
                       bypasses_from(since, k_client), "%zu");
        ASSERTm("and the resolver is what said so", g_policy_calls > 0);
        ASSERT_EQ_FMTm("a client outside the policy is nobody's business here", (size_t)0,
                       bypasses_from(since, other), "%zu");
        locked_app_down(&l);
        firc_loop_destroy(loop);
    }
    PASS();
}

typedef struct {
    locked_app_t *l;
    uint64_t since;
    size_t before;
    firc_err_t added;
} mid_add_t;

static void add_group_mid_capture(firc_loop_t *loop, void *ud) {
    (void)loop;
    mid_add_t *m = ud;
    m->before = bypasses_from(m->since, k_client);
    firc_group_t *g = make_group("media", true);
    firc_group_add_rule(g, make_rule());
    m->added = firc_app_add_group(m->l->app, g);
    (void)send_hello(k_client, k_real, "example.com");
}

TEST a_group_added_during_a_capture_is_judged_against(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    mid_add_t m = {&l, journal_mark(), 99, FIRC_ERR_STATE};
    ASSERT(send_hello(k_client, k_real, "example.com"));
    int id = 0;
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 200, 0, add_group_mid_capture, &m, &id));
    ASSERT(run_loop_for(loop, 500));
    ASSERT_EQ(FIRC_OK, m.added);
    ASSERT_EQ_FMTm("with no group the first hello was nothing to report", (size_t)0, m.before,
                   "%zu");
    ASSERT_EQ_FMTm("the group the daemon just took on is the one the capture judges by",
                   (size_t)1, bypasses_from(m.since, k_client), "%zu");

    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERTm("and both hellos were read", journal_says(m.since, "2 packets read"));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: a capture on a missing interface reporting the same summary as five quiet minutes. */
TEST a_capture_on_an_interface_that_is_not_there_says_so(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    char *lo[] = {"lo"};
    char **kept = l.cfg.app.link;
    size_t n_kept = l.cfg.app.n_link;
    l.cfg.app.link = lo;
    l.cfg.app.n_link = 1;

    uint64_t since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERT_FALSEm("lo is there, so nothing to say", journal_says(since, "does not exist"));
    ASSERT_FALSE(journal_says(since, "went away"));

    char *two[] = {"lo", "nosuchif0"};
    l.cfg.app.link = two;
    l.cfg.app.n_link = 2;
    since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERTm("one missing of two is said", journal_says(since, "does not exist"));

    l.cfg.app.link = lo;
    l.cfg.app.n_link = 1;
    g_iface_there = 0;
    since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    g_iface_there = 1;
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERT_FALSEm("not the verdict on the whole capture", journal_says(since, "does not exist"));
    ASSERTm("but the seconds it was away are not claimed", journal_says(since, "went away"));

    l.cfg.app.link = kept;
    l.cfg.app.n_link = n_kept;
    locked_app_down(&l);
    PASS();
}

/* Waits until the fake has refused a restore since `before`, then lets the committer count it */
static bool a_restore_was_tried(const locked_app_t *l, size_t before) {
    for (int i = 0; i < 500; i++) {
        if (firc_fake_ipt_restore_calls(l->fake) > before) {
            sleep_ms(100);
            return true;
        }
        sleep_ms(10);
    }
    return false;
}

/* Catches: a pass that failed during a capture, leaving its rules out, missing from its report. */
TEST a_pass_that_failed_while_a_capture_ran_is_said_out_loud(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));

    uint64_t since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT(wait_for_chain(&l, true));
    size_t before = firc_fake_ipt_restore_calls(l.fake);
    firc_fake_ipt_fail_next_restore(l.fake, FIRC_ERR_IO);
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    ASSERTm("the pass that fails actually ran", a_restore_was_tried(&l, before));
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERTm("the seconds that were not watched are counted",
            journal_says(since, "netfilter pass failed"));

    since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT(wait_for_chain(&l, true));
    before = firc_fake_ipt_restore_calls(l.fake);
    firc_fake_ipt_fail_next_restore(l.fake, FIRC_ERR_AGAIN);
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    ASSERT(a_restore_was_tried(&l, before));
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERT(journal_says(since, "capture stopped"));
    ASSERT_FALSEm("a raced pass is not an unwatched second", journal_says(since, "netfilter pass"));

    locked_app_down(&l);
    PASS();
}

/* Catches: a failed-pass count from one capture carried into the next capture's report. */
TEST one_captures_failed_pass_is_not_the_next_ones(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    size_t before = firc_fake_ipt_restore_calls(l.fake);
    firc_fake_ipt_fail_next_restore(l.fake, FIRC_ERR_IO);
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    ASSERTm("the pass that fails actually ran", a_restore_was_tried(&l, before));
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));

    uint64_t since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 2000, NULL));
    sleep_ms(300);
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERT(journal_says(since, "capture stopped"));
    ASSERT_FALSEm("this capture's rules were never gone", journal_says(since, "netfilter pass"));

    locked_app_down(&l);
    PASS();
}

/* Catches: a capture started on a kernel without xt_string, whose refused rules fail every pass. */
TEST a_rule_this_kernel_will_not_take_does_not_start_a_capture(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    bool landed = false;
    for (int i = 0; i < 500 && !landed; i++) {
        sleep_ms(10);
        landed = pass_landed(&l);
    }
    ASSERTm("a pass got through before the capture was asked for", landed);

    firc_fake_ipt_refuse_rules_containing(l.fake, "-m string");
    ASSERT_EQ_FMTm("its own answer, not a 500", FIRC_ERR_NOSYS,
                   firc_app_capture_start(l.app, 1000, NULL), "%d");
    ASSERT_FALSEm("nothing is left running", running(&l));
    ASSERT_FALSEm("and the capture rules were never staged", tap_chain_there(&l));
    sleep_ms(200);
    ASSERTm("the DNS remap survived the refusal", pass_landed(&l));
    firc_fake_ipt_refuse_rules_containing(l.fake, "--ctorigdst");
    ASSERT_EQ(FIRC_ERR_NOSYS, firc_app_capture_start(l.app, 1000, NULL));

    firc_fake_ipt_refuse_rules_containing(l.fake, NULL);
    firc_fake_ipt_refuse_rules_containing(l.fake6, "-m string");
    ASSERT_EQ_FMTm("v6 counts", FIRC_ERR_NOSYS, firc_app_capture_start(l.app, 1000, NULL), "%d");
    ASSERT_FALSE(running(&l));

    firc_fake_ipt_refuse_rules_containing(l.fake6, NULL);
    firc_fake_ipt_fail_next_restore(l.fake, FIRC_ERR_CANCELED);
    ASSERT_EQ_FMTm("a question that did not get out starts the capture", FIRC_OK,
                   firc_app_capture_start(l.app, 1000, NULL), "%d");
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    firc_fake_ipt_fail_next_restore(l.fake, FIRC_ERR_AGAIN);
    ASSERT_EQ_FMTm("nor does a lost race refuse it", FIRC_OK,
                   firc_app_capture_start(l.app, 1000, NULL), "%d");
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));

    locked_app_down(&l);
    PASS();
}

static firc_nflog_t *tap_open_refused(uint16_t group, uint16_t copy_range) {
    (void)group;
    (void)copy_range;
    return NULL;
}

/* Binds the new-connection group and refuses the hello group, as if another process held it. */
static firc_nflog_t *tap_hello_refused(uint16_t group, uint16_t copy_range) {
    if (group == FIRC_TAP_GROUP_HELLO) { return NULL; }
    return tap_fake_open(group, copy_range);
}

/* Catches: a capture starting with an NFLOG group unbound, so nobody reads what it copies. */
TEST a_capture_that_cannot_read_does_not_start(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_full(&l, loop, tap_open_refused));
    ASSERT_EQ(FIRC_ERR_SYS, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT_FALSEm("and nothing is left running", running(&l));
    locked_app_down(&l);
    firc_loop_destroy(loop);

    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT(locked_app_up_full(&l, loop, tap_hello_refused));
    ASSERT_EQ(FIRC_ERR_SYS, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT_FALSE(running(&l));
    ASSERT(g_tap_kernel[0] != NULL);
    ASSERT_FALSEm("the group that did bind was let go again",
                  fake_nflog_send(g_tap_kernel[0], "x", 1));
    sleep_ms(300);
    ASSERT_FALSEm("and no rules were staged for it", tap_chain_there(&l));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

static int g_broken_fd = -1;

static firc_nflog_t *tap_hello_breaks(uint16_t group, uint16_t copy_range) {
    firc_nflog_t *n = tap_fake_open(group, copy_range);
    if (n == NULL || group != FIRC_TAP_GROUP_HELLO) { return n; }
    int ev = eventfd(0, EFD_NONBLOCK);
    if (ev < 0 || dup2(ev, firc_nflog_fd(n)) < 0) { return n; }
    close(ev);
    g_broken_fd = firc_nflog_fd(n);
    return n;
}

TEST a_reader_that_breaks_ends_the_capture(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    g_broken_fd = -1;
    ASSERT(locked_app_up_full(&l, loop, tap_hello_breaks));
    uint64_t since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT(g_broken_fd >= 0);
    uint64_t one = 1;
    ASSERT_EQ((ssize_t)sizeof(one), write(g_broken_fd, &one, sizeof(one)));
    ASSERT(run_loop_for(loop, 300));

    ASSERT_FALSEm("the capture ended", running(&l));
    ASSERTm("and the journal names the reader that failed",
            journal_says(since, "ClientHello reader failed"));
    ASSERTm("and says the capture stopped", journal_says(since, "capture stopped"));
    ASSERT(g_tap_kernel[0] != NULL);
    ASSERT_FALSEm("the other reader went with it", fake_nflog_send(g_tap_kernel[0], "x", 1));
    ASSERTm("and the rules with them", wait_for_chain(&l, false));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: a capture running past its deadline when nobody stops it. */
TEST the_deadline_ends_the_capture_by_itself(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    g_capture_seconds = 1;
    ASSERT(locked_app_up_with_loop(&l, loop));

    uint64_t since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT(running(&l));

    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, drain_loop, loop));
    bool ended = false;
    for (int i = 0; i < 400 && !ended; i++) {
        sleep_ms(10);
        ended = !running(&l);
    }
    ASSERTm("the capture ended on its own", ended);
    ASSERTm("and took its rules with it", wait_for_chain(&l, false));

    firc_app_stop_netfilter_committer(l.app);
    firc_loop_stop(loop);
    pthread_join(th, NULL);
    locked_app_down(&l);
    firc_loop_destroy(loop);
    ASSERTm("and said so", journal_says(since, "capture reached its end"));
    PASS();
}

/* Catches: an early stop leaving its timer armed, which then ends the next capture early. */
TEST stopping_early_disarms_the_deadline(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    g_capture_seconds = 1;
    ASSERT(locked_app_up_with_loop(&l, loop));

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    sleep_ms(600);
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT(run_loop_for(loop, 700));
    ASSERTm("the second capture outlived the first one's clock", running(&l));

    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: a later pass or a refused second start retargeting the running capture's interfaces. */
TEST the_rules_carry_the_interfaces_the_capture_started_with(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    char rule[512];
    char *eth0[] = {"eth0"};
    char *wg1[] = {"wg1"};
    char **kept = l.cfg.app.link;
    size_t n_kept = l.cfg.app.n_link;
    l.cfg.app.link = eth0;
    l.cfg.app.n_link = 1;

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT(wait_for_chain(&l, true));
    ASSERT(tap_rule_text(&l, rule, sizeof(rule)));
    ASSERT_STR_EQm("the new-connection rule, first, on eth0",
                   "-i eth0 -m conntrack --ctstate NEW ! --ctorigdst 198.18.0.0/15 "
                   "-m mark ! --mark 0x40000000/0x40000000 -m limit "
                   "--limit 500/sec --limit-burst 500 -j NFLOG --nflog-group 5 "
                   "--nflog-threshold 1",
                   rule);

    l.cfg.app.link = wg1;
    ASSERT_EQ(FIRC_ERR_EXIST, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    sleep_ms(400);
    ASSERT(wait_for_chain(&l, true));
    ASSERT(tap_rule_text(&l, rule, sizeof(rule)));
    ASSERTm("neither retargeted the running capture",
            strstr(rule, "-i eth0 ") != NULL && strstr(rule, "wg1") == NULL);

    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    l.cfg.app.link = kept;
    l.cfg.app.n_link = n_kept;
    locked_app_down(&l);
    PASS();
}

/* Catches: a capture with no pool refused as a bad interface name instead of a missing pool. */
TEST a_capture_without_a_pool_says_which_thing_is_missing(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);
    ASSERT(app != NULL);
    ASSERT_EQ_FMTm("not INVAL, which is what a bad interface gets", FIRC_ERR_STATE,
                   firc_app_capture_start(app, 1000, NULL), "%d");
    firc_capture_status_t st;
    firc_app_capture_status(app, &st);
    ASSERT_FALSE(st.running);
    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a daemon stop writing the capture rules back while it removes the DNAT chain. */
TEST stopping_the_daemon_ends_the_capture(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));

    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT(wait_for_chain(&l, true));
    firc_fake_ipt_reset(l.fake);
    ASSERT_FALSE(tap_chain_there(&l));

    uint64_t since = journal_mark();
    firc_app_destroy(l.app);
    l.app = NULL;
    ASSERT_FALSEm("a stopped daemon left an NFLOG rule behind", tap_chain_there(&l));
    ASSERTm("and the journal says the capture ended", journal_says(since, "capture stopped"));
    locked_app_down_rest(&l);
    PASS();
}

/* Catches: a second capture at once, a length the caller picks, or a start with no LAN interface. */
TEST a_capture_has_a_deadline_and_only_one_exists(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));

    char **kept = l.cfg.app.link;
    size_t n_kept = l.cfg.app.n_link;
    l.cfg.app.n_link = 0;
    ASSERT_EQm("no LAN interface", FIRC_ERR_INVAL, firc_app_capture_start(l.app, 1000, NULL));
    char *too_long[] = {"an-interface-name-of-thirty"};
    l.cfg.app.link = too_long;
    l.cfg.app.n_link = 1;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_capture_start(l.app, 1000, NULL));
    l.cfg.app.link = kept;
    l.cfg.app.n_link = n_kept;
    ASSERT_FALSEm("none of those started anything", running(&l));

    uint64_t locks = firc_app_nf_enters_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    ASSERT_EQ_FMTm("starting takes the netfilter lock", (unsigned long long)(locks + 1),
                   (unsigned long long)firc_app_nf_enters_for_test(l.app), "%llu");
    firc_capture_status_t st;
    firc_app_capture_status(l.app, &st);
    ASSERT(st.running);
    ASSERT_EQ_FMTm("it ends five minutes after it started", 1000L + FIRC_CAPTURE_SECONDS,
                   (long)st.ends_at, "%ld");
    /* A range, never tighten to 300: the monotonic clock truncates, so a read across a second gives 299. */
    ASSERTm("what it actually has left", st.seconds_left >= FIRC_CAPTURE_SECONDS - 1 &&
                                             st.seconds_left <= FIRC_CAPTURE_SECONDS);

    ASSERT_EQm("a second capture would be a second chain with one name", FIRC_ERR_EXIST,
               firc_app_capture_start(l.app, 1000, NULL));
    l.cfg.app.n_link = 0;
    firc_err_t emptied = firc_app_capture_start(l.app, 1000, NULL);
    l.cfg.app.n_link = n_kept;
    ASSERT_EQ_FMTm("running is the answer even with link emptied", FIRC_ERR_EXIST, emptied,
                   "%d");
    locks = firc_app_nf_enters_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    ASSERTm("stopping takes the lock too", firc_app_nf_enters_for_test(l.app) > locks);
    ASSERT_FALSE(running(&l));
    ASSERT_EQm("stopping twice is not an error", FIRC_OK, firc_app_capture_stop(l.app, NULL));
    locked_app_down(&l);

    g_capture_seconds = 1;
    ASSERT(locked_app_up(&l));
    ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
    sleep_ms(1300);
    firc_app_capture_status(l.app, &st);
    ASSERT(st.running);
    ASSERT_EQ_FMTm("a capture past its end has nothing left, not less than nothing", 0L,
                   (long)st.seconds_left, "%ld");
    ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
    locked_app_down(&l);
    PASS();
}

/* Catches: a capture whose start, stop or summary is missing from the journal at any log level. */
TEST a_capture_logs_its_start_its_stop_and_its_summary(void) {
    firc_log_level_t kept = firc_log_level();
    static const firc_log_level_t levels[] = {FIRC_LOG_INFO, FIRC_LOG_ERROR};
    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
        locked_app_t l;
        ASSERT(locked_app_up(&l));
        firc_log_set_level(levels[i]);
        ASSERT_EQ(FIRC_OK, firc_app_capture_start(l.app, 1000, NULL));
        ASSERT_EQ(FIRC_OK, firc_app_capture_stop(l.app, NULL));
        firc_log_set_level(kept);

        char why[64];
        snprintf(why, sizeof(why), "the start, at level %d", (int)levels[i]);
        ASSERTm(why, journal_says(0, "capture started: 300s on the LAN side, on br0"));
        snprintf(why, sizeof(why), "the stop, at level %d", (int)levels[i]);
        ASSERTm(why, journal_says(0, "capture stopped"));
        snprintf(why, sizeof(why), "the summary, at level %d", (int)levels[i]);
        ASSERTm(why, journal_says(0, "0 packets read, 0 bypasses reported."));
        ASSERTm("and that it started with nothing recalled",
                journal_says(0, "recorded no real address"));
        size_t n = journal(0), starts = 0;
        for (size_t k = 0; k < n; k++) {
            if (g_events[k].kind == FIRC_EVENT_LOG &&
                strstr(g_events[k].u.log.text, "capture started:") != NULL) {
                starts++;
            }
        }
        ASSERT_EQ_FMTm("one line per start", (size_t)1, starts, "%zu");
        locked_app_down(&l);
    }
    PASS();
}

static firc_rule_t *edit_rule(const char *type, const char *text) {
    firc_rule_t *r = firc_rule_new();
    r->id = firc_id_random();
    r->type = strdup(type);
    r->rule = strdup(text);
    r->enable = true;
    return r;
}

static bool wait_passes(const locked_app_t *l, uint64_t want) {
    for (int i = 0; i < 500; i++) {
        if (firc_app_nf_passes_for_test(l->app) >= want) { return true; }
        sleep_ms(10);
    }
    return false;
}

/* Waits for a pass that started after `started` to finish writing, not merely to start. */
static bool wait_written_after(const locked_app_t *l, uint64_t started) {
    for (int i = 0; i < 1000; i++) {
        if (firc_app_nf_last_completed_pass_for_test(l->app) > started) { return true; }
        sleep_ms(10);
    }
    return false;
}

/* Catches: a domain rule edit costing a pass, or a subnet rule edit (a chain rule) asking for none. */
TEST a_domain_rule_edit_asks_for_no_pass_but_a_subnet_rule_does(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);

    firc_group_t *g = firc_group_new();
    g->id = firc_id_random();
    g->name = strdup("g");
    g->iface = strdup("lo");
    g->enable = true;
    firc_id_t gid = g->id;
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));
    firc_ruleset_t *rs = firc_app_find_group_by_id(l.app, gid);
    ASSERT(rs != NULL);
    ASSERTm("the group is live on the fake engines", firc_ruleset_runtime_enabled(rs));
    sleep_ms(600);
    uint64_t before = firc_app_nf_passes_for_test(l.app);

    ASSERT_EQ(FIRC_OK, firc_group_add_rule(firc_ruleset_group_mut(rs), edit_rule(FIRC_RULE_DOMAIN, "example.com")));
    ASSERT_EQ(FIRC_OK, firc_app_sync_group(l.app, rs));
    sleep_ms(600);
    ASSERT_EQ_FMTm("a domain rule costs the kernel nothing", (unsigned long long)before,
                   (unsigned long long)firc_app_nf_passes_for_test(l.app), "%llu");

    ASSERT_EQ(FIRC_OK, firc_group_add_rule(firc_ruleset_group_mut(rs), edit_rule(FIRC_RULE_SUBNET, "10.9.0.0/16")));
    ASSERT_EQ(FIRC_OK, firc_app_sync_group(l.app, rs));
    ASSERTm("a subnet rule is a chain rule: one pass", wait_passes(&l, before + 1));

    firc_group_t *live = firc_ruleset_group_mut(rs);
    free(live->rules[live->n_rules - 1]->rule);
    live->rules[live->n_rules - 1]->rule = strdup("10.8.0.0/16");
    ASSERT_EQ(FIRC_OK, firc_app_sync_group(l.app, rs));
    ASSERTm("an edited prefix is one more pass", wait_passes(&l, before + 2));
    locked_app_down(&l);
    PASS();
}

/* Whether the group's mangle chain marks traffic to `cidr`, read under the netfilter lock. */
static bool chain_marks(locked_app_t *l, firc_id_t gid, const char *cidr) {
    char id[FIRC_ID_STR_LEN], chain[64];
    firc_id_format(gid, id);
    snprintf(chain, sizeof(chain), "FIRC_%s", id);
    firc_app_nf_enter(l->app);
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    bool found = false;
    if (firc_fake_ipt_get_rules(l->fake, "mangle", chain, &rules, &n)) {
        for (size_t i = 0; i < n && !found; i++) {
            char *text = firc_ipt_rule_string(rules[i]);
            found = text != NULL && strstr(text, cidr) != NULL;
            free(text);
        }
    }
    firc_app_nf_leave(l->app);
    return found;
}

static locked_app_t g_ll;
static bool g_ll_open = false;

static void close_open_list_app(void *unused) {
    (void)unused;
    if (!g_ll_open) { return; }
    g_ll_open = false;
    locked_app_down(&g_ll);
}

/* A running list group holding `specs` (text, type pairs), once the passes its add asked for settle. */
static firc_ruleset_t *live_list_group(locked_app_t *l, const char *const (*specs)[2], size_t n,
                                       firc_id_t *out_gid) {
    fake_rtnl_set_link_flags(l->kernel, 0x1 | 0x10);
    firc_group_t *g = firc_group_new();
    g->id = firc_id_random();
    g->name = strdup("g");
    g->iface = strdup("lo");
    g->enable = true;
    g->list = firc_group_list_new();
    firc_strset(&g->list->url, "http://127.0.0.1:1/list");
    g->list->has_body_hash = true;
    for (size_t i = 0; i < n; i++) {
        firc_sub_rules_push(&g->list->rules, specs[i][0], specs[i][1], true, firc_id_random());
    }
    *out_gid = g->id;
    firc_app_set_running(l->app, true);
    if (firc_app_add_group(l->app, g) != FIRC_OK) { return NULL; }
    firc_ruleset_t *rs = firc_app_find_group_by_id(l->app, *out_gid);
    if (rs == NULL || !firc_ruleset_runtime_enabled(rs)) { return NULL; }
    sleep_ms(600);
    return rs;
}

static firc_id_t list_rule_id(firc_ruleset_t *rs, size_t i) {
    return firc_sub_rules_id(&firc_ruleset_group(rs)->list->rules, i);
}

/* Catches: disabling a list's subnet rule in the DNS view while its chain keeps marking it. */
TEST disabling_a_subnet_list_rule_asks_for_one_pass_and_the_chain_drops_it(void) {
    locked_app_t *l = &g_ll;
    ASSERT(locked_app_up(l));
    g_ll_open = true;
    static const char *const specs[][2] = {{"10.9.0.0/16", FIRC_RULE_SUBNET},
                                           {"example.com", FIRC_RULE_NAMESPACE}};
    firc_id_t gid;
    firc_ruleset_t *rs = live_list_group(l, specs, 2, &gid);
    ASSERT(rs != NULL);
    ASSERTm("fixture: the list's subnet is in the chain", chain_marks(l, gid, "10.9.0.0/16"));
    uint64_t before = firc_app_nf_passes_for_test(l->app);

    firc_list_rule_edit_t e = {.rule = list_rule_id(rs, 0), .has_enable = true, .enable = false};
    char msg[128] = "";
    ASSERT_EQ(FIRC_OK, firc_app_patch_list_rules(l->app, gid, &e, 1, msg, sizeof(msg)));
    ASSERTm("one pass", wait_passes(l, before + 1));
    ASSERTm("written", wait_written_after(l, before));
    sleep_ms(300);
    ASSERT_EQ_FMTm("exactly one", (unsigned long long)(before + 1),
                   (unsigned long long)firc_app_nf_passes_for_test(l->app), "%llu");
    ASSERT_FALSEm("and the chain no longer marks it", chain_marks(l, gid, "10.9.0.0/16"));
    g_ll_open = false;
    locked_app_down(l);
    PASS();
}

/* Catches: a list's name rule edit asking for a pass, which rewrites the whole DNAT chain. */
TEST a_name_list_rule_edit_asks_for_no_pass(void) {
    locked_app_t *l = &g_ll;
    ASSERT(locked_app_up(l));
    g_ll_open = true;
    static const char *const specs[][2] = {{"10.9.0.0/16", FIRC_RULE_SUBNET},
                                           {"example.com", FIRC_RULE_NAMESPACE}};
    firc_id_t gid;
    firc_ruleset_t *rs = live_list_group(l, specs, 2, &gid);
    ASSERT(rs != NULL);
    uint64_t before = firc_app_nf_passes_for_test(l->app);

    firc_list_rule_edit_t e = {.rule = list_rule_id(rs, 1), .has_enable = true, .enable = false,
                               .type = FIRC_RULE_DOMAIN};
    char msg[128] = "";
    ASSERT_EQ(FIRC_OK, firc_app_patch_list_rules(l->app, gid, &e, 1, msg, sizeof(msg)));
    sleep_ms(600);
    ASSERT_EQ_FMTm("a name rule costs the kernel nothing", (unsigned long long)before,
                   (unsigned long long)firc_app_nf_passes_for_test(l->app), "%llu");
    ASSERTm("and the subnet beside it is still marked", chain_marks(l, gid, "10.9.0.0/16"));
    g_ll_open = false;
    locked_app_down(l);
    PASS();
}

/* Catches: an edit turning a list rule into a subnet rule not asking for a netfilter pass. */
TEST a_list_rule_moved_to_subnet_asks_for_one_pass(void) {
    locked_app_t *l = &g_ll;
    ASSERT(locked_app_up(l));
    g_ll_open = true;
    static const char *const specs[][2] = {{"10.7.0.0/16", FIRC_RULE_NAMESPACE}};
    firc_id_t gid;
    firc_ruleset_t *rs = live_list_group(l, specs, 1, &gid);
    ASSERT(rs != NULL);
    ASSERT_FALSEm("fixture: not in the chain yet", chain_marks(l, gid, "10.7.0.0/16"));
    uint64_t before = firc_app_nf_passes_for_test(l->app);

    firc_list_rule_edit_t e = {.rule = list_rule_id(rs, 0), .type = FIRC_RULE_SUBNET};
    char msg[128] = "";
    ASSERT_EQ(FIRC_OK, firc_app_patch_list_rules(l->app, gid, &e, 1, msg, sizeof(msg)));
    ASSERTm("one pass", wait_passes(l, before + 1));
    ASSERTm("written", wait_written_after(l, before));
    ASSERTm("and the chain marks it now", chain_marks(l, gid, "10.7.0.0/16"));
    g_ll_open = false;
    locked_app_down(l);
    PASS();
}

/* Catches: the subnet check made only on the rule's type after the edit. */
TEST a_list_rule_moved_off_subnet_asks_for_one_pass(void) {
    locked_app_t *l = &g_ll;
    ASSERT(locked_app_up(l));
    g_ll_open = true;
    static const char *const specs[][2] = {{"10.9.0.0/16", FIRC_RULE_SUBNET}};
    firc_id_t gid;
    firc_ruleset_t *rs = live_list_group(l, specs, 1, &gid);
    ASSERT(rs != NULL);
    ASSERTm("fixture: in the chain", chain_marks(l, gid, "10.9.0.0/16"));
    uint64_t before = firc_app_nf_passes_for_test(l->app);

    firc_list_rule_edit_t e = {.rule = list_rule_id(rs, 0), .type = FIRC_RULE_REGEX};
    char msg[128] = "";
    ASSERT_EQ_FMTm(msg, FIRC_OK, firc_app_patch_list_rules(l->app, gid, &e, 1, msg, sizeof(msg)), "%d");
    ASSERTm("one pass", wait_passes(l, before + 1));
    ASSERTm("written", wait_written_after(l, before));
    ASSERT_FALSEm("and the chain no longer marks it", chain_marks(l, gid, "10.9.0.0/16"));
    g_ll_open = false;
    locked_app_down(l);
    PASS();
}

/* A running group on "lo" with `hand_rule` as its domain rule, or as its list's rule if `list_url` is set. */
static firc_group_t *activation_group(uint8_t tag, const char *hand_rule, const char *list_url,
                                     const char *list_rule) {
    firc_group_t *g = firc_group_new();
    g->id = (firc_id_t){{tag, tag, tag, tag}};
    g->name = strdup("g");
    g->iface = strdup("lo");
    g->enable = true;
    if (hand_rule != NULL) { firc_group_add_rule(g, edit_rule(FIRC_RULE_DOMAIN, hand_rule)); }
    if (list_url != NULL) {
        g->list = firc_group_list_new();
        firc_strset(&g->list->url, list_url);
        firc_sub_rules_push(&g->list->rules, list_rule, FIRC_RULE_NAMESPACE, true, firc_id_random());
        g->list->has_body_hash = true;
    }
    return g;
}

static int g_ended_calls;
static char g_ended_error[256];
static void record_ended(void *ud, firc_id_t owner, const firc_group_list_t *list, bool done) {
    (void)ud;
    (void)owner;
    if (!done) { return; }
    g_ended_calls++;
    snprintf(g_ended_error, sizeof(g_ended_error), "%s", list->sync_error);
}

/* Catches: a failed activation's rollback releasing the DNS snapshot, so no routed name matches. */
TEST a_group_that_fails_to_activate_leaves_the_snapshot_serving(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "keep.example", NULL, NULL)));
    const firc_ruleset_snapshot_t *snap = firc_dns_pipeline_snapshot(l.pipeline);
    ASSERTm("fixture: the first group's name is served",
            snap != NULL && firc_ruleset_snapshot_first_match(snap, "keep.example") != NULL);

    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT(firc_app_add_group(l.app, activation_group(2, "other.example", NULL, NULL)) != FIRC_OK);
    ASSERT_EQm("the failing group was rolled out", NULL,
               firc_app_find_group_by_id(l.app, (firc_id_t){{2, 2, 2, 2}}));

    snap = firc_dns_pipeline_snapshot(l.pipeline);
    ASSERTm("the pipeline still has a snapshot", snap != NULL);
    const firc_group_snapshot_t *owner = firc_ruleset_snapshot_first_match(snap, "keep.example");
    ASSERTm("and the first group still owns its name", owner != NULL);
    locked_app_down(&l);
    PASS();
}

/* Catches: a Save whose failed group is dropped, loses its sync stream, or has its list freed early. */
TEST a_replace_whose_activation_fails_frees_lists_after_the_release(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    g_ended_calls = 0;
    g_ended_error[0] = '\0';
    firc_app_set_sync_listener(l.app, record_ended, NULL);

    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, NULL, "http://127.0.0.1:1/l",
                                                                  "ads.example.com")));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "keep.example", NULL, NULL)));
    firc_ruleset_t *rs = firc_app_find_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}});
    ASSERT(rs != NULL);
    firc_ruleset_group_mut(rs)->list->sync_state = FIRC_SUB_SYNC_FETCHING;
    const firc_ruleset_snapshot_t *snap = firc_dns_pipeline_snapshot(l.pipeline);
    ASSERTm("fixture: the list's name is served",
            snap != NULL && firc_ruleset_snapshot_first_match(snap, "a.ads.example.com") != NULL);

    firc_group_t *arrival = activation_group(1, NULL, "http://127.0.0.1:1/l", "x.invalid");
    firc_sub_rules_free(&arrival->list->rules);
    firc_sub_rules_init(&arrival->list->rules);
    arrival->list->has_body_hash = false;
    firc_group_t **arr = calloc(2, sizeof(*arr));
    arr[0] = arrival;
    arr[1] = activation_group(2, "keep.example", NULL, NULL);
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, arr, 2));
    ASSERT_FALSEm("the armed refusal was met", fake_rtnl_failure_armed(l.kernel));

    ASSERTm("the list group stays in the config",
            firc_app_find_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}}) != NULL);
    ASSERT_EQm("its stream was not ended: the list is still there", 0, g_ended_calls);
    snap = firc_dns_pipeline_snapshot(l.pipeline);
    ASSERTm("the pipeline has a snapshot", snap != NULL);
    ASSERT_EQ(NULL, firc_ruleset_snapshot_first_match(snap, "a.ads.example.com"));
    ASSERT(firc_ruleset_snapshot_first_match(snap, "keep.example") != NULL);
    firc_app_set_sync_listener(l.app, NULL, NULL);
    locked_app_down(&l);
    PASS();
}

/* Catches: an interface value that is not a name (newline, empty, too long) reaching iptables. */
TEST a_group_whose_interface_is_not_a_name_routes_nothing(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);

    static const char *bad[] = {
        "lo\n-A FORWARD -j ACCEPT",
        "",
        "an-interface-name-of-thirty-two",
    };
    char chains[3][128];
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_group_t *g = firc_group_new();
        g->id = firc_id_random();
        g->name = strdup("g");
        g->iface = strdup(bad[i]);
        g->enable = true;
        char id_buf[FIRC_ID_STR_LEN];
        firc_id_format(g->id, id_buf);
        snprintf(chains[i], sizeof(chains[i]), "%s%s",
                 l.cfg.app.netfilter.iptables.chain_prefix, id_buf);
        ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));
    }
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    sleep_ms(600);

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERT_FALSEm(bad[i], firc_fake_ipt_chain_exists(l.fake, "mangle", chains[i]));
    }
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    bool injected = false, unreadable = false;
    firc_app_nf_enter(l.app);
    if (firc_fake_ipt_get_rules(l.fake, "mangle", "FORWARD", &rules, &n)) {
        for (size_t i = 0; i < n; i++) {
            char *text = firc_ipt_rule_string(rules[i]);
            unreadable = unreadable || text == NULL;
            injected = injected || (text != NULL && strstr(text, "-j ACCEPT") != NULL);
            free(text);
        }
    }
    firc_app_nf_leave(l.app);
    ASSERT_FALSE(unreadable);
    ASSERT_FALSEm("a rule nobody asked for, out of an interface name", injected);
    locked_app_down(&l);
    PASS();
}

/* Catches: a pass or firc_app_nf_enter not taking the netfilter lock, or a pass that never runs. */
TEST a_pass_waits_for_the_netfilter_lock(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));

    firc_app_nf_enter(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    sleep_ms(600);
    ASSERT_FALSEm("a pass wrote the table while the loop thread held the lock", pass_landed(&l));
    firc_app_nf_leave(l.app);

    bool landed = false;
    for (int i = 0; i < 500 && !landed; i++) {
        sleep_ms(10);
        landed = pass_landed(&l);
    }
    ASSERTm("the pass must land once the lock is released", landed);

    locked_app_down(&l);
    PASS();
}

static void count_chunk(void *ud, const char *group_id, unsigned family, const firc_ip_t *base,
                        uint8_t prefix) {
    (void)group_id; (void)family; (void)base; (void)prefix;
    (*(int *)ud)++;
}

/* Catches: a pool change taking the lock that aborts the pass in flight, so no pass completes. */
TEST a_pool_change_does_not_take_the_interrupting_lock_and_asks_for_a_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    uint64_t before = firc_app_nf_enters_for_test(l.app);
    ASSERT_FALSE(pass_landed(&l));
    firc_app_pool_changed(l.app);
    firc_app_pool_changed(l.app);
    ASSERT_EQ_FMT((unsigned long long)before, (unsigned long long)firc_app_nf_enters_for_test(l.app), "%llu");
    bool landed = false;
    for (int i = 0; i < 500 && !landed; i++) {
        sleep_ms(10);
        landed = pass_landed(&l);
    }
    ASSERTm("a pool change must ask the committer for a pass", landed);
    locked_app_down(&l);
    PASS();
}

/* Catches: a pool change asking for its pass with the long settle meant for chain changes. */
TEST a_pool_change_gets_its_pass_after_the_short_settle(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    firc_nfcommit_t *c = firc_app_committer_for_test(l.app);
    ASSERT(c != NULL);
    firc_app_pool_changed(l.app);
    for (int i = 0; i < 500 && !pass_landed(&l); i++) { sleep_ms(10); }
    ASSERT(pass_landed(&l));
    uint64_t before = firc_nfcommit_passes(c);
    for (int quiet = 0; quiet < 30; quiet++) {
        sleep_ms(10);
        uint64_t now = firc_nfcommit_passes(c);
        if (now != before) {
            before = now;
            quiet = 0;
        }
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_app_pool_changed(l.app);
    for (int i = 0; i < 2000 && firc_nfcommit_passes(c) == before; i++) { sleep_ms(1); }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (long)(t1.tv_sec - t0.tv_sec) * 1000L + (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    ASSERT(firc_nfcommit_passes(c) > before);
    ASSERT_LT(ms, 120);
    locked_app_down(&l);
    PASS();
}

/* Catches: a group enabled outside a pass built from a stale snapshot, missing its chunk rules. */
TEST outside_a_pass_the_rules_read_the_current_snapshot(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18; c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37; c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);
    firc_ip_t v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &v4, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_refresh_pool_snapshot(app));

    const firc_fakeip_snapshot_t *s = firc_app_rules_snapshot(app);
    ASSERT(s != NULL);
    int chunks = 0;
    firc_fakeip_snapshot_walk_chunks(s, "g1", count_chunk, &chunks);
    ASSERT_EQ_FMTm("the current snapshot, chunks and all", 2, chunks, "%d");

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a Save or reload forgetting the pool state of groups that keep their ids. */
TEST a_replacement_keeps_the_pool_state_of_groups_that_persist(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18; c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37; c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);
    firc_group_t *stays = make_group("stays", false);
    firc_group_t *goes = make_group("goes", false);
    char id_stays[FIRC_ID_STR_LEN], id_goes[FIRC_ID_STR_LEN];
    firc_id_format(stays->id, id_stays);
    firc_id_format(goes->id, id_goes);
    firc_id_t stays_id = stays->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(app, stays));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(app, goes));
    firc_ip_t a_addr = {{0}, 0}, v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", id_stays, 1000, &a_addr, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "b.example.com", id_goes, 1000, &v4, NULL));

    firc_group_t **fresh = calloc(1, sizeof(*fresh));
    fresh[0] = make_group("stays-renamed", false);
    fresh[0]->id = stays_id;
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(app, fresh, 1));

    int chunks = 0;
    firc_fakeip_walk_chunks(pool, id_stays, count_chunk, &chunks);
    ASSERT_EQ_FMTm("the persisting group keeps its chunks and names", 2, chunks, "%d");
    firc_ip_t again = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", id_stays, 1001, &again, NULL));
    ASSERT_MEM_EQm("and the name its address", a_addr.b, again.b, 4);
    chunks = 0;
    firc_fakeip_walk_chunks(pool, id_goes, count_chunk, &chunks);
    ASSERT_EQ_FMTm("the group that is gone is forgotten", 0, chunks, "%d");

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a replace locking per group, so a pass in between writes a table with half the groups. */
TEST replace_groups_takes_the_netfilter_lock_once(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));

    firc_app_add_group(l.app, make_group("a", false));
    firc_app_add_group(l.app, make_group("b", false));
    uint64_t before = firc_app_nf_enters_for_test(l.app);
    ASSERTm("add_group must take the real lock, or the count below means nothing", before >= 2);

    firc_group_t **fresh = calloc(3, sizeof(*fresh));
    fresh[0] = make_group("x", false);
    fresh[1] = make_group("y", false);
    fresh[2] = make_group("z", false);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, fresh, 3));

    ASSERT_EQ(3u, firc_app_user_group_count(l.app));
    ASSERT_STR_EQ("x", firc_ruleset_group(firc_app_user_group_at(l.app, 0))->name);
    ASSERT_STR_EQ("z", firc_ruleset_group(firc_app_user_group_at(l.app, 2))->name);
    ASSERT_EQ_FMT((unsigned long long)before + 1,
                  (unsigned long long)firc_app_nf_enters_for_test(l.app), "%llu");

    locked_app_down(&l);
    PASS();
}

/* Catches: a group that fails to come up failing the Save or being dropped from the config. */
TEST replace_groups_while_running_keeps_the_groups_that_did_not_come_up(void) {
    if (geteuid() == 0) { SKIPm("would write real rules as root"); }
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_ipt_executable_t *exe4 = firc_ipt_executable_real_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt4 = firc_ipt_new(exe4);
    firc_rtnl_t *rtnl = firc_rtnl_open();
    ASSERT(ipt4 != NULL && rtnl != NULL);
    firc_app_deps_t deps = {.cfg = &cfg, .ipt4 = ipt4, .rtnl = rtnl};
    firc_app_t *app = firc_app_create(&deps);
    firc_app_set_running(app, true);

    firc_group_t **fresh = calloc(2, sizeof(*fresh));
    fresh[0] = make_group("x", true);
    fresh[1] = make_group("y", true);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(app, fresh, 2));
    ASSERT_EQ_FMT(2u, (unsigned)firc_app_user_group_count(app), "%u");
    ASSERT_EQ_FMT(2u, (unsigned)cfg.n_groups, "%u");
    for (size_t i = 0; i < 2; i++) {
        ASSERT_FALSE(firc_ruleset_runtime_enabled(firc_app_user_group_at(app, i)));
    }

    firc_app_destroy(app);
    firc_ipt_free(ipt4);
    firc_rtnl_close(rtnl);
    firc_config_clear(&cfg);
    PASS();
}

/* The mark the daemon installed for its ip rule, read back from the fake kernel. */
static uint32_t rule_mark_installed(fake_rtnl_t *k) {
    fake_rtnl_msg_t msgs[64];
    size_t n = fake_rtnl_messages(k, msgs, 64);
    for (size_t i = 0; i < n; i++) {
        if (msgs[i].type == 32  && (msgs[i].mark & FIRC_MARK_GROUP_MASK) != 0) {
            return msgs[i].mark & FIRC_MARK_GROUP_MASK;
        }
    }
    return 0;
}

/* Catches: a daemon stop flushing the conntrack entries of flows it will route the same way again. */
TEST stopping_the_daemon_keeps_the_flows_it_was_steering(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    fake_ct_t *ctk = l.ctk;

    firc_group_t *g = firc_group_new();
    g->id = firc_id_random();
    g->name = strdup("g");
    g->iface = strdup("lo");
    g->enable = true;
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));
    uint32_t mark = rule_mark_installed(l.kernel);
    ASSERTm("the group got a mark", mark != 0);
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, ours[4] = {198, 18, 0, 5};
    fake_ct_add(ctk, AF_INET, src, dst, ours, mark | FIRC_MARK_HANDLED);

    firc_app_destroy(l.app);
    l.app = NULL;
    ASSERT_EQ_FMTm("the kernel was not asked to drop anything", (size_t)0, fake_ct_deletes(ctk), "%zu");
    ASSERT_EQ_FMTm("the flow is still running", (size_t)1, fake_ct_remaining(ctk), "%zu");

    locked_app_down(&l);
    PASS();
}

/* Catches: a Save flushing the flows of a group kept under the same id and interface. */
TEST a_replacement_keeps_the_flows_of_groups_that_persist(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    fake_ct_t *ctk = l.ctk;
    firc_app_set_running(l.app, true);

    firc_group_t *stays = firc_group_new();
    stays->id = firc_id_random();
    stays->name = strdup("stays");
    stays->iface = strdup("lo");
    stays->enable = true;
    firc_id_t stays_id = stays->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, stays));
    uint32_t stays_mark = rule_mark_installed(l.kernel);
    ASSERTm("the group got a mark", stays_mark != 0);

    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, ours[4] = {198, 18, 0, 5};
    fake_ct_add(ctk, AF_INET, src, dst, ours, stays_mark | FIRC_MARK_HANDLED);

    firc_group_t **fresh = calloc(1, sizeof(*fresh));
    fresh[0] = firc_group_new();
    fresh[0]->id = stays_id;
    fresh[0]->name = strdup("stays-renamed");
    fresh[0]->iface = strdup("lo");
    fresh[0]->enable = true;
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, fresh, 1));
    ASSERT_EQ_FMTm("the persisting group keeps its flows", (size_t)0, fake_ct_deletes(ctk), "%zu");

    locked_app_down(&l);
    PASS();
}

/* Catches: a Save keeping the flows of a group it removed or moved to another interface. */
TEST a_replacement_drops_the_flows_of_groups_it_withdraws(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    fake_ct_t *ctk = l.ctk;
    firc_app_set_running(l.app, true);

    firc_group_t *goes = firc_group_new();
    goes->id = firc_id_random();
    goes->name = strdup("goes");
    goes->iface = strdup("lo");
    goes->enable = true;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, goes));
    uint32_t goes_mark = rule_mark_installed(l.kernel);
    ASSERTm("the group got a mark", goes_mark != 0);
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5};
    const uint8_t ours[4] = {198, 18, 0, 5}, theirs[4] = {8, 8, 8, 8};
    ASSERT(wait_written_after(&l, 0));
    fake_ct_add(ctk, AF_INET, src, dst, ours, goes_mark | FIRC_MARK_HANDLED);
    fake_ct_add(ctk, AF_INET, src, dst, theirs, 0);

    firc_group_t **fresh = calloc(1, sizeof(*fresh));
    fresh[0] = firc_group_new();
    fresh[0]->id = firc_id_random();
    fresh[0]->name = strdup("other");
    fresh[0]->iface = strdup("lo");
    fresh[0]->enable = true;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, fresh, 1));
    ASSERT(wait_written_after(&l, started));

    ASSERTm("the withdrawn group's flow went", fake_ct_deleted(ctk, ours, 4));
    ASSERTm("nobody else's did", !fake_ct_deleted(ctk, theirs, 4));

    locked_app_down(&l);
    PASS();
}

/* Catches: mark fields given by position, so a reorder steers each group's flows by the other's rule. */
TEST a_reorder_does_not_move_a_group_s_mark_field(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);

    firc_group_t *a = firc_group_new();
    a->id = firc_id_random();
    a->name = strdup("a");
    a->iface = strdup("lo");
    a->enable = true;
    firc_id_t a_id = a->id;
    firc_group_t *b = firc_group_new();
    b->id = firc_id_random();
    b->name = strdup("b");
    b->iface = strdup("lo");
    b->enable = true;
    firc_id_t b_id = b->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, a));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, b));

    uint32_t a_field = firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, a_id));
    uint32_t b_field = firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, b_id));
    ASSERTm("both are in the kernel", a_field != 0 && b_field != 0);
    ASSERTm("and they are not the same group", a_field != b_field);

    firc_group_t **fresh = calloc(2, sizeof(*fresh));
    fresh[0] = firc_group_new();
    fresh[0]->id = b_id;
    fresh[0]->name = strdup("b");
    fresh[0]->iface = strdup("lo");
    fresh[0]->enable = true;
    fresh[1] = firc_group_new();
    fresh[1]->id = a_id;
    fresh[1]->name = strdup("a");
    fresh[1]->iface = strdup("lo");
    fresh[1]->enable = true;
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, fresh, 2));

    ASSERT_EQ_FMTm("a keeps the field its flows are marked with", a_field,
                   firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, a_id)), "0x%x");
    ASSERT_EQ_FMTm("and so does b", b_field,
                   firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, b_id)), "0x%x");

    locked_app_down(&l);
    PASS();
}

/* Catches: a group prepended by a Save taking the mark field an existing group's flows carry. */
TEST adding_a_group_ahead_of_another_does_not_take_its_field(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);

    firc_group_t *a = firc_group_new();
    a->id = firc_id_random();
    a->name = strdup("a");
    a->iface = strdup("lo");
    a->enable = true;
    firc_id_t a_id = a->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, a));
    uint32_t a_field = firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, a_id));
    ASSERTm("a is in the kernel", a_field != 0);

    firc_group_t **fresh = calloc(2, sizeof(*fresh));
    fresh[0] = firc_group_new();
    fresh[0]->id = firc_id_random();
    fresh[0]->name = strdup("new");
    fresh[0]->iface = strdup("lo");
    fresh[0]->enable = true;
    firc_id_t new_id = fresh[0]->id;
    fresh[1] = firc_group_new();
    fresh[1]->id = a_id;
    fresh[1]->name = strdup("a");
    fresh[1]->iface = strdup("lo");
    fresh[1]->enable = true;
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, fresh, 2));

    uint32_t a_now = firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, a_id));
    uint32_t new_now = firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, new_id));
    ASSERT_EQ_FMTm("a keeps the field its flows are marked with", a_field, a_now, "0x%x");
    ASSERTm("and the new group got a different one", new_now != 0 && new_now != a_field);

    locked_app_down(&l);
    PASS();
}

/* Catches: a deleted group keeping its mark field, so create and delete cycles use up the fields. */
TEST a_removed_group_gives_its_field_back(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);

    firc_group_t *a = firc_group_new();
    a->id = firc_id_random();
    a->name = strdup("a");
    a->iface = strdup("lo");
    a->enable = true;
    firc_id_t a_id = a->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, a));
    uint32_t a_field = firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, a_id));
    ASSERT(a_field != 0);

    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_remove_group_by_id(l.app, a_id);
    ASSERT(wait_written_after(&l, started));

    firc_group_t *b = firc_group_new();
    b->id = firc_id_random();
    b->name = strdup("b");
    b->iface = strdup("lo");
    b->enable = true;
    firc_id_t b_id = b->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, b));
    ASSERT_EQ_FMTm("the field the removed group held is free again", a_field,
                   firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, b_id)), "0x%x");

    locked_app_down(&l);
    PASS();
}

typedef struct {
    pthread_mutex_t mu;
    size_t calls;
    size_t n;
    char owner[FIRC_ID_STR_LEN];
    uint32_t field;
} field_store_t;

static void field_store_cb(void *ud, const firc_rtnl_field_t *v, size_t n) {
    field_store_t *s = ud;
    pthread_mutex_lock(&s->mu);
    s->calls++;
    s->n = n;
    s->owner[0] = '\0';
    s->field = 0;
    if (n > 0) {
        snprintf(s->owner, sizeof(s->owner), "%s", v[0].owner);
        s->field = v[0].field;
    }
    pthread_mutex_unlock(&s->mu);
}

static size_t field_store_n(field_store_t *s) {
    pthread_mutex_lock(&s->mu);
    size_t n = s->n;
    pthread_mutex_unlock(&s->mu);
    return n;
}

/* Catches: a removed group's field left in the stored map after its flush, or dropped from it before. */
TEST a_removed_group_s_entry_leaves_the_store_when_its_flush_is_paid(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    field_store_t store = {.mu = PTHREAD_MUTEX_INITIALIZER};
    firc_rtnl_watch_mark_fields(l.rtnl, field_store_cb, &store);
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);

    firc_group_t *a = firc_group_new();
    a->id = firc_id_random();
    a->name = strdup("a");
    a->iface = strdup("lo");
    a->enable = true;
    firc_id_t a_id = a->id;
    char a_str[FIRC_ID_STR_LEN];
    firc_id_format(a_id, a_str);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, a));
    ASSERT(wait_written_after(&l, 0));
    uint32_t a_field = firc_ruleset_mark_field(firc_app_find_group_by_id(l.app, a_id)) >> FIRC_MARK_GROUP_SHIFT;
    pthread_mutex_lock(&store.mu);
    size_t n_after_add = store.n;
    uint32_t stored_field = store.field;
    bool stored_a = strcmp(store.owner, a_str) == 0;
    pthread_mutex_unlock(&store.mu);
    ASSERT_EQ_FMT((size_t)1, n_after_add, "%zu");
    ASSERT(stored_a);
    ASSERT_EQ_FMT(a_field, stored_field, "%u");

    firc_app_nf_enter(l.app);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_remove_group_by_id(l.app, a_id);
    size_t n_before_pass = field_store_n(&store);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMT((size_t)1, n_before_pass, "%zu");
    ASSERT(wait_written_after(&l, started));
    for (int i = 0; i < 500 && field_store_n(&store) != 0; i++) { sleep_ms(10); }
    ASSERT_EQ_FMT((size_t)0, field_store_n(&store), "%zu");

    firc_rtnl_watch_mark_fields(l.rtnl, NULL, NULL);
    locked_app_down(&l);
    PASS();
}

static void *drain_loop(void *ud) {
    firc_loop_run((firc_loop_t *)ud);
    return NULL;
}

static void noop_post(firc_loop_t *loop, void *ud) {
    (void)loop;
    (void)ud;
}

static void mark_post(firc_loop_t *loop, void *ud) {
    (void)loop;
    atomic_store((_Atomic int *)ud, 1);
}

/* Catches: a full pass whose report cannot be posted asking for more full passes for ever. */
TEST an_unreportable_full_pass_asks_once_and_then_says_so(void) {
    locked_app_t l;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT(locked_app_up_with_loop(&l, loop));
    firc_app_set_running(l.app, true);

    size_t posted = 0;
    while (firc_loop_post(loop, noop_post, NULL) == FIRC_OK) {
        posted++;
        if (posted > 4096) { break; }
    }
    ASSERTm("the queue really is full", posted > 0 && posted <= 4096);

    size_t requests = firc_nfcommit_requests_for_test(firc_app_committer_for_test(l.app));
    char out[8192];
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    (void)firc_app_rebuild_netfilter_kind(l.app, NULL, true);
    (void)firc_app_rebuild_netfilter_kind(l.app, NULL, true);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    ssize_t got = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);
    if (got < 0) { got = 0; }
    out[got] = '\0';

    size_t asked = 0;
    for (const char *c = out; (c = strstr(c, "asking for another")) != NULL; c++) { asked++; }
    ASSERT_EQ_FMTm("asked once, not once per failure", (size_t)1, asked, "%zu");

    ASSERT_EQ_FMTm("asked the committer once, not twice and not never", (size_t)1,
                   firc_nfcommit_requests_for_test(firc_app_committer_for_test(l.app)) - requests,
                   "%zu");
    ASSERTm("and the second failure says the window may be left unswept",
            strstr(out, "unswept") != NULL);

    {
        pthread_t th;
        _Atomic int seen = 0;
        ASSERT_EQ(0, pthread_create(&th, NULL, drain_loop, loop));
        while (firc_loop_post(loop, mark_post, &seen) != FIRC_OK) { sched_yield(); }
        while (atomic_load(&seen) == 0) { sched_yield(); }
        atomic_store(&seen, 0);
        (void)firc_app_rebuild_netfilter_kind(l.app, NULL, true);
        while (firc_loop_post(loop, mark_post, &seen) != FIRC_OK) { sched_yield(); }
        while (atomic_load(&seen) == 0) { sched_yield(); }
        firc_loop_stop(loop);
        pthread_join(th, NULL);
    }
    while (firc_loop_post(loop, noop_post, NULL) == FIRC_OK) {  }
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_fd(fds[1]);
    (void)firc_app_rebuild_netfilter_kind(l.app, NULL, true);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    got = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);
    if (got < 0) { got = 0; }
    out[got] = '\0';
    ASSERTm("a failure after a successful report asks again",
            strstr(out, "asking for another") != NULL);

    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* A group with only a list url, as a reload or a Save hands it to the app. */
static firc_group_t *list_group(firc_id_t id, const char *iface, bool enable) {
    firc_group_t *g = firc_group_new();
    g->id = id;
    g->name = strdup("s");
    g->iface = strdup(iface);
    g->enable = enable;
    g->list = firc_group_list_new();
    free(g->list->url);
    g->list->url = strdup("http://example.invalid/list");
    return g;
}

/* Catches: a list group moved to another interface keeping its flows because its id is still there. */
TEST a_list_group_that_changes_interface_drops_its_flows(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    fake_ct_t *ctk = l.ctk;
    firc_app_set_running(l.app, true);

    firc_id_t sid = firc_id_random();
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, list_group(sid, "lo", true)));
    uint32_t mark = rule_mark_installed(l.kernel);
    ASSERTm("the group is in the kernel", mark != 0);
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, ours[4] = {198, 18, 0, 5};
    ASSERT(wait_written_after(&l, 0));
    fake_ct_add(ctk, AF_INET, src, dst, ours, mark | FIRC_MARK_HANDLED);

    firc_group_t **fresh = calloc(1, sizeof(*fresh));
    fresh[0] = list_group(sid, "eth0", true);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, fresh, 1));
    ASSERT(wait_written_after(&l, started));

    ASSERTm("its flow went with the interface", fake_ct_deleted(ctk, ours, 4));
    locked_app_down(&l);
    PASS();
}

/* Catches: a list group turned off keeping its flows because its id is still in the config. */
TEST a_list_group_that_is_turned_off_drops_its_flows(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    fake_ct_t *ctk = l.ctk;
    firc_app_set_running(l.app, true);

    firc_id_t sid = firc_id_random();
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, list_group(sid, "lo", true)));
    uint32_t mark = rule_mark_installed(l.kernel);
    ASSERT(mark != 0);
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, ours[4] = {198, 18, 0, 6};
    ASSERT(wait_written_after(&l, 0));
    fake_ct_add(ctk, AF_INET, src, dst, ours, mark | FIRC_MARK_HANDLED);

    firc_group_t **fresh = calloc(1, sizeof(*fresh));
    fresh[0] = list_group(sid, "lo", false);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, fresh, 1));
    ASSERT(wait_written_after(&l, started));

    ASSERTm("a group that routes nothing steers nothing", fake_ct_deleted(ctk, ours, 4));
    locked_app_down(&l);
    PASS();
}

/* Catches: a removed group's chunks and names left in the pool, keeping their DNAT rules for ever. */
TEST a_removed_group_is_forgotten_by_the_pool(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18; c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37; c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);
    firc_group_t *g = make_group("g", false);
    char gid[FIRC_ID_STR_LEN];
    firc_id_format(g->id, gid);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(app, g));

    firc_ip_t v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", gid, 1000, &v4, NULL));
    int chunks = 0;
    firc_fakeip_walk_chunks(pool, gid, count_chunk, &chunks);
    ASSERT_EQ_FMT(2, chunks, "%d");

    firc_app_remove_group_by_index(app, 0);
    chunks = 0;
    firc_fakeip_walk_chunks(pool, gid, count_chunk, &chunks);
    ASSERT_EQ_FMTm("the group's chunks are no longer its", 0, chunks, "%d");

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: an A answer held until the deadline for a v6 change it does not carry. */
TEST a_held_answer_waits_only_for_the_families_it_carries(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18; c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37; c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);

    firc_ip_t v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &v4, NULL));
    const firc_ip_t real4 = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(pool, "a.example.com", &real4, 1));
    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(pool);
    firc_app_pass_committed(app, firc_fakeip_snapshot_gen(s));
    firc_fakeip_snapshot_free(s);
    const firc_ip_t real6 = {{0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(pool, "a.example.com", &real6, 1));

    static const uint8_t name[] = {1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    firc_dns_msg_t m = {0};
    firc_dns_question_t q = {0};
    memcpy(q.name, name, sizeof(name));
    q.name_len = sizeof(name);
    q.qtype = FIRC_DNS_TYPE_A;
    m.questions = &q;
    m.n_questions = 1;
    firc_dns_rr_t rr = {0};
    memcpy(rr.name, name, sizeof(name));
    rr.name_len = sizeof(name);
    rr.rtype = FIRC_DNS_TYPE_A;
    m.answers = &rr;
    m.n_answers = 1;
    ASSERTm("the v4 pair is in; the v6 one is not its business", firc_app_answer_ready(app, &m));
    rr.rtype = FIRC_DNS_TYPE_AAAA;
    ASSERT_FALSEm("an AAAA answer does wait for the v6 pair", firc_app_answer_ready(app, &m));

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: an off-by-one freeing the groups a failed replace did not add (double free or leak). */
TEST replace_groups_frees_what_it_could_not_add(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);

    firc_group_t **fresh = calloc(3, sizeof(*fresh));
    fresh[0] = make_group("x", false);
    fresh[1] = make_group("y", false);
    fresh[1]->id = fresh[0]->id;
    fresh[2] = make_group("z", false);
    ASSERT_EQ(FIRC_ERR_EXIST, firc_app_replace_groups(app, fresh, 3));
    ASSERT_EQ_FMTm("the group before the failure stays", 1u,
                   (unsigned)firc_app_user_group_count(app), "%u");
    ASSERT_STR_EQ("x", firc_ruleset_group(firc_app_user_group_at(app, 0))->name);

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

TEST remove_by_id_and_by_index(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);

    firc_app_add_group(app, make_group("a", false));
    firc_app_add_group(app, make_group("b", false));
    firc_app_add_group(app, make_group("c", false));
    firc_id_t b_id = firc_ruleset_group(firc_app_user_group_at(app, 1))->id;

    ASSERT(firc_app_remove_group_by_id(app, b_id));
    ASSERT_EQ(2u, firc_app_user_group_count(app));
    ASSERT_STR_EQ("a", firc_ruleset_group(firc_app_user_group_at(app, 0))->name);
    ASSERT_STR_EQ("c", firc_ruleset_group(firc_app_user_group_at(app, 1))->name);
    ASSERT_EQ(2u, cfg.n_groups);

    firc_id_t ghost = firc_id_random();
    ASSERT(!firc_app_remove_group_by_id(app, ghost));

    firc_app_remove_group_by_index(app, 0);
    ASSERT_EQ(1u, firc_app_user_group_count(app));
    ASSERT_STR_EQ("c", firc_ruleset_group(firc_app_user_group_at(app, 0))->name);

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

TEST list_interfaces_show_all_finds_loopback(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    cfg.app.show_all_interfaces = true;
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);

    firc_iface_info_t *ifaces = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_app_list_interfaces(app, &ifaces, &n));
    ASSERT(n > 0);
    bool found_lo = false;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(ifaces[i].id, "lo") == 0) { found_lo = true; }
    }
    ASSERT(found_lo);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            ASSERT(strcmp(ifaces[i].id, ifaces[j].id) != 0);
        }
    }

    free(ifaces);
    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: settings written to groups.yaml or groups to firc.conf, so a rule edit can touch settings. */
TEST save_config_round_trips(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);
    firc_app_add_group(app, make_group("saved-group", false));

    char dir[] = "/tmp/firc_app_test_config_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char conf[256], groups[256];
    snprintf(conf, sizeof(conf), "%s/firc.conf", dir);
    snprintf(groups, sizeof(groups), "%s/groups.yaml", dir);

    ASSERT_EQ(FIRC_OK, firc_app_save_config(app, conf, "0.1"));

    firc_config_t reloaded;
    firc_config_init_defaults(&reloaded);
    ASSERT_EQ_FMTm("the settings file exists and loads", FIRC_OK,
                   firc_config_load_file(&reloaded, conf), "%d");
    ASSERT_EQ_FMTm("and carries no groups", 0u, (unsigned)reloaded.n_groups, "%u");
    ASSERT_EQ_FMTm("the groups are next door", FIRC_OK,
                   firc_config_load_file(&reloaded, groups), "%d");
    ASSERT_EQ(1u, reloaded.n_groups);
    ASSERT_STR_EQ("saved-group", reloaded.groups[0]->name);

    ASSERT_EQ(0, unlink(conf));
    firc_app_add_group(app, make_group("second-group", false));
    ASSERT_EQ(FIRC_OK, firc_app_save_groups(app, conf, "0.1"));
    ASSERT_EQ_FMTm("the settings file was not rewritten", -1, access(conf, F_OK), "%d");

    firc_config_t after;
    firc_config_init_defaults(&after);
    ASSERT_EQ(FIRC_OK, firc_config_load_file(&after, groups));
    ASSERT_EQ_FMTm("and both groups are in the groups file", 2u, (unsigned)after.n_groups, "%u");

    unlink(groups);
    rmdir(dir);
    firc_config_clear(&after);
    firc_config_clear(&reloaded);
    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

TEST force_commit_iptables_noop_without_engines(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_app_deps_t deps = {.cfg = &cfg};
    firc_app_t *app = firc_app_create(&deps);

    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(app));

    firc_app_destroy(app);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a group add that does not republish routes, or a mark given to a group not running. */
TEST the_app_publishes_a_route_per_group(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_resolve_router_t *router = firc_resolve_router_new(NULL);
    firc_app_deps_t deps = {.cfg = &cfg, .router = router};
    firc_app_t *app = firc_app_create(&deps);

    firc_group_t *g = make_group("own", true);
    firc_strset(&g->resolve.server, "9.9.9.9");
    firc_id_t gid = g->id;
    firc_group_t *h = make_group("off", true);
    h->resolve.tunnel = false;
    firc_id_t hid = h->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(app, g));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(app, h));

    firc_resolve_route_t r;
    ASSERT(firc_resolve_router_route(router, gid, &r));
    ASSERT_EQ(FIRC_RESOLVE_SOURCE_GROUP, r.source);
    ASSERT_EQ((size_t)1, r.n_servers);
    ASSERT_EQ(0u, r.mark);
    ASSERT_STR_EQ("eth0", r.iface);
    ASSERT(firc_resolve_router_route(router, hid, &r));
    ASSERT_EQ(FIRC_RESOLVE_SOURCE_OFF, r.source);

    firc_app_destroy(app);
    firc_resolve_router_free(router);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a firmware resolver inside the fake pool becoming a group's route instead of being dropped. */
TEST a_firmware_resolver_inside_the_pool_is_dropped(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18; c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37; c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));

    firc_kn_iface_resolvers_t *items = calloc(1, sizeof(*items));
    ASSERT(items != NULL);
    snprintf(items[0].iface, sizeof(items[0].iface), "%s", "eth0");
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, firc_resolver_addr_parse("198.18.0.1", &items[0].servers[0]));
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, firc_resolver_addr_parse("9.9.9.9", &items[0].servers[1]));
    items[0].n = 2;
    firc_kn_resolver_map_t m = {.items = items, .n = 1};
    firc_kn_resolvers_t *resolvers = firc_kn_resolvers_start(NULL, 30, NULL, NULL);
    ASSERT(resolvers != NULL);
    firc_kn_resolvers_swap(resolvers, &m);

    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_resolve_router_t *router = firc_resolve_router_new(NULL);
    firc_app_deps_t deps = {.cfg = &cfg, .router = router, .resolvers = resolvers, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);

    firc_group_t *g = make_group("g", true);
    firc_id_t gid = g->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(app, g));

    firc_resolve_route_t r;
    ASSERT(firc_resolve_router_route(router, gid, &r));
    ASSERT_EQ(FIRC_RESOLVE_SOURCE_FIRMWARE, r.source);
    ASSERT_EQ_FMTm("the pool address must not survive the filter", (size_t)1, r.n_servers, "%zu");
    ASSERT_EQ(9, r.servers[0].ip.b[0]);

    firc_app_destroy(app);
    firc_resolve_router_free(router);
    firc_kn_resolvers_stop(resolvers);
    firc_fakeip_free(pool);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a route given the bare mark field without the handled bit, or a constant v6_route. */
TEST a_running_group_s_route_carries_its_real_mark_and_v6_route(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);

    firc_group_t *up = firc_group_new();
    up->id = firc_id_random();
    up->name = strdup("v6up");
    up->iface = strdup("lo");
    up->enable = true;
    firc_strset(&up->resolve.server, "[2620:fe::9]:53");
    firc_id_t up_id = up->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, up));

    firc_ruleset_t *up_rs = firc_app_find_group_by_id(l.app, up_id);
    uint32_t up_field = firc_ruleset_mark_field(up_rs);
    ASSERTm("the group is in the kernel", up_field != 0);
    ASSERTm("lo answered up, so its route was added", firc_ruleset_has_iface_route(up_rs, AF_INET6));

    firc_resolve_route_t r;
    ASSERT(firc_resolve_router_route(l.router, up_id, &r));
    ASSERT_EQ_FMTm("mark must be field | HANDLED, not the bare field", up_field | FIRC_MARK_HANDLED, r.mark,
                   "%u");
    ASSERT_EQ_FMTm("an IPv6 route: the group's own IPv6 server must survive", (size_t)1, r.n_servers, "%zu");

    fake_rtnl_set_link_flags(l.kernel, 0);
    firc_group_t *down = firc_group_new();
    down->id = firc_id_random();
    down->name = strdup("v6down");
    down->iface = strdup("lo");
    down->enable = true;
    firc_strset(&down->resolve.server, "[2620:fe::9]:53");
    firc_id_t down_id = down->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, down));

    firc_ruleset_t *down_rs = firc_app_find_group_by_id(l.app, down_id);
    ASSERTm("still in the kernel: a down link is not an enable failure", firc_ruleset_mark_field(down_rs) != 0);
    ASSERT_FALSEm("the link is down, so no route was added", firc_ruleset_has_iface_route(down_rs, AF_INET6));

    ASSERT(firc_resolve_router_route(l.router, down_id, &r));
    ASSERT_EQ_FMTm("no IPv6 route: the group's own IPv6-only server must be dropped", (size_t)0, r.n_servers,
                   "%zu");

    locked_app_down(&l);
    PASS();
}

/* Catches: a neutral update republishing the route mid-update with mark 0, bumping its generation. */
TEST an_update_of_a_running_group_does_not_bounce_its_route(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);

    firc_group_t *g = firc_group_new();
    g->id = firc_id_random();
    g->name = strdup("g");
    g->iface = strdup("lo");
    g->enable = true;
    firc_strset(&g->resolve.server, "9.9.9.9");
    firc_id_t gid = g->id;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));

    firc_resolve_route_t before;
    ASSERT(firc_resolve_router_route(l.router, gid, &before));
    ASSERTm("usable before the update", firc_resolve_route_usable(&before));

    firc_group_t *built = firc_group_new();
    built->id = gid;
    built->name = strdup("g");
    built->iface = strdup("lo");
    built->enable = true;
    firc_strset(&built->resolve.server, "9.9.9.9");

    uint64_t since = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, built));

    firc_resolve_route_t after;
    ASSERT(firc_resolve_router_route(l.router, gid, &after));
    ASSERT_EQ_FMTm("the generation must not move: nothing about the route changed", (unsigned long long)before.gen,
                   (unsigned long long)after.gen, "%llu");
    ASSERT_FALSEm("no false 'not routed yet' state for this update",
                  journal_says(since, "uses the common upstream until"));
    ASSERT_FALSEm("nothing about the route changed, so nothing should be logged about it",
                  journal_says(since, "\"g\" resolves") || journal_says(since, "\"g\" uses"));

    locked_app_down(&l);
    PASS();
}

/* Catches: close and forget swapped, called for an unchanged group, or not called at all. */
TEST a_republish_closes_the_moved_groups_and_forgets_the_gone_ones(void) {
    locked_app_t l;
    g_app_proxy = PROXY_SENTINEL;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);

    firc_id_t ids[3];
    const char *names[3] = {"g", "h", "k"};
    for (int i = 0; i < 3; i++) {
        firc_group_t *grp = firc_group_new();
        grp->id = firc_id_random();
        grp->name = strdup(names[i]);
        grp->iface = strdup("lo");
        grp->enable = true;
        firc_strset(&grp->resolve.server, "9.9.9.9");
        ids[i] = grp->id;
        ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, grp));
    }
    firc_resolve_route_t before;
    ASSERT(firc_resolve_router_route(l.router, ids[1], &before));
    memset(&g_closed, 0, sizeof(g_closed));
    memset(&g_forgot, 0, sizeof(g_forgot));

    firc_group_t *built = firc_group_new();
    built->id = ids[1];
    built->name = strdup("h");
    built->iface = strdup("lo");
    built->enable = true;
    firc_strset(&built->resolve.server, "1.1.1.1");
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, ids[1], built));
    firc_resolve_route_t after;
    ASSERT(firc_resolve_router_route(l.router, ids[1], &after));
    ASSERTm("h's route really moved", before.gen != after.gen);
    ASSERT_EQm("h's pools were closed", (size_t)1, id_log_count(&g_closed, ids[1]));
    ASSERT_EQm("h still exists: not forgotten", (size_t)0, g_forgot.n);

    ASSERT(firc_app_remove_group_by_id(l.app, ids[2]));
    ASSERT_EQm("k's pools were closed", (size_t)1, id_log_count(&g_closed, ids[2]));
    ASSERT_EQm("k was forgotten", (size_t)1, id_log_count(&g_forgot, ids[2]));
    ASSERT_EQm("nothing else was forgotten", (size_t)1, g_forgot.n);
    ASSERT_EQm("nothing was called for g", (size_t)0, id_log_count(&g_closed, ids[0]));
    ASSERT_EQm("h once, k once", (size_t)2, g_closed.n);

    locked_app_down(&l);
    PASS();
}

static void chain_of(const locked_app_t *l, firc_id_t gid, char *out, size_t cap) {
    firc_ruleset_chain_name_for(l->cfg.app.netfilter.iptables.chain_prefix, gid, out, cap);
}

/* Whether some rule in the table's chain, in one family's fake, carries this text */
static bool chain_has_text_in(firc_fake_ipt_t *fake, const char *table, const char *chain,
                              const char *needle) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    bool found = false;
    if (firc_fake_ipt_get_rules(fake, table, chain, &rules, &n)) {
        for (size_t i = 0; i < n && !found; i++) {
            char *text = firc_ipt_rule_string(rules[i]);
            found = text != NULL && strstr(text, needle) != NULL;
            free(text);
        }
    }
    return found;
}

static bool jump_in_of(locked_app_t *l, firc_fake_ipt_t *fake, const char *table, const char *base,
                       firc_id_t gid) {
    char chain[64], want[80];
    chain_of(l, gid, chain, sizeof(chain));
    snprintf(want, sizeof(want), "-j %s", chain);
    return chain_has_text_in(fake, table, base, want);
}

/* How much of the group is in the v4 fake (three chains, three jumps), read under the netfilter lock. */
static int group_in_fake_of(locked_app_t *l, firc_fake_ipt_t *fake, firc_id_t gid) {
    char chain[64];
    chain_of(l, gid, chain, sizeof(chain));
    return (int)firc_fake_ipt_chain_exists(fake, "filter", chain) +
           (int)firc_fake_ipt_chain_exists(fake, "mangle", chain) +
           (int)firc_fake_ipt_chain_exists(fake, "nat", chain) +
           (int)jump_in_of(l, fake, "filter", "FORWARD", gid) +
           (int)jump_in_of(l, fake, "mangle", "PREROUTING", gid) +
           (int)jump_in_of(l, fake, "nat", "POSTROUTING", gid);
}

static int group_in_fake(locked_app_t *l, firc_id_t gid) { return group_in_fake_of(l, l->fake, gid); }

static int group_in_kernel(locked_app_t *l, firc_id_t gid) {
    firc_app_nf_enter(l->app);
    int n = group_in_fake(l, gid);
    firc_app_nf_leave(l->app);
    return n;
}

static bool group_fully_in(locked_app_t *l, firc_id_t gid) { return group_in_kernel(l, gid) == 6; }
static bool group_fully_out(locked_app_t *l, firc_id_t gid) { return group_in_kernel(l, gid) == 0; }

static const firc_group_snapshot_t *view_owner(locked_app_t *l, const char *name) {
    const firc_ruleset_snapshot_t *snap = firc_dns_pipeline_snapshot(l->pipeline);
    return snap != NULL ? firc_ruleset_snapshot_first_match(snap, name) : NULL;
}

static size_t log_len(locked_app_t *l) {
    firc_app_nf_enter(l->app);
    const char *log = firc_fake_ipt_restore_log(l->fake);
    size_t n = log != NULL ? strlen(log) : 0;
    firc_app_nf_leave(l->app);
    return n;
}

static bool log_since_has(locked_app_t *l, size_t from, const char *needle) {
    firc_app_nf_enter(l->app);
    const char *log = firc_fake_ipt_restore_log(l->fake);
    bool has = log != NULL && strlen(log) > from && strstr(log + from, needle) != NULL;
    firc_app_nf_leave(l->app);
    return has;
}

/* Catches: the loop writing an update itself, or a pass that lost a race to the firmware not retried. */
TEST an_update_that_lost_one_race_comes_back(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "old.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("fixture: the group is in the kernel", group_fully_in(&l, gid));

    firc_app_nf_enter(l.app);
    firc_fake_ipt_reset(l.fake);
    firc_fake_ipt_fail_at_commit(l.fake, 2, FIRC_ERR_IO);
    started = firc_app_nf_passes_for_test(l.app);
    firc_err_t err = firc_app_update_group(l.app, gid, activation_group(1, "newer.example", NULL, NULL));
    bool loop_wrote = !firc_fake_ipt_failure_armed(l.fake);
    firc_app_nf_leave(l.app);

    ASSERT_EQ(FIRC_OK, err);
    ASSERT_FALSEm("the loop wrote no iptables", loop_wrote);
    ASSERTm("the edit is in the DNS view", view_owner(&l, "newer.example") != NULL);
    ASSERT_EQ(NULL, view_owner(&l, "old.example"));
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSEm("the race happened: a pass lost at the second COMMIT", firc_fake_ipt_failure_armed(l.fake));
    ASSERTm("and the retry put the whole group back", group_fully_in(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: an update whose refused write stops before the move, so its old names stay owned. */
TEST an_update_whose_write_was_refused_keeps_nothing_old(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "2ip.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));

    firc_app_nf_enter(l.app);
    firc_fake_ipt_reset(l.fake);
    firc_fake_ipt_fail_next_restore(l.fake, FIRC_ERR_IO);
    started = firc_app_nf_passes_for_test(l.app);
    firc_err_t err = firc_app_update_group(l.app, gid, activation_group(1, "other.example", NULL, NULL));
    firc_app_nf_leave(l.app);

    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQm("the old rule left the DNS view", NULL, view_owner(&l, "2ip.example"));
    ASSERTm("the new one is in it", view_owner(&l, "other.example") != NULL);
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSEm("the refusal fired", firc_fake_ipt_failure_armed(l.fake));
    ASSERT(group_fully_in(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: a Save that lost a race to the firmware failing, or dropping groups from config or view. */
TEST a_save_that_lost_one_race_drops_nothing(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    static const char *names[] = {"one.example", "two.example", "gc.apple.example"};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    for (uint8_t t = 1; t <= 3; t++) {
        ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(t, names[t - 1], NULL, NULL)));
    }
    ASSERT(wait_written_after(&l, started));
    firc_ruleset_t *rs2 = firc_app_find_group_by_id(l.app, (firc_id_t){{2, 2, 2, 2}});
    char mark[64];
    snprintf(mark, sizeof(mark), "--mark 0x%x/0x%x", firc_ruleset_mark_field(rs2), FIRC_MARK_GROUP_MASK);

    firc_group_t **arr = calloc(3, sizeof(*arr));
    ASSERT(arr != NULL);
    for (uint8_t t = 1; t <= 3; t++) { arr[t - 1] = activation_group(t, names[t - 1], NULL, NULL); }
    size_t calls = firc_fake_ipt_restore_calls(l.fake);
    size_t from = log_len(&l);
    firc_app_nf_enter(l.app);
    firc_fake_ipt_reset(l.fake);
    firc_fake_ipt_refuse_rules_containing(l.fake, mark);
    firc_err_t err = firc_app_replace_groups(l.app, arr, 3);
    firc_app_nf_leave(l.app);

    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMT((size_t)3, firc_app_user_group_count(l.app), "%zu");
    for (size_t i = 0; i < 3; i++) { ASSERTm(names[i], view_owner(&l, names[i]) != NULL); }
    ASSERTm("a pass tried", a_restore_was_tried(&l, calls));
    ASSERTm("and group 2's rules were in what was refused", log_since_has(&l, from, mark));

    started = firc_app_nf_passes_for_test(l.app);
    firc_fake_ipt_refuse_rules_containing(l.fake, NULL);
    ASSERT(wait_written_after(&l, started));
    for (uint8_t t = 1; t <= 3; t++) { ASSERT(group_fully_in(&l, (firc_id_t){{t, t, t, t}})); }
    locked_app_down(&l);
    PASS();
}

/* Catches: a group mutation asking for a full pass, which opens the fail-open window on every edit. */
TEST no_group_mutation_asks_for_a_full_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_nfcommit_t *c = firc_app_committer_for_test(l.app);
    size_t full = firc_nfcommit_requests_for_test(c);
    firc_id_t gid = {{1, 1, 1, 1}};

    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "b.example", NULL, NULL)));
    firc_group_t *off = activation_group(1, "b.example", NULL, NULL);
    off->enable = false;
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, off));
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "b.example", NULL, NULL)));
    firc_group_t *moved = activation_group(1, "b.example", NULL, NULL);
    free(moved->iface);
    moved->iface = strdup("eth0");
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, moved));
    firc_group_t **arr = calloc(1, sizeof(*arr));
    ASSERT(arr != NULL);
    arr[0] = activation_group(1, "b.example", NULL, NULL);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, arr, 1));
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    ASSERT_EQ_FMTm("add, edit, off, on, interface, Save, delete: no full pass", full,
                   firc_nfcommit_requests_for_test(c), "%zu");

    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    ASSERT_EQ_FMTm("the hook's kind of request is counted", full + 1, firc_nfcommit_requests_for_test(c), "%zu");
    locked_app_down(&l);
    PASS();
}

/* Catches: the no-committer path leaving its writes to a committer that does not exist. */
TEST without_a_committer_the_loop_writes_the_chain_at_once(void) {
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERTm("in the kernel as the add returns", group_fully_in(&l, gid));
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    ASSERTm("out of it as the delete returns", group_fully_out(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: a deleted group's chain left in place, deleted in a commit of its own, or half deleted. */
TEST a_deleted_group_leaves_by_tombstone_in_the_next_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_in(&l, gid));

    char chain[64], del[80];
    chain_of(&l, gid, chain, sizeof(chain));
    snprintf(del, sizeof(del), "-X %s", chain);
    size_t calls = firc_fake_ipt_restore_calls(l.fake);
    size_t from = log_len(&l);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    ASSERT(wait_written_after(&l, started));
    sleep_ms(300);
    ASSERTm("the chain and all three jumps are gone", group_fully_out(&l, gid));
    ASSERTm("deleted by the pass", log_since_has(&l, from, del));
    ASSERT_EQ_FMTm("in one restore, with the rest of the pass", calls + 1,
                   firc_fake_ipt_restore_calls(l.fake), "%zu");
    locked_app_down(&l);
    PASS();
}

/* Catches: a tombstone for a chain the firmware already removed failing the pass on a missing jump. */
TEST a_tombstone_for_a_chain_already_gone_costs_nothing(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));

    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    firc_fake_ipt_reset(l.fake);
    firc_app_nf_leave(l.app);
    ASSERTm("the pass completed", wait_written_after(&l, started));
    ASSERT(group_fully_out(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: losing both the untombstone on re-add and the tombstones-first order, deleting the chain. */
TEST a_group_deleted_and_added_back_before_the_pass_keeps_its_chain(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));

    char chain[64], del[80];
    chain_of(&l, gid, chain, sizeof(chain));
    snprintf(del, sizeof(del), "-X %s", chain);
    size_t from = log_len(&l);
    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    firc_app_nf_leave(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_in(&l, gid));
    ASSERT_FALSEm("no pass deleted it", log_since_has(&l, from, del));
    locked_app_down(&l);
    PASS();
}

/* Catches: a Save that changes nothing deleting every live chain in the pass after it. */
TEST a_save_of_the_same_groups_keeps_every_chain(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "b.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));

    size_t from = log_len(&l);
    firc_group_t **arr = calloc(2, sizeof(*arr));
    ASSERT(arr != NULL);
    arr[0] = activation_group(1, "a.example", NULL, NULL);
    arr[1] = activation_group(2, "b.example", NULL, NULL);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, arr, 2));
    ASSERT(wait_written_after(&l, started));
    for (uint8_t t = 1; t <= 2; t++) {
        firc_id_t gid = {{t, t, t, t}};
        char chain[64], del[80];
        chain_of(&l, gid, chain, sizeof(chain));
        snprintf(del, sizeof(del), "-X %s", chain);
        ASSERT(group_fully_in(&l, gid));
        ASSERT_FALSE(log_since_has(&l, from, del));
    }
    locked_app_down(&l);
    PASS();
}

/* Catches: a teardown error keeping the deleted group, or skipping its tombstone. */
TEST a_delete_whose_teardown_failed_still_removes_the_group(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));

    fake_rtnl_fail_next_of(l.kernel, RTM_DELRULE, EPERM);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    ASSERT_FALSEm("the teardown met the refusal", fake_rtnl_failure_armed(l.kernel));
    ASSERT_EQm("gone from the config", NULL, firc_app_find_group_by_id(l.app, gid));
    ASSERT_EQm("and from the DNS view", NULL, view_owner(&l, "a.example"));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("and from the kernel after the pass", group_fully_out(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: routed read as in-view, the group switch or runtime enable ignored, or a wrong chain name. */
TEST in_view_routed_and_the_chain_name_say_what_the_kernel_has(void) {
    char name[64];
    firc_ruleset_chain_name_for("FIRC_", (firc_id_t){{0xab, 0x01, 0x02, 0xff}}, name, sizeof(name));
    ASSERT_STR_EQ("FIRC_ab0102ff", name);
    firc_ruleset_chain_name_for(NULL, (firc_id_t){{0xab, 0x01, 0x02, 0xff}}, name, sizeof(name));
    ASSERT_STR_EQ("ab0102ff", name);

    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(4, "idle.example", NULL, NULL)));
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "one.example", NULL, NULL)));
    firc_group_t *off = activation_group(2, "two.example", NULL, NULL);
    off->enable = false;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, off));
    firc_group_t *bad = activation_group(3, "three.example", NULL, NULL);
    free(bad->iface);
    bad->iface = strdup("not an iface");
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, bad));

    const firc_ruleset_t *rs[5] = {NULL};
    for (uint8_t t = 1; t <= 4; t++) {
        rs[t] = firc_app_find_group_by_id(l.app, (firc_id_t){{t, t, t, t}});
        ASSERT(rs[t] != NULL);
    }
    ASSERT(firc_ruleset_in_view(rs[1]) && firc_ruleset_routed(rs[1]));
    ASSERTm("routed: its chain is in the kernel under that name",
            firc_fake_ipt_chain_exists(l.fake, "mangle", "FIRC_01010101"));
    ASSERT_FALSE(firc_ruleset_in_view(rs[2]) || firc_ruleset_routed(rs[2]));
    ASSERTm("no interface: in the view", firc_ruleset_in_view(rs[3]));
    ASSERT_FALSEm("and not routed", firc_ruleset_routed(rs[3]));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(l.fake, "mangle", "FIRC_03030303"));
    ASSERT_FALSE(firc_ruleset_in_view(rs[4]) || firc_ruleset_routed(rs[4]));
    ASSERT_FALSE(firc_ruleset_in_view(NULL) || firc_ruleset_routed(NULL));
    locked_app_down(&l);
    PASS();
}

/* Catches: a failed pass clearing the tombstones it carried, so the retry deletes nothing. */
TEST a_tombstone_outlives_a_failed_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_in(&l, gid));

    firc_app_nf_enter(l.app);
    firc_fake_ipt_fail_next_restore(l.fake, FIRC_ERR_IO);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    firc_app_nf_leave(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSEm("the first pass was refused", firc_fake_ipt_failure_armed(l.fake));
    ASSERTm("and the retry deleted the chain", group_fully_out(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: a completed pass keeping its tombstones, or a delete that queues none. */
TEST a_completed_pass_empties_the_tombstones(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));

    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    size_t queued = firc_app_tombstones_for_test(l.app);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("the delete queued its chain", (size_t)1, queued, "%zu");
    ASSERT(wait_written_after(&l, started));
    firc_app_nf_enter(l.app);
    size_t left = firc_app_tombstones_for_test(l.app);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("and the pass that carried it cleared the list", (size_t)0, left, "%zu");
    ASSERTm("having deleted the chain", group_fully_out(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: a daemon stop leaving tombstoned chains, or deleting one table, no jumps or one family. */
TEST stopping_deletes_the_chains_still_tombstoned(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_in(&l, gid));
    firc_app_nf_enter(l.app);
    int v6_before = group_in_fake_of(&l, l.fake6, gid);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("fixture: the group is in the v6 kernel too", 6, v6_before, "%d");

    char chain[64], del[80];
    chain_of(&l, gid, chain, sizeof(chain));
    snprintf(del, sizeof(del), "-X %s", chain);
    firc_fake_ipt_refuse_rules_containing(l.fake, del);
    firc_fake_ipt_refuse_rules_containing(l.fake6, del);
    size_t calls = firc_fake_ipt_restore_calls(l.fake);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    ASSERTm("a pass tried and was refused", a_restore_was_tried(&l, calls));
    ASSERT_FALSEm("so the chain is still there", group_fully_out(&l, gid));
    firc_app_nf_enter(l.app);
    int v6_left = group_in_fake_of(&l, l.fake6, gid);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("in v6 as well", 6, v6_left, "%d");

    firc_app_stop_netfilter_committer(l.app);
    firc_fake_ipt_refuse_rules_containing(l.fake, NULL);
    firc_fake_ipt_refuse_rules_containing(l.fake6, NULL);
    firc_app_destroy(l.app);
    l.app = NULL;
    ASSERT_EQ_FMTm("the stop deleted the chain and its jumps", 0, group_in_fake(&l, gid), "%d");
    ASSERT_EQ_FMTm("in both families", 0, group_in_fake_of(&l, l.fake6, gid), "%d");
    locked_app_down(&l);
    PASS();
}

/* Routed, not live: live also reads the link, which the host may not have. */
static bool group_routed(locked_app_t *l, uint8_t tag) {
    firc_app_nf_enter(l->app);
    bool routed = firc_ruleset_routed(firc_app_find_group_by_id(l->app, (firc_id_t){{tag, tag, tag, tag}}));
    firc_app_nf_leave(l->app);
    return routed;
}

static const char *live_reason(locked_app_t *l, uint8_t tag) {
    const char *reason = "unset";
    bool live = firc_app_group_live(l->app, (firc_id_t){{tag, tag, tag, tag}}, &reason);
    return live ? (reason == NULL ? "live" : "live-with-a-reason") : (reason != NULL ? reason : "null");
}

/* Catches: a Save that fails, or drops groups, when its second group fails to come up. */
TEST a_save_whose_second_group_fails_keeps_all_three(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_app_pool_changed(l.app);
    ASSERT(wait_written_after(&l, 0));
    static const char *names[] = {"one.example", "two.example", "three.example"};
    firc_group_t **arr = calloc(3, sizeof(*arr));
    ASSERT(arr != NULL);
    for (uint8_t t = 1; t <= 3; t++) { arr[t - 1] = activation_group(t, names[t - 1], NULL, NULL); }
    fake_rtnl_fail_after_of(l.kernel, RTM_NEWRULE, EPERM, 3);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, arr, 3));
    ASSERT_FALSEm("the armed refusal was met", fake_rtnl_failure_armed(l.kernel));

    ASSERT_EQ_FMT((size_t)3, firc_app_user_group_count(l.app), "%zu");
    ASSERT(view_owner(&l, "one.example") != NULL);
    ASSERT_EQm("the failed group is out of the view", NULL, view_owner(&l, "two.example"));
    ASSERT(view_owner(&l, "three.example") != NULL);
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 2));
    ASSERT_STR_EQ("live", live_reason(&l, 3));

    char dir[] = "/tmp/firc-save-XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char conf[64], groups[64];
    snprintf(conf, sizeof(conf), "%s/firc.conf", dir);
    snprintf(groups, sizeof(groups), "%s/groups.yaml", dir);
    ASSERT_EQ(FIRC_OK, firc_app_save_groups(l.app, conf, ""));
    FILE *f = fopen(groups, "r");
    ASSERT(f != NULL);
    char body[8192];
    size_t n = fread(body, 1, sizeof(body) - 1, f);
    fclose(f);
    body[n] = '\0';
    ASSERTm("group 1 saved", strstr(body, "01010101") != NULL);
    ASSERTm("group 2 saved, although it did not come up", strstr(body, "02020202") != NULL);
    ASSERTm("group 3 saved", strstr(body, "03030303") != NULL);
    unlink(groups);
    unlink(conf);
    rmdir(dir);
    locked_app_down(&l);
    PASS();
}

/* Catches: a failed POST keeping the group, or not naming the step that failed. */
TEST a_new_group_that_fails_to_come_up_says_which_step(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    char why[FIRC_APP_WHY_MAX] = "";
    ASSERT(firc_app_add_group_why(l.app, activation_group(1, "a.example", NULL, NULL), why, sizeof(why)) != FIRC_OK);
    char want[FIRC_APP_WHY_MAX];
    snprintf(want, sizeof(want), "group \"g\": ip rule: %s", firc_err_str(firc_err_from_errno(EPERM)));
    ASSERT_STR_EQ(want, why);
    ASSERT_EQ_FMT((size_t)0, firc_app_user_group_count(l.app), "%zu");
    locked_app_down(&l);
    PASS();
}

/* Catches: the mark field or pool reject route step misnamed, or the group kept after either fails. */
TEST a_new_group_names_the_mark_field_and_the_pool_reject_route_steps(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    const char *err = firc_err_str(firc_err_from_errno(EPERM));
    char why[FIRC_APP_WHY_MAX], want[FIRC_APP_WHY_MAX];

    fake_rtnl_fail_after_of(l.kernel, RTM_GETRULE, EPERM, 2);
    why[0] = '\0';
    ASSERT(firc_app_add_group_why(l.app, activation_group(1, "a.example", NULL, NULL), why, sizeof(why)) != FIRC_OK);
    ASSERT_FALSEm("the armed dump refusal was met", fake_rtnl_failure_armed(l.kernel));
    snprintf(want, sizeof(want), "group \"g\": mark field: %s", err);
    ASSERT_STR_EQ(want, why);
    ASSERT_EQ_FMT((size_t)0, firc_app_user_group_count(l.app), "%zu");

    fake_rtnl_fail_after_of(l.kernel, RTM_NEWROUTE, EPERM, 4);
    why[0] = '\0';
    ASSERT(firc_app_add_group_why(l.app, activation_group(1, "a.example", NULL, NULL), why, sizeof(why)) != FIRC_OK);
    ASSERT_FALSEm("the armed route refusal was met", fake_rtnl_failure_armed(l.kernel));
    snprintf(want, sizeof(want), "group \"g\": pool reject route: %s", err);
    ASSERT_STR_EQ(want, why);
    ASSERT_EQ_FMT((size_t)0, firc_app_user_group_count(l.app), "%zu");
    locked_app_down(&l);
    PASS();
}

/* Catches: a startup stopping at its first failed group, or keeping that group's names in the view. */
TEST a_startup_whose_first_group_fails_starts_the_rest(void) {
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "bad.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "good.example", NULL, NULL)));
    ASSERTm("fixture: before the start the config is the view", view_owner(&l, "bad.example") != NULL);
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    ASSERT_FALSEm("group 1 met the refusal", fake_rtnl_failure_armed(l.kernel));
    ASSERT(firc_app_is_running(l.app));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 1));
    ASSERT_STR_EQ("live", live_reason(&l, 2));
    ASSERT_EQm("the failed group is out of the view", NULL, view_owner(&l, "bad.example"));
    ASSERT(view_owner(&l, "good.example") != NULL);

    ASSERT_EQ(FIRC_OK, firc_app_start_netfilter_committer(l.app));
    firc_app_pool_changed(l.app);
    ASSERT(wait_written_after(&l, 0));
    ASSERTm("the first pass wrote group 2", group_fully_in(&l, (firc_id_t){{2, 2, 2, 2}}));
    ASSERTm("and nothing of group 1", group_fully_out(&l, (firc_id_t){{1, 1, 1, 1}}));
    locked_app_down(&l);
    PASS();
}

/* Catches: a startup writing the chains itself, or a refused first pass not retried. */
TEST a_startup_whose_first_write_is_refused_comes_up_on_the_retry(void) {
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    firc_fake_ipt_fail_at_commit(l.fake, 1, FIRC_ERR_IO);
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    ASSERTm("the startup wrote no iptables", firc_fake_ipt_failure_armed(l.fake));
    ASSERT_STR_EQ("live", live_reason(&l, 1));

    ASSERT_EQ(FIRC_OK, firc_app_start_netfilter_committer(l.app));
    firc_app_pool_changed(l.app);
    ASSERT(wait_written_after(&l, 0));
    ASSERT_FALSEm("the first pass met the refusal", firc_fake_ipt_failure_armed(l.fake));
    ASSERTm("and the retry wrote the group", group_fully_in(&l, gid));
    ASSERTm("the pass that landed was not the first", firc_app_nf_last_completed_pass_for_test(l.app) >= 2);
    locked_app_down(&l);
    PASS();
}

/* Catches: an update that stops when rtnetlink refuses its teardown. */
TEST an_update_whose_teardown_failed_still_moves_and_comes_up(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_app_pool_changed(l.app);
    ASSERT(wait_written_after(&l, 0));
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "old.example", NULL, NULL)));
    fake_rtnl_fail_next_of(l.kernel, RTM_DELRULE, EPERM);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "new.example", NULL, NULL)));
    ASSERT_FALSEm("the teardown met the refusal", fake_rtnl_failure_armed(l.kernel));
    ASSERT_EQ(NULL, view_owner(&l, "old.example"));
    ASSERT(view_owner(&l, "new.example") != NULL);
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_in(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: an update whose re-enable fails leaving its old chain marking traffic with no ip rule. */
TEST a_failed_re_enable_leaves_no_chain_after_the_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_in(&l, gid));

    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "b.example", NULL, NULL)));
    ASSERT_FALSEm("the re-enable met the refusal", fake_rtnl_failure_armed(l.kernel));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 1));
    ASSERT_EQm("out of the view", NULL, view_owner(&l, "b.example"));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("and out of the kernel", group_fully_out(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: live reasons checked out of order (disabled, not-enabled, no-interface), or a stale chain. */
TEST live_reason_is_checked_in_its_order(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_group_t *g5 = activation_group(5, "e.example", NULL, NULL);
    g5->enable = false;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g5));
    firc_app_set_running(l.app, true);
    firc_group_t *g1 = activation_group(1, "a.example", NULL, NULL);
    g1->enable = false;
    free(g1->iface);
    g1->iface = strdup("");
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g1));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "b.example", NULL, NULL)));
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(3, "c.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(4, "d.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("fixture: group 3 is in the kernel", group_fully_in(&l, (firc_id_t){{3, 3, 3, 3}}));
    firc_group_t *g3 = activation_group(3, "c.example", NULL, NULL);
    free(g3->iface);
    g3->iface = strdup("");
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, (firc_id_t){{3, 3, 3, 3}}, g3));
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, (firc_id_t){{2, 2, 2, 2}},
                                             activation_group(2, "b.example", NULL, NULL)));
    ASSERT_FALSEm("group 2's re-enable met the refusal", fake_rtnl_failure_armed(l.kernel));

    ASSERT_STR_EQ("disabled", live_reason(&l, 1));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 2));
    ASSERT_STR_EQ("no-interface", live_reason(&l, 3));
    ASSERT_STR_EQ("live", live_reason(&l, 4));
    ASSERT_STR_EQ("disabled", live_reason(&l, 5));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 9));
    ASSERTm("a group with no interface stays in the view: it fails closed",
            view_owner(&l, "c.example") != NULL);
    started = firc_app_nf_passes_for_test(l.app);
    firc_app_pool_changed(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERTm("and its old chain left by tombstone", group_fully_out(&l, (firc_id_t){{3, 3, 3, 3}}));
    locked_app_down(&l);
    PASS();
}

static bool live_reason_becomes(locked_app_t *l, uint8_t tag, const char *want) {
    for (int i = 0; i < 1000; i++) {
        if (strcmp(live_reason(l, tag), want) == 0) { return true; }
        sleep_ms(10);
    }
    return false;
}

/* Catches: a group read live while passes keep failing past the bound, or not-written before it. */
TEST a_committer_that_keeps_failing_says_not_written(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    firc_nfcommit_set_failing_after_for_test(firc_app_committer_for_test(l.app), 1500u);
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_group_t *g3 = activation_group(3, "c.example", NULL, NULL);
    free(g3->iface);
    g3->iface = strdup("");
    firc_group_t *g5 = activation_group(5, "e.example", NULL, NULL);
    g5->enable = false;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g3));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g5));
    ASSERT(wait_written_after(&l, started));
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    firc_nfcommit_health_t h;
    firc_app_netfilter_health(l.app, &h);
    ASSERT_FALSE(h.failing);

    char chain[64];
    chain_of(&l, (firc_id_t){{1, 1, 1, 1}}, chain, sizeof(chain));
    int64_t before = (int64_t)time(NULL);
    size_t calls = firc_fake_ipt_restore_calls(l.fake);
    struct timespec ts0;
    clock_gettime(CLOCK_MONOTONIC, &ts0);
    firc_app_nf_enter(l.app);
    firc_fake_ipt_refuse_rules_containing(l.fake, chain);
    uint64_t refused_from = firc_app_nf_passes_for_test(l.app);
    (void)firc_app_force_commit_iptables(l.app);
    firc_app_nf_leave(l.app);
    ASSERTm("a pass tried and was refused", a_restore_was_tried(&l, calls));
    for (int i = 0; i < 500 && firc_app_nf_passes_for_test(l.app) < refused_from + 2; i++) { sleep_ms(10); }
    const char *early = live_reason(&l, 1);
    struct timespec ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    long early_ms = (ts1.tv_sec - ts0.tv_sec) * 1000L + (ts1.tv_nsec - ts0.tv_nsec) / 1000000L;
    ASSERTm("fixture: the retry started", firc_app_nf_passes_for_test(l.app) >= refused_from + 2);
    ASSERTm("fixture: read inside the bound", early_ms < 1500);
    ASSERT_STR_EQm("one refusal, inside the bound: still live", "live", early);
    ASSERT(live_reason_becomes(&l, 1, "not-written"));
    firc_app_netfilter_health(l.app, &h);
    ASSERT(h.failing);
    ASSERT_EQ(FIRC_ERR_IO, h.err);
    ASSERT(h.since >= before && h.since <= (int64_t)time(NULL));
    ASSERT_STR_EQ("no-interface", live_reason(&l, 3));
    ASSERT_STR_EQ("disabled", live_reason(&l, 5));

    firc_app_nf_enter(l.app);
    firc_fake_ipt_refuse_rules_containing(l.fake, NULL);
    started = firc_app_nf_passes_for_test(l.app);
    firc_app_nf_leave(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    firc_app_netfilter_health(l.app, &h);
    ASSERT_FALSE(h.failing);
    locked_app_down(&l);
    PASS();
}

/* Catches: a group read live before the first pass has written its chain. */
TEST before_the_first_pass_a_group_reads_not_written(void) {
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    firc_nfcommit_health_t h;
    firc_app_netfilter_health(l.app, &h);
    ASSERT_FALSEm("no committer, nothing pending", h.first_pending);
    ASSERT_STR_EQ("live", live_reason(&l, 1));

    ASSERT_EQ(FIRC_OK, firc_app_start_netfilter_committer(l.app));
    firc_app_nf_enter(l.app);
    firc_app_pool_changed(l.app);
    bool none_yet = firc_app_nf_last_completed_pass_for_test(l.app) == 0;
    const char *before = live_reason(&l, 1);
    firc_app_netfilter_health(l.app, &h);
    firc_app_nf_leave(l.app);
    ASSERTm("fixture: no pass has completed", none_yet);
    ASSERT_STR_EQ("not-written", before);
    ASSERT(h.first_pending);
    ASSERT_FALSE(h.failing);

    ASSERT(wait_written_after(&l, 0));
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    firc_app_netfilter_health(l.app, &h);
    ASSERT_FALSE(h.first_pending);
    ASSERT(group_fully_in(&l, (firc_id_t){{1, 1, 1, 1}}));
    locked_app_down(&l);
    PASS();
}

/* Catches: a group whose interface is missing or down reading live. */
TEST live_follows_the_interface_link(void) {
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x10);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    ASSERT_EQ(FIRC_OK, firc_app_start_netfilter_committer(l.app));

    firc_app_nf_enter(l.app);
    firc_app_pool_changed(l.app);
    bool none_yet = firc_app_nf_last_completed_pass_for_test(l.app) == 0;
    const char *down_first = live_reason(&l, 1);
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    const char *up_first = live_reason(&l, 1);
    fake_rtnl_set_link_flags(l.kernel, 0x10);
    firc_app_nf_leave(l.app);
    ASSERTm("fixture: no pass has completed", none_yet);
    ASSERT_STR_EQm("no-interface is said before not-written", "no-interface", down_first);
    ASSERT_STR_EQm("fixture: up, it is the pending pass", "not-written", up_first);
    ASSERT(wait_written_after(&l, 0));

    firc_group_t *g2 = activation_group(2, "b.example", NULL, NULL);
    free(g2->iface);
    g2->iface = strdup("fircabsent0");
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g2));
    firc_group_t *g3 = activation_group(3, "c.example", NULL, NULL);
    free(g3->iface);
    g3->iface = strdup("");
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g3));
    firc_group_t *g4 = activation_group(4, "d.example", NULL, NULL);
    free(g4->iface);
    g4->iface = strdup("fircabsent0");
    g4->enable = false;
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g4));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(6, "f.example", NULL, NULL)));
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, (firc_id_t){{6, 6, 6, 6}},
                                             activation_group(6, "f.example", NULL, NULL)));
    ASSERT_FALSEm("fixture: group 6's re-enable met the refusal", fake_rtnl_failure_armed(l.kernel));
    firc_group_t *g7 = activation_group(7, "g.example", NULL, NULL);
    free(g7->iface);
    g7->iface = strdup("blackhole");
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g7));

    ASSERT_STR_EQm("down: not live", "no-interface", live_reason(&l, 1));
    ASSERT_STR_EQm("missing: not live", "no-interface", live_reason(&l, 2));
    ASSERT_STR_EQm("an invalid name, as before", "no-interface", live_reason(&l, 3));
    ASSERT_STR_EQm("off comes first", "disabled", live_reason(&l, 4));
    ASSERT_STR_EQm("a failed enable comes first", "not-enabled", live_reason(&l, 6));
    ASSERT_STR_EQm("blackhole needs no link", "live", live_reason(&l, 7));
    ASSERTm("routing is unchanged: the down group is still routed", group_routed(&l, 1));
    ASSERTm("and so is the missing one", group_routed(&l, 2));

    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    ASSERT_STR_EQm("up: live again, by itself", "live", live_reason(&l, 1));
    ASSERT_STR_EQm("the missing one stays out", "no-interface", live_reason(&l, 2));
    ASSERT_STR_EQ("no-interface", live_reason(&l, 3));
    ASSERT_STR_EQ("disabled", live_reason(&l, 4));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 6));

    fake_rtnl_fail_next_of(l.kernel, RTM_GETLINK, EPERM);
    const char *refused = live_reason(&l, 1);
    ASSERT_FALSEm("fixture: the lookup met the refusal", fake_rtnl_failure_armed(l.kernel));
    ASSERT_STR_EQm("a lookup that fails is not live", "no-interface", refused);
    ASSERT_STR_EQm("and the next one is", "live", live_reason(&l, 1));

    fake_rtnl_set_link_flags(l.kernel, 0x10);
    ASSERT_STR_EQm("down again: not live", "no-interface", live_reason(&l, 1));
    locked_app_down(&l);
    PASS();
}

static firc_sub_event_t *sync_event(uint8_t tag, firc_sub_event_kind_t kind) {
    firc_sub_event_t *ev = calloc(1, sizeof(*ev));
    if (ev == NULL) { return NULL; }
    ev->kind = kind;
    ev->group_id = (firc_id_t){{tag, tag, tag, tag}};
    ev->seq = 0;
    return ev;
}

/* Catches: sync STARTED or PROGRESS taking the lock that aborts a pass, or RESULT not taking it. */
TEST a_syncs_progress_does_not_interrupt_the_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", "https://x.example/l", "b.example")));
    firc_group_t *g = firc_ruleset_group_mut(firc_app_find_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}}));

    uint64_t before = firc_app_nf_enters_for_test(l.app);
    firc_app_on_sync_event(l.app, sync_event(1, FIRC_SUB_EV_STARTED), 1000);
    ASSERT_EQ(FIRC_SUB_SYNC_FETCHING, g->list->sync_state);
    for (size_t i = 1; i <= 30; i++) {
        firc_sub_event_t *ev = sync_event(1, FIRC_SUB_EV_PROGRESS);
        ASSERT(ev != NULL);
        ev->bytes = i * 1000;
        firc_app_on_sync_event(l.app, ev, 1000);
    }
    ASSERT_EQ_FMT((size_t)30000, g->list->sync_progress.bytes, "%zu");
    ASSERT_EQ_FMTm("no report took the interrupting lock", (unsigned long long)before,
                   (unsigned long long)firc_app_nf_enters_for_test(l.app), "%llu");

    firc_sub_event_t *res = sync_event(1, FIRC_SUB_EV_RESULT);
    ASSERT(res != NULL);
    res->result = FIRC_SUB_RESULT_ERROR;
    res->err = FIRC_ERR_IO;
    firc_app_on_sync_event(l.app, res, 1000);
    ASSERT_EQ(FIRC_SUB_SYNC_ERROR, g->list->sync_state);
    ASSERT_EQ_FMTm("the result did", (unsigned long long)(before + 1),
                   (unsigned long long)firc_app_nf_enters_for_test(l.app), "%llu");
    locked_app_down(&l);
    PASS();
}

/* Catches: list bookkeeping (sync asks, sweeps, url changes) taking the lock that aborts a pass. */
TEST a_lists_bookkeeping_does_not_interrupt_the_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", "https://x.example/l", "b.example")));
    firc_id_t gid = {{1, 1, 1, 1}};
    firc_group_t *g = firc_ruleset_group_mut(firc_app_find_group_by_id(l.app, gid));

    uint64_t before = firc_app_nf_enters_for_test(l.app);
    (void)firc_app_request_sync(l.app, gid);
    firc_app_request_sync_missing(l.app);
    firc_app_request_sync_due(l.app, 4000000000);
    ASSERT_EQ(FIRC_OK, firc_app_set_list_url(l.app, gid, "https://y.example/l"));
    ASSERT_STR_EQ("https://y.example/l", g->list->url);
    ASSERT_EQ_FMT((unsigned long long)before, (unsigned long long)firc_app_nf_enters_for_test(l.app), "%llu");
    locked_app_down(&l);
    PASS();
}

static uint64_t g_now_ms;
static uint64_t test_clock(void) { return g_now_ms; }

static size_t journal_count(uint64_t since, const char *needle) {
    size_t n = journal(since), c = 0;
    for (size_t i = 0; i < n; i++) {
        if (g_events[i].kind == FIRC_EVENT_LOG && strstr(g_events[i].u.log.text, needle) != NULL) { c++; }
    }
    return c;
}

/* Catches: a failed group not retried on its own link-up, or retried before its spacing. */
TEST a_group_that_failed_comes_up_by_itself_on_link_up(void) {
    g_now_ms = 100000;
    g_app_mono = test_clock;
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    ASSERT_FALSEm("the refusal fired", fake_rtnl_failure_armed(l.kernel));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 1));
    ASSERT_EQ(FIRC_OK, firc_app_start_netfilter_committer(l.app));
    firc_app_pool_changed(l.app);
    ASSERT(wait_written_after(&l, 0));

    g_now_ms += 999;
    firc_app_retry_groups(l.app, "lo");
    ASSERT_STR_EQm("not due yet", "not-enabled", live_reason(&l, 1));
    g_now_ms += 1;
    firc_app_retry_groups(l.app, "eth9");
    ASSERT_STR_EQm("another interface", "not-enabled", live_reason(&l, 1));
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_retry_groups(l.app, "lo");
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    ASSERTm("back in the view", view_owner(&l, "a.example") != NULL);
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_in(&l, gid));
    locked_app_down(&l);
    PASS();
}

/* Catches: retry spacing not doubling from 1 s or not capped at 60 s, or a warning on every try. */
TEST a_group_that_keeps_failing_is_retried_no_more_often_than_its_spacing(void) {
    g_now_ms = 100000;
    g_app_mono = test_clock;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    fake_rtnl_fail_times(l.kernel, RTM_NEWRULE, EPERM, 1000);
    uint64_t mark = journal_mark();
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    const uint64_t t0 = g_now_ms;
    static const struct { uint64_t at; size_t tries; uint64_t delay; } steps[] = {
        {0, 1, 1000},          {999, 1, 1000},        {1000, 2, 2000},     {2999, 2, 2000},
        {3000, 3, 4000},       {6999, 3, 4000},       {7000, 4, 8000},     {15000, 5, 16000},
        {31000, 6, 32000},     {63000, 7, 60000},     {123000, 8, 60000},
    };
    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        g_now_ms = t0 + steps[i].at;
        firc_app_retry_groups(l.app, NULL);
        static char what[64];
        snprintf(what, sizeof(what), "tries at +%llu ms", (unsigned long long)steps[i].at);
        ASSERT_EQ_FMTm(what, steps[i].tries, fake_rtnl_count(l.kernel, RTM_NEWRULE, 0), "%zu");
        uint64_t delay = 0;
        snprintf(what, sizeof(what), "timer at +%llu ms", (unsigned long long)steps[i].at);
        ASSERTm(what, firc_app_retry_timer_for_test(l.app, &delay));
        ASSERT_EQ_FMTm(what, (unsigned long long)steps[i].delay, (unsigned long long)delay, "%llu");
    }
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 1));
    ASSERT_EQ_FMTm("one warning for the run", (size_t)1, journal_count(mark, "trying again"), "%zu");
    ASSERT(firc_app_remove_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}}));
    ASSERT_FALSEm("no group left to retry, no timer", firc_app_retry_timer_for_test(l.app, NULL));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: no retry timer armed for a failed group, or one left armed once nothing fails. */
TEST a_failed_group_comes_up_on_its_timer_with_no_trigger(void) {
    g_now_ms = 100000;
    g_app_mono = test_clock;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_ex(&l, loop, tap_fake_open, false));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    ASSERT_FALSEm("the refusal fired", fake_rtnl_failure_armed(l.kernel));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 1));
    uint64_t delay = 0;
    ASSERT(firc_app_retry_timer_for_test(l.app, &delay));
    ASSERT_EQ_FMT(1000ull, (unsigned long long)delay, "%llu");

    g_now_ms += 1000;
    ASSERT(run_loop_for(loop, 1500));
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    ASSERT(view_owner(&l, "a.example") != NULL);
    ASSERT_FALSEm("nothing left to retry, no timer", firc_app_retry_timer_for_test(l.app, NULL));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: a failed edit continuing the old retry run instead of restarting at 1 s with a warning. */
TEST an_edit_that_fails_starts_a_fresh_run(void) {
    g_now_ms = 100000;
    g_app_mono = test_clock;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    uint64_t mark = journal_mark();
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    g_now_ms += 1000;
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    firc_app_retry_groups(l.app, NULL);
    ASSERT_FALSEm("the retry was refused", fake_rtnl_failure_armed(l.kernel));
    uint64_t delay = 0;
    ASSERT(firc_app_retry_timer_for_test(l.app, &delay));
    ASSERT_EQ_FMTm("fixture: the run got to 2 s", 2000ull, (unsigned long long)delay, "%llu");
    ASSERT_EQ_FMT((size_t)1, journal_count(mark, "trying again"), "%zu");

    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "b.example", NULL, NULL)));
    ASSERT_FALSEm("the edit was refused", fake_rtnl_failure_armed(l.kernel));
    ASSERT(firc_app_retry_timer_for_test(l.app, &delay));
    ASSERT_EQ_FMTm("a fresh run: 1 s", 1000ull, (unsigned long long)delay, "%llu");
    g_now_ms += 1000;
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    firc_app_retry_groups(l.app, NULL);
    ASSERT_FALSE(fake_rtnl_failure_armed(l.kernel));
    ASSERT_EQ_FMTm("and it warns again", (size_t)2, journal_count(mark, "trying again"), "%zu");
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: a rolled-out POST leaving its retry timer armed. */
TEST a_new_group_rolled_out_leaves_no_retry_timer(void) {
    g_now_ms = 100000;
    g_app_mono = test_clock;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT(firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)) != FIRC_OK);
    ASSERT_FALSEm("the refusal fired", fake_rtnl_failure_armed(l.kernel));
    ASSERT_EQ_FMT((size_t)0, firc_app_user_group_count(l.app), "%zu");
    ASSERT_FALSE(firc_app_retry_timer_for_test(l.app, NULL));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: a successful retry leaving the timer armed. */
TEST a_retry_that_holds_ends_the_run(void) {
    g_now_ms = 100000;
    g_app_mono = test_clock;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    uint64_t mark = journal_mark();
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    ASSERT(wait_written_after(&l, 0));
    g_now_ms += 1000;
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    firc_app_retry_groups(l.app, NULL);
    ASSERT_FALSE(fake_rtnl_failure_armed(l.kernel));
    g_now_ms += 2000;
    ASSERTm("the next try holds", firc_app_retry_groups(l.app, NULL));
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    ASSERT_FALSEm("the run is over, no timer", firc_app_retry_timer_for_test(l.app, NULL));

    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "b.example", NULL, NULL)));
    uint64_t delay = 0;
    ASSERT(firc_app_retry_timer_for_test(l.app, &delay));
    ASSERT_EQ_FMT(1000ull, (unsigned long long)delay, "%llu");
    g_now_ms += 1000;
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    firc_app_retry_groups(l.app, NULL);
    ASSERT_EQ_FMTm("one warning per run", (size_t)2, journal_count(mark, "trying again"), "%zu");
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: a pass report that does not retry the failed groups that are due. */
TEST a_group_that_failed_comes_up_by_itself_after_a_pass(void) {
    g_now_ms = 100000;
    g_app_mono = test_clock;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    ASSERT_FALSEm("the refusal fired", fake_rtnl_failure_armed(l.kernel));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 1));

    g_now_ms += 1000;
    firc_app_pool_changed(l.app);
    ASSERT(run_loop_for(loop, 800));
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    ASSERT(view_owner(&l, "a.example") != NULL);
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: groups reading not-written between a Save and its pass, or an owed pass read as a failure. */
TEST a_save_before_its_pass_still_reads_live(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    static const char *names[] = {"one.example", "two.example"};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    for (uint8_t t = 1; t <= 2; t++) {
        ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(t, names[t - 1], NULL, NULL)));
    }
    ASSERT(wait_written_after(&l, started));

    firc_group_t **arr = calloc(2, sizeof(*arr));
    ASSERT(arr != NULL);
    for (uint8_t t = 1; t <= 2; t++) { arr[t - 1] = activation_group(t, names[t - 1], NULL, NULL); }
    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    uint64_t done = firc_app_nf_last_completed_pass_for_test(l.app);
    firc_err_t err = firc_app_replace_groups(l.app, arr, 2);
    const char *r1 = live_reason(&l, 1);
    const char *r2 = live_reason(&l, 2);
    firc_nfcommit_health_t h;
    firc_app_netfilter_health(l.app, &h);
    bool unwritten = firc_app_nf_last_completed_pass_for_test(l.app) == done;
    firc_app_nf_leave(l.app);

    ASSERT_EQ(FIRC_OK, err);
    ASSERTm("no pass landed while the lock was held", unwritten);
    ASSERT_STR_EQ("live", r1);
    ASSERT_STR_EQ("live", r2);
    ASSERT_FALSE(h.failing);
    ASSERTm("the pass the Save owed then completes", wait_written_after(&l, started));
    locked_app_down(&l);
    PASS();
}

/* Issues `name` an address from group `tag`'s chunk with a real address behind it, and tells the app. */
static bool issue(locked_app_t *l, const char *name, uint8_t tag, firc_ip_t *fake) {
    char gid[FIRC_ID_STR_LEN];
    firc_id_format((firc_id_t){{tag, tag, tag, tag}}, gid);
    const firc_ip_t real = {{93, 184, 216, 34}, 4};
    firc_app_nf_enter(l->app);
    bool ok = firc_fakeip_get(l->pool, name, gid, (int64_t)time(NULL), fake, NULL) == FIRC_OK &&
              firc_fakeip_set_reals(l->pool, name, &real, 1) == FIRC_OK;
    if (ok) { firc_app_pool_changed(l->app); }
    firc_app_nf_leave(l->app);
    return ok;
}

/* Whether the DNAT chain rewrites `fake` */
static bool dnat_has(locked_app_t *l, const firc_ip_t *fake) {
    char want[32];
    snprintf(want, sizeof(want), "-d %u.%u.%u.%u/32", fake->b[0], fake->b[1], fake->b[2], fake->b[3]);
    firc_app_nf_enter(l->app);
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    bool found = false;
    if (firc_fake_ipt_get_rules(l->fake, "nat", "FIRC_DNAT", &rules, &n)) {
        for (size_t i = 0; i < n && !found; i++) {
            char *text = firc_ipt_rule_string(rules[i]);
            found = text != NULL && strstr(text, want) != NULL;
            free(text);
        }
    }
    firc_app_nf_leave(l->app);
    return found;
}

/* firc_app_answer_ready for an A answer to a.example, as the proxy asks before releasing it. */
static bool answer_ready_for_a(locked_app_t *l) {
    static const uint8_t name[] = {1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0};
    firc_dns_msg_t m = {0};
    firc_dns_question_t q = {0};
    memcpy(q.name, name, sizeof(name));
    q.name_len = sizeof(name);
    q.qtype = FIRC_DNS_TYPE_A;
    m.questions = &q;
    m.n_questions = 1;
    firc_dns_rr_t rr = {0};
    memcpy(rr.name, name, sizeof(name));
    rr.name_len = sizeof(name);
    rr.rtype = FIRC_DNS_TYPE_A;
    m.answers = &rr;
    m.n_answers = 1;
    firc_app_nf_enter(l->app);
    bool ready = firc_app_answer_ready(l->app, &m);
    firc_app_nf_leave(l->app);
    return ready;
}

/* Catches: a turned-off group keeping its DNAT rule or chain, or a pass dropping another group's rule. */
TEST a_group_turned_off_keeps_its_mapping_and_loses_its_dnat_rule(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "b.example", NULL, NULL)));
    firc_ip_t f1 = {{0}, 0}, f2 = {{0}, 0};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &f1) && issue(&l, "b.example", 2, &f2));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("fixture: both are rewritten", dnat_has(&l, &f1) && dnat_has(&l, &f2));

    firc_group_t *off = activation_group(1, "a.example", NULL, NULL);
    off->enable = false;
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, (firc_id_t){{1, 1, 1, 1}}, off));
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSEm("the group that is off has no DNAT rule", dnat_has(&l, &f1));
    ASSERTm("the routed one keeps its own", dnat_has(&l, &f2));
    ASSERTm("and the group that is off lost its chain", group_fully_out(&l, (firc_id_t){{1, 1, 1, 1}}));
    firc_ip_t again = {{0}, 0};
    firc_app_nf_enter(l.app);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(l.pool, "a.example", "01010101", (int64_t)time(NULL), &again, NULL));
    firc_app_nf_leave(l.app);
    ASSERT_MEM_EQm("the mapping is still the group's", f1.b, again.b, 4);
    locked_app_down(&l);
    PASS();
}

/* Catches: a group without a usable interface leaving the DNS view, or keeping DNAT (a WAN leak). */
TEST a_group_with_no_usable_interface_fails_closed(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_group_t *g = activation_group(1, "a.example", NULL, NULL);
    free(g->iface);
    g->iface = strdup("");
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "b.example", NULL, NULL)));
    ASSERTm("in the view: its names get fake addresses", view_owner(&l, "a.example") != NULL);
    ASSERT_STR_EQ("no-interface", live_reason(&l, 1));

    firc_ip_t f1 = {{0}, 0}, f2 = {{0}, 0};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &f1) && issue(&l, "b.example", 2, &f2));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("the pass wrote DNAT rules", dnat_has(&l, &f2));
    ASSERT_FALSEm("but none for the group that routes nowhere", dnat_has(&l, &f1));
    locked_app_down(&l);
    PASS();
}

/* Catches: a group turned back on answering before its DNAT rules exist, or a rename being held. */
TEST a_group_turned_back_on_holds_its_cached_names_until_the_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    firc_ip_t f1 = {{0}, 0};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &f1));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("fixture: committed", answer_ready_for_a(&l));

    firc_app_nf_enter(l.app);
    firc_group_t *renamed = activation_group(1, "a.example", NULL, NULL);
    free(renamed->name);
    renamed->name = strdup("renamed");
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, renamed));
    bool rename_held = !answer_ready_for_a(&l);
    firc_app_nf_leave(l.app);
    ASSERT_FALSEm("a group that stays routed is not held", rename_held);

    firc_group_t *off = activation_group(1, "a.example", NULL, NULL);
    off->enable = false;
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, off));
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSEm("off: no DNAT rule", dnat_has(&l, &f1));

    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "a.example", NULL, NULL)));
    bool held = !answer_ready_for_a(&l);
    bool waits = firc_fakeip_needs_commit(l.pool, "a.example", FIRC_FAM_V4);
    firc_app_nf_leave(l.app);
    ASSERTm("turned back on: the answer is held", held && waits);
    ASSERT(wait_written_after(&l, started));
    ASSERTm("released by the pass that wrote the rule", answer_ready_for_a(&l));
    ASSERT(dnat_has(&l, &f1));
    locked_app_down(&l);
    PASS();
}

/* Catches: a fixed interface answering cached names before the pass writes their DNAT rules. */
TEST a_group_given_a_usable_interface_holds_its_cached_names_until_the_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    firc_group_t *g = activation_group(1, "a.example", NULL, NULL);
    free(g->iface);
    g->iface = strdup("");
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));
    firc_ip_t f1 = {{0}, 0};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &f1));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("fixture: the pool believes it committed", answer_ready_for_a(&l));
    ASSERT_FALSEm("fixture: no DNAT rule while not routed", dnat_has(&l, &f1));

    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "a.example", NULL, NULL)));
    bool held = !answer_ready_for_a(&l);
    firc_app_nf_leave(l.app);
    ASSERTm("routed now: held", held);
    ASSERT(wait_written_after(&l, started));
    ASSERT(answer_ready_for_a(&l));
    ASSERT(dnat_has(&l, &f1));
    locked_app_down(&l);
    PASS();
}

/* Catches: a Save holding every cached name, or not holding those of a group it turns back on. */
TEST a_save_holds_only_the_groups_it_makes_routed(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "b.example", NULL, NULL)));
    firc_ip_t f1 = {{0}, 0}, f2 = {{0}, 0};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &f1) && issue(&l, "b.example", 2, &f2));
    ASSERT(wait_written_after(&l, started));
    firc_group_t *off = activation_group(2, "b.example", NULL, NULL);
    off->enable = false;
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, (firc_id_t){{2, 2, 2, 2}}, off));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("fixture: a.example committed", answer_ready_for_a(&l));
    ASSERT_FALSEm("fixture: group 2 is off and unrewritten", dnat_has(&l, &f2));

    firc_group_t **save = calloc(2, sizeof(*save));
    ASSERT(save != NULL);
    save[0] = activation_group(1, "a.example", NULL, NULL);
    save[1] = activation_group(2, "b.example", NULL, NULL);
    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, save, 2));
    bool a_waits = firc_fakeip_needs_commit(l.pool, "a.example", FIRC_FAM_V4);
    bool b_waits = firc_fakeip_needs_commit(l.pool, "b.example", FIRC_FAM_V4);
    firc_app_nf_leave(l.app);
    ASSERT_FALSEm("the group routed throughout is not held", a_waits);
    ASSERTm("the group the Save turned on is held", b_waits);
    ASSERT(wait_written_after(&l, started));
    firc_app_nf_enter(l.app);
    b_waits = firc_fakeip_needs_commit(l.pool, "b.example", FIRC_FAM_V4);
    firc_app_nf_leave(l.app);
    ASSERT_FALSEm("released by the pass that wrote its rule", b_waits);
    ASSERT(dnat_has(&l, &f2));
    locked_app_down(&l);
    PASS();
}

static const uint8_t k_flow_src[4] = {192, 168, 1, 10}, k_flow_dst[4] = {198, 18, 0, 5};

/* The first pass is full and sweeps pool flows, so a test waits it out before planting one. */
static bool first_pass_done(const locked_app_t *l) { return wait_written_after(l, 0); }

static uint32_t field_of(locked_app_t *l, uint8_t tag) {
    return firc_ruleset_mark_field(firc_app_find_group_by_id(l->app, (firc_id_t){{tag, tag, tag, tag}}));
}

/* Catches: a removed group's flows flushed at the teardown, where the old chain remarks them, or never. */
TEST a_removed_groups_flows_go_after_the_pass_that_carries_it(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "b.example", NULL, NULL)));
    const uint8_t one[4] = {198, 18, 0, 5};
    const uint8_t two[4] = {93, 184, 216, 34};
    ASSERT(first_pass_done(&l));
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, one, field_of(&l, 1) | FIRC_MARK_HANDLED);
    fake_ct_add(l.ctk, AF_INET, k_flow_src, two, two, field_of(&l, 2) | FIRC_MARK_HANDLED);

    firc_app_nf_enter(l.app);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}}));
    size_t early = fake_ct_deletes(l.ctk);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("nothing is flushed before the pass", (size_t)0, early, "%zu");
    ASSERT(wait_written_after(&l, started));
    ASSERTm("an incremental pass pays it", fake_ct_deleted(l.ctk, one, 4));

    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, (firc_id_t){{2, 2, 2, 2}}));
    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(l.app));
    firc_app_nf_leave(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERTm("so does a full one", fake_ct_deleted(l.ctk, two, 4));
    locked_app_down(&l);
    PASS();
}

/* Catches: a flush paid by an older pass's report, or never paid because tickets compare backwards. */
TEST a_report_with_an_older_ticket_does_not_pay(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    const uint8_t one[4] = {198, 18, 0, 5};
    ASSERT(first_pass_done(&l));
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, one, field_of(&l, 1) | FIRC_MARK_HANDLED);

    firc_app_nf_enter(l.app);
    uint64_t before = firc_app_nf_change_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}}));
    firc_app_pay_flushes_for_test(l.app, before);
    bool early = fake_ct_deleted(l.ctk, one, 4);
    firc_app_pay_flushes_for_test(l.app, firc_app_nf_change_for_test(l.app));
    bool paid = fake_ct_deleted(l.ctk, one, 4);
    firc_app_nf_leave(l.app);
    ASSERT_FALSEm("a report from before the delete does not pay it", early);
    ASSERTm("the one that carries it does", paid);
    locked_app_down(&l);
    PASS();
}

/* Catches: a queued flush resetting a group put back under the same id and interface before it ran. */
TEST an_owner_added_back_before_the_payment_is_not_flushed(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    uint32_t field = field_of(&l, 1);
    const uint8_t one[4] = {198, 18, 0, 5};
    ASSERT(first_pass_done(&l));
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, one, field | FIRC_MARK_HANDLED);

    firc_app_nf_enter(l.app);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}}));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    firc_app_nf_leave(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERT_EQ_FMTm("the same field", field, field_of(&l, 1), "0x%x");
    ASSERT_EQ_FMTm("nothing was flushed", (size_t)0, fake_ct_deletes(l.ctk), "%zu");
    locked_app_down(&l);
    PASS();
}

/* Catches: a deleted group's mark field reused before its flush has run, or never freed after it. */
TEST a_removed_groups_field_is_held_until_its_flush(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    uint32_t field = field_of(&l, 1);
    ASSERT(field != 0);

    firc_app_nf_enter(l.app);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}}));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "b.example", NULL, NULL)));
    uint32_t second = field_of(&l, 2);
    firc_app_nf_leave(l.app);
    ASSERTm("held while its flush is queued", second != 0 && second != field);
    ASSERT(wait_written_after(&l, started));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(3, "c.example", NULL, NULL)));
    ASSERT_EQ_FMTm("and free once it ran", field, field_of(&l, 3), "0x%x");
    locked_app_down(&l);
    PASS();
}

/* Catches: an interface change keeping the old interface's flows because the group is routed again. */
TEST an_interface_change_is_paid_although_the_owner_is_routed_again(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    const uint8_t one[4] = {198, 18, 0, 5};
    ASSERT(first_pass_done(&l));
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, one, field_of(&l, 1) | FIRC_MARK_HANDLED);
    firc_group_t *moved = activation_group(1, "a.example", NULL, NULL);
    free(moved->iface);
    moved->iface = strdup("eth0");
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, (firc_id_t){{1, 1, 1, 1}}, moved));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("routed again, through eth0", group_routed(&l, 1));
    ASSERTm("its old flows went", fake_ct_deleted(l.ctk, one, 4));
    locked_app_down(&l);
    PASS();
}

/* Catches: an interface edit undone before the pass flushing flows, or queueing a second entry. */
TEST an_interface_change_undone_before_the_pass_flushes_nothing(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    const uint8_t one[4] = {198, 18, 0, 5};
    ASSERT(first_pass_done(&l));
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, one, field_of(&l, 1) | FIRC_MARK_HANDLED);

    firc_app_nf_enter(l.app);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_group_t *moved = activation_group(1, "a.example", NULL, NULL);
    free(moved->iface);
    moved->iface = strdup("eth0");
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, moved));
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "a.example", NULL, NULL)));
    firc_app_nf_leave(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(l.ctk), "%zu");
    locked_app_down(&l);
    PASS();
}

/* Catches: deleting an unrouted group queueing a flush or holding back its mark field. */
TEST deleting_a_group_that_never_came_up_holds_nothing(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    uint32_t field = field_of(&l, 1);

    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "a.example", NULL, NULL)));
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 1));
    ASSERT(wait_written_after(&l, started));

    firc_app_nf_enter(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(2, "b.example", NULL, NULL)));
    uint32_t next = field_of(&l, 2);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("its field was free at once", field, next, "0x%x");
    locked_app_down(&l);
    PASS();
}

/* Catches: a rule edit or rename resetting every flow of a group that came back on the same field. */
TEST a_rule_edit_that_comes_back_keeps_its_flows_after_the_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    uint32_t field = field_of(&l, 1);
    const uint8_t one[4] = {198, 18, 0, 5};
    ASSERT(first_pass_done(&l));
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, one, field | FIRC_MARK_HANDLED);

    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "b.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    ASSERT_EQ_FMTm("on the same field", field, field_of(&l, 1), "0x%x");
    ASSERT_EQ_FMTm("nothing was flushed", (size_t)0, fake_ct_deletes(l.ctk), "%zu");
    locked_app_down(&l);
    PASS();
}

/* Catches: a rule edit whose re-enable fails keeping its flows, or flushing them before the pass. */
TEST a_rule_edit_whose_re_enable_fails_flushes_its_flows_after_the_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    const uint8_t one[4] = {198, 18, 0, 5};
    ASSERT(first_pass_done(&l));
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, one, field_of(&l, 1) | FIRC_MARK_HANDLED);

    firc_app_nf_enter(l.app);
    fake_rtnl_fail_next_of(l.kernel, RTM_NEWRULE, EPERM);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "b.example", NULL, NULL)));
    bool refused = !fake_rtnl_failure_armed(l.kernel);
    size_t early = fake_ct_deletes(l.ctk);
    firc_app_nf_leave(l.app);
    ASSERTm("the re-enable met the refusal", refused);
    ASSERT_STR_EQ("not-enabled", live_reason(&l, 1));
    ASSERT_EQ_FMTm("nothing is flushed before the pass", (size_t)0, early, "%zu");
    ASSERT(wait_written_after(&l, started));
    ASSERTm("its flows went after it", fake_ct_deleted(l.ctk, one, 4));
    locked_app_down(&l);
    PASS();
}

/* Catches: a daemon stop dropping the flushes still queued. */
TEST stopping_pays_the_flushes_still_queued(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    const uint8_t one[4] = {198, 18, 0, 5};
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, one, field_of(&l, 1) | FIRC_MARK_HANDLED);

    char chain[64], del[80];
    chain_of(&l, gid, chain, sizeof(chain));
    snprintf(del, sizeof(del), "-X %s", chain);
    firc_fake_ipt_refuse_rules_containing(l.fake, del);
    size_t calls = firc_fake_ipt_restore_calls(l.fake);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    ASSERTm("a pass tried and was refused", a_restore_was_tried(&l, calls));
    ASSERT_FALSEm("so nothing was paid", fake_ct_deleted(l.ctk, one, 4));

    firc_app_destroy(l.app);
    l.app = NULL;
    ASSERTm("the stop paid it", fake_ct_deleted(l.ctk, one, 4));
    locked_app_down(&l);
    PASS();
}

/* Catches: flushes not paid by the report on the loop, or paid on the committer thread instead. */
TEST a_report_on_the_loop_pays_the_flushes_it_carried(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    locked_app_t l;
    ASSERT(locked_app_up_with_loop(&l, loop));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    const uint8_t real[4] = {93, 184, 216, 34};
    fake_ct_add(l.ctk, AF_INET, k_flow_src, real, real, field_of(&l, 1) | FIRC_MARK_HANDLED);

    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, (firc_id_t){{1, 1, 1, 1}}));
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSEm("the pass itself pays nothing", fake_ct_deleted(l.ctk, real, 4));
    ASSERT(run_loop_for(loop, 300));
    ASSERTm("its report, run on the loop, does", fake_ct_deleted(l.ctk, real, 4));
    locked_app_down(&l);
    firc_loop_destroy(loop);
    PASS();
}

static uint32_t g_stub_mark;
static bool stub_mark(const char *policy, uint32_t *mark, void *ud) {
    (void)ud;
    if (strcmp(policy, "Kids") == 0 && g_stub_mark != 0) { *mark = g_stub_mark; return true; }
    if (strcmp(policy, "Guests") == 0) { *mark = 0x0ffffaadu; return true; }
    return false;
}
static firc_err_t stub_hosts(const firc_ip_t *net, uint8_t prefix, bool deny, firc_devsel_addr_fn cb, void *cb_ud,
                             void *ud) {
    (void)net; (void)prefix; (void)deny; (void)cb; (void)cb_ud; (void)ud;
    return FIRC_OK;
}
static bool g_kids_host;
static firc_err_t stub_policy_hosts(const char *policy, bool deny, firc_devsel_addr_fn cb, void *cb_ud, void *ud) {
    (void)ud;
    (void)deny;
    firc_ip_t h = {{192, 168, 1, 40}, 4};
    if (strcmp(policy, "Kids") == 0 && g_kids_host) { cb(&h, cb_ud); }
    return FIRC_OK;
}

static firc_group_t *selector_group(uint8_t tag, char **allow, size_t na, char **deny, size_t nd) {
    firc_group_t *g = activation_group(tag, "a.example", NULL, NULL);
    firc_devsel_spec_t s = {.allow = allow, .n_allow = na, .deny = deny, .n_deny = nd};
    if (firc_devsel_spec_copy(&g->devices, &s) != FIRC_OK) { abort(); }
    return g;
}

static void devices_chain_of(const locked_app_t *l, firc_id_t gid, char *out, size_t cap) {
    firc_ruleset_devices_chain_name_for(l->cfg.app.netfilter.iptables.chain_prefix, gid, out, cap);
}

/* Whether the mangle chain has a rule containing `needle`, read under the netfilter lock. */
static bool mangle_has(locked_app_t *l, const char *chain, const char *needle) {
    firc_app_nf_enter(l->app);
    bool has = chain_has_text_in(l->fake, "mangle", chain, needle);
    firc_app_nf_leave(l->app);
    return has;
}

static bool mangle_chain_there(locked_app_t *l, const char *chain) {
    firc_app_nf_enter(l->app);
    bool there = firc_fake_ipt_chain_exists(l->fake, "mangle", chain);
    firc_app_nf_leave(l->app);
    return there;
}

/* Catches: the app not handing the rulesets its lookup, or the enable not rendering the devices chain. */
TEST a_selector_group_s_chunk_jumps_to_its_devices_chain(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0x0ffffaabu;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char kids[] = "policy:Kids";
    char *allow[] = {kids};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    firc_ip_t fake;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &fake));
    ASSERT(wait_written_after(&l, started));
    char chain[64], dchain[64], jump[80];
    chain_of(&l, gid, chain, sizeof(chain));
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    snprintf(jump, sizeof(jump), "-j %s", dchain);
    ASSERTm("the chunk jumps", mangle_has(&l, chain, jump));
    ASSERTm("the policy's mark, masked", mangle_has(&l, dchain, "-m mark --mark 0xf00faab/0xbf00ffff -j MARK"));
    g_stub_mark = 0;
    locked_app_down(&l);
    PASS();
}

/* Catches: the enable leaving a selector group's subnet rule in its MARK form, or the committer path writing the pair. */
TEST a_subnet_rule_of_a_selector_group_jumps_to_its_devices_chain(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char dev[] = "10.0.0.1";
    char *allow[] = {dev};
    firc_group_t *g = selector_group(1, allow, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_group_add_rule(g, edit_rule(FIRC_RULE_SUBNET, "10.0.0.0/8")));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));
    ASSERT(first_pass_done(&l));
    char chain[64], dchain[64], jump[160];
    chain_of(&l, gid, chain, sizeof(chain));
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    snprintf(jump, sizeof(jump), "-d 10.0.0.0/8 -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -j %s",
             dchain);
    ASSERT(mangle_has(&l, chain, jump));
    ASSERT_FALSE(mangle_has(&l, chain,
                            "-d 10.0.0.0/8 -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -j MARK"));
    locked_app_down(&l);
    PASS();
}

/* Catches: a selector emptied still jumping its subnet rule to the devices chain the same pass deletes. */
TEST a_selector_emptied_returns_its_subnet_rule_to_a_mark(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char dev[] = "10.0.0.1";
    char *allow[] = {dev};
    firc_group_t *g = selector_group(1, allow, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_group_add_rule(g, edit_rule(FIRC_RULE_SUBNET, "10.0.0.0/8")));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, g));
    ASSERT(first_pass_done(&l));
    char chain[64], dchain[64];
    chain_of(&l, gid, chain, sizeof(chain));
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERTm("fixture: the devices chain is there", mangle_chain_there(&l, dchain));

    firc_group_t *emptied = selector_group(1, NULL, 0, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_group_add_rule(emptied, edit_rule(FIRC_RULE_SUBNET, "10.0.0.0/8")));
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, emptied));
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSE(mangle_chain_there(&l, dchain));
    ASSERT(mangle_has(&l, chain,
                      "-d 10.0.0.0/8 -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -j MARK "
                      "--set-xmark"));
    ASSERT(mangle_has(&l, chain,
                      "-d 10.0.0.0/8 -m conntrack --ctdir ORIGINAL -j CONNMARK --save-mark --nfmask 0x40ff0000 "
                      "--ctmask 0x40ff0000"));
    ASSERT_FALSE(mangle_has(&l, chain, dchain));
    locked_app_down(&l);
    PASS();
}

/* Binds the policy "Guests" to the segment 10.99.0.0/24. */
static firc_err_t stub_policy_nets(const char *policy, bool deny, firc_devsel_net_fn cb, void *cb_ud, void *ud) {
    (void)ud;
    (void)deny;
    firc_ip_t net = {{10, 99, 0, 0}, 4};
    if (strcmp(policy, "Guests") == 0) { cb(&net, 24, cb_ud); }
    return FIRC_OK;
}

/* Catches: a deny policy's segment missing from the devices chain, which then carries the mark alone. */
TEST a_policy_s_segment_reaches_the_devices_chain(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, stub_policy_nets, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char guests[] = "policy:Guests";
    char *deny[] = {guests};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, NULL, 0, deny, 1)));
    ASSERT(first_pass_done(&l));
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERTm("the mark", mangle_has(&l, dchain, "-m mark --mark 0xf00faad/0xbf00ffff -j RETURN"));
    ASSERTm("the segment", mangle_has(&l, dchain, "-s 10.99.0.0/24 -j RETURN"));
    locked_app_down(&l);
    PASS();
}

/* Catches: a moved policy mark not re-rendered or not written, or its lost allow source not flushed. */
TEST a_changed_policy_mark_is_rewritten_by_the_next_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0x0ffffaabu;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char kids[] = "policy:Kids";
    char *allow[] = {kids};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    ASSERT(first_pass_done(&l));
    const uint8_t real[4] = {93, 184, 216, 34};
    fake_ct_add(l.ctk, AF_INET, k_flow_src, k_flow_dst, real, field_of(&l, 1) | FIRC_MARK_HANDLED);
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERT(mangle_has(&l, dchain, "0xf00faab/0xbf00ffff"));

    g_stub_mark = 0x0ffffaadu;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_devices_changed(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERTm("the new mark", mangle_has(&l, dchain, "0xf00faad/0xbf00ffff"));
    ASSERT_FALSEm("and not the old", mangle_has(&l, dchain, "0xf00faab/0xbf00ffff"));
    ASSERTm("the chunk flow was reset", fake_ct_deleted(l.ctk, real, 4));
    ASSERT_EQ_FMT((size_t)0, fake_ct_remaining(l.ctk), "%zu");
    g_stub_mark = 0;
    locked_app_down(&l);
    PASS();
}

/* Catches: an unchanged render asking for a pass or the lock, or a moved chain asking for 0 or 2. */
TEST a_table_change_that_renders_the_same_asks_for_no_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0x0ffffaabu;
    g_kids_host = false;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    char kids[] = "policy:Kids", mac[] = "mac:aa:bb:cc:dd:ee:ff";
    char *by_policy[] = {kids}, *by_mac[] = {mac};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, by_policy, 1, NULL, 0)));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(2, by_mac, 1, NULL, 0)));
    ASSERT(first_pass_done(&l));

    firc_app_nf_enter(l.app);
    uint64_t before = firc_app_nf_change_for_test(l.app);
    firc_app_nf_leave(l.app);
    uint64_t enters = firc_app_nf_enters_for_test(l.app);
    firc_app_devices_changed(l.app);
    uint64_t enters_same = firc_app_nf_enters_for_test(l.app);
    firc_app_nf_enter(l.app);
    uint64_t same = firc_app_nf_change_for_test(l.app);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("nothing moved, nothing asked", (unsigned long long)before, (unsigned long long)same, "%llu");
    ASSERT_EQ_FMTm("nothing moved, no pass interrupted", (unsigned long long)enters,
                   (unsigned long long)enters_same, "%llu");

    g_kids_host = true;
    enters = firc_app_nf_enters_for_test(l.app);
    firc_app_devices_changed(l.app);
    ASSERT_EQ_FMTm("a moved chain takes the lock once", (unsigned long long)(enters + 1),
                   (unsigned long long)firc_app_nf_enters_for_test(l.app), "%llu");
    firc_app_nf_enter(l.app);
    uint64_t moved = firc_app_nf_change_for_test(l.app);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("one chain moved, one pass asked", (unsigned long long)(before + 1), (unsigned long long)moved,
                   "%llu");
    g_stub_mark = 0;
    g_kids_host = false;
    locked_app_down(&l);
    PASS();
}

/* Catches: an emptied selector's devices chain written back by every pass, or still jumped to. */
TEST a_selector_emptied_loses_its_devices_chain(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char mac[] = "mac:aa:bb:cc:dd:ee:ff";
    char *allow[] = {mac};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    firc_ip_t fake;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &fake));
    ASSERT(wait_written_after(&l, started));
    char chain[64], dchain[64];
    chain_of(&l, gid, chain, sizeof(chain));
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERTm("fixture: the devices chain is there", mangle_chain_there(&l, dchain));

    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, activation_group(1, "a.example", NULL, NULL)));
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSEm("the devices chain went", mangle_chain_there(&l, dchain));
    ASSERTm("and the chunk marks again", mangle_has(&l, chain, "-j MARK --set-xmark"));
    locked_app_down(&l);
    PASS();
}

/* Catches: a deleted selector group's devices chain written back by its stale registration. */
TEST a_deleted_selector_group_leaves_no_devices_chain(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char mac[] = "mac:aa:bb:cc:dd:ee:ff";
    char *allow[] = {mac};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    firc_ip_t fake;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &fake));
    ASSERT(wait_written_after(&l, started));
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERT(mangle_chain_there(&l, dchain));

    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    firc_app_nf_leave(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_out(&l, gid));
    ASSERT_FALSE(mangle_chain_there(&l, dchain));
    locked_app_down(&l);
    PASS();
}

/* Catches: the no-committer path rendering without the link's devices copy. */
TEST without_a_committer_the_devices_chain_is_written_at_once(void) {
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char mac[] = "mac:aa:bb:cc:dd:ee:ff";
    char *allow[] = {mac};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERT(firc_fake_ipt_chain_exists(l.fake, "mangle", dchain));
    ASSERT(mangle_has(&l, dchain, "--mac-source AA:BB:CC:DD:EE:FF"));
    locked_app_down(&l);
    PASS();
}

static const uint8_t k_chunk_reply[4] = {93, 184, 216, 34};
static const uint8_t k_subnet_dst[4] = {10, 1, 2, 3};

static const uint8_t k_other_field_reply[4] = {10, 1, 2, 4};
static const uint8_t k_unhandled_reply[4] = {10, 1, 2, 5};

static void plant_group_flows(locked_app_t *l, uint8_t tag) {
    uint32_t mark = field_of(l, tag) | FIRC_MARK_HANDLED;
    fake_ct_add(l->ctk, AF_INET, k_flow_src, k_flow_dst, k_chunk_reply, mark);
    fake_ct_add(l->ctk, AF_INET, k_flow_src, k_subnet_dst, k_subnet_dst, mark);
    fake_ct_add(l->ctk, AF_INET, k_flow_src, k_other_field_reply, k_other_field_reply,
                firc_mark_group_value(200) | FIRC_MARK_HANDLED);
    fake_ct_add(l->ctk, AF_INET, k_flow_src, k_unhandled_reply, k_unhandled_reply, field_of(l, tag));
}

static bool strangers_kept(locked_app_t *l) {
    return !fake_ct_deleted(l->ctk, k_other_field_reply, 4) && !fake_ct_deleted(l->ctk, k_unhandled_reply, 4);
}

static char k_dev_a[] = "10.0.0.1", k_dev_b[] = "10.0.0.2";

/* Catches: a narrowing that flushes nothing, only the chunk flows, another field or an unhandled flow, or before the pass. */
TEST a_narrowed_selector_resets_its_flows_after_the_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char *two[] = {k_dev_a, k_dev_b}, *one[] = {k_dev_a};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, two, 2, NULL, 0)));
    ASSERT(first_pass_done(&l));
    plant_group_flows(&l, 1);

    firc_app_nf_enter(l.app);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, selector_group(1, one, 1, NULL, 0)));
    size_t early = fake_ct_deletes(l.ctk);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("nothing before the pass", (size_t)0, early, "%zu");
    ASSERT(wait_written_after(&l, started));
    ASSERTm("the chunk flow went", fake_ct_deleted(l.ctk, k_chunk_reply, 4));
    ASSERTm("the subnet flow went", fake_ct_deleted(l.ctk, k_subnet_dst, 4));
    ASSERT_EQ_FMT((size_t)2, fake_ct_deletes(l.ctk), "%zu");
    ASSERTm("another field's flow and an unhandled one stayed", strangers_kept(&l));
    ASSERT_STR_EQ("live", live_reason(&l, 1));
    locked_app_down(&l);
    PASS();
}

/* Catches: a later edit's merge clearing a narrowing still queued for the same group, or the flush taking only the chunk flows. */
TEST a_later_edit_before_the_pass_keeps_a_narrowing_queued(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char *two[] = {k_dev_a, k_dev_b}, *one[] = {k_dev_a};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, two, 2, NULL, 0)));
    ASSERT(first_pass_done(&l));
    plant_group_flows(&l, 1);
    firc_group_t *renamed = selector_group(1, one, 1, NULL, 0);
    free(renamed->name);
    renamed->name = strdup("renamed");

    firc_app_nf_enter(l.app);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, selector_group(1, one, 1, NULL, 0)));
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, renamed));
    size_t early = fake_ct_deletes(l.ctk);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("nothing before the pass", (size_t)0, early, "%zu");
    ASSERT(wait_written_after(&l, started));
    ASSERTm("the chunk flow went", fake_ct_deleted(l.ctk, k_chunk_reply, 4));
    ASSERTm("the subnet flow went", fake_ct_deleted(l.ctk, k_subnet_dst, 4));
    ASSERT_EQ_FMT((size_t)2, fake_ct_deletes(l.ctk), "%zu");
    ASSERTm("another field's flow and an unhandled one stayed", strangers_kept(&l));
    locked_app_down(&l);
    PASS();
}

/* Catches: a widening selector edit taken for a narrowing, flushing its flows. */
TEST a_widened_selector_resets_nothing(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char *one[] = {k_dev_a}, *two[] = {k_dev_a, k_dev_b};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, one, 1, NULL, 0)));
    ASSERT(first_pass_done(&l));
    plant_group_flows(&l, 1);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, selector_group(1, two, 2, NULL, 0)));
    ASSERT(wait_written_after(&l, started));
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(l.ctk), "%zu");
    ASSERT_EQ_FMT((size_t)4, fake_ct_remaining(l.ctk), "%zu");
    locked_app_down(&l);
    PASS();
}

/* Catches: a Save not comparing the old selector with the new, so its narrowing flushes nothing or only the chunk flows. */
TEST a_save_that_narrows_a_selector_resets_its_flows(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    char *two[] = {k_dev_a, k_dev_b}, *one[] = {k_dev_a};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, two, 2, NULL, 0)));
    ASSERT(first_pass_done(&l));
    plant_group_flows(&l, 1);
    firc_group_t **arr = calloc(1, sizeof(*arr));
    ASSERT(arr != NULL);
    arr[0] = selector_group(1, one, 1, NULL, 0);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, arr, 1));
    ASSERT(wait_written_after(&l, started));
    ASSERT(fake_ct_deleted(l.ctk, k_chunk_reply, 4));
    ASSERT(fake_ct_deleted(l.ctk, k_subnet_dst, 4));
    ASSERT_EQ_FMT((size_t)2, fake_ct_deletes(l.ctk), "%zu");
    ASSERTm("another field's flow and an unhandled one stayed", strangers_kept(&l));
    locked_app_down(&l);
    PASS();
}

/* Catches: the no-committer path queueing a narrowing flush nothing pays, skipping it, or taking only the chunk flows. */
TEST without_a_committer_a_narrowing_edit_resets_at_once(void) {
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char *two[] = {k_dev_a, k_dev_b}, *one[] = {k_dev_a};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, two, 2, NULL, 0)));
    plant_group_flows(&l, 1);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, selector_group(1, one, 1, NULL, 0)));
    ASSERT(fake_ct_deleted(l.ctk, k_chunk_reply, 4));
    ASSERT(fake_ct_deleted(l.ctk, k_subnet_dst, 4));
    ASSERT_EQ_FMT((size_t)2, fake_ct_deletes(l.ctk), "%zu");
    ASSERTm("another field's flow and an unhandled one stayed", strangers_kept(&l));
    locked_app_down(&l);
    PASS();
}

/* Catches: a narrowing that also moves the interface flushing only chunk flows, not subnet ones. */
TEST a_narrowing_edit_that_moves_the_interface_resets_every_flow(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char *two[] = {k_dev_a, k_dev_b}, *one[] = {k_dev_a};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, two, 2, NULL, 0)));
    ASSERT(first_pass_done(&l));
    plant_group_flows(&l, 1);
    firc_group_t *moved = selector_group(1, one, 1, NULL, 0);
    free(moved->iface);
    moved->iface = strdup("eth0");
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, moved));
    ASSERT(wait_written_after(&l, started));
    ASSERTm("routed through the new name", group_routed(&l, 1));
    ASSERT(fake_ct_deleted(l.ctk, k_chunk_reply, 4));
    ASSERT(fake_ct_deleted(l.ctk, k_subnet_dst, 4));
    ASSERT(strangers_kept(&l));
    locked_app_down(&l);
    PASS();
}

/* Catches: a policy entry not writing its hosts, or a re-render keeping a host that left. */
TEST a_host_that_leaves_a_policy_leaves_the_chain_after_the_next_map(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0x0ffffaabu;
    g_kids_host = true;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char kids[] = "policy:Kids";
    char *allow[] = {kids};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    ASSERT(first_pass_done(&l));
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERTm("the host is in the chain", mangle_has(&l, dchain, "-s 192.168.1.40/32 -j MARK"));

    g_kids_host = false;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_devices_changed(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSEm("and out of it after the next map", mangle_has(&l, dchain, "192.168.1.40"));
    ASSERTm("the mark rule stays", mangle_has(&l, dchain, "0xf00faab/0xbf00ffff"));
    g_stub_mark = 0;
    g_kids_host = false;
    locked_app_down(&l);
    PASS();
}

static bool mangle_rules_are(locked_app_t *l, const char *chain, char want[][128], size_t n_want) {
    firc_app_nf_enter(l->app);
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    bool ok = firc_fake_ipt_get_rules(l->fake, "mangle", chain, &rules, &n) && n == n_want;
    for (size_t i = 0; ok && i < n; i++) {
        char *text = firc_ipt_rule_string(rules[i]);
        ok = text != NULL && strcmp(text, want[i]) == 0;
        free(text);
    }
    firc_app_nf_leave(l->app);
    return ok;
}

/* Catches: a mixed selector's rules reordered or dropped, or the CONNMARK anywhere but last. */
TEST a_mixed_selector_writes_its_rules_in_order(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0x0ffffaabu;
    g_kids_host = true;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char kids[] = "policy:Kids", mac[] = "mac:aa:bb:cc:dd:ee:ff", a1[] = "10.0.0.1";
    char guests[] = "policy:Guests", a9[] = "10.0.0.9";
    char *allow[] = {kids, mac, a1}, *deny[] = {guests, a9};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 3, deny, 2)));
    ASSERT(first_pass_done(&l));
    char m[48];
    snprintf(m, sizeof(m), "0x%x/0x40ff0000", FIRC_MARK_HANDLED | field_of(&l, 1));
    char want[7][128];
    snprintf(want[0], 128, "-m mark --mark 0xf00faad/0xbf00ffff -j RETURN");
    snprintf(want[1], 128, "-s 10.0.0.9/32 -j RETURN");
    snprintf(want[2], 128, "-m mark --mark 0xf00faab/0xbf00ffff -j MARK --set-xmark %s", m);
    snprintf(want[3], 128, "-s 192.168.1.40/32 -j MARK --set-xmark %s", m);
    snprintf(want[4], 128, "-m mac --mac-source AA:BB:CC:DD:EE:FF -j MARK --set-xmark %s", m);
    snprintf(want[5], 128, "-s 10.0.0.1/32 -j MARK --set-xmark %s", m);
    snprintf(want[6], 128, "-m mark --mark %s -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000", m);
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERT(mangle_rules_are(&l, dchain, want, 7));
    g_stub_mark = 0;
    g_kids_host = false;
    locked_app_down(&l);
    PASS();
}

/* Catches: a Save, unlike an update, not tombstoning an emptied selector's devices chain. */
TEST a_save_that_empties_a_selector_loses_its_devices_chain(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char mac[] = "mac:aa:bb:cc:dd:ee:ff";
    char *allow[] = {mac};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    firc_ip_t fake;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT(issue(&l, "a.example", 1, &fake));
    ASSERT(wait_written_after(&l, started));
    char chain[64], dchain[64];
    chain_of(&l, gid, chain, sizeof(chain));
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERT(mangle_chain_there(&l, dchain));
    firc_group_t **arr = calloc(1, sizeof(*arr));
    ASSERT(arr != NULL);
    arr[0] = activation_group(1, "a.example", NULL, NULL);
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(l.app, arr, 1));
    ASSERT(wait_written_after(&l, started));
    ASSERT_FALSE(mangle_chain_there(&l, dchain));
    ASSERT(mangle_has(&l, chain, "-j MARK --set-xmark"));
    locked_app_down(&l);
    PASS();
}

/* Catches: the fake not flushing a declared chain, or a tombstone forgetting the devices chain. */
TEST a_group_given_a_selector_and_then_deleted_leaves_nothing(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, activation_group(1, "a.example", NULL, NULL)));
    firc_ip_t fake;
    ASSERT(issue(&l, "a.example", 1, &fake));
    ASSERT(wait_written_after(&l, started));

    char mac[] = "mac:aa:bb:cc:dd:ee:ff";
    char *allow[] = {mac};
    started = firc_app_nf_passes_for_test(l.app);
    ASSERT_EQ(FIRC_OK, firc_app_update_group(l.app, gid, selector_group(1, allow, 1, NULL, 0)));
    ASSERT(wait_written_after(&l, started));
    char chain[64], dchain[64], jump[80];
    chain_of(&l, gid, chain, sizeof(chain));
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    snprintf(jump, sizeof(jump), "-j %s", dchain);
    ASSERTm("fixture: the chunk jumps to the devices chain", mangle_has(&l, chain, jump));

    firc_app_nf_enter(l.app);
    started = firc_app_nf_passes_for_test(l.app);
    size_t calls = firc_fake_ipt_restore_calls(l.fake);
    ASSERT(firc_app_remove_group_by_id(l.app, gid));
    firc_app_nf_leave(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERT(group_fully_out(&l, gid));
    ASSERT_FALSE(mangle_chain_there(&l, dchain));
    firc_app_nf_enter(l.app);
    size_t after = firc_fake_ipt_restore_calls(l.fake);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("one v4 restore, none refused", calls + 1, after, "%zu");
    firc_nfcommit_health_t h;
    firc_app_netfilter_health(l.app, &h);
    ASSERT_FALSE(h.failing);
    locked_app_down(&l);
    PASS();
}

/* Catches: the startup rendering the devices chain without the lookup the app is handed later. */
TEST a_startup_after_the_lookup_writes_a_deny_policy_on_its_first_pass(void) {
    locked_app_t l;
    ASSERT(locked_app_up_no_committer(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    firc_id_t gid = {{1, 1, 1, 1}};
    char guests[] = "policy:Guests";
    char *deny[] = {guests};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, NULL, 0, deny, 1)));
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    ASSERT_EQ(FIRC_OK, firc_app_start_groups(l.app));
    ASSERT_EQ(FIRC_OK, firc_app_start_netfilter_committer(l.app));
    firc_app_pool_changed(l.app);
    ASSERT(wait_written_after(&l, 0));
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERTm("the deny policy's RETURN", mangle_has(&l, dchain, "-m mark --mark 0xf00faad/0xbf00ffff -j RETURN"));
    locked_app_down(&l);
    PASS();
}

static bool both_flows_reset(locked_app_t *l) {
    return fake_ct_deleted(l->ctk, k_chunk_reply, 4) && fake_ct_deleted(l->ctk, k_subnet_dst, 4) &&
           fake_ct_deletes(l->ctk) == 2 && strangers_kept(l);
}

/* Catches: a host joining a denied policy keeping its chunk flows or its subnet flows. */
TEST a_host_joining_a_denied_policy_resets_its_flows(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0;
    g_kids_host = false;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char kids[] = "policy:Kids";
    char *deny[] = {kids};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, NULL, 0, deny, 1)));
    ASSERT(first_pass_done(&l));
    plant_group_flows(&l, 1);
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERT_FALSEm("fixture: the host is not denied yet", mangle_has(&l, dchain, "192.168.1.40"));

    g_kids_host = true;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_devices_changed(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERTm("the host is denied", mangle_has(&l, dchain, "-s 192.168.1.40/32 -j RETURN"));
    ASSERTm("the chunk flow and the subnet flow reset", both_flows_reset(&l));
    g_kids_host = false;
    locked_app_down(&l);
    PASS();
}

/* Catches: a host joining an allowed policy taken for a narrowing, flushing its flows. */
TEST a_host_joining_an_allowed_policy_resets_nothing(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0x0ffffaabu;
    g_kids_host = false;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char kids[] = "policy:Kids";
    char *allow[] = {kids};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    ASSERT(first_pass_done(&l));
    plant_group_flows(&l, 1);

    g_kids_host = true;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_devices_changed(l.app);
    ASSERT(wait_written_after(&l, started));
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERTm("the pass wrote the host", mangle_has(&l, dchain, "-s 192.168.1.40/32 -j MARK"));
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(l.ctk), "%zu");
    ASSERT_EQ_FMT((size_t)4, fake_ct_remaining(l.ctk), "%zu");
    g_stub_mark = 0;
    g_kids_host = false;
    locked_app_down(&l);
    PASS();
}

static bool g_map_in;
static bool boot_mark(const char *policy, uint32_t *mark, void *ud) {
    (void)ud;
    if (g_map_in && strcmp(policy, "Guests") == 0) { *mark = 0x0ffffaadu; return true; }
    return false;
}

static bool boot_read(void *ud) {
    (void)ud;
    return g_map_in;
}

static bool boot_deny_guests(locked_app_t *l, char *dchain, size_t cap) {
    g_map_in = false;
    if (!locked_app_up_no_committer(l)) { return false; }
    fake_rtnl_set_link_flags(l->kernel, 0x1 | 0x10);
    char guests[] = "policy:Guests";
    char *deny[] = {guests};
    firc_group_t *g = selector_group(1, NULL, 0, deny, 1);
    if (firc_group_add_rule(g, edit_rule(FIRC_RULE_SUBNET, "10.0.0.0/8")) != FIRC_OK ||
        firc_app_add_group(l->app, g) != FIRC_OK) {
        return false;
    }
    firc_app_set_device_lookup(l->app, boot_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_policies_read(l->app, boot_read);
    if (firc_app_start_groups(l->app) != FIRC_OK || firc_app_start_netfilter_committer(l->app) != FIRC_OK) {
        return false;
    }
    firc_app_pool_changed(l->app);
    devices_chain_of(l, (firc_id_t){{1, 1, 1, 1}}, dchain, cap);
    return first_pass_done(l);
}

/* Catches: a deny-policy group marking every device before the first map is read, in its chunk or subnet path. */
TEST before_the_first_map_a_deny_policy_group_marks_nobody(void) {
    locked_app_t l;
    char dchain[64];
    ASSERT(boot_deny_guests(&l, dchain, sizeof(dchain)));
    ASSERTm("the chain is there", mangle_has(&l, dchain, "-j CONNMARK --save-mark"));
    ASSERT_FALSEm("no unconditional MARK before the map", mangle_has(&l, dchain, "-j MARK"));

    g_map_in = true;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_devices_changed(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERTm("the deny's mark", mangle_has(&l, dchain, "-m mark --mark 0xf00faad/0xbf00ffff -j RETURN"));
    ASSERTm("everyone else is marked", mangle_has(&l, dchain, "-j MARK --set-xmark"));
    g_map_in = false;
    locked_app_down(&l);
    PASS();
}

/* Catches: the first map after a start counted as a narrowing, resetting every chunk and subnet flow at each start. */
TEST the_first_map_after_start_resets_no_flows(void) {
    locked_app_t l;
    char dchain[64];
    ASSERT(boot_deny_guests(&l, dchain, sizeof(dchain)));
    plant_group_flows(&l, 1);

    g_map_in = true;
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_devices_changed(l.app);
    ASSERT(wait_written_after(&l, started));
    ASSERTm("fixture: the map reached the chain",
            mangle_has(&l, dchain, "-m mark --mark 0xf00faad/0xbf00ffff -j RETURN"));
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(l.ctk), "%zu");
    ASSERT_EQ_FMT((size_t)4, fake_ct_remaining(l.ctk), "%zu");
    g_map_in = false;
    locked_app_down(&l);
    PASS();
}

/* Whether a sync (`how` 0), update (1) or Save (2) that renders first still counts as a narrowing. */
static bool narrowed_by(unsigned how) {
    locked_app_t l;
    if (!locked_app_up(&l)) { return false; }
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0;
    g_kids_host = false;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char kids[] = "policy:Kids";
    char *deny[] = {kids};
    bool ok = firc_app_add_group(l.app, selector_group(1, NULL, 0, deny, 1)) == FIRC_OK && first_pass_done(&l);
    if (ok) {
        plant_group_flows(&l, 1);
        g_kids_host = true;
        uint64_t started = firc_app_nf_passes_for_test(l.app);
        if (how == 0) {
            ok = firc_app_sync_group(l.app, firc_app_find_group_by_id(l.app, gid)) == FIRC_OK;
        } else if (how == 1) {
            ok = firc_app_update_group(l.app, gid, selector_group(1, NULL, 0, deny, 1)) == FIRC_OK;
        } else {
            firc_group_t **arr = calloc(1, sizeof(*arr));
            ok = arr != NULL;
            if (ok) {
                arr[0] = selector_group(1, NULL, 0, deny, 1);
                ok = firc_app_replace_groups(l.app, arr, 1) == FIRC_OK;
            }
        }
        firc_app_devices_changed(l.app);
        char dchain[64];
        devices_chain_of(&l, gid, dchain, sizeof(dchain));
        ok = ok && wait_written_after(&l, started) && mangle_has(&l, dchain, "-s 192.168.1.40/32 -j RETURN") &&
             both_flows_reset(&l);
    }
    g_kids_host = false;
    locked_app_down(&l);
    return ok;
}

TEST a_sync_an_update_and_a_save_that_render_narrower_reset_its_flows(void) {
    ASSERTm("a sync", narrowed_by(0));
    ASSERTm("an update", narrowed_by(1));
    ASSERTm("a Save", narrowed_by(2));
    PASS();
}

/* Catches: a sync whose render is unchanged taken for a narrowing, flushing its flows. */
TEST a_sync_of_an_unchanged_selector_keeps_its_chunk_flows(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_stub_mark = 0;
    g_kids_host = true;
    firc_app_set_device_lookup(l.app, stub_mark, stub_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char kids[] = "policy:Kids";
    char *deny[] = {kids};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, NULL, 0, deny, 1)));
    ASSERT(first_pass_done(&l));
    plant_group_flows(&l, 1);
    ASSERT_EQ(FIRC_OK, firc_app_sync_group(l.app, firc_app_find_group_by_id(l.app, gid)));
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_app_pool_changed(l.app);
    ASSERT(wait_written_after(&l, started));
    char dchain[64];
    devices_chain_of(&l, gid, dchain, sizeof(dchain));
    ASSERTm("the host is still denied", mangle_has(&l, dchain, "-s 192.168.1.40/32 -j RETURN"));
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(l.ctk), "%zu");
    ASSERT_EQ_FMT((size_t)4, fake_ct_remaining(l.ctk), "%zu");
    g_kids_host = false;
    locked_app_down(&l);
    PASS();
}

static bool g_hosts_fail;
static firc_err_t failing_hosts(const firc_ip_t *net, uint8_t prefix, bool deny, firc_devsel_addr_fn cb,
                                void *cb_ud, void *ud) {
    (void)net; (void)prefix; (void)deny; (void)cb; (void)cb_ud; (void)ud;
    return g_hosts_fail ? FIRC_ERR_NOMEM : FIRC_OK;
}

TEST a_sync_whose_devices_render_fails_still_writes_its_subnets(void) {
    locked_app_t l;
    ASSERT(locked_app_up(&l));
    fake_rtnl_set_link_flags(l.kernel, 0x1 | 0x10);
    g_hosts_fail = false;
    firc_app_set_device_lookup(l.app, stub_mark, failing_hosts, stub_policy_hosts, NULL, NULL);
    firc_app_set_running(l.app, true);
    firc_id_t gid = {{1, 1, 1, 1}};
    char *allow[] = {k_dev_a};
    ASSERT_EQ(FIRC_OK, firc_app_add_group(l.app, selector_group(1, allow, 1, NULL, 0)));
    ASSERT(first_pass_done(&l));
    firc_ruleset_t *rs = firc_app_find_group_by_id(l.app, gid);
    ASSERT(rs != NULL);
    ASSERT_EQ(FIRC_OK, firc_group_add_rule(firc_ruleset_group_mut(rs), edit_rule(FIRC_RULE_SUBNET, "10.9.0.0/16")));
    g_hosts_fail = true;
    firc_app_nf_enter(l.app);
    uint64_t before = firc_app_nf_change_for_test(l.app);
    firc_app_nf_leave(l.app);
    uint64_t started = firc_app_nf_passes_for_test(l.app);
    firc_err_t err = firc_app_sync_group(l.app, rs);
    g_hosts_fail = false;
    ASSERT_EQ_FMTm("the armed failure fired", FIRC_ERR_NOMEM, err, "%d");
    firc_app_nf_enter(l.app);
    uint64_t after = firc_app_nf_change_for_test(l.app);
    firc_app_nf_leave(l.app);
    ASSERT_EQ_FMTm("one pass asked for", (unsigned long long)(before + 1), (unsigned long long)after, "%llu");
    ASSERT(wait_written_after(&l, started));
    ASSERTm("the prefix reached the kernel", chain_marks(&l, gid, "10.9.0.0/16"));
    locked_app_down(&l);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(close_open_list_app, NULL);
    RUN_TEST(create_wraps_preexisting_groups);
    RUN_TEST(a_republish_closes_the_moved_groups_and_forgets_the_gone_ones);
    RUN_TEST(add_group_rejects_duplicate_id);
    RUN_TEST(add_group_rejects_duplicate_rule_id);
    RUN_TEST(add_group_while_not_running_does_not_touch_netfilter);
    RUN_TEST(add_group_while_running_rolls_back_on_failure);
    RUN_TEST(clear_groups_empties_both_lists);
    RUN_TEST(a_pass_waits_for_the_netfilter_lock);
    RUN_TEST(a_capture_survives_the_firmware_rewriting_the_table);
    RUN_TEST(a_capture_has_a_deadline_and_only_one_exists);
    RUN_TEST(a_group_the_api_made_is_what_the_capture_judges_by);
    RUN_TEST(a_capture_reads_both_sockets);
    RUN_TEST(a_policy_scoped_group_is_judged_with_the_daemons_resolvers);
    RUN_TEST(a_group_added_during_a_capture_is_judged_against);
    RUN_TEST(a_capture_on_an_interface_that_is_not_there_says_so);
    RUN_TEST(a_pass_that_failed_while_a_capture_ran_is_said_out_loud);
    RUN_TEST(one_captures_failed_pass_is_not_the_next_ones);
    RUN_TEST(a_rule_this_kernel_will_not_take_does_not_start_a_capture);
    RUN_TEST(a_capture_that_cannot_read_does_not_start);
    RUN_TEST(a_reader_that_breaks_ends_the_capture);
    RUN_TEST(the_deadline_ends_the_capture_by_itself);
    RUN_TEST(stopping_early_disarms_the_deadline);
    RUN_TEST(the_rules_carry_the_interfaces_the_capture_started_with);
    RUN_TEST(a_capture_without_a_pool_says_which_thing_is_missing);
    RUN_TEST(stopping_the_daemon_ends_the_capture);
    RUN_TEST(a_capture_logs_its_start_its_stop_and_its_summary);
    RUN_TEST(a_pool_change_does_not_take_the_interrupting_lock_and_asks_for_a_pass);
    RUN_TEST(a_pool_change_gets_its_pass_after_the_short_settle);
    RUN_TEST(a_replacement_keeps_the_pool_state_of_groups_that_persist);
    RUN_TEST(outside_a_pass_the_rules_read_the_current_snapshot);
    RUN_TEST(replace_groups_takes_the_netfilter_lock_once);
    RUN_TEST(replace_groups_while_running_keeps_the_groups_that_did_not_come_up);
    RUN_TEST(replace_groups_frees_what_it_could_not_add);
    RUN_TEST(stopping_the_daemon_keeps_the_flows_it_was_steering);
    RUN_TEST(a_replacement_keeps_the_flows_of_groups_that_persist);
    RUN_TEST(a_replacement_drops_the_flows_of_groups_it_withdraws);
    RUN_TEST(a_reorder_does_not_move_a_group_s_mark_field);
    RUN_TEST(adding_a_group_ahead_of_another_does_not_take_its_field);
    RUN_TEST(a_removed_group_gives_its_field_back);
    RUN_TEST(a_removed_group_s_entry_leaves_the_store_when_its_flush_is_paid);
    RUN_TEST(an_unreportable_full_pass_asks_once_and_then_says_so);
    RUN_TEST(a_list_group_that_changes_interface_drops_its_flows);
    RUN_TEST(a_list_group_that_is_turned_off_drops_its_flows);
    RUN_TEST(a_removed_group_is_forgotten_by_the_pool);
    RUN_TEST(a_held_answer_waits_only_for_the_families_it_carries);
    RUN_TEST(remove_by_id_and_by_index);
    RUN_TEST(list_interfaces_show_all_finds_loopback);
    RUN_TEST(save_config_round_trips);
    RUN_TEST(force_commit_iptables_noop_without_engines);
    RUN_TEST(the_app_publishes_a_route_per_group);
    RUN_TEST(a_firmware_resolver_inside_the_pool_is_dropped);
    RUN_TEST(a_running_group_s_route_carries_its_real_mark_and_v6_route);
    RUN_TEST(an_update_of_a_running_group_does_not_bounce_its_route);
    RUN_TEST(a_domain_rule_edit_asks_for_no_pass_but_a_subnet_rule_does);
    RUN_TEST(disabling_a_subnet_list_rule_asks_for_one_pass_and_the_chain_drops_it);
    RUN_TEST(a_name_list_rule_edit_asks_for_no_pass);
    RUN_TEST(a_list_rule_moved_to_subnet_asks_for_one_pass);
    RUN_TEST(a_list_rule_moved_off_subnet_asks_for_one_pass);
    RUN_TEST(a_group_that_fails_to_activate_leaves_the_snapshot_serving);
    RUN_TEST(a_replace_whose_activation_fails_frees_lists_after_the_release);
    RUN_TEST(a_group_whose_interface_is_not_a_name_routes_nothing);
    RUN_TEST(an_update_that_lost_one_race_comes_back);
    RUN_TEST(an_update_whose_write_was_refused_keeps_nothing_old);
    RUN_TEST(a_save_that_lost_one_race_drops_nothing);
    RUN_TEST(no_group_mutation_asks_for_a_full_pass);
    RUN_TEST(without_a_committer_the_loop_writes_the_chain_at_once);
    RUN_TEST(a_deleted_group_leaves_by_tombstone_in_the_next_pass);
    RUN_TEST(a_tombstone_for_a_chain_already_gone_costs_nothing);
    RUN_TEST(a_group_deleted_and_added_back_before_the_pass_keeps_its_chain);
    RUN_TEST(a_save_of_the_same_groups_keeps_every_chain);
    RUN_TEST(a_delete_whose_teardown_failed_still_removes_the_group);
    RUN_TEST(a_save_whose_second_group_fails_keeps_all_three);
    RUN_TEST(a_new_group_that_fails_to_come_up_says_which_step);
    RUN_TEST(a_new_group_names_the_mark_field_and_the_pool_reject_route_steps);
    RUN_TEST(a_startup_whose_first_group_fails_starts_the_rest);
    RUN_TEST(a_startup_whose_first_write_is_refused_comes_up_on_the_retry);
    RUN_TEST(an_update_whose_teardown_failed_still_moves_and_comes_up);
    RUN_TEST(a_failed_re_enable_leaves_no_chain_after_the_pass);
    RUN_TEST(live_reason_is_checked_in_its_order);
    RUN_TEST(live_follows_the_interface_link);
    RUN_TEST(a_committer_that_keeps_failing_says_not_written);
    RUN_TEST(a_save_before_its_pass_still_reads_live);
    RUN_TEST(before_the_first_pass_a_group_reads_not_written);
    RUN_TEST(a_group_that_failed_comes_up_by_itself_on_link_up);
    RUN_TEST(a_group_that_keeps_failing_is_retried_no_more_often_than_its_spacing);
    RUN_TEST(a_group_that_failed_comes_up_by_itself_after_a_pass);
    RUN_TEST(a_failed_group_comes_up_on_its_timer_with_no_trigger);
    RUN_TEST(an_edit_that_fails_starts_a_fresh_run);
    RUN_TEST(a_retry_that_holds_ends_the_run);
    RUN_TEST(a_new_group_rolled_out_leaves_no_retry_timer);
    RUN_TEST(a_syncs_progress_does_not_interrupt_the_pass);
    RUN_TEST(a_lists_bookkeeping_does_not_interrupt_the_pass);
    RUN_TEST(in_view_routed_and_the_chain_name_say_what_the_kernel_has);
    RUN_TEST(a_tombstone_outlives_a_failed_pass);
    RUN_TEST(a_completed_pass_empties_the_tombstones);
    RUN_TEST(stopping_deletes_the_chains_still_tombstoned);
    RUN_TEST(a_group_turned_off_keeps_its_mapping_and_loses_its_dnat_rule);
    RUN_TEST(a_group_with_no_usable_interface_fails_closed);
    RUN_TEST(a_group_turned_back_on_holds_its_cached_names_until_the_pass);
    RUN_TEST(a_group_given_a_usable_interface_holds_its_cached_names_until_the_pass);
    RUN_TEST(a_save_holds_only_the_groups_it_makes_routed);
    RUN_TEST(a_removed_groups_flows_go_after_the_pass_that_carries_it);
    RUN_TEST(a_report_with_an_older_ticket_does_not_pay);
    RUN_TEST(an_owner_added_back_before_the_payment_is_not_flushed);
    RUN_TEST(a_removed_groups_field_is_held_until_its_flush);
    RUN_TEST(an_interface_change_is_paid_although_the_owner_is_routed_again);
    RUN_TEST(an_interface_change_undone_before_the_pass_flushes_nothing);
    RUN_TEST(deleting_a_group_that_never_came_up_holds_nothing);
    RUN_TEST(a_rule_edit_that_comes_back_keeps_its_flows_after_the_pass);
    RUN_TEST(a_rule_edit_whose_re_enable_fails_flushes_its_flows_after_the_pass);
    RUN_TEST(stopping_pays_the_flushes_still_queued);
    RUN_TEST(a_report_on_the_loop_pays_the_flushes_it_carried);
    RUN_TEST(a_selector_group_s_chunk_jumps_to_its_devices_chain);
    RUN_TEST(a_subnet_rule_of_a_selector_group_jumps_to_its_devices_chain);
    RUN_TEST(a_policy_s_segment_reaches_the_devices_chain);
    RUN_TEST(a_changed_policy_mark_is_rewritten_by_the_next_pass);
    RUN_TEST(a_table_change_that_renders_the_same_asks_for_no_pass);
    RUN_TEST(a_selector_emptied_loses_its_devices_chain);
    RUN_TEST(a_selector_emptied_returns_its_subnet_rule_to_a_mark);
    RUN_TEST(a_deleted_selector_group_leaves_no_devices_chain);
    RUN_TEST(without_a_committer_the_devices_chain_is_written_at_once);
    RUN_TEST(a_narrowed_selector_resets_its_flows_after_the_pass);
    RUN_TEST(a_later_edit_before_the_pass_keeps_a_narrowing_queued);
    RUN_TEST(a_widened_selector_resets_nothing);
    RUN_TEST(a_save_that_narrows_a_selector_resets_its_flows);
    RUN_TEST(without_a_committer_a_narrowing_edit_resets_at_once);
    RUN_TEST(a_narrowing_edit_that_moves_the_interface_resets_every_flow);
    RUN_TEST(a_host_that_leaves_a_policy_leaves_the_chain_after_the_next_map);
    RUN_TEST(a_mixed_selector_writes_its_rules_in_order);
    RUN_TEST(a_save_that_empties_a_selector_loses_its_devices_chain);
    RUN_TEST(a_group_given_a_selector_and_then_deleted_leaves_nothing);
    RUN_TEST(a_startup_after_the_lookup_writes_a_deny_policy_on_its_first_pass);
    RUN_TEST(a_host_joining_a_denied_policy_resets_its_flows);
    RUN_TEST(a_host_joining_an_allowed_policy_resets_nothing);
    RUN_TEST(before_the_first_map_a_deny_policy_group_marks_nobody);
    RUN_TEST(the_first_map_after_start_resets_no_flows);
    RUN_TEST(a_sync_an_update_and_a_save_that_render_narrower_reset_its_flows);
    RUN_TEST(a_sync_of_an_unchanged_selector_keeps_its_chunk_flows);
    RUN_TEST(a_sync_whose_devices_render_fails_still_writes_its_subnets);
    GREATEST_MAIN_END();
}
