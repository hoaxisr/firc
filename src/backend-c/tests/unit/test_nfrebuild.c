#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/socket.h>

#include "fake_conntrack.h"
#include "fake_iptables.h"

#include "firc/app.h"
#include "firc/fakeip.h"
#include "firc/netfilter_cleaner.h"
#include "firc/port_remap.h"

typedef struct {
    firc_config_t cfg;
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
    firc_app_t *app;
    firc_port_remap_t *remap;
} fixture_t;

/* Rules belonging to somebody else, which a rebuild must leave alone. */
static void seed_foreign_rules(firc_fake_ipt_t *f) {
    static const char *fwd[] = {"-i", "eth0", "-j", "ACCEPT"};
    static const char *pre[] = {"-i", "eth0", "-j", "ACCEPT"};
    static const char *post[] = {"-o", "eth0", "-j", "MASQUERADE"};
    static const char *mangle[] = {"-i", "eth0", "-j", "MARK", "--set-mark", "7"};

    const char *const *rules[1];
    size_t lens[1];

    rules[0] = fwd;
    lens[0] = 4;
    firc_fake_ipt_set_initial_rules(f, "filter", "FORWARD", rules, lens, 1);
    rules[0] = mangle;
    lens[0] = 6;
    firc_fake_ipt_set_initial_rules(f, "mangle", "PREROUTING", rules, lens, 1);
    rules[0] = pre;
    lens[0] = 4;
    firc_fake_ipt_set_initial_rules(f, "nat", "PREROUTING", rules, lens, 1);
    rules[0] = post;
    lens[0] = 4;
    firc_fake_ipt_set_initial_rules(f, "nat", "POSTROUTING", rules, lens, 1);
}

static void fixture_up(fixture_t *fx) {
    memset(fx, 0, sizeof(*fx));
    firc_config_init_defaults(&fx->cfg);

    fx->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fx->fake);
    fx->ipt = firc_ipt_new(firc_fake_ipt_as_executable(fx->fake));
    firc_netfilter_register_base_chains(fx->ipt, NULL);

    firc_app_deps_t deps = {.cfg = &fx->cfg, .ipt4 = fx->ipt};
    fx->app = firc_app_create(&deps);

    fx->remap = firc_port_remap_new(fx->cfg.app.netfilter.iptables.chain_prefix, 53, 3553, NULL, 0,
                                  fx->ipt, NULL);
    firc_port_remap_enable(fx->remap);
    firc_app_set_port_remap(fx->app, fx->remap);
}

static void fixture_down(fixture_t *fx) {
    firc_port_remap_free(fx->remap);
    firc_app_destroy(fx->app);
    firc_ipt_free(fx->ipt);
    firc_config_clear(&fx->cfg);
}

static void seed_stale_chain(firc_fake_ipt_t *f) {
    static const char *rule[] = {"-m", "set", "--match-set", "firc_old_4", "dst", "-j", "MASQUERADE"};
    static const char *jump[] = {"-j", "FIRC_old"};
    const char *const *rules[1] = {rule};
    size_t lens[1] = {7};
    firc_fake_ipt_set_initial_rules(f, "nat", "FIRC_old", rules, lens, 1);

    const char *const *keep[2];
    size_t keep_lens[2];
    static const char *foreign[] = {"-o", "eth0", "-j", "MASQUERADE"};
    keep[0] = foreign;
    keep_lens[0] = 4;
    keep[1] = jump;
    keep_lens[1] = 2;
    firc_fake_ipt_set_initial_rules(f, "nat", "POSTROUTING", keep, keep_lens, 2);
}

static bool chain_has_rule(firc_fake_ipt_t *f, const char *table, const char *chain,
                          const char *const *parts, size_t n_parts) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        if (rules[i]->n_parts != n_parts) { continue; }
        bool same = true;
        for (size_t j = 0; j < n_parts; j++) {
            if (strcmp(rules[i]->parts[j], parts[j]) != 0) {
                same = false;
                break;
            }
        }
        if (same) { return true; }
    }
    return false;
}

static size_t count_rule(firc_fake_ipt_t *f, const char *table, const char *chain,
                        const char *const *parts, size_t n_parts) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0, found = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return 0; }
    for (size_t i = 0; i < n; i++) {
        if (rules[i]->n_parts != n_parts) { continue; }
        bool same = true;
        for (size_t j = 0; j < n_parts; j++) {
            if (strcmp(rules[i]->parts[j], parts[j]) != 0) {
                same = false;
                break;
            }
        }
        if (same) { found++; }
    }
    return found;
}

static const char *const k_remap_jump[] = {"-j", "FIRC_DNSOR"};
static const char *const k_foreign_post[] = {"-o", "eth0", "-j", "MASQUERADE"};

TEST rebuild_restores_the_table_after_a_wipe(void) {
    fixture_t fx;
    fixture_up(&fx);

    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));
    ASSERT(chain_has_rule(fx.fake, "nat", "PREROUTING", k_remap_jump, 2));

    firc_fake_ipt_reset(fx.fake);
    seed_foreign_rules(fx.fake);
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, NULL));

    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));
    ASSERT(chain_has_rule(fx.fake, "nat", "PREROUTING", k_remap_jump, 2));

    fixture_down(&fx);
    PASS();
}

TEST rebuild_does_not_duplicate_jumps(void) {
    fixture_t fx;
    fixture_up(&fx);

    for (int i = 0; i < 4; i++) { ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, NULL)); }

    ASSERT_EQ(1u, count_rule(fx.fake, "nat", "PREROUTING", k_remap_jump, 2));

    fixture_down(&fx);
    PASS();
}

TEST rebuild_drops_chains_left_by_a_previous_run(void) {
    fixture_t fx;
    fixture_up(&fx);
    seed_stale_chain(fx.fake);
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, NULL));

    ASSERT_FALSE(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));
    static const char *const stale_jump[] = {"-j", "FIRC_old"};
    ASSERT_EQ(0u, count_rule(fx.fake, "nat", "POSTROUTING", stale_jump, 2));
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    fixture_down(&fx);
    PASS();
}

TEST rebuild_keeps_other_writers_rules(void) {
    fixture_t fx;
    fixture_up(&fx);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, NULL));

    ASSERT(chain_has_rule(fx.fake, "nat", "POSTROUTING", k_foreign_post, 4));
    static const char *const foreign_fwd[] = {"-i", "eth0", "-j", "ACCEPT"};
    ASSERT(chain_has_rule(fx.fake, "filter", "FORWARD", foreign_fwd, 4));

    fixture_down(&fx);
    PASS();
}

/* Catches: a pass with a raised cancel token writing, or reporting a failure. */
TEST rebuild_aborts_on_a_raised_cancel(void) {
    fixture_t fx;
    fixture_up(&fx);

    firc_fake_ipt_reset(fx.fake);
    seed_foreign_rules(fx.fake);

    firc_cancel_t *cancel = firc_cancel_new();
    firc_cancel_raise(cancel);

    ASSERT_EQ(FIRC_ERR_CANCELED, firc_app_rebuild_netfilter(fx.app, cancel));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    firc_cancel_clear(cancel);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, cancel));
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    firc_cancel_free(cancel);
    fixture_down(&fx);
    PASS();
}

/* Catches: an aborted pass leaving deletes staged for the next commit to carry out. */
TEST an_aborted_pass_stages_nothing_for_the_next_commit(void) {
    fixture_t fx;
    fixture_up(&fx);
    static const char *rule[] = {"-j", "ACCEPT"};
    const char *const *rules[1] = {rule};
    size_t lens[1] = {2};
    firc_fake_ipt_set_initial_rules(fx.fake, "mangle", "FIRC_live", rules, lens, 1);

    firc_cancel_t *cancel = firc_cancel_new();
    firc_cancel_raise(cancel);
    ASSERT_EQ(FIRC_ERR_CANCELED, firc_app_rebuild_netfilter(fx.app, cancel));
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "mangle", "FIRC_live"));

    ASSERT_EQ(FIRC_OK, firc_ipt_commit(fx.ipt));
    ASSERTm("the aborted pass's staged delete must not fire here",
            firc_fake_ipt_chain_exists(fx.fake, "mangle", "FIRC_live"));
    static const char *jump[] = {"-j", "FIRC_live"};
    ASSERT_EQ_FMTm("a jump into a base chain after an aborted pass", (int)FIRC_OK,
                   (int)firc_ipt_append(fx.ipt, "filter", "FORWARD", jump, 2), "%d");

    firc_cancel_free(cancel);
    fixture_down(&fx);
    PASS();
}

/* Catches: a pass not writing the DNAT chain from its snapshot, or not committing the pool. */
TEST a_pass_writes_the_dnat_chain_and_commits_the_pool(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.base.b[2] = 0x9a;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));

    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    firc_fake_ipt_t *fake6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt6 = firc_ipt_new(firc_fake_ipt_as_executable(fake6));
    firc_netfilter_register_base_chains(ipt, ipt6);
    firc_app_deps_t deps = {.cfg = &cfg, .ipt4 = ipt, .ipt6 = ipt6, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);

    firc_ip_t fake4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &fake4, NULL));
    const firc_ip_t real = {{93, 184, 216, 34}, 4};
    const firc_ip_t real6 = {{0x26, 0x06, 0x28, 0, 0x02, 0x20, 0, 1, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46}, 16};
    firc_ip_t both[] = {real, real6};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(pool, "a.example.com", both, 2));
    ASSERT(firc_fakeip_needs_commit(pool, "a.example.com", FIRC_FAM_V4));
    ASSERT_EQ(FIRC_OK, firc_app_refresh_pool_snapshot(app));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));

    static const char *want[] = {"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination", "93.184.216.34"};
    ASSERT_FALSEm("a mapping of a group the app does not route gets no rule",
                  chain_has_rule(fake, "nat", "FIRC_DNAT", want, 6));
    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERTm("entered from PREROUTING, guarded by the pool prefix", chain_has_rule(fake, "nat", "PREROUTING", jump, 4));
    static const char *want6[] = {"-d", "fd37:9a00::1/128", "-j", "DNAT", "--to-destination",
                                  "2606:2800:220:1:248:1893:25c8:1946"};
    ASSERT_FALSEm("nor in the v6 table", chain_has_rule(fake6, "nat", "FIRC_DNAT", want6, 6));
    ASSERT_FALSEm("and the pool was told the pass completed",
                  firc_fakeip_needs_commit(pool, "a.example.com", FIRC_FAM_V4));

    const firc_ip_t moved = {{93, 184, 216, 35}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(pool, "a.example.com", &moved, 1));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));
    ASSERTm("a pass over an older snapshot does not commit a newer pair",
            firc_fakeip_needs_commit(pool, "a.example.com", FIRC_FAM_V4));

    firc_app_destroy(app);
    firc_ipt_free(ipt);
    firc_ipt_free(ipt6);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Builds an app with fake conntrack and a loop, for the window a full pass opens. */
static void up_with_conntrack_and_loop(firc_config_t *cfg, firc_fake_ipt_t **fake, firc_ipt_t **ipt,
                                       firc_fakeip_t **pool, fake_ct_t **kernel, firc_ct_t **ct,
                                       firc_app_t **app, firc_loop_t *loop) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37;
    c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    *pool = NULL;
    if (firc_fakeip_new(&c, pool) != FIRC_OK) { return; }
    firc_config_init_defaults(cfg);
    *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    *ipt = firc_ipt_new(firc_fake_ipt_as_executable(*fake));
    firc_netfilter_register_base_chains(*ipt, NULL);
    *kernel = fake_ct_start(ct);
    firc_app_deps_t deps = {.cfg = cfg, .ipt4 = *ipt, .pool = *pool, .ct = *ct, .loop = loop};
    *app = firc_app_create(&deps);
}

static void up_with_conntrack(firc_config_t *cfg, firc_fake_ipt_t **fake, firc_ipt_t **ipt,
                              firc_fakeip_t **pool, fake_ct_t **kernel, firc_ct_t **ct,
                              firc_app_t **app) {
    up_with_conntrack_and_loop(cfg, fake, ipt, pool, kernel, ct, app, NULL);
}

static const uint8_t k_issued4[4] = {198, 18, 0, 1};
static const uint8_t k_real4[4] = {93, 184, 216, 34};
static const uint8_t k_issued6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t k_real6[16] = {0x26, 0x06, 0x28, 0, 2, 0x20, 0, 1,
                                    2,    0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46};

static void seed_window_flows(fake_ct_t *k) {
    const uint8_t client[4] = {192, 168, 1, 10};
    const uint8_t client6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    fake_ct_add(k, AF_INET, client, k_issued4, k_issued4, 0);
    fake_ct_add(k, AF_INET, client, k_issued4, k_real4, 0);
    fake_ct_add(k, AF_INET6, client6, k_issued6, k_issued6, 0);
    fake_ct_add(k, AF_INET6, client6, k_issued6, k_real6, 0);
}

/* Catches: flows answered from the pool during a full pass's window left unswept. */
TEST a_full_pass_clears_the_flows_of_the_window_it_opened(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    up_with_conntrack(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));

    ASSERTm("the unbound v4 flow of the window is dropped", fake_ct_deleted(kernel, k_issued4, 4));
    ASSERTm("and the v6 one, which has a half of the sweep to itself",
            fake_ct_deleted(kernel, k_issued6, 16));
    ASSERT_FALSEm("the bound v4 flow is not: it is routed correctly",
                  fake_ct_deleted(kernel, k_real4, 4));
    ASSERT_FALSEm("nor the bound v6 one", fake_ct_deleted(kernel, k_real6, 16));

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: an incremental pass sweeping live flows. */
TEST an_incremental_pass_opens_no_window_and_clears_nothing(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    up_with_conntrack(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(app, NULL, false));

    ASSERT_EQ_FMTm("the kernel was not asked for a dump at all", (size_t)0,
                   fake_ct_dumps(kernel), "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(kernel), "%zu");

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

static void stop_the_loop(firc_loop_t *loop, void *ud) {
    (void)ud;
    firc_loop_stop(loop);
}

/* Catches: a full pass reported through the loop not sweeping. */
TEST the_sweep_also_happens_when_the_pass_is_reported_through_the_loop(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    up_with_conntrack_and_loop(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app, loop);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));
    ASSERT_FALSEm("nothing has run on the loop yet", fake_ct_deleted(kernel, k_issued4, 4));

    ASSERT_EQ(FIRC_OK, firc_loop_post(loop, stop_the_loop, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));

    ASSERTm("the window's flow went when the report landed",
            fake_ct_deleted(kernel, k_issued4, 4));

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: an incremental pass reported through the loop sweeping. */
TEST an_incremental_pass_reported_through_the_loop_clears_nothing(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    up_with_conntrack_and_loop(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app, loop);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(app, NULL, false));
    ASSERT_EQ(FIRC_OK, firc_loop_post(loop, stop_the_loop, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));

    ASSERT_EQ_FMTm("the kernel was not asked for a dump at all", (size_t)0,
                   fake_ct_dumps(kernel), "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(kernel), "%zu");

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    firc_loop_destroy(loop);
    PASS();
}

typedef struct {
    firc_app_t *app;
    fake_ct_t *kernel;
    size_t dumps_before_the_second_report;
} debt_probe_t;

static void incremental_then_full_then_stop(firc_loop_t *loop, void *ud) {
    debt_probe_t *p = ud;
    (void)firc_app_rebuild_netfilter_kind(p->app, NULL, false);
    p->dumps_before_the_second_report = fake_ct_dumps(p->kernel);
    firc_loop_stop(loop);
}

TEST a_sweep_that_could_not_finish_waits_for_the_next_full_pass(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    up_with_conntrack_and_loop(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app, loop);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    fake_ct_fail_dump_of(kernel, AF_INET, ENOBUFS);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));

    debt_probe_t probe = {.app = app, .kernel = kernel, .dumps_before_the_second_report = 0};
    ASSERT_EQ(FIRC_OK, firc_loop_post(loop, incremental_then_full_then_stop, &probe));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    size_t after_incremental = probe.dumps_before_the_second_report;
    ASSERTm("the full pass's sweep did run", after_incremental > 0);

    ASSERT_EQ_FMTm("no sweep rode on the incremental report", after_incremental,
                   fake_ct_dumps(kernel), "%zu");

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    firc_loop_destroy(loop);
    PASS();
}

static size_t rule_count(firc_fake_ipt_t *f, const char *table, const char *chain) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    return firc_fake_ipt_get_rules(f, table, chain, &rules, &n) ? n : 0;
}

static size_t forward_jumps(firc_fake_ipt_t *f, const char *chain) {
    const char *jump[] = {"-j", chain};
    return count_rule(f, "filter", "FORWARD", jump, 2);
}

/* Catches: the pool reject barrier missing from FORWARD, or behind the firmware's accepts. */
TEST a_pass_puts_the_pool_reject_barrier_first_in_forward(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.base.b[2] = 0x9a;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    firc_fake_ipt_t *fake6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    seed_foreign_rules(fake6);
    firc_ipt_t *ipt6 = firc_ipt_new(firc_fake_ipt_as_executable(fake6));
    firc_netfilter_register_base_chains(ipt, ipt6);
    firc_app_deps_t deps = {.cfg = &cfg, .ipt4 = ipt, .ipt6 = ipt6, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));

    firc_ipt_rule_t *const *fwd = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "FORWARD", &fwd, &n));
    ASSERT(n >= 2);
    ASSERT_STR_EQm("entered before anything the firmware accepts", "FIRC_POOLREJECT", fwd[0]->parts[1]);
    ASSERT_EQ_FMTm("one jump, however many passes", (size_t)1, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");
    static const char *foreign_fwd[] = {"-i", "eth0", "-j", "ACCEPT"};
    ASSERT(chain_has_rule(fake, "filter", "FORWARD", foreign_fwd, 4));
    static const char *tcp4[] = {"-d", "198.18.0.0/15", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    static const char *rest4[] = {"-d", "198.18.0.0/15", "-j", "REJECT", "--reject-with", "icmp-host-unreachable"};
    ASSERT(chain_has_rule(fake, "filter", "FIRC_POOLREJECT", tcp4, 8));
    ASSERT(chain_has_rule(fake, "filter", "FIRC_POOLREJECT", rest4, 6));
    ASSERT_EQ_FMT((size_t)2, rule_count(fake, "filter", "FIRC_POOLREJECT"), "%zu");
    static const char *tcp6[] = {"-d", "fd37:9a00::/48", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    static const char *rest6[] = {"-d", "fd37:9a00::/48", "-j", "REJECT", "--reject-with", "icmp6-addr-unreachable"};
    ASSERT(chain_has_rule(fake6, "filter", "FIRC_POOLREJECT", tcp6, 8));
    ASSERT(chain_has_rule(fake6, "filter", "FIRC_POOLREJECT", rest6, 6));
    ASSERT_EQ_FMT((size_t)1, forward_jumps(fake6, "FIRC_POOLREJECT"), "%zu");

    firc_app_destroy(app);
    ASSERTm("a clean stop leaves the barrier, like the main-table routes",
            firc_fake_ipt_chain_exists(fake, "filter", "FIRC_POOLREJECT") && forward_jumps(fake, "FIRC_POOLREJECT") == 1);
    firc_ipt_free(ipt);
    firc_ipt_free(ipt6);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a sweep removing the barrier, opening a window before the refill. */
TEST the_sweep_leaves_the_barrier_in_place(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    static const char *tcp[] = {"-d", "198.18.0.0/15", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    const char *const *rules[1] = {tcp};
    size_t lens[1] = {8};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FIRC_POOLREJECT", rules, lens, 1);
    static const char *jump[] = {"-j", "FIRC_POOLREJECT"};
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *fwd[2] = {jump, foreign};
    size_t fwd_lens[2] = {2, 4};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", fwd, fwd_lens, 2);
    seed_stale_chain(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    firc_netfilter_register_base_chains(ipt, NULL);

    ASSERT_EQ(FIRC_OK, firc_netfilter_clean_iptables(ipt, NULL, "FIRC_"));
    ASSERT_FALSEm("the stale chain went", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    ASSERTm("the barrier stayed", firc_fake_ipt_chain_exists(fake, "filter", "FIRC_POOLREJECT"));
    ASSERT_EQ_FMTm("and its jump", (size_t)1, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a purge leaving the barrier behind. */
TEST the_purge_takes_the_barrier_as_well(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    static const char *tcp[] = {"-d", "198.18.0.0/15", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    const char *const *rules[1] = {tcp};
    size_t lens[1] = {8};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FIRC_POOLREJECT", rules, lens, 1);
    static const char *jump[] = {"-j", "FIRC_POOLREJECT"};
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *fwd[2] = {jump, foreign};
    size_t fwd_lens[2] = {2, 4};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", fwd, fwd_lens, 2);
    seed_stale_chain(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    firc_netfilter_register_base_chains(ipt, NULL);

    ASSERT_EQ(FIRC_OK, firc_netfilter_purge_iptables(ipt, NULL, "FIRC_"));
    ASSERT_FALSEm("the stale chain went", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    ASSERT_FALSEm("and so did the barrier", firc_fake_ipt_chain_exists(fake, "filter", "FIRC_POOLREJECT"));
    ASSERT_EQ_FMTm("and its jump", (size_t)0, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");
    ASSERTm("the foreign FORWARD rule stayed", firc_fake_ipt_chain_exists(fake, "filter", "FORWARD"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a stopped daemon leaving its DNAT chain or the jump into it. */
TEST destroying_the_app_takes_the_dnat_chain_back(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.base.b[2] = 0x9a;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_app_deps_t deps = {.cfg = &cfg, .ipt4 = ipt, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);
    firc_ip_t fake4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &fake4, NULL));
    const firc_ip_t real = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(pool, "a.example.com", &real, 1));
    ASSERT_EQ(FIRC_OK, firc_app_refresh_pool_snapshot(app));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));
    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_DNAT"));
    ASSERT(chain_has_rule(fake, "nat", "PREROUTING", jump, 4));

    firc_app_destroy(app);
    ASSERT_FALSEm("the chain is gone with the daemon", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_DNAT"));
    ASSERT_FALSEm("and the jump into it", chain_has_rule(fake, "nat", "PREROUTING", jump, 4));
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    ASSERTm("the firmware's rule next to it is untouched", chain_has_rule(fake, "nat", "PREROUTING", foreign, 4));
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: an incremental pass wiping before it writes, or sweeping a previous instance's chain. */
TEST an_incremental_pass_writes_ours_and_sweeps_nothing(void) {
    fixture_t fx;
    fixture_up(&fx);
    seed_stale_chain(fx.fake);
    firc_fake_ipt_reset(fx.fake);
    seed_foreign_rules(fx.fake);
    seed_stale_chain(fx.fake);
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, false));
    ASSERTm("ours is written", firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));
    ASSERTm("the stale chain is not this pass's business",
            firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, true));
    ASSERT_FALSEm("a full pass sweeps it", firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    fixture_down(&fx);
    PASS();
}

/* Catches: a forced commit without a committer not committing at once. */
TEST force_commit_without_a_committer_commits_in_place(void) {
    fixture_t fx;
    fixture_up(&fx);

    ASSERT_EQ(FIRC_OK, firc_app_force_commit_iptables(fx.app));

    fixture_down(&fx);
    PASS();
}

TEST port_remap_uses_the_configured_chain_prefix(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    firc_netfilter_register_base_chains(ipt, NULL);

    firc_port_remap_t *remap = firc_port_remap_new("XX_", 53, 3553, NULL, 0, ipt, NULL);
    ASSERT(remap != NULL);
    ASSERT_EQ(FIRC_OK, firc_port_remap_enable(remap));
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "XX_DNSOR"));
    static const char *const jump[] = {"-j", "XX_DNSOR"};
    ASSERT(chain_has_rule(fake, "nat", "PREROUTING", jump, 2));

    ASSERT_EQ(FIRC_OK, firc_port_remap_disable(remap));
    firc_port_remap_free(remap);
    firc_ipt_free(ipt);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(rebuild_restores_the_table_after_a_wipe);
    RUN_TEST(rebuild_does_not_duplicate_jumps);
    RUN_TEST(rebuild_drops_chains_left_by_a_previous_run);
    RUN_TEST(rebuild_keeps_other_writers_rules);
    RUN_TEST(rebuild_aborts_on_a_raised_cancel);
    RUN_TEST(an_aborted_pass_stages_nothing_for_the_next_commit);
    RUN_TEST(a_pass_writes_the_dnat_chain_and_commits_the_pool);
    RUN_TEST(an_incremental_pass_writes_ours_and_sweeps_nothing);
    RUN_TEST(force_commit_without_a_committer_commits_in_place);
    RUN_TEST(port_remap_uses_the_configured_chain_prefix);
    RUN_TEST(destroying_the_app_takes_the_dnat_chain_back);
    RUN_TEST(a_pass_puts_the_pool_reject_barrier_first_in_forward);
    RUN_TEST(the_sweep_leaves_the_barrier_in_place);
    RUN_TEST(the_purge_takes_the_barrier_as_well);
    RUN_TEST(a_full_pass_clears_the_flows_of_the_window_it_opened);
    RUN_TEST(an_incremental_pass_opens_no_window_and_clears_nothing);
    RUN_TEST(the_sweep_also_happens_when_the_pass_is_reported_through_the_loop);
    RUN_TEST(a_sweep_that_could_not_finish_waits_for_the_next_full_pass);
    RUN_TEST(an_incremental_pass_reported_through_the_loop_clears_nothing);
    GREATEST_MAIN_END();
}
