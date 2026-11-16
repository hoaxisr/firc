#include "greatest.h"

#include <errno.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fake_iptables.h"
#include "fake_rtnl.h"
#include "fake_setnl.h"
#include "firc/events.h"
#include "firc/mark.h"
#include "firc/netfilter_cleaner.h"
#include "firc/purge.h"

typedef struct {
    firc_fake_ipt_t *fake4, *fake6;
    firc_ipt_t *ipt4, *ipt6;
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    char dir[64];
    char pool[128], tmp[128], sock[128], lock[128], fields[128], fields_tmp[136];
} fx_t;

static void seed_family(firc_fake_ipt_t *f, const char *pool) {
    static const char *stale[] = {"-j", "MASQUERADE"};
    const char *const *stale_rules[1] = {stale};
    size_t stale_lens[1] = {2};
    firc_fake_ipt_set_initial_rules(f, "nat", "FIRC_old", stale_rules, stale_lens, 1);
    static const char *stale_jump[] = {"-j", "FIRC_old"};
    const char *const *pre[1] = {stale_jump};
    size_t pre_lens[1] = {2};
    firc_fake_ipt_set_initial_rules(f, "nat", "PREROUTING", pre, pre_lens, 1);
    const char *tcp[] = {"-d", pool, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    const char *const *barrier[1] = {tcp};
    size_t barrier_lens[1] = {8};
    firc_fake_ipt_set_initial_rules(f, "filter", "FIRC_POOLREJECT", barrier, barrier_lens, 1);
    static const char *jump[] = {"-j", "FIRC_POOLREJECT"};
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *fwd[2] = {jump, foreign};
    size_t fwd_lens[2] = {2, 4};
    firc_fake_ipt_set_initial_rules(f, "filter", "FORWARD", fwd, fwd_lens, 2);
}

static const uint8_t k_pool4[4] = {198, 18, 0, 0};
static const uint8_t k_pool6[16] = {0xfd, 0x37, 0x9a, 0};
static const uint8_t k_other4[4] = {10, 99, 0, 0};

static bool up(fx_t *f) {
    memset(f, 0, sizeof(*f));
    f->fake4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    f->fake6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    seed_family(f->fake4, "198.18.0.0/15");
    seed_family(f->fake6, "fd37:9a00::/48");
    f->ipt4 = firc_ipt_new(firc_fake_ipt_as_xt(f->fake4), "FIRC_");
    f->ipt6 = firc_ipt_new(firc_fake_ipt_as_xt(f->fake6), "FIRC_");
    firc_netfilter_register_base_chains(f->ipt4, f->ipt6);
    f->kernel = fake_rtnl_start(&f->rtnl);
    if (f->kernel == NULL) { return false; }
    fake_rtnl_add_rule(f->kernel, AF_INET, 0x10000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY);
    fake_rtnl_add_rule(f->kernel, AF_INET6, 0x10000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY);
    fake_rtnl_add_route(f->kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, FIRC_RTPROT, k_pool4, 15, 4096);
    fake_rtnl_add_route(f->kernel, AF_INET6, RT_TABLE_MAIN, RTN_UNREACHABLE, FIRC_RTPROT, k_pool6, 48, 4096);
    fake_rtnl_add_route(f->kernel, AF_INET, 1000, RTN_UNREACHABLE, FIRC_RTPROT, k_pool4, 15, 5);
    fake_rtnl_add_route(f->kernel, AF_INET, 1000, RTN_UNICAST, FIRC_RTPROT, k_other4, 0, 10);
    fake_rtnl_add_route(f->kernel, AF_INET, 1000, RTN_BLACKHOLE, FIRC_RTPROT, k_other4, 0, 20);
    fake_rtnl_add_route(f->kernel, AF_INET, 1000, RTN_UNICAST, FIRC_RTPROT, k_other4, 0, 30);
    fake_rtnl_scope_last_route(f->kernel, RT_SCOPE_LINK);
    fake_rtnl_add_route(f->kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, RTPROT_STATIC, k_pool4, 15, 4096);
    fake_rtnl_add_route(f->kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, RTPROT_STATIC, k_other4, 16, 10);
    fake_rtnl_add_route(f->kernel, AF_INET, 100, RTN_UNICAST, RTPROT_BOOT, k_other4, 0, 0);
    fake_rtnl_add_rule(f->kernel, AF_INET, 0x989, 0x989, 989, 90);
    snprintf(f->dir, sizeof(f->dir), "/tmp/firc-purge-XXXXXX");
    if (mkdtemp(f->dir) == NULL) { return false; }
    snprintf(f->pool, sizeof(f->pool), "%s/pool.state", f->dir);
    snprintf(f->tmp, sizeof(f->tmp), "%s/pool.state.tmp", f->dir);
    snprintf(f->sock, sizeof(f->sock), "%s/firc.sock", f->dir);
    snprintf(f->lock, sizeof(f->lock), "%s/fircd.lock", f->dir);
    snprintf(f->fields, sizeof(f->fields), "%s/fields.state", f->dir);
    snprintf(f->fields_tmp, sizeof(f->fields_tmp), "%s/fields.state.tmp", f->dir);
    const char *files[6] = {f->pool, f->tmp, f->sock, f->lock, f->fields, f->fields_tmp};
    for (int i = 0; i < 6; i++) {
        FILE *fp = fopen(files[i], "w");
        if (fp == NULL) { return false; }
        fputs("x", fp);
        fclose(fp);
    }
    return true;
}

static void down(fx_t *f) {
    firc_rtnl_close(f->rtnl);
    fake_rtnl_stop(f->kernel);
    firc_ipt_free(f->ipt4);
    firc_ipt_free(f->ipt6);
    unlink(f->pool);
    unlink(f->tmp);
    unlink(f->sock);
    unlink(f->lock);
    unlink(f->fields);
    unlink(f->fields_tmp);
    rmdir(f->dir);
}

static firc_purge_paths_t paths_of(const fx_t *f) {
    firc_purge_paths_t p = {.pool_file = f->pool, .fields_file = f->fields, .sock = f->sock, .lock = f->lock, .run_dir = f->dir};
    return p;
}

static size_t count_rule(firc_fake_ipt_t *f, const char *table, const char *chain, const char *const *rule,
                         size_t n) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t got = 0, hits = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &got)) { return 0; }
    for (size_t i = 0; i < got; i++) {
        if (rules[i]->n_parts != n) { continue; }
        bool same = true;
        for (size_t k = 0; k < n && same; k++) { same = strcmp(rules[i]->parts[k], rule[k]) == 0; }
        if (same) { hits++; }
    }
    return hits;
}

TEST nothing_of_ours_is_left_and_nothing_of_anyone_elses_is_touched(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ(FIRC_OK, firc_purge(f.ipt4, f.ipt6, f.rtnl, NULL, "FIRC_", &p, &rep));

    static const char *jump[] = {"-j", "FIRC_POOLREJECT"};
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    firc_fake_ipt_t *fakes[2] = {f.fake4, f.fake6};
    for (int i = 0; i < 2; i++) {
        ASSERT_FALSEm("the stale chain went", firc_fake_ipt_chain_exists(fakes[i], "nat", "FIRC_old"));
        ASSERT_FALSEm("the barrier went", firc_fake_ipt_chain_exists(fakes[i], "filter", "FIRC_POOLREJECT"));
        ASSERT_EQ_FMTm("and its jump", (size_t)0, count_rule(fakes[i], "filter", "FORWARD", jump, 2), "%zu");
        ASSERT_EQ_FMTm("the foreign FORWARD rule stayed", (size_t)1, count_rule(fakes[i], "filter", "FORWARD", foreign, 4), "%zu");
    }
    ASSERT(rep.iptables_ok);

    ASSERT_EQ_FMT((size_t)2, rep.rules_removed, "%zu");
    ASSERT_EQ_FMT((size_t)6, rep.routes_removed, "%zu");
    ASSERTm("a dump afterwards shows nothing of ours", rep.routes_ok);
    ASSERT_EQ_FMTm("nat and filter hold ours and are written once each; mangle holds nothing of ours", (size_t)2,
                   firc_fake_ipt_writes(f.fake4), "%zu");
    ASSERT_EQ_FMT((size_t)2, firc_fake_ipt_writes(f.fake6), "%zu");
    fake_rtnl_msg_t msgs[16];
    size_t n = fake_rtnl_messages(f.kernel, msgs, 16);
    size_t del_routes = 0, del_rules = 0, group_table = 0, v6 = 0, scoped = 0;
    for (size_t i = 0; i < n; i++) {
        if (msgs[i].type == RTM_DELRULE) { del_rules++; }
        if (msgs[i].type != RTM_DELROUTE) { continue; }
        del_routes++;
        ASSERT_EQ_FMTm("every delete carries our tag (what scopes the kernel's match)", FIRC_RTPROT, msgs[i].protocol, "%d");
        ASSERT_FALSEm("never the operator's 10.99/16", msgs[i].dst_len == 16 && memcmp(msgs[i].dst, k_other4, 4) == 0);
        if (msgs[i].table == 1000) { group_table++; }
        if (msgs[i].scope == RT_SCOPE_LINK) { scoped++; }
        if (msgs[i].family == AF_INET6) {
            v6++;
            ASSERT_EQ(48, msgs[i].dst_len);
            ASSERT_EQ(0, memcmp(msgs[i].dst, k_pool6, 16));
        }
    }
    ASSERT_EQ_FMT((size_t)6, del_routes, "%zu");
    ASSERT_EQ_FMT((size_t)2, del_rules, "%zu");
    ASSERT_EQ_FMTm("the group table's four routes too", (size_t)4, group_table, "%zu");
    ASSERT_EQ_FMTm("the link-scoped route was deleted as such", (size_t)1, scoped, "%zu");
    ASSERT_EQ_FMT((size_t)2, fake_rtnl_count(f.kernel, RTM_DELROUTE, RTN_UNICAST), "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_rtnl_count(f.kernel, RTM_DELROUTE, RTN_BLACKHOLE), "%zu");
    ASSERT_EQ_FMT((size_t)3, fake_rtnl_count(f.kernel, RTM_DELROUTE, RTN_UNREACHABLE), "%zu");
    ASSERT_EQ_FMTm("the v6 one too", (size_t)1, v6, "%zu");

    struct stat st;
    ASSERT(stat(f.pool, &st) != 0);
    ASSERTm("a save cut short leaves every name in the .tmp: gone too", stat(f.tmp, &st) != 0);
    ASSERT(stat(f.sock, &st) != 0);
    ASSERT(stat(f.lock, &st) != 0);
    ASSERTm("the run dir is gone", stat(f.dir, &st) != 0);
    ASSERT(rep.run_dir_removed);
    down(&f);
    PASS();
}

/* Catches: a purge write that loses a race to the firmware not retried. */
TEST a_raced_iptables_write_is_retried(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_fake_ipt_fail_at_commit(f.fake4, 1, FIRC_ERR_AGAIN);
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ(FIRC_OK, firc_purge(f.ipt4, f.ipt6, f.rtnl, NULL, "FIRC_", &p, &rep));
    ASSERT(rep.iptables_ok);
    ASSERT_EQ_FMTm("the raced write was tried again", (size_t)2, firc_fake_ipt_writes(f.fake4), "%zu");
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fake4, "filter", "FIRC_POOLREJECT"));
    down(&f);
    PASS();
}

/* Catches: a refused route delete hidden, not propagated, or stopping the file removal. */
TEST a_route_the_kernel_will_not_delete_is_reported_not_hidden(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_rtnl_fail_next_of(f.kernel, RTM_DELROUTE, EPERM);
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT(firc_purge(f.ipt4, f.ipt6, f.rtnl, NULL, "FIRC_", &p, &rep) != FIRC_OK);
    ASSERT(rep.iptables_ok);
    ASSERT_EQ_FMTm("the rules went first, untouched by the refusal", (size_t)2, rep.rules_removed, "%zu");
    ASSERT_FALSEm("a route of ours is still there, and the report says so", rep.routes_ok);
    struct stat st;
    ASSERTm("the files went anyway", stat(f.pool, &st) != 0 && stat(f.dir, &st) != 0);
    down(&f);
    PASS();
}

/* Catches: a failed barrier removal skipping the routes or the files. */
TEST every_step_runs_whatever_the_earlier_ones_did(void) {
    fx_t f;
    ASSERT(up(&f));
    for (int i = 0; i < 3; i++) { firc_fake_ipt_fail_next_write(f.fake4, FIRC_ERR_IO); }
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ(FIRC_ERR_IO, firc_purge(f.ipt4, f.ipt6, f.rtnl, NULL, "FIRC_", &p, &rep));
    ASSERT_FALSE(rep.iptables_ok);
    ASSERT_EQ_FMT((size_t)6, rep.routes_removed, "%zu");
    ASSERT_EQ_FMT((size_t)2, rep.rules_removed, "%zu");
    struct stat st;
    ASSERTm("the files went anyway", stat(f.pool, &st) != 0 && stat(f.dir, &st) != 0);
    down(&f);
    PASS();
}

/* Catches: a tolerated ESRCH taken as clean while a dump still shows the route. */
TEST a_route_still_there_after_a_tolerated_delete_is_reported(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_rtnl_fail_next_of(f.kernel, RTM_DELROUTE, ESRCH);
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ_FMT(FIRC_ERR_STATE, firc_purge(f.ipt4, f.ipt6, f.rtnl, NULL, "FIRC_", &p, &rep), "%d");
    ASSERT_FALSE(rep.routes_ok);
    ASSERT_EQ_FMTm("a delete the kernel found nothing for is not counted", (size_t)5, rep.routes_removed, "%zu");
    down(&f);
    PASS();
}

/* Catches: a refused ip rule delete not failing the purge. */
TEST a_rule_the_kernel_will_not_delete_fails_the_purge(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_rtnl_fail_next_of(f.kernel, RTM_DELRULE, EPERM);
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT(firc_purge(f.ipt4, f.ipt6, f.rtnl, NULL, "FIRC_", &p, &rep) != FIRC_OK);
    ASSERTm("the routes were still taken", rep.routes_ok);
    down(&f);
    PASS();
}

/* Catches: a file that cannot be removed not failing the purge. */
TEST a_file_that_cannot_be_removed_fails_the_purge(void) {
    if (geteuid() == 0) { SKIPm("permissions do not bind root"); }
    fx_t f;
    ASSERT(up(&f));
    char keep_dir[64] = "/tmp/firc-purge-keep-XXXXXX";
    ASSERT(mkdtemp(keep_dir) != NULL);
    char kept[128];
    snprintf(kept, sizeof(kept), "%s/firc.sock", keep_dir);
    FILE *fp = fopen(kept, "w");
    ASSERT(fp != NULL);
    fclose(fp);
    ASSERT_EQ(0, chmod(keep_dir, 0555));
    firc_purge_paths_t p = paths_of(&f);
    p.sock = kept;
    unlink(f.sock);
    firc_purge_report_t rep;
    ASSERT(firc_purge(f.ipt4, f.ipt6, f.rtnl, NULL, "FIRC_", &p, &rep) != FIRC_OK);
    struct stat st;
    ASSERTm("the run dir itself went", stat(f.dir, &st) != 0);
    chmod(keep_dir, 0700);
    unlink(kept);
    rmdir(keep_dir);
    down(&f);
    PASS();
}

/* Catches: missing netlink skipping the chains, or not reported. */
TEST without_netlink_the_chains_still_go(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT(firc_purge(f.ipt4, f.ipt6, NULL, NULL, "FIRC_", &p, &rep) != FIRC_OK);
    ASSERT(rep.iptables_ok);
    ASSERT_FALSE(rep.routes_ok);
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fake6, "filter", "FIRC_POOLREJECT"));
    down(&f);
    PASS();
}

/* Catches: a refused filter or mangle dump left behind by --purge (the run dir then stays). */
TEST the_refused_table_dumps_go_with_the_purge(void) {
    fx_t f;
    ASSERT(up(&f));
    static const char *const names[] = {"refused-ipv4-filter.bin", "refused-ipv4-mangle.bin",
                                        "refused-ipv4-nat.bin",    "refused-ipv6-filter.bin",
                                        "refused-ipv6-mangle.bin", "refused-ipv6-nat.bin"};
    char path[6][160];
    for (int i = 0; i < 6; i++) {
        snprintf(path[i], sizeof(path[i]), "%s/%s", f.dir, names[i]);
        FILE *fp = fopen(path[i], "w");
        ASSERT(fp != NULL);
        fputs("x", fp);
        fclose(fp);
    }
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    (void)firc_purge(f.ipt4, f.ipt6, f.rtnl, NULL, "FIRC_", &p, &rep);
    struct stat st;
    for (int i = 0; i < 6; i++) {
        ASSERT(stat(path[i], &st) != 0 && errno == ENOENT);
    }
    ASSERT(rep.run_dir_removed);
    down(&f);
    PASS();
}

/* Catches: a purge on a kernel without IPv6 failing or skipping the IPv4 tables because the v6 engine is absent. */
TEST without_an_ipv6_engine_the_ipv4_tables_still_go(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ipt_free(f.ipt6);
    f.ipt6 = NULL;
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ(FIRC_OK, firc_purge(f.ipt4, NULL, f.rtnl, NULL, "FIRC_", &p, &rep));
    ASSERT(rep.iptables_ok);
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fake4, "nat", "FIRC_old"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fake4, "filter", "FIRC_POOLREJECT"));
    down(&f);
    PASS();
}

static fake_setnl_t *crash_sets(firc_setnl_t **sets) {
    fake_setnl_t *k = fake_setnl_start(sets);
    if (k == NULL) { return NULL; }
    fake_setnl_plant(k, "FIRC_deadbeefS4", 4);
    fake_setnl_plant(k, "FIRC_deadbeefT6", 6);
    fake_setnl_plant(k, "_NDM_X", 4);
    return k;
}

TEST the_sweep_helper_with_an_empty_keep_takes_every_set_of_ours(void) {
    firc_setnl_t *sets = NULL;
    fake_setnl_t *k = crash_sets(&sets);
    ASSERT(k != NULL);
    size_t destroyed = 0;
    ASSERT_EQ(FIRC_OK, firc_purge_sets(sets, "FIRC_", &destroyed));
    ASSERT_EQ_FMT((size_t)2, destroyed, "%zu");
    ASSERT_FALSE(fake_setnl_has(k, "FIRC_deadbeefS4"));
    ASSERT_FALSE(fake_setnl_has(k, "FIRC_deadbeefT6"));
    ASSERT(fake_setnl_has(k, "_NDM_X"));
    firc_setnl_free(sets);
    fake_setnl_stop(k);
    PASS();
}

TEST purge_destroys_the_sets_and_counts_them(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_setnl_t *sets = NULL;
    fake_setnl_t *k = crash_sets(&sets);
    ASSERT(k != NULL);
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ(FIRC_OK, firc_purge(f.ipt4, f.ipt6, f.rtnl, sets, "FIRC_", &p, &rep));
    ASSERT_EQ_FMT((size_t)2, rep.sets, "%zu");
    ASSERT_FALSE(fake_setnl_has(k, "FIRC_deadbeefS4"));
    ASSERT_FALSE(fake_setnl_has(k, "FIRC_deadbeefT6"));
    ASSERT(fake_setnl_has(k, "_NDM_X"));
    firc_setnl_free(sets);
    fake_setnl_stop(k);
    down(&f);
    PASS();
}

TEST purge_with_a_busy_set_exits_nonzero(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_setnl_t *sets = NULL;
    fake_setnl_t *k = crash_sets(&sets);
    ASSERT(k != NULL);
    fake_setnl_reference(k, "FIRC_deadbeefS4", true);
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT(firc_purge(f.ipt4, f.ipt6, f.rtnl, sets, "FIRC_", &p, &rep) != FIRC_OK);
    ASSERT(rep.iptables_ok);
    ASSERT(fake_setnl_has(k, "FIRC_deadbeefS4"));
    ASSERT_FALSE(fake_setnl_has(k, "FIRC_deadbeefT6"));
    firc_setnl_free(sets);
    fake_setnl_stop(k);
    down(&f);
    PASS();
}

TEST a_kernel_without_ip_set_has_no_sets_to_sweep(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_setnl_t *sets = NULL;
    fake_setnl_t *k = fake_setnl_start(&sets);
    ASSERT(k != NULL);
    fake_setnl_no_subsystem(k);
    size_t destroyed = 7;
    ASSERT_EQ(FIRC_OK, firc_purge_sets(sets, "FIRC_", &destroyed));
    ASSERT_EQ_FMT((size_t)0, destroyed, "%zu");
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ(FIRC_OK, firc_purge(f.ipt4, f.ipt6, f.rtnl, sets, "FIRC_", &p, &rep));
    firc_setnl_free(sets);
    fake_setnl_stop(k);
    down(&f);
    PASS();
}

#define OPKG_FX "tests/unit/fixtures/opkgtun/"
#define SAVE_OK                                                                                     \
    "[{\"system\":{\"configuration\":{\"save\":{\"status\":[{\"status\":\"message\",\"code\":\"0\"," \
    "\"ident\":\"Core::ConfigurationSaver\",\"message\":\"saving (http/rci).\"}]}}}}]"
#define SAVE_REFUSED                                                                              \
    "[{\"system\":{\"configuration\":{\"save\":{\"status\":[{\"status\":\"error\",\"code\":\"1\"," \
    "\"ident\":\"Core::ConfigurationSaver\",\"message\":\"flash busy\"}]}}}}]"
#define DELETE_REFUSED                                                                        \
    "[{\"interface\":{\"status\":[{\"status\":\"error\",\"code\":\"1\",\"ident\":\"Network\"," \
    "\"message\":\"RCI refused\"}]}}]"

typedef struct {
    char log[1024];
    char *list;
    bool save_fails;
    bool delete_fails;
    const char *refuse;
    const char *routes[4];
    int n_routes;
    int64_t now;
    int sleeps;
    firc_err_t lock_rc;
    char dir[64];
    char intent[128];
} pio_t;

static pio_t g_p;

static void plog(const char *line) {
    size_t off = strlen(g_p.log);
    snprintf(g_p.log + off, sizeof g_p.log - off, "%s ", line);
}

static char *slurp_fx(const char *name) {
    char path[256];
    snprintf(path, sizeof path, OPKG_FX "%s", name);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) { return NULL; }
    char *buf = calloc(1, 65536);
    size_t n = fread(buf, 1, 65535, fp);
    buf[n] = 0;
    fclose(fp);
    return buf;
}

static firc_err_t p_get(void *ud, const char *path, char **body) {
    (void)ud;
    *body = NULL;
    if (strcmp(path, FIRC_OPKGTUN_ROUTE_PATH) == 0) {
        plog("R");
        *body = slurp_fx(g_p.n_routes > 0 ? g_p.routes[--g_p.n_routes] : "rc-route-without.json");
        return FIRC_OK;
    }
    if (strcmp(path, FIRC_OPKGTUN_LIST_PATH) != 0) {
        plog("NS");
        *body = strdup("[]");
        return FIRC_OK;
    }
    plog("L");
    if (g_p.list == NULL) { return FIRC_ERR_UPSTREAM; }
    *body = strdup(g_p.list);
    return FIRC_OK;
}

static firc_err_t p_post(void *ud, const char *body, long timeout_s, char **out) {
    (void)ud;
    (void)timeout_s;
    if (strstr(body, "\"save\"") != NULL) {
        plog("SAVE");
        *out = strdup(g_p.save_fails ? SAVE_REFUSED : SAVE_OK);
        return FIRC_OK;
    }
    if (strstr(body, "\"route\"") != NULL) {
        plog("NOROUTE");
        *out = slurp_fx("route-off.json");
        return FIRC_OK;
    }
    if (strstr(body, "\"global\"") != NULL) {
        plog("NOGLOBAL");
        *out = slurp_fx("global-off.json");
        return FIRC_OK;
    }
    plog(strstr(body, "\"no\":true") != NULL ? "DELETE" : "POST");
    bool refused = g_p.delete_fails || (g_p.refuse != NULL && strstr(body, g_p.refuse) != NULL);
    *out = refused ? strdup(DELETE_REFUSED) : slurp_fx("delete-ok.json");
    return FIRC_OK;
}

static bool p_dev(void *ud, const char *dev) {
    (void)ud;
    (void)dev;
    return false;
}

static firc_err_t p_unpersist(void *ud, const char *dev) {
    (void)ud;
    (void)dev;
    return FIRC_OK;
}

static bool p_holder(void *ud, int n, const char *own, char out[16]) {
    (void)ud;
    (void)n;
    (void)own;
    (void)out;
    return false;
}

static int64_t p_now(void *ud) {
    (void)ud;
    return g_p.now;
}

static bool p_sleep(void *ud, int ms) {
    (void)ud;
    g_p.sleeps++;
    g_p.now += ms;
    return true;
}

static firc_err_t p_lock(const char *path, int *fd) {
    (void)path;
    plog("LOCK");
    *fd = g_p.lock_rc == FIRC_OK ? 99 : -1;
    return g_p.lock_rc;
}

static firc_err_t p_revoke(void *ud) {
    (void)ud;
    plog("REVOKE");
    return FIRC_OK;
}

static atomic_bool g_pstop;

static firc_opkgtun_io_t pio_up(const char *list_fx, bool dirty) {
    free(g_p.list);
    memset(&g_p, 0, sizeof g_p);
    g_p.now = 1000;
    g_p.list = list_fx != NULL ? slurp_fx(list_fx) : NULL;
    snprintf(g_p.dir, sizeof g_p.dir, "/tmp/firc_purge_opkg_XXXXXX");
    if (mkdtemp(g_p.dir) == NULL) { abort(); }
    snprintf(g_p.intent, sizeof g_p.intent, "%s/opkgtun", g_p.dir);
    if (dirty) {
        FILE *fp = fopen(g_p.intent, "w");
        fputs("dirty\n", fp);
        fclose(fp);
    }
    firc_event_reset_for_test();
    atomic_store(&g_pstop, false);
    firc_opkgtun_io_t io = {p_get, p_post, p_dev, p_unpersist, p_holder, p_now, p_sleep, g_p.intent, &g_pstop, NULL, NULL};
    return io;
}

static void pio_down(void) {
    unlink(g_p.intent);
    char tmp[160];
    snprintf(tmp, sizeof tmp, "%s/opkgtun.tmp", g_p.dir);
    unlink(tmp);
    rmdir(g_p.dir);
    free(g_p.list);
    g_p.list = NULL;
}

static int warns_with(const char *text) {
    static firc_event_t ev[256];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, 256, &next, &dropped);
    int k = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].kind == FIRC_EVENT_LOG && ev[i].u.log.level == FIRC_LOG_WARN && strstr(ev[i].u.log.text, text) != NULL) {
            k++;
        }
    }
    return k;
}

static const firc_purge_lock_t k_lock = {p_lock, "/run/x.lock"};

TEST a_purge_beside_a_running_daemon_touches_no_record(void) {
    /* catches: the router step or the revoke placed before the lock, so a purge beside a live daemon deletes its records */
    firc_opkgtun_io_t io = pio_up("rc-list-ours.json", false);
    g_p.lock_rc = FIRC_ERR_EXIST;
    int fd = 7;
    ASSERT_EQ(1, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK ", g_p.log);
    ASSERT_EQ(-1, fd);
    pio_down();
    PASS();
}

TEST the_purge_runs_lock_sweep_save_revoke(void) {
    /* catches: a purge that revokes before its sweep, saves before its removal, or skips the save after one */
    firc_opkgtun_io_t io = pio_up("rc-list-ours.json", false);
    g_p.lock_rc = FIRC_OK;
    int fd = -1;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK L R NS DELETE SAVE REVOKE ", g_p.log);
    ASSERT_EQ(99, fd);
    pio_down();
    PASS();
}

TEST a_purge_with_no_record_of_ours_saves_nothing(void) {
    /* catches: an unconditional save, which would write the user's unsaved router changes */
    firc_opkgtun_io_t io = pio_up("rc-list-without.json", false);
    int fd = -1;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK L REVOKE ", g_p.log);
    pio_down();
    PASS();
}

TEST a_purge_with_dirty_and_nothing_to_remove_saves(void) {
    /* catches: a dirty intent file ignored, which leaves an earlier unsaved change of ours for a reboot to undo */
    firc_opkgtun_io_t io = pio_up("rc-list-without.json", true);
    int fd = -1;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK L SAVE REVOKE ", g_p.log);
    pio_down();
    PASS();
}

TEST an_unlocked_purge_sweeps_nothing_and_revokes(void) {
    /* catches: an unlocked purge that sweeps beside a daemon it cannot see, or one that skips the revoke */
    firc_opkgtun_io_t io = pio_up("rc-list-ours.json", true);
    g_p.lock_rc = FIRC_ERR_IO;
    int fd = 7;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK REVOKE ", g_p.log);
    ASSERT_EQ(-1, fd);
    ASSERT_EQ(1, warns_with("could not take the instance lock"));
    ASSERT_EQ(1, warns_with("delete OpkgTun<N> in the router"));
    pio_down();
    PASS();
}

TEST a_dead_rci_purge_is_one_pass(void) {
    /* catches: a retry or a backoff inside the purge's sweep, which holds prerm while RCI is down */
    firc_opkgtun_io_t io = pio_up(NULL, true);
    int fd = -1;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK L REVOKE ", g_p.log);
    ASSERT_EQ(0, g_p.sleeps);
    ASSERT_EQ(1, warns_with("may remain"));
    pio_down();
    PASS();
}

TEST the_router_step_removes_records_then_revokes(void) {
    /* catches: the router step revoking the token before the RCI calls that need it */
    firc_opkgtun_io_t io = pio_up("rc-list-ours.json", false);
    (void)firc_purge_router(&io, p_revoke, NULL);
    ASSERT_STR_EQ("L R NS DELETE SAVE REVOKE ", g_p.log);
    ASSERT_EQ(0, warns_with("OpkgTun"));
    pio_down();
    PASS();
}

TEST a_failed_router_step_keeps_the_exit_status(void) {
    /* catches: a router-step failure that fails --purge, so prerm retries for it, or that skips the revoke */
    firc_opkgtun_io_t io = pio_up("rc-list-ours.json", false);
    g_p.delete_fails = true;
    int fd = -1;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT(strstr(g_p.log, "DELETE") != NULL);
    ASSERT(strstr(g_p.log, "REVOKE ") != NULL);
    ASSERT_EQ(1, warns_with("firc's OpkgTun records may remain; delete OpkgTun<N> in the router"));
    pio_down();
    PASS();
}

TEST a_refused_removal_with_nothing_unsaved_saves_nothing(void) {
    /* catches: dirty kept after a delete NDM refused whole, so the purge saves changes that are not its own */
    firc_opkgtun_io_t io = pio_up("rc-list-ours.json", false);
    g_p.delete_fails = true;
    (void)firc_purge_router(&io, p_revoke, NULL);
    ASSERT_STR_EQ("L R NS DELETE L REVOKE ", g_p.log);
    pio_down();
    PASS();
}

TEST a_failed_save_after_removal_says_they_come_back(void) {
    /* catches: a removal whose save failed reported as done, though a reboot brings the records back */
    firc_opkgtun_io_t io = pio_up("rc-list-ours.json", false);
    g_p.save_fails = true;
    int fd = -1;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK L R NS DELETE SAVE REVOKE ", g_p.log);
    ASSERT_EQ(1, warns_with("they come back after a reboot"));
    ASSERT_EQ(0, warns_with("may remain"));
    pio_down();
    PASS();
}

TEST a_purge_removes_the_route_first(void) {
    /* catches: a purge that deletes the interface with its route line still there, or clears global first */
    firc_opkgtun_io_t io = pio_up(NULL, false);
    g_p.routes[0] = "rc-route-after-off.json";
    g_p.routes[1] = "rc-route-with.json";
    g_p.n_routes = 2;
    g_p.list = strdup("{\"OpkgTun9\":{\"description\":\"firc:a\",\"ip\":{\"global\":{\"order\":2,"
                      "\"priority\":1}},\"up\":true}}");
    int fd = -1;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK L R NOROUTE R NOGLOBAL NS DELETE SAVE REVOKE ", g_p.log);
    ASSERT_EQ(1, warns_with("OpkgTun9 was removed; router policies that used it no longer have it"));
    pio_down();
    PASS();
}

TEST a_failed_route_removal_in_the_purge_leaves_the_record(void) {
    /* catches: a purge that deletes an interface whose route line NDM kept */
    firc_opkgtun_io_t io = pio_up(NULL, false);
    g_p.list = strdup("{\"OpkgTun9\":{\"description\":\"firc:a\",\"ip\":{\"global\":{\"order\":2,"
                      "\"priority\":1}},\"up\":true}}");
    g_p.routes[0] = "rc-route-with.json";
    g_p.routes[1] = "rc-route-with.json";
    g_p.n_routes = 2;
    int fd = -1;
    ASSERT_EQ(0, firc_purge_begin(&k_lock, &io, p_revoke, NULL, &fd));
    ASSERT_STR_EQ("LOCK L R NOROUTE R SAVE REVOKE ", g_p.log);
    ASSERT_EQ(1, warns_with("the router kept the default route via OpkgTun9"));
    ASSERT_EQ(1, warns_with("firc's OpkgTun records may remain; delete OpkgTun<N> in the router"));
    pio_down();
    PASS();
}

TEST a_partial_removal_whose_save_failed_says_both(void) {
    /* catches: a purge that removed some records, kept others and could not save, naming only those that remain */
    firc_opkgtun_io_t io = pio_up(NULL, false);
    g_p.list = strdup("{\"OpkgTun2\":{\"description\":\"firc:a\",\"up\":true},"
                      "\"OpkgTun9\":{\"description\":\"firc:b\",\"up\":true}}");
    g_p.refuse = "OpkgTun9";
    g_p.save_fails = true;
    (void)firc_purge_router(&io, p_revoke, NULL);
    ASSERT_STR_EQ("L R NS DELETE R NS DELETE L SAVE REVOKE ", g_p.log);
    ASSERT_EQ(1, warns_with("may remain"));
    ASSERT_EQ(1, warns_with("they come back after a reboot"));
    pio_down();
    PASS();
}

TEST a_failed_save_of_an_earlier_run_s_removal_warns(void) {
    /* catches: a dirty file from an earlier run whose save fails now, so records deleted unsaved come back silently */
    firc_opkgtun_io_t io = pio_up("rc-list-without.json", true);
    g_p.save_fails = true;
    (void)firc_purge_router(&io, p_revoke, NULL);
    ASSERT_STR_EQ("L SAVE REVOKE ", g_p.log);
    ASSERT_EQ(1, warns_with("they come back after a reboot"));
    pio_down();
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(nothing_of_ours_is_left_and_nothing_of_anyone_elses_is_touched);
    RUN_TEST(a_raced_iptables_write_is_retried);
    RUN_TEST(a_route_the_kernel_will_not_delete_is_reported_not_hidden);
    RUN_TEST(a_route_still_there_after_a_tolerated_delete_is_reported);
    RUN_TEST(a_rule_the_kernel_will_not_delete_fails_the_purge);
    RUN_TEST(a_file_that_cannot_be_removed_fails_the_purge);
    RUN_TEST(every_step_runs_whatever_the_earlier_ones_did);
    RUN_TEST(without_netlink_the_chains_still_go);
    RUN_TEST(the_refused_table_dumps_go_with_the_purge);
    RUN_TEST(without_an_ipv6_engine_the_ipv4_tables_still_go);
    RUN_TEST(the_sweep_helper_with_an_empty_keep_takes_every_set_of_ours);
    RUN_TEST(purge_destroys_the_sets_and_counts_them);
    RUN_TEST(purge_with_a_busy_set_exits_nonzero);
    RUN_TEST(a_kernel_without_ip_set_has_no_sets_to_sweep);
    RUN_TEST(a_purge_beside_a_running_daemon_touches_no_record);
    RUN_TEST(the_purge_runs_lock_sweep_save_revoke);
    RUN_TEST(a_purge_with_no_record_of_ours_saves_nothing);
    RUN_TEST(a_purge_with_dirty_and_nothing_to_remove_saves);
    RUN_TEST(an_unlocked_purge_sweeps_nothing_and_revokes);
    RUN_TEST(a_dead_rci_purge_is_one_pass);
    RUN_TEST(the_router_step_removes_records_then_revokes);
    RUN_TEST(a_failed_router_step_keeps_the_exit_status);
    RUN_TEST(a_refused_removal_with_nothing_unsaved_saves_nothing);
    RUN_TEST(a_failed_save_after_removal_says_they_come_back);
    RUN_TEST(a_partial_removal_whose_save_failed_says_both);
    RUN_TEST(a_purge_removes_the_route_first);
    RUN_TEST(a_failed_route_removal_in_the_purge_leaves_the_record);
    RUN_TEST(a_failed_save_of_an_earlier_run_s_removal_warns);
    GREATEST_MAIN_END();
}
