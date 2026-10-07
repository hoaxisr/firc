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
    f->ipt4 = firc_ipt_new(firc_fake_ipt_as_executable(f->fake4));
    f->ipt6 = firc_ipt_new(firc_fake_ipt_as_executable(f->fake6));
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
    ASSERT_EQ(FIRC_OK, firc_purge(f.ipt4, f.ipt6, f.rtnl, "FIRC_", &p, &rep));

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
    ASSERT_EQ_FMTm("one restore per family", (size_t)1, firc_fake_ipt_restore_calls(f.fake4), "%zu");
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
    firc_fake_ipt_fail_next_restore(f.fake4, FIRC_ERR_AGAIN);
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ(FIRC_OK, firc_purge(f.ipt4, f.ipt6, f.rtnl, "FIRC_", &p, &rep));
    ASSERT(rep.iptables_ok);
    ASSERT_EQ_FMTm("the raced write was tried again", (size_t)2, firc_fake_ipt_restore_calls(f.fake4), "%zu");
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
    ASSERT(firc_purge(f.ipt4, f.ipt6, f.rtnl, "FIRC_", &p, &rep) != FIRC_OK);
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
    for (int i = 0; i < 3; i++) { firc_fake_ipt_fail_next_restore(f.fake4, FIRC_ERR_IO); }
    firc_purge_paths_t p = paths_of(&f);
    firc_purge_report_t rep;
    ASSERT_EQ(FIRC_ERR_IO, firc_purge(f.ipt4, f.ipt6, f.rtnl, "FIRC_", &p, &rep));
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
    ASSERT_EQ_FMT(FIRC_ERR_STATE, firc_purge(f.ipt4, f.ipt6, f.rtnl, "FIRC_", &p, &rep), "%d");
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
    ASSERT(firc_purge(f.ipt4, f.ipt6, f.rtnl, "FIRC_", &p, &rep) != FIRC_OK);
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
    ASSERT(firc_purge(f.ipt4, f.ipt6, f.rtnl, "FIRC_", &p, &rep) != FIRC_OK);
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
    ASSERT(firc_purge(f.ipt4, f.ipt6, NULL, "FIRC_", &p, &rep) != FIRC_OK);
    ASSERT(rep.iptables_ok);
    ASSERT_FALSE(rep.routes_ok);
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fake6, "filter", "FIRC_POOLREJECT"));
    down(&f);
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
    GREATEST_MAIN_END();
}
