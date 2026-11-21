#include "greatest.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "fake_iptables.h"
#include "xt_golden.h"
#include "firc/dnat.h"
#include "firc/ipset_to_link.h"
#include "firc/mark.h"
#include "firc/netfilter_cleaner.h"
#include "firc/port_remap.h"

static bool has_rule(firc_fake_ipt_t *f, const char *table, const char *chain,
                     const char *const *want, size_t n_want) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        if (rules[i]->n_parts != n_want) { continue; }
        size_t j = 0;
        for (; j < n_want; j++) {
            if (strcmp(rules[i]->parts[j], want[j]) != 0) { break; }
        }
        if (j == n_want) { return true; }
    }
    return false;
}

static size_t rule_count(firc_fake_ipt_t *f, const char *table, const char *chain) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return 0; }
    return n;
}

static firc_fakeip_cfg_t cfg(void) {
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
    return c;
}

static firc_err_t mark_group(firc_ipt_t *ipt, const firc_fakeip_snapshot_t *snap, const char *gid, uint32_t field) {
    uint32_t mark = 0;
    if (!firc_mark_for_field(field, &mark)) { return FIRC_ERR_INVAL; }
    char chain[32];
    snprintf(chain, sizeof(chain), "FIRC_%s", gid);
    return firc_ipset_to_link_build_rules(ipt, chain, "lo", mark, field, snap, gid);
}

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c2, uint8_t d) {
    firc_ip_t p = {{a, b, c2, d}, 4};
    return p;
}

/* Catches: a resolved mapping written as anything but one rule keyed on the host address. */
TEST a_resolved_mapping_becomes_one_host_rule(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));

    firc_ip_t fake4 = {{0}, 0}, fake6 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &fake4, &fake6));
    ASSERT_EQ_FMT(1, (int)fake4.b[3], "%d");

    firc_ip_t real = v4(93, 184, 216, 34);
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", "g1", &real));

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap_, NULL, NULL));
        ASSERT_EQ(FIRC_OK, mark_group(ipt, snap_, "g1", 1));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    static const char *want[] = {"-d", "198.18.0.1/32", "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination",
                                 "93.184.216.34"};
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", want, 10));
    ASSERT_EQ_FMTm("one mapping, one rule", (size_t)1, rule_count(f, "nat", "FIRC_DNAT"), "%zu");

    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERT(has_rule(f, "nat", "PREROUTING", jump, 4));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a rule written for a mapping with no real address. */
TEST an_unresolved_mapping_contributes_no_rule(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));

    firc_ip_t a = {{0}, 0}, b = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "unresolved.example.com", "g1", 1000, &a, &b));

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap_, NULL, NULL));
        ASSERT_EQ(FIRC_OK, mark_group(ipt, snap_, "g1", 1));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_EQ_FMTm("no real address means no rule", (size_t)0, rule_count(f, "nat", "FIRC_DNAT"),
                   "%zu");
    ASSERT(firc_fake_ipt_chain_exists(f, "nat", "FIRC_DNAT"));
    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERT(has_rule(f, "nat", "PREROUTING", jump, 4));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a v6 rule in the v4 table, which fails the whole commit. */
TEST each_family_gets_only_its_own_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));

    firc_ip_t fake4 = {{0}, 0}, fake6 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "dual.example.com", "g1", 1000, &fake4, &fake6));
    firc_ip_t real4 = v4(1, 2, 3, 4);
    firc_ip_t real6 = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "dual.example.com", "g1", &real4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "dual.example.com", "g1", &real6));

    firc_fake_ipt_t *f4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *i4 = firc_ipt_new(firc_fake_ipt_as_xt(f4), "FIRC_");
    firc_netfilter_register_base_chains(i4, NULL);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(i4, "FIRC_", snap_, NULL, NULL));
        ASSERT_EQ(FIRC_OK, mark_group(i4, snap_, "g1", 1));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(i4));

    firc_fake_ipt_t *f6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *i6 = firc_ipt_new(firc_fake_ipt_as_xt(f6), "FIRC_");
    firc_netfilter_register_base_chains(NULL, i6);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(i6, "FIRC_", snap_, NULL, NULL));
        ASSERT_EQ(FIRC_OK, mark_group(i6, snap_, "g1", 1));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(i6));

    ASSERT_EQ_FMT((size_t)1, rule_count(f4, "nat", "FIRC_DNAT"), "%zu");
    ASSERT_EQ_FMT((size_t)1, rule_count(f6, "nat", "FIRC_DNAT"), "%zu");

    static const char *w4[] = {"-d", "198.18.0.1/32", "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination", "1.2.3.4"};
    ASSERT(has_rule(f4, "nat", "FIRC_DNAT", w4, 10));

    static const char *w6[] = {"-d", "fd37:9a00::1/128", "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination",
                               "2001:db8::1"};
    ASSERT(has_rule(f6, "nat", "FIRC_DNAT", w6, 10));

    firc_ipt_rule_t *const *rr = NULL;
    size_t n = 0;
    firc_fake_ipt_get_rules(f4, "nat", "FIRC_DNAT", &rr, &n);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < rr[i]->n_parts; j++) {
            if (strchr(rr[i]->parts[j], ':') != NULL) { FAILm("a v6 address reached the v4 table"); }
        }
    }
    firc_fake_ipt_get_rules(f6, "nat", "FIRC_DNAT", &rr, &n);
    for (size_t i = 0; i < n; i++) {
        if (rr[i]->n_parts > 1 && strcmp(rr[i]->parts[1], "198.18.0.1/32") == 0) {
            FAILm("a v4 address reached the v6 table");
        }
    }

    firc_ipt_free(i4);
    firc_ipt_free(i6);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a builder emitting only the first or the last mapping's rule. */
TEST every_resolved_mapping_gets_its_own_rule(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));

    char name[64];
    for (int i = 0; i < 10; i++) {
        firc_ip_t a = {{0}, 0}, b = {{0}, 0};
        snprintf(name, sizeof(name), "h%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, name, "g1", 1000, &a, &b));
        firc_ip_t real = v4(10, 0, 0, (uint8_t)(i + 1));
        ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, name, "g1", &real));
    }

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap_, NULL, NULL));
        ASSERT_EQ(FIRC_OK, mark_group(ipt, snap_, "g1", 1));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_EQ_FMT((size_t)10, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    static const char *first[] = {"-d", "198.18.0.1/32", "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination",
                                  "10.0.0.1"};
    static const char *tenth[] = {"-d", "198.18.0.10/32", "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination",
                                  "10.0.0.10"};
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", first, 10));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", tenth, 10));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a reclaimed pair losing its rule before its quarantine ends while the name's other group still maps it. */
TEST a_reclaimed_pair_keeps_its_rule_beside_the_other_groups_pair(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t fake4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &fake4, NULL));
    firc_ip_t real = v4(93, 184, 216, 34);
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", "g1", &real));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g2", 1000 + 86400 - 1, &fake4, NULL));
    firc_ip_t real2 = v4(93, 184, 216, 35);
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", "g2", &real2));
    firc_fakeip_reclaim(pool, 1000 + 86400);
    firc_ip_t parked = v4(198, 18, 0, 1);
    ASSERT_EQm("g1's mapping is parked, not live", NULL, firc_fakeip_name_of(pool, &parked));

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap_, NULL, NULL));
    ASSERT_EQ(FIRC_OK, mark_group(ipt, snap_, "g1", 1));
    ASSERT_EQ(FIRC_OK, mark_group(ipt, snap_, "g2", 2));
    firc_fakeip_snapshot_free(snap_);
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    static const char *old_rule[] = {"-d", "198.18.0.1/32", "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination",
                                     "93.184.216.34"};
    static const char *new_rule[] = {"-d", "198.18.1.1/32", "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination",
                                     "93.184.216.35"};
    ASSERTm("the parked pair, as it was when parked", has_rule(f, "nat", "FIRC_DNAT", old_rule, 10));
    ASSERTm("the new pair", has_rule(f, "nat", "FIRC_DNAT", new_rule, 10));
    ASSERT_EQ_FMT((size_t)2, rule_count(f, "nat", "FIRC_DNAT"), "%zu");

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST without_a_pool_only_the_chain_is_staged(void) {
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", NULL, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT(firc_fake_ipt_chain_exists(f, "nat", "FIRC_DNAT"));
    ASSERT_EQ_FMT((size_t)0, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    ASSERT_FALSEm("no pool means no prefix to guard a jump with", 
                  has_rule(f, "nat", "PREROUTING", (const char *[]){"-j", "FIRC_DNAT"}, 2));
    firc_ipt_free(ipt);
    PASS();
}

static bool only_g1(const char *group_id, void *ud) {
    (void)ud;
    return strcmp(group_id, "g1") == 0;
}

/* Catches: DNAT rules for an unrouted group, the wrong group, or NULL not meaning every group. */
TEST only_a_routed_groups_mappings_are_rewritten(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t f1 = {{0}, 0}, f2 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &f1, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "b.example.com", "g2", 1000, &f2, NULL));
    firc_ip_t r1 = v4(93, 184, 216, 34), r2 = v4(104, 18, 32, 7);
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", "g1", &r1));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "b.example.com", "g2", &r2));
    char d1[24], d2[24];
    snprintf(d1, sizeof(d1), "%u.%u.%u.%u/32", f1.b[0], f1.b[1], f1.b[2], f1.b[3]);
    snprintf(d2, sizeof(d2), "%u.%u.%u.%u/32", f2.b[0], f2.b[1], f2.b[2], f2.b[3]);

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    ASSERT(snap != NULL);

    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap, only_g1, NULL));
    ASSERT_EQ(FIRC_OK, mark_group(ipt, snap, "g1", 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    const char *want1[] = {"-d", d1, "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination", "93.184.216.34"};
    const char *want2[] = {"-d", d2, "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination", "104.18.32.7"};
    ASSERTm("the routed group's mapping is rewritten", has_rule(f, "nat", "FIRC_DNAT", want1, 10));
    ASSERT_FALSEm("the other group's is not", has_rule(f, "nat", "FIRC_DNAT", want2, 10));
    ASSERT_EQ_FMT((size_t)1, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERTm("the guarded jump is there either way", has_rule(f, "nat", "PREROUTING", jump, 4));

    ASSERT_EQ(FIRC_OK, firc_netfilter_register_base_chains(ipt, NULL));
    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap, NULL, NULL));
    ASSERT_EQ(FIRC_OK, mark_group(ipt, snap, "g1", 1));
    ASSERT_EQ(FIRC_OK, mark_group(ipt, snap, "g2", 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERTm("NULL is every group", has_rule(f, "nat", "FIRC_DNAT", want1, 10) &&
                                   has_rule(f, "nat", "FIRC_DNAT", want2, 10));

    firc_fakeip_snapshot_free(snap);
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: dnat registering nat/PREROUTING itself, which drops every jump another builder staged there. */
TEST the_dnat_jump_joins_what_others_staged_in_prerouting(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    ASSERT_EQ(FIRC_OK, firc_netfilter_register_base_chains(ipt, NULL));
    static const char *other[] = {"-j", "FIRC_OTHER"};
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_OTHER"));
    ASSERT_EQ(FIRC_OK, firc_ipt_insert(ipt, "nat", "PREROUTING", 1, other, 2));
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    ASSERT(snap != NULL);
    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERT(has_rule(f, "nat", "PREROUTING", jump, 4));
    ASSERTm("the jump staged before it stays", has_rule(f, "nat", "PREROUTING", other, 2));
    firc_fakeip_snapshot_free(snap);
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: dnat staging into nat/PREROUTING without the caller having registered it as a patch chain. */
TEST dnat_without_the_base_chain_is_refused(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    ASSERT(snap != NULL);
    ASSERT_EQ(FIRC_ERR_STATE, firc_dnat_build_rules(ipt, "FIRC_", snap, NULL, NULL));
    firc_fakeip_snapshot_free(snap);
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the DNS remap needing a caller to have registered nat/PREROUTING, which a commit before it used up. */
TEST the_dns_remap_registers_its_own_base_chain(void) {
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_remap_addr_t a = {AF_INET, {192, 168, 1, 1}, 4};
    firc_port_remap_t *p = firc_port_remap_new("FIRC_", 53, 3553, &a, 1, ipt, NULL);
    ASSERT(p != NULL);
    ASSERT_EQ(FIRC_OK, firc_port_remap_enable(p));
    ASSERT(firc_fake_ipt_chain_exists(f, "nat", "FIRC_DNSOR"));
    firc_port_remap_free(p);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a DNAT rule without the handled-bit condition, which rewrites a fake address once the firmware wiped the marks. */
TEST a_wiped_mangle_leaves_only_conditional_dnat(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t fake4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &fake4, NULL));
    firc_ip_t real = v4(93, 184, 216, 34);
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", "g1", &real));

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    ASSERT(snap != NULL);
    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap, NULL, NULL));
    ASSERT_EQ(FIRC_OK, mark_group(ipt, snap, "g1", 1));
    firc_fakeip_snapshot_free(snap);
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(rule_count(f, "mangle", "FIRC_g1") > 0);

    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_test_xt_read("m-firmware", FIRC_IPT_PROTO_IPV4, &info, &blob));
    ASSERT(firc_fake_xt_load(firc_fake_ipt_xt(f), "mangle", &info, blob));
    free(blob);
    ASSERT_FALSEm("the firmware's mangle holds no mark of ours", firc_fake_ipt_chain_exists(f, "mangle", "FIRC_g1"));

    static const char *want[] = {"-d", "198.18.0.1/32", "-m", "mark", "--mark", "0x40000000/0x40000000",
                                 "-j", "DNAT", "--to-destination", "93.184.216.34"};
    ASSERT_EQ_FMT((size_t)1, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    ASSERTm("the rewrite left in nat asks for the handled bit", has_rule(f, "nat", "FIRC_DNAT", want, 10));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the port-53 remap made conditional on firc's mark, which no LAN query carries. */
TEST the_dns_remap_asks_for_no_mark(void) {
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_remap_addr_t a = {AF_INET, {192, 168, 1, 1}, 4};
    firc_port_remap_t *p = firc_port_remap_new("FIRC_", 53, 3553, &a, 1, ipt, NULL);
    ASSERT(p != NULL);
    ASSERT_EQ(FIRC_OK, firc_port_remap_enable(p));
    static const char *tcp[] = {"-d", "192.168.1.1/32", "-p", "tcp", "-m", "tcp", "--dport", "53",
                                "-j", "DNAT", "--to-destination", ":3553"};
    static const char *udp[] = {"-d", "192.168.1.1/32", "-p", "udp", "-m", "udp", "--dport", "53",
                                "-j", "DNAT", "--to-destination", ":3553"};
    ASSERT_EQ_FMT((size_t)2, rule_count(f, "nat", "FIRC_DNSOR"), "%zu");
    ASSERT(has_rule(f, "nat", "FIRC_DNSOR", tcp, 12));
    ASSERT(has_rule(f, "nat", "FIRC_DNSOR", udp, 12));
    firc_port_remap_free(p);
    firc_ipt_free(ipt);
    PASS();
}

static ssize_t rule_index(firc_fake_ipt_t *f, const char *chain, const char *const *want, size_t n_want) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, "nat", chain, &rules, &n)) { return -1; }
    for (size_t i = 0; i < n; i++) {
        if (rules[i]->n_parts != n_want) { continue; }
        size_t j = 0;
        for (; j < n_want; j++) {
            if (strcmp(rules[i]->parts[j], want[j]) != 0) { break; }
        }
        if (j == n_want) { return (ssize_t)i; }
    }
    return -1;
}

static bool any_rule_has(firc_fake_ipt_t *f, const char *chain, const char *part) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, "nat", chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < rules[i]->n_parts; j++) {
            if (strcmp(rules[i]->parts[j], part) == 0) { return true; }
        }
    }
    return false;
}

static firc_fake_ipt_t *commit_pool(firc_fakeip_t *pool, firc_ipt_proto_t proto, firc_dnat_routed_fn routed,
                                    firc_ipt_t **ipt_out) {
    firc_fake_ipt_t *f = firc_fake_ipt_new(proto);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    if (snap == NULL || firc_dnat_build_rules(ipt, "FIRC_", snap, routed, NULL) != FIRC_OK ||
        mark_group(ipt, snap, "g1", 1) != FIRC_OK || mark_group(ipt, snap, "g2", 2) != FIRC_OK ||
        firc_ipt_commit(ipt) != FIRC_OK) {
        firc_ipt_free(ipt);
        firc_fake_ipt_free(f);
        firc_fakeip_snapshot_free(snap);
        return NULL;
    }
    firc_fakeip_snapshot_free(snap);
    *ipt_out = ipt;
    return f;
}

static firc_err_t cf_name(firc_fakeip_t *pool, const char *name, const char *gid, int64_t now,
                          const firc_ip_t *real) {
    firc_ip_t a, b;
    firc_err_t err = firc_fakeip_get_in(pool, name, gid, now, FIRC_FAKEIP_KIND_CF, &a, &b);
    return err != FIRC_OK ? err : firc_fakeip_set_real(pool, name, gid, real);
}

#define TCP_RANGE(cidr, to) {"-d", cidr, "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "mark", \
                             "--mark", "0x40000000/0x40000000", "-j", "DNAT", "--to-destination", to}
#define UDP_RANGE(cidr, to) {"-d", cidr, "-p", "udp", "-m", "udp", "--dport", "443", "-m", "mark", "--mark", \
                             "0x40000000/0x40000000", "-j", "DNAT", "--to-destination", to}
#define HOST_RULE(fake, to) {"-d", fake, "-m", "mark", "--mark", "0x40000000/0x40000000", "-j", "DNAT", \
                             "--to-destination", to}

TEST a_cf_chunk_with_a_target_gets_two_range_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t real = v4(104, 16, 0, 1), target = v4(104, 16, 9, 9);
    ASSERT_EQ(FIRC_OK, cf_name(pool, "a.example.com", "g1", 1000, &real));
    firc_fakeip_set_cf_target(pool, "g1", FIRC_FAM_V4, &target);
    firc_ipt_t *ipt = NULL;
    firc_fake_ipt_t *f = commit_pool(pool, FIRC_IPT_PROTO_IPV4, NULL, &ipt);
    ASSERT(f != NULL);
    static const char *tcp[] = TCP_RANGE("198.18.0.0/24", "104.16.9.9");
    static const char *udp[] = UDP_RANGE("198.18.0.0/24", "104.16.9.9");
    static const char *host[] = HOST_RULE("198.18.0.1/32", "104.16.0.1");
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", tcp, 16));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", udp, 16));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", host, 10));
    ASSERT_EQ_FMT((size_t)3, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST two_cf_chunks_get_two_pairs_of_range_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    c.v4.chunk_cidr = 28;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t real = v4(104, 16, 0, 1), target = v4(104, 16, 9, 9);
    char name[32];
    for (int i = 0; i < 20; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, cf_name(pool, name, "g1", 1000, &real));
    }
    firc_fakeip_set_cf_target(pool, "g1", FIRC_FAM_V4, &target);
    firc_ipt_t *ipt = NULL;
    firc_fake_ipt_t *f = commit_pool(pool, FIRC_IPT_PROTO_IPV4, NULL, &ipt);
    ASSERT(f != NULL);
    static const char *t0[] = TCP_RANGE("198.18.0.0/28", "104.16.9.9");
    static const char *u0[] = UDP_RANGE("198.18.0.0/28", "104.16.9.9");
    static const char *t1[] = TCP_RANGE("198.18.0.16/28", "104.16.9.9");
    static const char *u1[] = UDP_RANGE("198.18.0.16/28", "104.16.9.9");
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", t0, 16));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", u0, 16));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", t1, 16));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", u1, 16));
    ASSERT_EQ_FMT((size_t)24, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST no_target_keeps_only_host_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t cover = v4(104, 16, 0, 1), other = v4(93, 184, 216, 34);
    ASSERT_EQ(FIRC_OK, cf_name(pool, "c.example.com", "g1", 1000, &cover));
    ASSERT_EQ(FIRC_OK, cf_name(pool, "x.example.com", "g1", 1000, &other));
    firc_ipt_t *ipt = NULL;
    firc_fake_ipt_t *f = commit_pool(pool, FIRC_IPT_PROTO_IPV4, NULL, &ipt);
    ASSERT(f != NULL);
    static const char *covered[] = HOST_RULE("198.18.0.1/32", "104.16.0.1");
    static const char *exception[] = HOST_RULE("198.18.0.2/32", "93.184.216.34");
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", covered, 10));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", exception, 10));
    ASSERT_FALSE(any_rule_has(f, "FIRC_DNAT", "multiport"));
    ASSERT_FALSE(any_rule_has(f, "FIRC_DNAT", "--dport"));
    ASSERT_EQ_FMT((size_t)2, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST an_unrouted_group_gets_neither_range_nor_host_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t real = v4(104, 16, 0, 1), target = v4(104, 16, 9, 9);
    ASSERT_EQ(FIRC_OK, cf_name(pool, "a.example.com", "g1", 1000, &real));
    ASSERT_EQ(FIRC_OK, cf_name(pool, "b.example.com", "g2", 1000, &real));
    firc_fakeip_set_cf_target(pool, "g1", FIRC_FAM_V4, &target);
    firc_fakeip_set_cf_target(pool, "g2", FIRC_FAM_V4, &target);
    firc_ipt_t *ipt = NULL;
    firc_fake_ipt_t *f = commit_pool(pool, FIRC_IPT_PROTO_IPV4, only_g1, &ipt);
    ASSERT(f != NULL);
    static const char *host[] = HOST_RULE("198.18.0.1/32", "104.16.0.1");
    static const char *tcp[] = TCP_RANGE("198.18.0.0/24", "104.16.9.9");
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", host, 10));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", tcp, 16));
    ASSERT_FALSE(any_rule_has(f, "FIRC_DNAT", "198.18.1.0/24"));
    ASSERT_FALSE(any_rule_has(f, "FIRC_DNAT", "198.18.1.1/32"));
    ASSERT_EQ_FMT((size_t)3, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST an_exception_comes_before_the_range_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t cover = v4(104, 16, 0, 1), other = v4(93, 184, 216, 34), target = v4(104, 16, 9, 9);
    ASSERT_EQ(FIRC_OK, cf_name(pool, "x.example.com", "g1", 1000, &other));
    ASSERT_EQ(FIRC_OK, cf_name(pool, "c.example.com", "g1", 1000, &cover));
    firc_fakeip_set_cf_target(pool, "g1", FIRC_FAM_V4, &target);
    firc_ipt_t *ipt = NULL;
    firc_fake_ipt_t *f = commit_pool(pool, FIRC_IPT_PROTO_IPV4, NULL, &ipt);
    ASSERT(f != NULL);
    static const char *exception[] = HOST_RULE("198.18.0.1/32", "93.184.216.34");
    static const char *tcp[] = TCP_RANGE("198.18.0.0/24", "104.16.9.9");
    ssize_t e = rule_index(f, "FIRC_DNAT", exception, 10), t = rule_index(f, "FIRC_DNAT", tcp, 16);
    ASSERT(e >= 0 && t >= 0);
    ASSERT(e < t);
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_parked_exception_comes_before_the_range_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t cover = v4(104, 16, 0, 1), other = v4(93, 184, 216, 34), target = v4(104, 16, 9, 9);
    ASSERT_EQ(FIRC_OK, cf_name(pool, "x.example.com", "g1", 1000, &other));
    ASSERT_EQ(FIRC_OK, cf_name(pool, "c.example.com", "g1", 1000 + 86400 - 1, &cover));
    firc_fakeip_reclaim(pool, 1000 + 86400);
    firc_ip_t parked = v4(198, 18, 0, 1);
    ASSERT_EQm("x is parked, not live", NULL, firc_fakeip_name_of(pool, &parked));
    firc_fakeip_set_cf_target(pool, "g1", FIRC_FAM_V4, &target);
    firc_ipt_t *ipt = NULL;
    firc_fake_ipt_t *f = commit_pool(pool, FIRC_IPT_PROTO_IPV4, NULL, &ipt);
    ASSERT(f != NULL);
    static const char *exception[] = HOST_RULE("198.18.0.1/32", "93.184.216.34");
    static const char *tcp[] = TCP_RANGE("198.18.0.0/24", "104.16.9.9");
    ssize_t e = rule_index(f, "FIRC_DNAT", exception, 10), t = rule_index(f, "FIRC_DNAT", tcp, 16);
    ASSERT(e >= 0 && t >= 0);
    ASSERT(e < t);
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_covered_cf_pair_comes_after_the_range_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t cover = v4(104, 16, 0, 1), target = v4(104, 16, 9, 9);
    ASSERT_EQ(FIRC_OK, cf_name(pool, "c.example.com", "g1", 1000, &cover));
    firc_fakeip_set_cf_target(pool, "g1", FIRC_FAM_V4, &target);
    firc_ipt_t *ipt = NULL;
    firc_fake_ipt_t *f = commit_pool(pool, FIRC_IPT_PROTO_IPV4, NULL, &ipt);
    ASSERT(f != NULL);
    static const char *host[] = HOST_RULE("198.18.0.1/32", "104.16.0.1");
    static const char *tcp[] = TCP_RANGE("198.18.0.0/24", "104.16.9.9");
    static const char *udp[] = UDP_RANGE("198.18.0.0/24", "104.16.9.9");
    ssize_t h = rule_index(f, "FIRC_DNAT", host, 10), t = rule_index(f, "FIRC_DNAT", tcp, 16),
            u = rule_index(f, "FIRC_DNAT", udp, 16);
    ASSERT(h >= 0 && t >= 0 && u >= 0);
    ASSERT(t < u && u < h);
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST the_v6_table_gets_v6_range_rules(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t real = {{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16};
    firc_ip_t target = {{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, 16};
    firc_ip_t v4target = v4(104, 16, 9, 9);
    ASSERT_EQ(FIRC_OK, cf_name(pool, "a.example.com", "g1", 1000, &real));
    firc_fakeip_set_cf_target(pool, "g1", FIRC_FAM_V6, &target);
    firc_fakeip_set_cf_target(pool, "g1", FIRC_FAM_V4, &v4target);
    firc_ipt_t *ipt = NULL;
    firc_fake_ipt_t *f = commit_pool(pool, FIRC_IPT_PROTO_IPV6, NULL, &ipt);
    ASSERT(f != NULL);
    static const char *tcp[] = TCP_RANGE("fd37:9a00::/64", "2606:4700::9");
    static const char *udp[] = UDP_RANGE("fd37:9a00::/64", "2606:4700::9");
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", tcp, 16));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", udp, 16));
    ASSERT_FALSE(any_rule_has(f, "FIRC_DNAT", "104.16.9.9"));
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_resolved_mapping_becomes_one_host_rule);
    RUN_TEST(an_unresolved_mapping_contributes_no_rule);
    RUN_TEST(each_family_gets_only_its_own_rules);
    RUN_TEST(every_resolved_mapping_gets_its_own_rule);
    RUN_TEST(a_reclaimed_pair_keeps_its_rule_beside_the_other_groups_pair);
    RUN_TEST(without_a_pool_only_the_chain_is_staged);
    RUN_TEST(only_a_routed_groups_mappings_are_rewritten);
    RUN_TEST(the_dnat_jump_joins_what_others_staged_in_prerouting);
    RUN_TEST(dnat_without_the_base_chain_is_refused);
    RUN_TEST(the_dns_remap_registers_its_own_base_chain);
    RUN_TEST(a_wiped_mangle_leaves_only_conditional_dnat);
    RUN_TEST(the_dns_remap_asks_for_no_mark);
    RUN_TEST(a_cf_chunk_with_a_target_gets_two_range_rules);
    RUN_TEST(two_cf_chunks_get_two_pairs_of_range_rules);
    RUN_TEST(no_target_keeps_only_host_rules);
    RUN_TEST(an_unrouted_group_gets_neither_range_nor_host_rules);
    RUN_TEST(an_exception_comes_before_the_range_rules);
    RUN_TEST(a_parked_exception_comes_before_the_range_rules);
    RUN_TEST(a_covered_cf_pair_comes_after_the_range_rules);
    RUN_TEST(the_v6_table_gets_v6_range_rules);
    GREATEST_MAIN_END();
}
