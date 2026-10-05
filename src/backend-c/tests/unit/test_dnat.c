#include "greatest.h"

#include <stdio.h>
#include <string.h>

#include "fake_iptables.h"
#include "firc/dnat.h"
#include "firc/netfilter_cleaner.h"

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
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", &real));

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f));
    firc_netfilter_register_base_chains(ipt, NULL);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap_, NULL, NULL));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    static const char *want[] = {"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination",
                                 "93.184.216.34"};
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", want, 6));
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
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f));
    firc_netfilter_register_base_chains(ipt, NULL);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap_, NULL, NULL));
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
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "dual.example.com", &real4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "dual.example.com", &real6));

    firc_fake_ipt_t *f4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *i4 = firc_ipt_new(firc_fake_ipt_as_executable(f4));
    firc_netfilter_register_base_chains(i4, NULL);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(i4, "FIRC_", snap_, NULL, NULL));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(i4));

    firc_fake_ipt_t *f6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *i6 = firc_ipt_new(firc_fake_ipt_as_executable(f6));
    firc_netfilter_register_base_chains(NULL, i6);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(i6, "FIRC_", snap_, NULL, NULL));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(i6));

    ASSERT_EQ_FMT((size_t)1, rule_count(f4, "nat", "FIRC_DNAT"), "%zu");
    ASSERT_EQ_FMT((size_t)1, rule_count(f6, "nat", "FIRC_DNAT"), "%zu");

    static const char *w4[] = {"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination", "1.2.3.4"};
    ASSERT(has_rule(f4, "nat", "FIRC_DNAT", w4, 6));

    static const char *w6[] = {"-d", "fd37:9a00::1/128", "-j", "DNAT", "--to-destination",
                               "2001:db8::1"};
    ASSERT(has_rule(f6, "nat", "FIRC_DNAT", w6, 6));

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
        ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, name, &real));
    }

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f));
    firc_netfilter_register_base_chains(ipt, NULL);
    {
        firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
        ASSERT(snap_ != NULL);
        ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap_, NULL, NULL));
        firc_fakeip_snapshot_free(snap_);
    }
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_EQ_FMT((size_t)10, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    static const char *first[] = {"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination",
                                  "10.0.0.1"};
    static const char *tenth[] = {"-d", "198.18.0.10/32", "-j", "DNAT", "--to-destination",
                                  "10.0.0.10"};
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", first, 6));
    ASSERT(has_rule(f, "nat", "FIRC_DNAT", tenth, 6));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a moved name's old pair losing its rule before its quarantine ends. */
TEST a_moved_names_old_address_keeps_its_rule(void) {
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ip_t fake4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &fake4, NULL));
    firc_ip_t real = v4(93, 184, 216, 34);
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", &real));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g2", 1000, &fake4, NULL));
    firc_ip_t real2 = v4(93, 184, 216, 35);
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", &real2));

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f));
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fakeip_snapshot_t *snap_ = firc_fakeip_snapshot_take(pool);
    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap_, NULL, NULL));
    firc_fakeip_snapshot_free(snap_);
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    static const char *old_rule[] = {"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination",
                                     "93.184.216.34"};
    static const char *new_rule[] = {"-d", "198.18.1.1/32", "-j", "DNAT", "--to-destination",
                                     "93.184.216.35"};
    ASSERTm("the parked pair, as it was when parked", has_rule(f, "nat", "FIRC_DNAT", old_rule, 6));
    ASSERTm("the new pair", has_rule(f, "nat", "FIRC_DNAT", new_rule, 6));
    ASSERT_EQ_FMT((size_t)2, rule_count(f, "nat", "FIRC_DNAT"), "%zu");

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST without_a_pool_only_the_chain_is_staged(void) {
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f));
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
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "a.example.com", &r1));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(pool, "b.example.com", &r2));
    char d1[24], d2[24];
    snprintf(d1, sizeof(d1), "%u.%u.%u.%u/32", f1.b[0], f1.b[1], f1.b[2], f1.b[3]);
    snprintf(d2, sizeof(d2), "%u.%u.%u.%u/32", f2.b[0], f2.b[1], f2.b[2], f2.b[3]);

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f));
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    ASSERT(snap != NULL);

    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap, only_g1, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    const char *want1[] = {"-d", d1, "-j", "DNAT", "--to-destination", "93.184.216.34"};
    const char *want2[] = {"-d", d2, "-j", "DNAT", "--to-destination", "104.18.32.7"};
    ASSERTm("the routed group's mapping is rewritten", has_rule(f, "nat", "FIRC_DNAT", want1, 6));
    ASSERT_FALSEm("the other group's is not", has_rule(f, "nat", "FIRC_DNAT", want2, 6));
    ASSERT_EQ_FMT((size_t)1, rule_count(f, "nat", "FIRC_DNAT"), "%zu");
    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERTm("the guarded jump is there either way", has_rule(f, "nat", "PREROUTING", jump, 4));

    ASSERT_EQ(FIRC_OK, firc_dnat_build_rules(ipt, "FIRC_", snap, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERTm("NULL is every group", has_rule(f, "nat", "FIRC_DNAT", want1, 6) &&
                                   has_rule(f, "nat", "FIRC_DNAT", want2, 6));

    firc_fakeip_snapshot_free(snap);
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
    RUN_TEST(a_moved_names_old_address_keeps_its_rule);
    RUN_TEST(without_a_pool_only_the_chain_is_staged);
    RUN_TEST(only_a_routed_groups_mappings_are_rewritten);
    GREATEST_MAIN_END();
}
