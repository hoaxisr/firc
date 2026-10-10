#include "greatest.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "fake_iptables.h"
#include "firc/ipset_to_link.h"
#include "firc/netfilter_cleaner.h"
#include "firc/mark.h"
#include "firc/fakeip.h"

static bool has_rule(firc_fake_ipt_t *f, const char *table, const char *chain,
                     const char *const *want, size_t n_want)
{
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

static bool any_arg_equals(firc_fake_ipt_t *f, const char *table, const char *chain,
                           const char *needle)
{
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < rules[i]->n_parts; j++) {
            if (strcmp(rules[i]->parts[j], needle) == 0) { return true; }
        }
    }
    return false;
}

TEST the_mark_is_written_masked(void)
{
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    ASSERT(f != NULL);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    ASSERT(ipt != NULL);
    firc_netfilter_register_base_chains(ipt, NULL);

    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(1, &mark));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g1", "nwg0", mark, 1, NULL, NULL));
    const firc_ipv4_subnet_t p[] = {{.addr = {10, 0, 0, 0}, .cidr = 8}};
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_subnet_rules(ipt, "FIRC_g1", mark, p, 1, NULL, 0));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_FALSEm("--set-mark writes all 32 bits and must never be emitted",
                  any_arg_equals(f, "mangle", "FIRC_g1", "--set-mark"));
    ASSERTm("--set-xmark is the masked form", any_arg_equals(f, "mangle", "FIRC_g1", "--set-xmark"));
    ASSERTm("group 1's mark is the group field plus the handled bit, over firc's mask",
            any_arg_equals(f, "mangle", "FIRC_g1", "0x40010000/0x40ff0000"));

    firc_ipt_free(ipt);
    PASS();
}

TEST the_masquerade_matches_the_mark_and_the_interface(void)
{
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    ASSERT(f != NULL);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    ASSERT(ipt != NULL);
    firc_netfilter_register_base_chains(ipt, NULL);

    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(2, &mark));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g2", "nwg1", mark, 2, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    static const char *want[] = {"-o",     "nwg1",                "-m", "mark",
                                 "--mark", "0x20000/0xff0000",    "-j", "MASQUERADE"};
    ASSERTm("anchored on the interface as well as the mark", has_rule(f, "nat", "FIRC_g2", want, 8));

    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a masquerade rule naming "blackhole" as a device, failing the whole commit. */
TEST a_blackhole_group_gets_no_masquerade(void)
{
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    ASSERT(f != NULL);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    ASSERT(ipt != NULL);
    firc_netfilter_register_base_chains(ipt, NULL);

    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(3, &mark));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_bh", "blackhole", mark, 3, NULL, NULL));
    const firc_ipv4_subnet_t p[] = {{.addr = {10, 0, 0, 0}, .cidr = 8}};
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_subnet_rules(ipt, "FIRC_bh", mark, p, 1, NULL, 0));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_FALSE(any_arg_equals(f, "nat", "FIRC_bh", "MASQUERADE"));
    ASSERT_FALSE(any_arg_equals(f, "filter", "FIRC_bh", "blackhole"));
    ASSERT(any_arg_equals(f, "mangle", "FIRC_bh", "--set-xmark"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: the CONNMARK save rule Keenetic needs missing from a MARK carrier. */
TEST the_connmark_rule_keenetic_needs_is_still_emitted(void)
{
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    ASSERT(f != NULL);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    ASSERT(ipt != NULL);
    firc_netfilter_register_base_chains(ipt, NULL);

    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(1, &mark));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g1", "nwg0", mark, 1, NULL, NULL));
    const firc_ipv4_subnet_t p[] = {{.addr = {10, 0, 0, 0}, .cidr = 8}};
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_subnet_rules(ipt, "FIRC_g1", mark, p, 1, NULL, 0));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERTm("CONNMARK rides on every MARK carrier",
            any_arg_equals(f, "mangle", "FIRC_g1", "CONNMARK"));
    ASSERT(any_arg_equals(f, "mangle", "FIRC_g1", "--save-mark"));

    firc_ipt_free(ipt);
    PASS();
}

/* A /22 pool in /26 chunks where one group holds two: 64 names spill into 198.18.0.64. */
static firc_fakeip_t *pool_with_two_v4_chunks(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 22;
    c.v4.chunk_cidr = 26;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.base.b[2] = 0x9a;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = 4096;
    c.idle_secs = 86400;
    c.clamp_secs = 300;

    firc_fakeip_t *f = NULL;
    if (firc_fakeip_new(&c, &f) != FIRC_OK) { return NULL; }
    char name[64];
    firc_ip_t v4, v6;
    for (int i = 0; i < 64; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        if (firc_fakeip_get(f, name, "g1", 1000, &v4, &v6) != FIRC_OK) {
            firc_fakeip_free(f);
            return NULL;
        }
    }
    return f;
}

TEST every_chunk_a_group_holds_becomes_a_rule(void)
{
    firc_fakeip_t *pool = pool_with_two_v4_chunks();
    ASSERT(pool != NULL);
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    ASSERT(snap != NULL);

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    firc_netfilter_register_base_chains(ipt, NULL);

    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(1, &mark));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g1", "nwg0", mark, 1,
                                                      snap, "g1"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    static const char *m0[] = {"-d", "198.18.0.0/26", "-j", "MARK", "--set-xmark",
                               "0x40010000/0x40ff0000"};
    static const char *m1[] = {"-d", "198.18.0.64/26", "-j", "MARK", "--set-xmark",
                               "0x40010000/0x40ff0000"};
    ASSERTm("the chunk being filled", has_rule(f, "mangle", "FIRC_g1", m0, 6));
    ASSERTm("and the one filled before it", has_rule(f, "mangle", "FIRC_g1", m1, 6));

    static const char *acc[] = {"-o",     "nwg0",             "-m", "mark",
                                "--mark", "0x10000/0xff0000", "-j", "ACCEPT"};
    ASSERTm("the forward accept anchors on the mark", has_rule(f, "filter", "FIRC_g1", acc, 8));
    ASSERT_FALSEm("a destination match in FORWARD sees the real address, never a chunk",
                  any_arg_equals(f, "filter", "FIRC_g1", "-d"));

    static const char *c0[] = {"-d", "198.18.0.0/26", "-j", "CONNMARK", "--save-mark", "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    ASSERTm("in the form iptables-save echoes, or every commit rewrites the chain",
            has_rule(f, "mangle", "FIRC_g1", c0, 9));

    ASSERT_FALSEm("a v6 prefix in the v4 table would be refused by the kernel and take "
                  "every other rule in the same buffer down with it",
                  any_arg_equals(f, "mangle", "FIRC_g1", "fd37:9a00::/64"));
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    firc_fake_ipt_get_rules(f, "mangle", "FIRC_g1", &rules, &n);
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < rules[i]->n_parts; j++) {
            if (strchr(rules[i]->parts[j], ':') != NULL) { FAILm("a v6 address reached the v4 table"); }
        }
    }

    firc_ipt_free(ipt);
    firc_fakeip_snapshot_free(snap);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the accept, masquerade or chunk rules written to the v4 engine only. */
TEST the_v6_table_gets_the_same_rules_with_v6_chunks(void)
{
    firc_fakeip_t *pool = pool_with_two_v4_chunks();
    ASSERT(pool != NULL);
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    firc_netfilter_register_base_chains(NULL, ipt);

    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(1, &mark));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g1", "nwg0", mark, 1,
                                                      snap, "g1"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    static const char *acc[] = {"-o",     "nwg0",             "-m", "mark",
                                "--mark", "0x10000/0xff0000", "-j", "ACCEPT"};
    ASSERT(has_rule(f, "filter", "FIRC_g1", acc, 8));
    static const char *masq[] = {"-o",     "nwg0",             "-m", "mark",
                                 "--mark", "0x10000/0xff0000", "-j", "MASQUERADE"};
    ASSERT(has_rule(f, "nat", "FIRC_g1", masq, 8));
    static const char *m6[] = {"-d", "fd37:9a00::/64", "-j", "MARK", "--set-xmark",
                               "0x40010000/0x40ff0000"};
    ASSERTm("the group's v6 chunk", has_rule(f, "mangle", "FIRC_g1", m6, 6));
    static const char *c6[] = {"-d", "fd37:9a00::/64", "-j", "CONNMARK", "--save-mark", "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    ASSERTm("and its CONNMARK, which Keenetic needs in both families",
            has_rule(f, "mangle", "FIRC_g1", c6, 9));
    ASSERT_FALSEm("a destination match in FORWARD sees the real address, never a chunk",
                  any_arg_equals(f, "filter", "FIRC_g1", "-d"));
    ASSERT_FALSEm("a v4 prefix in the v6 table would be refused by the kernel",
                  any_arg_equals(f, "mangle", "FIRC_g1", "198.18.0.0/26"));

    firc_ipt_free(ipt);
    firc_fakeip_snapshot_free(snap);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a subnet rule written as nothing, into the wrong family's table, or outside mangle. */
TEST a_subnet_rule_is_a_static_mark_rule_in_the_groups_chain(void)
{
    firc_fake_ipt_t *f4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt4 = firc_ipt_new(firc_fake_ipt_as_executable(f4), firc_fake_ipt_as_xt(f4));
    firc_netfilter_register_base_chains(ipt4, NULL);
    firc_fake_ipt_t *f6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt6 = firc_ipt_new(firc_fake_ipt_as_executable(f6), firc_fake_ipt_as_xt(f6));
    firc_netfilter_register_base_chains(NULL, ipt6);

    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(1, &mark));
    const firc_ipv4_subnet_t v4[] = {{.addr = {10, 1, 0, 0}, .cidr = 16}, {.addr = {0, 0, 0, 0}, .cidr = 0}};
    const firc_ipv6_subnet_t v6[] = {{.addr = {0x20, 0x01, 0x0d, 0xb8}, .cidr = 32}};
    for (int fam = 0; fam < 2; fam++) {
        firc_ipt_t *ipt = fam == 0 ? ipt4 : ipt6;
        ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g1", "nwg0", mark, 1,
                                                          NULL, NULL));
        ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_subnet_rules(ipt, "FIRC_g1", mark, v4, 2, v6, 1));
        ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    }

    static const char *m1[] = {"-d", "10.1.0.0/16", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m",
                               "mark", "!", "--mark", "0x40000000/0x40000000", "-j", "MARK", "--set-xmark",
                               "0x40010000/0x40ff0000"};
    static const char *c1[] = {"-d", "10.1.0.0/16", "-m", "conntrack", "--ctdir", "ORIGINAL",
                               "-j", "CONNMARK", "--save-mark", "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    static const char *m0[] = {"-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "mark", "!", "--mark",
                               "0x40000000/0x40000000", "-j", "MARK", "--set-xmark", "0x40010000/0x40ff0000"};
    static const char *m6[] = {"-d", "2001:db8::/32", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m",
                               "mark", "!", "--mark", "0x40000000/0x40000000", "-j", "MARK", "--set-xmark",
                               "0x40010000/0x40ff0000"};
    static const char *c6[] = {"-d", "2001:db8::/32", "-m", "conntrack", "--ctdir", "ORIGINAL",
                               "-j", "CONNMARK", "--save-mark", "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    ASSERT(has_rule(f4, "mangle", "FIRC_g1", m1, 15));
    ASSERT(has_rule(f4, "mangle", "FIRC_g1", c1, 13));
    ASSERTm("a /0 is one rule with no destination at all", has_rule(f4, "mangle", "FIRC_g1", m0, 13));
    ASSERT_FALSEm("iptables-save would never echo this form back",
                  any_arg_equals(f4, "mangle", "FIRC_g1", "0.0.0.0/0"));
    ASSERT(has_rule(f6, "mangle", "FIRC_g1", m6, 15));
    ASSERT(has_rule(f6, "mangle", "FIRC_g1", c6, 13));
    ASSERT_FALSEm("v6 prefix in the v4 table", any_arg_equals(f4, "mangle", "FIRC_g1", "2001:db8::/32"));
    ASSERT_FALSEm("v4 prefix in the v6 table", any_arg_equals(f6, "mangle", "FIRC_g1", "10.1.0.0/16"));
    ASSERT_FALSEm("nothing of it in filter", any_arg_equals(f4, "filter", "FIRC_g1", "10.1.0.0/16"));
    ASSERT_FALSEm("nothing of it in nat", any_arg_equals(f4, "nat", "FIRC_g1", "10.1.0.0/16"));

    firc_ipt_free(ipt4);
    firc_ipt_free(ipt6);
    PASS();
}

/* Catches: a subnet rule's protocol or ports left off its MARK or CONNMARK, or worded unlike iptables-save. */
TEST a_subnet_rule_with_a_protocol_marks_that_protocol_only(void) {
    firc_fake_ipt_t *f4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt4 = firc_ipt_new(firc_fake_ipt_as_executable(f4), firc_fake_ipt_as_xt(f4));
    firc_netfilter_register_base_chains(ipt4, NULL);
    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(1, &mark));
    const firc_ipv4_subnet_t v4[] = {
        {.addr = {10, 1, 0, 0}, .cidr = 16, .proto = IPPROTO_UDP, .ports = "53"},
        {.addr = {10, 2, 0, 0}, .cidr = 16, .proto = IPPROTO_TCP, .ports = "443,1000:2000"},
        {.addr = {10, 3, 0, 0}, .cidr = 16, .proto = IPPROTO_UDP},
        {.addr = {0, 0, 0, 0}, .cidr = 0, .proto = IPPROTO_UDP, .ports = "51820"},
    };
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt4, "FIRC_g1", "nwg0", mark, 1, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_subnet_rules(ipt4, "FIRC_g1", mark, v4, 4, NULL, 0));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt4));

    static const char *m1[] = {"-d", "10.1.0.0/16", "-p", "udp", "-m", "conntrack", "--ctdir", "ORIGINAL",
                               "-m", "mark", "!", "--mark", "0x40000000/0x40000000", "-m", "udp", "--dport", "53",
                               "-j", "MARK", "--set-xmark", "0x40010000/0x40ff0000"};
    static const char *c1[] = {"-d", "10.1.0.0/16", "-p", "udp", "-m", "conntrack", "--ctdir", "ORIGINAL",
                               "-m", "udp", "--dport", "53", "-j", "CONNMARK", "--save-mark",
                               "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    static const char *m2[] = {"-d", "10.2.0.0/16", "-p", "tcp", "-m", "conntrack", "--ctdir", "ORIGINAL",
                               "-m", "mark", "!", "--mark", "0x40000000/0x40000000", "-m", "multiport", "--dports",
                               "443,1000:2000", "-j", "MARK", "--set-xmark", "0x40010000/0x40ff0000"};
    static const char *m3[] = {"-d", "10.3.0.0/16", "-p", "udp", "-m", "conntrack", "--ctdir", "ORIGINAL",
                               "-m", "mark", "!", "--mark", "0x40000000/0x40000000", "-j", "MARK", "--set-xmark",
                               "0x40010000/0x40ff0000"};
    static const char *m0[] = {"-p", "udp", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "mark",
                               "!", "--mark", "0x40000000/0x40000000", "-m", "udp", "--dport", "51820", "-j", "MARK",
                               "--set-xmark", "0x40010000/0x40ff0000"};
    ASSERTm("udp, one port", has_rule(f4, "mangle", "FIRC_g1", m1, 21));
    ASSERTm("the CONNMARK twin carries the same match", has_rule(f4, "mangle", "FIRC_g1", c1, 19));
    ASSERTm("tcp, a list, through multiport", has_rule(f4, "mangle", "FIRC_g1", m2, 21));
    ASSERTm("a protocol without ports", has_rule(f4, "mangle", "FIRC_g1", m3, 17));
    ASSERTm("a /0 with a protocol still has no -d", has_rule(f4, "mangle", "FIRC_g1", m0, 19));
    const firc_ipv4_subnet_t widened[] = {{.addr = {10, 4, 0, 0}, .cidr = 16, .ports = "53"}};
    ASSERT_EQm("ports without a protocol are refused, not written wide",
               FIRC_ERR_INVAL, firc_ipset_to_link_build_subnet_rules(ipt4, "FIRC_g1", mark, widened, 1, NULL, 0));
    firc_ipt_free(ipt4);
    PASS();
}

/* Catches: a rewrite keeping a removed prefix, or duplicating the PREROUTING jump. */
TEST a_rewrite_drops_a_removed_prefix_and_keeps_one_jump(void)
{
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    firc_netfilter_register_base_chains(ipt, NULL);
    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(1, &mark));
    const firc_ipv4_subnet_t two[] = {{.addr = {10, 1, 0, 0}, .cidr = 16}, {.addr = {10, 2, 0, 0}, .cidr = 16}};

    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g1", "nwg0", mark, 1, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_subnet_rules(ipt, "FIRC_g1", mark, two, 2, NULL, 0));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(any_arg_equals(f, "mangle", "FIRC_g1", "10.2.0.0/16"));

    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g1", "nwg0", mark, 1, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_subnet_rules(ipt, "FIRC_g1", mark, two, 1, NULL, 0));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(any_arg_equals(f, "mangle", "FIRC_g1", "10.1.0.0/16"));
    ASSERT_FALSEm("the removed prefix is gone", any_arg_equals(f, "mangle", "FIRC_g1", "10.2.0.0/16"));

    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0, jumps = 0;
    ASSERT(firc_fake_ipt_get_rules(f, "mangle", "PREROUTING", &rules, &n));
    for (size_t i = 0; i < n; i++) {
        jumps += rules[i]->n_parts == 2 && strcmp(rules[i]->parts[1], "FIRC_g1") == 0;
    }
    ASSERT_EQ_FMTm("one jump, however many writes", (size_t)1, jumps, "%zu");

    firc_ipt_free(ipt);
    PASS();
}

/* Catches: prefixes handed through set_subnets not reaching each family's engine. */
TEST prefixes_set_on_the_object_reach_both_engines(void)
{
    firc_fake_ipt_t *f4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt4 = firc_ipt_new(firc_fake_ipt_as_executable(f4), firc_fake_ipt_as_xt(f4));
    firc_netfilter_register_base_chains(ipt4, NULL);
    firc_fake_ipt_t *f6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt6 = firc_ipt_new(firc_fake_ipt_as_executable(f6), firc_fake_ipt_as_xt(f6));
    firc_netfilter_register_base_chains(NULL, ipt6);

    firc_ipset_to_link_t *l = firc_ipset_to_link_new("FIRC_g1", "nwg0", ipt4, ipt6, NULL, 100,
                                                     NULL, "g1", NULL, NULL);
    ASSERT(l != NULL);
    const firc_ipv4_subnet_t v4[] = {{.addr = {10, 1, 0, 0}, .cidr = 16}};
    const firc_ipv6_subnet_t v6[] = {{.addr = {0x20, 0x01, 0x0d, 0xb8}, .cidr = 32}};
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_set_subnets(l, v4, 1, v6, 1, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_stage_for_test(l));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt4));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt6));

    ASSERT(any_arg_equals(f4, "mangle", "FIRC_g1", "10.1.0.0/16"));
    ASSERT(any_arg_equals(f6, "mangle", "FIRC_g1", "2001:db8::/32"));

    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_set_subnets(l, NULL, 0, NULL, 0, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_stage_for_test(l));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt4));
    ASSERT_FALSE(any_arg_equals(f4, "mangle", "FIRC_g1", "10.1.0.0/16"));

    firc_ipset_to_link_free(l);
    firc_ipt_free(ipt4);
    firc_ipt_free(ipt6);
    PASS();
}

static const firc_fakeip_snapshot_t *give_snapshot(void *ud) {
    return ud;
}

/* Catches: chunk rules built from the running pass's snapshot instead of the current one. */
TEST the_chunk_rules_come_from_the_snapshot_the_object_is_given(void)
{
    firc_fakeip_t *pool = pool_with_two_v4_chunks();
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    firc_fake_ipt_t *f4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt4 = firc_ipt_new(firc_fake_ipt_as_executable(f4), firc_fake_ipt_as_xt(f4));
    firc_netfilter_register_base_chains(ipt4, NULL);

    firc_ipset_to_link_t *l = firc_ipset_to_link_new("FIRC_g1", "nwg0", ipt4, NULL, NULL, 100,
                                                     NULL, "g1", give_snapshot, snap);
    ASSERT(l != NULL);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_stage_for_test(l));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt4));
    ASSERT(any_arg_equals(f4, "mangle", "FIRC_g1", "198.18.0.0/26"));
    ASSERT(any_arg_equals(f4, "mangle", "FIRC_g1", "198.18.0.64/26"));

    firc_ipset_to_link_free(l);
    firc_ipt_free(ipt4);
    firc_fakeip_snapshot_free(snap);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: chunk rules emitted for a group that holds no chunks. */
TEST a_group_with_no_chunks_emits_no_chunk_rules(void)
{
    firc_fakeip_t *pool = pool_with_two_v4_chunks();
    ASSERT(pool != NULL);
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    ASSERT(snap != NULL);

    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    firc_netfilter_register_base_chains(ipt, NULL);

    uint32_t mark = 0;
    ASSERT(firc_mark_for_field(2, &mark));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_build_rules(ipt, "FIRC_g2", "nwg1", mark, 2,
                                                      snap, "g2"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_FALSEm("another group's chunk must never appear here",
                  any_arg_equals(f, "mangle", "FIRC_g2", "198.18.0.0/26"));
    ASSERT_FALSE(any_arg_equals(f, "mangle", "FIRC_g2", "198.18.0.64/26"));

    firc_ipt_free(ipt);
    firc_fakeip_snapshot_free(snap);
    firc_fakeip_free(pool);
    PASS();
}

/* Whether the chain's rules are, in order, the given lines (each rule's words joined by spaces). */
static bool rules_are(firc_fake_ipt_t *f, const char *table, const char *chain, const char *const *want,
                      size_t n_want)
{
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n) || n != n_want) { return false; }
    for (size_t i = 0; i < n; i++) {
        char *text = firc_ipt_rule_string(rules[i]);
        bool same = text != NULL && strcmp(text, want[i]) == 0;
        free(text);
        if (!same) { return false; }
    }
    return true;
}

static size_t rule_count(firc_fake_ipt_t *f, const char *table, const char *chain)
{
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    return firc_fake_ipt_get_rules(f, table, chain, &rules, &n) ? n : 0;
}

static firc_nf_source_t v4_src(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t prefix)
{
    firc_nf_source_t s;
    memset(&s, 0, sizeof(s));
    s.kind = FIRC_NF_SRC_ADDR;
    s.family = 4;
    s.prefix = prefix;
    s.addr[0] = a;
    s.addr[1] = b;
    s.addr[2] = c;
    s.addr[3] = d;
    return s;
}

static firc_nf_source_t fd00_30(void)
{
    firc_nf_source_t s;
    memset(&s, 0, sizeof(s));
    s.kind = FIRC_NF_SRC_ADDR;
    s.family = 6;
    s.prefix = 128;
    s.addr[0] = 0xfd;
    s.addr[15] = 0x30;
    return s;
}

static firc_nf_source_t mac_src(void)
{
    firc_nf_source_t s;
    memset(&s, 0, sizeof(s));
    s.kind = FIRC_NF_SRC_MAC;
    const uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    memcpy(s.mac, mac, 6);
    return s;
}

static firc_nf_source_t mark_src(uint32_t mark)
{
    firc_nf_source_t s;
    memset(&s, 0, sizeof(s));
    s.kind = FIRC_NF_SRC_MARK;
    s.mark = mark;
    return s;
}

typedef struct {
    firc_fakeip_t *pool;
    firc_fakeip_snapshot_t *snap;
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt;
} built_t;

/* Builds group g1 as FIRC_g1 on field 5 through nwg0 over the two-chunk pool with `dev`, committed. */
static bool build_g1_subnets(built_t *b, firc_ipt_proto_t proto, const firc_nf_devices_t *dev,
                             const firc_ipv4_subnet_t *v4, size_t n4, const firc_ipv6_subnet_t *v6, size_t n6)
{
    memset(b, 0, sizeof(*b));
    b->pool = pool_with_two_v4_chunks();
    if (b->pool == NULL) { return false; }
    b->snap = firc_fakeip_snapshot_take(b->pool);
    b->f = firc_fake_ipt_new(proto);
    b->ipt = firc_ipt_new(firc_fake_ipt_as_executable(b->f), firc_fake_ipt_as_xt(b->f));
    if (b->snap == NULL || b->ipt == NULL) { return false; }
    if (proto == FIRC_IPT_PROTO_IPV6) {
        firc_netfilter_register_base_chains(NULL, b->ipt);
    } else {
        firc_netfilter_register_base_chains(b->ipt, NULL);
    }
    uint32_t mark = 0;
    if (!firc_mark_for_field(5, &mark)) { return false; }
    return firc_ipset_to_link_build_rules_dev(b->ipt, "FIRC_g1", "nwg0", mark, 5, b->snap, "g1", dev) == FIRC_OK &&
           firc_ipset_to_link_build_subnet_rules_dev(b->ipt, "FIRC_g1", mark, v4, n4, v6, n6, dev) == FIRC_OK &&
           firc_ipt_commit(b->ipt) == FIRC_OK;
}

static bool build_g1(built_t *b, firc_ipt_proto_t proto, const firc_nf_devices_t *dev)
{
    return build_g1_subnets(b, proto, dev, NULL, 0, NULL, 0);
}

static void built_free(built_t *b)
{
    firc_ipt_free(b->ipt);
    firc_fakeip_snapshot_free(b->snap);
    firc_fakeip_free(b->pool);
}

#define F5 "0x40050000/0x40ff0000"
#define F5_CONNMARK "-m mark --mark " F5 " -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000"

/* Catches: an inactive selector still writing the devices jump or chain. */
TEST a_group_without_a_selector_marks_its_chunks_as_before(void)
{
    firc_nf_devices_t none = {0};
    built_t b;
    ASSERT(build_g1(&b, FIRC_IPT_PROTO_IPV4, &none));
    static const char *mk[] = {"-d", "198.18.0.0/26", "-j", "MARK", "--set-xmark", "0x40050000/0x40ff0000"};
    ASSERT(has_rule(b.f, "mangle", "FIRC_g1", mk, 6));
    static const char *cm[] = {"-d", "198.18.0.64/26", "-j", "CONNMARK", "--save-mark", "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    ASSERT(has_rule(b.f, "mangle", "FIRC_g1", cm, 9));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(b.f, "mangle", "FIRC_g1D"));
    built_free(&b);
    PASS();
}

/* Catches: a selector group's chunk still marking, a chunk not jumped, or a MAC written in lower case. */
TEST a_selector_group_jumps_from_each_chunk_to_its_devices_chain(void)
{
    firc_nf_source_t allow[] = {mac_src()};
    firc_nf_devices_t dev = {.active = true, .allow = allow, .n_allow = 1};
    built_t b;
    ASSERT(build_g1(&b, FIRC_IPT_PROTO_IPV4, &dev));
    static const char *j0[] = {"-d", "198.18.0.0/26", "-j", "FIRC_g1D"};
    static const char *j1[] = {"-d", "198.18.0.64/26", "-j", "FIRC_g1D"};
    ASSERT(has_rule(b.f, "mangle", "FIRC_g1", j0, 4));
    ASSERT(has_rule(b.f, "mangle", "FIRC_g1", j1, 4));
    ASSERT_EQ_FMTm("the ctdir return and two jumps, nothing else", (size_t)3, rule_count(b.f, "mangle", "FIRC_g1"), "%zu");
    ASSERT_FALSE(any_arg_equals(b.f, "mangle", "FIRC_g1", "--set-xmark"));
    static const char *const want[] = {
        "-m mac --mac-source AA:BB:CC:DD:EE:FF -j MARK --set-xmark " F5,
        F5_CONNMARK,
    };
    ASSERT(rules_are(b.f, "mangle", "FIRC_g1D", want, 2));
    built_free(&b);
    PASS();
}

/* Catches: a selector group's subnet rule marking by itself, losing its guard, ctdir or ports, or keeping a CONNMARK twin, in either family. */
TEST a_selector_group_s_subnet_rule_jumps_to_its_devices_chain(void)
{
    firc_nf_source_t allow[] = {mac_src()};
    firc_nf_devices_t dev = {.active = true, .allow = allow, .n_allow = 1};
    const firc_ipv4_subnet_t v4[] = {
        {.addr = {10, 1, 0, 0}, .cidr = 16},
        {.addr = {10, 2, 0, 0}, .cidr = 16, .proto = IPPROTO_TCP, .ports = "443,1000:2000"},
        {.addr = {0, 0, 0, 0}, .cidr = 0, .proto = IPPROTO_UDP, .ports = "51820"},
    };
    const firc_ipv6_subnet_t v6[] = {{.addr = {0x20, 0x01, 0x0d, 0xb8}, .cidr = 32}};
    built_t b4, b6;
    ASSERT(build_g1_subnets(&b4, FIRC_IPT_PROTO_IPV4, &dev, v4, 3, v6, 1));
    ASSERT(build_g1_subnets(&b6, FIRC_IPT_PROTO_IPV6, &dev, v4, 3, v6, 1));

    static const char *j1[] = {"-d", "10.1.0.0/16", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "mark",
                               "!", "--mark", "0x40000000/0x40000000", "-j", "FIRC_g1D"};
    static const char *j2[] = {"-d", "10.2.0.0/16", "-p", "tcp", "-m", "conntrack", "--ctdir", "ORIGINAL",
                               "-m", "mark", "!", "--mark", "0x40000000/0x40000000", "-m", "multiport",
                               "--dports", "443,1000:2000", "-j", "FIRC_g1D"};
    static const char *j0[] = {"-p", "udp", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "mark", "!",
                               "--mark", "0x40000000/0x40000000", "-m", "udp", "--dport", "51820", "-j",
                               "FIRC_g1D"};
    static const char *j6[] = {"-d", "2001:db8::/32", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "mark",
                               "!", "--mark", "0x40000000/0x40000000", "-j", "FIRC_g1D"};
    ASSERT(has_rule(b4.f, "mangle", "FIRC_g1", j1, 13));
    ASSERT(has_rule(b4.f, "mangle", "FIRC_g1", j2, 19));
    ASSERT(has_rule(b4.f, "mangle", "FIRC_g1", j0, 17));
    ASSERT_EQ_FMTm("the ctdir return, two chunk jumps, three subnet jumps", (size_t)6,
                   rule_count(b4.f, "mangle", "FIRC_g1"), "%zu");
    ASSERT_FALSE(any_arg_equals(b4.f, "mangle", "FIRC_g1", "--set-xmark"));
    ASSERT_FALSE(any_arg_equals(b4.f, "mangle", "FIRC_g1", "CONNMARK"));
    ASSERT_FALSE(any_arg_equals(b4.f, "mangle", "FIRC_g1", "0.0.0.0/0"));
    static const char *const want[] = {
        "-m mac --mac-source AA:BB:CC:DD:EE:FF -j MARK --set-xmark " F5,
        F5_CONNMARK,
    };
    ASSERT(rules_are(b4.f, "mangle", "FIRC_g1D", want, 2));

    ASSERT(has_rule(b6.f, "mangle", "FIRC_g1", j6, 13));
    ASSERT_EQ_FMT((size_t)3, rule_count(b6.f, "mangle", "FIRC_g1"), "%zu");
    ASSERT_FALSE(any_arg_equals(b6.f, "mangle", "FIRC_g1", "10.1.0.0/16"));
    ASSERT_FALSE(any_arg_equals(b6.f, "mangle", "FIRC_g1", "--set-xmark"));
    ASSERT(rules_are(b6.f, "mangle", "FIRC_g1D", want, 2));
    built_free(&b4);
    built_free(&b6);
    PASS();
}

/* Catches: an inactive or absent selector writing the subnet jump to a devices chain that does not exist. */
TEST a_group_without_a_selector_keeps_its_subnet_mark_and_connmark(void)
{
    const firc_ipv4_subnet_t v4[] = {{.addr = {10, 1, 0, 0}, .cidr = 16}};
    static const char *m1[] = {"-d", "10.1.0.0/16", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m",
                               "mark", "!", "--mark", "0x40000000/0x40000000", "-j", "MARK", "--set-xmark",
                               "0x40050000/0x40ff0000"};
    static const char *c1[] = {"-d", "10.1.0.0/16", "-m", "conntrack", "--ctdir", "ORIGINAL",
                               "-j", "CONNMARK", "--save-mark", "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    firc_nf_devices_t none = {0};
    const firc_nf_devices_t *cases[] = {&none, NULL};
    for (size_t i = 0; i < 2; i++) {
        built_t b;
        ASSERT(build_g1_subnets(&b, FIRC_IPT_PROTO_IPV4, cases[i], v4, 1, NULL, 0));
        ASSERT(has_rule(b.f, "mangle", "FIRC_g1", m1, 15));
        ASSERT(has_rule(b.f, "mangle", "FIRC_g1", c1, 13));
        ASSERT_FALSE(any_arg_equals(b.f, "mangle", "FIRC_g1", "FIRC_g1D"));
        ASSERT_FALSE(firc_fake_ipt_chain_exists(b.f, "mangle", "FIRC_g1D"));
        built_free(&b);
    }
    PASS();
}

/* Catches: an empty allow list marking nobody, or the MARK written before the RETURN. */
TEST everyone_except_a_denied_address_is_one_return_and_one_mark(void)
{
    firc_nf_source_t deny[] = {v4_src(192, 168, 1, 30, 32)};
    firc_nf_devices_t dev = {.active = true, .allow_all = true, .deny = deny, .n_deny = 1};
    built_t b;
    ASSERT(build_g1(&b, FIRC_IPT_PROTO_IPV4, &dev));
    static const char *const want[] = {
        "-s 192.168.1.30/32 -j RETURN",
        "-j MARK --set-xmark " F5,
        F5_CONNMARK,
    };
    ASSERT(rules_are(b.f, "mangle", "FIRC_g1D", want, 3));
    built_free(&b);
    PASS();
}

/* Catches: a policy mark written unmasked, with a leading zero, under another mask, or misplaced. */
TEST a_policy_is_matched_by_its_mark_outside_firc_s_bits(void)
{
    firc_nf_source_t allow[] = {mark_src(0x0f00faabu)};
    firc_nf_source_t deny[] = {mark_src(0x0ffffaadu)};
    firc_nf_devices_t dev = {.active = true, .allow = allow, .n_allow = 1, .deny = deny, .n_deny = 1};
    built_t b;
    ASSERT(build_g1(&b, FIRC_IPT_PROTO_IPV4, &dev));
    static const char *const want[] = {
        "-m mark --mark 0xf00faad/0xbf00ffff -j RETURN",
        "-m mark --mark 0xf00faab/0xbf00ffff -j MARK --set-xmark " F5,
        F5_CONNMARK,
    };
    ASSERT(rules_are(b.f, "mangle", "FIRC_g1D", want, 3));
    built_free(&b);
    PASS();
}

/* Catches: a v4 source written to ip6tables, v6 left out, or the v6 group chain still marking. */
TEST each_family_gets_its_own_sources(void)
{
    firc_nf_source_t deny[] = {v4_src(192, 168, 1, 30, 32), fd00_30()};
    firc_nf_source_t allow[] = {mac_src()};
    firc_nf_devices_t dev = {.active = true, .deny = deny, .n_deny = 2, .allow = allow, .n_allow = 1};
    built_t b4, b6;
    ASSERT(build_g1(&b4, FIRC_IPT_PROTO_IPV4, &dev));
    ASSERT(build_g1(&b6, FIRC_IPT_PROTO_IPV6, &dev));
    static const char *const want4[] = {
        "-s 192.168.1.30/32 -j RETURN",
        "-m mac --mac-source AA:BB:CC:DD:EE:FF -j MARK --set-xmark " F5,
        F5_CONNMARK,
    };
    static const char *const want6[] = {
        "-s fd00::30/128 -j RETURN",
        "-m mac --mac-source AA:BB:CC:DD:EE:FF -j MARK --set-xmark " F5,
        F5_CONNMARK,
    };
    ASSERT(rules_are(b4.f, "mangle", "FIRC_g1D", want4, 3));
    ASSERT(rules_are(b6.f, "mangle", "FIRC_g1D", want6, 3));
    static const char *j6[] = {"-d", "fd37:9a00::/64", "-j", "FIRC_g1D"};
    ASSERT(has_rule(b6.f, "mangle", "FIRC_g1", j6, 4));
    built_free(&b4);
    built_free(&b6);
    PASS();
}

/* Catches: `-s 0.0.0.0/0` written, or a /0 reaching the other family. */
TEST a_whole_family_entry_is_written_without_a_source(void)
{
    firc_nf_source_t allow[] = {v4_src(0, 0, 0, 0, 0)};
    firc_nf_devices_t dev = {.active = true, .allow = allow, .n_allow = 1};
    built_t b4, b6;
    ASSERT(build_g1(&b4, FIRC_IPT_PROTO_IPV4, &dev));
    ASSERT(build_g1(&b6, FIRC_IPT_PROTO_IPV6, &dev));
    static const char *const want4[] = {"-j MARK --set-xmark " F5, F5_CONNMARK};
    static const char *const want6[] = {F5_CONNMARK};
    ASSERT(rules_are(b4.f, "mangle", "FIRC_g1D", want4, 2));
    ASSERT(rules_are(b6.f, "mangle", "FIRC_g1D", want6, 1));
    built_free(&b4);
    built_free(&b6);
    PASS();
}

/* Catches: an allow list that renders nothing read as allow everyone. */
TEST an_allow_list_that_renders_nothing_marks_nobody(void)
{
    firc_nf_devices_t dev = {.active = true, .allow_all = false};
    built_t b;
    ASSERT(build_g1(&b, FIRC_IPT_PROTO_IPV4, &dev));
    static const char *const want[] = {F5_CONNMARK};
    ASSERT(rules_are(b.f, "mangle", "FIRC_g1D", want, 1));
    ASSERT_FALSE(any_arg_equals(b.f, "mangle", "FIRC_g1", "--set-xmark"));
    built_free(&b);
    PASS();
}

/* Catches: unchanged devices read as changed, new ones as unchanged, or the build ignoring its copy. */
TEST devices_set_on_the_object_reach_the_pass(void)
{
    firc_fake_ipt_t *f4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt4 = firc_ipt_new(firc_fake_ipt_as_executable(f4), firc_fake_ipt_as_xt(f4));
    firc_netfilter_register_base_chains(ipt4, NULL);
    firc_ipset_to_link_t *l = firc_ipset_to_link_new("FIRC_g1", "nwg0", ipt4, NULL, NULL, 100, NULL, "g1", NULL, NULL);
    ASSERT(l != NULL);
    firc_nf_source_t allow[] = {mac_src()};
    firc_nf_devices_t dev = {.active = true, .allow = allow, .n_allow = 1};
    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_set_devices(l, &dev, &changed));
    ASSERTm("new devices are a change", changed);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_set_devices(l, &dev, &changed));
    ASSERT_FALSEm("the same ones are not", changed);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_stage_for_test(l));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt4));
    ASSERT(any_arg_equals(f4, "mangle", "FIRC_g1D", "AA:BB:CC:DD:EE:FF"));
    firc_nf_devices_t none = {0};
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_set_devices(l, &none, &changed));
    ASSERTm("an emptied selector is a change", changed);
    firc_ipset_to_link_free(l);
    firc_ipt_free(ipt4);
    PASS();
}

/* Catches: the link's pass handing the subnet builder no selector, or a stale one, while its chunks jump. */
TEST subnets_and_devices_set_on_the_object_jump_together(void)
{
    firc_fake_ipt_t *f4 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt4 = firc_ipt_new(firc_fake_ipt_as_executable(f4), firc_fake_ipt_as_xt(f4));
    firc_netfilter_register_base_chains(ipt4, NULL);
    firc_fake_ipt_t *f6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt6 = firc_ipt_new(firc_fake_ipt_as_executable(f6), firc_fake_ipt_as_xt(f6));
    firc_netfilter_register_base_chains(NULL, ipt6);
    firc_ipset_to_link_t *l = firc_ipset_to_link_new("FIRC_g1", "nwg0", ipt4, ipt6, NULL, 100, NULL, "g1", NULL, NULL);
    ASSERT(l != NULL);
    firc_nf_source_t allow[] = {mac_src()};
    firc_nf_devices_t dev = {.active = true, .allow = allow, .n_allow = 1};
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_set_devices(l, &dev, NULL));
    const firc_ipv4_subnet_t v4[] = {{.addr = {10, 1, 0, 0}, .cidr = 16}};
    const firc_ipv6_subnet_t v6[] = {{.addr = {0x20, 0x01, 0x0d, 0xb8}, .cidr = 32}};
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_set_subnets(l, v4, 1, v6, 1, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_stage_for_test(l));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt4));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt6));

    static const char *j4[] = {"-d", "10.1.0.0/16", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "mark",
                               "!", "--mark", "0x40000000/0x40000000", "-j", "FIRC_g1D"};
    static const char *j6[] = {"-d", "2001:db8::/32", "-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "mark",
                               "!", "--mark", "0x40000000/0x40000000", "-j", "FIRC_g1D"};
    ASSERT(has_rule(f4, "mangle", "FIRC_g1", j4, 13));
    ASSERT(has_rule(f6, "mangle", "FIRC_g1", j6, 13));
    ASSERT(firc_fake_ipt_chain_exists(f4, "mangle", "FIRC_g1D"));
    ASSERT(firc_fake_ipt_chain_exists(f6, "mangle", "FIRC_g1D"));

    firc_nf_devices_t none = {0};
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_set_devices(l, &none, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_stage_for_test(l));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt4));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt6));
    ASSERT(any_arg_equals(f4, "mangle", "FIRC_g1", "MARK"));
    ASSERT(any_arg_equals(f6, "mangle", "FIRC_g1", "MARK"));
    ASSERT_FALSE(any_arg_equals(f4, "mangle", "FIRC_g1", "FIRC_g1D"));
    ASSERT_FALSE(any_arg_equals(f6, "mangle", "FIRC_g1", "FIRC_g1D"));

    firc_ipset_to_link_free(l);
    firc_ipt_free(ipt4);
    firc_ipt_free(ipt6);
    PASS();
}

/* Catches: sources compared by struct bytes instead of by what they render. */
TEST a_source_is_compared_by_what_it_renders(void)
{
    firc_nf_source_t a = mac_src(), b;
    memset(&b, 0xff, sizeof(b));
    b.kind = FIRC_NF_SRC_MAC;
    memcpy(b.mac, a.mac, 6);
    firc_nf_devices_t d1 = {.active = true}, d2 = {.active = true};
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&d1, false, &a));
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&d1, false, &b));
    ASSERT_EQ_FMTm("the same MAC is one source", (size_t)1, d1.n_allow, "%zu");
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&d2, false, &b));
    ASSERTm("equal whatever the padding", firc_nf_devices_equal(&d1, &d2));

    firc_nf_source_t m1 = mark_src(0x0ffffaadu), m2 = mark_src(0x4f01faadu);
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&d1, true, &m1));
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&d1, true, &m2));
    ASSERT_EQ_FMTm("marks equal outside firc's bits are one source", (size_t)1, d1.n_deny, "%zu");

    firc_nf_source_t other = mac_src();
    other.mac[5] = 0x00;
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&d1, false, &other));
    ASSERT_EQ_FMTm("another MAC is another source", (size_t)2, d1.n_allow, "%zu");
    ASSERT_FALSE(firc_nf_devices_equal(&d1, &d2));
    firc_nf_devices_clear(&d1);
    firc_nf_devices_clear(&d2);
    ASSERT_EQ_FMT((size_t)0, d1.n_allow, "%zu");
    PASS();
}

/* One MAC source per value of its last byte. */
static firc_nf_source_t mac_n(uint8_t last)
{
    firc_nf_source_t s = mac_src();
    s.mac[5] = last;
    return s;
}

/* A devices copy built by push: `deny` and `allow` are last MAC bytes, 0-ended. */
static firc_nf_devices_t devs(bool allow_all, const uint8_t *deny, const uint8_t *allow)
{
    firc_nf_devices_t d = {.active = true, .allow_all = allow_all};
    for (size_t i = 0; deny != NULL && deny[i] != 0; i++) {
        firc_nf_source_t x = mac_n(deny[i]);
        if (firc_nf_devices_push(&d, true, &x) != FIRC_OK) { abort(); }
    }
    for (size_t i = 0; allow != NULL && allow[i] != 0; i++) {
        firc_nf_source_t x = mac_n(allow[i]);
        if (firc_nf_devices_push(&d, false, &x) != FIRC_OK) { abort(); }
    }
    return d;
}

/* Catches: narrowing judged by count or order instead of by set, or a widening taken for one. */
TEST a_narrowing_render_is_a_gained_deny_or_a_lost_allow(void)
{
    static const uint8_t n1[] = {1, 0}, n2[] = {2, 0}, n12[] = {1, 2, 0}, n21[] = {2, 1, 0};
    firc_nf_devices_t off = {0};
    struct {
        firc_nf_devices_t was, now;
        bool narrows;
    } k[] = {
        {devs(true, n1, NULL), devs(true, n1, NULL), false},
        {devs(true, NULL, NULL), devs(true, n1, NULL), true},
        {devs(true, n12, NULL), devs(true, n1, NULL), false},
        {devs(false, NULL, n12), devs(false, NULL, n1), true},
        {devs(false, NULL, n1), devs(false, NULL, n12), false},
        {devs(true, NULL, NULL), devs(false, NULL, n1), true},
        {devs(false, NULL, n1), devs(true, NULL, NULL), false},
        {devs(true, n12, NULL), devs(true, n21, NULL), false},
        {devs(false, NULL, n1), devs(false, NULL, n2), true},
        {off, devs(true, n1, NULL), true},
        {off, devs(true, NULL, NULL), false},
        {devs(true, n1, NULL), off, false},
        {devs(false, n1, n1), devs(false, n2, n1), true},
        {off, devs(false, NULL, n1), true},
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        bool got = firc_nf_devices_narrows(&k[i].was, &k[i].now);
        firc_nf_devices_clear(&k[i].was);
        firc_nf_devices_clear(&k[i].now);
        if (got != k[i].narrows) {
            static char row[32];
            snprintf(row, sizeof(row), "row %zu", i + 1);
            FAILm(row);
        }
    }
    firc_nf_devices_t a = {.active = true, .allow_all = true}, b = a;
    firc_nf_source_t m1 = mark_src(0x0ffffaadu), m2 = mark_src(0x4f01faadu);
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&a, true, &m1));
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&b, true, &m2));
    bool masked = firc_nf_devices_narrows(&a, &b);
    firc_nf_devices_clear(&a);
    firc_nf_devices_clear(&b);
    ASSERT_FALSEm("the same mark under firc's mask", masked);
    PASS();
}

/* Catches: a chain that marked nobody read as narrowed when its deny list grows, flushing flows it never marked. */
TEST a_chain_that_marked_nobody_cannot_narrow(void)
{
    static const uint8_t n1[] = {1, 0}, n12[] = {1, 2, 0};
    struct {
        firc_nf_devices_t was, now;
        bool narrows;
    } k[] = {
        {devs(false, NULL, NULL), devs(true, n1, NULL), false},
        {devs(false, n1, NULL), devs(true, n12, NULL), false},
        {devs(false, NULL, NULL), devs(false, n1, NULL), false},
        {devs(false, n1, NULL), devs(false, n12, n1), false},
        {devs(false, NULL, n1), devs(false, n1, n1), true},
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        bool got = firc_nf_devices_narrows(&k[i].was, &k[i].now);
        firc_nf_devices_clear(&k[i].was);
        firc_nf_devices_clear(&k[i].now);
        if (got != k[i].narrows) {
            static char row[32];
            snprintf(row, sizeof(row), "row %zu", i + 1);
            FAILm(row);
        }
    }
    PASS();
}

/* Catches: push growing by one instead of doubling, or losing the duplicate check when it grows. */
TEST push_doubles_its_room_and_keeps_the_duplicate_scan(void)
{
    firc_nf_devices_t d = {.active = true};
    size_t room[10] = {0};
    for (uint8_t i = 1; i <= 9; i++) {
        firc_nf_source_t x = mac_n(i);
        ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&d, false, &x));
        room[i] = d.cap_allow;
    }
    ASSERT_EQ_FMT((size_t)4, room[4], "%zu");
    ASSERT_EQ_FMT((size_t)8, room[5], "%zu");
    ASSERT_EQ_FMT((size_t)8, room[8], "%zu");
    ASSERT_EQ_FMT((size_t)16, room[9], "%zu");
    firc_nf_source_t again = mac_n(3);
    ASSERT_EQ(FIRC_OK, firc_nf_devices_push(&d, false, &again));
    ASSERT_EQ_FMTm("a duplicate is not appended", (size_t)9, d.n_allow, "%zu");
    for (size_t i = 0; i < d.n_allow; i++) { ASSERT_EQ_FMT((unsigned)(i + 1), (unsigned)d.allow[i].mac[5], "%u"); }
    firc_nf_devices_t c;
    ASSERT_EQ(FIRC_OK, firc_nf_devices_copy(&c, &d));
    ASSERTm("a copy is equal", firc_nf_devices_equal(&c, &d));
    firc_nf_devices_clear(&c);
    firc_nf_devices_clear(&d);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_mark_is_written_masked);
    RUN_TEST(the_masquerade_matches_the_mark_and_the_interface);
    RUN_TEST(a_blackhole_group_gets_no_masquerade);
    RUN_TEST(the_connmark_rule_keenetic_needs_is_still_emitted);
    RUN_TEST(every_chunk_a_group_holds_becomes_a_rule);
    RUN_TEST(the_v6_table_gets_the_same_rules_with_v6_chunks);
    RUN_TEST(a_subnet_rule_is_a_static_mark_rule_in_the_groups_chain);
    RUN_TEST(a_subnet_rule_with_a_protocol_marks_that_protocol_only);
    RUN_TEST(a_rewrite_drops_a_removed_prefix_and_keeps_one_jump);
    RUN_TEST(prefixes_set_on_the_object_reach_both_engines);
    RUN_TEST(the_chunk_rules_come_from_the_snapshot_the_object_is_given);
    RUN_TEST(a_group_with_no_chunks_emits_no_chunk_rules);
    RUN_TEST(a_group_without_a_selector_marks_its_chunks_as_before);
    RUN_TEST(a_selector_group_jumps_from_each_chunk_to_its_devices_chain);
    RUN_TEST(a_selector_group_s_subnet_rule_jumps_to_its_devices_chain);
    RUN_TEST(a_group_without_a_selector_keeps_its_subnet_mark_and_connmark);
    RUN_TEST(everyone_except_a_denied_address_is_one_return_and_one_mark);
    RUN_TEST(a_policy_is_matched_by_its_mark_outside_firc_s_bits);
    RUN_TEST(each_family_gets_its_own_sources);
    RUN_TEST(a_whole_family_entry_is_written_without_a_source);
    RUN_TEST(an_allow_list_that_renders_nothing_marks_nobody);
    RUN_TEST(devices_set_on_the_object_reach_the_pass);
    RUN_TEST(subnets_and_devices_set_on_the_object_jump_together);
    RUN_TEST(a_source_is_compared_by_what_it_renders);
    RUN_TEST(a_narrowing_render_is_a_gained_deny_or_a_lost_allow);
    RUN_TEST(a_chain_that_marked_nobody_cannot_narrow);
    RUN_TEST(push_doubles_its_room_and_keeps_the_duplicate_scan);
    GREATEST_MAIN_END();
}
