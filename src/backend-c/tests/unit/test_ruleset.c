#include "greatest.h"

#include "firc/events.h"
#include "firc/ruleset.h"
#include "firc/keenetic_policy.h"
#include "firc/mark.h"
#include "firc/netfilter_cleaner.h"

#include "fake_iptables.h"
#include "xt_golden.h"
#include "fake_rtnl.h"

#include "firc/log.h"

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct entry {
    int family;
    uint8_t addr[16];
    uint8_t cidr;
    uint8_t proto;
    char ports[64];
} entry_t;

typedef struct plan {
    entry_t e[8];
    size_t n;
} plan_t;

static void collect(int family, const uint8_t *addr, uint8_t cidr, uint8_t proto, const char *ports,
                    void *ud) {
    plan_t *p = ud;
    if (p->n == 8) { abort(); }
    entry_t *e = &p->e[p->n++];
    e->family = family;
    memcpy(e->addr, addr, family == 4 ? 4 : 16);
    e->cidr = cidr;
    e->proto = proto;
    snprintf(e->ports, sizeof(e->ports), "%s", ports);
}

static void add_group(firc_config_t *cfg, uint8_t id, const char *type, const char *rule,
                      bool enable) {
    firc_group_t *g = firc_group_new();
    g->id = (firc_id_t){{id, 0, 0, 0}};
    g->enable = true;
    firc_rule_t *r = firc_rule_new();
    r->id = (firc_id_t){{id, 1, 0, 0}};
    r->type = strdup(type);
    r->rule = strdup(rule);
    r->enable = enable;
    if (firc_group_add_rule(g, r) != FIRC_OK) { abort(); }
    if (firc_config_add_group(cfg, g) != FIRC_OK) { abort(); }
}

typedef struct fixture {
    firc_config_t cfg;
} fixture_t;

static void fixture_up(fixture_t *f, const char *type, const char *rule, bool enable) {
    firc_config_init_defaults(&f->cfg);
    add_group(&f->cfg, 1, type, rule, enable);
}

static void fixture_down(fixture_t *f) {
    firc_config_clear(&f->cfg);
}

/* Catches: an enabled subnet rule, a /0 included, missing from the chain plan or rewritten. */
TEST a_subnet_rule_is_a_prefix_for_the_chain(void) {
    fixture_t f;
    fixture_up(&f, FIRC_RULE_SUBNET, "10.1.0.0/16", true);
    add_group(&f.cfg, 2, FIRC_RULE_SUBNET6, "2001:db8::/32", true);
    add_group(&f.cfg, 3, FIRC_RULE_SUBNET, "0.0.0.0/0", true);
    add_group(&f.cfg, 4, FIRC_RULE_SUBNET, "10.9.0.0/16", false);

    plan_t p = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(f.cfg.groups[0], collect, &p));
    ASSERT_EQ_FMT((size_t)1, p.n, "%zu");
    ASSERT_EQ(4, p.e[0].family);
    const uint8_t want4[4] = {10, 1, 0, 0};
    ASSERT_MEM_EQ(want4, p.e[0].addr, 4);
    ASSERT_EQ(16, p.e[0].cidr);

    plan_t p6 = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(f.cfg.groups[1], collect, &p6));
    ASSERT_EQ_FMT((size_t)1, p6.n, "%zu");
    ASSERT_EQ(6, p6.e[0].family);
    const uint8_t want6[16] = {0x20, 0x01, 0x0d, 0xb8};
    ASSERT_MEM_EQ(want6, p6.e[0].addr, 16);
    ASSERT_EQ(32, p6.e[0].cidr);

    plan_t p0 = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(f.cfg.groups[2], collect, &p0));
    ASSERT_EQ_FMTm("a /0 is one prefix, not two halves", (size_t)1, p0.n, "%zu");
    ASSERT_EQ(0, p0.e[0].cidr);

    plan_t pd = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(f.cfg.groups[3], collect, &pd));
    ASSERT_EQ_FMTm("a disabled rule contributes nothing", (size_t)0, pd.n, "%zu");
    fixture_down(&f);
    PASS();
}

/* Catches: an unusable subnet rule planned as a match-all, or said again at every plan though the config load already said it. */
TEST an_unusable_subnet_rule_is_skipped_without_a_word(void) {
    fixture_t f;
    fixture_up(&f, FIRC_RULE_SUBNET, "10.1.0.0/16", true);
    f.cfg.groups[0]->rules[0]->ports = strdup("53");
    add_group(&f.cfg, 2, FIRC_RULE_SUBNET6, "not-a-prefix", true);
    firc_event_reset_for_test();
    plan_t p = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(f.cfg.groups[0], collect, &p));
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(f.cfg.groups[1], collect, &p));
    ASSERT_EQ_FMT((size_t)0, p.n, "%zu");
    firc_event_t ev[4];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)0, firc_event_read(0, ev, 4, &next, &dropped), "%zu");
    fixture_down(&f);
    PASS();
}

/* Catches: a prefix with host bits written as given, so the chain is rewritten on every commit. */
TEST a_prefix_with_host_bits_is_normalised(void) {
    fixture_t f;
    fixture_up(&f, FIRC_RULE_SUBNET, "10.1.2.3/16", true);
    add_group(&f.cfg, 2, FIRC_RULE_SUBNET6, "2001:db8::1/32", true);
    plan_t p = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(f.cfg.groups[0], collect, &p));
    ASSERT_EQ_FMT((size_t)1, p.n, "%zu");
    const uint8_t want4[4] = {10, 1, 0, 0};
    ASSERT_MEM_EQ(want4, p.e[0].addr, 4);
    plan_t p6 = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(f.cfg.groups[1], collect, &p6));
    ASSERT_EQ_FMT((size_t)1, p6.n, "%zu");
    const uint8_t want6[16] = {0x20, 0x01, 0x0d, 0xb8};
    ASSERT_MEM_EQ(want6, p6.e[0].addr, 16);
    fixture_down(&f);
    PASS();
}

/* Catches: a list's enabled subnet rules left out of the plan, or its disabled or name rules put in. */
TEST a_group_plans_its_list_subnets_with_its_own(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    add_group(&cfg, 1, FIRC_RULE_SUBNET, "10.1.0.0/16", true);
    firc_group_t *g = cfg.groups[0];
    g->list = firc_group_list_new();
    ASSERT(g->list != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&g->list->rules, "10.2.0.0/16", FIRC_RULE_SUBNET, true,
                                           (firc_id_t){{1, 2, 0, 0}}));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&g->list->rules, "10.3.0.0/16", FIRC_RULE_SUBNET, false,
                                           (firc_id_t){{1, 3, 0, 0}}));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&g->list->rules, "list.example.com", FIRC_RULE_DOMAIN, true,
                                           (firc_id_t){{1, 4, 0, 0}}));

    plan_t p = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(g, collect, &p));
    ASSERT_EQ_FMTm("the hand prefix and the one enabled list prefix, no more", (size_t)2, p.n, "%zu");
    const uint8_t want_hand[4] = {10, 1, 0, 0};
    const uint8_t want_list[4] = {10, 2, 0, 0};
    ASSERT_MEM_EQ(want_hand, p.e[0].addr, 4);
    ASSERT_MEM_EQ(want_list, p.e[1].addr, 4);
    ASSERT_EQ_FMTm("no protocol: any protocol", 0, p.e[1].proto, "%d");
    ASSERT_STR_EQm("no ports: every port", "", p.e[1].ports);

    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a list rule's proto or ports dropped on the way to the chain, marking every protocol. */
TEST a_list_prefix_carries_its_protocol_and_ports(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    add_group(&cfg, 1, FIRC_RULE_DOMAIN, "hand.example.com", true);
    firc_group_t *g = cfg.groups[0];
    g->list = firc_group_list_new();
    ASSERT(g->list != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&g->list->rules, "10.2.0.0/16", FIRC_RULE_SUBNET, true,
                                                (firc_id_t){{1, 2, 0, 0}}, "udp", "50000-50099,19200-19400"));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&g->list->rules, "10.3.0.0/16", FIRC_RULE_SUBNET, true,
                                                (firc_id_t){{1, 3, 0, 0}}, NULL, "53"));
    plan_t p = {0};
    ASSERT_EQ(FIRC_OK, firc_ruleset_plan_subnets(g, collect, &p));
    ASSERT_EQ_FMT((size_t)1, p.n, "%zu");
    ASSERT_EQ(IPPROTO_UDP, p.e[0].proto);
    ASSERT_STR_EQ("50000:50099,19200:19400", p.e[0].ports);
    firc_config_clear(&cfg);
    PASS();
}

SUITE(ruleset) {
    RUN_TEST(a_subnet_rule_is_a_prefix_for_the_chain);
    RUN_TEST(a_prefix_with_host_bits_is_normalised);
    RUN_TEST(a_group_plans_its_list_subnets_with_its_own);
    RUN_TEST(a_list_prefix_carries_its_protocol_and_ports);
    RUN_TEST(an_unusable_subnet_rule_is_skipped_without_a_word);
}

static bool t_mark(const char *policy, uint32_t *mark, void *ud) {
    (void)ud;
    if (strcmp(policy, "Kids") == 0) { *mark = 0x0ffffaabu; return true; }
    if (strcmp(policy, "Guests") == 0) { *mark = 0x0ffffaadu; return true; }
    return false;
}

/* One host: 192.168.1.30 and fd00::30. */
static firc_err_t t_hosts(const firc_ip_t *net, uint8_t prefix, bool deny, firc_devsel_addr_fn cb, void *cb_ud,
                          void *ud) {
    (void)ud;
    (void)deny;
    firc_ip_t a4 = {{192, 168, 1, 30}, 4};
    firc_ip_t a6 = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30}, 16};
    if (firc_devsel_prefix_covers(net, prefix, &a4) || firc_devsel_prefix_covers(net, prefix, &a6)) {
        cb(&a4, cb_ud);
        cb(&a6, cb_ud);
    }
    return FIRC_OK;
}

/* Policy hosts: "Kids" 192.168.1.40 and fd00::40, "Hosted" (no mark) 192.168.1.50, "Guests" none. */
static firc_err_t t_policy_hosts(const char *policy, bool deny, firc_devsel_addr_fn cb, void *cb_ud, void *ud) {
    (void)ud;
    (void)deny;
    firc_ip_t k4 = {{192, 168, 1, 40}, 4};
    firc_ip_t k6 = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40}, 16};
    firc_ip_t h4 = {{192, 168, 1, 50}, 4};
    if (strcmp(policy, "Kids") == 0) {
        cb(&k4, cb_ud);
        cb(&k6, cb_ud);
    } else if (strcmp(policy, "Hosted") == 0) {
        cb(&h4, cb_ud);
    }
    return FIRC_OK;
}

static const firc_ruleset_lookup_t k_lookup = {t_mark, t_hosts, t_policy_hosts, NULL, NULL, NULL};

static firc_group_t *selector(char **allow, size_t na, char **deny, size_t nd) {
    firc_group_t *g = firc_group_new();
    firc_devsel_spec_t s = {.allow = allow, .n_allow = na, .deny = deny, .n_deny = nd};
    if (g == NULL || firc_devsel_spec_copy(&g->devices, &s) != FIRC_OK) { abort(); }
    return g;
}

static bool is_addr(const firc_nf_source_t *s, uint8_t family, const uint8_t *addr, uint8_t prefix) {
    size_t len = family == 4 ? 4 : 16;
    uint8_t want[16] = {0};
    memcpy(want, addr, len);
    return s->kind == FIRC_NF_SRC_ADDR && s->family == family && s->prefix == prefix &&
           memcmp(s->addr, want, 16) == 0;
}

static const uint8_t k_30[4] = {192, 168, 1, 30};
static const uint8_t k_fd30[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30};

/* Catches: an empty selector rendering an active chain, so the group stops marking by chunk. */
TEST an_empty_selector_renders_no_chain(void) {
    firc_group_t *g = selector(NULL, 0, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &k_lookup, &d));
    ASSERT_FALSE(d.active);
    ASSERT_EQ_FMT((size_t)0, d.n_allow + d.n_deny, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: a deny entry missing its host's other address, the entry itself, or allow_all misread. */
TEST a_denied_address_brings_its_host_s_other_address(void) {
    char e[] = "192.168.1.30";
    char *deny[] = {e};
    firc_group_t *g = selector(NULL, 0, deny, 1);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &k_lookup, &d));
    ASSERT(d.active && d.allow_all);
    ASSERT_EQ_FMT((size_t)2, d.n_deny, "%zu");
    ASSERTm("the entry", is_addr(&d.deny[0], 4, k_30, 32));
    ASSERTm("its host's v6 address", is_addr(&d.deny[1], 6, k_fd30, 128));
    firc_nf_devices_clear(&d);

    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT_EQ_FMT((size_t)1, d.n_deny, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: a prefix entry written with host bits, or a covered host address written again. */
TEST a_prefix_entry_is_written_as_its_network(void) {
    char e[] = "192.168.1.77/24";
    char *allow[] = {e};
    firc_group_t *g = selector(allow, 1, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &k_lookup, &d));
    ASSERT(d.active && !d.allow_all);
    ASSERT_EQ_FMT((size_t)2, d.n_allow, "%zu");
    const uint8_t net[4] = {192, 168, 1, 0};
    ASSERT(is_addr(&d.allow[0], 4, net, 24));
    ASSERT(is_addr(&d.allow[1], 6, k_fd30, 128));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: a policy mark written unmasked, allow and deny swapped, or the policy's hosts left out. */
TEST policies_render_their_marks_and_their_hosts(void) {
    char kids[] = "policy:Kids", guests[] = "policy:Guests";
    char *allow[] = {kids}, *deny[] = {guests};
    firc_group_t *g = selector(allow, 1, deny, 1);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &k_lookup, &d));
    ASSERT_EQ_FMT((size_t)3, d.n_allow, "%zu");
    ASSERT_EQ_FMT((size_t)1, d.n_deny, "%zu");
    ASSERT_EQ(FIRC_NF_SRC_MARK, d.allow[0].kind);
    ASSERT_EQ_FMT(0x0f00faabu, d.allow[0].mark, "0x%x");
    const uint8_t k40[4] = {192, 168, 1, 40};
    const uint8_t kfd40[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40};
    ASSERT(is_addr(&d.allow[1], 4, k40, 32));
    ASSERT(is_addr(&d.allow[2], 6, kfd40, 128));
    ASSERT_EQ_FMT(0x0f00faadu, d.deny[0].mark, "0x%x");
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: a policy without a firmware mark skipping its hosts too, so it marks nobody. */
TEST a_policy_without_a_mark_renders_its_hosts(void) {
    char hosted[] = "policy:Hosted";
    char *allow[] = {hosted};
    firc_group_t *g = selector(allow, 1, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &k_lookup, &d));
    ASSERT_EQ_FMT((size_t)1, d.n_allow, "%zu");
    const uint8_t h50[4] = {192, 168, 1, 50};
    ASSERT(is_addr(&d.allow[0], 4, h50, 32));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: an allow list that renders empty turned into allow_all. */
TEST an_allow_list_of_unknown_policies_marks_nobody(void) {
    char nope[] = "policy:Nope";
    char *allow[] = {nope};
    firc_group_t *g = selector(allow, 1, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &k_lookup, &d));
    ASSERT(d.active);
    ASSERT_FALSE(d.allow_all);
    ASSERT_EQ_FMT((size_t)0, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: a MAC entry dropped without the host table, or a duplicate source written twice. */
TEST a_mac_entry_needs_no_table_and_a_duplicate_is_one_rule(void) {
    char mac[] = "mac:aa:bb:cc:dd:ee:ff", kids1[] = "policy:Kids", kids2[] = "policy:Kids";
    char *allow[] = {mac};
    firc_group_t *g = selector(allow, 1, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT_EQ_FMT((size_t)1, d.n_allow, "%zu");
    ASSERT_EQ(FIRC_NF_SRC_MAC, d.allow[0].kind);
    const uint8_t want[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    ASSERT_MEM_EQ(want, d.allow[0].mac, 6);
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    char *twice[] = {kids1, kids2};
    g = selector(twice, 2, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &k_lookup, &d));
    ASSERT_EQ_FMTm("its mark and its two host addresses, once", (size_t)3, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: host bits kept on a /0, or a v4-mapped /96 kept as v6. */
TEST a_whole_family_entry_is_its_family_s_zero_prefix(void) {
    char a[] = "10.1.2.3/0", b[] = "::ffff:10.0.0.1/96";
    char *allow[] = {a, b};
    firc_group_t *g = selector(allow, 2, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT_EQ_FMT((size_t)1, d.n_allow, "%zu");
    const uint8_t zero[4] = {0, 0, 0, 0};
    ASSERT(is_addr(&d.allow[0], 4, zero, 0));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: host bits kept in the byte where a prefix ends. */
TEST a_prefix_off_a_byte_boundary_keeps_only_its_network_bits(void) {
    char a[] = "10.1.23.77/20", b[] = "fd00:1234::1/22";
    char *allow[] = {a, b};
    firc_group_t *g = selector(allow, 2, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT_EQ_FMT((size_t)2, d.n_allow, "%zu");
    const uint8_t net4[4] = {10, 1, 16, 0};
    const uint8_t net6[16] = {0xfd, 0x00, 0x10, 0x00};
    ASSERT(is_addr(&d.allow[0], 4, net4, 20));
    ASSERT(is_addr(&d.allow[1], 6, net6, 22));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* Catches: a deny entry that cannot be written skipped (fail open) instead of marking nobody. */
TEST a_deny_entry_that_cannot_be_rendered_marks_nobody(void) {
    char bad[] = "not-a-device", host[] = "192.168.1.30", other[] = "192.168.1.31";
    char *deny_bad[] = {bad}, *deny_ok[] = {other}, *allow[] = {host};

    firc_group_t *g = selector(allow, 1, deny_bad, 1);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT(d.active);
    ASSERT_FALSE(d.allow_all);
    ASSERT_EQ_FMTm("nothing is marked", (size_t)0, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    g = selector(NULL, 0, deny_bad, 1);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT(d.active);
    ASSERT_FALSE(d.allow_all);
    ASSERT_EQ_FMT((size_t)0, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    g = selector(allow, 1, deny_ok, 1);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT_EQ_FMT((size_t)1, d.n_deny, "%zu");
    ASSERT_EQ_FMT((size_t)1, d.n_allow, "%zu");
    ASSERT(is_addr(&d.allow[0], 4, k_30, 32));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    g = selector(NULL, 0, deny_ok, 1);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT(d.allow_all);
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    char *allow_bad[] = {bad, host};
    g = selector(allow_bad, 2, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, NULL, &d));
    ASSERT_FALSE(d.allow_all);
    ASSERT_EQ_FMT((size_t)1, d.n_allow, "%zu");
    ASSERT(is_addr(&d.allow[0], 4, k_30, 32));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

static bool t_not_read(void *ud) {
    (void)ud;
    return false;
}

static bool t_read(void *ud) {
    (void)ud;
    return true;
}

/* Catches: a policy entry rendered before the first map marking everyone (a deny of nobody) or its allow siblings. */
TEST a_policy_entry_before_the_first_map_marks_nobody(void) {
    char kids[] = "policy:Kids", host[] = "192.168.1.30", other[] = "192.168.1.31";
    char *deny_kids[] = {kids}, *allow_mixed[] = {host, kids}, *deny_addr[] = {other};
    firc_ruleset_lookup_t early = {t_mark, t_hosts, t_policy_hosts, NULL, NULL, t_not_read};
    firc_ruleset_lookup_t read = {t_mark, t_hosts, t_policy_hosts, NULL, NULL, t_read};
    firc_nf_devices_t d;

    firc_group_t *g = selector(NULL, 0, deny_kids, 1);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &early, &d));
    ASSERT(d.active);
    ASSERT_FALSEm("no map yet: not everyone", d.allow_all);
    ASSERT_EQ_FMT((size_t)0, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &read, &d));
    ASSERTm("the map read: everyone but Kids", d.allow_all);
    ASSERT(d.n_deny >= 1);
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    g = selector(allow_mixed, 2, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &early, &d));
    ASSERT_FALSE(d.allow_all);
    ASSERT_EQ_FMTm("the address beside the unread policy is not marked either", (size_t)0, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    g = selector(NULL, 0, deny_addr, 1);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &early, &d));
    ASSERTm("a selector naming no policy does not wait for the map", d.allow_all);
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* A policy mark with no bits under firc's mask: 0x40ff0000 & 0xbf00ffff is 0. */
static bool t_mark_zero(const char *policy, uint32_t *mark, void *ud) {
    (void)ud;
    if (strcmp(policy, "Zero") == 0) { *mark = 0x40ff0000u; return true; }
    return false;
}

TEST a_policy_mark_that_masks_to_zero_is_not_written(void) {
    firc_ruleset_lookup_t lk = {t_mark_zero, NULL, NULL, NULL, NULL, NULL};
    char zero[] = "policy:Zero", host[] = "192.168.1.30";
    char *allow[] = {zero, host}, *deny[] = {zero}, *allow_host[] = {host};

    firc_group_t *g = selector(allow, 2, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &lk, &d));
    ASSERT_EQ_FMTm("only the address is written", (size_t)1, d.n_allow, "%zu");
    ASSERT(is_addr(&d.allow[0], 4, k_30, 32));
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    g = selector(allow_host, 1, deny, 1);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &lk, &d));
    ASSERT(d.active);
    ASSERT_FALSE(d.allow_all);
    ASSERT_EQ_FMT((size_t)0, d.n_deny, "%zu");
    ASSERT_EQ_FMTm("the group marks nobody", (size_t)0, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* A host address with no family (len 0), which written as is would be a /0. */
static firc_err_t t_hosts_broken(const firc_ip_t *net, uint8_t prefix, bool deny, firc_devsel_addr_fn cb,
                                 void *cb_ud, void *ud) {
    (void)deny;
    (void)net;
    (void)prefix;
    (void)ud;
    firc_ip_t none = {{192, 168, 1, 99}, 0};
    cb(&none, cb_ud);
    return FIRC_OK;
}

TEST an_address_the_table_gets_wrong_is_not_written(void) {
    static const firc_ruleset_lookup_t broken = {NULL, t_hosts_broken, NULL, NULL, NULL, NULL};
    char host[] = "192.168.1.30";
    char *list[] = {host};

    firc_group_t *g = selector(list, 1, NULL, 0);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &broken, &d));
    ASSERT_EQ_FMTm("the entry alone", (size_t)1, d.n_allow, "%zu");
    ASSERT(is_addr(&d.allow[0], 4, k_30, 32));
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    g = selector(NULL, 0, list, 1);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &broken, &d));
    ASSERT(d.active);
    ASSERT_FALSE(d.allow_all);
    ASSERT_EQ_FMT((size_t)0, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

static uint8_t g_other_octet = 61;

static firc_err_t t_hosts_moving(const firc_ip_t *net, uint8_t prefix, bool deny, firc_devsel_addr_fn cb,
                                 void *cb_ud, void *ud) {
    (void)ud;
    (void)deny;
    firc_ip_t self = {{192, 168, 1, 60}, 4};
    firc_ip_t other = {{192, 168, 1, g_other_octet}, 4};
    if (firc_devsel_prefix_covers(net, prefix, &self)) {
        cb(&self, cb_ud);
        cb(&other, cb_ud);
    }
    return FIRC_OK;
}

static bool devices_chain_has(firc_fake_ipt_t *fipt, const char *chain, const char *text) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(fipt, "mangle", chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        if (firc_test_rule_contains(rules[i], text)) { return true; }
    }
    return false;
}

static const firc_ruleset_lookup_t k_moving = {NULL, t_hosts_moving, NULL, NULL, NULL, NULL};

typedef struct nf_fx {
    firc_fake_ipt_t *fipt;
    firc_ipt_t *ipt;
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    firc_group_t *g;
    firc_ruleset_t *rs;
} nf_fx_t;

static bool nf_up_sel(nf_fx_t *f, char **allow, size_t na, char **deny, size_t nd) {
    memset(f, 0, sizeof(*f));
    g_other_octet = 61;
    f->fipt = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    f->ipt = f->fipt != NULL ? firc_ipt_new(firc_fake_ipt_as_xt(f->fipt), "FIRC_") : NULL;
    if (f->ipt == NULL || firc_netfilter_register_base_chains(f->ipt, NULL) != FIRC_OK) { return false; }
    f->kernel = fake_rtnl_start(&f->rtnl);
    if (f->kernel == NULL) { return false; }
    fake_rtnl_set_link_flags(f->kernel, IFF_UP | IFF_POINTOPOINT);
    f->g = selector(allow, na, deny, nd);
    f->g->id = (firc_id_t){{0x0a, 0x0b, 0x0c, 0x0d}};
    f->g->enable = true;
    f->g->iface = strdup("lo");
    if (f->g->iface == NULL) { return false; }
    firc_ruleset_deps_t deps = {.ipt4 = f->ipt, .rtnl = f->rtnl, .chain_prefix = "FIRC_", .start_idx = 100,
                                .lookup = &k_moving};
    f->rs = firc_ruleset_new(f->g, &deps);
    return f->rs != NULL;
}

static bool nf_up(nf_fx_t *f, char **allow, size_t na) { return nf_up_sel(f, allow, na, NULL, 0); }

static firc_err_t nf_pass(nf_fx_t *f) {
    firc_err_t err = firc_netfilter_register_base_chains(f->ipt, NULL);
    if (err == FIRC_OK) { err = firc_ruleset_prepare_iptables(f->rs); }
    return err == FIRC_OK ? firc_ipt_commit(f->ipt) : err;
}

static void nf_down(nf_fx_t *f) {
    if (f->rs != NULL) { firc_ruleset_disable(f->rs); }
    firc_ruleset_free(f->rs);
    firc_group_free(f->g);
    if (f->rtnl != NULL) { firc_rtnl_close(f->rtnl); }
    if (f->kernel != NULL) { fake_rtnl_stop(f->kernel); }
    firc_ipt_free(f->ipt);
}

TEST sync_renders_the_selector_again_and_says_when_it_moved(void) {
    char host[] = "192.168.1.60";
    char *allow[] = {host};
    nf_fx_t f;
    ASSERT(nf_up(&f, allow, 1));
    firc_fake_ipt_t *fipt = f.fipt;
    firc_ruleset_t *rs = f.rs;
    char dchain[64];
    firc_ruleset_devices_chain_name_for("FIRC_", f.g->id, dchain, sizeof(dchain));
    ASSERT_STR_EQ("FIRC_0a0b0c0dD", dchain);

    ASSERT_EQ(FIRC_OK, firc_ruleset_enable(rs, NULL));
    ASSERT_EQ(FIRC_OK, nf_pass(&f));
    ASSERTm("enable writes the host's other address",
            devices_chain_has(fipt, dchain, "-s 192.168.1.61/32 -j MARK"));

    bool changed = true;
    ASSERT_EQ(FIRC_OK, firc_ruleset_sync(rs, &changed));
    ASSERT_FALSEm("nothing moved", changed);

    g_other_octet = 62;
    ASSERT_EQ(FIRC_OK, firc_ruleset_sync(rs, &changed));
    ASSERTm("the host's address moved", changed);
    ASSERT_EQ(FIRC_OK, nf_pass(&f));
    ASSERT(devices_chain_has(fipt, dchain, "-s 192.168.1.62/32 -j MARK"));
    ASSERT_FALSE(devices_chain_has(fipt, dchain, "192.168.1.61"));
    ASSERT(devices_chain_has(fipt, dchain, "-s 192.168.1.60/32 -j MARK"));

    ASSERT_EQ(FIRC_OK, firc_ruleset_sync(rs, &changed));
    ASSERT_FALSEm("and then nothing again", changed);
    nf_down(&f);
    PASS();
}

/* Catches: a MAC-only group re-rendered on every table change, or an address group not. */
TEST a_selector_follows_the_table_unless_it_names_only_macs(void) {
    char mac[] = "mac:aa:bb:cc:dd:ee:ff", addr[] = "192.168.1.60", pol[] = "policy:Kids";
    char *only_mac[] = {mac}, *with_addr[] = {mac, addr}, *with_pol[] = {pol};
    firc_ruleset_deps_t deps = {.chain_prefix = "FIRC_"};
    struct {
        char **allow;
        size_t na;
        char **deny;
        size_t nd;
        bool has, follows;
    } k[] = {
        {NULL, 0, NULL, 0, false, false},
        {only_mac, 1, NULL, 0, true, false},
        {NULL, 0, only_mac, 1, true, false},
        {with_addr, 2, NULL, 0, true, true},
        {only_mac, 1, with_pol, 1, true, true},
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        firc_group_t *g = selector(k[i].allow, k[i].na, k[i].deny, k[i].nd);
        firc_ruleset_t *rs = firc_ruleset_new(g, &deps);
        ASSERT(rs != NULL);
        ASSERT_EQ_FMT((int)k[i].has, (int)firc_ruleset_has_devices(rs), "%d");
        ASSERT_EQ_FMT((int)k[i].follows, (int)firc_ruleset_devices_follow_table(rs), "%d");
        firc_ruleset_free(rs);
        firc_group_free(g);
    }
    PASS();
}

/* Catches: a table refresh rendering a group not in the kernel, or never reporting a move. */
TEST a_table_refresh_renders_only_a_routed_group(void) {
    char host[] = "192.168.1.60";
    char *allow[] = {host};
    nf_fx_t f;
    ASSERT(nf_up(&f, allow, 1));
    char dchain[64];
    firc_ruleset_devices_chain_name_for("FIRC_", f.g->id, dchain, sizeof(dchain));

    bool changed = true;
    g_other_octet = 62;
    ASSERT_EQ(FIRC_OK, firc_ruleset_refresh_devices(f.rs, &changed));
    ASSERT_FALSEm("not enabled: nothing to render into", changed);

    g_other_octet = 61;
    ASSERT_EQ(FIRC_OK, firc_ruleset_enable(f.rs, NULL));
    ASSERT_EQ(FIRC_OK, firc_ruleset_refresh_devices(f.rs, &changed));
    ASSERT_FALSEm("the same table", changed);
    g_other_octet = 62;
    ASSERT_EQ(FIRC_OK, firc_ruleset_refresh_devices(f.rs, &changed));
    ASSERTm("the host's address moved", changed);
    ASSERT_EQ(FIRC_OK, nf_pass(&f));
    ASSERT(devices_chain_has(f.fipt, dchain, "-s 192.168.1.62/32 -j MARK"));
    nf_down(&f);
    PASS();
}

/* The daemon's lookups over one map, as main.c hands it the live ones. */
static bool m_mark(const char *policy, uint32_t *mark, void *ud) { return firc_kn_policy_map_mark(ud, policy, mark); }
static firc_err_t m_hosts(const firc_ip_t *net, uint8_t prefix, bool deny, firc_devsel_addr_fn cb, void *cb_ud,
                          void *ud) {
    return firc_kn_policy_map_hosts_in(ud, net, prefix, deny, cb, cb_ud);
}
static firc_err_t m_policy_hosts(const char *policy, bool deny, firc_devsel_addr_fn cb, void *cb_ud, void *ud) {
    return firc_kn_policy_map_policy_hosts(ud, policy, deny, cb, cb_ud);
}
static firc_err_t m_policy_nets(const char *policy, bool deny, firc_devsel_net_fn cb, void *cb_ud, void *ud) {
    return firc_kn_policy_map_policy_nets(ud, policy, deny, cb, cb_ud);
}

static const char k_stale[] =
    "{\"host\":["
    "{\"mac\":\"aa:00:00:00:00:01\",\"ip\":\"192.168.1.50\",\"ip6\":[\"fd00::60\",\"2001:db8::60\"],"
    "\"policy\":\"Policy0\",\"active\":false},"
    "{\"mac\":\"aa:00:00:00:00:02\",\"ip\":\"192.168.1.50\",\"ip6\":[\"fd00::77\"],\"policy\":\"\",\"active\":true}"
    "]}";

static const uint8_t k_50[4] = {192, 168, 1, 50};
static const uint8_t k_fd60[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60};
static const uint8_t k_db60[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60};
static const uint8_t k_fd77[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};

/* Catches: a deny rendering only the host the index picks, or an allow rendering every host. */
TEST a_denied_address_renders_every_host_that_lists_it(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(k_stale, NULL, &m));
    firc_ruleset_lookup_t lk = {m_mark, m_hosts, m_policy_hosts, m_policy_nets, m, NULL};
    char e[] = "192.168.1.50";
    char *list[] = {e};

    firc_group_t *g = selector(NULL, 0, list, 1);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &lk, &d));
    ASSERT(d.allow_all);
    ASSERT_EQ_FMT((size_t)4, d.n_deny, "%zu");
    ASSERT(is_addr(&d.deny[0], 4, k_50, 32));
    ASSERT(is_addr(&d.deny[1], 6, k_fd60, 128));
    ASSERT(is_addr(&d.deny[2], 6, k_db60, 128));
    ASSERT(is_addr(&d.deny[3], 6, k_fd77, 128));
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    g = selector(list, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &lk, &d));
    ASSERT_EQ_FMT((size_t)2, d.n_allow, "%zu");
    ASSERT(is_addr(&d.allow[0], 4, k_50, 32));
    ASSERT(is_addr(&d.allow[1], 6, k_fd77, 128));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a policy's segments not asked for, so a peer with no host entry is matched by mark only. */
TEST a_policy_renders_its_segments(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", "{\"Policy9\":{\"description\":\"Guests\"}}", &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, "{\"Policy9\":{\"mark\":\"ffffaad\"}}"));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    firc_ruleset_lookup_t lk = {m_mark, m_hosts, m_policy_hosts, m_policy_nets, m, NULL};
    char e[] = "policy:Guests";
    char *list[] = {e};
    const uint8_t net[4] = {10, 99, 0, 0};

    firc_group_t *g = selector(NULL, 0, list, 1);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &lk, &d));
    ASSERT_EQ_FMT((size_t)2, d.n_deny, "%zu");
    ASSERT_EQ(FIRC_NF_SRC_MARK, d.deny[0].kind);
    ASSERT_EQ_FMT(0x0f00faadu, d.deny[0].mark, "0x%x");
    ASSERT(is_addr(&d.deny[1], 4, net, 24));
    firc_nf_devices_clear(&d);
    firc_group_free(g);

    g = selector(list, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &lk, &d));
    ASSERT_EQ_FMT((size_t)2, d.n_allow, "%zu");
    ASSERT(is_addr(&d.allow[1], 4, net, 24));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    firc_kn_policy_map_free(m);

    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(
                           "{\"host\":[{\"mac\":\"aa:00:00:00:00:0b\",\"ip\":\"10.99.0.5\",\"policy\":\"Policy0\","
                           "\"active\":true}]}",
                           "{\"Policy9\":{\"description\":\"Guests\"}}", &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, "{\"Policy9\":{\"mark\":\"ffffaad\"}}"));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    lk.ud = m;
    g = selector(NULL, 0, list, 1);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &lk, &d));
    ASSERT_EQ_FMT((size_t)2, d.n_deny, "%zu");
    ASSERT(is_addr(&d.deny[1], 4, net, 24));
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    g = selector(list, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &lk, &d));
    ASSERT_EQ_FMTm("the mark alone", (size_t)1, d.n_allow, "%zu");
    ASSERT_EQ(FIRC_NF_SRC_MARK, d.allow[0].kind);
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    firc_kn_policy_map_free(m);
    PASS();
}

/* A segment with no family (len 0), which written as is would be a /0. */
static firc_err_t t_nets_broken(const char *policy, bool deny, firc_devsel_net_fn cb, void *cb_ud, void *ud) {
    (void)policy;
    (void)deny;
    (void)ud;
    firc_ip_t none = {{10, 99, 0, 0}, 0};
    cb(&none, 24, cb_ud);
    return FIRC_OK;
}

TEST a_segment_the_table_gets_wrong_is_not_written(void) {
    static const firc_ruleset_lookup_t broken = {NULL, NULL, NULL, t_nets_broken, NULL, NULL};
    char pol[] = "policy:Guests", host[] = "192.168.1.30";
    char *deny[] = {pol}, *allow[] = {host};
    firc_group_t *g = selector(allow, 1, deny, 1);
    firc_nf_devices_t d;
    ASSERT_EQ(FIRC_OK, firc_ruleset_render_devices(g, &broken, &d));
    ASSERT(d.active);
    ASSERT_FALSE(d.allow_all);
    ASSERT_EQ_FMTm("the group marks nobody", (size_t)0, d.n_allow, "%zu");
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    PASS();
}

/* What the log said while `f` was enabled and synced twice; NULL with no temp file. */
static char *log_of_enable_and_syncs(nf_fx_t *f) {
    char path[] = "/tmp/firc-rs-log-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { return NULL; }
    unlink(path);
    firc_log_set_fd(fd);
    bool changed = false;
    firc_err_t e1 = firc_ruleset_enable(f->rs, NULL);
    firc_err_t e2 = firc_ruleset_sync(f->rs, &changed);
    firc_err_t e3 = firc_ruleset_sync(f->rs, &changed);
    firc_log_set_fd(1);
    char *buf = NULL;
    off_t len = lseek(fd, 0, SEEK_END);
    if (e1 == FIRC_OK && e2 == FIRC_OK && e3 == FIRC_OK && len >= 0 && lseek(fd, 0, SEEK_SET) == 0 &&
        (buf = calloc(1, (size_t)len + 1)) != NULL && read(fd, buf, (size_t)len) != len) {
        free(buf);
        buf = NULL;
    }
    close(fd);
    return buf;
}

static size_t times_in(const char *hay, const char *needle) {
    size_t n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) { n++; }
    return n;
}

/* Catches: an unwritable entry's warning dropped, missing its count, or repeated on every sync. */
TEST an_entry_that_cannot_be_written_is_warned_once(void) {
    char bad[] = "not-a-device", host[] = "192.168.1.60";
    char *deny[] = {bad}, *allow[] = {bad, host};
    nf_fx_t f;
    ASSERT(nf_up_sel(&f, NULL, 0, deny, 1));
    f.g->name = strdup("kids");
    char *log = log_of_enable_and_syncs(&f);
    nf_down(&f);
    ASSERT(log != NULL);
    size_t deny_said = times_in(log, "group kids marks no device: 1 deny entry of its selector could not be written");
    size_t allow_said = times_in(log, "allow entr");
    free(log);
    ASSERT_EQ_FMTm("the deny warning, once", (size_t)1, deny_said, "%zu");
    ASSERT_EQ_FMTm("no allow warning for it", (size_t)0, allow_said, "%zu");

    ASSERT(nf_up_sel(&f, allow, 2, NULL, 0));
    f.g->name = strdup("kids");
    log = log_of_enable_and_syncs(&f);
    nf_down(&f);
    ASSERT(log != NULL);
    allow_said = times_in(log, "group kids: 1 allow entry of its selector could not be written and marks nobody");
    deny_said = times_in(log, "marks no device");
    free(log);
    ASSERT_EQ_FMTm("the allow warning, once", (size_t)1, allow_said, "%zu");
    ASSERT_EQ_FMTm("no deny warning for it", (size_t)0, deny_said, "%zu");
    PASS();
}

static unsigned list_links(const char *name) {
    if (strcmp(name, "up0") == 0) { return 7; }
    if (strcmp(name, "up1") == 0) { return 8; }
    return strcmp(name, "lo") == 0 ? 1u : 0u;
}

static size_t defaults_via(nf_fx_t *f, uint16_t type, uint32_t oif) {
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f->kernel, m, 64), c = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == type && m[i].rtm_type == RTN_UNICAST && m[i].oif == oif && m[i].table == 100) { c++; }
    }
    return c;
}

static bool nf_up_list(nf_fx_t *f) {
    if (!nf_up(f, NULL, 0)) { return false; }
    firc_rtnl_set_nametoindex_for_test(list_links);
    const char *const names[] = {"up0", "up1"};
    return firc_group_set_ifaces(f->g, names, 2) == FIRC_OK;
}

TEST a_ruleset_starts_its_list_on_the_entry_it_was_told(void) {
    nf_fx_t f;
    ASSERT(nf_up_list(&f));
    ASSERT_STR_EQ("up0", firc_ruleset_active_iface(f.rs));
    ASSERT_EQ(NULL, firc_ruleset_link(f.rs));
    firc_ruleset_set_start(f.rs, 1, false);
    ASSERT_EQ(FIRC_OK, firc_ruleset_enable(f.rs, NULL));
    ASSERT_STR_EQ("up1", firc_ruleset_active_iface(f.rs));
    bool blocked = true;
    ASSERT_EQ_FMT((size_t)1, firc_ruleset_active(f.rs, &blocked), "%zu");
    ASSERT_FALSE(blocked);
    ASSERT_EQ_FMT((size_t)1, defaults_via(&f, RTM_NEWROUTE, 8), "%zu");
    ASSERT_EQ_FMT((size_t)0, defaults_via(&f, RTM_NEWROUTE, 7), "%zu");
    ASSERT(firc_ruleset_link(f.rs) != NULL);
    ASSERT_EQ(FIRC_OK, firc_ruleset_set_active(f.rs, 0, false));
    ASSERT_EQ_FMT((size_t)1, defaults_via(&f, RTM_DELROUTE, 8), "%zu");
    ASSERT_EQ_FMT((size_t)1, defaults_via(&f, RTM_NEWROUTE, 7), "%zu");
    f.g->enable = false;
    ASSERT_EQ(FIRC_ERR_STATE, firc_ruleset_set_active(f.rs, 1, false));
    ASSERT_EQ(NULL, firc_ruleset_link(f.rs));
    f.g->enable = true;
    ASSERT_EQ(FIRC_OK, firc_ruleset_disable(f.rs));
    ASSERT_STR_EQ("up0", firc_ruleset_active_iface(f.rs));
    ASSERT_EQ(NULL, firc_ruleset_link(f.rs));
    ASSERT_EQ(FIRC_ERR_STATE, firc_ruleset_set_active(f.rs, 1, false));
    firc_rtnl_set_nametoindex_for_test(NULL);
    nf_down(&f);
    PASS();
}

TEST a_ruleset_started_blocked_writes_no_default(void) {
    nf_fx_t f;
    ASSERT(nf_up_list(&f));
    firc_ruleset_set_start(f.rs, 1, true);
    ASSERT_EQ(FIRC_OK, firc_ruleset_enable(f.rs, NULL));
    bool blocked = false;
    ASSERT_EQ_FMT((size_t)1, firc_ruleset_active(f.rs, &blocked), "%zu");
    ASSERT(blocked);
    ASSERT_EQ_FMT((size_t)0, defaults_via(&f, RTM_NEWROUTE, 7) + defaults_via(&f, RTM_NEWROUTE, 8), "%zu");
    ASSERT_EQ(FIRC_OK, firc_ruleset_set_active(f.rs, 1, false));
    ASSERT_EQ_FMT((size_t)1, defaults_via(&f, RTM_NEWROUTE, 8), "%zu");
    firc_rtnl_set_nametoindex_for_test(NULL);
    nf_down(&f);
    PASS();
}

TEST a_list_with_an_unusable_entry_routes_nothing(void) {
    nf_fx_t f;
    ASSERT(nf_up(&f, NULL, 0));
    firc_rtnl_set_nametoindex_for_test(list_links);
    const char *const names[] = {"up0", "up 1"};
    ASSERT_EQ(FIRC_OK, firc_group_set_ifaces(f.g, names, 2));
    ASSERT_EQ(FIRC_OK, firc_ruleset_enable(f.rs, NULL));
    ASSERT_FALSE(firc_ruleset_routed(f.rs));
    ASSERT_EQ_FMT((size_t)0, defaults_via(&f, RTM_NEWROUTE, 7), "%zu");
    firc_rtnl_set_nametoindex_for_test(NULL);
    nf_down(&f);
    PASS();
}

GREATEST_MAIN_DEFS();
int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(ruleset);
    RUN_TEST(an_empty_selector_renders_no_chain);
    RUN_TEST(a_denied_address_brings_its_host_s_other_address);
    RUN_TEST(a_prefix_entry_is_written_as_its_network);
    RUN_TEST(policies_render_their_marks_and_their_hosts);
    RUN_TEST(a_policy_without_a_mark_renders_its_hosts);
    RUN_TEST(an_allow_list_of_unknown_policies_marks_nobody);
    RUN_TEST(a_mac_entry_needs_no_table_and_a_duplicate_is_one_rule);
    RUN_TEST(a_whole_family_entry_is_its_family_s_zero_prefix);
    RUN_TEST(a_prefix_off_a_byte_boundary_keeps_only_its_network_bits);
    RUN_TEST(a_deny_entry_that_cannot_be_rendered_marks_nobody);
    RUN_TEST(a_policy_entry_before_the_first_map_marks_nobody);
    RUN_TEST(a_policy_mark_that_masks_to_zero_is_not_written);
    RUN_TEST(an_address_the_table_gets_wrong_is_not_written);
    RUN_TEST(sync_renders_the_selector_again_and_says_when_it_moved);
    RUN_TEST(a_selector_follows_the_table_unless_it_names_only_macs);
    RUN_TEST(a_table_refresh_renders_only_a_routed_group);
    RUN_TEST(a_denied_address_renders_every_host_that_lists_it);
    RUN_TEST(a_policy_renders_its_segments);
    RUN_TEST(a_segment_the_table_gets_wrong_is_not_written);
    RUN_TEST(an_entry_that_cannot_be_written_is_warned_once);
    RUN_TEST(a_ruleset_starts_its_list_on_the_entry_it_was_told);
    RUN_TEST(a_ruleset_started_blocked_writes_no_default);
    RUN_TEST(a_list_with_an_unusable_entry_routes_nothing);
    GREATEST_MAIN_END();
}
