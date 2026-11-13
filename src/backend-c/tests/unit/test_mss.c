#include "greatest.h"

#include <string.h>

#include "fake_iptables.h"
#include "firc/mss.h"
#include "firc/netfilter_cleaner.h"

typedef struct {
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
} rig_t;

static const char *const k_foreign[] = {"-o", "ppp0", "-j", "ACCEPT"};
static const char *const k_jump[] = {"-j", "FIRC_MSS"};
static const char *const k_clamp1[] = {"-o", "tunvless1", "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                                       "-j", "TCPMSS", "--clamp-mss-to-pmtu"};
static const char *const k_clamp3[] = {"-o", "tunvless3", "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                                       "-j", "TCPMSS", "--clamp-mss-to-pmtu"};
static const uint8_t k_devs[] = {1, 3};

static bool rig_up(rig_t *r, firc_ipt_proto_t fam) {
    r->fake = firc_fake_ipt_new(fam);
    const char *const *rules[1] = {k_foreign};
    size_t lens[1] = {4};
    firc_fake_ipt_set_initial_rules(r->fake, "mangle", "FORWARD", rules, lens, 1);
    r->ipt = firc_ipt_new(firc_fake_ipt_as_xt(r->fake), "FIRC_");
    return r->ipt != NULL;
}

static void rig_down(rig_t *r) { firc_ipt_free(r->ipt); }

static firc_err_t write_devs(rig_t *r, const uint8_t *devs, size_t n) {
    bool v6 = firc_ipt_proto(r->ipt) == FIRC_IPT_PROTO_IPV6;
    firc_err_t err = v6 ? firc_netfilter_register_base_chains(NULL, r->ipt) : firc_netfilter_register_base_chains(r->ipt, NULL);
    if (err == FIRC_OK) { err = firc_mss_build_rules(r->ipt, "FIRC_", devs, n); }
    if (err != FIRC_OK) {
        firc_ipt_discard(r->ipt);
        return err;
    }
    return firc_ipt_commit(r->ipt);
}

static bool parts_are(const firc_ipt_rule_t *rule, const char *const *want, size_t n) {
    if (rule->n_parts != n) { return false; }
    for (size_t i = 0; i < n; i++) {
        if (strcmp(rule->parts[i], want[i]) != 0) { return false; }
    }
    return true;
}

static size_t jumps_in(rig_t *r, const char *chain) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0, found = 0;
    if (!firc_fake_ipt_get_rules(r->fake, "mangle", chain, &rules, &n)) { return 0; }
    for (size_t i = 0; i < n; i++) { found += parts_are(rules[i], k_jump, 2) ? 1u : 0u; }
    return found;
}

static enum greatest_test_res one_clamp_per_device_in(firc_ipt_proto_t fam) {
    rig_t r;
    ASSERT(rig_up(&r, fam));
    ASSERT_EQ(FIRC_OK, write_devs(&r, k_devs, 2));
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(r.fake, "mangle", "FIRC_MSS", &rules, &n));
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    ASSERT(parts_are(rules[0], k_clamp1, 12));
    ASSERT(parts_are(rules[1], k_clamp3, 12));
    ASSERT(firc_fake_ipt_get_rules(r.fake, "mangle", "FORWARD", &rules, &n));
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    ASSERT(parts_are(rules[0], k_jump, 2));
    ASSERT(parts_are(rules[1], k_foreign, 4));
    ASSERT_EQ_FMT((size_t)0, jumps_in(&r, "PREROUTING"), "%zu");
    ASSERT_EQ_FMT((size_t)0, jumps_in(&r, "POSTROUTING"), "%zu");
    rig_down(&r);
    PASS();
}

/* Catches: a device's clamp lost, reordered or on the wrong -o, or the jump not at FORWARD 1 (PREROUTING is refused). */
TEST v4_holds_one_clamp_per_device_jumped_from_forward(void) { return one_clamp_per_device_in(FIRC_IPT_PROTO_IPV4); }

/* Catches: the IPv6 engine refused or given another rule than IPv4's. */
TEST v6_holds_one_clamp_per_device_jumped_from_forward(void) { return one_clamp_per_device_in(FIRC_IPT_PROTO_IPV6); }

static enum greatest_test_res no_device_no_chain_in(firc_ipt_proto_t fam) {
    rig_t r;
    ASSERT(rig_up(&r, fam));
    ASSERT_EQ(FIRC_OK, write_devs(&r, NULL, 0));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "mangle", "FIRC_MSS"));
    ASSERT_EQ(FIRC_OK, write_devs(&r, k_devs, 2));
    ASSERT(firc_fake_ipt_chain_exists(r.fake, "mangle", "FIRC_MSS"));
    ASSERT_EQ(FIRC_OK, write_devs(&r, k_devs, 0));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "mangle", "FIRC_MSS"));
    ASSERT_EQ_FMT((size_t)0, jumps_in(&r, "FORWARD"), "%zu");
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(r.fake, "mangle", "FORWARD", &rules, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    rig_down(&r);
    PASS();
}

/* Catches: an empty chain jumped to on every packet. */
TEST no_device_stages_no_chain(void) {
    CHECK_CALL(no_device_no_chain_in(FIRC_IPT_PROTO_IPV4));
    return no_device_no_chain_in(FIRC_IPT_PROTO_IPV6);
}

/* Catches: a missing engine or device list taken for an empty one. */
TEST a_bad_call_is_refused(void) {
    rig_t r;
    ASSERT(rig_up(&r, FIRC_IPT_PROTO_IPV4));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_mss_build_rules(NULL, "FIRC_", k_devs, 2));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_mss_build_rules(r.ipt, NULL, k_devs, 2));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_mss_build_rules(r.ipt, "FIRC_", NULL, 2));
    rig_down(&r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(v4_holds_one_clamp_per_device_jumped_from_forward);
    RUN_TEST(v6_holds_one_clamp_per_device_jumped_from_forward);
    RUN_TEST(no_device_stages_no_chain);
    RUN_TEST(a_bad_call_is_refused);
    GREATEST_MAIN_END();
}
