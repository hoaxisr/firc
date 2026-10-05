#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "fake_iptables.h"
#include "firc/netfilter_cleaner.h"
#include "firc/taprules.h"

#define PREFIX "FIRC_"
#define TAP_CHAIN PREFIX FIRC_TAP_CHAIN_SUFFIX

static firc_fakeip_t *make_pool(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37;
    c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *f = NULL;
    return firc_fakeip_new(&c, &f) == FIRC_OK ? f : NULL;
}

/* The rules of `chain`, joined, for asserting on. */
static bool joined(firc_fake_ipt_t *f, const char *table, const char *chain, char *out,
                   size_t cap) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    out[0] = '\0';
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        char *s = firc_ipt_rule_string(rules[i]);
        if (s == NULL) { return false; }
        size_t len = strlen(out);
        snprintf(out + len, cap - len, "%s%s", len ? "\n" : "", s);
        free(s);
    }
    return true;
}

/* Catches: removing capture rules that are not there reported as an error. */
TEST removing_nothing_is_not_an_error(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT_EQ(FIRC_OK, firc_tap_rules_remove(ipt, PREFIX));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a chain with only some of its rules or no jump read as still installed. */
TEST half_the_rules_is_not_there(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_fake_ipt_reset(fake);
    static const char *jump_only[] = {"-j", TAP_CHAIN};
    const char *const *seed[] = {jump_only};
    const size_t lens[] = {2};
    ASSERT_EQ(FIRC_OK,
              firc_fake_ipt_set_initial_rules(fake, "mangle", "FORWARD", seed, lens, 1));

    bool there = true;
    ASSERT_EQ(FIRC_OK, firc_tap_rules_present(ipt, PREFIX, &there));
    ASSERT_FALSEm("a jump to nothing is not watching", there);

    firc_fake_ipt_reset(fake);
    static const char *capture[] = {"-i", "br0", "-j", "NFLOG", "--nflog-group", "5"};
    const char *const *chain_seed[] = {capture};
    const size_t chain_lens[] = {6};
    ASSERT_EQ(FIRC_OK,
              firc_fake_ipt_set_initial_rules(fake, "mangle", TAP_CHAIN, chain_seed, chain_lens,
                                              1));
    there = true;
    ASSERT_EQ(FIRC_OK, firc_tap_rules_present(ipt, PREFIX, &there));
    ASSERT_FALSEm("a chain nothing jumps to sees no packets", there);

    firc_fake_ipt_reset(fake);
    ASSERT_EQ(FIRC_OK,
              firc_fake_ipt_set_initial_rules(fake, "mangle", TAP_CHAIN, NULL, NULL, 0));
    ASSERT_EQ(FIRC_OK,
              firc_fake_ipt_set_initial_rules(fake, "mangle", "FORWARD", seed, lens, 1));
    there = true;
    ASSERT_EQ(FIRC_OK, firc_tap_rules_present(ipt, PREFIX, &there));
    ASSERT_FALSEm("an empty chain is as deaf as no chain", there);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST the_preflight_asks_about_the_rules_that_get_installed(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_supported(ipt, PREFIX, pool, lan, 1));
    const char *probe = firc_fake_ipt_restore_log(fake);
    ASSERTm("the kernel was actually asked", probe != NULL);
    char asked[4096];
    snprintf(asked, sizeof(asked), "%s", probe);
    ASSERTm("and nothing of the probe is left",
            !firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN FIRC_TAP_PROBE_SUFFIX));
    ASSERTm("no jump was written", strstr(asked, "FORWARD") == NULL);

    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    char installed[1024];
    ASSERT(joined(fake, "mangle", TAP_CHAIN, installed, sizeof(installed)));

    char want[1400] = {0};
    char installed_copy[1024];
    snprintf(installed_copy, sizeof(installed_copy), "%s", installed);
    for (char *line = strtok(installed_copy, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        size_t len = strlen(want);
        snprintf(want + len, sizeof(want) - len, "-A %s %s\n", TAP_CHAIN FIRC_TAP_PROBE_SUFFIX,
                 line);
    }
    ASSERTm("and about the same rules, to the byte", strstr(asked, want) != NULL);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST the_capture_rules_go_in_a_chain_of_our_own(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    char buf[1024];
    ASSERTm("the chain is there", joined(fake, "mangle", TAP_CHAIN, buf, sizeof(buf)));
    ASSERT_STR_EQ("-i br0 -m conntrack --ctstate NEW ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 5 --nflog-threshold 1\n"
                  "-i br0 -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-p tcp --dport 443 --tcp-flags SYN,ACK ACK "
                  "-m length --length 100: "
                  "-m connbytes --connbytes 2:8 --connbytes-dir original "
                  "--connbytes-mode packets "
                  "-m string --algo bm --hex-string |1603| --from 40 --to 84 "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 4 --nflog-threshold 1",
                  buf);

    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERT_STR_EQm("and FORWARD jumps to it", "-j " TAP_CHAIN, buf);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: two interfaces' rule pairs interleaved or out of order in the chain. */
TEST each_lan_interface_gets_its_own_pair_in_the_chain(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0", "br1"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", TAP_CHAIN, &rules, &n));
    ASSERT_EQ_FMTm("a pair per interface", (size_t)4, n, "%zu");

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST the_v6_engine_gets_the_v6_pool(void) {
    firc_fakeip_t *pool = make_pool();
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT(ipt != NULL);
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    char buf[1024];
    ASSERT(joined(fake, "mangle", TAP_CHAIN, buf, sizeof(buf)));
    ASSERTm("the v6 pool is excluded", strstr(buf, "! --ctorigdst fd37::/48") != NULL);
    ASSERT_FALSEm("and no v4 prefix is in it", strstr(buf, "198.18") != NULL);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST removing_takes_the_chain_and_the_jump(void) {
    firc_fakeip_t *pool = make_pool();
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));

    ASSERT_EQ(FIRC_OK, firc_tap_rules_remove(ipt, PREFIX));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSEm("the chain is gone", firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));

    char buf[1024];
    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERT_STR_EQm("and so is the jump", "", buf);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST the_jump_goes_first_and_the_other_rules_stay(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);

    static const char *rule_a[] = {"-j", "NDMMARK", "--set-xndmmark", "0x4/0x0"};
    static const char *rule_b[] = {"-o", "ppp0", "-p", "tcp", "-j", "TCPMSS",
                                   "--clamp-mss-to-pmtu"};
    const char *const *seed[] = {rule_a, rule_b};
    const size_t lens[] = {4, 7};
    ASSERT_EQ(FIRC_OK,
              firc_fake_ipt_set_initial_rules(fake, "mangle", "FORWARD", seed, lens, 2));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    char buf[1024];
    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERT_STR_EQm("ours first, theirs untouched",
                   "-j " TAP_CHAIN "\n"
                   "-j NDMMARK --set-xndmmark 0x4/0x0\n"
                   "-o ppp0 -p tcp -j TCPMSS --clamp-mss-to-pmtu",
                   buf);

    ASSERT_EQ(FIRC_OK, firc_tap_rules_remove(ipt, PREFIX));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERT_STR_EQ("-j NDMMARK --set-xndmmark 0x4/0x0\n"
                  "-o ppp0 -p tcp -j TCPMSS --clamp-mss-to-pmtu",
                  buf);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST installing_twice_leaves_one_pair(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", TAP_CHAIN, &rules, &n));
    ASSERT_EQ_FMTm("one pair, not two", (size_t)2, n, "%zu");

    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", "FORWARD", &rules, &n));
    ASSERT_EQ_FMTm("and one jump", (size_t)1, n, "%zu");

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_killed_capture_is_swept_by_the_daemons_own_cleaner(void) {
    firc_fakeip_t *pool = make_pool();
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));

    ASSERT_EQ(FIRC_OK, firc_netfilter_clean_iptables(ipt, NULL, PREFIX));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_FALSEm("the chain a dead capture left is gone",
                  firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));
    char buf[1024];
    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERT_STR_EQm("and the jump to it with it", "", buf);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_firmware_rewrite_takes_the_rules_away(void) {
    firc_fakeip_t *pool = make_pool();
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));

    firc_fake_ipt_reset(fake);
    ASSERT_FALSEm("gone, with nothing said", firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));

    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_capture_can_tell_whether_its_rules_are_still_there(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));

    bool there = true;
    ASSERT_EQ(FIRC_OK, firc_tap_rules_present(ipt, PREFIX, &there));
    ASSERT_FALSEm("nothing installed yet", there);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_EQ(FIRC_OK, firc_tap_rules_present(ipt, PREFIX, &there));
    ASSERTm("installed and jumped to", there);

    firc_fake_ipt_reset(fake);
    ASSERT_EQ(FIRC_OK, firc_tap_rules_present(ipt, PREFIX, &there));
    ASSERT_FALSEm("taken, and the capture can see that", there);

    ASSERT_EQ(FIRC_OK, firc_tap_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_EQ(FIRC_OK, firc_tap_rules_present(ipt, PREFIX, &there));
    ASSERT(there);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST install_refuses_what_build_refuses(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));

    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_install(ipt, PREFIX, pool, NULL, 0));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_supported(ipt, PREFIX, pool, NULL, 0));
    const char *bad_lan[] = {"not an iface"};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_install(ipt, PREFIX, pool, bad_lan, 1));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_supported(ipt, PREFIX, pool, bad_lan, 1));

    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSEm("a refused install stages nothing",
                  firc_fake_ipt_chain_exists(fake, "mangle", TAP_CHAIN));
    ASSERT_FALSEm("and FORWARD was never touched to add a jump",
                  firc_fake_ipt_chain_exists(fake, "mangle", "FORWARD"));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(removing_nothing_is_not_an_error);
    RUN_TEST(half_the_rules_is_not_there);

    RUN_TEST(the_preflight_asks_about_the_rules_that_get_installed);
    RUN_TEST(the_capture_rules_go_in_a_chain_of_our_own);
    RUN_TEST(each_lan_interface_gets_its_own_pair_in_the_chain);
    RUN_TEST(the_v6_engine_gets_the_v6_pool);
    RUN_TEST(removing_takes_the_chain_and_the_jump);
    RUN_TEST(the_jump_goes_first_and_the_other_rules_stay);
    RUN_TEST(installing_twice_leaves_one_pair);
    RUN_TEST(a_killed_capture_is_swept_by_the_daemons_own_cleaner);
    RUN_TEST(a_firmware_rewrite_takes_the_rules_away);
    RUN_TEST(a_capture_can_tell_whether_its_rules_are_still_there);
    RUN_TEST(install_refuses_what_build_refuses);
    GREATEST_MAIN_END();
}
