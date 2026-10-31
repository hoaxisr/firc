#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fake_iptables.h"
#include "xt_golden.h"
#include "firc/autolistrules.h"
#include "firc/netfilter_cleaner.h"
#include "../../src/xtables/xt_internal.h"

#define PREFIX "FIRC_"
#define AL_CHAIN PREFIX FIRC_AUTOLIST_CHAIN_SUFFIX

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

static bool joined(firc_fake_ipt_t *f, const char *table, const char *chain, char *out, size_t cap) {
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

TEST the_rules_go_in_a_chain_of_their_own(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    char buf[4096];
    ASSERT(joined(fake, "mangle", AL_CHAIN, buf, sizeof(buf)));
    ASSERT_STR_EQ("-i br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-m tcp --dport 443 --tcp-flags SYN,ACK ACK "
                  "-m length --length 100:65535 "
                  "-m connbytes --connbytes 2:128 --connbytes-mode packets --connbytes-dir original "
                  "-m string --hex-string \"|1603|\" --algo bm --from 40 --to 84 "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 6 --nflog-threshold 1\n"
                  "-o br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m tcp --sport 443 --tcp-flags RST RST "
                  "-m connbytes --connbytes 0:255 --connbytes-mode bytes --connbytes-dir reply "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 7 --nflog-threshold 1\n"
                  "-o br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m tcp --sport 443 "
                  "-m connbytes --connbytes 512:4096 --connbytes-mode bytes --connbytes-dir reply "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 8 --nflog-threshold 1\n"
                  "-i br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-m tcp --dport 443 --tcp-flags FIN FIN "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 9 --nflog-threshold 1\n"
                  "-i br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-m tcp --dport 443 --tcp-flags RST,ACK RST,ACK "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 10 --nflog-threshold 1\n"
                  "-i br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-m tcp --dport 443 --tcp-flags SYN,ACK SYN "
                  "-m connbytes --connbytes 1:18446744073709551615 --connbytes-mode packets --connbytes-dir original "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 11 --nflog-threshold 1",
                  buf);

    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERT_STR_EQm("and FORWARD jumps to it", "-j " AL_CHAIN, buf);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST the_preflight_leaves_nothing_behind(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_autolist_rules_supported(ipt, PREFIX, pool, lan, 1));
    ASSERTm("the kernel was asked", firc_fake_ipt_writes_log(fake) != NULL);
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", AL_CHAIN FIRC_AUTOLIST_PROBE_SUFFIX));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", AL_CHAIN));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_chain_left_unstaged_goes_away(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "mangle", AL_CHAIN));
    ASSERT_EQ(FIRC_OK, firc_netfilter_register_base_chains(ipt, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERTm("switched off, the next pass takes the chain away",
            !firc_fake_ipt_chain_exists(fake, "mangle", AL_CHAIN));
    char buf[1024];
    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERTm("and the jump to it", strstr(buf, AL_CHAIN) == NULL);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST each_family_and_interface_gets_its_six(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0", "br1"};
    ASSERT_EQ(FIRC_OK, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", AL_CHAIN, &rules, &n));
    ASSERT_EQ(12u, (unsigned)n);
    char buf[8192];
    ASSERT(joined(fake, "mangle", AL_CHAIN, buf, sizeof(buf)));
    ASSERTm("the v6 hello is searched for past the longer header", strstr(buf, "--from 60 --to 104") != NULL);
    ASSERTm("the pool excluded is the v6 one", strstr(buf, "! --ctorigdst fd37::/48") != NULL);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_bad_interface_registers_nothing(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);
    const char *lan[] = {"br0 -j ACCEPT"};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 0));
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

typedef struct {
    size_t n;
    unsigned family[16];
    char line[16][1024];
} built_t;

static void collect(void *ud, unsigned family, const char *const *args, size_t n_args) {
    built_t *b = ud;
    if (b->n >= 16) { return; }
    b->family[b->n] = family;
    char *out = b->line[b->n];
    out[0] = '\0';
    for (size_t i = 0; i < n_args; i++) {
        size_t len = strlen(out);
        snprintf(out + len, sizeof(b->line[0]) - len, "%s%s", i ? " " : "", args[i]);
    }
    b->n++;
}

static bool build_br0(built_t *b) {
    firc_fakeip_t *pool = make_pool();
    if (pool == NULL) { return false; }
    memset(b, 0, sizeof(*b));
    const char *lan[] = {"br0"};
    firc_err_t err = firc_autolist_rules_build(pool, lan, 1, collect, b);
    firc_fakeip_free(pool);
    return err == FIRC_OK;
}

TEST reset_rule_counts_only_before_server_data(void) {
    built_t b;
    ASSERT(build_br0(&b));
    ASSERT_EQ(12u, (unsigned)b.n);
    ASSERT(strstr(b.line[1], "--tcp-flags RST RST") != NULL);
    ASSERT(strstr(b.line[1], "--connbytes 0:255 --connbytes-dir reply --connbytes-mode bytes") != NULL);
    ASSERT(strstr(b.line[7], "--connbytes 0:255 --connbytes-dir reply --connbytes-mode bytes") != NULL);
    PASS();
}

TEST answered_rule_is_early_band(void) {
    built_t b;
    ASSERT(build_br0(&b));
    ASSERT(strstr(b.line[2], "--connbytes 512:4096 --connbytes-dir reply --connbytes-mode bytes") != NULL);
    ASSERT(strstr(b.line[2], "--nflog-group 8 ") != NULL);
    PASS();
}

TEST fin_rule_is_client_side(void) {
    built_t b;
    ASSERT(build_br0(&b));
    ASSERT_STR_EQ("-i br0 -m conntrack ! --ctorigdst 198.18.0.0/15 -m mark ! --mark 0x40000000/0x40000000 "
                  "-p tcp --dport 443 --tcp-flags FIN FIN -m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 9 --nflog-threshold 1",
                  b.line[3]);
    ASSERT_STR_EQ("-i br0 -m conntrack ! --ctorigdst fd37::/48 -m mark ! --mark 0x40000000/0x40000000 "
                  "-p tcp --dport 443 --tcp-flags FIN FIN -m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 9 --nflog-threshold 1",
                  b.line[9]);
    PASS();
}

TEST client_rst_rule_needs_ack(void) {
    built_t b;
    ASSERT(build_br0(&b));
    ASSERT_STR_EQ("-i br0 -m conntrack ! --ctorigdst 198.18.0.0/15 -m mark ! --mark 0x40000000/0x40000000 "
                  "-p tcp --dport 443 --tcp-flags RST,ACK RST,ACK -m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 10 --nflog-threshold 1",
                  b.line[4]);
    ASSERT_STR_EQ("-i br0 -m conntrack ! --ctorigdst fd37::/48 -m mark ! --mark 0x40000000/0x40000000 "
                  "-p tcp --dport 443 --tcp-flags RST,ACK RST,ACK -m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 10 --nflog-threshold 1",
                  b.line[10]);
    PASS();
}

TEST syn_rule_is_client_side_any_position(void) {
    built_t b;
    ASSERT(build_br0(&b));
    ASSERT_STR_EQ("-i br0 -m conntrack ! --ctorigdst 198.18.0.0/15 -m mark ! --mark 0x40000000/0x40000000 "
                  "-p tcp --dport 443 --tcp-flags SYN,ACK SYN "
                  "-m connbytes --connbytes 1: --connbytes-dir original --connbytes-mode packets "
                  "-m limit --limit 500/sec --limit-burst 500 -j NFLOG --nflog-group 11 --nflog-threshold 1",
                  b.line[5]);
    ASSERT_STR_EQ("-i br0 -m conntrack ! --ctorigdst fd37::/48 -m mark ! --mark 0x40000000/0x40000000 "
                  "-p tcp --dport 443 --tcp-flags SYN,ACK SYN "
                  "-m connbytes --connbytes 1: --connbytes-dir original --connbytes-mode packets "
                  "-m limit --limit 500/sec --limit-burst 500 -j NFLOG --nflog-group 11 --nflog-threshold 1",
                  b.line[11]);
    PASS();
}

TEST encoder_takes_every_autolist_rule(void) {
    built_t b;
    ASSERT(build_br0(&b));
    ASSERT_EQ(12u, (unsigned)b.n);
    for (size_t i = 0; i < b.n; i++) {
        firc_ipt_proto_t fam = b.family[i] == FIRC_FAM_V6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4;
        firc_ipt_rule_t *r = firc_test_rule(b.line[i]);
        ASSERT(r != NULL);
        firc_xt_entry_t e;
        uint32_t exts = 0;
        firc_err_t err = firc_xt_encode(fam, 0, r, &e, &exts);
        firc_ipt_rule_free(r);
        free(e.bytes);
        ASSERT_EQm(b.line[i], FIRC_OK, err);
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_rules_go_in_a_chain_of_their_own);
    RUN_TEST(the_preflight_leaves_nothing_behind);
    RUN_TEST(a_chain_left_unstaged_goes_away);
    RUN_TEST(each_family_and_interface_gets_its_six);
    RUN_TEST(a_bad_interface_registers_nothing);
    RUN_TEST(reset_rule_counts_only_before_server_data);
    RUN_TEST(answered_rule_is_early_band);
    RUN_TEST(fin_rule_is_client_side);
    RUN_TEST(client_rst_rule_needs_ack);
    RUN_TEST(syn_rule_is_client_side_any_position);
    RUN_TEST(encoder_takes_every_autolist_rule);
    GREATEST_MAIN_END();
}
