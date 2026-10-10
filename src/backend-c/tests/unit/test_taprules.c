#include "greatest.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fake_iptables.h"
#include "firc/ipset_to_link.h"
#include "firc/mark.h"
#include "firc/netfilter_cleaner.h"
#include "firc/taprules.h"

/* A pool with both families: firc_fakeip_new refuses one missing either. */
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

typedef struct {
    size_t n;
    unsigned family[16];
    char joined[16][512];
} caught_t;

static void catch_rule(void *ud, unsigned family, const char *const *args, size_t n_args) {
    caught_t *c = ud;
    if (c->n >= 16) { return; }
    c->family[c->n] = family;
    char *at = c->joined[c->n];
    size_t left = sizeof(c->joined[0]);
    for (size_t i = 0; i < n_args; i++) {
        size_t len = strlen(args[i]);
        if (len + 2 > left) { break; }
        if (i > 0) { *at++ = ' '; left--; }
        memcpy(at, args[i], len);
        at += len;
        left -= len;
    }
    *at = '\0';
    c->n++;
}

/* Whether the space-joined argv `joined` carries `tok` as a whole word, not a substring. */
static bool has_token(const char *joined, const char *tok) {
    size_t tlen = strlen(tok);
    const char *p = joined;
    while ((p = strstr(p, tok)) != NULL) {
        bool left_ok = (p == joined) || p[-1] == ' ';
        bool right_ok = p[tlen] == '\0' || p[tlen] == ' ';
        if (left_ok && right_ok) { return true; }
        p += tlen;
    }
    return false;
}

/* Catches: any field of the new-connection or ClientHello rule wider or narrower than written. */
TEST the_rules_for_one_lan_interface_are_the_ones_written_down(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    caught_t c = {0};
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_build(pool, lan, 1, catch_rule, &c));
    ASSERT_EQ_FMTm("new+hello per family", (size_t)4, c.n, "%zu");

    ASSERT_EQ_FMT((unsigned)FIRC_FAM_V4, c.family[0], "%u");
    ASSERT_STR_EQm("the new-connection rule",
                  "-i br0 -m conntrack --ctstate NEW ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 5 --nflog-threshold 1",
                  c.joined[0]);

    ASSERT_EQ_FMT((unsigned)FIRC_FAM_V4, c.family[1], "%u");
    ASSERT_STR_EQm("the ClientHello rule, right after it",
                  "-i br0 -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-p tcp --dport 443 --tcp-flags SYN,ACK ACK "
                  "-m length --length 100: "
                  "-m connbytes --connbytes 2:8 --connbytes-dir original "
                  "--connbytes-mode packets "
                  "-m string --algo bm --hex-string |1603| --from 40 --to 84 "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 4 --nflog-threshold 1",
                  c.joined[1]);

    ASSERT_EQ_FMT((unsigned)FIRC_FAM_V6, c.family[2], "%u");
    ASSERT_EQ_FMT((unsigned)FIRC_FAM_V6, c.family[3], "%u");
    ASSERTm("v6 new rule excludes the v6 pool", strstr(c.joined[2], "! --ctorigdst fd37::/48") != NULL);
    ASSERTm("v6 hello rule searches the v6 window", strstr(c.joined[3], "--from 60 --to 104") != NULL);

    firc_fakeip_free(pool);
    PASS();
}

/* Catches: one interface's rule pair leaking into another's. */
TEST each_lan_interface_gets_its_own_pair(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    caught_t c = {0};
    const char *lan[] = {"br0", "br1"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_build(pool, lan, 2, catch_rule, &c));
    ASSERT_EQ_FMTm("a pair per family per interface", (size_t)8, c.n, "%zu");

    ASSERTm("br0 new", has_token(c.joined[0], "br0"));
    ASSERTm("br0 hello", has_token(c.joined[1], "br0"));
    ASSERTm("br0 v6 new", has_token(c.joined[2], "br0"));
    ASSERTm("br0 v6 hello", has_token(c.joined[3], "br0"));
    ASSERTm("br1 new", has_token(c.joined[4], "br1"));
    ASSERTm("br1 hello", has_token(c.joined[5], "br1"));
    ASSERTm("br1 v6 new", has_token(c.joined[6], "br1"));
    ASSERTm("br1 v6 hello", has_token(c.joined[7], "br1"));

    ASSERTm("br1's rule does not carry br0's interface", !has_token(c.joined[4], "br0"));
    ASSERTm("br0's rule does not carry br1's interface", !has_token(c.joined[0], "br1"));

    ASSERT_EQ_FMT((unsigned)FIRC_FAM_V4, c.family[4], "%u");
    ASSERT_EQ_FMT((unsigned)FIRC_FAM_V4, c.family[5], "%u");
    ASSERT_EQ_FMT((unsigned)FIRC_FAM_V6, c.family[6], "%u");
    ASSERT_EQ_FMT((unsigned)FIRC_FAM_V6, c.family[7], "%u");
    ASSERTm("br1 v4 new is the new-connection rule", has_token(c.joined[4], "NEW"));
    ASSERTm("br1 v4 hello is the ClientHello rule", strstr(c.joined[5], "--dport 443") != NULL);
    ASSERTm("br1 v6 new is the new-connection rule", has_token(c.joined[6], "NEW"));
    ASSERTm("br1 v6 hello is the ClientHello rule", strstr(c.joined[7], "--dport 443") != NULL);
    ASSERTm("br1 v6 hello searches the v6 window", strstr(c.joined[7], "--from 60 --to 104") != NULL);

    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the pool excluded with `-d`, which sees the post-DNAT address and excludes nothing. */
TEST firc_s_own_traffic_never_reaches_the_tap(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    caught_t c = {0};
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_build(pool, lan, 1, catch_rule, &c));
    ASSERT_EQ_FMT((size_t)4, c.n, "%zu");

    for (size_t i = 0; i < 4; i++) {
        const bool v6 = c.family[i] == FIRC_FAM_V6;
        const char *want = v6 ? "! --ctorigdst fd37::/48" : "! --ctorigdst 198.18.0.0/15";
        ASSERTm("carries the original-destination exclusion", strstr(c.joined[i], want) != NULL);
        ASSERTm("and never a bare -d, which would exclude nothing post-DNAT here",
                !has_token(c.joined[i], "-d"));
    }

    firc_fakeip_free(pool);
    PASS();
}

typedef struct {
    bool neg;
    uint32_t val, mask;
} mark_match_t;

static bool parse_vm(const char *s, uint32_t *val, uint32_t *mask) {
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 0);
    if (end == s || *end != '/') { return false; }
    const char *m = end + 1;
    unsigned long k = strtoul(m, &end, 0);
    if (end == m || *end != '\0' || v > 0xffffffffUL || k > 0xffffffffUL) { return false; }
    *val = (uint32_t)v;
    *mask = (uint32_t)k;
    return true;
}

/* Exactly one `-m mark` match in the rule, or false. */
static bool mark_match_of(const char *joined, mark_match_t *out) {
    char copy[512];
    snprintf(copy, sizeof(copy), "%s", joined);
    char *tok[64];
    size_t n = 0;
    char *save = NULL;
    for (char *t = strtok_r(copy, " ", &save); t != NULL && n < 64; t = strtok_r(NULL, " ", &save)) {
        tok[n++] = t;
    }
    size_t found = 0;
    for (size_t i = 0; i + 1 < n; i++) {
        if (strcmp(tok[i], "-m") != 0 || strcmp(tok[i + 1], "mark") != 0) { continue; }
        size_t j = i + 2;
        bool neg = j < n && strcmp(tok[j], "!") == 0;
        if (neg) { j++; }
        if (j + 1 >= n || strcmp(tok[j], "--mark") != 0) { return false; }
        if (!parse_vm(tok[j + 1], &out->val, &out->mask)) { return false; }
        out->neg = neg;
        found++;
    }
    return found == 1;
}

/* Whether a packet carrying `mark` gets past the rule's mark match, so it can still be captured. */
static bool passes(const mark_match_t *m, uint32_t mark) {
    bool hit = (mark & m->mask) == m->val;
    return m->neg ? !hit : hit;
}

typedef struct {
    size_t n;
    uint32_t after[16];
    bool chunk, subnet;
} marks_t;

static bool firc_marks_over(uint32_t field, uint32_t before, marks_t *out) {
    memset(out, 0, sizeof(*out));
    firc_fakeip_t *pool = make_pool();
    if (pool == NULL) { return false; }
    firc_ip_t v4, v6;
    bool ok = firc_fakeip_get(pool, "a.example.com", "g1", 1000, &v4, &v6) == FIRC_OK;
    firc_fakeip_snapshot_t *snap = ok ? firc_fakeip_snapshot_take(pool) : NULL;
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    uint32_t mark = 0;
    const firc_ipv4_subnet_t sub[] = {{.addr = {10, 1, 0, 0}, .cidr = 16}};
    ok = ok && snap != NULL && firc_netfilter_register_base_chains(ipt, NULL) == FIRC_OK &&
         firc_mark_for_field(field, &mark) &&
         firc_ipset_to_link_build_rules(ipt, "FIRC_g1", "nwg0", mark, field, snap, "g1") ==
             FIRC_OK &&
         firc_ipset_to_link_build_subnet_rules(ipt, "FIRC_g1", mark, sub, 1, NULL, 0) ==
             FIRC_OK &&
         firc_ipt_commit(ipt) == FIRC_OK;

    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ok = ok && firc_fake_ipt_get_rules(f, "mangle", "FIRC_g1", &rules, &n);
    for (size_t i = 0; ok && i < n; i++) {
        const firc_ipt_rule_t *r = rules[i];
        for (size_t k = 0; k + 1 < r->n_parts; k++) {
            if (strcmp(r->parts[k], "--set-xmark") != 0) { continue; }
            uint32_t v = 0, m = 0;
            if (!parse_vm(r->parts[k + 1], &v, &m) || out->n >= 16) {
                ok = false;
                break;
            }
            out->after[out->n++] = (before & ~m) ^ v;
            if (firc_ipt_rule_contains(r, "-d 198.18.")) { out->chunk = true; }
            if (firc_ipt_rule_contains(r, "-d 10.1.0.0/16")) { out->subnet = true; }
        }
    }
    firc_ipt_free(ipt);
    if (snap != NULL) { firc_fakeip_snapshot_free(snap); }
    firc_fakeip_free(pool);
    return ok;
}

TEST a_flow_firc_marked_never_reaches_the_tap_and_a_policy_host_s_does(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    caught_t c = {0};
    const char *lan[] = {"br0", "br1"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_build(pool, lan, 2, catch_rule, &c));
    firc_fakeip_free(pool);
    ASSERT_EQ_FMT((size_t)8, c.n, "%zu");

    static const uint32_t policy = 0x0ffffaaa;
    static const uint32_t fields[] = {1, 3, 255};

    for (size_t i = 0; i < c.n; i++) {
        mark_match_t m;
        ASSERTm("every rule carries exactly one mark match", mark_match_of(c.joined[i], &m));
        ASSERTm("and still the original-destination exclusion",
                strstr(c.joined[i], "! --ctorigdst ") != NULL);

        ASSERTm("an unmarked packet can be captured", passes(&m, 0));
        ASSERTm("so can a policy host's, whose mark fills the group field's bits",
                passes(&m, policy));
        ASSERTm("and the source-ipset package's 0x989", passes(&m, 0x989));

        for (size_t fi = 0; fi < sizeof(fields) / sizeof(fields[0]); fi++) {
            const uint32_t before[] = {0, policy};
            for (size_t b = 0; b < 2; b++) {
                marks_t mk;
                ASSERTm("firc's own group rules build", firc_marks_over(fields[fi], before[b], &mk));
                ASSERTm("a chunk rule marked", mk.chunk);
                ASSERTm("a subnet rule marked", mk.subnet);
                for (size_t k = 0; k < mk.n; k++) {
                    ASSERTm("a packet firc marked is not captured", !passes(&m, mk.after[k]));
                }
            }
        }
    }
    PASS();
}

/* Catches: an empty or overlong interface name built into a rule, or a partial set built. */
TEST an_interface_that_is_not_one_is_refused(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    caught_t c = {0};
    char too_long[64];
    memset(too_long, 'e', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';

    const char *empty_lan[] = {""};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_build(pool, empty_lan, 1, catch_rule, &c));

    const char *null_lan[] = {NULL};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_build(pool, null_lan, 1, catch_rule, &c));

    const char *long_lan[] = {too_long};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_build(pool, long_lan, 1, catch_rule, &c));

    const char *mixed_lan[] = {"br0", "not an iface"};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_build(pool, mixed_lan, 2, catch_rule, &c));

    ASSERT_EQ_FMTm("nothing built on any refusal", (size_t)0, c.n, "%zu");
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: an empty interface list building no rules without an error. */
TEST no_lan_interface_is_refused(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    caught_t c = {0};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_build(pool, NULL, 0, catch_rule, &c));
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_tap_rules_build(pool, lan, 0, catch_rule, &c));
    ASSERT_EQ_FMT((size_t)0, c.n, "%zu");
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the refusal's module list drifting from the modules the rules actually use. */
TEST the_module_list_names_every_module_the_lan_rules_use(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    caught_t c = {0};
    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_tap_rules_build(pool, lan, 1, catch_rule, &c));
    ASSERT_EQ_FMT((size_t)4, c.n, "%zu");

    static const char *want_modules[] = {"conntrack", "mark", "limit", "string", "length", "connbytes"};
    for (size_t m = 0; m < sizeof(want_modules) / sizeof(want_modules[0]); m++) {
        char xt_name[32];
        snprintf(xt_name, sizeof(xt_name), "xt_%s", want_modules[m]);
        ASSERTm(xt_name, strstr(FIRC_TAP_LAN_MODULES, xt_name) != NULL);
    }
    ASSERTm("xt_NFLOG", strstr(FIRC_TAP_LAN_MODULES, "xt_NFLOG") != NULL);

    for (size_t i = 0; i < c.n; i++) {
        char copy[512];
        snprintf(copy, sizeof(copy), "%s", c.joined[i]);
        char *save = NULL;
        for (char *tok = strtok_r(copy, " ", &save); tok != NULL; tok = strtok_r(NULL, " ", &save)) {
            if (strcmp(tok, "-m") != 0) { continue; }
            char *mod = strtok_r(NULL, " ", &save);
            ASSERT(mod != NULL);
            char xt_name[32];
            snprintf(xt_name, sizeof(xt_name), "xt_%s", mod);
            ASSERTm(xt_name, strstr(FIRC_TAP_LAN_MODULES, xt_name) != NULL);
        }
    }

    firc_fakeip_free(pool);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_rules_for_one_lan_interface_are_the_ones_written_down);
    RUN_TEST(each_lan_interface_gets_its_own_pair);
    RUN_TEST(firc_s_own_traffic_never_reaches_the_tap);
    RUN_TEST(a_flow_firc_marked_never_reaches_the_tap_and_a_policy_host_s_does);
    RUN_TEST(an_interface_that_is_not_one_is_refused);
    RUN_TEST(no_lan_interface_is_refused);
    RUN_TEST(the_module_list_names_every_module_the_lan_rules_use);
    GREATEST_MAIN_END();
}
