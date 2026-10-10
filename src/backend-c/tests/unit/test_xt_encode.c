#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "xt_golden.h"
#include "../../src/xtables/xt_internal.h"

static const firc_ipt_proto_t k_fams[] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

typedef struct {
    const char *chain;
    size_t idx;
    const char *v4;
    const char *v6;
    uint32_t exts;
} rule_case_t;

static const rule_case_t k_rules[] = {
    {"FIRC_DNSOR", 0, "-p tcp -d 192.168.1.1 --dport 53 -j DNAT --to-destination :3553",
     "-p tcp -d fd00:1::1 --dport 53 -j DNAT --to-destination :3553", FIRC_XT_EXT_DNAT | FIRC_XT_EXT_TCP},
    {"FIRC_DNSOR", 1, "-p udp -d 192.168.1.1 --dport 53 -j DNAT --to-destination :3553",
     "-p udp -d fd00:1::1 --dport 53 -j DNAT --to-destination :3553", FIRC_XT_EXT_DNAT | FIRC_XT_EXT_UDP},
    {"FIRC_DNAT", 0, "-d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.34",
     "-d fd37:9a00::1/128 -j DNAT --to-destination 2606:2800:220:1:248:1893:25c8:1946", FIRC_XT_EXT_DNAT},
    {"FIRC_g1", 0, "-o nwg1 -m mark --mark 0x10000/0xff0000 -j MASQUERADE",
     "-o nwg1 -m mark --mark 0x10000/0xff0000 -j MASQUERADE", FIRC_XT_EXT_MASQUERADE | FIRC_XT_EXT_MARK},
    {"PREROUTING", 0, "-j FIRC_DNSOR", "-j FIRC_DNSOR", 0},
    {"PREROUTING", 1, "-i eth3 -j _NDM_DNAT", "-i eth3 -j _NDM_DNAT", 0},
    {"PREROUTING", 3, "-d 198.18.0.0/15 -j FIRC_DNAT", "-d fd37:9a00::/48 -j FIRC_DNAT", 0},
    {"POSTROUTING", 1, "-j FIRC_g1", "-j FIRC_g1", 0},
    {"POSTROUTING", 2, "-j FIRC_bh", "-j FIRC_bh", 0},
    {"ACME_PRE", 0, "-s 192.168.1.0/24 -p udp -m udp --dport 5353 -j RETURN",
     "-s fd00:1::/64 -p udp -m udp --dport 5353 -j RETURN", FIRC_XT_EXT_UDP},
    {"_NDM_MASQ", 1, "-o ppp0 -j MASQUERADE", "-o ppp0 -j MASQUERADE", FIRC_XT_EXT_MASQUERADE},
};

static bool same_entry(const firc_xt_entry_t *a, const firc_xt_entry_t *b) {
    return a->len == b->len && strcmp(a->jump, b->jump) == 0 && memcmp(a->bytes, b->bytes, a->len) == 0;
}

/* Catches: an encoded rule differing from iptables-restore's bytes for the same words (a field, revision, match order or byte order). */
TEST every_builder_rule_encodes_as_iptables_restore_wrote_it(void) {
    for (size_t f = 0; f < 2; f++) {
        firc_xt_info_t info;
        uint8_t *blob = NULL;
        ASSERT(firc_test_xt_read("firmware-firc", k_fams[f], &info, &blob));
        firc_xt_table_t t;
        const char *why = NULL;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(k_fams[f], &info, blob, &t, &why), "%d");
        for (size_t i = 0; i < sizeof(k_rules) / sizeof(k_rules[0]); i++) {
            const char *line = f == 0 ? k_rules[i].v4 : k_rules[i].v6;
            firc_xt_chain_t *c = firc_xt_find_chain(&t, k_rules[i].chain);
            ASSERTm(line, c != NULL && c->n_rules > k_rules[i].idx);
            firc_ipt_rule_t *r = firc_test_rule(line);
            firc_xt_entry_t e;
            memset(&e, 0, sizeof(e));
            uint32_t exts = 0;
            ASSERT_EQ_FMTm(line, FIRC_OK, firc_xt_encode(k_fams[f], r, &e, &exts), "%d");
            ASSERTm(line, same_entry(&e, &c->rules[k_rules[i].idx]));
            ASSERT_EQ_FMTm(line, k_rules[i].exts, exts, "%u");
            firc_xt_entry_clear(&e);
            firc_ipt_rule_free(r);
        }
        firc_xt_table_clear(&t);
        free(blob);
    }
    PASS();
}

/* Catches: the outiface mask one byte short or long at the 15-character limit. */
TEST an_interface_at_the_length_limit_gets_a_full_mask(void) {
    static const unsigned at_name[] = {32, 80}, at_mask[] = {64, 112};
    for (size_t f = 0; f < 2; f++) {
        firc_ipt_rule_t *r = firc_test_rule("-o abcdefghijklmno -j MASQUERADE");
        firc_xt_entry_t e;
        memset(&e, 0, sizeof(e));
        uint32_t exts = 0;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(k_fams[f], r, &e, &exts), "%d");
        ASSERT_MEM_EQ("abcdefghijklmno\0", e.bytes + at_name[f], 16);
        static const uint8_t full[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        ASSERT_MEM_EQ(full, e.bytes + at_mask[f], 16);
        firc_xt_entry_clear(&e);
        firc_ipt_rule_free(r);
    }
    PASS();
}

/* Catches: a mark without a mask matched under a partial mask (the kernel's default is every bit). */
TEST a_mark_without_a_mask_matches_every_bit(void) {
    firc_ipt_rule_t *r = firc_test_rule("-m mark --mark 0x10000 -j RETURN");
    firc_xt_entry_t e;
    memset(&e, 0, sizeof(e));
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(FIRC_IPT_PROTO_IPV4, r, &e, &exts), "%d");
    uint32_t mark, mask;
    memcpy(&mark, e.bytes + 112 + 32, 4);
    memcpy(&mask, e.bytes + 112 + 36, 4);
    ASSERT_EQ_FMT(0x10000u, mark, "%x");
    ASSERT_EQ_FMT(0xffffffffu, mask, "%x");
    ASSERT_STR_EQ("mark", (const char *)e.bytes + 112 + 2);
    ASSERT_EQ(1, e.bytes[112 + 31]);
    firc_xt_entry_clear(&e);
    firc_ipt_rule_free(r);
    PASS();
}

/* Catches: a word outside the vocabulary written anyway, or a rule the kernel would read differently from its words. */
TEST a_rule_outside_the_vocabulary_is_refused(void) {
    static const char *const v4[] = {
        "-o nwg+ -j MASQUERADE",
        "-o abcdefghijklmnop -j MASQUERADE",
        "--dport 53 -j DNAT --to-destination :3553",
        "-d 10.0.0.1 -j DNAT --to-destination :3553",
        "-m conntrack --ctstate NEW -j RETURN",
        "-d 10.0.0.1 -j DNAT --to-destination 1.2.3.4:53",
        "-d 300.1.1.1/32 -j RETURN",
        "-d 10.0.0.1/33 -j RETURN",
        "-p icmp -j RETURN",
        "-j DNAT",
        "-j MASQUERADE --random",
        "-m mark --mark zz -j RETURN",
        "-p tcp -m udp --dport 53 -j RETURN",
        "-j",
        "-d 10.0.0.1",
        "! -d 10.0.0.1 -j RETURN",
        "-j ABCDEFGHIJKLMNOPQRSTUVWXYZ012",
        "-p tcp --dport 70000 -j RETURN",
        "-p tcp --dport 90:80 -j RETURN",
        "-j RETURN -j ACCEPT",
        "-d 10.0.0.1 -d 10.0.0.2 -j RETURN",
        "-s 10.0.0.1 -s 10.0.0.2 -j RETURN",
    };
    for (size_t i = 0; i < sizeof(v4) / sizeof(v4[0]); i++) {
        firc_ipt_rule_t *r = firc_test_rule(v4[i]);
        firc_xt_entry_t e;
        memset(&e, 0, sizeof(e));
        uint32_t exts = 0;
        ASSERT_EQ_FMTm(v4[i], FIRC_ERR_INVAL, firc_xt_encode(FIRC_IPT_PROTO_IPV4, r, &e, &exts), "%d");
        ASSERTm(v4[i], e.bytes == NULL);
        firc_ipt_rule_free(r);
    }
    static const char *const v6[] = {"-d 10.0.0.1 -j RETURN", "-j DNAT --to-destination 10.0.0.1",
                                     "-d fd00::1 -d fd00::2 -j RETURN", "-s fd00::1 -s fd00::2 -j RETURN"};
    for (size_t i = 0; i < sizeof(v6) / sizeof(v6[0]); i++) {
        firc_ipt_rule_t *r = firc_test_rule(v6[i]);
        firc_xt_entry_t e;
        memset(&e, 0, sizeof(e));
        uint32_t exts = 0;
        ASSERT_EQ_FMTm(v6[i], FIRC_ERR_INVAL, firc_xt_encode(FIRC_IPT_PROTO_IPV6, r, &e, &exts), "%d");
        ASSERTm(v6[i], e.bytes == NULL);
        firc_ipt_rule_free(r);
    }
    PASS();
}

/* Catches: the probe asking the kernel for a revision other than the one the encoder writes. */
TEST the_probe_list_names_what_the_encoder_writes(void) {
    static const struct { uint32_t bit; const char *v4; const char *v6; } uses[] = {
        {FIRC_XT_EXT_DNAT, "-d 1.2.3.4/32 -j DNAT --to-destination 5.6.7.8", "-d ::1/128 -j DNAT --to-destination ::2"},
        {FIRC_XT_EXT_MASQUERADE, "-j MASQUERADE", "-j MASQUERADE"},
        {FIRC_XT_EXT_MARK, "-m mark --mark 1 -j RETURN", "-m mark --mark 1 -j RETURN"},
        {FIRC_XT_EXT_TCP, "-p tcp --dport 1 -j RETURN", "-p tcp --dport 1 -j RETURN"},
        {FIRC_XT_EXT_UDP, "-p udp --dport 1 -j RETURN", "-p udp --dport 1 -j RETURN"},
    };
    ASSERT_EQ_FMT((size_t)5, firc_xt_n_exts, "%zu");
    for (size_t d = 0; d < firc_xt_n_exts; d++) {
        const firc_xt_ext_desc_t *x = &firc_xt_exts[d];
        size_t u = 0;
        while (u < 5 && uses[u].bit != x->bit) { u++; }
        ASSERT(u < 5);
        for (size_t f = 0; f < 2; f++) {
            firc_ipt_rule_t *r = firc_test_rule(f == 0 ? uses[u].v4 : uses[u].v6);
            firc_xt_entry_t e;
            memset(&e, 0, sizeof(e));
            uint32_t exts = 0;
            ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(k_fams[f], r, &e, &exts), "%d");
            uint32_t eh = f == 0 ? 112 : 168;
            uint16_t toff;
            memcpy(&toff, e.bytes + (f == 0 ? 88 : 140), 2);
            const uint8_t *ext = x->target ? e.bytes + toff : e.bytes + eh;
            ASSERT_STR_EQ(x->name, (const char *)ext + 2);
            ASSERT_EQ_FMT(f == 0 ? x->rev4 : x->rev6, ext[31], "%u");
            ASSERT(exts & x->bit);
            firc_xt_entry_clear(&e);
            firc_ipt_rule_free(r);
        }
    }
    PASS();
}

/* Catches: an address written with host bits under its prefix, which the kernel's masked compare never matches. */
TEST a_prefix_clears_the_host_bits(void) {
    static const uint8_t dst4[4] = {198, 18, 0, 0}, dmsk4[4] = {0xff, 0xfe, 0, 0};
    static const uint8_t dst6[16] = {0xfd, 0x37, 0x9a, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t dmsk6[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static const char *const lines[] = {"-d 198.19.1.2/15 -j RETURN", "-d fd37:9a00:0:7::1/48 -j RETURN"};
    for (size_t f = 0; f < 2; f++) {
        firc_ipt_rule_t *r = firc_test_rule(lines[f]);
        firc_xt_entry_t e;
        memset(&e, 0, sizeof(e));
        uint32_t exts = 0;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(k_fams[f], r, &e, &exts), "%d");
        if (f == 0) {
            ASSERT_MEM_EQ(dst4, e.bytes + 4, 4);
            ASSERT_MEM_EQ(dmsk4, e.bytes + 12, 4);
        } else {
            ASSERT_MEM_EQ(dst6, e.bytes + 16, 16);
            ASSERT_MEM_EQ(dmsk6, e.bytes + 48, 16);
        }
        firc_xt_entry_clear(&e);
        firc_ipt_rule_free(r);
    }
    PASS();
}

/* Catches: matches laid out in a fixed order instead of the order the words name them, as iptables does. */
TEST matches_follow_the_order_of_the_words(void) {
    static const struct { const char *line; const char *first; const char *second; } cases[] = {
        {"-m mark --mark 1 -p tcp --dport 53 -j RETURN", "mark", "tcp"},
        {"-p udp --dport 53 -m mark --mark 1 -j RETURN", "udp", "mark"},
        {"-p tcp -m tcp -m mark --mark 1 --dport 53 -j RETURN", "tcp", "mark"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        firc_ipt_rule_t *r = firc_test_rule(cases[i].line);
        firc_xt_entry_t e;
        memset(&e, 0, sizeof(e));
        uint32_t exts = 0;
        ASSERT_EQ_FMTm(cases[i].line, FIRC_OK, firc_xt_encode(FIRC_IPT_PROTO_IPV4, r, &e, &exts), "%d");
        ASSERT_STR_EQm(cases[i].line, cases[i].first, (const char *)e.bytes + 112 + 2);
        ASSERT_STR_EQm(cases[i].line, cases[i].second, (const char *)e.bytes + 112 + 48 + 2);
        uint16_t toff;
        memcpy(&toff, e.bytes + 88, 2);
        ASSERT_EQ_FMTm(cases[i].line, 112 + 96, toff, "%u");
        firc_xt_entry_clear(&e);
        firc_ipt_rule_free(r);
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(every_builder_rule_encodes_as_iptables_restore_wrote_it);
    RUN_TEST(an_interface_at_the_length_limit_gets_a_full_mask);
    RUN_TEST(a_mark_without_a_mask_matches_every_bit);
    RUN_TEST(a_rule_outside_the_vocabulary_is_refused);
    RUN_TEST(the_probe_list_names_what_the_encoder_writes);
    RUN_TEST(a_prefix_clears_the_host_bits);
    RUN_TEST(matches_follow_the_order_of_the_words);
    GREATEST_MAIN_END();
}
