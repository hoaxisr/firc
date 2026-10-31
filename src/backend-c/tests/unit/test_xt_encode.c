#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "firc/taprules.h"
#include "xt_golden.h"
#include "../../src/xtables/xt_internal.h"

static const firc_ipt_proto_t k_fams[] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

static firc_err_t enc(firc_ipt_proto_t fam, const char *line, firc_xt_entry_t *e, uint32_t *exts) {
    firc_ipt_rule_t *r = firc_test_rule(line);
    firc_err_t err = firc_xt_encode(fam, 0, r, e, exts);
    firc_ipt_rule_free(r);
    return err;
}

static const uint8_t *match_named(firc_ipt_proto_t fam, const firc_xt_entry_t *e, const char *name) {
    uint32_t eh = firc_xt_ehdr(fam), toff = firc_xt_rd16(e->bytes + firc_xt_at_toff(fam));
    for (uint32_t m = eh; m < toff; m += firc_xt_rd16(e->bytes + m)) {
        if (strcmp((const char *)e->bytes + m + 2, name) == 0) { return e->bytes + m + XT_MATCH_HDR_LEN; }
    }
    return NULL;
}

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

static const rule_case_t k_redir_rules[] = {
    {"FIRC_REDIR", 0, "-p tcp -m mark --mark 0x40050000/0x40ff0000 -j REDIRECT --to-ports 3603", NULL,
     FIRC_XT_EXT_MARK | FIRC_XT_EXT_REDIRECT},
    {"FIRC_REDIR", 1, "-p tcp -m mark --mark 0x40060000/0x40ff0000 -j REDIRECT --to-ports 3600-3601", NULL,
     FIRC_XT_EXT_MARK | FIRC_XT_EXT_REDIRECT},
    {"PREROUTING", 0, "-p tcp -m mark --mark 0x40000000/0x40000000 -m addrtype ! --dst-type LOCAL -j FIRC_REDIR", NULL,
     FIRC_XT_EXT_MARK | FIRC_XT_EXT_ADDRTYPE},
};

static enum greatest_test_res rules_encode_as_golden(const char *fixture, firc_ipt_proto_t fam, const rule_case_t *rules,
                                                     size_t n) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERTm(fixture, firc_test_xt_read(fixture, fam, &info, &blob));
    firc_xt_table_t t;
    const char *why = NULL;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(fam, &info, blob, &t, &why), "%d");
    for (size_t i = 0; i < n; i++) {
        const char *line = fam == FIRC_IPT_PROTO_IPV4 ? rules[i].v4 : rules[i].v6;
        firc_xt_chain_t *c = firc_xt_find_chain(&t, rules[i].chain);
        ASSERTm(line, c != NULL && c->n_rules > rules[i].idx);
        firc_ipt_rule_t *r = firc_test_rule(line);
        firc_xt_entry_t e;
        memset(&e, 0, sizeof(e));
        uint32_t exts = 0;
        ASSERT_EQ_FMTm(line, FIRC_OK, firc_xt_encode(fam, 0, r, &e, &exts), "%d");
        ASSERTm(line, firc_xt_entry_same(fam, &e, &c->rules[rules[i].idx]));
        ASSERT_EQ_FMTm(line, rules[i].exts, exts, "%u");
        firc_xt_entry_clear(&e);
        firc_ipt_rule_free(r);
    }
    firc_xt_table_clear(&t);
    free(blob);
    PASS();
}

/* Catches: an encoded rule differing from iptables-restore's bytes for the same words (a field, revision, match order or byte order). */
TEST every_builder_rule_encodes_as_iptables_restore_wrote_it(void) {
    for (size_t f = 0; f < 2; f++) {
        CHECK_CALL(rules_encode_as_golden("firmware-firc", k_fams[f], k_rules, sizeof(k_rules) / sizeof(k_rules[0])));
    }
    CHECK_CALL(rules_encode_as_golden("redir-mark", FIRC_IPT_PROTO_IPV4, k_redir_rules,
                                      sizeof(k_redir_rules) / sizeof(k_redir_rules[0])));
    PASS();
}

static enum greatest_test_res refused(firc_ipt_proto_t fam, const char *line) {
    firc_ipt_rule_t *r = firc_test_rule(line);
    firc_xt_entry_t e;
    memset(&e, 0, sizeof(e));
    uint32_t exts = 0;
    ASSERT_EQ_FMTm(line, FIRC_ERR_INVAL, firc_xt_encode(fam, 0, r, &e, &exts), "%d");
    ASSERTm(line, e.bytes == NULL);
    firc_ipt_rule_free(r);
    PASS();
}

/* Catches: a REDIRECT written without the protocol 1.4.21 demands, with a port or range the kernel would misread, twice, or in v6. */
TEST redirect_needs_a_protocol_and_a_valid_range(void) {
    static const char *const v4[] = {
        "-j REDIRECT --to-ports 3603",
        "-m mark --mark 0x1/0x1 -j REDIRECT --to-ports 3603",
        "-p tcp -j REDIRECT --to-ports 0",
        "-p tcp -j REDIRECT --to-ports 0-5",
        "-p tcp -j REDIRECT --to-ports 5-4",
        "-p tcp -j REDIRECT --to-ports 70000",
        "-p tcp -j REDIRECT --to-ports 3600-70000",
        "-p tcp -j REDIRECT --to-ports 3600-",
        "-p tcp -j REDIRECT --to-ports -3600",
        "-p tcp -j REDIRECT --to-ports 3600:3601",
        "-p tcp -j REDIRECT --to-ports 3603 --to-ports 3604",
        "-p tcp -j REDIRECT",
        "-p tcp -j REDIRECT --to-ports",
        "-p tcp -j REDIRECT --random",
    };
    for (size_t i = 0; i < sizeof(v4) / sizeof(v4[0]); i++) { CHECK_CALL(refused(FIRC_IPT_PROTO_IPV4, v4[i])); }
    CHECK_CALL(refused(FIRC_IPT_PROTO_IPV6, "-p tcp -j REDIRECT --to-ports 3603"));
    static const struct { const char *line; uint16_t lo, hi; } ok[] = {
        {"-p udp -j REDIRECT --to-ports 1", 1, 1},
        {"-p tcp -j REDIRECT --to-ports 65535", 65535, 65535},
        {"-p tcp -j REDIRECT --to-ports 7-7", 7, 7},
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        firc_xt_entry_t e;
        uint32_t exts = 0;
        ASSERT_EQ_FMTm(ok[i].line, FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, ok[i].line, &e, &exts), "%d");
        ASSERT_EQ_FMTm(ok[i].line, 112u + 56u, e.len, "%u");
        const uint8_t *t = e.bytes + 112;
        uint8_t want[24] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            (uint8_t)(ok[i].lo >> 8), (uint8_t)ok[i].lo, (uint8_t)(ok[i].hi >> 8), (uint8_t)ok[i].hi, 0, 0, 0, 0};
        uint32_t one = 1, proto = 2;
        memcpy(want, &one, 4);
        memcpy(want + 4, &proto, 4);
        ASSERT_STR_EQm(ok[i].line, "REDIRECT", (const char *)t + 2);
        ASSERT_MEM_EQm(ok[i].line, want, t + 32, 24);
        firc_xt_entry_clear(&e);
    }
    PASS();
}

/* Catches: an addrtype word accepted that firc never writes and the golden never checked, or one written in v6. */
TEST addrtype_takes_only_the_local_destination(void) {
    static const char *const v4[] = {
        "-m addrtype ! --dst-type UNICAST -j RETURN",
        "-m addrtype --dst-type LOCAL,UNICAST -j RETURN",
        "-m addrtype --src-type LOCAL -j RETURN",
        "-m addrtype ! --src-type LOCAL -j RETURN",
        "-m addrtype -j RETURN",
        "-m addrtype --dst-type -j RETURN",
        "-m addrtype --dst-type LOCAL --dst-type LOCAL -j RETURN",
        "-m addrtype ! ! --dst-type LOCAL -j RETURN",
        "-m addrtype --dst-type LOCAL --limit-iface-in -j RETURN",
        "-m addrtype --dst-type local -j RETURN",
        "-m mark ! --dst-type LOCAL -j RETURN",
    };
    for (size_t i = 0; i < sizeof(v4) / sizeof(v4[0]); i++) { CHECK_CALL(refused(FIRC_IPT_PROTO_IPV4, v4[i])); }
    CHECK_CALL(refused(FIRC_IPT_PROTO_IPV6, "-m addrtype ! --dst-type LOCAL -j RETURN"));
    CHECK_CALL(refused(FIRC_IPT_PROTO_IPV6, "-m addrtype --dst-type LOCAL -j RETURN"));
    static const struct { const char *line; uint32_t flags; } ok[] = {
        {"-m addrtype --dst-type LOCAL -j RETURN", 0},
        {"-m addrtype ! --dst-type LOCAL -j RETURN", 2},
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        firc_xt_entry_t e;
        uint32_t exts = 0;
        ASSERT_EQ_FMTm(ok[i].line, FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, ok[i].line, &e, &exts), "%d");
        const uint8_t *m = match_named(FIRC_IPT_PROTO_IPV4, &e, "addrtype");
        ASSERTm(ok[i].line, m != NULL);
        ASSERT_EQ_FMTm(ok[i].line, 40u, (unsigned)firc_xt_rd16(m - XT_MATCH_HDR_LEN), "%u");
        ASSERT_EQ_FMTm(ok[i].line, 1u, (unsigned)m[-1], "%u");
        uint16_t src, dst;
        uint32_t flags;
        memcpy(&src, m, 2);
        memcpy(&dst, m + 2, 2);
        memcpy(&flags, m + 4, 4);
        ASSERT_EQ_FMTm(ok[i].line, 0u, (unsigned)src, "%u");
        ASSERT_EQ_FMTm(ok[i].line, 4u, (unsigned)dst, "%u");
        ASSERT_EQ_FMTm(ok[i].line, ok[i].flags, flags, "%u");
        ASSERT_EQ_FMTm(ok[i].line, (uint32_t)FIRC_XT_EXT_ADDRTYPE, exts, "%u");
        firc_xt_entry_clear(&e);
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
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(k_fams[f], 0, r, &e, &exts), "%d");
        ASSERT_MEM_EQ("abcdefghijklmno\0", e.bytes + at_name[f], 16);
        static const uint8_t full[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        ASSERT_MEM_EQ(full, e.bytes + at_mask[f], 16);
        firc_xt_entry_clear(&e);
        firc_ipt_rule_free(r);
    }
    PASS();
}

/* Catches: an inverted interface written with the other side's bit, both bits, or none. */
TEST an_inverted_interface_sets_its_own_bit(void) {
    static const unsigned at_inv[] = {83, 132};
    static const struct { const char *line; uint8_t inv; } k[] = {
        {"! -i nwg1 -j DROP", 0x01},
        {"! -o nwg1 -j DROP", 0x02},
        {"! -i nwg1 ! -o nwg1 -j DROP", 0x03},
        {"-i nwg1 -o nwg1 -j DROP", 0x00},
        {"-i br0 ! -o nwg1 -j DROP", 0x02},
    };
    for (size_t f = 0; f < 2; f++) {
        for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
            firc_xt_entry_t e;
            uint32_t exts = 0;
            ASSERT_EQ_FMTm(k[i].line, FIRC_OK, enc(k_fams[f], k[i].line, &e, &exts), "%d");
            ASSERT_EQ_FMTm(k[i].line, (unsigned)k[i].inv, (unsigned)e.bytes[at_inv[f]], "%u");
            firc_xt_entry_clear(&e);
        }
    }
    PASS();
}

/* Catches: a mark without a mask matched under a partial mask (the kernel's default is every bit). */
TEST a_mark_without_a_mask_matches_every_bit(void) {
    firc_ipt_rule_t *r = firc_test_rule("-m mark --mark 0x10000 -j RETURN");
    firc_xt_entry_t e;
    memset(&e, 0, sizeof(e));
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(FIRC_IPT_PROTO_IPV4, 0, r, &e, &exts), "%d");
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
        "-m conntrack --ctstate UNTRACKED -j RETURN",
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
        "! -s 10.0.0.1 -j RETURN",
        "! -p tcp -j RETURN",
        "! ! -o nwg1 -j DROP",
        "-o nwg1 ! -j DROP",
        "! -o -j DROP",
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
        ASSERT_EQ_FMTm(v4[i], FIRC_ERR_INVAL, firc_xt_encode(FIRC_IPT_PROTO_IPV4, 0, r, &e, &exts), "%d");
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
        ASSERT_EQ_FMTm(v6[i], FIRC_ERR_INVAL, firc_xt_encode(FIRC_IPT_PROTO_IPV6, 0, r, &e, &exts), "%d");
        ASSERTm(v6[i], e.bytes == NULL);
        firc_ipt_rule_free(r);
    }
    PASS();
}

/* Catches: the probe asking the kernel for a revision other than the one the encoder writes, or a capture extension not marked as the capture's. */
TEST the_probe_list_names_what_the_encoder_writes(void) {
    static const struct { uint32_t bit; const char *v4; const char *v6; } uses[] = {
        {FIRC_XT_EXT_DNAT, "-d 1.2.3.4/32 -j DNAT --to-destination 5.6.7.8", "-d ::1/128 -j DNAT --to-destination ::2"},
        {FIRC_XT_EXT_MASQUERADE, "-j MASQUERADE", "-j MASQUERADE"},
        {FIRC_XT_EXT_MARK, "-m mark --mark 1 -j RETURN", "-m mark --mark 1 -j RETURN"},
        {FIRC_XT_EXT_TCP, "-p tcp --dport 1 -j RETURN", "-p tcp --dport 1 -j RETURN"},
        {FIRC_XT_EXT_UDP, "-p udp --dport 1 -j RETURN", "-p udp --dport 1 -j RETURN"},
        {FIRC_XT_EXT_REJECT, "-j REJECT --reject-with icmp-host-unreachable", "-j REJECT --reject-with icmp6-addr-unreachable"},
        {FIRC_XT_EXT_MARK_TARGET, "-j MARK --set-xmark 0x1/0x1", "-j MARK --set-xmark 0x1/0x1"},
        {FIRC_XT_EXT_CONNMARK, "-j CONNMARK --save-mark", "-j CONNMARK --save-mark"},
        {FIRC_XT_EXT_CONNTRACK, "-m conntrack --ctdir ORIGINAL -j RETURN", "-m conntrack --ctdir ORIGINAL -j RETURN"},
        {FIRC_XT_EXT_MULTIPORT, "-p tcp -m multiport --dports 1,2 -j RETURN", "-p tcp -m multiport --dports 1,2 -j RETURN"},
        {FIRC_XT_EXT_MAC, "-m mac --mac-source 02:00:00:00:00:01 -j RETURN", "-m mac --mac-source 02:00:00:00:00:01 -j RETURN"},
        {FIRC_XT_EXT_LIMIT, "-m limit -j RETURN", "-m limit -j RETURN"},
        {FIRC_XT_EXT_LENGTH, "-m length --length 1 -j RETURN", "-m length --length 1 -j RETURN"},
        {FIRC_XT_EXT_CONNBYTES, "-m connbytes --connbytes 1:2 --connbytes-dir both --connbytes-mode packets -j RETURN",
         "-m connbytes --connbytes 1:2 --connbytes-dir both --connbytes-mode packets -j RETURN"},
        {FIRC_XT_EXT_STRING, "-m string --algo bm --string x -j RETURN", "-m string --algo bm --string x -j RETURN"},
        {FIRC_XT_EXT_NFLOG, "-j NFLOG", "-j NFLOG"},
        {FIRC_XT_EXT_CONNMARK_MATCH, "-m connmark --mark 1 -j RETURN", "-m connmark --mark 1 -j RETURN"},
        {FIRC_XT_EXT_REDIRECT, "-p tcp -j REDIRECT --to-ports 1", NULL},
        {FIRC_XT_EXT_ADDRTYPE, "-m addrtype --dst-type LOCAL -j RETURN", NULL},
    };
    const uint32_t capture = FIRC_XT_EXT_LIMIT | FIRC_XT_EXT_LENGTH | FIRC_XT_EXT_CONNBYTES | FIRC_XT_EXT_STRING |
                             FIRC_XT_EXT_NFLOG;
    size_t n_uses = sizeof(uses) / sizeof(uses[0]);
    ASSERT_EQ_FMT(n_uses, firc_xt_n_exts, "%zu");
    for (size_t d = 0; d < firc_xt_n_exts; d++) {
        const firc_xt_ext_desc_t *x = &firc_xt_exts[d];
        ASSERT_EQ(x->capture, (x->bit & capture) != 0);
        size_t u = 0;
        while (u < n_uses && uses[u].bit != x->bit) { u++; }
        ASSERT(u < n_uses);
        for (size_t f = 0; f < 2; f++) {
            if (f == 1 && uses[u].v6 == NULL) { continue; }
            firc_ipt_rule_t *r = firc_test_rule(f == 0 ? uses[u].v4 : uses[u].v6);
            firc_xt_entry_t e;
            memset(&e, 0, sizeof(e));
            uint32_t exts = 0;
            ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(k_fams[f], 0, r, &e, &exts), "%d");
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
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(k_fams[f], 0, r, &e, &exts), "%d");
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
        ASSERT_EQ_FMTm(cases[i].line, FIRC_OK, firc_xt_encode(FIRC_IPT_PROTO_IPV4, 0, r, &e, &exts), "%d");
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

/* Catches: entry_same ignoring more than the verdict word of a jump, or comparing the verdict word and missing a staged jump's read twin. */
TEST entry_same_ignores_only_the_verdict_of_a_jump(void) {
    for (size_t f = 0; f < 2; f++) {
        firc_xt_info_t info;
        uint8_t *blob = NULL;
        ASSERT(firc_test_xt_read("firmware-firc", k_fams[f], &info, &blob));
        firc_xt_table_t t;
        const char *why = NULL;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(k_fams[f], &info, blob, &t, &why), "%d");
        firc_xt_chain_t *c = firc_xt_find_chain(&t, "PREROUTING");
        ASSERT(c != NULL && c->n_rules > 0);
        const firc_xt_entry_t *j = NULL;
        for (size_t r = 0; r < c->n_rules && j == NULL; r++) {
            if (c->rules[r].jump[0] != '\0') { j = &c->rules[r]; }
        }
        ASSERT(j != NULL);
        uint8_t *copy = malloc(j->len);
        ASSERT(copy != NULL);
        memcpy(copy, j->bytes, j->len);
        firc_xt_entry_t b = *j;
        b.bytes = copy;
        b.owned = false;
        ASSERT(firc_xt_entry_same(k_fams[f], j, &b));
        uint16_t toff;
        memcpy(&toff, copy + firc_xt_at_toff(k_fams[f]), 2);
        uint32_t v = toff + 32u;
        copy[v] ^= 0x5a;
        ASSERT(firc_xt_entry_same(k_fams[f], j, &b));
        copy[v] ^= 0x5a;
        copy[v + 4u] ^= 0x5a;
        ASSERT_FALSE(firc_xt_entry_same(k_fams[f], j, &b));
        copy[v + 4u] ^= 0x5a;
        copy[v - 30u] ^= 0x01;
        ASSERT_FALSE(firc_xt_entry_same(k_fams[f], j, &b));
        copy[v - 30u] ^= 0x01;
        copy[firc_xt_ehdr(k_fams[f]) - 1u] ^= 0x01;
        ASSERT_FALSE(firc_xt_entry_same(k_fams[f], j, &b));
        free(copy);
        firc_xt_table_clear(&t);
        free(blob);
    }
    PASS();
}

/* Catches: a multiport list cut short or overrun: 15 slots fit, a sixteenth or a range starting in the last slot is refused. */
TEST a_source_port_fills_the_source_range(void) {
    firc_xt_entry_t e;
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-p tcp --sport 443 --tcp-flags RST RST -j RETURN", &e, &exts),
                  "%d");
    xt_tcp_t t;
    memcpy(&t, match_named(FIRC_IPT_PROTO_IPV4, &e, "tcp"), sizeof(t));
    ASSERT_EQ_FMT(443, (int)t.spts[0], "%d");
    ASSERT_EQ_FMT(443, (int)t.spts[1], "%d");
    ASSERT_EQ_FMT(0, (int)t.dpts[0], "%d");
    ASSERT_EQ_FMT(0xffff, (int)t.dpts[1], "%d");
    ASSERT_EQ_FMT(0x04, (int)t.flg_mask, "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV6, "-p udp --sport 1000:2000 -j RETURN", &e, &exts), "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, enc(FIRC_IPT_PROTO_IPV4, "-p tcp --sport 1 --sport 2 -j RETURN", &e, &exts), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, enc(FIRC_IPT_PROTO_IPV4, "-p tcp ! --sport 1 -j RETURN", &e, &exts), "%d");
    PASS();
}

TEST multiport_holds_fifteen_slots_and_refuses_a_sixteenth(void) {
    firc_xt_entry_t e;
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-p udp -m multiport --dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 -j RETURN", &e, &exts), "%d");
    xt_multiport_v1_t mp;
    memcpy(&mp, match_named(FIRC_IPT_PROTO_IPV4, &e, "multiport"), sizeof(mp));
    ASSERT_EQ_FMT(15, (int)mp.count, "%d");
    ASSERT_EQ_FMT(15, (int)mp.ports[14], "%d");
    ASSERT_EQ_FMT(1, (int)mp.flags, "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-p udp -m multiport --dports 1,2,3,4,5,6,7,8,9,10,11,12,13,20:30 -j RETURN", &e, &exts), "%d");
    memcpy(&mp, match_named(FIRC_IPT_PROTO_IPV4, &e, "multiport"), sizeof(mp));
    ASSERT_EQ_FMT(15, (int)mp.count, "%d");
    ASSERT_EQ_FMT(20, (int)mp.ports[13], "%d");
    ASSERT_EQ_FMT(30, (int)mp.ports[14], "%d");
    ASSERT_EQ_FMT(1, (int)mp.pflags[13], "%d");
    ASSERT_EQ_FMT(0, (int)mp.pflags[14], "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, enc(FIRC_IPT_PROTO_IPV4, "-p udp -m multiport --dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 -j RETURN", &e, &exts), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, enc(FIRC_IPT_PROTO_IPV4, "-p udp -m multiport --dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,20:30 -j RETURN", &e, &exts), "%d");
    PASS();
}

/* Catches: a word outside what firc writes encoded as something (a wrong rule in the kernel) instead of refused. */
TEST the_mangle_and_filter_refusals(void) {
    static const struct { int fam; const char *line; } cases[] = {
        {4, "-p tcp -j REJECT --reject-with icmp-port-unreachable"},
        {4, "-j REJECT"},
        {4, "-j REJECT --reject-with tcp-reset"},
        {4, "-j REJECT --reject-with icmp6-addr-unreachable"},
        {6, "-j REJECT --reject-with icmp-host-unreachable"},
        {4, "-j MARK --set-mark 7"},
        {4, "-j MARK"},
        {4, "-j MARK --set-xmark 0x1/0x2 --set-xmark 0x3"},
        {4, "-j CONNMARK --restore-mark"},
        {4, "-j CONNMARK --nfmask 0x1 --ctmask 0x1"},
        {4, "-j CONNMARK --save-mark --nfmask 0x1 --nfmask 0x2"},
        {4, "-m conntrack --ctdir BOTH -j RETURN"},
        {4, "-m conntrack ! --ctdir REPLY -j RETURN"},
        {4, "-m conntrack -j RETURN"},
        {4, "-m conntrack --ctstate NEW,FOO -j RETURN"},
        {4, "-m multiport --dports 53 -j RETURN"},
        {4, "-p tcp -m multiport --dports 5:5 -j RETURN"},
        {4, "-p tcp -m multiport --dports 53,,80 -j RETURN"},
        {4, "-m mac --mac-source 02:00:00:00:00 -j RETURN"},
        {4, "-m mac --mac-source 02:00:00:00:00:0G -j RETURN"},
        {4, "-m mark --mark 0x1 -m mark --mark 0x2 -j RETURN"},
        {4, "-m mark -j RETURN"},
        {4, "-p tcp --tcp-flags SYN,FOO ACK -j RETURN"},
        {4, "-p tcp --tcp-flags SYN -j RETURN"},
        {4, "-m tcp --dport 1 -j RETURN"},
        {4, "! -s 1.2.3.4/32 -j RETURN"},
        {4, "! -s 1.2.3.4/32 -m mark --mark 0x1 -j RETURN"},
        {4, "! -m mark --mark 0x1 -j RETURN"},
        {4, "-p tcp ! --dport 1 -j RETURN"},
        {4, "-m mark ! ! --mark 0x1 -j RETURN"},
        {4, "-m mark --mark 0x1 ! -j RETURN"},
        {4, "-j RETURN --to-destination 1.2.3.4"},
        {4, "-m conntrack ! --ctorigdst 198.18.0.1/15 -j RETURN"},
        {6, "-m conntrack ! --ctorigdst fd37:9a00::1/48 -j RETURN"},
        {4, "-m connmark -j DROP"},
        {4, "-m connmark --mark -j DROP"},
        {4, "-m connmark --mark zz -j DROP"},
        {4, "-m connmark --mark 0x1/0x1/0x1 -j DROP"},
        {4, "-m connmark --mark 0x1 --mark 0x2 -j DROP"},
        {4, "-m connmark --mark 0x1 -m connmark --mark 0x2 -j DROP"},
        {4, "-m connmark ! ! --mark 0x1 -j DROP"},
        {4, "-m connmark --mark 0x1 ! -j DROP"},
        {6, "-m connmark --ctmask 0x1 -j DROP"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        firc_xt_entry_t e;
        memset(&e, 0, sizeof(e));
        uint32_t exts = 0;
        firc_ipt_proto_t fam = cases[i].fam == 6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4;
        ASSERT_EQ_FMTm(cases[i].line, FIRC_ERR_INVAL, enc(fam, cases[i].line, &e, &exts), "%d");
        ASSERTm(cases[i].line, e.bytes == NULL);
    }
    PASS();
}

/* Catches: matches written in another order than the rule names them (iptables-restore keeps the order, the kernel evaluates in it). */
TEST matches_keep_the_order_the_rule_names_them(void) {
    firc_xt_entry_t e;
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-p tcp -m mark --mark 0x1/0x1 --dport 443 -m conntrack --ctdir ORIGINAL -j RETURN", &e, &exts), "%d");
    uint32_t eh = firc_xt_ehdr(FIRC_IPT_PROTO_IPV4), toff = firc_xt_rd16(e.bytes + firc_xt_at_toff(FIRC_IPT_PROTO_IPV4));
    const char *want[] = {"mark", "tcp", "conntrack"};
    size_t k = 0;
    for (uint32_t m = eh; m < toff; m += firc_xt_rd16(e.bytes + m), k++) {
        ASSERT(k < 3);
        ASSERT_STR_EQ(want[k], (const char *)e.bytes + m + 2);
    }
    ASSERT_EQ_FMT((size_t)3, k, "%zu");
    ASSERT_EQ_FMT((uint32_t)(FIRC_XT_EXT_MARK | FIRC_XT_EXT_TCP | FIRC_XT_EXT_CONNTRACK), exts, "%u");
    firc_xt_entry_clear(&e);
    PASS();
}

/* Catches: the mac match written at another revision than the kernel confirmed, or its payload changed with the revision. */
TEST the_mac_match_takes_the_revision_it_is_given(void) {
    for (size_t f = 0; f < 2; f++) {
        for (uint8_t rev = 0; rev < 2; rev++) {
            firc_ipt_rule_t *r = firc_test_rule("-m mac ! --mac-source 02:00:00:00:00:0a -j RETURN");
            firc_xt_entry_t e;
            uint32_t exts = 0;
            ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(k_fams[f], rev, r, &e, &exts), "%d");
            uint32_t eh = firc_xt_ehdr(k_fams[f]);
            ASSERT_STR_EQ("mac", (const char *)e.bytes + eh + 2);
            ASSERT_EQ_FMT(rev, e.bytes[eh + 31], "%u");
            ASSERT_EQ_FMT(XT_MATCH_HDR_LEN + 16u, firc_xt_rd16(e.bytes + eh), "%u");
            static const uint8_t mac[6] = {0x02, 0, 0, 0, 0, 0x0a};
            ASSERT_MEM_EQ(mac, e.bytes + eh + XT_MATCH_HDR_LEN, 6);
            ASSERT_EQ_FMT(1u, firc_xt_rd32(e.bytes + eh + XT_MATCH_HDR_LEN + 8), "%u");
            ASSERT_EQ_FMT((uint32_t)FIRC_XT_EXT_MAC, exts, "%u");
            firc_xt_entry_clear(&e);
            ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_encode(k_fams[f], 2, r, &e, &exts), "%d");
            ASSERT(e.bytes == NULL);
            firc_ipt_rule_free(r);
        }
    }
    PASS();
}

/* Catches: a state list, an inverted original destination, --tcp-flags or a -p after the matches encoded unlike iptables-restore wrote the capture's rules. */
TEST conntrack_mark_and_tcp_words_encode_as_in_the_capture(void) {
    static const char *const lines[2][2] = {
        {"-i br0 -m conntrack --ctstate NEW ! --ctorigdst 198.18.0.0/15 -m mark ! --mark 0x40000000/0x40000000 -j RETURN",
         "-i br0 -m conntrack ! --ctorigdst 198.18.0.0/15 -m mark ! --mark 0x40000000/0x40000000 -p tcp --dport 443 --tcp-flags SYN,ACK ACK -j RETURN"},
        {"-i br0 -m conntrack --ctstate NEW ! --ctorigdst fd37:9a00::/48 -m mark ! --mark 0x40000000/0x40000000 -j RETURN",
         "-i br0 -m conntrack ! --ctorigdst fd37:9a00::/48 -m mark ! --mark 0x40000000/0x40000000 -p tcp --dport 443 --tcp-flags SYN,ACK ACK -j RETURN"},
    };
    for (size_t f = 0; f < 2; f++) {
        firc_xt_info_t info;
        uint8_t *blob = NULL;
        ASSERT(firc_test_xt_read("m-tap", k_fams[f], &info, &blob));
        firc_xt_table_t t;
        const char *why = NULL;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(k_fams[f], &info, blob, &t, &why), "%d");
        firc_xt_chain_t *c = firc_xt_find_chain(&t, "FIRC_TAP");
        ASSERT(c != NULL && c->n_rules == 2);
        for (size_t i = 0; i < 2; i++) {
            firc_xt_entry_t e;
            uint32_t exts = 0;
            ASSERT_EQ_FMTm(lines[f][i], FIRC_OK, enc(k_fams[f], lines[f][i], &e, &exts), "%d");
            uint32_t eh = firc_xt_ehdr(k_fams[f]), toff = firc_xt_rd16(e.bytes + firc_xt_at_toff(k_fams[f]));
            ASSERTm(lines[f][i], c->rules[i].len > toff);
            ASSERT_MEM_EQm(lines[f][i], c->rules[i].bytes, e.bytes, firc_xt_at_toff(k_fams[f]) - 4u);
            ASSERT_MEM_EQm(lines[f][i], c->rules[i].bytes + eh, e.bytes + eh, toff - eh);
            firc_xt_entry_clear(&e);
        }
        firc_xt_table_clear(&t);
        free(blob);
    }
    PASS();
}

/* Catches: the FORWARD barrier encoded unlike iptables-restore 1.4.21 wrote it (connmark revision, payload, match order or the DROP verdict). */
TEST the_barrier_encodes_as_iptables_restore_wrote_it(void) {
    static const char *const line =
        "-m conntrack --ctdir ORIGINAL -m connmark --mark 0x40000000/0x40000000 -m mark ! --mark 0x40000000/0x40000000 -j DROP";
    static const char *const fieldless = "-m connmark --mark 0x40000000/0x40ff0000 -j RETURN";
    for (size_t f = 0; f < 2; f++) {
        firc_xt_info_t info;
        uint8_t *blob = NULL;
        ASSERT(firc_test_xt_read("f-firc", k_fams[f], &info, &blob));
        firc_xt_table_t t;
        const char *why = NULL;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(k_fams[f], &info, blob, &t, &why), "%d");
        firc_xt_chain_t *c = firc_xt_find_chain(&t, "FIRC_POOLREJECT");
        ASSERT(c != NULL && c->n_rules == 4);
        firc_xt_entry_t e;
        uint32_t exts = 0;
        ASSERT_EQ_FMT(FIRC_OK, enc(k_fams[f], line, &e, &exts), "%d");
        ASSERT(firc_xt_entry_same(k_fams[f], &e, &c->rules[3]));
        ASSERT_EQ_FMT((uint32_t)(FIRC_XT_EXT_CONNTRACK | FIRC_XT_EXT_CONNMARK_MATCH | FIRC_XT_EXT_MARK), exts, "%u");
        firc_xt_entry_clear(&e);
        exts = 0;
        ASSERT_EQ_FMT(FIRC_OK, enc(k_fams[f], fieldless, &e, &exts), "%d");
        ASSERT(firc_xt_entry_same(k_fams[f], &e, &c->rules[2]));
        ASSERT_EQ_FMT((uint32_t)FIRC_XT_EXT_CONNMARK_MATCH, exts, "%u");
        firc_xt_entry_clear(&e);
        firc_xt_table_clear(&t);
        free(blob);
    }
    PASS();
}

/* Catches: a connmark match whose inversion, default mask or revision differs from iptables-restore's. */
TEST the_connmark_match_values(void) {
    static const struct { const char *line; uint32_t mark, mask; uint8_t invert; } k[] = {
        {"-m connmark ! --mark 0x1/0x3 -j DROP", 1u, 3u, 1},
        {"-m connmark --mark 0x5 -j DROP", 5u, 0xffffffffu, 0},
    };
    for (size_t f = 0; f < 2; f++) {
        for (size_t i = 0; i < 2; i++) {
            firc_xt_entry_t e;
            uint32_t exts = 0;
            ASSERT_EQ_FMTm(k[i].line, FIRC_OK, enc(k_fams[f], k[i].line, &e, &exts), "%d");
            uint32_t eh = firc_xt_ehdr(k_fams[f]);
            ASSERT_STR_EQ("connmark", (const char *)e.bytes + eh + 2);
            ASSERT_EQ_FMT(1u, e.bytes[eh + 31], "%u");
            ASSERT_EQ_FMT(XT_MATCH_HDR_LEN + 16u, firc_xt_rd16(e.bytes + eh), "%u");
            const uint8_t *m = match_named(k_fams[f], &e, "connmark");
            ASSERT(m != NULL);
            ASSERT_EQ_FMT(k[i].mark, firc_xt_rd32(m), "%x");
            ASSERT_EQ_FMT(k[i].mask, firc_xt_rd32(m + 4), "%x");
            ASSERT_EQ_FMT(k[i].invert, m[8], "%u");
            static const uint8_t pad[7] = {0};
            ASSERT_MEM_EQ(pad, m + 9, 7);
            ASSERT_EQ_FMT((uint32_t)FIRC_XT_EXT_CONNMARK_MATCH, exts, "%u");
            firc_xt_entry_clear(&e);
        }
    }
    PASS();
}

static const uint8_t *target_of(firc_ipt_proto_t fam, const firc_xt_entry_t *e) {
    return e->bytes + firc_xt_rd16(e->bytes + firc_xt_at_toff(fam)) + XT_MATCH_HDR_LEN;
}

/* Catches: a default or a flag the goldens never exercise written wrong: --save-mark's masks, a mark without a mask, the reject codes, state and flag names. */
TEST the_filter_and_mangle_values(void) {
    firc_xt_entry_t e;
    uint32_t exts = 0;
    xt_connmark_tginfo1_t cm;
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-j CONNMARK --save-mark", &e, &exts), "%d");
    memcpy(&cm, target_of(FIRC_IPT_PROTO_IPV4, &e), sizeof(cm));
    ASSERT_EQ_FMT(1u, (unsigned)cm.mode, "%u");
    ASSERT_EQ_FMT(0xffffffffu, cm.ctmask, "%x");
    ASSERT_EQ_FMT(0xffffffffu, cm.nfmask, "%x");
    ASSERT_EQ_FMT(0u, cm.ctmark, "%x");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV6, "-j CONNMARK --save-mark --ctmask 0x40ff0000", &e, &exts), "%d");
    memcpy(&cm, target_of(FIRC_IPT_PROTO_IPV6, &e), sizeof(cm));
    ASSERT_EQ_FMT(0x40ff0000u, cm.ctmask, "%x");
    ASSERT_EQ_FMT(0xffffffffu, cm.nfmask, "%x");
    firc_xt_entry_clear(&e);
    xt_mark_tginfo2_t mk;
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-j MARK --set-xmark 0x5", &e, &exts), "%d");
    memcpy(&mk, target_of(FIRC_IPT_PROTO_IPV4, &e), sizeof(mk));
    ASSERT_EQ_FMT(5u, mk.mark, "%x");
    ASSERT_EQ_FMT(0xffffffffu, mk.mask, "%x");
    firc_xt_entry_clear(&e);
    static const struct { int fam; const char *line; uint32_t with; } rejects[] = {
        {4, "-p tcp -j REJECT --reject-with tcp-reset", 7},
        {6, "-p tcp -j REJECT --reject-with tcp-reset", 6},
        {4, "-p udp -j REJECT --reject-with icmp-host-unreachable", 1},
        {6, "-j REJECT --reject-with icmp6-addr-unreachable", 3},
    };
    for (size_t i = 0; i < sizeof(rejects) / sizeof(rejects[0]); i++) {
        firc_ipt_proto_t fam = rejects[i].fam == 6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4;
        ASSERT_EQ_FMTm(rejects[i].line, FIRC_OK, enc(fam, rejects[i].line, &e, &exts), "%d");
        ASSERT_EQ_FMTm(rejects[i].line, rejects[i].with, firc_xt_rd32(target_of(fam, &e)), "%u");
        firc_xt_entry_clear(&e);
    }
    xt_conntrack_mtinfo3_t ct;
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m conntrack --ctstate NEW,RELATED,ESTABLISHED,INVALID --ctdir ORIGINAL -j RETURN", &e, &exts), "%d");
    memcpy(&ct, match_named(FIRC_IPT_PROTO_IPV4, &e, "conntrack"), sizeof(ct));
    ASSERT_EQ_FMT(0x1001u, (unsigned)ct.match_flags, "%x");
    ASSERT_EQ_FMT(0u, (unsigned)ct.invert_flags, "%x");
    ASSERT_EQ_FMT(0x0fu, (unsigned)ct.state_mask, "%x");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m conntrack --ctdir REPLY -j RETURN", &e, &exts), "%d");
    memcpy(&ct, match_named(FIRC_IPT_PROTO_IPV4, &e, "conntrack"), sizeof(ct));
    ASSERT_EQ_FMT(0x1000u, (unsigned)ct.match_flags, "%x");
    ASSERT_EQ_FMT(0x1000u, (unsigned)ct.invert_flags, "%x");
    firc_xt_entry_clear(&e);
    xt_tcp_t tcp;
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-p tcp --tcp-flags ALL FIN,RST,URG -j RETURN", &e, &exts), "%d");
    memcpy(&tcp, match_named(FIRC_IPT_PROTO_IPV4, &e, "tcp"), sizeof(tcp));
    ASSERT_EQ_FMT(0x3fu, (unsigned)tcp.flg_mask, "%x");
    ASSERT_EQ_FMT(0x25u, (unsigned)tcp.flg_cmp, "%x");
    ASSERT_EQ_FMT(0xffffu, (unsigned)tcp.dpts[1], "%x");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-p tcp --tcp-flags PSH,ACK NONE -j RETURN", &e, &exts), "%d");
    memcpy(&tcp, match_named(FIRC_IPT_PROTO_IPV4, &e, "tcp"), sizeof(tcp));
    ASSERT_EQ_FMT(0x18u, (unsigned)tcp.flg_mask, "%x");
    ASSERT_EQ_FMT(0u, (unsigned)tcp.flg_cmp, "%x");
    firc_xt_entry_clear(&e);
    PASS();
}

/* Catches: a capture value encoded wrong where the goldens cannot see it (a rate unit, a default, an omitted bound). */
TEST the_capture_values(void) {
    firc_xt_entry_t e;
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m limit --limit 3/minute -j RETURN", &e, &exts), "%d");
    xt_rateinfo_t r;
    memcpy(&r, match_named(FIRC_IPT_PROTO_IPV4, &e, "limit"), sizeof(r));
    ASSERT_EQ_FMT(200000u, r.avg, "%u");
    ASSERT_EQ_FMT(5u, r.burst, "%u");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m limit -j RETURN", &e, &exts), "%d");
    memcpy(&r, match_named(FIRC_IPT_PROTO_IPV4, &e, "limit"), sizeof(r));
    ASSERT_EQ_FMT(12000000u, r.avg, "%u");
    firc_xt_entry_clear(&e);
    static const struct { const char *rate; uint32_t avg; } rates[] = {
        {"6/min", 100000u}, {"4/hour", 9000000u}, {"8/second", 1250u}, {"25", 400u}};
    for (size_t i = 0; i < sizeof(rates) / sizeof(rates[0]); i++) {
        char line[64];
        snprintf(line, sizeof(line), "-m limit --limit %s -j RETURN", rates[i].rate);
        ASSERT_EQ_FMTm(line, FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, line, &e, &exts), "%d");
        memcpy(&r, match_named(FIRC_IPT_PROTO_IPV4, &e, "limit"), sizeof(r));
        ASSERT_EQ_FMTm(line, rates[i].avg, r.avg, "%u");
        firc_xt_entry_clear(&e);
    }
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m limit --limit 2/day --limit-burst 7 -j RETURN", &e, &exts), "%d");
    memcpy(&r, match_named(FIRC_IPT_PROTO_IPV4, &e, "limit"), sizeof(r));
    ASSERT_EQ_FMT(432000000u, r.avg, "%u");
    ASSERT_EQ_FMT(7u, r.burst, "%u");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m length --length 100: -j RETURN", &e, &exts), "%d");
    xt_length_info_t l;
    memcpy(&l, match_named(FIRC_IPT_PROTO_IPV4, &e, "length"), sizeof(l));
    ASSERT_EQ_FMT(100, (int)l.min, "%d");
    ASSERT_EQ_FMT(65535, (int)l.max, "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m length --length 60 -j RETURN", &e, &exts), "%d");
    memcpy(&l, match_named(FIRC_IPT_PROTO_IPV4, &e, "length"), sizeof(l));
    ASSERT_EQ_FMT(60, (int)l.min, "%d");
    ASSERT_EQ_FMT(60, (int)l.max, "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m connbytes --connbytes 2: --connbytes-dir both --connbytes-mode bytes -j RETURN", &e, &exts), "%d");
    xt_connbytes_info_t c;
    memcpy(&c, match_named(FIRC_IPT_PROTO_IPV4, &e, "connbytes"), sizeof(c));
    ASSERT_EQ_FMT((unsigned long long)2, (unsigned long long)c.from, "%llu");
    ASSERT_EQ_FMT(0xffffffffffffffffull, (unsigned long long)c.to, "%llx");
    ASSERT_EQ_FMT(2, (int)c.direction, "%d");
    ASSERT_EQ_FMT(1, (int)c.what, "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m connbytes --connbytes-mode avgpkt --connbytes-dir reply --connbytes 9 -j RETURN", &e, &exts), "%d");
    memcpy(&c, match_named(FIRC_IPT_PROTO_IPV4, &e, "connbytes"), sizeof(c));
    ASSERT_EQ_FMT((unsigned long long)9, (unsigned long long)c.from, "%llu");
    ASSERT_EQ_FMT(0xffffffffffffffffull, (unsigned long long)c.to, "%llx");
    ASSERT_EQ_FMT(1, (int)c.direction, "%d");
    ASSERT_EQ_FMT(2, (int)c.what, "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m string --algo kmp --hex-string ab|0d0a|c -j RETURN", &e, &exts), "%d");
    xt_string_info_t s;
    memcpy(&s, match_named(FIRC_IPT_PROTO_IPV4, &e, "string"), sizeof(s));
    ASSERT_EQ_FMT(5, (int)s.patlen, "%d");
    ASSERT_EQ(0, memcmp(s.pattern, "ab\r\nc", 5));
    ASSERT_STR_EQ("kmp", s.algo);
    ASSERT_EQ_FMT(0, (int)s.from_offset, "%d");
    ASSERT_EQ_FMT(65535, (int)s.to_offset, "%d");
    ASSERT_EQ_FMT(0, (int)s.flags, "%d");
    firc_xt_entry_clear(&e);
    const char *spaced[] = {"-m", "string", "--algo", "bm", "--hex-string", "a\\|b|16 03|", "-j", "RETURN"};
    firc_ipt_rule_t *sr = firc_ipt_rule_new(spaced, sizeof(spaced) / sizeof(spaced[0]));
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_encode(FIRC_IPT_PROTO_IPV4, 0, sr, &e, &exts), "%d");
    firc_ipt_rule_free(sr);
    memcpy(&s, match_named(FIRC_IPT_PROTO_IPV4, &e, "string"), sizeof(s));
    ASSERT_EQ_FMT(5, (int)s.patlen, "%d");
    ASSERT_EQ(0, memcmp(s.pattern, "a|b\x16\x03", 5));
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV4, "-m string --string GET --algo bm --to 9 -j RETURN", &e, &exts), "%d");
    memcpy(&s, match_named(FIRC_IPT_PROTO_IPV4, &e, "string"), sizeof(s));
    ASSERT_EQ_FMT(3, (int)s.patlen, "%d");
    ASSERT_EQ(0, memcmp(s.pattern, "GET", 3));
    ASSERT_STR_EQ("bm", s.algo);
    ASSERT_EQ_FMT(9, (int)s.to_offset, "%d");
    firc_xt_entry_clear(&e);
    ASSERT_EQ_FMT(FIRC_OK, enc(FIRC_IPT_PROTO_IPV6, "-j NFLOG", &e, &exts), "%d");
    xt_nflog_info_t n;
    memcpy(&n, target_of(FIRC_IPT_PROTO_IPV6, &e), sizeof(n));
    ASSERT_EQ_FMT(0, (int)n.group, "%d");
    ASSERT_EQ_FMT(0, (int)n.threshold, "%d");
    ASSERT_EQ_FMT(0u, n.len, "%u");
    firc_xt_entry_clear(&e);
    static const char *const bad[] = {
        "-m limit --limit 0/sec -j RETURN",
        "-m limit --limit 20000/sec -j RETURN",
        "-m limit --limit 5/fortnight -j RETURN",
        "-m limit --limit 1/sec --limit 2/sec -j RETURN",
        "-m limit --limit-burst 0 -j RETURN",
        "-m limit --limit-burst 10001 -j RETURN",
        "-m length -j RETURN",
        "-m length --length 9:8 -j RETURN",
        "-m length ! --length 9 -j RETURN",
        "-m connbytes --connbytes 2:8 --connbytes-dir original -j RETURN",
        "-m connbytes --connbytes 8:2 --connbytes-dir original --connbytes-mode packets -j RETURN",
        "-m connbytes --connbytes 2:8 --connbytes-dir sideways --connbytes-mode packets -j RETURN",
        "-m connbytes --connbytes 2:8 --connbytes 3:9 --connbytes-dir both --connbytes-mode packets -j RETURN",
        "-m string --hex-string |1603| -j RETURN",
        "-m string --algo bm -j RETURN",
        "-m string --algo rk --string x -j RETURN",
        "-m string --algo bm --hex-string |16x3| -j RETURN",
        "-m string --algo bm --hex-string |1603 -j RETURN",
        "-m string --algo bm --hex-string |1603| --from 90 --to 80 -j RETURN",
        "-m string --algo bm --string x --string y -j RETURN",
        "-j NFLOG --nflog-prefix x",
        "-j NFLOG --nflog-group 1 --nflog-group 2",
        "-j NFLOG --nflog-group 70000",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERT_EQ_FMTm(bad[i], FIRC_ERR_INVAL, enc(FIRC_IPT_PROTO_IPV4, bad[i], &e, &exts), "%d");
    }
    PASS();
}

typedef struct {
    size_t n;
    unsigned family[8];
    uint32_t exts[8];
    firc_err_t err[8];
    bool v6_ok;
} tap_seen_t;

static void tap_encode(void *ud, unsigned family, const char *const *args, size_t n_args) {
    tap_seen_t *s = ud;
    if (s->n >= 8) { return; }
    firc_ipt_rule_t *r = firc_ipt_rule_new(args, n_args);
    firc_xt_entry_t e;
    memset(&e, 0, sizeof(e));
    s->family[s->n] = family;
    s->exts[s->n] = 0;
    s->err[s->n] = firc_xt_encode(family == FIRC_FAM_V6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4, 0, r, &e,
                                  &s->exts[s->n]);
    firc_xt_entry_clear(&e);
    s->n++;
    firc_ipt_rule_free(r);
}

/* Catches: a capture rule the daemon builds using a word, match or option the encoder does not know, found only when a capture starts. */
TEST the_captures_own_rules_encode_in_both_families(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37;
    c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ_FMT(FIRC_OK, firc_fakeip_new(&c, &pool), "%d");
    tap_seen_t seen;
    memset(&seen, 0, sizeof(seen));
    const char *lan[] = {"br0"};
    ASSERT_EQ_FMT(FIRC_OK, firc_tap_rules_build(pool, lan, 1, tap_encode, &seen), "%d");
    ASSERT_EQ_FMT((size_t)4, seen.n, "%zu");
    const uint32_t fresh = FIRC_XT_EXT_CONNTRACK | FIRC_XT_EXT_MARK | FIRC_XT_EXT_LIMIT | FIRC_XT_EXT_NFLOG;
    const uint32_t hello = FIRC_XT_EXT_CONNTRACK | FIRC_XT_EXT_MARK | FIRC_XT_EXT_TCP | FIRC_XT_EXT_LENGTH |
                           FIRC_XT_EXT_CONNBYTES | FIRC_XT_EXT_STRING | FIRC_XT_EXT_LIMIT | FIRC_XT_EXT_NFLOG;
    const uint32_t want[4] = {fresh, hello, fresh, hello};
    for (size_t i = 0; i < 4; i++) {
        ASSERT_EQ_FMTm("encoded", FIRC_OK, seen.err[i], "%d");
        ASSERT_EQ_FMTm("extensions", want[i], seen.exts[i], "%u");
        ASSERT_EQ_FMTm("family", i < 2 ? FIRC_FAM_V4 : FIRC_FAM_V6, seen.family[i], "%u");
    }
    firc_fakeip_free(pool);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(every_builder_rule_encodes_as_iptables_restore_wrote_it);
    RUN_TEST(redirect_needs_a_protocol_and_a_valid_range);
    RUN_TEST(addrtype_takes_only_the_local_destination);
    RUN_TEST(an_interface_at_the_length_limit_gets_a_full_mask);
    RUN_TEST(an_inverted_interface_sets_its_own_bit);
    RUN_TEST(a_mark_without_a_mask_matches_every_bit);
    RUN_TEST(a_rule_outside_the_vocabulary_is_refused);
    RUN_TEST(the_probe_list_names_what_the_encoder_writes);
    RUN_TEST(entry_same_ignores_only_the_verdict_of_a_jump);
    RUN_TEST(a_prefix_clears_the_host_bits);
    RUN_TEST(matches_follow_the_order_of_the_words);
    RUN_TEST(a_source_port_fills_the_source_range);
    RUN_TEST(multiport_holds_fifteen_slots_and_refuses_a_sixteenth);
    RUN_TEST(the_mangle_and_filter_refusals);
    RUN_TEST(matches_keep_the_order_the_rule_names_them);
    RUN_TEST(the_mac_match_takes_the_revision_it_is_given);
    RUN_TEST(conntrack_mark_and_tcp_words_encode_as_in_the_capture);
    RUN_TEST(the_filter_and_mangle_values);
    RUN_TEST(the_barrier_encodes_as_iptables_restore_wrote_it);
    RUN_TEST(the_connmark_match_values);
    RUN_TEST(the_capture_values);
    RUN_TEST(the_captures_own_rules_encode_in_both_families);
    GREATEST_MAIN_END();
}
