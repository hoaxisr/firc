#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "xt_golden.h"
#include "../../src/xtables/xt_internal.h"

static const firc_ipt_proto_t k_fams[] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

static uint16_t get16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t get32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static uint32_t error_named_v4(const uint8_t *b, uint32_t size, const char *name) {
    for (uint32_t off = 0; off < size; off += get16(b + off + 90)) {
        const uint8_t *t = b + off + get16(b + off + 88);
        if (strcmp((const char *)t + 2, "ERROR") == 0 && strcmp((const char *)t + 32, name) == 0) { return off; }
    }
    return UINT32_MAX;
}

static firc_err_t run(firc_ipt_proto_t fam, const firc_xt_info_t *info, uint8_t *blob, const firc_xt_stage_t *stage,
                      firc_xt_info_t *ni, uint8_t **nb, int32_t **oi, char *why, size_t why_len) {
    firc_xt_table_t t;
    const char *bad = NULL;
    uint32_t exts = 0;
    firc_err_t err = firc_xt_parse(fam, info, blob, &t, &bad);
    if (err == FIRC_OK) { err = firc_xt_merge(&t, stage, &exts, why, why_len); }
    if (err == FIRC_OK) { err = firc_xt_serialise(&t, nb, ni, oi, why, why_len); }
    firc_xt_table_clear(&t);
    return err;
}

/* Catches: a merge writing a table iptables-restore would not have written from the same transcript. */
TEST each_fixture_merges_as_iptables_restore_did(void) {
    static const struct { const char *base, *stage, *want; } cases[] = {
        {"firmware", "firmware-firc", "firmware-firc"},
        {"firmware-firc", "firmware-firc", "firmware-firc"},
        {"firmware-firc", "full", "firmware-firc"},
        {"firmware-firc", "firmware-firc-remove", "firmware-firc-remove"},
        {"firmware-firc", "sweep", "sweep"},
        {"dedupe-seed", "dedupe", "dedupe"},
        {"kept-seed", "kept", "kept-seed"},
        {"empty", "dnat2000", "dnat2000"},
    };
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        for (size_t f = 0; f < 2; f++) {
            firc_xt_info_t bi, wi, ni;
            uint8_t *base = NULL, *want = NULL, *nb = NULL;
            int32_t *oi = NULL;
            char why[256];
            ASSERTm(cases[c].base, firc_test_xt_read(cases[c].base, k_fams[f], &bi, &base));
            ASSERTm(cases[c].want, firc_test_xt_read(cases[c].want, k_fams[f], &wi, &want));
            firc_test_stage_t *s = firc_test_stage_new();
            firc_test_stage_fixture(s, cases[c].stage, k_fams[f]);
            ASSERT_EQ_FMTm(cases[c].stage, FIRC_OK, run(k_fams[f], &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
            ASSERTm(cases[c].stage, firc_test_xt_same(k_fams[f], &wi, want, &ni, nb));
            firc_test_stage_free(s);
            free(base);
            free(want);
            free(nb);
            free(oi);
        }
    }
    PASS();
}

/* Catches: counters of an entry that stayed byte-equal not carried, or a changed rule given the old rule's counters. */
TEST carried_entries_keep_their_old_index(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    firc_ipt_rule_free(s->chains[1].rules[0]);
    s->rules[2] = firc_test_rule("-d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.35");
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT_EQ_FMT(bi.num_entries, ni.num_entries, "%u");
    for (uint32_t k = 0; k < ni.num_entries; k++) {
        ASSERT_EQ_FMT(k == 15 ? -1 : (int32_t)k, oi[k], "%d");
    }
    firc_test_stage_free(s);
    free(base);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: a jump into the middle of a firmware chain written to a stale offset after the table moved. */
TEST a_jump_into_the_middle_of_a_chain_is_carried(void) {
    firc_xt_info_t bi, wi, ni;
    uint8_t *base = NULL, *want = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &wi, &want));
    uint32_t head = error_named_v4(base, bi.size, "ACME_PRE");
    uint32_t tail = head + 176 + get16(base + head + 176 + 90);
    put32(base + 152 + 112 + 32, tail);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    uint32_t whead = error_named_v4(want, wi.size, "ACME_PRE");
    uint32_t wtail = whead + 176 + get16(want + whead + 176 + 90);
    ASSERT_EQ_FMT(wtail, get32(nb + 2 * 152 + 112 + 32), "%u");
    firc_test_stage_free(s);
    free(base);
    free(want);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: a goto that loses its flag or lands on the chain's old offset after a write. */
TEST a_goto_into_our_chain_follows_it(void) {
    firc_xt_info_t bi, wi, ni;
    uint8_t *base = NULL, *want = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    ASSERT(firc_test_xt_read("firmware-firc-remove", FIRC_IPT_PROTO_IPV4, &wi, &want));
    base[3 * 152 + 82] |= XT_IPT_F_GOTO;
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc-remove", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(nb[3 * 152 + 82] & XT_IPT_F_GOTO);
    uint32_t first = error_named_v4(want, wi.size, "FIRC_DNAT") + 176;
    ASSERT_EQ_FMT(first, get32(nb + 3 * 152 + 112 + 32), "%u");
    firc_test_stage_free(s);
    free(base);
    free(want);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: a deleted chain still jumped to written with a dangling verdict instead of refused. */
TEST a_chain_deleted_while_jumped_to_is_refused(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_delete(s, "FIRC_g1");
    ASSERT_EQ_FMT(FIRC_ERR_IO, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(strstr(why, "FIRC_g1") != NULL);
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: a duplicate cut from the end, where iptables -D cuts the first match, or an insert at n+1 refused. */
TEST the_first_of_two_copies_is_cut(void) {
    firc_xt_info_t bi, mi, ni;
    uint8_t *base = NULL, *mb = NULL, *nb = NULL;
    int32_t *om = NULL, *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const char *post[] = {"-j FIRC_bh", "-j _NDM_MASQ", "-j FIRC_bh"};
    firc_test_stage_override(s, "POSTROUTING", post, 3);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &mi, &mb, &om, why, sizeof(why)), "%d");
    firc_test_stage_free(s);
    s = firc_test_stage_new();
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND, FIRC_IPT_OP_INSERT};
    const int nums[] = {0, 3};
    const char *lines[] = {"-j FIRC_bh", "-j FIRC_g1"};
    firc_test_stage_patch(s, "POSTROUTING", 2, ops, nums, lines);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &mi, mb, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    char *got = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, &ni, nb);
    ASSERT(strstr(got, "-A POSTROUTING -j _NDM_MASQ\n-A POSTROUTING -j FIRC_bh\n-A POSTROUTING -j FIRC_g1\n-A ACME_PRE") != NULL);
    ASSERT_EQ_FMT(8, oi[7], "%d");
    ASSERT_EQ_FMT(9, oi[8], "%d");
    ASSERT_EQ_FMT(-1, oi[9], "%d");
    free(got);
    firc_test_stage_free(s);
    free(base);
    free(mb);
    free(om);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: a staged jump to a chain the table lacks written with a dangling verdict instead of refused. */
TEST a_jump_to_a_missing_chain_is_refused(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
    const int nums[] = {0};
    const char *lines[] = {"-j FIRC_nowhere"};
    firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, lines);
    ASSERT_EQ_FMT(FIRC_ERR_IO, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(strstr(why, "FIRC_nowhere") != NULL);
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: a jump to a built-in chain written as a jump to its first rule, which iptables-restore refuses. */
TEST a_jump_to_a_built_in_chain_is_refused(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
    const int nums[] = {0};
    const char *lines[] = {"-j PREROUTING"};
    firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, lines);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(strstr(why, "PREROUTING") != NULL);
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: a staged delete of a built-in chain passed over silently, where iptables-restore refuses it. */
TEST a_built_in_chain_is_not_deleted(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_delete(s, "POSTROUTING");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(strstr(why, "POSTROUTING") != NULL);
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: an insert past the end of a chain written at the end, where iptables-restore refuses it. */
TEST an_insert_past_the_end_is_refused(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_INSERT};
    const int nums[] = {9};
    const char *lines[] = {"-j ACME_PRE"};
    firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, lines);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: a refused rule reported without the words that were refused. */
TEST a_refused_rule_is_quoted(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const char *bad[] = {"-o nwg+ -j MASQUERADE"};
    firc_test_stage_override(s, "FIRC_g1", bad, 1);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(strstr(why, "\"-o nwg+ -j MASQUERADE\"") != NULL);
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: a sweep removing a jump the same write staged, or keeping one of ours it did not stage. */
TEST a_sweep_keeps_what_the_same_write_staged(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const char *dnat[] = {"-d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.34"};
    firc_test_stage_override(s, "FIRC_DNAT", dnat, 1);
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
    const int nums[] = {0};
    const char *pre[] = {"-d 198.18.0.0/15 -j FIRC_DNAT"};
    firc_test_stage_patch(s, "PREROUTING", 1, ops, nums, pre);
    s->stage.sweep_prefix = "FIRC_";
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    char *got = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, &ni, nb);
    ASSERT_STR_EQ("*nat\n"
                  ":PREROUTING ACCEPT [0:0]\n"
                  ":INPUT ACCEPT [0:0]\n"
                  ":OUTPUT ACCEPT [0:0]\n"
                  ":POSTROUTING ACCEPT [0:0]\n"
                  ":ACME_PRE - [0:0]\n"
                  ":FIRC_DNAT - [0:0]\n"
                  ":_NDM_DNAT - [0:0]\n"
                  ":_NDM_MASQ - [0:0]\n"
                  "-A PREROUTING -i eth3 -j _NDM_DNAT\n"
                  "-A PREROUTING -j ACME_PRE\n"
                  "-A PREROUTING -d 198.18.0.0/15 -j FIRC_DNAT\n"
                  "-A POSTROUTING -j _NDM_MASQ\n"
                  "-A ACME_PRE -s 192.168.1.0/24 -p udp -m udp --dport 5353 -j RETURN\n"
                  "-A FIRC_DNAT -d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.34\n"
                  "-A _NDM_DNAT -d 203.0.113.5/32 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 192.168.1.10:443\n"
                  "-A _NDM_MASQ -o eth3 -j SNAT --to-source 203.0.113.5\n"
                  "-A _NDM_MASQ -o ppp0 -j MASQUERADE\n"
                  "COMMIT\n",
                  got);
    free(got);
    firc_test_stage_free(s);
    free(base);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: the unchanged check missing a changed mark, or seeing a change in an identical table. */
TEST blob_equal_sees_a_changed_mark_only(void) {
    firc_xt_info_t bi, ni, mi;
    uint8_t *base = NULL, *nb = NULL, *mb = NULL;
    int32_t *oi = NULL, *om = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    uint8_t *copy = malloc(bi.size);
    memcpy(copy, base, bi.size);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, copy, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(firc_xt_blob_equal(&ni, nb, &bi, copy));
    firc_ipt_rule_free(s->rules[3]);
    s->rules[3] = firc_test_rule("-o nwg1 -m mark --mark 0x20000/0xff0000 -j MASQUERADE");
    memcpy(copy, base, bi.size);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, copy, &s->stage, &mi, &mb, &om, why, sizeof(why)), "%d");
    ASSERT_FALSE(firc_xt_blob_equal(&mi, mb, &bi, copy));
    firc_test_stage_free(s);
    free(copy);
    free(base);
    free(nb);
    free(mb);
    free(oi);
    free(om);
    PASS();
}

/* Catches: counters handed to a new entry, or an old entry's counters dropped, when carried over. */
TEST counters_follow_old_index(void) {
    const int32_t old_index[] = {2, -1, 0};
    const firc_xt_counter_t old[] = {{10, 100}, {20, 200}, {30, 300}};
    firc_xt_counter_t *out = NULL;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_carry_counters(old_index, 3, old, 3, &out), "%d");
    ASSERT_EQ(30u, (unsigned)out[0].pcnt);
    ASSERT_EQ(300u, (unsigned)out[0].bcnt);
    ASSERT_EQ(0u, (unsigned)out[1].pcnt);
    ASSERT_EQ(0u, (unsigned)out[1].bcnt);
    ASSERT_EQ(10u, (unsigned)out[2].pcnt);
    free(out);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(each_fixture_merges_as_iptables_restore_did);
    RUN_TEST(carried_entries_keep_their_old_index);
    RUN_TEST(a_jump_into_the_middle_of_a_chain_is_carried);
    RUN_TEST(a_goto_into_our_chain_follows_it);
    RUN_TEST(a_chain_deleted_while_jumped_to_is_refused);
    RUN_TEST(the_first_of_two_copies_is_cut);
    RUN_TEST(a_jump_to_a_missing_chain_is_refused);
    RUN_TEST(a_jump_to_a_built_in_chain_is_refused);
    RUN_TEST(a_built_in_chain_is_not_deleted);
    RUN_TEST(an_insert_past_the_end_is_refused);
    RUN_TEST(a_refused_rule_is_quoted);
    RUN_TEST(a_sweep_keeps_what_the_same_write_staged);
    RUN_TEST(blob_equal_sees_a_changed_mark_only);
    RUN_TEST(counters_follow_old_index);
    GREATEST_MAIN_END();
}
