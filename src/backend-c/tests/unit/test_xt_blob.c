#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "xt_golden.h"
#include "../../src/xtables/xt_internal.h"

static const firc_ipt_proto_t k_fams[] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

static uint16_t get16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t get32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static uint32_t nth_v4(const uint8_t *b, uint32_t k) {
    uint32_t off = 0;
    for (uint32_t i = 0; i < k; i++) { off += get16(b + off + 90); }
    return off;
}

static uint32_t error_named_v4(const uint8_t *b, uint32_t size, const char *name) {
    for (uint32_t off = 0; off < size; off += get16(b + off + 90)) {
        const uint8_t *t = b + off + get16(b + off + 88);
        if (strcmp((const char *)t + 2, "ERROR") == 0 && strcmp((const char *)t + 32, name) == 0) { return off; }
    }
    return UINT32_MAX;
}

/* Catches: chains cut at the wrong entry, or a jump not named for the chain it lands on. */
TEST a_golden_table_reads_as_its_chains(void) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &info, &blob));
    firc_xt_table_t t;
    const char *why = NULL;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why), "%d");
    static const char *const names[] = {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING", "ACME_PRE", "FIRC_DNAT",
                                        "FIRC_DNSOR", "FIRC_bh", "FIRC_g1", "_NDM_DNAT", "_NDM_MASQ"};
    static const size_t rules[] = {4, 0, 0, 3, 1, 1, 2, 0, 1, 1, 2};
    ASSERT_EQ_FMT((size_t)11, t.n_chains, "%zu");
    for (size_t i = 0; i < 11; i++) {
        ASSERT_STR_EQ(names[i], t.chains[i].name);
        ASSERT_EQ_FMT(rules[i], t.chains[i].n_rules, "%zu");
    }
    ASSERT_EQ(0, t.chains[0].hook);
    ASSERT_EQ(4, t.chains[3].hook);
    ASSERT_EQ(-1, t.chains[4].hook);
    static const char *const pre[] = {"FIRC_DNSOR", "_NDM_DNAT", "ACME_PRE", "FIRC_DNAT"};
    for (size_t r = 0; r < 4; r++) { ASSERT_STR_EQ(pre[r], t.chains[0].rules[r].jump); }
    static const char *const post[] = {"_NDM_MASQ", "FIRC_g1", "FIRC_bh"};
    for (size_t r = 0; r < 3; r++) { ASSERT_STR_EQ(post[r], t.chains[3].rules[r].jump); }
    ASSERT_EQ_FMT(34u, t.n_read, "%u");
    firc_xt_table_clear(&t);
    free(blob);
    PASS();
}

/* Catches: serialise moving an entry, a hook offset or a verdict that parse read. */
TEST every_golden_reads_and_writes_back_byte_for_byte(void) {
    for (size_t i = 0; i < firc_test_xt_n_fixtures; i++) {
        for (size_t f = 0; f < 2; f++) {
            const char *name = firc_test_xt_fixtures[i];
            firc_xt_info_t info, ni;
            uint8_t *blob = NULL, *nb = NULL;
            int32_t *oi = NULL;
            ASSERTm(name, firc_test_xt_read(name, k_fams[f], &info, &blob));
            firc_test_xt_zero_kernel_fields(k_fams[f], blob, info.size);
            uint8_t *copy = malloc(info.size);
            memcpy(copy, blob, info.size);
            firc_xt_table_t t;
            const char *why = NULL;
            char w[256];
            ASSERT_EQ_FMTm(name, FIRC_OK, firc_xt_parse(k_fams[f], &info, copy, &t, &why), "%d");
            ASSERT_EQ_FMTm(name, FIRC_OK, firc_xt_serialise(&t, &nb, &ni, &oi, w, sizeof(w)), "%d");
            ASSERTm(name, firc_test_xt_same(k_fams[f], &info, blob, &ni, nb));
            ASSERT_MEM_EQm(name, blob, nb, info.size);
            for (uint32_t k = 0; k < ni.num_entries; k++) { ASSERT_EQ_FMTm(name, (int32_t)k, oi[k], "%d"); }
            firc_xt_table_clear(&t);
            free(copy);
            free(nb);
            free(oi);
            free(blob);
        }
    }
    PASS();
}

static void dirty(firc_ipt_proto_t fam, uint8_t *b, uint32_t size) {
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    uint32_t eh = v6 ? 168 : 112, at_t = v6 ? 140 : 88, at_from = v6 ? 144 : 92, at_cnt = v6 ? 152 : 96;
    for (uint32_t off = 0; off < size; off += get16(b + off + at_t + 2)) {
        uint8_t *e = b + off;
        put32(e + at_from, 0x5a5a5a5au);
        uint64_t c[2] = {7, 9};
        memcpy(e + at_cnt, c, sizeof(c));
        uint16_t toff = get16(e + at_t);
        for (uint32_t m = eh; m <= toff; m += get16(e + m)) {
            size_t n = strlen((const char *)e + m + 2);
            memset(e + m + 2 + n + 1, 0xa5, 29 - n - 1);
            if (m == toff) { break; }
        }
    }
}

/* Catches: a read keeping what the kernel leaves in names, comefrom or counters, so an unchanged table looks changed. */
TEST what_the_kernel_leaves_in_a_read_is_cleared(void) {
    for (size_t f = 0; f < 2; f++) {
        firc_xt_info_t info, ni;
        uint8_t *blob = NULL, *nb = NULL;
        int32_t *oi = NULL;
        ASSERT(firc_test_xt_read("firmware-firc", k_fams[f], &info, &blob));
        firc_test_xt_zero_kernel_fields(k_fams[f], blob, info.size);
        uint8_t *d = malloc(info.size);
        memcpy(d, blob, info.size);
        dirty(k_fams[f], d, info.size);
        ASSERT(memcmp(d, blob, info.size) != 0);
        firc_xt_table_t t;
        const char *why = NULL;
        char w[256];
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(k_fams[f], &info, d, &t, &why), "%d");
        ASSERT_MEM_EQ(blob, d, info.size);
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_serialise(&t, &nb, &ni, &oi, w, sizeof(w)), "%d");
        ASSERT_MEM_EQ(blob, nb, info.size);
        firc_xt_table_clear(&t);
        free(d);
        free(nb);
        free(oi);
        free(blob);
    }
    PASS();
}

typedef void (*spoil_fn)(uint8_t *b, firc_xt_info_t *info);

static void next_zero(uint8_t *b, firc_xt_info_t *i) { (void)i; put16(b + 90, 0); }
static void next_past_end(uint8_t *b, firc_xt_info_t *i) { put16(b + 90, (uint16_t)(i->size + 8)); }
static void next_unaligned(uint8_t *b, firc_xt_info_t *i) { (void)i; put16(b + 90, 153); }
static void toff_in_header(uint8_t *b, firc_xt_info_t *i) { (void)i; put16(b + 88, 100); }
static void target_too_big(uint8_t *b, firc_xt_info_t *i) { (void)i; put16(b + 112, 48); }
static void match_size_zero(uint8_t *b, firc_xt_info_t *i) {
    for (uint32_t off = 0; off < i->size; off += get16(b + off + 90)) {
        if (get16(b + off + 88) > 112) { put16(b + off + 112, 0); return; }
    }
}
static void hook_off_entry(uint8_t *b, firc_xt_info_t *i) { (void)b; i->hook_entry[0] = 4; }
static void underflow_off_entry(uint8_t *b, firc_xt_info_t *i) { (void)b; i->underflow[4] += 8; }
static void count_wrong(uint8_t *b, firc_xt_info_t *i) { (void)b; i->num_entries += 1; }
static void no_error_at_end(uint8_t *b, firc_xt_info_t *i) {
    uint32_t last = nth_v4(b, i->num_entries - 1);
    b[last + get16(b + last + 88) + 2] = 'X';
}
static void jump_into_an_entry(uint8_t *b, firc_xt_info_t *i) { (void)i; put32(b + 112 + 32, get32(b + 112 + 32) + 8); }
static void verdict_unknown(uint8_t *b, firc_xt_info_t *i) { (void)i; put32(b + 112 + 32, (uint32_t)-9); }
static void user_chain_without_return(uint8_t *b, firc_xt_info_t *i) {
    uint32_t dnat = error_named_v4(b, i->size, "FIRC_DNAT");
    uint32_t off = 0, prev = 0;
    while (off < dnat) { prev = off; off += get16(b + off + 90); }
    put32(b + prev + 112 + 32, (uint32_t)XT_VERDICT_ACCEPT);
}
static void hook_that_does_not_exist(uint8_t *b, firc_xt_info_t *i) { (void)b; i->valid_hooks |= 1u << 7; }
static void rename_dnat(uint8_t *b, firc_xt_info_t *i, const char *to) {
    uint32_t dnat = error_named_v4(b, i->size, "FIRC_DNAT");
    uint8_t *name = b + dnat + get16(b + dnat + 88) + 32;
    memset(name, 0, 30);
    memcpy(name, to, strlen(to));
}
static void name_used_twice(uint8_t *b, firc_xt_info_t *i) { rename_dnat(b, i, "ACME_PRE"); }
static void user_chain_named_for_a_hook(uint8_t *b, firc_xt_info_t *i) { rename_dnat(b, i, "FORWARD"); }
static void name_without_nul(uint8_t *b, firc_xt_info_t *i) { (void)i; memset(b + 112 + 2, 'A', 29); }

/* Catches: one of the read checks gone, so a malformed blob reaches the merge. */
TEST a_malformed_table_is_refused(void) {
    static const struct { const char *what; spoil_fn spoil; const char *why; } cases[] = {
        {"next_offset 0", next_zero, "an entry's next_offset is out of bounds"},
        {"next_offset past the end", next_past_end, "an entry's next_offset is out of bounds"},
        {"next_offset not 8-aligned", next_unaligned, "an entry's next_offset is out of bounds"},
        {"target_offset inside the header", toff_in_header, "an entry's target_offset is out of bounds"},
        {"a target larger than its entry", target_too_big, "a target's size is out of bounds"},
        {"a match of size 0", match_size_zero, "a match's size is out of bounds"},
        {"a hook entry off an entry", hook_off_entry, "a hook entry or underflow is not on an entry"},
        {"an underflow off an entry", underflow_off_entry, "a hook entry or underflow is not on an entry"},
        {"num_entries wrong", count_wrong, "num_entries does not match the entries"},
        {"no ERROR at the end", no_error_at_end, "the last entry is not an ERROR target"},
        {"a jump into an entry", jump_into_an_entry, "a jump lands inside an entry"},
        {"an unknown verdict", verdict_unknown, "a standard target has an unknown verdict"},
        {"a user chain without RETURN", user_chain_without_return, "a user chain does not end in RETURN"},
        {"a hook that does not exist", hook_that_does_not_exist, "valid_hooks names a hook that does not exist"},
        {"a name without its NUL", name_without_nul, "a target name has no end"},
        {"a chain name used twice", name_used_twice, "two chains share a name"},
        {"a user chain named for a hook", user_chain_named_for_a_hook, "two chains share a name"},
    };
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        firc_xt_info_t info;
        uint8_t *blob = NULL;
        ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &info, &blob));
        cases[c].spoil(blob, &info);
        firc_xt_table_t t;
        const char *why = NULL;
        ASSERT_EQ_FMTm(cases[c].what, FIRC_ERR_PROTO, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why), "%d");
        ASSERTm(cases[c].what, why != NULL);
        ASSERT_STR_EQm(cases[c].what, cases[c].why, why);
        free(blob);
    }
    PASS();
}

/* Catches: relocation moving hook entries, underflows or jumps by the wrong amount when a built-in chain grows. */
TEST a_rule_added_to_prerouting_moves_what_follows_it(void) {
    firc_xt_info_t info, ni;
    uint8_t *blob = NULL, *nb = NULL;
    int32_t *oi = NULL;
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &info, &blob));
    uint32_t old_verdict = get32(blob + 152 + 112 + 32);
    uint8_t *copy = malloc(info.size);
    memcpy(copy, blob, info.size);
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256];
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, copy, &t, &why), "%d");
    firc_xt_chain_t *pre = firc_xt_find_chain(&t, "PREROUTING");
    ASSERT(pre != NULL && pre->n_rules == 2 && strcmp(pre->rules[1].jump, "ACME_PRE") == 0);
    firc_xt_entry_t *grown = realloc(pre->rules, 3 * sizeof(*grown));
    ASSERT(grown != NULL);
    pre->rules = grown;
    pre->cap_rules = 3;
    memmove(&pre->rules[1], &pre->rules[0], 2 * sizeof(*grown));
    firc_xt_entry_t fresh = pre->rules[2];
    fresh.bytes = malloc(fresh.len);
    memcpy(fresh.bytes, pre->rules[2].bytes, fresh.len);
    fresh.old_index = -1;
    fresh.old_off = FIRC_XT_NONE;
    pre->rules[0] = fresh;
    pre->n_rules = 3;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_serialise(&t, &nb, &ni, &oi, w, sizeof(w)), "%d");
    ASSERT_EQ_FMT(info.size + 152u, ni.size, "%u");
    ASSERT_EQ_FMT(info.num_entries + 1u, ni.num_entries, "%u");
    ASSERT_EQ_FMT(0u, ni.hook_entry[0], "%u");
    ASSERT_EQ_FMT(info.underflow[0] + 152u, ni.underflow[0], "%u");
    static const int moved[] = {1, 3, 4};
    for (size_t k = 0; k < 3; k++) {
        ASSERT_EQ_FMT(info.hook_entry[moved[k]] + 152u, ni.hook_entry[moved[k]], "%u");
        ASSERT_EQ_FMT(info.underflow[moved[k]] + 152u, ni.underflow[moved[k]], "%u");
    }
    ASSERT_EQ_FMT(old_verdict + 152u, get32(nb + 112 + 32), "%u");
    ASSERT_EQ_FMT(old_verdict + 152u, get32(nb + 2 * 152 + 112 + 32), "%u");
    ASSERT_EQ_FMT(-1, oi[0], "%d");
    ASSERT_EQ_FMT(0, oi[1], "%d");
    firc_xt_table_clear(&t);
    free(copy);
    free(nb);
    free(oi);
    free(blob);
    PASS();
}

/* Catches: a jump to an entry that starts no chain left at its old offset when the entries before it move. */
TEST a_jump_into_a_chain_moves_with_its_entry(void) {
    firc_xt_info_t info, ni;
    uint8_t *blob = NULL, *nb = NULL;
    int32_t *oi = NULL;
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &info, &blob));
    put32(blob + 152 + 112 + 32, info.underflow[0]);
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256];
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why), "%d");
    firc_xt_chain_t *pre = firc_xt_find_chain(&t, "PREROUTING");
    ASSERT(pre != NULL && pre->n_rules == 2);
    ASSERT_STR_EQ("", pre->rules[1].jump);
    ASSERT_EQ_FMT(info.underflow[0], pre->rules[1].points_at, "%u");
    firc_xt_entry_t *grown = realloc(pre->rules, 3 * sizeof(*grown));
    ASSERT(grown != NULL);
    pre->rules = grown;
    pre->cap_rules = 3;
    memmove(&pre->rules[1], &pre->rules[0], 2 * sizeof(*grown));
    firc_xt_entry_t fresh = pre->rules[1];
    fresh.bytes = malloc(fresh.len);
    memcpy(fresh.bytes, pre->rules[1].bytes, fresh.len);
    fresh.old_index = -1;
    fresh.old_off = FIRC_XT_NONE;
    pre->rules[0] = fresh;
    pre->n_rules = 3;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_serialise(&t, &nb, &ni, &oi, w, sizeof(w)), "%d");
    ASSERT_EQ_FMT(info.underflow[0] + 152u, ni.underflow[0], "%u");
    ASSERT_EQ_FMT(info.underflow[0] + 152u, get32(nb + 2 * 152 + 112 + 32), "%u");
    free(nb);
    free(oi);
    pre->rules[2].points_at = 8;
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_serialise(&t, &nb, &ni, &oi, w, sizeof(w)), "%d");
    ASSERT(strstr(w, "PREROUTING") != NULL);
    firc_xt_table_clear(&t);
    free(blob);
    PASS();
}

/* Catches: a second chain under a name the table already has, so a jump by name lands on the first. */
TEST a_name_the_table_has_is_not_added_again(void) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &info, &blob));
    firc_xt_table_t t;
    const char *why = NULL;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why), "%d");
    size_t before = t.n_chains;
    firc_xt_chain_t *c = NULL;
    firc_err_t twice = firc_xt_add_user_chain(&t, "ACME_PRE", &c);
    firc_err_t hook = firc_xt_add_user_chain(&t, "FORWARD", &c);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, twice, "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, hook, "%d");
    ASSERT_EQ_FMT(before, t.n_chains, "%zu");
    firc_xt_table_clear(&t);
    free(blob);
    PASS();
}

/* Catches: a built-in chain dropped, or a valid hook written with no chain behind it as offset 0. */
TEST a_hook_never_loses_its_chain(void) {
    firc_xt_info_t info, ni;
    uint8_t *blob = NULL, *nb = NULL;
    int32_t *oi = NULL;
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &info, &blob));
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256];
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why), "%d");
    size_t before = t.n_chains;
    firc_err_t dropped = firc_xt_drop_chain(&t, firc_xt_find_chain(&t, "POSTROUTING"));
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, dropped, "%d");
    ASSERT_EQ_FMT(before, t.n_chains, "%zu");
    ASSERT(firc_xt_find_chain(&t, "POSTROUTING") != NULL);
    t.valid_hooks |= 1u << 2;
    firc_err_t written = firc_xt_serialise(&t, &nb, &ni, &oi, w, sizeof(w));
    ASSERT_EQ_FMT(FIRC_ERR_IO, written, "%d");
    ASSERT(strstr(w, "FORWARD") != NULL);
    ASSERT(nb == NULL && oi == NULL);
    firc_xt_table_clear(&t);
    free(blob);
    PASS();
}

/* Catches: a new user chain placed out of name order, or with a head or tail libiptc would not write. */
TEST a_new_chain_lands_where_libiptc_puts_it(void) {
    firc_xt_info_t info, want_info, ni;
    uint8_t *blob = NULL, *want = NULL, *nb = NULL;
    int32_t *oi = NULL;
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &info, &blob));
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &want_info, &want));
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256];
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why), "%d");
    firc_xt_chain_t *c = NULL;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_add_user_chain(&t, "FIRC_bh", &c), "%d");
    ASSERT_STR_EQ("FIRC_bh", t.chains[5].name);
    ASSERT_STR_EQ("ACME_PRE", t.chains[4].name);
    ASSERT_STR_EQ("_NDM_DNAT", t.chains[6].name);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_serialise(&t, &nb, &ni, &oi, w, sizeof(w)), "%d");
    uint32_t ours = error_named_v4(nb, ni.size, "FIRC_bh");
    uint32_t theirs = error_named_v4(want, want_info.size, "FIRC_bh");
    ASSERT(ours != UINT32_MAX && theirs != UINT32_MAX);
    ASSERT_MEM_EQ(want + theirs, nb + ours, 176 + 152);
    firc_xt_table_clear(&t);
    free(nb);
    free(oi);
    free(want);
    free(blob);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_golden_table_reads_as_its_chains);
    RUN_TEST(every_golden_reads_and_writes_back_byte_for_byte);
    RUN_TEST(what_the_kernel_leaves_in_a_read_is_cleared);
    RUN_TEST(a_malformed_table_is_refused);
    RUN_TEST(a_rule_added_to_prerouting_moves_what_follows_it);
    RUN_TEST(a_jump_into_a_chain_moves_with_its_entry);
    RUN_TEST(a_new_chain_lands_where_libiptc_puts_it);
    RUN_TEST(a_name_the_table_has_is_not_added_again);
    RUN_TEST(a_hook_never_loses_its_chain);
    GREATEST_MAIN_END();
}
