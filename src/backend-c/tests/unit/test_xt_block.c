#include "greatest.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../../src/xtables/xt_internal.h"
#include "firc/xtables.h"
#include "xt_golden.h"

static const firc_ipt_proto_t k_fams[2] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

static void addr(firc_ipt_proto_t fam, const char *text, uint8_t out[16]) {
    memset(out, 0, 16);
    if (inet_pton(fam == FIRC_IPT_PROTO_IPV6 ? AF_INET6 : AF_INET, text, out) != 1) { abort(); }
}

static firc_err_t add_line(firc_xt_block_t *b, firc_ipt_proto_t fam, const char *line) {
    firc_ipt_rule_t *r = firc_test_rule(line);
    firc_err_t err = firc_xt_block_add_rule(b, fam, r);
    firc_ipt_rule_free(r);
    return err;
}

/* Catches: a typed DNAT entry unlike iptables-restore's conditional one (no mark match, another mask or revision, a flag). */
TEST a_typed_dnat_entry_is_the_golden_one(void) {
    const char *fake[2] = {"198.18.0.1", "fd37:9a00::1"};
    const char *real[2] = {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"};
    for (size_t f = 0; f < 2; f++) {
        uint8_t a[16], b[16];
        addr(k_fams[f], fake[f], a);
        addr(k_fams[f], real[f], b);
        firc_xt_block_t typed;
        firc_xt_block_init(&typed);
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_add_dnat(&typed, k_fams[f], a, b), "%d");
        ASSERT_EQ_FMT((uint32_t)1, typed.n, "%u");
        ASSERT_EQ_FMT((uint32_t)(FIRC_XT_EXT_DNAT | FIRC_XT_EXT_MARK), typed.exts, "%u");
        firc_xt_info_t info;
        uint8_t *blob = NULL;
        ASSERT(firc_test_xt_read("dnat-mark", k_fams[f], &info, &blob));
        firc_xt_table_t t;
        const char *why = NULL;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(k_fams[f], &info, blob, &t, &why), "%d");
        firc_xt_chain_t *c = firc_xt_find_chain(&t, "FIRC_DNAT");
        ASSERT(c != NULL && c->n_rules == 1);
        firc_xt_entry_t e;
        memset(&e, 0, sizeof(e));
        e.bytes = typed.bytes;
        e.len = (uint32_t)typed.len;
        e.old_index = -1;
        e.old_off = FIRC_XT_NONE;
        e.points_at = FIRC_XT_NONE;
        ASSERT(firc_xt_entry_same(k_fams[f], &e, &c->rules[0]));
        firc_xt_table_clear(&t);
        free(blob);
        firc_xt_block_free(&typed);
    }
    PASS();
}

/* Catches: a staging from blocks laid out differently from the argv path iptables-restore 1.4.21 was checked against. */
TEST two_thousand_typed_rules_merge_to_the_golden(void) {
    for (size_t f = 0; f < 2; f++) {
        bool v6 = k_fams[f] == FIRC_IPT_PROTO_IPV6;
        firc_xt_block_t b;
        firc_xt_block_init(&b);
        for (unsigned i = 0; i < 2000; i++) {
            uint8_t fake[16] = {0}, real[16] = {0};
            if (v6) {
                fake[0] = 0xfd; fake[1] = 0x37; fake[2] = 0x9a; fake[14] = (uint8_t)((i + 1) >> 8); fake[15] = (uint8_t)(i + 1);
                real[0] = 0x20; real[1] = 0x01; real[2] = 0x0d; real[3] = 0xb8; real[14] = (uint8_t)((i + 1) >> 8); real[15] = (uint8_t)(i + 1);
            } else {
                fake[0] = 198; fake[1] = 18; fake[2] = (uint8_t)(i / 256); fake[3] = (uint8_t)(i % 256);
                real[0] = 100; real[1] = 64; real[2] = (uint8_t)(i / 256); real[3] = (uint8_t)(i % 256);
            }
            ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_add_dnat(&b, k_fams[f], fake, real), "%d");
        }
        firc_test_stage_t *s = firc_test_stage_new();
        firc_test_stage_block(s, "FIRC_DNAT", &b);
        const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
        const int nums[] = {0};
        const char *pre[] = {v6 ? "-d fd37:9a00::/48 -j FIRC_DNAT" : "-d 198.18.0.0/15 -j FIRC_DNAT"};
        firc_test_stage_patch(s, "PREROUTING", 1, ops, nums, pre);
        firc_xt_info_t ei, gi, ni;
        uint8_t *empty = NULL, *golden = NULL, *out = NULL;
        int32_t *oi = NULL;
        ASSERT(firc_test_xt_read("empty", k_fams[f], &ei, &empty));
        ASSERT(firc_test_xt_read("dnat2000-mark", k_fams[f], &gi, &golden));
        firc_xt_table_t t;
        const char *why = NULL;
        char w[256];
        uint32_t exts = 0;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(k_fams[f], &ei, empty, &t, &why), "%d");
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_merge(&t, &s->stage, &exts, w, sizeof(w)), "%d");
        ASSERT_EQ_FMT((uint32_t)(FIRC_XT_EXT_DNAT | FIRC_XT_EXT_MARK), exts, "%u");
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_serialise(&t, &out, &ni, &oi, w, sizeof(w)), "%d");
        ASSERT(firc_test_xt_same(k_fams[f], &gi, golden, &ni, out));
        free(out);
        free(oi);
        firc_xt_table_clear(&t);
        free(empty);
        free(golden);
        firc_test_stage_free(s);
        firc_xt_block_free(&b);
    }
    PASS();
}

/* Catches: a block's jump left at verdict 0, which the kernel reads as a jump to the table's first entry. */
TEST a_jump_in_a_block_lands_on_its_chain(void) {
    firc_xt_block_t g, d;
    firc_xt_block_init(&g);
    firc_xt_block_init(&d);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&g, FIRC_IPT_PROTO_IPV4, "-d 198.18.0.0/24 -j FIRC_g1D"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, add_line(&d, FIRC_IPT_PROTO_IPV4, "-o nwg1 -j ACCEPT"), "%d");
    ASSERT_EQ_FMT((size_t)1, g.n_jumps, "%zu");
    ASSERT_STR_EQ("FIRC_g1D", g.jumps[0].chain);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_block(s, "FIRC_g1", &g);
    firc_test_stage_block(s, "FIRC_g1D", &d);
    firc_xt_info_t ei, ni;
    uint8_t *empty = NULL, *out = NULL;
    int32_t *oi = NULL;
    ASSERT(firc_test_xt_read("empty", FIRC_IPT_PROTO_IPV4, &ei, &empty));
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256];
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &ei, empty, &t, &why), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_merge(&t, &s->stage, &exts, w, sizeof(w)), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_serialise(&t, &out, &ni, &oi, w, sizeof(w)), "%d");
    char *text = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "nat", &ni, out);
    ASSERT(text != NULL);
    ASSERT(strstr(text, "-A FIRC_g1 -d 198.18.0.0/24 -j FIRC_g1D\n") != NULL);
    free(text);
    free(out);
    free(oi);
    firc_xt_table_clear(&t);
    free(empty);
    firc_test_stage_free(s);
    firc_xt_block_free(&g);
    firc_xt_block_free(&d);
    PASS();
}

/* Catches: two blocks with the same bytes but jumping to different chains judged equal, so the skip would keep a stale jump. */
TEST blocks_jumping_elsewhere_are_not_equal(void) {
    firc_xt_block_t a, b, c;
    firc_xt_block_init(&a);
    firc_xt_block_init(&b);
    firc_xt_block_init(&c);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&a, FIRC_IPT_PROTO_IPV4, "-d 198.18.0.0/24 -j FIRC_g1D"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV4, "-d 198.18.0.0/24 -j FIRC_g2D"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, add_line(&c, FIRC_IPT_PROTO_IPV4, "-d 198.18.0.0/24 -j FIRC_g1D"), "%d");
    ASSERT_EQ_FMT(a.len, b.len, "%zu");
    ASSERT_EQ(0, memcmp(a.bytes, b.bytes, a.len));
    ASSERT_FALSE(firc_xt_block_equal(&a, &b));
    ASSERT(firc_xt_block_equal(&a, &c));
    ASSERT_EQ_FMT(FIRC_OK, add_line(&c, FIRC_IPT_PROTO_IPV4, "-j RETURN"), "%d");
    ASSERT_FALSE(firc_xt_block_equal(&a, &c));
    firc_xt_block_free(&a);
    firc_xt_block_free(&b);
    firc_xt_block_free(&c);
    PASS();
}

/* Catches: a re-staged chain nothing changed in written with the staging's bytes instead of the read's (a write every pass once a payload has kernel bytes). */
TEST an_unchanged_chain_keeps_the_entries_it_was_read_with(void) {
    firc_xt_info_t gi, ni;
    uint8_t *golden = NULL, *out = NULL;
    int32_t *oi = NULL;
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &gi, &golden));
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV4, "-o nwg1 -m mark --mark 0x10000/0xff0000 -j MASQUERADE"), "%d");
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_block(s, "FIRC_g1", &b);
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256];
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &gi, golden, &t, &why), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_merge(&t, &s->stage, &exts, w, sizeof(w)), "%d");
    firc_xt_chain_t *c = firc_xt_find_chain(&t, "FIRC_g1");
    ASSERT(c != NULL);
    ASSERT_EQ_FMT((size_t)1, c->n_rules, "%zu");
    ASSERT(c->rules[0].bytes >= golden && c->rules[0].bytes < golden + gi.size);
    ASSERT(c->rules[0].old_index >= 0);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_serialise(&t, &out, &ni, &oi, w, sizeof(w)), "%d");
    ASSERT(firc_xt_blob_equal(&ni, out, &gi, golden));
    free(out);
    free(oi);
    firc_xt_table_clear(&t);
    free(golden);
    firc_test_stage_free(s);
    firc_xt_block_free(&b);
    PASS();
}

static firc_err_t merge_into_empty(firc_ipt_proto_t fam, const firc_xt_block_t *b) {
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_block(s, "FIRC_g1", b);
    firc_xt_info_t ei;
    uint8_t *empty = NULL;
    if (!firc_test_xt_read("empty", fam, &ei, &empty)) { abort(); }
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256];
    uint32_t exts = 0;
    if (firc_xt_parse(fam, &ei, empty, &t, &why) != FIRC_OK) { abort(); }
    firc_err_t err = firc_xt_merge(&t, &s->stage, &exts, w, sizeof(w));
    firc_xt_table_clear(&t);
    free(empty);
    firc_test_stage_free(s);
    return err;
}

/* Catches: a block of one family merged into the other's table, whose entries the kernel would read at the wrong offsets. */
TEST a_block_of_the_other_family_is_refused(void) {
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV4, "-o nwg1 -j ACCEPT"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, add_line(&b, FIRC_IPT_PROTO_IPV6, "-o nwg1 -j ACCEPT"), "%d");
    uint8_t fake[16] = {0xfd, 0x37, 0x9a}, real[16] = {0x20, 0x01, 0x0d, 0xb8};
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_add_dnat(&b, FIRC_IPT_PROTO_IPV6, fake, real), "%d");
    ASSERT_EQ_FMT((uint32_t)1, b.n, "%u");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, merge_into_empty(FIRC_IPT_PROTO_IPV6, &b), "%d");
    ASSERT_EQ_FMT(FIRC_OK, merge_into_empty(FIRC_IPT_PROTO_IPV4, &b), "%d");
    firc_xt_block_free(&b);
    firc_xt_block_t six;
    firc_xt_block_init(&six);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&six, FIRC_IPT_PROTO_IPV6, "-o nwg1 -j ACCEPT"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, merge_into_empty(FIRC_IPT_PROTO_IPV6, &six), "%d");
    six.fam = FIRC_IPT_PROTO_IPV4;
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, merge_into_empty(FIRC_IPT_PROTO_IPV6, &six), "%d");
    firc_xt_block_free(&six);
    PASS();
}

/* Catches: an entry length or count in a block trusted, so the merge walks past its bytes or loops on a zero length. */
TEST a_block_with_a_corrupt_length_is_refused(void) {
    const uint16_t bad[3] = {0, 8, 4096};
    for (size_t k = 0; k < 3; k++) {
        firc_xt_block_t b;
        firc_xt_block_init(&b);
        ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV4, "-o nwg1 -j ACCEPT"), "%d");
        ASSERT_EQ_FMT(FIRC_OK, merge_into_empty(FIRC_IPT_PROTO_IPV4, &b), "%d");
        firc_xt_wr16(b.bytes + firc_xt_at_next(FIRC_IPT_PROTO_IPV4), bad[k]);
        ASSERT_EQ_FMT(FIRC_ERR_INVAL, merge_into_empty(FIRC_IPT_PROTO_IPV4, &b), "%d");
        firc_xt_block_free(&b);
    }
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV4, "-o nwg1 -j ACCEPT"), "%d");
    b.n = 2;
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, merge_into_empty(FIRC_IPT_PROTO_IPV4, &b), "%d");
    b.n = 0;
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, merge_into_empty(FIRC_IPT_PROTO_IPV4, &b), "%d");
    firc_xt_block_free(&b);
    const uint32_t at = firc_xt_at_next(FIRC_IPT_PROTO_IPV4);
    firc_xt_block_t two;
    firc_xt_block_init(&two);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&two, FIRC_IPT_PROTO_IPV4, "-o nwg1 -j ACCEPT"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, add_line(&two, FIRC_IPT_PROTO_IPV4, "-o nwg2 -j ACCEPT"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, merge_into_empty(FIRC_IPT_PROTO_IPV4, &two), "%d");
    firc_xt_wr16(two.bytes + at, 8);
    firc_xt_wr16(two.bytes + 8 + at, (uint16_t)(two.len - 8));
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, merge_into_empty(FIRC_IPT_PROTO_IPV4, &two), "%d");
    firc_xt_wr16(two.bytes + at, 0xfff8);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, merge_into_empty(FIRC_IPT_PROTO_IPV4, &two), "%d");
    firc_xt_block_free(&two);
    PASS();
}

/* Catches: a family value that is neither v4 nor v6 encoded as v4 instead of refused. */
TEST an_unknown_family_is_refused(void) {
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    uint8_t fake[16] = {198, 18, 0, 1}, real[16] = {100, 64, 0, 1};
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_add_dnat(&b, (firc_ipt_proto_t)7, fake, real), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, add_line(&b, (firc_ipt_proto_t)7, "-o nwg1 -j ACCEPT"), "%d");
    ASSERT_EQ_FMT((uint32_t)0, b.n, "%u");
    ASSERT_EQ_FMT((size_t)0, b.len, "%zu");
    firc_xt_block_free(&b);
    PASS();
}

/* Catches: a block's mac match encoded at another revision than its own, or merged into a table whose kernel takes another revision. */
TEST a_block_carries_its_mac_revision_and_the_table_checks_it(void) {
    firc_xt_block_t mac, plain;
    firc_xt_block_init(&mac);
    firc_xt_block_init(&plain);
    mac.mac_rev = 1;
    plain.mac_rev = 1;
    ASSERT_EQ_FMT(FIRC_OK, add_line(&mac, FIRC_IPT_PROTO_IPV4, "-m mac --mac-source 02:00:00:00:00:0A -j RETURN"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, add_line(&plain, FIRC_IPT_PROTO_IPV4, "-s 192.168.1.50/32 -j RETURN"), "%d");
    ASSERT_STR_EQ("mac", (const char *)mac.bytes + 112 + 2);
    ASSERT_EQ_FMT(1u, mac.bytes[112 + 31], "%u");
    for (uint8_t rev = 0; rev < 2; rev++) {
        firc_xt_info_t ei;
        uint8_t *empty = NULL;
        ASSERT(firc_test_xt_read("m-empty", FIRC_IPT_PROTO_IPV4, &ei, &empty));
        firc_xt_table_t t;
        const char *why = NULL;
        char w[256] = "";
        uint32_t exts = 0;
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &ei, empty, &t, &why), "%d");
        t.mac_rev = rev;
        firc_test_stage_t *s = firc_test_stage_new();
        firc_test_stage_block(s, "FIRC_g1", &plain);
        firc_test_stage_block(s, "FIRC_g1D", &mac);
        ASSERT_EQ_FMTm(w, rev == 1 ? FIRC_OK : FIRC_ERR_INVAL, firc_xt_merge(&t, &s->stage, &exts, w, sizeof(w)), "%d");
        if (rev == 0) { ASSERT_STR_EQ("the block for FIRC_g1D holds mac revision 1, the kernel takes 0", w); }
        firc_xt_table_clear(&t);
        free(empty);
        firc_test_stage_free(s);
    }
    firc_xt_block_free(&mac);
    firc_xt_block_free(&plain);
    PASS();
}

/* Catches: a block mixing mac revisions, or checked against the table by the revision set after its rules were encoded. */
TEST a_block_keeps_the_mac_revision_of_its_first_rule(void) {
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV4, "-m mac --mac-source 02:00:00:00:00:0A -j RETURN"), "%d");
    b.mac_rev = 1;
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, add_line(&b, FIRC_IPT_PROTO_IPV4, "-s 192.168.1.50/32 -j RETURN"), "%d");
    ASSERT_EQ_FMT((uint32_t)1, b.n, "%u");
    firc_xt_info_t ei;
    uint8_t *empty = NULL;
    ASSERT(firc_test_xt_read("m-empty", FIRC_IPT_PROTO_IPV4, &ei, &empty));
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256] = "";
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &ei, empty, &t, &why), "%d");
    t.mac_rev = 1;
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_block(s, "FIRC_g1D", &b);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_merge(&t, &s->stage, &exts, w, sizeof(w)), "%d");
    ASSERT_STR_EQ("the block for FIRC_g1D holds mac revision 0, the kernel takes 1", w);
    firc_xt_table_clear(&t);
    free(empty);
    firc_test_stage_free(s);
    firc_xt_block_free(&b);
    PASS();
}

typedef struct seen {
    firc_xt_role_t role[16];
    uint8_t addr[16][16];
    uint8_t mask[16][16];
    size_t n;
} seen_t;

static void note(void *ud, uint32_t i, firc_xt_role_t role, const uint8_t *addr, const uint8_t *mask) {
    seen_t *s = ud;
    if (i != s->n || s->n == 16) { abort(); }
    s->role[s->n] = role;
    memcpy(s->addr[s->n], addr, 16);
    memcpy(s->mask[s->n], mask, 16);
    s->n++;
}

typedef struct want_role {
    firc_xt_role_t role;
    const char *addr;
    unsigned plen;
} want_role_t;

static void prefix_mask(unsigned plen, uint8_t out[16]) {
    memset(out, 0, 16);
    for (unsigned k = 0; k < plen; k++) { out[k / 8] = (uint8_t)(out[k / 8] | (0x80u >> (k % 8))); }
}

static enum greatest_test_res roles_are(firc_ipt_proto_t fam, const char *const *lines, const want_role_t *want, size_t n) {
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    for (size_t i = 0; i < n; i++) { ASSERT_EQ_FMTm(lines[i], FIRC_OK, add_line(&b, fam, lines[i]), "%d"); }
    seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_roles(&b, fam, note, &s), "%d");
    ASSERT_EQ_FMT(n, s.n, "%zu");
    for (size_t i = 0; i < n; i++) {
        uint8_t a[16], m[16];
        memset(a, 0, sizeof(a));
        if (want[i].addr != NULL) { addr(fam, want[i].addr, a); }
        prefix_mask(want[i].plen, m);
        ASSERT_EQ_FMTm(lines[i], (int)want[i].role, (int)s.role[i], "%d");
        ASSERTm(lines[i], memcmp(a, s.addr[i], 16) == 0);
        ASSERTm(lines[i], memcmp(m, s.mask[i], 16) == 0);
    }
    firc_xt_block_free(&b);
    PASS();
}

/* Catches: the write order misreading a staging (a mark taken for a rewrite, a port-only DNAT taken for an address rewrite, a jump without destination taken for a mark). */
TEST each_entry_says_what_it_does_for_the_order(void) {
    static const char *const lines[] = {
        "-m conntrack --ctdir REPLY -j RETURN",
        "-d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d 198.18.0.0/24 -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000",
        "-d 198.18.1.0/24 -j FIRC_g2D",
        "-j FIRC_g2D",
        "-p udp -d 192.168.1.1 --dport 53 -j DNAT --to-destination :3553",
        "-d 198.18.0.7/32 -j DNAT --to-destination 93.184.216.34",
    };
    static const want_role_t want[] = {
        {FIRC_XT_ROLE_OTHER, NULL, 0},
        {FIRC_XT_ROLE_MARKS, "198.18.0.0", 24},
        {FIRC_XT_ROLE_OTHER, "198.18.0.0", 24},
        {FIRC_XT_ROLE_MARKS, "198.18.1.0", 24},
        {FIRC_XT_ROLE_OTHER, NULL, 0},
        {FIRC_XT_ROLE_OTHER, "192.168.1.1", 32},
        {FIRC_XT_ROLE_REWRITES, "198.18.0.7", 32},
    };
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV4, lines, want, 7));
    PASS();
}

/* Catches: v6 roles read at v4 offsets (a destination or the DNAT flags taken from the wrong bytes). */
TEST v6_entries_say_what_they_do_for_the_order(void) {
    static const char *const lines[] = {
        "-d fd37:9a00::/64 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d fd37:9a00:0:1::/64 -j FIRC_g2D",
        "-p udp -d fd00:1::1 --dport 53 -j DNAT --to-destination :3553",
        "-d fd37:9a00::7/128 -j DNAT --to-destination 2606:2800:220:1:248:1893:25c8:1946",
        "-d fd37:9a00::/48 -j REJECT --reject-with icmp6-addr-unreachable",
    };
    static const want_role_t want[] = {
        {FIRC_XT_ROLE_MARKS, "fd37:9a00::", 64},
        {FIRC_XT_ROLE_MARKS, "fd37:9a00:0:1::", 64},
        {FIRC_XT_ROLE_OTHER, "fd00:1::1", 128},
        {FIRC_XT_ROLE_REWRITES, "fd37:9a00::7", 128},
        {FIRC_XT_ROLE_OTHER, "fd37:9a00::", 48},
    };
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV6, lines, want, 5));
    PASS();
}

/* Catches: a mark that holds only for some packets (a port, a source, an interface, a match) taken as covering its whole destination. */
TEST a_conditional_mark_covers_nothing(void) {
    static const char *const lines[] = {
        "-d 10.20.0.0/16 -p tcp -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -m tcp --dport 443 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d 10.40.0.0/16 -p udp -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -m udp --dport 5000:5100 -j FIRC_g2D",
        "-s 192.168.1.5 -d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-i br0 -d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d 198.18.0.0/24 -p tcp -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d 198.18.0.0/24 -m mark --mark 0x0/0x40000000 -j FIRC_g1D",
        "-m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -j MARK --set-xmark 0x40010000/0x40ff0000",
    };
    static const want_role_t want[] = {
        {FIRC_XT_ROLE_OTHER, "10.20.0.0", 16},
        {FIRC_XT_ROLE_OTHER, "10.40.0.0", 16},
        {FIRC_XT_ROLE_OTHER, "198.18.0.0", 24},
        {FIRC_XT_ROLE_OTHER, "198.18.0.0", 24},
        {FIRC_XT_ROLE_OTHER, "198.18.0.0", 24},
        {FIRC_XT_ROLE_OTHER, "198.18.0.0", 24},
        {FIRC_XT_ROLE_OTHER, NULL, 0},
    };
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV4, lines, want, 7));
    PASS();
}

/* Catches: the FORWARD barrier taken for a mark or a rewrite (the coverage check then trusts or refuses it). */
TEST the_barrier_is_neither_a_mark_nor_a_rewrite(void) {
    static const char *const line[] = {
        "-m conntrack --ctdir ORIGINAL -m connmark --mark 0x40000000/0x40000000 -m mark ! --mark 0x40000000/0x40000000 -j DROP",
    };
    static const want_role_t want[] = {{FIRC_XT_ROLE_OTHER, NULL, 0}};
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV4, line, want, 1));
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV6, line, want, 1));
    PASS();
}

/* Catches: a REDIRECT or its addrtype jump taken for a rewrite or a mark, so the coverage check refuses or trusts it. */
TEST a_redirect_is_neither_a_mark_nor_a_rewrite(void) {
    static const char *const lines[] = {
        "-p tcp -m mark --mark 0x40050000/0x40ff0000 -j REDIRECT --to-ports 3603",
        "-d 198.18.0.0/15 -p tcp -j REDIRECT --to-ports 3600-3601",
        "-p tcp -m mark --mark 0x40000000/0x40000000 -m addrtype ! --dst-type LOCAL -j FIRC_REDIR",
    };
    static const want_role_t want[] = {
        {FIRC_XT_ROLE_OTHER, NULL, 0},
        {FIRC_XT_ROLE_OTHER, "198.18.0.0", 15},
        {FIRC_XT_ROLE_OTHER, NULL, 0},
    };
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV4, lines, want, 3));
    PASS();
}

/* Catches: a rewrite missed because it has conditions or no destination (its rewrites then counted as covered by nothing to check). */
TEST every_address_rewrite_is_a_rewrite(void) {
    static const char *const lines[] = {
        "-p tcp -d 198.18.0.9 --dport 443 -j DNAT --to-destination 93.184.216.34",
        "-p tcp -j DNAT --to-destination 192.168.1.10",
        "-d 198.18.0.0/15 -j FIRC_DNAT",
        "-d 198.18.0.0/15 -p tcp -j REJECT --reject-with tcp-reset",
        "-i br0 -m conntrack --ctstate NEW ! --ctorigdst 198.18.0.0/15 -m mark ! --mark 0x40000000/0x40000000 -m limit --limit 500/sec --limit-burst 500 -j NFLOG --nflog-group 5 --nflog-threshold 1",
    };
    static const want_role_t want[] = {
        {FIRC_XT_ROLE_REWRITES, "198.18.0.9", 32},
        {FIRC_XT_ROLE_REWRITES, NULL, 0},
        {FIRC_XT_ROLE_MARKS, "198.18.0.0", 15},
        {FIRC_XT_ROLE_OTHER, "198.18.0.0", 15},
        {FIRC_XT_ROLE_OTHER, NULL, 0},
    };
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV4, lines, want, 5));
    PASS();
}

/* Catches: the group chains firc writes misread (the real mark rules of two groups, a selector, subnet rules, the devices chain). */
TEST the_group_chains_say_their_marks(void) {
    static const char *const v4[] = {
        "-m conntrack --ctdir REPLY -j RETURN",
        "-d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d 198.18.0.0/24 -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000",
        "-d 198.18.5.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d 10.30.0.0/16 -p udp -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -m multiport --dports 53,1000:2000,5353 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d 198.18.1.0/24 -j FIRC_g2D",
        "-s 192.168.1.50/32 -j RETURN",
        "-m mac --mac-source 02:00:00:00:00:0B -j MARK --set-xmark 0x40020000/0x40ff0000",
        "-s 192.168.1.0/24 -j MARK --set-xmark 0x40020000/0x40ff0000",
        "-m mark --mark 0x40020000/0x40ff0000 -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000",
    };
    static const want_role_t w4[] = {
        {FIRC_XT_ROLE_OTHER, NULL, 0},           {FIRC_XT_ROLE_MARKS, "198.18.0.0", 24},
        {FIRC_XT_ROLE_OTHER, "198.18.0.0", 24}, {FIRC_XT_ROLE_MARKS, "198.18.5.0", 24},
        {FIRC_XT_ROLE_OTHER, "10.30.0.0", 16},  {FIRC_XT_ROLE_MARKS, "198.18.1.0", 24},
        {FIRC_XT_ROLE_OTHER, NULL, 0},           {FIRC_XT_ROLE_OTHER, NULL, 0},
        {FIRC_XT_ROLE_OTHER, NULL, 0},           {FIRC_XT_ROLE_OTHER, NULL, 0},
    };
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV4, v4, w4, 10));
    static const char *const v6[] = {
        "-d fd37:9a00:0:5::/64 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-d 2001:db8:20::/48 -p tcp -m conntrack --ctdir ORIGINAL -m mark ! --mark 0x40000000/0x40000000 -m tcp --dport 443 -j MARK --set-xmark 0x40010000/0x40ff0000",
        "-s fd00:1::/64 -j MARK --set-xmark 0x40020000/0x40ff0000",
    };
    static const want_role_t w6[] = {
        {FIRC_XT_ROLE_MARKS, "fd37:9a00:0:5::", 64},
        {FIRC_XT_ROLE_OTHER, "2001:db8:20::", 48},
        {FIRC_XT_ROLE_OTHER, NULL, 0},
    };
    CHECK_CALL(roles_are(FIRC_IPT_PROTO_IPV6, v6, w6, 3));
    PASS();
}

/* Catches: an inverted destination read as the place a mark or a rewrite applies (it applies everywhere else). */
TEST an_inverted_destination_marks_nothing_and_rewrites_anywhere(void) {
    for (size_t f = 0; f < 2; f++) {
        bool v6 = k_fams[f] == FIRC_IPT_PROTO_IPV6;
        firc_xt_block_t b;
        firc_xt_block_init(&b);
        ASSERT_EQ_FMT(FIRC_OK, add_line(&b, k_fams[f], v6 ? "-d fd37:9a00::/64 -j MARK --set-xmark 0x40010000/0x40ff0000"
                                                           : "-d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000"), "%d");
        size_t second = b.len;
        ASSERT_EQ_FMT(FIRC_OK, add_line(&b, k_fams[f], v6 ? "-d fd37:9a00::7/128 -j DNAT --to-destination 2001:db8::1"
                                                           : "-d 198.18.0.7/32 -j DNAT --to-destination 93.184.216.34"), "%d");
        size_t at = v6 ? offsetof(xt_ip6t_ip6_t, invflags) : offsetof(xt_ipt_ip_t, invflags);
        uint8_t inv = 0x10u;
        b.bytes[at] = inv;
        b.bytes[second + at] = inv;
        seen_t s;
        memset(&s, 0, sizeof(s));
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_roles(&b, k_fams[f], note, &s), "%d");
        ASSERT_EQ_FMT((size_t)2, s.n, "%zu");
        ASSERT_EQ_FMT((int)FIRC_XT_ROLE_OTHER, (int)s.role[0], "%d");
        ASSERT_EQ_FMT((int)FIRC_XT_ROLE_REWRITES, (int)s.role[1], "%d");
        static const uint8_t zero[16] = {0};
        ASSERT(memcmp(zero, s.addr[1], 16) == 0);
        ASSERT(memcmp(zero, s.mask[1], 16) == 0);
        firc_xt_block_free(&b);
    }
    PASS();
}

/* Catches: an inverted interface or source read as an inverted destination, so a rewrite reads as everywhere. */
TEST only_the_destination_flag_inverts_the_destination(void) {
    static const uint8_t others[] = {0x01u, 0x02u, 0x08u};
    for (size_t f = 0; f < 2; f++) {
        bool v6 = k_fams[f] == FIRC_IPT_PROTO_IPV6;
        uint8_t a[16], m[16];
        addr(k_fams[f], v6 ? "fd37:9a00::7" : "198.18.0.7", a);
        prefix_mask(v6 ? 128 : 32, m);
        for (size_t k = 0; k < sizeof(others); k++) {
            firc_xt_block_t b;
            firc_xt_block_init(&b);
            ASSERT_EQ_FMT(FIRC_OK, add_line(&b, k_fams[f], v6 ? "-d fd37:9a00::7/128 -j DNAT --to-destination 2001:db8::1"
                                                               : "-d 198.18.0.7/32 -j DNAT --to-destination 93.184.216.34"), "%d");
            b.bytes[v6 ? offsetof(xt_ip6t_ip6_t, invflags) : offsetof(xt_ipt_ip_t, invflags)] = others[k];
            seen_t s;
            memset(&s, 0, sizeof(s));
            ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_roles(&b, k_fams[f], note, &s), "%d");
            ASSERT_EQ_FMT((int)FIRC_XT_ROLE_REWRITES, (int)s.role[0], "%d");
            ASSERT(memcmp(a, s.addr[0], 16) == 0);
            ASSERT(memcmp(m, s.mask[0], 16) == 0);
            firc_xt_block_free(&b);
        }
    }
    PASS();
}

/* Catches: the typed rewrite firc writes per fake address not read as a rewrite of that address. */
TEST a_typed_dnat_is_a_rewrite_of_its_fake_address(void) {
    const char *fake[2] = {"198.18.3.7", "fd37:9a00::7"};
    const char *real[2] = {"93.184.216.34", "2001:db8::1"};
    for (size_t f = 0; f < 2; f++) {
        uint8_t a[16], r[16], m[16];
        addr(k_fams[f], fake[f], a);
        addr(k_fams[f], real[f], r);
        prefix_mask(f == 0 ? 32 : 128, m);
        firc_xt_block_t b;
        firc_xt_block_init(&b);
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_add_dnat(&b, k_fams[f], a, r), "%d");
        seen_t s;
        memset(&s, 0, sizeof(s));
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_roles(&b, k_fams[f], note, &s), "%d");
        ASSERT_EQ_FMT((size_t)1, s.n, "%zu");
        ASSERT_EQ_FMT((int)FIRC_XT_ROLE_REWRITES, (int)s.role[0], "%d");
        ASSERT(memcmp(a, s.addr[0], 16) == 0);
        ASSERT(memcmp(m, s.mask[0], 16) == 0);
        firc_xt_block_free(&b);
    }
    PASS();
}

/* Catches: roles read from a block of the other family or with a corrupt length (every role then misread), or a call for an empty block. */
TEST roles_of_an_unsound_block_are_refused(void) {
    seen_t s;
    memset(&s, 0, sizeof(s));
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_roles(&b, FIRC_IPT_PROTO_IPV6, note, &s), "%d");
    ASSERT_EQ_FMT((size_t)0, s.n, "%zu");
    ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV4, "-d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV4, "-d 198.18.0.7/32 -j DNAT --to-destination 93.184.216.34"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_roles(&b, FIRC_IPT_PROTO_IPV6, note, &s), "%d");
    ASSERT_EQ_FMT((size_t)0, s.n, "%zu");
    const uint32_t at = firc_xt_at_next(FIRC_IPT_PROTO_IPV4);
    uint16_t len = firc_xt_rd16(b.bytes + at);
    const uint16_t bad[3] = {0, 8, 4096};
    for (size_t k = 0; k < 3; k++) {
        firc_xt_wr16(b.bytes + at, bad[k]);
        ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_roles(&b, FIRC_IPT_PROTO_IPV4, note, &s), "%d");
        ASSERT_EQ_FMT((size_t)0, s.n, "%zu");
    }
    firc_xt_wr16(b.bytes + at, len);
    const uint32_t toff_at = firc_xt_at_toff(FIRC_IPT_PROTO_IPV4);
    uint16_t toff = firc_xt_rd16(b.bytes + toff_at);
    firc_xt_wr16(b.bytes + toff_at, 0);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_roles(&b, FIRC_IPT_PROTO_IPV4, note, &s), "%d");
    ASSERT_EQ_FMT((size_t)0, s.n, "%zu");
    firc_xt_wr16(b.bytes + toff_at, toff);
    b.n = 3;
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_roles(&b, FIRC_IPT_PROTO_IPV4, note, &s), "%d");
    ASSERT_EQ_FMT((size_t)0, s.n, "%zu");
    b.n = 2;
    b.fam = FIRC_IPT_PROTO_IPV6;
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_roles(&b, FIRC_IPT_PROTO_IPV4, note, &s), "%d");
    ASSERT_EQ_FMT((size_t)0, s.n, "%zu");
    b.fam = FIRC_IPT_PROTO_IPV4;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_roles(&b, FIRC_IPT_PROTO_IPV4, note, &s), "%d");
    ASSERT_EQ_FMT((size_t)2, s.n, "%zu");
    firc_xt_block_free(&b);
    firc_xt_block_t six;
    firc_xt_block_init(&six);
    ASSERT_EQ_FMT(FIRC_OK, add_line(&six, FIRC_IPT_PROTO_IPV6, "-d fd37:9a00::/64 -j MARK --set-xmark 0x40010000/0x40ff0000"), "%d");
    memset(&s, 0, sizeof(s));
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_roles(&six, FIRC_IPT_PROTO_IPV4, note, &s), "%d");
    ASSERT_EQ_FMT((size_t)0, s.n, "%zu");
    firc_xt_block_t o;
    firc_xt_block_init(&o);
    const bool keep[] = {true};
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_keep(&six, FIRC_IPT_PROTO_IPV4, keep, &o), "%d");
    firc_xt_block_free(&six);
    firc_xt_block_free(&o);
    PASS();
}

static firc_err_t kept(firc_ipt_proto_t fam, const char *const *lines, const bool *keep, size_t n, firc_xt_block_t *out) {
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    for (size_t i = 0; i < n; i++) {
        if (add_line(&b, fam, lines[i]) != FIRC_OK) { abort(); }
    }
    firc_err_t err = firc_xt_block_keep(&b, fam, keep, out);
    firc_xt_block_free(&b);
    return err;
}

static firc_xt_block_t lines_block(firc_ipt_proto_t fam, const char *const *lines, size_t n) {
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    for (size_t i = 0; i < n; i++) {
        if (add_line(&b, fam, lines[i]) != FIRC_OK) { abort(); }
    }
    return b;
}

/* Catches: a kept copy of a block losing or shifting a jump, so the first part of a two-part nat write jumps to the wrong chain. */
TEST a_kept_copy_carries_its_jumps(void) {
    static const char *const lines[] = {
        "-d 198.18.0.5/32 -j DNAT --to-destination 1.1.1.1",
        "-d 198.18.0.0/24 -j FIRC_x",
        "-d 198.18.1.5/32 -j DNAT --to-destination 1.1.1.2",
        "-d 198.18.1.0/24 -j FIRC_y",
    };
    firc_xt_block_t k;
    firc_xt_block_init(&k);
    const bool keep[] = {false, true, false, true};
    ASSERT_EQ_FMT(FIRC_OK, kept(FIRC_IPT_PROTO_IPV4, lines, keep, 4, &k), "%d");
    static const char *const wl[] = {"-d 198.18.0.0/24 -j FIRC_x", "-d 198.18.1.0/24 -j FIRC_y"};
    firc_xt_block_t want = lines_block(FIRC_IPT_PROTO_IPV4, wl, 2);
    ASSERT(firc_xt_block_equal(&want, &k));
    firc_xt_block_free(&k);
    firc_xt_block_free(&want);
    PASS();
}

/* Catches: a dropped jump still counted, so the next kept jump names the chain of the one dropped before it. */
TEST a_dropped_jump_takes_its_chain_with_it(void) {
    for (size_t f = 0; f < 2; f++) {
        bool v6 = k_fams[f] == FIRC_IPT_PROTO_IPV6;
        const char *const lines[] = {
            v6 ? "-d fd37:9a00::5/128 -j DNAT --to-destination 2001:db8::1" : "-d 198.18.0.5/32 -j DNAT --to-destination 1.1.1.1",
            v6 ? "-d fd37:9a00::/64 -j FIRC_x" : "-d 198.18.0.0/24 -j FIRC_x",
            v6 ? "-d fd37:9a00:0:1::5/128 -j DNAT --to-destination 2001:db8::2" : "-d 198.18.1.5/32 -j DNAT --to-destination 1.1.1.2",
            v6 ? "-d fd37:9a00:0:1::/64 -j FIRC_y" : "-d 198.18.1.0/24 -j FIRC_y",
            "-j FIRC_z",
        };
        firc_xt_block_t k;
        firc_xt_block_init(&k);
        const bool keep[] = {true, false, true, true, false};
        ASSERT_EQ_FMT(FIRC_OK, kept(k_fams[f], lines, keep, 5, &k), "%d");
        const char *const wl[] = {lines[0], lines[2], lines[3]};
        firc_xt_block_t want = lines_block(k_fams[f], wl, 3);
        ASSERT(firc_xt_block_equal(&want, &k));
        ASSERT_EQ_FMT((size_t)1, k.n_jumps, "%zu");
        ASSERT_EQ_FMT((uint32_t)2, k.jumps[0].entry, "%u");
        ASSERT_STR_EQ("FIRC_y", k.jumps[0].chain);
        firc_xt_block_free(&k);
        firc_xt_block_free(&want);
    }
    PASS();
}

/* Catches: a kept copy that cannot be staged (no family, another mac revision) or one appended to a block already holding rules. */
TEST a_kept_copy_stages_like_its_source(void) {
    static const char *const lines[] = {
        "-m mac --mac-source 02:00:00:00:00:0B -j MARK --set-xmark 0x40020000/0x40ff0000",
        "-s fd00:1::/64 -j MARK --set-xmark 0x40020000/0x40ff0000",
    };
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    b.mac_rev = 1;
    for (size_t i = 0; i < 2; i++) { ASSERT_EQ_FMT(FIRC_OK, add_line(&b, FIRC_IPT_PROTO_IPV6, lines[i]), "%d"); }
    firc_xt_block_t k;
    firc_xt_block_init(&k);
    const bool all[] = {true, true};
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_keep(&b, FIRC_IPT_PROTO_IPV6, all, &k), "%d");
    ASSERT(firc_xt_block_equal(&b, &k));
    ASSERT_EQ_FMT((int)FIRC_IPT_PROTO_IPV6, (int)k.fam, "%d");
    ASSERT_EQ_FMT(1, (int)k.first_mac_rev, "%d");
    ASSERT_EQ_FMT(b.exts, k.exts, "%u");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_keep(&b, FIRC_IPT_PROTO_IPV6, all, &k), "%d");
    ASSERT_EQ_FMT((uint32_t)2, k.n, "%u");
    firc_xt_block_t o;
    firc_xt_block_init(&o);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_keep(&b, FIRC_IPT_PROTO_IPV4, all, &o), "%d");
    const bool none[] = {false, false};
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_block_keep(&b, FIRC_IPT_PROTO_IPV6, none, &o), "%d");
    ASSERT_EQ_FMT((uint32_t)0, o.n, "%u");
    ASSERT_EQ_FMT((size_t)0, o.len, "%zu");
    firc_xt_block_free(&b);
    firc_xt_block_free(&k);
    firc_xt_block_free(&o);
    PASS();
}

TEST keeping_part_of_a_block_keeps_its_set_names(void) {
    static const char *const lines[] = {
        "-m set --match-set fircA dst -j RETURN",
        "-m mark --mark 1 -j RETURN",
        "-m set --match-set fircB dst -j FIRC_x",
        "-p tcp --dport 53 -m set --match-set fircC dst -j RETURN",
    };
    for (size_t f = 0; f < 2; f++) {
        uint32_t eh = f == 0 ? 112u : 168u;
        firc_xt_block_t k;
        firc_xt_block_init(&k);
        const bool keep[] = {false, true, true, true};
        ASSERT_EQ_FMT(FIRC_OK, kept(k_fams[f], lines, keep, 4, &k), "%d");
        ASSERT_EQ_FMT((size_t)2, k.n_sets, "%zu");
        ASSERT_EQ_FMT(1u, k.sets[0].entry, "%u");
        ASSERT_EQ_FMT(eh + 32u, k.sets[0].at, "%u");
        ASSERT_STR_EQ("fircB", k.sets[0].name);
        ASSERT_EQ_FMT(2u, k.sets[1].entry, "%u");
        ASSERT_EQ_FMT(eh + 48u + 32u, k.sets[1].at, "%u");
        ASSERT_STR_EQ("fircC", k.sets[1].name);
        firc_xt_block_t want = lines_block(k_fams[f], lines + 1, 3);
        ASSERT(firc_xt_block_equal(&want, &k));
        static const char *const other[] = {
            "-m mark --mark 1 -j RETURN",
            "-m set --match-set fircD dst -j FIRC_x",
            "-p tcp --dport 53 -m set --match-set fircC dst -j RETURN",
        };
        firc_xt_block_t renamed = lines_block(k_fams[f], other, 3);
        ASSERT_FALSE(firc_xt_block_equal(&renamed, &k));
        firc_xt_block_t bare = k;
        bare.n_sets = 0;
        ASSERT_FALSE(firc_xt_block_equal(&bare, &k));
        ASSERT_FALSE(firc_xt_block_equal(&k, &bare));
        firc_xt_block_t first;
        firc_xt_block_init(&first);
        const bool only_first[] = {true, false, false, false};
        ASSERT_EQ_FMT(FIRC_OK, kept(k_fams[f], lines, only_first, 4, &first), "%d");
        ASSERT_EQ_FMT((size_t)1, first.n_sets, "%zu");
        ASSERT_EQ_FMT(0u, first.sets[0].entry, "%u");
        ASSERT_STR_EQ("fircA", first.sets[0].name);
        firc_xt_block_free(&k);
        firc_xt_block_free(&want);
        firc_xt_block_free(&renamed);
        firc_xt_block_free(&first);
    }
    PASS();
}

TEST a_block_with_a_stray_set_is_refused(void) {
    for (size_t f = 0; f < 2; f++) {
        uint32_t eh = f == 0 ? 112u : 168u;
        firc_xt_block_t b = lines_block(k_fams[f], (const char *const[]){"-m set --match-set fircA dst -j RETURN"}, 1);
        const bool keep[] = {true};
        ASSERT_EQ_FMT(FIRC_OK, merge_into_empty(k_fams[f], &b), "%d");
        static const struct { uint32_t entry; uint32_t at_from_eh; } bad[] = {{1, 32}, {0, 8}, {0, 40}};
        for (size_t i = 0; i < 3; i++) {
            b.sets[0].entry = bad[i].entry;
            b.sets[0].at = eh + bad[i].at_from_eh;
            ASSERT_EQ_FMT(FIRC_ERR_INVAL, merge_into_empty(k_fams[f], &b), "%d");
            firc_xt_block_t o;
            firc_xt_block_init(&o);
            ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_block_keep(&b, k_fams[f], keep, &o), "%d");
            firc_xt_block_free(&o);
        }
        firc_xt_block_free(&b);
    }
    PASS();
}

TEST an_unresolved_set_is_not_written_out(void) {
    firc_xt_block_t b = lines_block(FIRC_IPT_PROTO_IPV4, (const char *const[]){"-m set --match-set fircA dst -j RETURN"}, 1);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_block(s, "FIRC_g1", &b);
    firc_xt_info_t ei, ni;
    uint8_t *empty = NULL, *out = NULL;
    int32_t *oi = NULL;
    ASSERT(firc_test_xt_read("empty", FIRC_IPT_PROTO_IPV4, &ei, &empty));
    firc_xt_table_t t;
    const char *why = NULL;
    char w[256];
    uint32_t exts = 0;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &ei, empty, &t, &why), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_merge(&t, &s->stage, &exts, w, sizeof(w)), "%d");
    ASSERT_EQ_FMT((size_t)1, t.n_sets, "%zu");
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_serialise(&t, &out, &ni, &oi, w, sizeof(w)), "%d");
    ASSERT(strstr(w, "fircA") != NULL);
    t.sets[0].index = 0x0102;
    t.sets[0].known = true;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_serialise(&t, &out, &ni, &oi, w, sizeof(w)), "%d");
    uint16_t at_index = 0;
    size_t hits = 0;
    for (uint32_t off = 0; off + 112u + 36u <= ni.size; off += firc_xt_rd16(out + off + 90)) {
        if (strcmp((const char *)out + off + 112 + 2, "set") == 0) {
            memcpy(&at_index, out + off + 112 + 32, 2);
            hits++;
        }
    }
    ASSERT_EQ_FMT((size_t)1, hits, "%zu");
    ASSERT_EQ_FMT(0x0102u, (unsigned)at_index, "%u");
    ASSERT_EQ_FMT(0u, (unsigned)firc_xt_rd16(b.bytes + 112 + 32), "%u");
    free(out);
    free(oi);
    firc_xt_table_clear(&t);
    free(empty);
    firc_test_stage_free(s);
    firc_xt_block_free(&b);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_typed_dnat_entry_is_the_golden_one);
    RUN_TEST(two_thousand_typed_rules_merge_to_the_golden);
    RUN_TEST(a_jump_in_a_block_lands_on_its_chain);
    RUN_TEST(blocks_jumping_elsewhere_are_not_equal);
    RUN_TEST(an_unchanged_chain_keeps_the_entries_it_was_read_with);
    RUN_TEST(a_block_of_the_other_family_is_refused);
    RUN_TEST(a_block_with_a_corrupt_length_is_refused);
    RUN_TEST(an_unknown_family_is_refused);
    RUN_TEST(a_block_carries_its_mac_revision_and_the_table_checks_it);
    RUN_TEST(a_block_keeps_the_mac_revision_of_its_first_rule);
    RUN_TEST(each_entry_says_what_it_does_for_the_order);
    RUN_TEST(v6_entries_say_what_they_do_for_the_order);
    RUN_TEST(a_conditional_mark_covers_nothing);
    RUN_TEST(every_address_rewrite_is_a_rewrite);
    RUN_TEST(the_barrier_is_neither_a_mark_nor_a_rewrite);
    RUN_TEST(a_redirect_is_neither_a_mark_nor_a_rewrite);
    RUN_TEST(the_group_chains_say_their_marks);
    RUN_TEST(an_inverted_destination_marks_nothing_and_rewrites_anywhere);
    RUN_TEST(only_the_destination_flag_inverts_the_destination);
    RUN_TEST(a_typed_dnat_is_a_rewrite_of_its_fake_address);
    RUN_TEST(roles_of_an_unsound_block_are_refused);
    RUN_TEST(a_kept_copy_carries_its_jumps);
    RUN_TEST(a_dropped_jump_takes_its_chain_with_it);
    RUN_TEST(a_kept_copy_stages_like_its_source);
    RUN_TEST(keeping_part_of_a_block_keeps_its_set_names);
    RUN_TEST(a_block_with_a_stray_set_is_refused);
    RUN_TEST(an_unresolved_set_is_not_written_out);
    GREATEST_MAIN_END();
}
