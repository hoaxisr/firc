#include "greatest.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fake_iptables.h"
#include "fake_xtables.h"
#include "firc/cancel.h"
#include "firc/iptables.h"
#include "xt_golden.h"

static firc_err_t add(firc_ipt_t *ipt, const char *table, const char *chain, const char *line) {
    firc_ipt_rule_t *r = firc_test_rule(line);
    firc_err_t err = firc_ipt_append(ipt, table, chain, (const char *const *)r->parts, r->n_parts);
    firc_ipt_rule_free(r);
    return err;
}

static bool has(firc_fake_ipt_t *f, const char *table, const char *line) {
    char *text = firc_fake_ipt_print(f, table);
    char want[512];
    snprintf(want, sizeof(want), "%s\n", line);
    bool found = text != NULL && strstr(text, want) != NULL;
    free(text);
    return found;
}

static void base(firc_ipt_t *ipt) {
    (void)firc_ipt_register_chain_patch(ipt, "filter", "FORWARD");
    (void)firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING");
    (void)firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING");
    (void)firc_ipt_register_chain_patch(ipt, "nat", "POSTROUTING");
    (void)add(ipt, "nat", "PREROUTING", "-d 198.18.0.0/15 -j FIRC_DNAT");
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT");
}

static void group(firc_ipt_t *ipt, unsigned g) {
    char chain[16], jump[24], line[128];
    snprintf(chain, sizeof(chain), "FIRC_g%u", g);
    snprintf(jump, sizeof(jump), "-j FIRC_g%u", g);
    snprintf(line, sizeof(line), "-d 198.18.%u.0/24 -j MARK --set-xmark 0x400%u0000/0x40ff0000", g - 1u, g);
    (void)firc_ipt_register_chain_override(ipt, "mangle", chain);
    (void)add(ipt, "mangle", chain, line);
    (void)add(ipt, "mangle", "PREROUTING", jump);
    const uint8_t fake[4] = {198, 18, (uint8_t)(g - 1u), 5}, real[4] = {93, 184, 216, (uint8_t)(30u + g)};
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", fake, real);
}

static firc_err_t pass(firc_ipt_t *ipt, bool a, bool b) {
    base(ipt);
    if (a) { group(ipt, 1); }
    if (b) { group(ipt, 2); }
    return firc_ipt_commit(ipt);
}

static firc_ipt_t *engine(firc_fake_ipt_t **f) {
    *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    return firc_ipt_new(firc_fake_ipt_as_xt(*f), "FIRC_");
}

static char *order_of(firc_fake_ipt_t *f) { return firc_fake_xt_write_order(firc_fake_ipt_xt(f)); }
static char *visits_of(firc_fake_ipt_t *f) { return firc_fake_xt_read_order(firc_fake_ipt_xt(f)); }

#define A_DNAT "-A FIRC_DNAT -d 198.18.0.5/32 -m mark --mark 0x40000000/0x40000000 -j DNAT --to-destination 93.184.216.31"
#define B_DNAT "-A FIRC_DNAT -d 198.18.1.5/32 -m mark --mark 0x40000000/0x40000000 -j DNAT --to-destination 93.184.216.32"
#define A_MARK "-A FIRC_g1 -d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000"
#define B_MARK "-A FIRC_g2 -d 198.18.1.0/24 -j MARK --set-xmark 0x40020000/0x40ff0000"

/* Catches: the start's clean (nothing rewrites, nothing known) taking marks away before a killed instance's DNAT. */
TEST a_fresh_engine_writes_nat_first_when_it_rewrites_nothing(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, false, false), "%d");
    char *visits = visits_of(f), *order = order_of(f);
    ASSERT_STR_EQ("nat\nfilter\nmangle\n", visits);
    ASSERT_STR_EQ("nat\n", order);
    free(visits);
    free(order);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a fresh engine (nothing known of the kernel) writing a rewrite before its mark, or a mark away before an unknown rewrite. */
TEST a_fresh_engine_with_rewrites_writes_nat_in_two_parts(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    char *visits = visits_of(f), *order = order_of(f);
    ASSERT_STR_EQ("nat\nfilter\nmangle\nnat\n", visits);
    ASSERT_STR_EQ("nat\nmangle\nnat\n", order);
    free(visits);
    free(order);
    ASSERT(has(f, "nat", A_DNAT));
    ASSERT(has(f, "mangle", A_MARK));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a new group's DNAT written before its mark (an unmarked rewrite leaves by the WAN for the time between). */
TEST adding_a_group_writes_marks_before_nat(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    char *before = order_of(f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, true), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("mangle\nnat\n", after + strlen(before));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a refused nat write after new marks leaving a rewrite without its mark (it must leave a mark without a rewrite). */
TEST a_refused_nat_after_new_marks_leaves_marks_without_rewrites(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    firc_fake_xt_fail_table(firc_fake_ipt_xt(f), "nat", EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, pass(ipt, true, true), "%d");
    ASSERT(has(f, "mangle", B_MARK));
    ASSERT_FALSE(has(f, "nat", B_DNAT));
    ASSERT(has(f, "nat", A_DNAT));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a withdrawn group's mark taken away before its DNAT (the rewrite then sends the client out in the clear). */
TEST withdrawing_a_group_writes_nat_before_marks(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, true), "%d");
    char *before = order_of(f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("nat\nmangle\n", after + strlen(before));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a withdraw that writes the marks although the nat write in front of it was refused. */
TEST a_refused_nat_withdraw_leaves_the_old_marks(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, true), "%d");
    char *before = order_of(f);
    firc_fake_xt_fail_table(firc_fake_ipt_xt(f), "nat", EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, pass(ipt, true, false), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("", after + strlen(before));
    ASSERT(has(f, "mangle", B_MARK));
    ASSERT(has(f, "nat", B_DNAT));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a pass that adds one group and withdraws another written in one order (one of the two then rewrites unmarked). */
TEST a_pass_that_adds_and_withdraws_writes_nat_in_two_parts(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    char *before = order_of(f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, false, true), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("nat\nmangle\nnat\n", after + strlen(before));
    ASSERT(has(f, "nat", B_DNAT));
    ASSERT_FALSE(has(f, "nat", A_DNAT));
    ASSERT(has(f, "mangle", B_MARK));
    ASSERT_FALSE(has(f, "mangle", A_MARK));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: the first nat part keeping a rewrite the new marks do not cover, or adding one the old marks do not. */
TEST a_refused_last_nat_part_leaves_every_rewrite_marked(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    firc_fake_ipt_fail_at_commit(f, 3, FIRC_ERR_IO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, pass(ipt, false, true), "%d");
    ASSERT_FALSE(has(f, "nat", A_DNAT));
    ASSERT_FALSE(has(f, "nat", B_DNAT));
    ASSERT(has(f, "mangle", B_MARK));
    ASSERT_FALSE(has(f, "mangle", A_MARK));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a refused first nat part followed by the mangle write anyway. */
TEST a_refused_first_nat_part_writes_nothing_else(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    firc_fake_xt_fail_table(firc_fake_ipt_xt(f), "nat", EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, pass(ipt, false, true), "%d");
    ASSERT(has(f, "mangle", A_MARK));
    ASSERT(has(f, "nat", A_DNAT));
    ASSERT_FALSE(has(f, "mangle", B_MARK));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a mangle-only commit taking away a mark a rewrite still in nat needs (fail-closed resting on the caller staging nat too). */
TEST a_mangle_staging_that_uncovers_a_rewrite_is_refused(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, true), "%d");
    (void)firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING");
    (void)add(ipt, "mangle", "PREROUTING", "-j FIRC_g1");
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g1");
    (void)add(ipt, "mangle", "FIRC_g1", "-d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_commit(ipt), "%d");
    ASSERT(has(f, "mangle", B_MARK));
    ASSERT(has(f, "nat", B_DNAT));
    firc_ipt_free(ipt);
    PASS();
}

static firc_err_t one_rewrite(firc_ipt_t *ipt, const char *mark_dst, const char *dnat) {
    char line[160];
    (void)firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING");
    (void)add(ipt, "mangle", "PREROUTING", "-j FIRC_g1");
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g1");
    snprintf(line, sizeof(line), "-d %s -j MARK --set-xmark 0x40010000/0x40ff0000", mark_dst);
    (void)add(ipt, "mangle", "FIRC_g1", line);
    (void)firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING");
    (void)add(ipt, "nat", "PREROUTING", "-d 198.18.0.0/15 -j FIRC_DNAT");
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT");
    (void)add(ipt, "nat", "FIRC_DNAT", dnat);
    return firc_ipt_commit(ipt);
}

/* Catches: a mark counted as cover for a rewrite wider than it, or for one of anywhere. */
TEST a_rewrite_is_covered_only_by_a_mark_as_wide(void) {
    static const struct {
        const char *mark, *dnat;
        firc_err_t want;
    } k[] = {
        {"198.18.0.0/24", "-d 198.18.0.0/16 -j DNAT --to-destination 93.184.216.34", FIRC_ERR_INVAL},
        {"0.0.0.0/1", "-j DNAT --to-destination 93.184.216.34", FIRC_ERR_INVAL},
        {"198.18.0.0/24", "-d 198.18.0.0/25 -j DNAT --to-destination 93.184.216.34", FIRC_OK},
        {"198.18.0.0/16", "-d 198.18.0.0/24 -j DNAT --to-destination 93.184.216.34", FIRC_OK},
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        firc_fake_ipt_t *f;
        firc_ipt_t *ipt = engine(&f);
        ASSERT_EQ_FMTm(k[i].dnat, k[i].want, one_rewrite(ipt, k[i].mark, k[i].dnat), "%d");
        char *order = order_of(f);
        ASSERT_STR_EQm(k[i].dnat, k[i].want == FIRC_OK ? "nat\nmangle\nnat\n" : "", order);
        free(order);
        firc_ipt_free(ipt);
    }
    PASS();
}

#define RANGE_TCP "-d 198.18.0.0/24 -p tcp -m multiport --dports 80,443 -m mark --mark 0x40000000/0x40000000 " \
                  "-j DNAT --to-destination 104.16.9.9"
#define RANGE_UDP "-d 198.18.0.0/24 -p udp -m udp --dport 443 -m mark --mark 0x40000000/0x40000000 " \
                  "-j DNAT --to-destination 104.16.9.9"

TEST a_range_rewrite_needs_its_chunks_mark_rule(void) {
    static const struct {
        const char *mark, *dnat;
        firc_err_t want;
    } k[] = {
        {"198.18.0.0/24", RANGE_TCP, FIRC_OK},
        {"198.18.0.0/24", RANGE_UDP, FIRC_OK},
        {"198.18.1.0/24", RANGE_TCP, FIRC_ERR_INVAL},
        {"198.18.1.0/24", RANGE_UDP, FIRC_ERR_INVAL},
    };
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        firc_fake_ipt_t *f;
        firc_ipt_t *ipt = engine(&f);
        ASSERT_EQ_FMTm(k[i].dnat, k[i].want, one_rewrite(ipt, k[i].mark, k[i].dnat), "%d");
        firc_ipt_free(ipt);
    }
    PASS();
}

/* Catches: a group chain PREROUTING does not jump to unconditionally counted as the mark a rewrite rests on. */
TEST an_unjumped_group_chain_covers_nothing(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, true), "%d");
    char *before = order_of(f);
    (void)firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING");
    (void)add(ipt, "mangle", "PREROUTING", "-j FIRC_g1");
    (void)add(ipt, "mangle", "PREROUTING", "-i br0 -j FIRC_g2");
    (void)firc_ipt_register_chain_patch(ipt, "mangle", "FORWARD");
    (void)add(ipt, "mangle", "FORWARD", "-j FIRC_g2");
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g1");
    (void)add(ipt, "mangle", "FIRC_g1", "-d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000");
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g2");
    (void)add(ipt, "mangle", "FIRC_g2", "-d 198.18.1.0/24 -j MARK --set-xmark 0x40020000/0x40ff0000");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_commit(ipt), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("", after + strlen(before));
    ASSERT(has(f, "mangle", "-A PREROUTING -j FIRC_g2"));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a nat-only commit adding a rewrite no mark in the kernel covers (fail-closed resting on the caller staging mangle too). */
TEST a_nat_staging_outside_the_marks_is_refused(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    char *before = order_of(f);
    (void)firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING");
    (void)add(ipt, "nat", "PREROUTING", "-d 198.18.0.0/15 -j FIRC_DNAT");
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT");
    const uint8_t a[4] = {198, 18, 0, 5}, ra[4] = {93, 184, 216, 31};
    const uint8_t b[4] = {198, 18, 1, 5}, rb[4] = {93, 184, 216, 32};
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", a, ra);
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", b, rb);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_commit(ipt), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("", after + strlen(before));
    ASSERT_FALSE(has(f, "nat", B_DNAT));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a refused mangle after the first nat part leaving a rewrite without its mark, or the next pass not finishing the move. */
TEST a_refused_mangle_after_the_first_nat_part_leaves_no_rewrite(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    firc_fake_ipt_fail_at_commit(f, 2, FIRC_ERR_IO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, pass(ipt, false, true), "%d");
    ASSERT_FALSE(has(f, "nat", A_DNAT));
    ASSERT_FALSE(has(f, "nat", B_DNAT));
    ASSERT(has(f, "mangle", A_MARK));
    ASSERT_FALSE(has(f, "mangle", B_MARK));
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, false, true), "%d");
    ASSERT(has(f, "nat", B_DNAT));
    ASSERT(has(f, "mangle", B_MARK));
    ASSERT_FALSE(has(f, "mangle", A_MARK));
    firc_ipt_free(ipt);
    PASS();
}

static void raise_it(void *ud) { firc_cancel_raise(ud); }

/* Catches: a cancel after the first nat part going on to write mangle, or the next pass trusting the part as the whole. */
TEST a_cancel_after_the_first_nat_part_stops_and_the_next_pass_finishes(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    firc_cancel_t *cancel = firc_cancel_new();
    firc_ipt_set_cancel(ipt, cancel);
    char *before = order_of(f);
    firc_fake_ipt_on_write(f, raise_it, cancel);
    ASSERT_EQ_FMT(FIRC_ERR_CANCELED, pass(ipt, false, true), "%d");
    firc_fake_ipt_on_write(f, NULL, NULL);
    char *after = order_of(f);
    ASSERT_STR_EQ("nat\n", after + strlen(before));
    ASSERT(has(f, "mangle", A_MARK));
    firc_cancel_clear(cancel);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, false, true), "%d");
    ASSERT(has(f, "nat", B_DNAT));
    ASSERT(has(f, "mangle", B_MARK));
    ASSERT_FALSE(has(f, "mangle", A_MARK));
    firc_ipt_set_cancel(ipt, NULL);
    firc_cancel_free(cancel);
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

static firc_err_t v6_pass(firc_ipt_t *ipt, uint8_t rewrite_chunk) {
    (void)firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING");
    (void)add(ipt, "mangle", "PREROUTING", "-j FIRC_g1");
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g1");
    (void)add(ipt, "mangle", "FIRC_g1", "-d fd37::/64 -j MARK --set-xmark 0x40010000/0x40ff0000");
    (void)firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING");
    (void)add(ipt, "nat", "PREROUTING", "-d fd37::/48 -j FIRC_DNAT");
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT");
    uint8_t fake[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, rewrite_chunk, 0, 0, 0, 0, 0, 0, 0, 5};
    const uint8_t real[16] = {0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x34};
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", fake, real);
    return firc_ipt_commit(ipt);
}

/* Catches: v6 coverage compared on the first 4 bytes only, so a rewrite in another /64 passes as marked. */
TEST v6_rewrites_need_their_own_chunk_marked(void) {
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, v6_pass(ipt, 1), "%d");
    char *order = order_of(f);
    ASSERT_STR_EQ("", order);
    free(order);
    ASSERT_EQ_FMT(FIRC_OK, v6_pass(ipt, 0), "%d");
    ASSERT(has(f, "nat", "-A FIRC_DNAT -d fd37::5/128 -m mark --mark 0x40000000/0x40000000 -j DNAT --to-destination 2606:2800:220:1::34"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a selector group's jump into its devices chain not counted as the mark its rewrites rest on. */
TEST a_selector_jump_covers_its_chunk(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    (void)firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING");
    (void)add(ipt, "mangle", "PREROUTING", "-j FIRC_g1");
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g1");
    (void)add(ipt, "mangle", "FIRC_g1", "-d 198.18.0.0/24 -j FIRC_g1D");
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g1D");
    (void)add(ipt, "mangle", "FIRC_g1D", "-s 192.168.1.10/32 -j MARK --set-xmark 0x40010000/0x40ff0000");
    (void)firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING");
    (void)add(ipt, "nat", "PREROUTING", "-d 198.18.0.0/15 -j FIRC_DNAT");
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT");
    const uint8_t fake[4] = {198, 18, 0, 5}, real[4] = {93, 184, 216, 31};
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", fake, real);
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT(has(f, "nat", A_DNAT));
    ASSERT(has(f, "mangle", "-A FIRC_g1 -d 198.18.0.0/24 -j FIRC_g1D"));
    firc_ipt_free(ipt);
    PASS();
}

#define A2_DNAT "-A FIRC_DNAT -d 198.18.0.6/32 -m mark --mark 0x40000000/0x40000000 -j DNAT --to-destination 93.184.216.40"
#define BARRIER "-A FIRC_POOLREJECT -j DROP"

static firc_err_t pass_more(firc_ipt_t *ipt) {
    base(ipt);
    group(ipt, 1);
    const uint8_t fake[4] = {198, 18, 0, 6}, real[4] = {93, 184, 216, 40};
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", fake, real);
    return firc_ipt_commit(ipt);
}

static firc_err_t pass_barrier(firc_ipt_t *ipt) {
    base(ipt);
    group(ipt, 1);
    (void)add(ipt, "filter", "FORWARD", "-d 198.18.0.0/15 -j FIRC_POOLREJECT");
    (void)firc_ipt_register_chain_override(ipt, "filter", "FIRC_POOLREJECT");
    (void)add(ipt, "filter", "FIRC_POOLREJECT", "-j DROP");
    return firc_ipt_commit(ipt);
}

typedef struct snap {
    firc_xt_info_t info;
    uint8_t *blob;
} snap_t;

static bool take(firc_fake_ipt_t *f, const char *table, snap_t *s) {
    return firc_fake_xt_blob(firc_fake_ipt_xt(f), table, &s->info, &s->blob);
}

static bool firmware_rewrites(firc_fake_ipt_t *f, const char *table, snap_t *s) {
    bool ok = firc_fake_xt_load(firc_fake_ipt_xt(f), table, &s->info, s->blob);
    free(s->blob);
    s->blob = NULL;
    return ok;
}

/* Catches: a pass trusting its memory of mangle after the firmware rewrote it unheard, so a new DNAT goes in without its mark. */
TEST a_mangle_rewritten_unheard_is_written_again_before_a_new_rewrite(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    snap_t s;
    ASSERT(take(f, "mangle", &s));
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    ASSERT(firmware_rewrites(f, "mangle", &s));
    ASSERT_FALSE(has(f, "mangle", A_MARK));
    char *before = order_of(f);
    ASSERT_EQ_FMT(FIRC_OK, pass_more(ipt), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("mangle\nnat\n", after + strlen(before));
    ASSERT(has(f, "mangle", A_MARK));
    ASSERT(has(f, "nat", A2_DNAT));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: the coverage check counting marks the firmware took away unheard, so a nat-only commit writes an unmarked rewrite. */
TEST a_nat_staging_over_marks_gone_unheard_is_refused(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    snap_t s;
    ASSERT(take(f, "mangle", &s));
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    ASSERT(firmware_rewrites(f, "mangle", &s));
    char *before = order_of(f);
    (void)firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING");
    (void)add(ipt, "nat", "PREROUTING", "-d 198.18.0.0/15 -j FIRC_DNAT");
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT");
    const uint8_t a[4] = {198, 18, 0, 5}, ra[4] = {93, 184, 216, 31};
    const uint8_t b[4] = {198, 18, 0, 6}, rb[4] = {93, 184, 216, 40};
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", a, ra);
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", b, rb);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_commit(ipt), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("", after + strlen(before));
    ASSERT_FALSE(has(f, "nat", A2_DNAT));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: an unchanged staging skipped although the table it matches was rewritten unheard (the barrier, a group's marks, its DNAT stay gone). */
TEST a_table_rewritten_unheard_is_written_again(void) {
    static const char *const tables[] = {"filter", "mangle", "nat"};
    static const char *const lines[] = {BARRIER, A_MARK, A_DNAT};
    for (size_t i = 0; i < 3; i++) {
        firc_fake_ipt_t *f;
        firc_ipt_t *ipt = engine(&f);
        snap_t s;
        ASSERT(take(f, tables[i], &s));
        ASSERT_EQ_FMTm(tables[i], FIRC_OK, pass_barrier(ipt), "%d");
        ASSERT(firmware_rewrites(f, tables[i], &s));
        ASSERT_FALSEm(tables[i], has(f, tables[i], lines[i]));
        char *before = order_of(f);
        ASSERT_EQ_FMTm(tables[i], FIRC_OK, pass_barrier(ipt), "%d");
        char *after = order_of(f);
        char want[16];
        snprintf(want, sizeof(want), "%s\n", tables[i]);
        ASSERT_STR_EQm(tables[i], want, after + strlen(before));
        ASSERTm(tables[i], has(f, tables[i], lines[i]));
        free(before);
        free(after);
        firc_ipt_free(ipt);
    }
    PASS();
}

/* Catches: a table read again on every pass although nothing touched it since firc wrote it or found it as staged. */
TEST an_untouched_table_stays_skipped(void) {
    for (int k = 0; k < 2; k++) {
        firc_fake_ipt_t *f;
        firc_ipt_t *ipt = engine(&f);
        ASSERT_EQ_FMT(FIRC_OK, k ? pass(ipt, true, false) : pass_barrier(ipt), "%d");
        char *before = visits_of(f);
        ASSERT_EQ_FMT(FIRC_OK, k ? pass(ipt, true, false) : pass_barrier(ipt), "%d");
        char *after = visits_of(f);
        ASSERT_STR_EQ("", after + strlen(before));
        free(before);
        free(after);
        firc_ipt_free(ipt);
    }
    PASS();
}

/* Catches: a nat rewritten unheard taken as holding no rewrite, so a withdrawn mark goes before the nat that may still need it. */
TEST a_nat_rewritten_unheard_is_written_before_a_withdraw(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, false), "%d");
    snap_t s;
    ASSERT(take(f, "nat", &s));
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, true, true), "%d");
    ASSERT(firmware_rewrites(f, "nat", &s));
    char *before = order_of(f);
    ASSERT_EQ_FMT(FIRC_OK, pass(ipt, false, true), "%d");
    char *after = order_of(f);
    ASSERT_STR_EQ("nat\nmangle\n", after + strlen(before));
    ASSERT_FALSE(has(f, "nat", A_DNAT));
    ASSERT_FALSE(has(f, "mangle", A_MARK));
    free(before);
    free(after);
    firc_ipt_free(ipt);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_mangle_staging_that_uncovers_a_rewrite_is_refused);
    RUN_TEST(a_fresh_engine_writes_nat_first_when_it_rewrites_nothing);
    RUN_TEST(a_fresh_engine_with_rewrites_writes_nat_in_two_parts);
    RUN_TEST(adding_a_group_writes_marks_before_nat);
    RUN_TEST(a_refused_nat_after_new_marks_leaves_marks_without_rewrites);
    RUN_TEST(withdrawing_a_group_writes_nat_before_marks);
    RUN_TEST(a_refused_nat_withdraw_leaves_the_old_marks);
    RUN_TEST(a_pass_that_adds_and_withdraws_writes_nat_in_two_parts);
    RUN_TEST(a_refused_last_nat_part_leaves_every_rewrite_marked);
    RUN_TEST(a_refused_first_nat_part_writes_nothing_else);
    RUN_TEST(a_rewrite_is_covered_only_by_a_mark_as_wide);
    RUN_TEST(a_range_rewrite_needs_its_chunks_mark_rule);
    RUN_TEST(an_unjumped_group_chain_covers_nothing);
    RUN_TEST(a_nat_staging_outside_the_marks_is_refused);
    RUN_TEST(a_refused_mangle_after_the_first_nat_part_leaves_no_rewrite);
    RUN_TEST(a_cancel_after_the_first_nat_part_stops_and_the_next_pass_finishes);
    RUN_TEST(v6_rewrites_need_their_own_chunk_marked);
    RUN_TEST(a_selector_jump_covers_its_chunk);
    RUN_TEST(a_mangle_rewritten_unheard_is_written_again_before_a_new_rewrite);
    RUN_TEST(a_nat_staging_over_marks_gone_unheard_is_refused);
    RUN_TEST(a_table_rewritten_unheard_is_written_again);
    RUN_TEST(an_untouched_table_stays_skipped);
    RUN_TEST(a_nat_rewritten_unheard_is_written_before_a_withdraw);
    GREATEST_MAIN_END();
}
