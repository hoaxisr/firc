#include "greatest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fake_xtables.h"
#include "firc/cancel.h"
#include "firc/log.h"
#include "firc/logrep.h"
#include "firc/xtables.h"
#include "xt_golden.h"
#include "../../src/xtables/xt_internal.h"

static FILE *g_log;

static void log_start(firc_log_level_t level) {
    g_log = tmpfile();
    firc_log_set_fd(fileno(g_log));
    firc_log_set_output_floor(level);
}

static char *log_stop(void) {
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_output_floor(FIRC_LOG_INFO);
    long n = ftell(g_log);
    char *text = calloc(1, (size_t)(n > 0 ? n : 0) + 1);
    rewind(g_log);
    if (n > 0 && fread(text, 1, (size_t)n, g_log) != (size_t)n) { text[0] = '\0'; }
    fclose(g_log);
    return text;
}

static size_t count(const char *hay, const char *needle) {
    size_t n = 0;
    for (const char *p = strstr(hay, needle); p != NULL; p = strstr(p + 1, needle)) { n++; }
    return n;
}

static firc_fake_xt_t *fake_with(const char *golden, firc_ipt_proto_t fam) {
    firc_fake_xt_t *f = firc_fake_xt_new(fam);
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    if (!firc_test_xt_read(golden, fam, &info, &blob) || !firc_fake_xt_load(f, "nat", &info, blob)) { abort(); }
    free(blob);
    return f;
}

static bool nat_is(firc_fake_xt_t *f, const char *golden, firc_ipt_proto_t fam) {
    firc_xt_info_t gi, ni;
    uint8_t *g = NULL, *n = NULL;
    bool same = firc_test_xt_read(golden, fam, &gi, &g) && firc_fake_xt_blob(f, "nat", &ni, &n) &&
                firc_test_xt_same(fam, &gi, g, &ni, n);
    free(g);
    free(n);
    return same;
}

static firc_err_t commit_fixture(firc_fake_xt_t *f, firc_ipt_proto_t fam, const char *fixture, firc_cancel_t *cancel) {
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, fixture, fam);
    firc_err_t err = firc_xt_commit(xt, "nat", &s->stage, cancel);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    return err;
}

static const firc_ipt_proto_t k_fams[] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

/* Catches: the commit writing something other than what iptables-restore wrote, or not writing at all. */
TEST a_staging_is_written_as_iptables_restore_wrote_it(void) {
    for (size_t i = 0; i < 2; i++) {
        firc_fake_xt_t *f = fake_with("firmware", k_fams[i]);
        ASSERT_EQ_FMT(FIRC_OK, commit_fixture(f, k_fams[i], "firmware-firc", NULL), "%d");
        ASSERT(nat_is(f, "firmware-firc", k_fams[i]));
        ASSERT_EQ_FMT((size_t)1, firc_fake_xt_replaces(f), "%zu");
        firc_fake_xt_free(f);
    }
    PASS();
}

/* Catches: an unchanged table written again, which resets counters and costs a replace every pass. */
TEST an_unchanged_table_is_read_but_not_written(void) {
    firc_fake_xt_t *f = fake_with("firmware-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_OK, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
    ASSERT_EQ_FMT((size_t)1, firc_fake_xt_reads(f), "%zu");
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: counters of carried entries lost in a replace, or a rewritten rule keeping the old rule's counters. */
TEST counters_of_carried_entries_survive_a_write(void) {
    firc_fake_xt_t *f = fake_with("firmware-firc", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_set_counters(f, "nat", 100);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    firc_ipt_rule_free(s->rules[2]);
    s->rules[2] = firc_test_rule("-d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.35");
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    firc_xt_counter_t c;
    ASSERT(firc_fake_xt_counter(f, "nat", 12, &c));
    ASSERT_EQ(112u, (unsigned)c.pcnt);
    ASSERT_EQ(224u, (unsigned)c.bcnt);
    ASSERT(firc_fake_xt_counter(f, "nat", 15, &c));
    ASSERT_EQ(0u, (unsigned)c.pcnt);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a stale num_counters answered as a refusal (backoff, not-written) instead of a lost race. */
TEST a_count_race_is_again_and_the_retry_writes(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_race_next(f, FIRC_FAKE_XT_RACE_MORE_ENTRIES);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_AGAIN, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)0, count(text, "x_tables"), "%zu");
    free(text);
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
    ASSERT_EQ_FMT(FIRC_OK, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    ASSERT(nat_is(f, "firmware-firc", FIRC_IPT_PROTO_IPV4));
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a firmware rewrite that kept the count crashing the write; it is reverted, as with iptables-restore. */
TEST a_same_count_race_is_reverted(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_race_next(f, FIRC_FAKE_XT_RACE_SAME_COUNT);
    ASSERT_EQ_FMT(FIRC_OK, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    ASSERT(nat_is(f, "firmware-firc", FIRC_IPT_PROTO_IPV4));
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the second GET_INFO missing, so a table whose size moved under the merge is overwritten. */
TEST a_table_that_moved_since_the_read_is_not_written(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_race_next(f, FIRC_FAKE_XT_RACE_SIZE_AT_SECOND_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_AGAIN, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a write that goes ahead while another xtables writer holds the lock, or one that never retries. */
TEST a_held_lock_is_again_without_a_write(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_hold_lock(f, true);
    ASSERT_EQ_FMT(FIRC_ERR_AGAIN, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
    firc_fake_xt_hold_lock(f, false);
    ASSERT_EQ_FMT(FIRC_OK, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the xtables lock held across the read and the merge, so a plain iptables call (zapret's, no -w) fails for the whole pass. */
TEST the_lock_covers_only_the_write(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_OK, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    ASSERT_EQ_FMT((size_t)1, firc_fake_xt_replaces(f), "%zu");
    ASSERT_EQ_FMTm("no read while the lock is held", (size_t)0, firc_fake_xt_reads_under_lock(f), "%zu");
    ASSERT_EQ_FMTm("no write without it", (size_t)0, firc_fake_xt_writes_outside_lock(f), "%zu");
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a refusal said every pass (a WARN flood), never said, or not said again after a recovery. */
TEST a_refusal_is_io_and_said_once_per_run(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    log_start(FIRC_LOG_INFO);
    for (int i = 0; i < 3; i++) {
        firc_fake_xt_fail_next_replace(f, EINVAL);
        ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    }
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    firc_test_stage_t *again = firc_test_stage_new();
    firc_test_stage_fixture(again, "firmware-firc-remove", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_fail_next_replace(f, EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &again->stage, NULL), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables refused ipv4 nat (EINVAL), 34 entries, 6 KB"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)2, count(text, "x_tables refused ipv4 nat (EINVAL)"), "%zu");
    free(text);
    firc_test_stage_free(again);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

static uint64_t g_clock_ms;
static uint64_t clock_ms(void) { return g_clock_ms; }

/* Catches: a refusal that lasts never said again at WARN, or its end not said when the table is written. */
TEST a_lasting_refusal_is_said_again_and_its_end_too(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    g_clock_ms = 1000;
    firc_logrep_set_clock_for_test(clock_ms);
    log_start(FIRC_LOG_INFO);
    for (int i = 0; i < 3; i++) {
        firc_fake_xt_fail_next_replace(f, EINVAL);
        ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
        g_clock_ms += FIRC_LOGREP_REMIND_MS / 2;
    }
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    char *text = log_stop();
    firc_logrep_set_clock_for_test(NULL);
    ASSERT_EQ_FMTm(text, (size_t)2, count(text, " WRN x_tables refused ipv4 nat (EINVAL)"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1,
                   count(text, "(still failing, 3 times for 10 min)"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1,
                   count(text, " INF x_tables ipv4 nat: recovered after 3 failures over 15 min"), "%zu");
    free(text);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a family without a nat table (no ip6table_nat) logged at every pass instead of once. */
TEST a_missing_table_is_said_once(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV6);
    firc_fake_xt_drop_table(f, "nat");
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV6);
    log_start(FIRC_LOG_INFO);
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    }
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables cannot read ipv6 nat (ENOENT)"), "%zu");
    free(text);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a missing extension written anyway (EINVAL every pass), not named, or failing tables that do not need it. */
TEST a_missing_revision_is_named_and_fails_only_its_rules(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_lack(f, true, "DNAT", 0);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_NOSYS, firc_xt_probe(xt), "%d");
    ASSERT_EQ_FMT((size_t)14, firc_fake_xt_revision_asks(f), "%zu");
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    ASSERT_EQ_FMT(0, firc_xt_refusal(xt), "%d");
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
    firc_test_stage_t *sweep = firc_test_stage_new();
    firc_test_stage_fixture(sweep, "sweep", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_commit(xt, "nat", &sweep->stage, NULL), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1,
                   count(text, "x_tables: no ipv4 target DNAT revision 0 (ENOENT): DNAT rules cannot be written"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)0, count(text, "no ipv4 target MASQUERADE"), "%zu");
    free(text);
    firc_test_stage_free(sweep);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

static void note_table(void *ud, const char *table) {
    strcat(ud, table);
    strcat(ud, ",");
}

static void raise_it(void *ud, const char *table) {
    (void)table;
    firc_cancel_raise(ud);
}

static enum greatest_test_res has_after_lacking(bool target, const char *name, uint8_t rev) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_lack(f, target, name, rev);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_NOSYS, firc_xt_probe(xt), "%d");
    free(log_stop());
    ASSERT_FALSE(firc_xt_has(xt, name));
    static const char *const others[] = {"REDIRECT", "addrtype", "DNAT", "mark", "MARK"};
    for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
        if (strcmp(others[i], name) != 0) { ASSERTm(others[i], firc_xt_has(xt, others[i])); }
    }
    ASSERT_FALSE(firc_xt_has(xt, "SNAT"));
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: firc_xt_has answering true for a REDIRECT the probe found missing, or false for what it found. */
TEST a_missing_redirect_is_reported_by_has(void) {
    CHECK_CALL(has_after_lacking(true, "REDIRECT", 0));
    PASS();
}

/* Catches: firc_xt_has answering true for an addrtype the probe found missing, or asking another revision of it. */
TEST a_missing_addrtype_is_reported_by_has(void) {
    CHECK_CALL(has_after_lacking(false, "addrtype", 1));
    PASS();
}

/* Catches: a name matched without its case, so the MARK target answers for the mark match or the other way round. */
TEST has_tells_a_target_from_its_match_by_case(void) {
    CHECK_CALL(has_after_lacking(true, "MARK", 2));
    CHECK_CALL(has_after_lacking(false, "mark", 1));
    PASS();
}

/* Catches: firc_xt_has answering yes on a v6 handle for REDIRECT or addrtype, which the encoder refuses in v6. */
TEST has_says_no_for_what_v6_never_writes(void) {
    for (size_t i = 0; i < 2; i++) {
        firc_fake_xt_t *f = firc_fake_xt_new(k_fams[i]);
        firc_xt_t *xt = firc_fake_xt_handle(f);
        ASSERT_EQ_FMT(FIRC_OK, firc_xt_probe(xt), "%d");
        ASSERT_EQ(i == 0, firc_xt_has(xt, "REDIRECT"));
        ASSERT_EQ(i == 0, firc_xt_has(xt, "addrtype"));
        ASSERT(firc_xt_has(xt, "DNAT"));
        ASSERT(firc_xt_has(xt, "mark"));
        firc_xt_free(xt);
        firc_fake_xt_free(f);
    }
    PASS();
}

/* Catches: a raised cancel ignored, so an aborted pass still replaces the table. */
TEST a_cancel_stops_the_write(void) {
    firc_cancel_t *cancel = firc_cancel_new();
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_cancel_raise(cancel);
    ASSERT_EQ_FMT(FIRC_ERR_CANCELED, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", cancel), "%d");
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_reads(f), "%zu");
    firc_cancel_clear(cancel);
    firc_fake_xt_on_read(f, raise_it, cancel);
    ASSERT_EQ_FMT(FIRC_ERR_CANCELED, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", cancel), "%d");
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
    firc_fake_xt_free(f);
    firc_cancel_free(cancel);
    PASS();
}

/* Catches: a rule outside the vocabulary reaching the kernel, or refused without its words. */
TEST a_refused_rule_writes_nothing_and_is_quoted(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    const char *bad[] = {"-o nwg+ -j MASQUERADE"};
    firc_test_stage_override(s, "FIRC_g1", bad, 1);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    char *text = log_stop();
    ASSERT(strstr(text, "x_tables ipv4 nat: the rule \"-o nwg+ -j MASQUERADE\" is outside what firc writes") != NULL);
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
    free(text);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a jump to a chain the table lacks reaching the kernel, or refused without saying which. */
TEST a_jump_to_a_missing_chain_is_io_and_named(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    const char *bad[] = {"-j FIRC_gone"};
    firc_test_stage_override(s, "FIRC_g1", bad, 1);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1,
                   count(text, "x_tables ipv4 nat: a rule in FIRC_g1 jumps to FIRC_gone, which the table does not have"),
                   "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
    free(text);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a failed counter carry failing the pass, though the rules are in. */
TEST failed_counters_still_complete_the_write(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_fail_next_counters(f, EINVAL);
    ASSERT_EQ_FMT(FIRC_OK, commit_fixture(f, FIRC_IPT_PROTO_IPV4, "firmware-firc", NULL), "%d");
    ASSERT(nat_is(f, "firmware-firc", FIRC_IPT_PROTO_IPV4));
    firc_fake_xt_free(f);
    PASS();
}

typedef struct unlock_seen {
    const char *path;
    int calls;
    bool dumped_before;
} unlock_seen_t;

static void at_unlock(void *ud) {
    unlock_seen_t *u = ud;
    struct stat st;
    u->calls++;
    u->dumped_before = u->dumped_before || stat(u->path, &st) == 0;
}

/* Catches: the refused blob written while the xtables lock is held, stretching the window other writers wait on. */
TEST a_refused_blob_is_dumped_after_the_lock_is_released(void) {
    char dir[] = "/tmp/firc-xt-XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/refused-ipv4-nat.bin", dir);
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    unlock_seen_t seen = {path, 0, false};
    firc_fake_xt_on_unlock(f, at_unlock, &seen);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_set_dump_dir(xt, dir), "%d");
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    log_start(FIRC_LOG_DEBUG);
    firc_fake_xt_fail_next_replace(f, EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    free(log_stop());
    struct stat st;
    ASSERT_EQ_FMT(1, seen.calls, "%d");
    ASSERT_FALSE(seen.dumped_before);
    ASSERT_EQ(0, stat(path, &st));
    unlink(path);
    rmdir(dir);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the debug line losing the parse/merge/serialise/compare split the pass bench and the router bench read. */
TEST the_debug_line_splits_the_merge(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    log_start(FIRC_LOG_DEBUG);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables ipv4 nat: read "), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables ipv4 nat: unchanged, read "), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)2, count(text, " us, parse "), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)2, count(text, " us, serialise "), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)2, count(text, " us, compare "), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, " us, write "), "%zu");
    free(text);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

static size_t pass_set_size(void) {
    size_t n = 0;
    for (size_t i = 0; i < firc_xt_n_exts; i++) { n += firc_xt_exts[i].capture ? 0u : 1u; }
    return n;
}

/* Catches: a probe that cannot ask (no CAP_NET_ADMIN, no socket) read as missing extensions, or said more than once each. */
TEST a_probe_that_cannot_ask_names_every_extension(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_fail_revisions(f, EPERM);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_probe(xt), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMT(pass_set_size(), firc_fake_xt_revision_asks(f), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables: cannot probe ipv4 target DNAT revision 0 (EPERM)"), "%zu");
    ASSERT_EQ_FMTm(text, pass_set_size(), count(text, "x_tables: cannot probe ipv4 "), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)0, count(text, "x_tables: no "), "%zu");
    free(text);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a probe that stops at the first errno it does not know, leaving the rest of the list unasked and unsaid. */
TEST the_probe_asks_every_extension_after_an_unknown_errno(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_fail_revision(f, "mark", EPERM);
    firc_fake_xt_lack(f, true, "CONNMARK", 1);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_probe(xt), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMT(pass_set_size(), firc_fake_xt_revision_asks(f), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables: cannot probe ipv4 match mark revision 1 (EPERM)"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables: no ipv4 target CONNMARK revision 1 (ENOENT): CONNMARK rules cannot be written"), "%zu");
    free(text);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    ASSERT_EQ_FMT(0, firc_xt_refusal(xt), "%d");
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the capture's extensions asked at start (where their modules may not be loaded yet) or never asked at all. */
TEST the_capture_set_is_asked_only_by_the_capture_probe(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV6);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_probe(xt), "%d");
    ASSERT_EQ_FMT(pass_set_size(), firc_fake_xt_revision_asks(f), "%zu");
    firc_fake_xt_lack(f, false, "string", 1);
    ASSERT_EQ_FMT(FIRC_ERR_NOSYS, firc_xt_probe_capture(xt), "%d");
    ASSERT_EQ_FMT(firc_xt_n_exts, firc_fake_xt_revision_asks(f), "%zu");
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: EPROTONOSUPPORT (the kernel's answer for a known name at an unknown revision) taken as a probe failure. */
TEST a_revision_the_kernel_does_not_support_is_missing(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV6);
    firc_fake_xt_fail_revisions(f, EPROTONOSUPPORT);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_NOSYS, firc_xt_probe(xt), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1,
                   count(text, "x_tables: no ipv6 target DNAT revision 1 (EPROTONOSUPPORT): DNAT rules cannot be written"),
                   "%zu");
    ASSERT_EQ_FMTm(text, (size_t)14, count(text, "x_tables: no ipv6 "), "%zu");
    free(text);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the refused blob written without a dump dir (run dir litter) or never written with one. */
TEST a_refused_blob_is_kept_only_with_a_dump_dir(void) {
    char dir[] = "/tmp/firc-xt-XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/refused-ipv4-nat.bin", dir);
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    log_start(FIRC_LOG_INFO);
    firc_fake_xt_fail_next_replace(f, EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    struct stat st;
    ASSERT(stat(path, &st) != 0);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_set_dump_dir(xt, dir), "%d");
    firc_fake_xt_fail_next_replace(f, EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    free(log_stop());
    ASSERT_EQ(0, stat(path, &st));
    ASSERT_EQ_FMT((long)(96 + 5712), (long)st.st_size, "%ld");
    unlink(path);
    rmdir(dir);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the dump tied to an output floor again, so a router run by the init script (floor error) keeps none. */
TEST a_refused_blob_is_kept_at_the_init_scripts_floor(void) {
    char dir[] = "/tmp/firc-xt-XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/refused-ipv4-nat.bin", dir);
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_set_dump_dir(xt, dir), "%d");
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    log_start(FIRC_LOG_ERROR);
    firc_fake_xt_fail_next_replace(f, EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    free(log_stop());
    struct stat st;
    ASSERT_EQ(0, stat(path, &st));
    unlink(path);
    rmdir(dir);
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a fake that accepts what a kernel refuses, so a broken serialiser would pass every other test. */
TEST the_fake_refuses_what_the_kernel_refuses(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    const firc_xt_kernel_ops_t *ops = firc_fake_xt_ops();
    firc_xt_info_t now, info;
    uint8_t *cur = NULL, *blob = NULL;
    ASSERT(firc_fake_xt_blob(f, "nat", &now, &cur));
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &info, &blob));
    firc_xt_counter_t *old = calloc(now.num_entries, sizeof(*old));
    static const struct { const char *what; uint32_t at; uint32_t value; int width; } spoil[] = {
        {"next_offset 0", 90, 0, 2},
        {"a hook entry inside an entry", 0, 0, 0},
        {"an underflow that is not ACCEPT or DROP", 1, 0, 0},
        {"a jump into an entry", 112 + 32, 8, 4},
        {"a standard target that is not 40 bytes", 112, 32, 2},
        {"hooks other than the table's", 2, 0, 0},
    };
    for (size_t i = 0; i < sizeof(spoil) / sizeof(spoil[0]); i++) {
        firc_xt_info_t bad = info;
        uint8_t *b = malloc(info.size);
        memcpy(b, blob, info.size);
        if (spoil[i].width == 2) {
            uint16_t v = (uint16_t)spoil[i].value;
            memcpy(b + spoil[i].at, &v, 2);
        } else if (spoil[i].width == 4) {
            uint32_t v;
            memcpy(&v, b + spoil[i].at, 4);
            v += spoil[i].value;
            memcpy(b + spoil[i].at, &v, 4);
        } else if (spoil[i].at == 0) {
            bad.hook_entry[4] += 8;
        } else if (spoil[i].at == 2) {
            bad.valid_hooks &= ~(1u << 1);
        } else {
            int32_t accept_to_return = -5;
            memcpy(b + bad.underflow[0] + 112 + 32, &accept_to_return, 4);
        }
        ASSERT_EQ_FMTm(spoil[i].what, EINVAL, ops->replace(f, FIRC_IPT_PROTO_IPV4, "nat", &bad, b, now.num_entries, old), "%d");
        free(b);
    }
    ASSERT_EQ_FMT(EAGAIN, ops->replace(f, FIRC_IPT_PROTO_IPV4, "nat", &info, blob, now.num_entries + 1, old), "%d");
    ASSERT_EQ_FMT(0, ops->replace(f, FIRC_IPT_PROTO_IPV4, "nat", &info, blob, now.num_entries, old), "%d");
    free(old);
    free(cur);
    free(blob);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the mac match written at a revision the probe did not confirm (Keenetic's kernel and iptables use 1, mainline has only 0), or written when neither is there. */
TEST the_mac_match_takes_the_revision_the_probe_confirmed(void) {
    for (size_t lack = 0; lack < 3; lack++) {
        for (size_t i = 0; i < 2; i++) {
            firc_fake_xt_t *f = firc_fake_xt_new(k_fams[i]);
            firc_xt_info_t bi, wi, ni;
            uint8_t *base = NULL, *want = NULL, *got = NULL;
            ASSERT(firc_test_xt_read("m-firmware", k_fams[i], &bi, &base));
            ASSERT(firc_fake_xt_load(f, "mangle", &bi, base));
            if (lack > 0) { firc_fake_xt_lack(f, false, "mac", 1); }
            if (lack > 1) { firc_fake_xt_lack(f, false, "mac", 0); }
            firc_xt_t *xt = firc_fake_xt_handle(f);
            ASSERT_EQ_FMT(lack > 1 ? FIRC_ERR_NOSYS : FIRC_OK, firc_xt_probe(xt), "%d");
            ASSERT_EQ_FMT(lack == 0 ? 1u : 0u, firc_xt_mac_rev(xt), "%u");
            firc_test_stage_t *s = firc_test_stage_new();
            firc_test_stage_rules_file(s, "m-firc", k_fams[i]);
            ASSERT_EQ_FMT(lack > 1 ? FIRC_ERR_IO : FIRC_OK, firc_xt_commit(xt, "mangle", &s->stage, NULL), "%d");
            ASSERT(firc_test_xt_read_as(lack > 1 ? "m-firmware" : "m-firc", k_fams[i], lack ? NULL : "kn", &wi, &want));
            ASSERT(firc_fake_xt_blob(f, "mangle", &ni, &got));
            ASSERT(firc_test_xt_same(k_fams[i], &wi, want, &ni, got));
            free(base);
            free(want);
            free(got);
            firc_test_stage_free(s);
            firc_xt_free(xt);
            firc_fake_xt_free(f);
        }
    }
    PASS();
}

/* Catches: a probe cut short by an unaskable revision leaving that extension and the ones after it writable, unconfirmed (mac then at revision 0). */
TEST an_unaskable_revision_refuses_what_was_not_confirmed(void) {
    static const char *const fails[] = {"mac", "conntrack"};
    for (size_t k = 0; k < 2; k++) {
        firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
        firc_xt_info_t bi;
        uint8_t *base = NULL;
        ASSERT(firc_test_xt_read("m-firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
        ASSERT(firc_fake_xt_load(f, "mangle", &bi, base));
        free(base);
        firc_fake_xt_fail_revision(f, fails[k], EIO);
        firc_xt_t *xt = firc_fake_xt_handle(f);
        log_start(FIRC_LOG_INFO);
        ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_probe(xt), "%d");
        firc_test_stage_t *s = firc_test_stage_new();
        firc_test_stage_rules_file(s, "m-firc", FIRC_IPT_PROTO_IPV4);
        ASSERT_EQ_FMTm(fails[k], FIRC_ERR_IO, firc_xt_commit(xt, "mangle", &s->stage, NULL), "%d");
        firc_test_stage_t *mac = firc_test_stage_new();
        const char *line[] = {"-m mac --mac-source 02:00:00:00:00:0A -j RETURN"};
        firc_test_stage_override(mac, "FIRC_g9D", line, 1);
        ASSERT_EQ_FMTm(fails[k], FIRC_ERR_IO, firc_xt_commit(xt, "mangle", &mac->stage, NULL), "%d");
        ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
        firc_test_stage_t *nat = firc_test_stage_new();
        firc_test_stage_fixture(nat, "firmware-firc", FIRC_IPT_PROTO_IPV4);
        ASSERT_EQ_FMTm(fails[k], FIRC_OK, firc_xt_commit(xt, "nat", &nat->stage, NULL), "%d");
        ASSERT(nat_is(f, "firmware-firc", FIRC_IPT_PROTO_IPV4));
        char *text = log_stop();
        ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables: cannot probe ipv4 match "), "%zu");
        free(text);
        firc_test_stage_free(nat);
        firc_test_stage_free(mac);
        firc_test_stage_free(s);
        firc_xt_free(xt);
        firc_fake_xt_free(f);
    }
    PASS();
}

static firc_err_t commit_lines(firc_xt_t *xt, const char *table, const char *chain_a, const char *rule_a,
                               const char *chain_b, const char *rule_b, const char *builtin, const char *jump) {
    firc_test_stage_t *s = firc_test_stage_new();
    const char *a[] = {rule_a};
    firc_test_stage_override(s, chain_a, a, 1);
    if (chain_b != NULL) {
        const char *b[] = {rule_b};
        firc_test_stage_override(s, chain_b, b, 1);
    }
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
    const int nums[] = {0};
    const char *j[] = {jump};
    firc_test_stage_patch(s, builtin, 1, ops, nums, j);
    firc_err_t err = firc_xt_commit(xt, table, &s->stage, NULL);
    firc_test_stage_free(s);
    return err;
}

/* Catches: a fake kernel that takes what the real one refuses (a jump loop, DNAT after routing, REJECT outside filter), so a codec bug passes the suite. */
TEST the_fake_refuses_loops_and_misplaced_targets(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    log_start(FIRC_LOG_DEBUG);
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "mangle", "FIRC_a", "-j FIRC_b", "FIRC_b", "-j FIRC_a", "PREROUTING", "-j FIRC_a"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "nat", "FIRC_d", "-d 198.18.0.1/32 -j DNAT --to-destination 1.1.1.1", NULL, NULL, "POSTROUTING", "-j FIRC_d"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "nat", "FIRC_m", "-o ppp0 -j MASQUERADE", NULL, NULL, "PREROUTING", "-j FIRC_m"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "mangle", "FIRC_r", "-p tcp -j REJECT --reject-with tcp-reset", NULL, NULL, "PREROUTING", "-j FIRC_r"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "mangle", "FIRC_f", "-p tcp -j REJECT --reject-with tcp-reset", NULL, NULL, "FORWARD", "-j FIRC_f"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "filter", "FIRC_r", "-p tcp -j REJECT --reject-with tcp-reset", NULL, NULL, "FORWARD", "-j FIRC_r"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "filter", "FIRC_i", "-p tcp -j REJECT --reject-with tcp-reset", NULL, NULL, "INPUT", "-j FIRC_i"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "filter", "FIRC_o", "-p tcp -j REJECT --reject-with tcp-reset", NULL, NULL, "OUTPUT", "-j FIRC_o"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "mangle", "FIRC_n", "-d 198.18.0.1/32 -j DNAT --to-destination 1.1.1.1", NULL, NULL, "PREROUTING", "-j FIRC_n"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "filter", "FIRC_n", "-o ppp0 -j MASQUERADE", "FIRC_e", "-j RETURN", "FORWARD", "-j FIRC_e"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "nat", "FIRC_d", "-d 198.18.0.1/32 -j DNAT --to-destination 1.1.1.1", NULL, NULL, "PREROUTING", "-j FIRC_d"), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables refused ipv4 mangle (ELOOP)"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)2, count(text, "x_tables refused ipv4 nat (EINVAL)"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)3, count(text, "x_tables refused ipv4 mangle (EINVAL)"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables refused ipv4 filter (EINVAL)"), "%zu");
    free(text);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a walk unlike mark_source_chains: past an unconditional RETURN, stopping at a conditional one, refusing a chain reached twice or a target nothing reaches. */
TEST the_fake_walks_what_the_kernel_reaches(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_test_stage_t *s = firc_test_stage_new();
    const char *u[] = {"-j RETURN", "-j FIRC_u", "-d 198.18.0.1/32 -j DNAT --to-destination 1.1.1.1"};
    firc_test_stage_override(s, "FIRC_u", u, 3);
    const char *t[] = {"-j FIRC_x", "-j FIRC_x"};
    firc_test_stage_override(s, "FIRC_t", t, 2);
    const char *x[] = {"-j RETURN"};
    firc_test_stage_override(s, "FIRC_x", x, 1);
    const char *idle[] = {"-d 198.18.0.1/32 -j DNAT --to-destination 1.1.1.1"};
    firc_test_stage_override(s, "FIRC_idle", idle, 1);
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND, FIRC_IPT_OP_APPEND};
    const int nums[] = {0, 0};
    const char *j[] = {"-j FIRC_u", "-j FIRC_t"};
    firc_test_stage_patch(s, "POSTROUTING", 2, ops, nums, j);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    firc_test_stage_free(s);
    s = firc_test_stage_new();
    const char *c[] = {"-p udp -j RETURN", "-d 198.18.0.1/32 -j DNAT --to-destination 1.1.1.1"};
    firc_test_stage_override(s, "FIRC_c", c, 2);
    const char *jc[] = {"-j FIRC_c"};
    firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, jc);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    free(log_stop());
    firc_test_stage_free(s);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the mac match taken from a hook its revision does not allow (rev 0 has no POSTROUTING), or Keenetic's rev 1 refused there. */
TEST the_mac_match_keeps_to_its_hooks(void) {
    for (unsigned rev = 0; rev < 2; rev++) {
        firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
        firc_xt_t *xt = firc_fake_xt_handle(f);
        if (rev == 1) { ASSERT_EQ_FMT(FIRC_OK, firc_xt_probe(xt), "%d"); }
        ASSERT_EQ_FMT(rev, (unsigned)firc_xt_mac_rev(xt), "%u");
        const char *line = "-m mac --mac-source 02:00:00:00:00:0A -j RETURN";
        log_start(FIRC_LOG_INFO);
        ASSERT_EQ_FMT(rev == 1 ? FIRC_OK : FIRC_ERR_IO, commit_lines(xt, "mangle", "FIRC_p", line, NULL, NULL, "POSTROUTING", "-j FIRC_p"), "%d");
        ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "mangle", "FIRC_o", line, NULL, NULL, "OUTPUT", "-j FIRC_o"), "%d");
        ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "mangle", "FIRC_q", line, NULL, NULL, "PREROUTING", "-j FIRC_q"), "%d");
        free(log_stop());
        firc_xt_free(xt);
        firc_fake_xt_free(f);
    }
    PASS();
}

/* Catches: one table's run of failures hiding another table's first refusal (stage 1 kept one flag per family). */
TEST a_failure_in_one_table_does_not_hide_another(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_fake_xt_drop_table(f, "mangle");
    log_start(FIRC_LOG_INFO);
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "mangle", "FIRC_g", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_g"), "%d");
    }
    firc_fake_xt_fail_table(f, "nat", EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "nat", "FIRC_g", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_g"), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables cannot read ipv4 mangle (ENOENT)"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables refused ipv4 nat (EINVAL)"), "%zu");
    free(text);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a fake that ignores ipt_ip flag bits the kernel's ip_checkentry refuses, or refuses the goto bit it knows. */
TEST the_fake_refuses_unknown_ip_flags(void) {
    static const struct { firc_ipt_proto_t fam; uint32_t flags; uint8_t known, unknown; } k[] = {
        {FIRC_IPT_PROTO_IPV4, 82, 0x02, 0x04},
        {FIRC_IPT_PROTO_IPV6, 131, 0x04, 0x08},
    };
    for (size_t i = 0; i < 2; i++) {
        firc_fake_xt_t *f = firc_fake_xt_new(k[i].fam);
        firc_xt_info_t info;
        uint8_t *blob = NULL;
        ASSERT(firc_test_xt_read("firmware", k[i].fam, &info, &blob));
        firc_xt_counter_t old[64];
        firc_xt_info_t now;
        ASSERT_EQ(0, firc_fake_xt_ops()->get_info(f, k[i].fam, "nat", &now));
        ASSERT(now.num_entries <= 64);
        static const struct { uint32_t at; uint8_t value; int err; } spoil[] = {
            {0, 0, EINVAL}, {1, 0x80, EINVAL}, {1, 0x40, 0}, {0, 0, 0},
        };
        for (size_t s = 0; s < 4; s++) {
            uint8_t value = s == 0 ? k[i].unknown : s == 3 ? k[i].known : spoil[s].value;
            uint8_t keep = blob[k[i].flags + spoil[s].at];
            blob[k[i].flags + spoil[s].at] = value;
            ASSERT_EQ_FMT(spoil[s].err, firc_fake_xt_ops()->replace(f, k[i].fam, "nat", &info, blob, now.num_entries, old), "%d");
            blob[k[i].flags + spoil[s].at] = keep;
            ASSERT_EQ(0, firc_fake_xt_ops()->get_info(f, k[i].fam, "nat", &now));
        }
        free(blob);
        firc_fake_xt_free(f);
    }
    PASS();
}

/* Catches: a fake that refuses a table iptables-restore wrote on a real kernel, so the goldens and the fake disagree. */
TEST the_fake_takes_every_golden(void) {
    for (size_t i = 0; i < firc_test_xt_n_all; i++) {
        for (size_t v = 0; v < 2; v++) {
            const char *variant = NULL;
            if (strcmp(firc_test_xt_all[i].name, "m-firc") == 0) { variant = "kn"; }
            if (strcmp(firc_test_xt_all[i].name, "m-tap") == 0 && sizeof(long) == 4) { variant = "ilp32"; }
            if (v == 1 && variant == NULL) { continue; }
            for (size_t fi = 0; fi < 2; fi++) {
                if (!firc_test_xt_in_family(firc_test_xt_all[i].name, k_fams[fi])) { continue; }
                firc_fake_xt_t *f = firc_fake_xt_new(k_fams[fi]);
                firc_xt_info_t info, now;
                uint8_t *blob = NULL;
                ASSERT(firc_test_xt_read_as(firc_test_xt_all[i].name, k_fams[fi], v == 1 ? variant : NULL, &info, &blob));
                ASSERT_EQ(0, firc_fake_xt_ops()->get_info(f, k_fams[fi], firc_test_xt_all[i].table, &now));
                firc_xt_counter_t *old = calloc(now.num_entries, sizeof(*old));
                ASSERT_EQ_FMTm(firc_test_xt_all[i].name, 0,
                               firc_fake_xt_ops()->replace(f, k_fams[fi], firc_test_xt_all[i].table, &info, blob, now.num_entries, old),
                               "%d");
                free(old);
                free(blob);
                firc_fake_xt_free(f);
            }
        }
    }
    PASS();
}

/* Catches: a failure armed for one table hitting another or replacing another table's, or an accepted write missing from the order the engine's tests read. */
TEST a_failure_armed_for_one_table_hits_only_it(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_fake_xt_fail_table(f, "nat", EINVAL);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "mangle", "FIRC_g", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_g"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "nat", "FIRC_g", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_g"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "nat", "FIRC_g", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_g"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "nat", "FIRC_g", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_g"), "%d");
    free(log_stop());
    char *order = firc_fake_xt_write_order(f);
    ASSERT_STR_EQ("mangle\nnat\n", order);
    free(order);
    order = firc_fake_xt_read_order(f);
    ASSERT_STR_EQ("mangle\nnat\nnat\nnat\n", order);
    free(order);
    firc_fake_xt_reset(f);
    order = firc_fake_xt_write_order(f);
    ASSERT_STR_EQ("", order);
    free(order);
    order = firc_fake_xt_read_order(f);
    ASSERT_STR_EQ("", order);
    free(order);
    firc_fake_xt_fail_table(f, "nat", EINVAL);
    firc_fake_xt_reset(f);
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "nat", "FIRC_g", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_g"), "%d");
    firc_fake_xt_fail_table(f, "nat", EINVAL);
    firc_fake_xt_fail_table(f, "mangle", EINVAL);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "nat", "FIRC_h", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_h"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_lines(xt, "mangle", "FIRC_h", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_h"), "%d");
    free(log_stop());
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "mangle", "FIRC_h", "-j RETURN", NULL, NULL, "PREROUTING", "-j FIRC_h"), "%d");
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a revision failure armed for one extension answering for every extension. */
TEST a_revision_failure_is_per_extension(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_fail_revision(f, "mark", EPERM);
    ASSERT_EQ(EPERM, firc_fake_xt_ops()->get_revision(f, FIRC_IPT_PROTO_IPV4, false, "mark", 1));
    ASSERT_EQ(0, firc_fake_xt_ops()->get_revision(f, FIRC_IPT_PROTO_IPV4, false, "tcp", 0));
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a read hook told the wrong table, so a test cancelling at one table's read stops at another. */
TEST the_read_hook_names_the_table(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    char seen[64] = "";
    firc_fake_xt_on_read(f, note_table, seen);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "filter", "FIRC_g", "-j RETURN", NULL, NULL, "FORWARD", "-j FIRC_g"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, commit_lines(xt, "mangle", "FIRC_g", "-j RETURN", NULL, NULL, "FORWARD", "-j FIRC_g"), "%d");
    ASSERT_STR_EQ("filter,mangle,", seen);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

static uint8_t *ext_in(firc_ipt_proto_t fam, uint8_t *blob, uint32_t size, const char *name, bool target, uint8_t **entry) {
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    uint32_t eh = v6 ? 168u : 112u, at_t = v6 ? 140u : 88u;
    for (uint32_t off = 0; off < size;) {
        uint8_t *e = blob + off;
        uint16_t toff, next, ms;
        memcpy(&toff, e + at_t, 2);
        memcpy(&next, e + at_t + 2, 2);
        for (uint32_t m = eh; m <= toff; m += ms) {
            memcpy(&ms, e + m, 2);
            if ((m == toff) == target && strcmp((const char *)e + m + 2, name) == 0) {
                *entry = e;
                return e + m;
            }
        }
        off += next;
    }
    return NULL;
}

static int replace_now(firc_fake_xt_t *f, firc_ipt_proto_t fam, const char *table, const firc_xt_info_t *info,
                       uint8_t *blob) {
    firc_xt_info_t now;
    if (firc_fake_xt_ops()->get_info(f, fam, table, &now) != 0) { return -1; }
    firc_xt_counter_t *old = calloc(now.num_entries, sizeof(*old));
    int err = firc_fake_xt_ops()->replace(f, fam, table, info, blob, now.num_entries, old);
    free(old);
    return err;
}

static void rename_ext(uint8_t *x, const char *name, uint8_t rev) {
    memset(x + 2, 0, 29);
    memcpy(x + 2, name, strlen(name));
    x[31] = rev;
}

/* Catches: a fake that takes an extension or revision 4.9 lacks, or a payload size its extension does not have. */
TEST the_fake_knows_its_extensions(void) {
    for (size_t i = 0; i < 2; i++) {
        firc_fake_xt_t *f = firc_fake_xt_new(k_fams[i]);
        firc_xt_info_t info;
        uint8_t *blob = NULL, *e = NULL;
        ASSERT(firc_test_xt_read("m-firc", k_fams[i], &info, &blob));
        uint8_t *mark = ext_in(k_fams[i], blob, info.size, "mark", false, &e);
        uint8_t *tcp = ext_in(k_fams[i], blob, info.size, "tcp", false, &e);
        uint8_t *tg = ext_in(k_fams[i], blob, info.size, "MARK", true, &e);
        ASSERT(mark != NULL && tcp != NULL && tg != NULL);
        rename_ext(mark, "marx", 1);
        ASSERT_EQ_FMTm("unknown match", ENOENT, replace_now(f, k_fams[i], "mangle", &info, blob), "%d");
        rename_ext(mark, "mark", 9);
        ASSERT_EQ_FMTm("unknown revision of a family-free match", EPROTOTYPE, replace_now(f, k_fams[i], "mangle", &info, blob), "%d");
        rename_ext(mark, "conntrack", 3);
        ASSERT_EQ_FMTm("payload of another size", EINVAL, replace_now(f, k_fams[i], "mangle", &info, blob), "%d");
        rename_ext(mark, "mark", 1);
        rename_ext(tcp, "tcp", 9);
        ASSERT_EQ_FMTm("unknown revision of a per-family match", ENOENT, replace_now(f, k_fams[i], "mangle", &info, blob), "%d");
        rename_ext(tcp, "tcp", 0);
        rename_ext(tg, "MARX", 2);
        ASSERT_EQ_FMTm("unknown target", ENOENT, replace_now(f, k_fams[i], "mangle", &info, blob), "%d");
        rename_ext(tg, "MARK", 2);
        ASSERT_EQ_FMT(0, replace_now(f, k_fams[i], "mangle", &info, blob), "%d");
        ASSERT_EQ(ENOENT, firc_fake_xt_ops()->get_revision(f, k_fams[i], false, "marx", 1));
        ASSERT_EQ(EPROTONOSUPPORT, firc_fake_xt_ops()->get_revision(f, k_fams[i], false, "mark", 9));
        ASSERT_EQ(i == 0 ? 0 : EPROTONOSUPPORT, firc_fake_xt_ops()->get_revision(f, k_fams[i], true, "DNAT", 0));
        free(blob);
        firc_fake_xt_free(f);
    }
    PASS();
}

/* Catches: a barrier written where the kernel has no connmark match at revision 1, or a fake that takes another revision or size of it. */
TEST the_barrier_needs_connmark_revision_one(void) {
    for (size_t i = 0; i < 2; i++) {
        firc_fake_xt_t *f = firc_fake_xt_new(k_fams[i]);
        firc_xt_info_t info, bi;
        uint8_t *blob = NULL, *base = NULL, *e = NULL;
        ASSERT(firc_test_xt_read("f-firc", k_fams[i], &info, &blob));
        uint8_t *cm = ext_in(k_fams[i], blob, info.size, "connmark", false, &e);
        ASSERT(cm != NULL);
        rename_ext(cm, "connmark", 0);
        ASSERT_EQ_FMTm("revision 0", EPROTOTYPE, replace_now(f, k_fams[i], "filter", &info, blob), "%d");
        rename_ext(cm, "conntrack", 3);
        ASSERT_EQ_FMTm("another payload size", EINVAL, replace_now(f, k_fams[i], "filter", &info, blob), "%d");
        rename_ext(cm, "connmark", 1);
        ASSERT_EQ_FMT(0, replace_now(f, k_fams[i], "filter", &info, blob), "%d");
        free(blob);
        firc_fake_xt_free(f);

        f = firc_fake_xt_new(k_fams[i]);
        ASSERT(firc_test_xt_read("f-firmware", k_fams[i], &bi, &base));
        ASSERT(firc_fake_xt_load(f, "filter", &bi, base));
        firc_fake_xt_lack(f, false, "connmark", 1);
        firc_xt_t *xt = firc_fake_xt_handle(f);
        log_start(FIRC_LOG_INFO);
        ASSERT_EQ_FMT(FIRC_ERR_NOSYS, firc_xt_probe(xt), "%d");
        firc_test_stage_t *st = firc_test_stage_new();
        firc_test_stage_rules_file(st, "f-firc", k_fams[i]);
        ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "filter", &st->stage, NULL), "%d");
        ASSERT_EQ_FMT(0, firc_xt_refusal(xt), "%d");
        ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(f), "%zu");
        char *text = log_stop();
        ASSERT_EQ_FMTm(text, (size_t)1, count(text, "match connmark revision 1 (ENOENT): connmark rules cannot be written"), "%zu");
        free(text);
        firc_test_stage_free(st);
        firc_xt_free(xt);
        free(base);
        firc_fake_xt_free(f);
    }
    PASS();
}

/* Catches: a fake that takes a port match or a tcp-reset without the protocol 4.9 requires of it. */
TEST the_fake_checks_protocols(void) {
    for (size_t i = 0; i < 2; i++) {
        bool v6 = k_fams[i] == FIRC_IPT_PROTO_IPV6;
        uint32_t at_proto = v6 ? 128u : 80u, at_inv = v6 ? 132u : 83u;
        firc_fake_xt_t *f = firc_fake_xt_new(k_fams[i]);
        firc_xt_info_t info;
        uint8_t *blob = NULL, *tcp_e = NULL, *mp_e = NULL;
        ASSERT(firc_test_xt_read("m-firc", k_fams[i], &info, &blob));
        ASSERT(ext_in(k_fams[i], blob, info.size, "tcp", false, &tcp_e) != NULL);
        ASSERT(ext_in(k_fams[i], blob, info.size, "multiport", false, &mp_e) != NULL);
        static const struct { const char *what; bool mp, inv; uint8_t proto; int err; } k[] = {
            {"tcp match on udp", false, false, 17, EINVAL},
            {"tcp match on ! -p tcp", false, true, 6, EINVAL},
            {"multiport on icmp", true, false, 1, EINVAL},
            {"multiport on ! -p udp", true, true, 17, EINVAL},
            {"multiport on tcp", true, false, 6, 0},
        };
        for (size_t s = 0; s < sizeof(k) / sizeof(k[0]); s++) {
            uint8_t *e = k[s].mp ? mp_e : tcp_e;
            uint16_t proto, want = k[s].proto;
            uint8_t inv = e[at_inv];
            memcpy(&proto, e + at_proto, 2);
            memcpy(e + at_proto, &want, 2);
            e[at_inv] = (uint8_t)(inv | (k[s].inv ? 0x40u : 0u));
            ASSERT_EQ_FMTm(k[s].what, k[s].err, replace_now(f, k_fams[i], "mangle", &info, blob), "%d");
            memcpy(e + at_proto, &proto, 2);
            e[at_inv] = inv;
        }
        free(blob);
        ASSERT(firc_test_xt_read("f-firc", k_fams[i], &info, &blob));
        uint8_t *e = NULL, *rej = ext_in(k_fams[i], blob, info.size, "REJECT", true, &e);
        ASSERT(rej != NULL);
        uint32_t with;
        memcpy(&with, rej + 32, 4);
        ASSERT_EQ(v6 ? 6u : 7u, with);
        uint16_t udp = 17, tcp = 6;
        memcpy(e + at_proto, &udp, 2);
        ASSERT_EQ_FMTm("tcp-reset on udp", EINVAL, replace_now(f, k_fams[i], "filter", &info, blob), "%d");
        memcpy(e + at_proto, &tcp, 2);
        e[at_inv] |= 0x40u;
        ASSERT_EQ_FMTm("tcp-reset on ! -p tcp", EINVAL, replace_now(f, k_fams[i], "filter", &info, blob), "%d");
        e[at_inv] &= (uint8_t)~0x40u;
        if (v6) {
            e[131] &= (uint8_t)~0x01u;
            ASSERT_EQ_FMTm("tcp-reset without the v6 proto flag", EINVAL, replace_now(f, k_fams[i], "filter", &info, blob), "%d");
            e[131] |= 0x01u;
        }
        uint32_t echo = v6 ? 5u : 4u;
        memcpy(rej + 32, &echo, 4);
        ASSERT_EQ_FMTm("echo-reply", EINVAL, replace_now(f, k_fams[i], "filter", &info, blob), "%d");
        memcpy(rej + 32, &with, 4);
        ASSERT_EQ_FMT(0, replace_now(f, k_fams[i], "filter", &info, blob), "%d");
        free(blob);
        firc_fake_xt_free(f);
    }
    PASS();
}

static bool host_is_little(void) {
    const uint16_t one = 1;
    uint8_t first;
    memcpy(&first, &one, 1);
    return first == 1;
}

static void dst_payload(uint8_t index, uint8_t out[4]) {
    out[0] = host_is_little() ? index : 0;
    out[1] = host_is_little() ? 0 : index;
    out[2] = 1;
    out[3] = 0;
}

static firc_err_t commit_set_lines(firc_xt_t *xt, const char *chain, const char *const *lines, size_t n, bool as_block) {
    firc_test_stage_t *s = firc_test_stage_new();
    firc_xt_block_t b;
    firc_xt_block_init(&b);
    if (as_block) {
        for (size_t i = 0; i < n; i++) {
            firc_ipt_rule_t *r = firc_test_rule(lines[i]);
            if (firc_xt_block_add_rule(&b, firc_xt_proto(xt), r) != FIRC_OK) { abort(); }
            firc_ipt_rule_free(r);
        }
        firc_test_stage_block(s, chain, &b);
    } else {
        firc_test_stage_override(s, chain, lines, n);
    }
    firc_err_t err = firc_xt_commit(xt, "mangle", &s->stage, NULL);
    firc_test_stage_free(s);
    firc_xt_block_free(&b);
    return err;
}

static uint32_t kernel_rule_at(firc_fake_xt_t *f, firc_ipt_proto_t fam, const char *chain, size_t i, uint8_t *out,
                               size_t *n_rules, int32_t *index) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    uint32_t len = 0;
    *n_rules = 0;
    *index = -1;
    if (!firc_fake_xt_blob(f, "mangle", &info, &blob)) { return 0; }
    firc_xt_table_t t;
    const char *why = NULL;
    if (firc_xt_parse(fam, &info, blob, &t, &why) == FIRC_OK) {
        firc_xt_chain_t *c = firc_xt_find_chain(&t, chain);
        if (c != NULL) { *n_rules = c->n_rules; }
        if (c != NULL && i < c->n_rules && c->rules[i].len <= 512) {
            len = c->rules[i].len;
            memcpy(out, c->rules[i].bytes, len);
            *index = c->rules[i].old_index;
        }
        firc_xt_table_clear(&t);
    }
    free(blob);
    return len;
}

static uint32_t kernel_rule(firc_fake_xt_t *f, firc_ipt_proto_t fam, const char *chain, size_t i, uint8_t *out,
                            size_t *n_rules) {
    int32_t index;
    return kernel_rule_at(f, fam, chain, i, out, n_rules, &index);
}

TEST a_set_match_encodes_revision_1_dim_1_dst(void) {
    static const char *const line[] = {"-m set --match-set fircAS4 dst -j RETURN"};
    for (size_t f = 0; f < 2; f++) {
        uint32_t eh = f == 0 ? 112u : 168u;
        firc_fake_xt_t *k = firc_fake_xt_new(k_fams[f]);
        firc_fake_xt_set(k, "fircAS4", 7);
        firc_xt_t *xt = firc_fake_xt_handle(k);
        ASSERT_EQ_FMT(FIRC_OK, commit_set_lines(xt, "FIRC_s", line, 1, true), "%d");
        ASSERT_EQ_FMT((size_t)1, firc_fake_xt_replaces(k), "%zu");
        uint8_t e[512];
        size_t n = 0;
        ASSERT_EQ_FMT(eh + 80u, kernel_rule(k, k_fams[f], "FIRC_s", 0, e, &n), "%u");
        uint16_t size = 0, toff = 0;
        memcpy(&size, e + eh, 2);
        memcpy(&toff, e + (f == 0 ? 88 : 140), 2);
        ASSERT_EQ_FMT(40u, (unsigned)size, "%u");
        ASSERT_EQ_FMT(eh + 40u, (unsigned)toff, "%u");
        ASSERT_STR_EQ("set", (const char *)e + eh + 2);
        ASSERT_EQ_FMT(1u, (unsigned)e[eh + 31], "%u");
        uint8_t want[8] = {0};
        dst_payload(7, want);
        ASSERT_MEM_EQ(want, e + eh + 32, 8);
        firc_xt_free(xt);
        firc_fake_xt_free(k);
    }
    PASS();
}

TEST a_missing_set_refuses_the_table_with_enoent(void) {
    static const char *const line[] = {"-m set --match-set fircAS4 dst -j RETURN"};
    for (size_t f = 0; f < 2; f++) {
        for (int as_block = 0; as_block < 2; as_block++) {
            firc_fake_xt_t *k = firc_fake_xt_new(k_fams[f]);
            firc_fake_xt_set(k, "fircOther", 3);
            firc_xt_info_t bi, ai;
            uint8_t *before = NULL, *after = NULL;
            ASSERT(firc_fake_xt_blob(k, "mangle", &bi, &before));
            firc_xt_t *xt = firc_fake_xt_handle(k);
            ASSERT_EQ_FMT(FIRC_ERR_IO, commit_set_lines(xt, "FIRC_s", line, 1, as_block != 0), "%d");
            ASSERT_EQ_FMT(ENOENT, firc_xt_refusal(xt), "%d");
            ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(k), "%zu");
            ASSERT(firc_fake_xt_blob(k, "mangle", &ai, &after));
            ASSERT(firc_test_xt_same(k_fams[f], &bi, before, &ai, after));
            free(before);
            free(after);
            firc_xt_free(xt);
            firc_fake_xt_free(k);
        }
    }
    PASS();
}

TEST a_kernel_without_the_set_match_refuses_with_enoent(void) {
    static const char *const line[] = {"-m set --match-set fircAS4 dst -j RETURN"};
    firc_fake_xt_t *k = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_set(k, "fircAS4", 7);
    firc_fake_xt_lack(k, false, "set", 1);
    firc_xt_t *xt = firc_fake_xt_handle(k);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_probe(xt), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_IO, commit_set_lines(xt, "FIRC_s", line, 1, true), "%d");
    ASSERT_EQ_FMT(ENOENT, firc_xt_refusal(xt), "%d");
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(k), "%zu");
    firc_xt_free(xt);
    firc_fake_xt_free(k);
    PASS();
}

TEST a_kernel_without_ipset_refuses_with_enoent(void) {
    static const char *const line[] = {"-m set --match-set fircAS4 dst -j RETURN"};
    static const struct { int asked, refusal; } cases[] = {{ENOPROTOOPT, ENOENT}, {EPERM, EPERM}};
    for (size_t i = 0; i < 2; i++) {
        firc_fake_xt_t *k = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
        firc_fake_xt_set(k, "fircAS4", 7);
        firc_fake_xt_fail_sets(k, cases[i].asked);
        firc_xt_t *xt = firc_fake_xt_handle(k);
        ASSERT_EQ_FMT(FIRC_ERR_IO, commit_set_lines(xt, "FIRC_s", line, 1, true), "%d");
        ASSERT_EQ_FMT(cases[i].refusal, firc_xt_refusal(xt), "%d");
        ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(k), "%zu");
        firc_xt_free(xt);
        firc_fake_xt_free(k);
    }
    PASS();
}

TEST a_set_that_moved_index_rewrites_the_rule(void) {
    static const char *const line[] = {"-m set --match-set fircAS4 dst -j RETURN"};
    for (size_t f = 0; f < 2; f++) {
        for (int as_block = 0; as_block < 2; as_block++) {
            uint32_t eh = f == 0 ? 112u : 168u;
            firc_fake_xt_t *k = firc_fake_xt_new(k_fams[f]);
            firc_fake_xt_set(k, "fircAS4", 7);
            firc_xt_t *xt = firc_fake_xt_handle(k);
            ASSERT_EQ_FMT(FIRC_OK, commit_set_lines(xt, "FIRC_s", line, 1, as_block != 0), "%d");
            firc_fake_xt_set(k, "fircAS4", 9);
            firc_fake_xt_set_counters(k, "mangle", 100);
            ASSERT_EQ_FMT(FIRC_OK, commit_set_lines(xt, "FIRC_s", line, 1, as_block != 0), "%d");
            ASSERT_EQ_FMT((size_t)2, firc_fake_xt_replaces(k), "%zu");
            uint8_t e[512], want[4];
            size_t n = 0;
            int32_t at = -1;
            ASSERT_EQ_FMT(eh + 80u, kernel_rule_at(k, k_fams[f], "FIRC_s", 0, e, &n, &at), "%u");
            ASSERT_EQ_FMT((size_t)1, n, "%zu");
            firc_xt_counter_t c;
            ASSERT(at >= 0 && firc_fake_xt_counter(k, "mangle", (uint32_t)at, &c));
            ASSERT_EQ_FMT(100u + (unsigned)at, (unsigned)c.pcnt, "%u");
            dst_payload(9, want);
            ASSERT_MEM_EQ(want, e + eh + 32, 4);
            ASSERT_EQ_FMT(FIRC_OK, commit_set_lines(xt, "FIRC_s", line, 1, as_block != 0), "%d");
            ASSERT_EQ_FMT((size_t)2, firc_fake_xt_replaces(k), "%zu");
            firc_xt_free(xt);
            firc_fake_xt_free(k);
        }
    }
    PASS();
}

TEST two_rules_on_one_set_ask_for_its_index_once(void) {
    static const char *const lines[] = {
        "-m set --match-set fircA dst -j RETURN",
        "-m set --match-set fircB dst -j RETURN",
        "-p tcp --dport 53 -m set --match-set fircA dst -j RETURN",
    };
    firc_fake_xt_t *k = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_set(k, "fircA", 7);
    firc_fake_xt_set(k, "fircB", 8);
    firc_xt_t *xt = firc_fake_xt_handle(k);
    ASSERT_EQ_FMT(FIRC_OK, commit_set_lines(xt, "FIRC_s", lines, 3, true), "%d");
    ASSERT_EQ_FMT((size_t)2, firc_fake_xt_set_asks(k), "%zu");
    uint8_t e[512], want[4];
    size_t n = 0;
    ASSERT(kernel_rule(k, FIRC_IPT_PROTO_IPV4, "FIRC_s", 0, e, &n) > 0);
    dst_payload(7, want);
    ASSERT_MEM_EQ(want, e + 112 + 32, 4);
    ASSERT(kernel_rule(k, FIRC_IPT_PROTO_IPV4, "FIRC_s", 1, e, &n) > 0);
    dst_payload(8, want);
    ASSERT_MEM_EQ(want, e + 112 + 32, 4);
    ASSERT(kernel_rule(k, FIRC_IPT_PROTO_IPV4, "FIRC_s", 2, e, &n) > 0);
    dst_payload(7, want);
    ASSERT_MEM_EQ(want, e + 112 + 48 + 32, 4);
    firc_xt_free(xt);
    firc_fake_xt_free(k);
    PASS();
}

static uint32_t foreign_set_entry(firc_ipt_proto_t fam, uint8_t rev, uint8_t index, uint8_t *out) {
    uint32_t eh = fam == FIRC_IPT_PROTO_IPV4 ? 112u : 168u;
    uint16_t msize = rev == 4 ? 80 : 40, tsize = 40;
    uint16_t toff = (uint16_t)(eh + msize), next = (uint16_t)(toff + tsize);
    memset(out, 0, next);
    memcpy(out + (fam == FIRC_IPT_PROTO_IPV4 ? 88 : 140), &toff, 2);
    memcpy(out + (fam == FIRC_IPT_PROTO_IPV4 ? 90 : 142), &next, 2);
    memcpy(out + eh, &msize, 2);
    memcpy(out + eh + 2, "set", 3);
    out[eh + 31] = rev;
    dst_payload(index, out + eh + 32);
    memcpy(out + toff, &tsize, 2);
    int32_t ret = -5;
    memcpy(out + toff + 32, &ret, 4);
    return next;
}

static firc_err_t commit_raw(firc_xt_t *xt, const char *chain, const uint8_t *bytes, uint32_t len) {
    firc_xt_block_t fb;
    firc_xt_block_init(&fb);
    fb.fam = firc_xt_proto(xt);
    fb.bytes = (uint8_t *)bytes;
    fb.len = len;
    fb.n = 1;
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_block(s, chain, &fb);
    firc_err_t err = firc_xt_commit(xt, "mangle", &s->stage, NULL);
    firc_test_stage_free(s);
    return err;
}

TEST a_foreign_set_match_of_revision_4_survives_a_commit(void) {
    for (size_t f = 0; f < 2; f++) {
        uint32_t eh = f == 0 ? 112u : 168u;
        uint8_t foreign[512];
        uint32_t len = foreign_set_entry(k_fams[f], 4, 5, foreign);
        ASSERT_EQ_FMT(eh + 80u + 40u, len, "%u");
        firc_fake_xt_t *k = firc_fake_xt_new(k_fams[f]);
        firc_fake_xt_set(k, "fwset", 5);
        firc_fake_xt_set(k, "fircAS4", 7);
        firc_xt_t *xt = firc_fake_xt_handle(k);
        ASSERT_EQ_FMT(FIRC_OK, commit_raw(xt, "fw_set", foreign, len), "%d");
        static const char *const line[] = {"-m set --match-set fircAS4 dst -j RETURN"};
        ASSERT_EQ_FMT(FIRC_OK, commit_set_lines(xt, "FIRC_s", line, 1, true), "%d");
        ASSERT_EQ_FMT((size_t)2, firc_fake_xt_replaces(k), "%zu");
        uint8_t e[512];
        size_t n = 0;
        ASSERT_EQ_FMT(len, kernel_rule(k, k_fams[f], "fw_set", 0, e, &n), "%u");
        ASSERT_MEM_EQ(foreign, e, len);
        firc_xt_free(xt);
        firc_fake_xt_free(k);
    }
    PASS();
}

TEST a_patch_carrying_a_set_match_is_refused(void) {
    static const char *const lines[] = {"-m set --match-set fircA dst -j RETURN", "-m set --match-set fwset dst -j RETURN"};
    const firc_ipt_option_t op[] = {FIRC_IPT_OP_APPEND};
    const int num[] = {0};
    for (size_t f = 0; f < 2; f++) {
        for (size_t l = 0; l < 2; l++) {
            firc_fake_xt_t *k = firc_fake_xt_new(k_fams[f]);
            firc_fake_xt_set(k, "fwset", 5);
            firc_fake_xt_set(k, "fircA", 7);
            firc_xt_t *xt = firc_fake_xt_handle(k);
            uint8_t foreign[512];
            uint32_t len = foreign_set_entry(k_fams[f], 1, 5, foreign);
            ASSERT_EQ_FMT(FIRC_OK, commit_raw(xt, "PREROUTING", foreign, len), "%d");
            size_t replaces = firc_fake_xt_replaces(k);
            firc_xt_info_t bi, ai;
            uint8_t *before = NULL, *after = NULL;
            ASSERT(firc_fake_xt_blob(k, "mangle", &bi, &before));
            firc_test_stage_t *s = firc_test_stage_new();
            firc_test_stage_patch(s, "PREROUTING", 1, op, num, lines + l);
            ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_xt_commit(xt, "mangle", &s->stage, NULL), "%d");
            ASSERT_EQ_FMT(0, firc_xt_refusal(xt), "%d");
            firc_test_stage_free(s);
            ASSERT_EQ_FMT(replaces, firc_fake_xt_replaces(k), "%zu");
            ASSERT(firc_fake_xt_blob(k, "mangle", &ai, &after));
            ASSERT(firc_test_xt_same(k_fams[f], &bi, before, &ai, after));
            uint8_t e[512];
            size_t n = 0;
            ASSERT_EQ_FMT(len, kernel_rule(k, k_fams[f], "PREROUTING", 0, e, &n), "%u");
            ASSERT_EQ_FMT((size_t)1, n, "%zu");
            ASSERT_MEM_EQ(foreign, e, len);
            free(before);
            free(after);
            firc_xt_free(xt);
            firc_fake_xt_free(k);
        }
    }
    PASS();
}

TEST a_set_dropped_between_commits_refuses_the_next(void) {
    static const char *const line[] = {"-m set --match-set fircAS4 dst -j RETURN", "-m mark --mark 1 -j RETURN"};
    for (size_t f = 0; f < 2; f++) {
        firc_fake_xt_t *k = firc_fake_xt_new(k_fams[f]);
        firc_fake_xt_set(k, "fircAS4", 7);
        firc_xt_t *xt = firc_fake_xt_handle(k);
        ASSERT_EQ_FMT(FIRC_OK, commit_set_lines(xt, "FIRC_s", line, 1, true), "%d");
        firc_fake_xt_set_drop(k, "fircAS4");
        firc_xt_info_t bi, ai;
        uint8_t *before = NULL, *after = NULL;
        ASSERT(firc_fake_xt_blob(k, "mangle", &bi, &before));
        ASSERT_EQ_FMT(FIRC_ERR_IO, commit_set_lines(xt, "FIRC_s", line, 2, true), "%d");
        ASSERT_EQ_FMT(ENOENT, firc_xt_refusal(xt), "%d");
        ASSERT_EQ_FMT((size_t)1, firc_fake_xt_replaces(k), "%zu");
        ASSERT(firc_fake_xt_blob(k, "mangle", &ai, &after));
        ASSERT(firc_test_xt_same(k_fams[f], &bi, before, &ai, after));
        free(before);
        free(after);
        firc_xt_free(xt);
        firc_fake_xt_free(k);
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_staging_is_written_as_iptables_restore_wrote_it);
    RUN_TEST(an_unchanged_table_is_read_but_not_written);
    RUN_TEST(counters_of_carried_entries_survive_a_write);
    RUN_TEST(a_count_race_is_again_and_the_retry_writes);
    RUN_TEST(a_same_count_race_is_reverted);
    RUN_TEST(a_table_that_moved_since_the_read_is_not_written);
    RUN_TEST(a_held_lock_is_again_without_a_write);
    RUN_TEST(the_lock_covers_only_the_write);
    RUN_TEST(a_refusal_is_io_and_said_once_per_run);
    RUN_TEST(a_lasting_refusal_is_said_again_and_its_end_too);
    RUN_TEST(a_missing_table_is_said_once);
    RUN_TEST(a_missing_revision_is_named_and_fails_only_its_rules);
    RUN_TEST(the_barrier_needs_connmark_revision_one);
    RUN_TEST(a_missing_redirect_is_reported_by_has);
    RUN_TEST(a_missing_addrtype_is_reported_by_has);
    RUN_TEST(has_tells_a_target_from_its_match_by_case);
    RUN_TEST(has_says_no_for_what_v6_never_writes);
    RUN_TEST(a_cancel_stops_the_write);
    RUN_TEST(a_refused_rule_writes_nothing_and_is_quoted);
    RUN_TEST(a_jump_to_a_missing_chain_is_io_and_named);
    RUN_TEST(failed_counters_still_complete_the_write);
    RUN_TEST(a_refused_blob_is_kept_only_with_a_dump_dir);
    RUN_TEST(a_refused_blob_is_kept_at_the_init_scripts_floor);
    RUN_TEST(a_refused_blob_is_dumped_after_the_lock_is_released);
    RUN_TEST(the_debug_line_splits_the_merge);
    RUN_TEST(a_probe_that_cannot_ask_names_every_extension);
    RUN_TEST(the_probe_asks_every_extension_after_an_unknown_errno);
    RUN_TEST(the_capture_set_is_asked_only_by_the_capture_probe);
    RUN_TEST(a_failure_in_one_table_does_not_hide_another);
    RUN_TEST(a_revision_the_kernel_does_not_support_is_missing);
    RUN_TEST(the_mac_match_takes_the_revision_the_probe_confirmed);
    RUN_TEST(an_unaskable_revision_refuses_what_was_not_confirmed);
    RUN_TEST(the_fake_refuses_what_the_kernel_refuses);
    RUN_TEST(the_fake_refuses_loops_and_misplaced_targets);
    RUN_TEST(the_fake_walks_what_the_kernel_reaches);
    RUN_TEST(the_mac_match_keeps_to_its_hooks);
    RUN_TEST(the_fake_refuses_unknown_ip_flags);
    RUN_TEST(the_fake_takes_every_golden);
    RUN_TEST(a_failure_armed_for_one_table_hits_only_it);
    RUN_TEST(a_revision_failure_is_per_extension);
    RUN_TEST(the_read_hook_names_the_table);
    RUN_TEST(the_fake_knows_its_extensions);
    RUN_TEST(the_fake_checks_protocols);
    RUN_TEST(a_set_match_encodes_revision_1_dim_1_dst);
    RUN_TEST(a_missing_set_refuses_the_table_with_enoent);
    RUN_TEST(a_kernel_without_the_set_match_refuses_with_enoent);
    RUN_TEST(a_kernel_without_ipset_refuses_with_enoent);
    RUN_TEST(a_set_that_moved_index_rewrites_the_rule);
    RUN_TEST(two_rules_on_one_set_ask_for_its_index_once);
    RUN_TEST(a_foreign_set_match_of_revision_4_survives_a_commit);
    RUN_TEST(a_patch_carrying_a_set_match_is_refused);
    RUN_TEST(a_set_dropped_between_commits_refuses_the_next);
    GREATEST_MAIN_END();
}
