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
#include "firc/xtables.h"
#include "xt_golden.h"

static FILE *g_log;

static void log_start(firc_log_level_t level) {
    g_log = tmpfile();
    firc_log_set_fd(fileno(g_log));
    firc_log_set_level(level);
}

static char *log_stop(void) {
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_level(FIRC_LOG_INFO);
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
    ASSERT_EQ_FMT((size_t)5, firc_fake_xt_revision_asks(f), "%zu");
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
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

static void raise_it(void *ud) { firc_cancel_raise(ud); }

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

/* Catches: a probe that cannot ask (no CAP_NET_ADMIN, no socket) read as five missing extensions, or said per extension. */
TEST a_probe_that_cannot_ask_is_io_and_said_once(void) {
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_fake_xt_fail_revisions(f, EPERM);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_probe(xt), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables: cannot probe ipv4 target DNAT revision 0 (EPERM)"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "x_tables"), "%zu");
    free(text);
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
    ASSERT_EQ_FMTm(text, (size_t)5, count(text, "x_tables: no ipv6 "), "%zu");
    free(text);
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: the refused blob written at every log level (flash wear, run dir litter) or never written. */
TEST a_refused_blob_is_kept_at_debug_only(void) {
    char dir[] = "/tmp/firc-xt-XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/refused-ipv4-nat.bin", dir);
    firc_fake_xt_t *f = fake_with("firmware", FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_set_dump_dir(xt, dir), "%d");
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    log_start(FIRC_LOG_INFO);
    firc_fake_xt_fail_next_replace(f, EINVAL);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_xt_commit(xt, "nat", &s->stage, NULL), "%d");
    struct stat st;
    ASSERT(stat(path, &st) != 0);
    firc_log_set_level(FIRC_LOG_DEBUG);
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
    RUN_TEST(a_missing_table_is_said_once);
    RUN_TEST(a_missing_revision_is_named_and_fails_only_its_rules);
    RUN_TEST(a_cancel_stops_the_write);
    RUN_TEST(a_refused_rule_writes_nothing_and_is_quoted);
    RUN_TEST(a_jump_to_a_missing_chain_is_io_and_named);
    RUN_TEST(failed_counters_still_complete_the_write);
    RUN_TEST(a_refused_blob_is_kept_at_debug_only);
    RUN_TEST(a_refused_blob_is_dumped_after_the_lock_is_released);
    RUN_TEST(a_probe_that_cannot_ask_is_io_and_said_once);
    RUN_TEST(a_revision_the_kernel_does_not_support_is_missing);
    RUN_TEST(the_fake_refuses_what_the_kernel_refuses);
    GREATEST_MAIN_END();
}
