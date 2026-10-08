#include "greatest.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "firc/log.h"
#include "firc/nfcommit.h"

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;

    int started;
    int full_passes;
    int partial_passes;
    int finished;
    int interrupted;

    bool block;
    bool release;
    int fail_times;
    firc_err_t fail_with;
    firc_err_t seq[16];
    int seq_n;
    int seq_at;
    int gate_at;
} probe_t;

static void probe_init(probe_t *p) {
    *p = (probe_t){0};
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);
}

static void probe_destroy(probe_t *p) {
    pthread_cond_destroy(&p->cv);
    pthread_mutex_destroy(&p->mu);
}

static firc_err_t probe_rebuild(void *ud, firc_cancel_t *cancel, bool full) {
    probe_t *p = ud;

    pthread_mutex_lock(&p->mu);
    int ordinal = ++p->started;
    if (full) { p->full_passes++; } else { p->partial_passes++; }
    bool block = p->block;
    firc_err_t fail = FIRC_OK;
    if (p->seq_at < p->seq_n) {
        fail = p->seq[p->seq_at++];
    } else if (p->fail_times > 0) {
        p->fail_times--;
        fail = p->fail_with;
    }
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);

    for (;;) {
        pthread_mutex_lock(&p->mu);
        bool parked = ordinal == p->gate_at;
        pthread_mutex_unlock(&p->mu);
        if (!parked) { break; }
        if (firc_cancel_raised(cancel)) { return FIRC_ERR_CANCELED; }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000L};
        nanosleep(&ts, NULL);
    }

    if (block) {
        for (;;) {
            if (firc_cancel_raised(cancel)) {
                pthread_mutex_lock(&p->mu);
                p->interrupted++;
                pthread_cond_broadcast(&p->cv);
                pthread_mutex_unlock(&p->mu);
                return FIRC_ERR_CANCELED;
            }
            pthread_mutex_lock(&p->mu);
            bool released = p->release;
            pthread_mutex_unlock(&p->mu);
            if (released) { break; }

            struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000L};
            nanosleep(&ts, NULL);
        }
    }

    pthread_mutex_lock(&p->mu);
    if (fail == FIRC_OK) { p->finished++; }
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
    return fail;
}

#define AWAIT(p, cond)                                                                      \
    do {                                                                                    \
        bool ok_ = false;                                                                   \
        for (int i_ = 0; i_ < 4000; i_++) {                                                 \
            pthread_mutex_lock(&(p)->mu);                                                   \
            ok_ = (cond);                                                                   \
            pthread_mutex_unlock(&(p)->mu);                                                 \
            if (ok_) { break; }                                                             \
            struct timespec ts_ = {.tv_sec = 0, .tv_nsec = 500000L};                        \
            nanosleep(&ts_, NULL);                                                          \
        }                                                                                   \
        ASSERT(ok_);                                                                        \
    } while (0)

static void sleep_ms(unsigned ms) {
    struct timespec ts = {.tv_sec = ms / 1000u, .tv_nsec = (long)(ms % 1000u) * 1000000L};
    nanosleep(&ts, NULL);
}

static firc_nfcommit_t *start_committer(probe_t *p) {
    firc_nfcommit_t *c = firc_nfcommit_new(probe_rebuild, p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    firc_nfcommit_start(c);
    return c;
}

static long elapsed_ms(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (long)(t1.tv_sec - t0->tv_sec) * 1000L + (t1.tv_nsec - t0->tv_nsec) / 1000000L;
}

static firc_nfcommit_t *start_settling(probe_t *p, unsigned long_ms, unsigned addr_ms) {
    firc_nfcommit_t *c = firc_nfcommit_new(probe_rebuild, p);
    firc_nfcommit_set_delays_for_test(c, long_ms, long_ms * 4u);
    firc_nfcommit_set_addr_delay_for_test(c, addr_ms);
    firc_nfcommit_start(c);
    return c;
}

/* Catches: a pass for new fake addresses waiting the settle meant for firmware bursts. */
TEST an_address_request_settles_short(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 300, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_LT(elapsed_ms(&t0), 150);
    pthread_mutex_lock(&p.mu);
    int partial = p.partial_passes;
    pthread_mutex_unlock(&p.mu);
    ASSERT_EQ_FMT(1, partial, "%d");
    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a chain change asked with request_more settling short like an address request. */
TEST a_more_request_settles_long(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 300, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_request_more(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_GTE(elapsed_ms(&t0), 290);
    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the settle length fixed when the wait begins, so a full request inside a short one is served early or twice. */
TEST a_full_request_during_a_short_settle_waits_the_long_one(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 300, 100);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_request_addresses(c);
    sleep_ms(50);
    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_GTE(elapsed_ms(&t0), 290);
    sleep_ms(400);
    pthread_mutex_lock(&p.mu);
    int started = p.started, full = p.full_passes;
    pthread_mutex_unlock(&p.mu);
    ASSERT_EQ_FMT(2, started, "%d");
    ASSERT_EQ_FMT(2, full, "%d");
    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the startup pass, which wipes, settling short. */
TEST the_first_pass_settles_long(void) {
    probe_t p;
    probe_init(&p);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_t *c = start_settling(&p, 300, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 1);
    ASSERT_GTE(elapsed_ms(&t0), 290);
    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a hard failure's backoff replaced by the short settle on the retry of an address pass. */
TEST a_failed_address_pass_still_backs_off(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 100, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    pthread_mutex_lock(&p.mu);
    p.fail_times = 1;
    p.fail_with = FIRC_ERR_SYS;
    pthread_mutex_unlock(&p.mu);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 2);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    AWAIT(&p, p.started >= 3);
    ASSERT_GTE(elapsed_ms(&t0), 190);
    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

TEST request_triggers_a_rebuild(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a first pass that does not wipe, a "more" request that wipes, or a failed wipe not owed. */
TEST the_first_pass_wipes_and_only_a_table_change_wipes_again(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request_more(c);
    AWAIT(&p, p.finished >= 1);
    ASSERT_EQ_FMTm("the first pass sweeps what a previous instance left", 1, p.full_passes, "%d");

    firc_nfcommit_request_more(c);
    AWAIT(&p, p.finished >= 2);
    ASSERT_EQ_FMTm("more to add: no wipe", 1, p.partial_passes, "%d");

    pthread_mutex_lock(&p.mu);
    p.fail_times = 1;
    p.fail_with = FIRC_ERR_AGAIN;
    pthread_mutex_unlock(&p.mu);
    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 3);
    ASSERT_EQ_FMTm("a table change wipes, and its failed attempt is retried as a wipe", 3,
                   p.full_passes, "%d");

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: firc_nfcommit_request blocking until the write is done. */
TEST request_does_not_wait_for_the_write(void) {
    probe_t p;
    probe_init(&p);
    p.block = true;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);

    firc_nfcommit_request(c);

    AWAIT(&p, p.interrupted >= 1);

    pthread_mutex_lock(&p.mu);
    p.release = true;
    pthread_mutex_unlock(&p.mu);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a request mid-write not aborting it, or no fresh pass after it. */
TEST request_interrupts_and_restarts(void) {
    probe_t p;
    probe_init(&p);
    p.block = true;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);

    firc_nfcommit_request(c);
    AWAIT(&p, p.interrupted >= 1);

    pthread_mutex_lock(&p.mu);
    p.block = false;
    pthread_mutex_unlock(&p.mu);

    AWAIT(&p, p.finished >= 1);
    ASSERT(p.started >= 2);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a burst of requests costing one pass each instead of one or two. */
TEST requests_coalesce(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = firc_nfcommit_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 30, 60);
    firc_nfcommit_start(c);

    for (int i = 0; i < 200; i++) { firc_nfcommit_request(c); }

    AWAIT(&p, p.finished >= 1);
    sleep_ms(200);

    uint64_t passes = firc_nfcommit_passes(c);
    ASSERT_FALSE(passes > 4);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a pass that lost a race to the firmware not retried until one gets through. */
TEST retries_until_the_table_holds_still(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 5;
    p.fail_with = FIRC_ERR_AGAIN;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);
    ASSERT(p.started >= 6);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a failure that is not a race being dropped instead of retried. */
TEST retries_unclassified_failures(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 3;
    p.fail_with = FIRC_ERR_IO;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

static firc_nfcommit_t *start_committer_failing_after(probe_t *p, unsigned ms) {
    firc_nfcommit_t *c = firc_nfcommit_new(probe_rebuild, p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    firc_nfcommit_set_failing_after_for_test(c, ms);
    firc_nfcommit_start(c);
    return c;
}

static firc_nfcommit_health_t health_of(firc_nfcommit_t *c) {
    firc_nfcommit_health_t h;
    firc_nfcommit_health(c, &h);
    return h;
}

/* Polls the health until it says `failing`, or about 2 s pass. */
static bool health_becomes(firc_nfcommit_t *c, bool failing) {
    for (int i = 0; i < 4000; i++) {
        if (health_of(c).failing == failing) { return true; }
        sleep_ms(1);
    }
    return false;
}

static int g_log_pipe[2] = {-1, -1};
static firc_log_level_t g_log_prev;
static char g_log[1 << 18];
static size_t g_log_len;

static void log_capture_begin(void) {
    if (pipe(g_log_pipe) != 0) { abort(); }
    fcntl(g_log_pipe[0], F_SETFL, fcntl(g_log_pipe[0], F_GETFL) | O_NONBLOCK);
    fcntl(g_log_pipe[1], F_SETFL, fcntl(g_log_pipe[1], F_GETFL) | O_NONBLOCK);
    g_log_len = 0;
    g_log[0] = '\0';
    g_log_prev = firc_log_level();
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(g_log_pipe[1]);
}

static const char *log_drain(void) {
    for (;;) {
        if (g_log_len + 1 >= sizeof(g_log)) { break; }
        ssize_t n = read(g_log_pipe[0], g_log + g_log_len, sizeof(g_log) - 1 - g_log_len);
        if (n <= 0) { break; }
        g_log_len += (size_t)n;
    }
    g_log[g_log_len] = '\0';
    return g_log;
}

/* Reads the log pipe; call it after the committer is freed, when nothing writes the pipe. */
static const char *log_capture_end(void) {
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_level(g_log_prev);
    const char *s = log_drain();
    close(g_log_pipe[0]);
    close(g_log_pipe[1]);
    return s;
}

static int occurrences(const char *hay, const char *needle) {
    int n = 0;
    for (const char *at = strstr(hay, needle); at != NULL; at = strstr(at + 1, needle)) { n++; }
    return n;
}

static void set_gate(probe_t *p, int at) {
    pthread_mutex_lock(&p->mu);
    p->gate_at = at;
    pthread_mutex_unlock(&p->mu);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

#define ESCALATION "netfilter pass keeps failing (3 in a row since "
#define RECOVERY "netfilter pass completed again"

/* Catches: one hard failure read as failing at once, said at WARN or ERR, or followed by a recovery line. */
TEST one_refusal_then_a_completed_pass_is_not_failing_and_no_error(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 1;
    p.fail_with = FIRC_ERR_IO;
    p.gate_at = 2;
    log_capture_begin();
    firc_nfcommit_t *c = start_committer_failing_after(&p, 3600u * 1000u);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_FALSEm("one refusal is not failing", health_of(c).failing);
    ASSERT_EQ_FMTm("nothing completed yet", 0ULL, (unsigned long long)firc_nfcommit_last_completed_pass(c), "%llu");

    set_gate(&p, 0);
    AWAIT(&p, p.finished >= 1);
    for (int i = 0; i < 2000 && firc_nfcommit_last_completed_pass(c) == 0; i++) { sleep_ms(1); }
    ASSERT_EQ_FMTm("the retry completed", 2ULL, (unsigned long long)firc_nfcommit_last_completed_pass(c), "%llu");
    ASSERT_FALSE(health_of(c).failing);

    firc_nfcommit_free(c);
    const char *log = log_capture_end();
    ASSERT_EQ_FMTm("nothing at WARN", 0, occurrences(log, " WRN "), "%d");
    ASSERT_EQ_FMTm("and nothing at ERR", 0, occurrences(log, " ERR "), "%d");
    ASSERT_EQ_FMTm("no recovery from a run that never escalated", 0, occurrences(log, RECOVERY), "%d");
    probe_destroy(&p);
    PASS();
}

/* Catches: ERR said at the wrong count or more than once, failing before the bound, or no recovery. */
TEST a_refusal_that_persists_escalates_once_and_fails_past_the_bound(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 1000000;
    p.fail_with = FIRC_ERR_IO;
    p.gate_at = 2;
    log_capture_begin();
    uint64_t t0 = now_ms();
    time_t w0 = time(NULL);
    firc_nfcommit_t *c = start_committer_failing_after(&p, 2000u);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 2);
    time_t w1 = time(NULL);
    while (time(NULL) <= w1) { sleep_ms(20); }
    set_gate(&p, 3);
    AWAIT(&p, p.started >= 3);
    ASSERT_EQ_FMTm("two failures: no ERR", 0, occurrences(log_drain(), " ERR "), "%d");

    set_gate(&p, 4);
    AWAIT(&p, p.started >= 4);
    const char *log = log_drain();
    ASSERT_EQ_FMTm("the third failure: one ERR", 1, occurrences(log, " ERR "), "%d");
    ASSERT_EQ_FMTm("and it is the escalation", 1, occurrences(log, "ERR " ESCALATION), "%d");
    const char *line = strstr(log, ESCALATION);
    const char *eol = line != NULL ? strchr(line, '\n') : NULL;
    ASSERTm("the line ends with the error", eol != NULL && (size_t)(eol - line) > strlen("): i/o error") &&
                                                memcmp(eol - strlen("): i/o error"), "): i/o error",
                                                       strlen("): i/o error")) == 0);
    char since0[128], since1[128];
    struct tm tm;
    gmtime_r(&w0, &tm);
    strftime(since0, sizeof(since0), ESCALATION "%Y-%m-%dT%H:%M:%SZ)", &tm);
    gmtime_r(&w1, &tm);
    strftime(since1, sizeof(since1), ESCALATION "%Y-%m-%dT%H:%M:%SZ)", &tm);
    ASSERTm("dated from the first refusal", strstr(log, since0) != NULL || strstr(log, since1) != NULL);
    bool early = health_of(c).failing;
    uint64_t early_at = now_ms();
    ASSERTm("fixture: read inside the bound", early_at - t0 < 2000u);
    ASSERT_FALSEm("three failures inside the bound are not failing", early);

    set_gate(&p, 0);
    bool failing = false;
    for (int i = 0; i < 4000 && !failing; i++) {
        failing = health_of(c).failing;
        if (!failing) {
            (void)log_drain();
            sleep_ms(1);
        }
    }
    ASSERT(failing);
    ASSERTm("failing only once the bound has passed", now_ms() - t0 >= 2000u);
    ASSERT_EQ(FIRC_ERR_IO, health_of(c).err);
    pthread_mutex_lock(&p.mu);
    int seen = p.started;
    pthread_mutex_unlock(&p.mu);
    (void)log_drain();
    AWAIT(&p, p.started >= seen + 2);
    ASSERT_EQ_FMTm("said once per run", 1, occurrences(log_drain(), " ERR "), "%d");
    ASSERT_EQ_FMTm("no recovery yet", 0, occurrences(log_drain(), RECOVERY), "%d");

    pthread_mutex_lock(&p.mu);
    p.fail_times = 0;
    pthread_mutex_unlock(&p.mu);
    bool cleared = false;
    for (int i = 0; i < 4000 && !cleared; i++) {
        cleared = !health_of(c).failing;
        if (!cleared) {
            (void)log_drain();
            sleep_ms(1);
        }
    }
    ASSERTm("a completed pass clears it", cleared);

    firc_nfcommit_free(c);
    log = log_capture_end();
    ASSERTm("fixture: the capture did not fill", g_log_len + 1 < sizeof(g_log));
    ASSERT_EQ_FMTm("the recovery is said once", 1, occurrences(log, "INF " RECOVERY), "%d");
    ASSERT_EQ_FMTm("still one ERR", 1, occurrences(log, " ERR "), "%d");
    probe_destroy(&p);
    PASS();
}

/* Catches: a race counted toward the escalation, or a race resetting the count. */
TEST races_neither_count_toward_the_escalation_nor_break_it(void) {
    static const firc_err_t two[] = {FIRC_ERR_IO, FIRC_ERR_AGAIN, FIRC_ERR_AGAIN, FIRC_ERR_IO, FIRC_ERR_AGAIN};
    static const firc_err_t three[] = {FIRC_ERR_IO, FIRC_ERR_AGAIN, FIRC_ERR_IO, FIRC_ERR_CANCELED, FIRC_ERR_IO};
    const firc_err_t *seqs[] = {two, three};
    const int want_err[] = {0, 1};
    for (int k = 0; k < 2; k++) {
        probe_t p;
        probe_init(&p);
        memcpy(p.seq, seqs[k], sizeof(two));
        p.seq_n = 5;
        log_capture_begin();
        firc_nfcommit_t *c = start_committer_failing_after(&p, 3600u * 1000u);
        firc_nfcommit_request(c);
        AWAIT(&p, p.finished >= 1);
        for (int i = 0; i < 2000 && firc_nfcommit_last_completed_pass(c) == 0; i++) { sleep_ms(1); }
        ASSERT_EQ_FMTm("five failures, then the pass that completed", 6ULL,
                       (unsigned long long)firc_nfcommit_last_completed_pass(c), "%llu");
        firc_nfcommit_free(c);
        const char *log = log_capture_end();
        ASSERT_EQ_FMT(want_err[k], occurrences(log, "ERR " ESCALATION), "%d");
        ASSERT_EQ_FMT(want_err[k], occurrences(log, " ERR "), "%d");
        ASSERT_EQ_FMT(want_err[k], occurrences(log, RECOVERY), "%d");
        probe_destroy(&p);
    }
    PASS();
}

/* Catches: lost races logged above debug, or escalating. */
TEST a_race_streak_says_nothing_above_debug(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 20;
    p.fail_with = FIRC_ERR_AGAIN;
    log_capture_begin();
    firc_nfcommit_t *c = start_committer_failing_after(&p, 3600u * 1000u);
    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);
    ASSERT_EQ_FMT(21, p.started, "%d");
    firc_nfcommit_free(c);
    const char *log = log_capture_end();
    ASSERT_EQ_FMT(0, occurrences(log, " WRN "), "%d");
    ASSERT_EQ_FMT(0, occurrences(log, " ERR "), "%d");
    ASSERT_EQ_FMT(0, occurrences(log, RECOVERY), "%d");
    probe_destroy(&p);
    PASS();
}

/* Catches: a hard failure never failing, the wrong error or `since`, or a completed pass not clearing it. */
TEST a_hard_failure_is_failing_until_a_pass_completes(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 1000000;
    p.fail_with = FIRC_ERR_IO;
    int64_t before = (int64_t)time(NULL);
    firc_nfcommit_t *c = start_committer_failing_after(&p, 200u);
    ASSERT_FALSEm("nothing has failed yet", health_of(c).failing);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);
    ASSERT(health_becomes(c, true));
    firc_nfcommit_health_t h = health_of(c);
    ASSERT_EQ(FIRC_ERR_IO, h.err);
    ASSERT(h.since >= before && h.since <= (int64_t)time(NULL));

    while ((int64_t)time(NULL) <= h.since) { sleep_ms(50); }
    pthread_mutex_lock(&p.mu);
    int seen = p.started;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.started >= seen + 2);
    ASSERT_EQ_FMTm("since is the first failure's", (long long)h.since, (long long)health_of(c).since, "%lld");
    ASSERTm("still failing", health_of(c).failing);

    pthread_mutex_lock(&p.mu);
    p.fail_times = 0;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.finished >= 1);
    ASSERTm("a completed pass clears it", health_becomes(c, false));

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: races or a hard error failing within the bound, or a later race replacing the error. */
TEST races_within_the_bound_are_not_failing(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 1000000;
    p.fail_with = FIRC_ERR_AGAIN;
    uint64_t t0 = now_ms();
    firc_nfcommit_t *c = start_committer_failing_after(&p, 1000u);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 5);
    ASSERT_FALSEm("four lost races in a row are not a failure", health_of(c).failing);

    pthread_mutex_lock(&p.mu);
    p.fail_with = FIRC_ERR_IO;
    int seen = p.started;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.started >= seen + 2);
    bool early = health_of(c).failing;
    ASSERTm("fixture: read inside the bound", now_ms() - t0 < 1000u);
    ASSERT_FALSEm("a hard error inside the bound is not failing", early);

    pthread_mutex_lock(&p.mu);
    p.fail_with = FIRC_ERR_AGAIN;
    pthread_mutex_unlock(&p.mu);
    ASSERT(health_becomes(c, true));
    ASSERT_EQ(FIRC_ERR_IO, health_of(c).err);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: races never counting as failing, whatever the time. */
TEST races_past_the_bound_are_failing(void) {
    firc_err_t kinds[] = {FIRC_ERR_AGAIN, FIRC_ERR_CANCELED};
    for (size_t k = 0; k < 2; k++) {
        probe_t p;
        probe_init(&p);
        p.fail_times = 1000000;
        p.fail_with = kinds[k];
        firc_nfcommit_t *c = start_committer_failing_after(&p, 0);

        firc_nfcommit_request(c);
        ASSERT(health_becomes(c, true));
        ASSERT_EQ(kinds[k], health_of(c).err);

        firc_nfcommit_free(c);
        probe_destroy(&p);
    }
    PASS();
}

/* Catches: a completed pass leaving the old run's start, so new races read as already old. */
TEST a_completed_pass_starts_the_bound_over(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 1;
    p.fail_with = FIRC_ERR_IO;
    firc_nfcommit_t *c = start_committer_failing_after(&p, 1000u);

    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);
    ASSERT(health_becomes(c, false));
    sleep_ms(1200);

    pthread_mutex_lock(&p.mu);
    p.fail_times = 1000000;
    p.fail_with = FIRC_ERR_AGAIN;
    int seen = p.started;
    pthread_mutex_unlock(&p.mu);
    firc_nfcommit_request_more(c);
    AWAIT(&p, p.started >= seen + 2);
    ASSERT_FALSEm("a new run, inside its bound", health_of(c).failing);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: first_pending false at start, cleared by a failed pass, or left set after a completed one. */
TEST the_first_write_is_pending_until_a_pass_completes(void) {
    probe_t p;
    probe_init(&p);
    p.fail_times = 2;
    p.fail_with = FIRC_ERR_IO;
    firc_nfcommit_t *c = firc_nfcommit_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    ASSERTm("before start", health_of(c).first_pending);
    firc_nfcommit_start(c);
    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 2);
    ASSERTm("a failed pass writes nothing", health_of(c).first_pending);
    AWAIT(&p, p.finished >= 1);
    bool cleared = false;
    for (int i = 0; i < 2000 && !cleared; i++) {
        cleared = !health_of(c).first_pending;
        if (!cleared) { sleep_ms(1); }
    }
    ASSERTm("the completed pass ends it", cleared);
    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a request made before the thread starts being lost. */
TEST request_before_start_is_served(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = firc_nfcommit_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);

    firc_nfcommit_request(c);
    ASSERT_EQ(0u, firc_nfcommit_passes(c));

    ASSERT_EQ(FIRC_OK, firc_nfcommit_start(c));
    AWAIT(&p, p.finished >= 1);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a stop waiting for the write in flight to finish. */
TEST stop_aborts_a_running_rebuild(void) {
    probe_t p;
    probe_init(&p);
    p.block = true;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);

    firc_nfcommit_stop(c);
    ASSERT(p.interrupted >= 1);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: an interrupt scheduling a rebuild of its own, or losing the interrupted pass. */
TEST interrupt_yields_without_asking_for_more_work(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_interrupt(c);
    sleep_ms(30);
    ASSERT_EQ(0u, firc_nfcommit_passes(c));

    pthread_mutex_lock(&p.mu);
    p.block = true;
    pthread_mutex_unlock(&p.mu);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);

    firc_nfcommit_interrupt(c);
    AWAIT(&p, p.interrupted >= 1);

    pthread_mutex_lock(&p.mu);
    p.block = false;
    p.release = true;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.finished >= 1);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

TEST idle_committer_does_nothing(void) {
    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_committer(&p);

    sleep_ms(50);
    ASSERT_EQ(0u, firc_nfcommit_passes(c));

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

TEST null_and_double_stop_are_safe(void) {
    firc_nfcommit_request(NULL);
    firc_nfcommit_stop(NULL);
    firc_nfcommit_free(NULL);
    ASSERT_EQ(0u, firc_nfcommit_passes(NULL));
    ASSERT(firc_nfcommit_cancel(NULL) == NULL);
    ASSERT(firc_nfcommit_new(NULL, NULL) == NULL);

    probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_committer(&p);
    firc_nfcommit_stop(c);
    firc_nfcommit_stop(c);
    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: request_more aborting the pass in flight like request, or not scheduling a pass. */
TEST request_more_does_not_interrupt_but_still_schedules(void) {
    probe_t p;
    probe_init(&p);
    p.block = true;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);

    for (int i = 0; i < 5; i++) { firc_nfcommit_request_more(c); }

    ASSERT_FALSEm("request_more must not raise the cancellation token",
                  firc_cancel_raised(firc_nfcommit_cancel(c)));

    pthread_mutex_lock(&p.mu);
    p.release = true;
    p.block = false;
    pthread_mutex_unlock(&p.mu);

    AWAIT(&p, p.finished >= 1);
    ASSERT_EQ_FMTm("the pass that was running finished rather than restarting", 0, p.interrupted,
                   "%d");

    AWAIT(&p, p.started >= 2);

    firc_nfcommit_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the cancel token cleared after the pass publishes it is running, losing an interrupt. */
TEST an_interrupt_at_the_instant_a_pass_begins_is_not_lost(void) {
    int lost = 0;
    int skipped = 0;
    for (int round = 0; round < 60; round++) {
        probe_t p;
        probe_init(&p);
        p.block = true;
        firc_nfcommit_t *c = start_committer(&p);

        uint64_t before = firc_nfcommit_passes(c);
        firc_nfcommit_request(c);
        bool published = false;
        for (int i = 0; i < 2000000 && !published; i++) {
            published = firc_nfcommit_passes(c) != before;
        }
        if (!published) {
            pthread_mutex_lock(&p.mu);
            p.release = true;
            p.block = false;
            pthread_mutex_unlock(&p.mu);
            firc_nfcommit_free(c);
            probe_destroy(&p);
            skipped++;
            continue;
        }
        firc_nfcommit_interrupt(c);

        bool started = false;
        for (int i = 0; i < 4000 && !started; i++) {
            pthread_mutex_lock(&p.mu);
            started = p.started > 0;
            pthread_mutex_unlock(&p.mu);
            if (started) { break; }
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000L};
            nanosleep(&ts, NULL);
        }

        bool aborted = false;
        if (started) {
            for (int i = 0; i < 2000 && !aborted; i++) {
                pthread_mutex_lock(&p.mu);
                aborted = p.interrupted > 0;
                pthread_mutex_unlock(&p.mu);
                if (aborted) { break; }
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 200000L};
                nanosleep(&ts, NULL);
            }
        }

        pthread_mutex_lock(&p.mu);
        p.release = true;
        p.block = false;
        pthread_mutex_unlock(&p.mu);
        if (started && !aborted) { lost++; }

        firc_nfcommit_free(c);
        probe_destroy(&p);
    }
    ASSERT_EQ_FMTm("an interrupt raised while a pass is running must abort it", 0, lost, "%d");
    ASSERTm("too few rounds observed a running pass to mean anything", skipped < 45);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(request_triggers_a_rebuild);
    RUN_TEST(the_first_pass_wipes_and_only_a_table_change_wipes_again);
    RUN_TEST(request_does_not_wait_for_the_write);
    RUN_TEST(request_interrupts_and_restarts);
    RUN_TEST(request_more_does_not_interrupt_but_still_schedules);
    RUN_TEST(an_address_request_settles_short);
    RUN_TEST(a_more_request_settles_long);
    RUN_TEST(a_full_request_during_a_short_settle_waits_the_long_one);
    RUN_TEST(the_first_pass_settles_long);
    RUN_TEST(a_failed_address_pass_still_backs_off);
    RUN_TEST(an_interrupt_at_the_instant_a_pass_begins_is_not_lost);
    RUN_TEST(requests_coalesce);
    RUN_TEST(retries_until_the_table_holds_still);
    RUN_TEST(retries_unclassified_failures);
    RUN_TEST(request_before_start_is_served);
    RUN_TEST(stop_aborts_a_running_rebuild);
    RUN_TEST(interrupt_yields_without_asking_for_more_work);
    RUN_TEST(idle_committer_does_nothing);
    RUN_TEST(null_and_double_stop_are_safe);
    RUN_TEST(a_hard_failure_is_failing_until_a_pass_completes);
    RUN_TEST(one_refusal_then_a_completed_pass_is_not_failing_and_no_error);
    RUN_TEST(a_refusal_that_persists_escalates_once_and_fails_past_the_bound);
    RUN_TEST(races_neither_count_toward_the_escalation_nor_break_it);
    RUN_TEST(a_race_streak_says_nothing_above_debug);
    RUN_TEST(races_within_the_bound_are_not_failing);
    RUN_TEST(races_past_the_bound_are_failing);
    RUN_TEST(a_completed_pass_starts_the_bound_over);
    RUN_TEST(the_first_write_is_pending_until_a_pass_completes);
    GREATEST_MAIN_END();
}
