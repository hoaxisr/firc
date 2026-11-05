#include "greatest.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "firc/log.h"
#include "firc/logrep.h"
#include "firc/nfcommit.h"

static firc_nfcommit_t *g_live[8];

static firc_nfcommit_t *tracked_new(firc_nfcommit_rebuild_fn fn, void *ud) {
    firc_nfcommit_t *c = firc_nfcommit_new(fn, ud);
    for (size_t i = 0; c != NULL && i < sizeof(g_live) / sizeof(g_live[0]); i++) {
        if (g_live[i] == NULL) { g_live[i] = c; break; }
    }
    return c;
}

static void tracked_free(firc_nfcommit_t *c) {
    for (size_t i = 0; c != NULL && i < sizeof(g_live) / sizeof(g_live[0]); i++) {
        if (g_live[i] == c) { g_live[i] = NULL; }
    }
    firc_nfcommit_free(c);
}

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
    firc_cancel_t *cancel;
    struct timespec started_at[32];
    void *watch;
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
    if (ordinal < 32) { clock_gettime(CLOCK_MONOTONIC, &p->started_at[ordinal]); }
    p->cancel = cancel;
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
    firc_nfcommit_t *c = tracked_new(probe_rebuild, p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    firc_nfcommit_start(c);
    return c;
}

static long started_after_ms(probe_t *p, int ordinal, const struct timespec *t0) {
    pthread_mutex_lock(&p->mu);
    struct timespec t1 = p->started_at[ordinal];
    pthread_mutex_unlock(&p->mu);
    return (long)(t1.tv_sec - t0->tv_sec) * 1000L + (t1.tv_nsec - t0->tv_nsec) / 1000000L;
}

static struct timespec start_of(probe_t *p, int ordinal) {
    pthread_mutex_lock(&p->mu);
    struct timespec t = p->started_at[ordinal];
    pthread_mutex_unlock(&p->mu);
    return t;
}

static firc_nfcommit_t *start_settling(probe_t *p, unsigned long_ms, unsigned addr_ms) {
    firc_nfcommit_t *c = tracked_new(probe_rebuild, p);
    firc_nfcommit_set_delays_for_test(c, long_ms, long_ms * 4u);
    firc_nfcommit_set_addr_delay_for_test(c, addr_ms);
    firc_nfcommit_set_addr_idle_for_test(c, 0);
    firc_nfcommit_start(c);
    return c;
}

static firc_nfcommit_t *start_idling(probe_t *p, unsigned long_ms, unsigned addr_ms, unsigned idle_ms) {
    firc_nfcommit_t *c = tracked_new(probe_rebuild, p);
    firc_nfcommit_set_delays_for_test(c, long_ms, long_ms * 4u);
    firc_nfcommit_set_addr_delay_for_test(c, addr_ms);
    firc_nfcommit_set_addr_idle_for_test(c, idle_ms);
    firc_nfcommit_start(c);
    return c;
}

/* Catches: a pass for new fake addresses waiting the settle meant for firmware bursts. */
TEST an_address_request_settles_short(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 300, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_LT(started_after_ms(&p, 2, &t0), 250);
    pthread_mutex_lock(&p.mu);
    int partial = p.partial_passes;
    pthread_mutex_unlock(&p.mu);
    ASSERT_EQ_FMT(1, partial, "%d");
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the idle check ignored or inverted, so a request long after the last pass settles long. */
TEST an_address_request_after_an_idle_stretch_settles_short(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_idling(&p, 300, 1, 400);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    sleep_ms(450);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_LT(started_after_ms(&p, 2, &t0), 250);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the idle check ignored, so back-to-back address passes split batches with the short settle. */
TEST an_address_request_right_after_a_pass_settles_long(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_idling(&p, 300, 1, 400);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_GTE(started_after_ms(&p, 2, &t0), 290);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a chain change asked with request_more settling short like an address request. */
TEST a_more_request_settles_long(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 300, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_request_more(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_GTE(started_after_ms(&p, 2, &t0), 290);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the settle length fixed when the wait begins, so a full request inside a short one is served early or twice. */
TEST a_full_request_during_a_short_settle_waits_the_long_one(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 600, 300);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_request_addresses(c);
    sleep_ms(50);
    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 2);
    ASSERT_GTE(started_after_ms(&p, 2, &t0), 590);
    sleep_ms(700);
    pthread_mutex_lock(&p.mu);
    int started = p.started, full = p.full_passes;
    pthread_mutex_unlock(&p.mu);
    ASSERT_EQ_FMT(2, started, "%d");
    ASSERT_EQ_FMT(2, full, "%d");
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the startup pass, which wipes, settling short. */
TEST the_first_pass_settles_long(void) {
    static probe_t p;
    probe_init(&p);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_t *c = start_settling(&p, 300, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 1);
    ASSERT_GTE(started_after_ms(&p, 1, &t0), 290);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a raced address pass retried after the short settle, so the firmware's rewrite is hit again at once. */
TEST a_raced_address_pass_retries_after_the_long_settle(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 300, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    pthread_mutex_lock(&p.mu);
    p.fail_times = 1;
    p.fail_with = FIRC_ERR_AGAIN;
    pthread_mutex_unlock(&p.mu);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 3);
    struct timespec t0 = start_of(&p, 2);
    ASSERT_GTE(started_after_ms(&p, 3, &t0), 290);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the long settle owed by a chain change lost when its pass is canceled and retried. */
TEST a_canceled_more_pass_retries_after_the_long_settle(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 300, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    pthread_mutex_lock(&p.mu);
    p.fail_times = 1;
    p.fail_with = FIRC_ERR_CANCELED;
    pthread_mutex_unlock(&p.mu);
    firc_nfcommit_request_more(c);
    AWAIT(&p, p.started >= 3);
    struct timespec t0 = start_of(&p, 2);
    ASSERT_GTE(started_after_ms(&p, 3, &t0), 290);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a hard failure's backoff replaced by the short settle on the retry of an address pass. */
TEST a_failed_address_pass_still_backs_off(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_settling(&p, 100, 1);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.finished >= 1);
    pthread_mutex_lock(&p.mu);
    p.fail_times = 1;
    p.fail_with = FIRC_ERR_SYS;
    pthread_mutex_unlock(&p.mu);
    firc_nfcommit_request_addresses(c);
    AWAIT(&p, p.started >= 3);
    struct timespec t0 = start_of(&p, 2);
    ASSERT_GTE(started_after_ms(&p, 3, &t0), 190);
    ASSERT_LT(started_after_ms(&p, 3, &t0), 350);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

TEST request_triggers_a_rebuild(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a first pass that does not wipe, a "more" request that wipes, or a failed wipe not owed. */
TEST the_first_pass_wipes_and_only_a_table_change_wipes_again(void) {
    static probe_t p;
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

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: firc_nfcommit_request blocking until the write is done. */
TEST request_does_not_wait_for_the_write(void) {
    static probe_t p;
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

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a request mid-write not aborting it, or no fresh pass after it. */
TEST request_interrupts_and_restarts(void) {
    static probe_t p;
    probe_init(&p);
    p.block = true;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);

    firc_nfcommit_request(c);
    AWAIT(&p, p.interrupted >= 1);

    pthread_mutex_lock(&p.mu);
    p.block = false;
    p.release = true;
    pthread_mutex_unlock(&p.mu);

    AWAIT(&p, p.finished >= 1);
    ASSERT(p.started >= 2);

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a burst of requests costing one pass each instead of one or two. */
TEST requests_coalesce(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 30, 60);
    firc_nfcommit_start(c);

    for (int i = 0; i < 200; i++) { firc_nfcommit_request(c); }

    AWAIT(&p, p.finished >= 1);
    sleep_ms(200);

    uint64_t passes = firc_nfcommit_passes(c);
    ASSERT_FALSE(passes > 4);

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a pass that lost a race to the firmware not retried until one gets through. */
TEST retries_until_the_table_holds_still(void) {
    static probe_t p;
    probe_init(&p);
    p.fail_times = 5;
    p.fail_with = FIRC_ERR_AGAIN;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);
    ASSERT(p.started >= 6);

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a failure that is not a race being dropped instead of retried. */
TEST retries_unclassified_failures(void) {
    static probe_t p;
    probe_init(&p);
    p.fail_times = 3;
    p.fail_with = FIRC_ERR_IO;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

static firc_nfcommit_t *start_committer_failing_after(probe_t *p, unsigned ms) {
    firc_nfcommit_t *c = tracked_new(probe_rebuild, p);
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
static char g_log[1 << 18];
static size_t g_log_len;

static void log_capture_begin(void) {
    if (pipe(g_log_pipe) != 0) { abort(); }
    fcntl(g_log_pipe[0], F_SETFL, fcntl(g_log_pipe[0], F_GETFL) | O_NONBLOCK);
    fcntl(g_log_pipe[1], F_SETFL, fcntl(g_log_pipe[1], F_GETFL) | O_NONBLOCK);
    g_log_len = 0;
    g_log[0] = '\0';
    firc_log_set_output_floor(FIRC_LOG_INFO);
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
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    const char *s = log_drain();
    close(g_log_pipe[0]);
    close(g_log_pipe[1]);
    g_log_pipe[0] = g_log_pipe[1] = -1;
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

#define ESCALATION "netfilter pass keeps failing: i/o error"
#define RECOVERY "netfilter pass: recovered after "

static _Atomic uint64_t g_rep_ms = 1000;
static uint64_t rep_clock(void) { return atomic_load(&g_rep_ms); }

/* Catches: one hard failure read as failing at once, said at WARN or ERR, or followed by a recovery line. */
TEST one_refusal_then_a_completed_pass_is_not_failing_and_no_error(void) {
    static probe_t p;
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

    tracked_free(c);
    const char *log = log_capture_end();
    ASSERT_EQ_FMTm("nothing at WARN", 0, occurrences(log, " WRN "), "%d");
    ASSERT_EQ_FMTm("and nothing at ERR", 0, occurrences(log, " ERR "), "%d");
    ASSERT_EQ_FMTm("no recovery from a run that never escalated", 0, occurrences(log, RECOVERY), "%d");
    probe_destroy(&p);
    PASS();
}

/* Catches: three quick failures said at ERROR, a run past a minute never raised to ERROR, raised more than once, failing before the bound, or no recovery. */
TEST a_refusal_that_persists_warns_then_errs_after_a_minute(void) {
    static probe_t p;
    probe_init(&p);
    p.fail_times = 1000000;
    p.fail_with = FIRC_ERR_IO;
    p.gate_at = 2;
    atomic_store(&g_rep_ms, 1000);
    firc_logrep_set_clock_for_test(rep_clock);
    log_capture_begin();
    uint64_t t0 = now_ms();
    firc_nfcommit_t *c = start_committer_failing_after(&p, 2000u);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 2);
    set_gate(&p, 3);
    AWAIT(&p, p.started >= 3);
    ASSERT_EQ_FMTm("two failures: nothing", 0, occurrences(log_drain(), " WRN "), "%d");

    set_gate(&p, 4);
    AWAIT(&p, p.started >= 4);
    const char *log = log_drain();
    ASSERT_EQ_FMTm("the third failure: one WARN", 1, occurrences(log, "WRN " ESCALATION), "%d");
    ASSERT_EQ_FMTm("and no ERR", 0, occurrences(log, " ERR "), "%d");
    bool early = health_of(c).failing;
    ASSERTm("fixture: read inside the bound", now_ms() - t0 < 2000u);
    ASSERT_FALSEm("three failures inside the bound are not failing", early);

    atomic_fetch_add(&g_rep_ms, 60000);
    set_gate(&p, 0);
    bool failing = false;
    for (int i = 0; i < 4000 && !failing; i++) {
        failing = health_of(c).failing;
        if (!failing) { sleep_ms(1); }
    }
    ASSERT(failing);
    ASSERTm("failing only once the bound has passed", now_ms() - t0 >= 2000u);
    ASSERT_EQ(FIRC_ERR_IO, health_of(c).err);
    pthread_mutex_lock(&p.mu);
    int seen = p.started;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.started >= seen + 2);
    log = log_drain();
    ASSERT_EQ_FMTm("a minute without a pass: one ERR", 1, occurrences(log, "ERR " ESCALATION " (still failing, "), "%d");
    ASSERT_EQ_FMTm("no recovery yet", 0, occurrences(log, RECOVERY), "%d");

    pthread_mutex_lock(&p.mu);
    p.fail_times = 0;
    pthread_mutex_unlock(&p.mu);
    bool cleared = false;
    for (int i = 0; i < 4000 && !cleared; i++) {
        cleared = !health_of(c).failing;
        if (!cleared) { sleep_ms(1); }
    }
    ASSERTm("a completed pass clears it", cleared);

    tracked_free(c);
    firc_logrep_set_clock_for_test(NULL);
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
        static probe_t p;
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
        tracked_free(c);
        const char *log = log_capture_end();
        ASSERT_EQ_FMT(want_err[k], occurrences(log, "WRN " ESCALATION), "%d");
        ASSERT_EQ_FMT(0, occurrences(log, " ERR "), "%d");
        ASSERT_EQ_FMT(want_err[k], occurrences(log, RECOVERY), "%d");
        probe_destroy(&p);
    }
    PASS();
}

/* Catches: lost races logged above debug, or escalating. */
TEST a_race_streak_says_nothing_above_debug(void) {
    static probe_t p;
    probe_init(&p);
    p.fail_times = 20;
    p.fail_with = FIRC_ERR_AGAIN;
    log_capture_begin();
    firc_nfcommit_t *c = start_committer_failing_after(&p, 3600u * 1000u);
    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);
    ASSERT_EQ_FMT(21, p.started, "%d");
    tracked_free(c);
    const char *log = log_capture_end();
    ASSERT_EQ_FMT(0, occurrences(log, " WRN "), "%d");
    ASSERT_EQ_FMT(0, occurrences(log, " ERR "), "%d");
    ASSERT_EQ_FMT(0, occurrences(log, RECOVERY), "%d");
    probe_destroy(&p);
    PASS();
}

#define RACES "netfilter pass keeps losing races: "
#define RACES_OVER RECOVERY

/* Catches: lost races past the bound never said above debug, said per pass, or never said over. */
TEST a_race_run_past_the_bound_warns_once(void) {
    static probe_t p;
    probe_init(&p);
    p.fail_times = 1000000;
    p.fail_with = FIRC_ERR_AGAIN;
    log_capture_begin();
    firc_nfcommit_t *c = start_committer_failing_after(&p, 200u);
    firc_nfcommit_request(c);
    ASSERT(health_becomes(c, true));
    pthread_mutex_lock(&p.mu);
    int seen = p.started;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.started >= seen + 3);
    ASSERT_EQ_FMTm("said once the bound passed", 1, occurrences(log_drain(), "WRN " RACES), "%d");
    pthread_mutex_lock(&p.mu);
    p.fail_times = 0;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.finished >= 1);
    ASSERT(health_becomes(c, false));
    tracked_free(c);
    const char *log = log_capture_end();
    ASSERT_EQ_FMTm("once per run", 1, occurrences(log, " WRN "), "%d");
    ASSERT_EQ_FMTm("never an error", 0, occurrences(log, " ERR "), "%d");
    ASSERT_EQ_FMTm("and its end is said", 1, occurrences(log, "INF " RACES_OVER), "%d");
    probe_destroy(&p);
    PASS();
}

/* Catches: a race run never raised to ERROR, or its minute counted from the WARN instead of the run's first race. */
TEST a_race_run_errs_a_minute_after_its_first_race(void) {
    static probe_t p;
    probe_init(&p);
    p.fail_times = 1000000;
    p.fail_with = FIRC_ERR_AGAIN;
    atomic_store(&g_rep_ms, 1000);
    firc_logrep_set_clock_for_test(rep_clock);
    log_capture_begin();
    firc_nfcommit_t *c = start_committer_failing_after(&p, 200u);
    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 2);
    atomic_fetch_add(&g_rep_ms, 30000);
    ASSERT(health_becomes(c, true));
    pthread_mutex_lock(&p.mu);
    int seen = p.started;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.started >= seen + 2);
    const char *log = log_drain();
    ASSERT_EQ_FMTm("the WARN half a minute in", 1, occurrences(log, "WRN " RACES), "%d");
    ASSERT_EQ_FMT(0, occurrences(log, " ERR "), "%d");
    atomic_fetch_add(&g_rep_ms, 30000);
    pthread_mutex_lock(&p.mu);
    seen = p.started;
    pthread_mutex_unlock(&p.mu);
    AWAIT(&p, p.started >= seen + 2);
    log = log_drain();
    ASSERT_EQ_FMTm("a minute after the first race: one ERR", 1, occurrences(log, "ERR " RACES), "%d");
    pthread_mutex_lock(&p.mu);
    p.fail_times = 0;
    pthread_mutex_unlock(&p.mu);
    ASSERT(health_becomes(c, false));
    tracked_free(c);
    firc_logrep_set_clock_for_test(NULL);
    (void)log_capture_end();
    probe_destroy(&p);
    PASS();
}

/* Catches: a hard failure never failing, the wrong error or `since`, or a completed pass not clearing it. */
TEST a_hard_failure_is_failing_until_a_pass_completes(void) {
    static probe_t p;
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

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: races or a hard error failing within the bound, or a later race replacing the error. */
TEST races_within_the_bound_are_not_failing(void) {
    static probe_t p;
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

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: races never counting as failing, whatever the time. */
TEST races_past_the_bound_are_failing(void) {
    firc_err_t kinds[] = {FIRC_ERR_AGAIN, FIRC_ERR_CANCELED};
    for (size_t k = 0; k < 2; k++) {
        static probe_t p;
        probe_init(&p);
        p.fail_times = 1000000;
        p.fail_with = kinds[k];
        firc_nfcommit_t *c = start_committer_failing_after(&p, 0);

        firc_nfcommit_request(c);
        ASSERT(health_becomes(c, true));
        ASSERT_EQ(kinds[k], health_of(c).err);

        tracked_free(c);
        probe_destroy(&p);
    }
    PASS();
}

/* Catches: a completed pass leaving the old run's start, so new races read as already old. */
TEST a_completed_pass_starts_the_bound_over(void) {
    static probe_t p;
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

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

typedef struct {
    atomic_int polls;
    atomic_int moved_left;
} watch_probe_t;

static bool watch_fn(void *ud) {
    probe_t *p = ud;
    watch_probe_t *w = p->watch;
    atomic_fetch_add(&w->polls, 1);
    int left = atomic_load(&w->moved_left);
    if (left > 0) { atomic_store(&w->moved_left, left - 1); }
    return left > 0;
}

static void await_polls(watch_probe_t *w, int n) {
    for (int i = 0; i < 4000 && atomic_load(&w->polls) < n; i++) {
        nanosleep(&(struct timespec){.tv_nsec = 1000000L}, NULL);
    }
}

TEST a_moved_table_gets_a_full_pass_with_no_request(void) {
    static probe_t p;
    static watch_probe_t w;
    probe_init(&p);
    atomic_store(&w.polls, 0);
    atomic_store(&w.moved_left, 1);
    p.watch = &w;
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    firc_nfcommit_set_watch(c, watch_fn, 1);
    firc_nfcommit_start(c);
    AWAIT(&p, p.finished >= 1);
    await_polls(&w, atomic_load(&w.polls) + 3);
    ASSERT_EQ_FMT(1, p.full_passes, "%d");
    ASSERT_EQ_FMT(0, p.partial_passes, "%d");
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

TEST an_unmoved_table_gets_no_pass(void) {
    static probe_t p;
    static watch_probe_t w;
    probe_init(&p);
    atomic_store(&w.polls, 0);
    atomic_store(&w.moved_left, 0);
    p.watch = &w;
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    firc_nfcommit_set_watch(c, watch_fn, 1);
    firc_nfcommit_start(c);
    await_polls(&w, 5);
    ASSERT(atomic_load(&w.polls) >= 5);
    ASSERT_EQ_FMT(0, p.started, "%d");
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

TEST the_watch_looks_once_an_interval(void) {
    static probe_t p;
    static watch_probe_t w;
    probe_init(&p);
    atomic_store(&w.polls, 0);
    atomic_store(&w.moved_left, 0);
    p.watch = &w;
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_watch(c, watch_fn, 50);
    firc_nfcommit_start(c);
    nanosleep(&(struct timespec){.tv_nsec = 240000000L}, NULL);
    int polls = atomic_load(&w.polls);
    tracked_free(c);
    probe_destroy(&p);
    ASSERT(polls >= 2 && polls <= 20);
    PASS();
}

TEST the_watch_keeps_looking_after_a_pass(void) {
    static probe_t p;
    static watch_probe_t w;
    probe_init(&p);
    atomic_store(&w.polls, 0);
    atomic_store(&w.moved_left, 0);
    p.watch = &w;
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    firc_nfcommit_set_watch(c, watch_fn, 1);
    firc_nfcommit_start(c);
    atomic_store(&w.moved_left, 1);
    AWAIT(&p, p.finished >= 1);
    atomic_store(&w.moved_left, 1);
    AWAIT(&p, p.finished >= 2);
    ASSERT_EQ_FMT(2, p.full_passes, "%d");
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

TEST the_watch_does_not_look_during_a_pass(void) {
    static probe_t p;
    static watch_probe_t w;
    probe_init(&p);
    atomic_store(&w.polls, 0);
    atomic_store(&w.moved_left, 0);
    p.watch = &w;
    p.gate_at = 1;
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    firc_nfcommit_set_watch(c, watch_fn, 1);
    firc_nfcommit_request(c);
    firc_nfcommit_start(c);
    AWAIT(&p, p.started >= 1);
    atomic_store(&w.polls, 0);
    nanosleep(&(struct timespec){.tv_nsec = 30000000L}, NULL);
    ASSERT_EQ_FMT(0, atomic_load(&w.polls), "%d");
    set_gate(&p, 0);
    AWAIT(&p, p.finished >= 1);
    await_polls(&w, 2);
    ASSERT(atomic_load(&w.polls) >= 2);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

TEST a_request_is_served_without_a_look(void) {
    static probe_t p;
    static watch_probe_t w;
    probe_init(&p);
    atomic_store(&w.polls, 0);
    atomic_store(&w.moved_left, 0);
    p.watch = &w;
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    firc_nfcommit_set_watch(c, watch_fn, 60000);
    firc_nfcommit_start(c);
    nanosleep(&(struct timespec){.tv_nsec = 30000000L}, NULL);
    firc_nfcommit_request(c);
    AWAIT(&p, p.finished >= 1);
    ASSERT_EQ_FMT(0, atomic_load(&w.polls), "%d");
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

TEST stop_does_not_wait_out_the_watch(void) {
    static probe_t p;
    static watch_probe_t w;
    probe_init(&p);
    atomic_store(&w.polls, 0);
    atomic_store(&w.moved_left, 0);
    p.watch = &w;
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_watch(c, watch_fn, 60000);
    firc_nfcommit_start(c);
    nanosleep(&(struct timespec){.tv_nsec = 30000000L}, NULL);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_nfcommit_stop(c);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ASSERT(t1.tv_sec - t0.tv_sec < 5);
    ASSERT_EQ_FMT(0, atomic_load(&w.polls), "%d");
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: first_pending false at start, cleared by a failed pass, or left set after a completed one. */
TEST the_first_write_is_pending_until_a_pass_completes(void) {
    static probe_t p;
    probe_init(&p);
    p.fail_times = 2;
    p.fail_with = FIRC_ERR_IO;
    p.gate_at = 3;
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);
    ASSERTm("before start", health_of(c).first_pending);
    firc_nfcommit_start(c);
    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 3);
    ASSERTm("a failed pass writes nothing", health_of(c).first_pending);
    set_gate(&p, 0);
    AWAIT(&p, p.finished >= 1);
    bool cleared = false;
    for (int i = 0; i < 2000 && !cleared; i++) {
        cleared = !health_of(c).first_pending;
        if (!cleared) { sleep_ms(1); }
    }
    ASSERTm("the completed pass ends it", cleared);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a request made before the thread starts being lost. */
TEST request_before_start_is_served(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = tracked_new(probe_rebuild, &p);
    firc_nfcommit_set_delays_for_test(c, 1, 4);

    firc_nfcommit_request(c);
    ASSERT_EQ(0u, firc_nfcommit_passes(c));

    ASSERT_EQ(FIRC_OK, firc_nfcommit_start(c));
    AWAIT(&p, p.finished >= 1);

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: a stop waiting for the write in flight to finish. */
TEST stop_aborts_a_running_rebuild(void) {
    static probe_t p;
    probe_init(&p);
    p.block = true;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);

    firc_nfcommit_stop(c);
    ASSERT(p.interrupted >= 1);

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: an interrupt scheduling a rebuild of its own, or losing the interrupted pass. */
TEST interrupt_yields_without_asking_for_more_work(void) {
    static probe_t p;
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

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

TEST idle_committer_does_nothing(void) {
    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_committer(&p);

    sleep_ms(50);
    ASSERT_EQ(0u, firc_nfcommit_passes(c));

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

TEST null_and_double_stop_are_safe(void) {
    firc_nfcommit_request(NULL);
    firc_nfcommit_stop(NULL);
    tracked_free(NULL);
    ASSERT_EQ(0u, firc_nfcommit_passes(NULL));
    ASSERT(tracked_new(NULL, NULL) == NULL);

    static probe_t p;
    probe_init(&p);
    firc_nfcommit_t *c = start_committer(&p);
    firc_nfcommit_stop(c);
    firc_nfcommit_stop(c);
    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: request_more aborting the pass in flight like request, or not scheduling a pass. */
TEST request_more_does_not_interrupt_but_still_schedules(void) {
    static probe_t p;
    probe_init(&p);
    p.block = true;
    firc_nfcommit_t *c = start_committer(&p);

    firc_nfcommit_request(c);
    AWAIT(&p, p.started >= 1);

    for (int i = 0; i < 5; i++) { firc_nfcommit_request_more(c); }

    ASSERT_FALSEm("request_more must not raise the cancellation token",
                  firc_cancel_raised(p.cancel));

    pthread_mutex_lock(&p.mu);
    p.release = true;
    p.block = false;
    pthread_mutex_unlock(&p.mu);

    AWAIT(&p, p.finished >= 1);
    ASSERT_EQ_FMTm("the pass that was running finished rather than restarting", 0, p.interrupted,
                   "%d");

    AWAIT(&p, p.started >= 2);

    tracked_free(c);
    probe_destroy(&p);
    PASS();
}

/* Catches: the cancel token cleared after the pass publishes it is running, losing an interrupt. */
TEST an_interrupt_at_the_instant_a_pass_begins_is_not_lost(void) {
    int lost = 0;
    int skipped = 0;
    for (int round = 0; round < 60; round++) {
        static probe_t p;
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
            tracked_free(c);
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

        tracked_free(c);
        probe_destroy(&p);
    }
    ASSERT_EQ_FMTm("an interrupt raised while a pass is running must abort it", 0, lost, "%d");
    ASSERTm("too few rounds observed a running pass to mean anything", skipped < 45);
    PASS();
}

static void teardown(void *arg) {
    (void)arg;
    for (size_t i = 0; i < sizeof(g_live) / sizeof(g_live[0]); i++) { tracked_free(g_live[i]); }
    firc_logrep_set_clock_for_test(NULL);
    if (g_log_pipe[0] >= 0) { (void)log_capture_end(); }
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(request_triggers_a_rebuild);
    RUN_TEST(the_first_pass_wipes_and_only_a_table_change_wipes_again);
    RUN_TEST(request_does_not_wait_for_the_write);
    RUN_TEST(request_interrupts_and_restarts);
    RUN_TEST(request_more_does_not_interrupt_but_still_schedules);
    RUN_TEST(an_address_request_settles_short);
    RUN_TEST(an_address_request_after_an_idle_stretch_settles_short);
    RUN_TEST(an_address_request_right_after_a_pass_settles_long);
    RUN_TEST(a_more_request_settles_long);
    RUN_TEST(a_full_request_during_a_short_settle_waits_the_long_one);
    RUN_TEST(the_first_pass_settles_long);
    RUN_TEST(a_failed_address_pass_still_backs_off);
    RUN_TEST(a_raced_address_pass_retries_after_the_long_settle);
    RUN_TEST(a_canceled_more_pass_retries_after_the_long_settle);
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
    RUN_TEST(a_refusal_that_persists_warns_then_errs_after_a_minute);
    RUN_TEST(races_neither_count_toward_the_escalation_nor_break_it);
    RUN_TEST(a_race_streak_says_nothing_above_debug);
    RUN_TEST(a_race_run_past_the_bound_warns_once);
    RUN_TEST(a_race_run_errs_a_minute_after_its_first_race);
    RUN_TEST(races_within_the_bound_are_not_failing);
    RUN_TEST(races_past_the_bound_are_failing);
    RUN_TEST(a_completed_pass_starts_the_bound_over);
    RUN_TEST(the_first_write_is_pending_until_a_pass_completes);
    RUN_TEST(a_moved_table_gets_a_full_pass_with_no_request);
    RUN_TEST(an_unmoved_table_gets_no_pass);
    RUN_TEST(the_watch_looks_once_an_interval);
    RUN_TEST(the_watch_keeps_looking_after_a_pass);
    RUN_TEST(the_watch_does_not_look_during_a_pass);
    RUN_TEST(a_request_is_served_without_a_look);
    RUN_TEST(stop_does_not_wait_out_the_watch);
    GREATEST_MAIN_END();
}
