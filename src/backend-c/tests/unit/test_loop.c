#include "greatest.h"

#include <dirent.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include "firc/loop.h"

/* A one-shot timer that stops the loop. */
static void stop_timer_cb(firc_loop_t *loop, void *ud)
{
    int *fired = ud;
    (*fired)++;
    firc_loop_stop(loop);
}

TEST oneshot_timer_fires_and_stops(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    int fired = 0;
    ASSERT_EQ(FIRC_OK,
              firc_loop_add_timer(loop, 10, 0, stop_timer_cb, &fired, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ(1, fired);
    firc_loop_destroy(loop);
    PASS();
}

/* catches: a stop that outlives its run, so every later run returns before anything is dispatched */
TEST a_stop_ends_one_run_only(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    int first = 0;
    int second = 0;
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 10, 0, stop_timer_cb, &first, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 30, 0, stop_timer_cb, &second, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ(1, first);
    ASSERT_EQ(1, second);
    firc_loop_destroy(loop);
    PASS();
}

struct periodic_ctx {
    int fires;
};

static void periodic_cb(firc_loop_t *loop, void *ud)
{
    struct periodic_ctx *ctx = ud;
    ctx->fires++;
    if (ctx->fires >= 3) {
        firc_loop_stop(loop);
    }
}

static void stop_after(firc_loop_t *loop, void *ud)
{
    (void)ud;
    firc_loop_stop(loop);
}

TEST periodic_timer_fires_repeatedly(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    struct periodic_ctx ctx = {0};
    ASSERT_EQ(FIRC_OK,
              firc_loop_add_timer(loop, 5, 5, periodic_cb, &ctx, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 2000, 0, stop_after, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ_FMTm("it kept firing", 3, ctx.fires, "%d");
    firc_loop_destroy(loop);
    PASS();
}

struct pipe_ctx {
    char buf[16];
    ssize_t n;
};

static void pipe_cb(firc_loop_t *loop, int fd, uint32_t events, void *ud)
{
    struct pipe_ctx *ctx = ud;
    (void)events;
    ctx->n = read(fd, ctx->buf, sizeof(ctx->buf));
    firc_loop_stop(loop);
}

TEST fd_readable_event_delivers_data(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));

    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    struct pipe_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ASSERT_EQ(FIRC_OK, firc_loop_add_fd(loop, fds[0], EPOLLIN, pipe_cb, &ctx));

    ASSERT_EQ(5, write(fds[1], "hello", 5));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ(5, ctx.n);
    ASSERT_EQ(0, memcmp(ctx.buf, "hello", 5));

    ASSERT_EQ(FIRC_OK, firc_loop_del_fd(loop, fds[0]));
    close(fds[0]);
    close(fds[1]);
    firc_loop_destroy(loop);
    PASS();
}

static void post_cb(firc_loop_t *loop, void *ud)
{
    int *hit = ud;
    (*hit)++;
    firc_loop_stop(loop);
}

static void *poster_thread(void *arg)
{
    firc_loop_t *loop = arg;
    struct timespec delay = {0, 10000000L};
    nanosleep(&delay, NULL);
    static int hit = 0;
    firc_loop_post(loop, post_cb, &hit);
    return &hit;
}

TEST cross_thread_post_executes_on_loop(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));

    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, poster_thread, loop));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));

    void *ret = NULL;
    pthread_join(th, &ret);
    ASSERT_EQ(1, *(int *)ret);
    firc_loop_destroy(loop);
    PASS();
}

typedef struct {
    int dropped;
    int last_payload;
} drop_log_t;

static void never_runs_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    (void)ud;
    abort();
}

typedef struct {
    drop_log_t *log;
    int payload;
} dropped_post_t;

static void count_drop(void *ud)
{
    dropped_post_t *p = ud;
    p->log->dropped++;
    p->log->last_payload = p->payload;
    free(p);
}

TEST an_undispatched_post_is_dropped_with_its_payload(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));

    drop_log_t log = {0, 0};
    for (int i = 1; i <= 3; i++) {
        dropped_post_t *p = malloc(sizeof(*p));
        ASSERT(p != NULL);
        p->log = &log;
        p->payload = i;
        ASSERT_EQ(FIRC_OK, firc_loop_post_with_drop(loop, never_runs_cb, p, count_drop));
    }

    firc_loop_destroy(loop);

    ASSERT_EQ_FMTm("every undispatched post was dropped", 3, log.dropped, "%d");
    ASSERT_EQ_FMTm("in the order they were posted", 3, log.last_payload, "%d");
    PASS();
}

/* Stops the loop and counts itself; only posts that did not run count as dropped. */
static void stop_and_count_cb(firc_loop_t *loop, void *ud)
{
    dropped_post_t *p = ud;
    p->log->last_payload = p->payload;
    free(p);
    firc_loop_stop(loop);
}

TEST a_dispatched_post_is_not_dropped(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));

    drop_log_t log = {0, 0};
    dropped_post_t *p = malloc(sizeof(*p));
    ASSERT(p != NULL);
    p->log = &log;
    p->payload = 7;
    ASSERT_EQ(FIRC_OK, firc_loop_post_with_drop(loop, stop_and_count_cb, p, count_drop));

    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    firc_loop_destroy(loop);

    ASSERT_EQ_FMTm("it ran", 7, log.last_payload, "%d");
    ASSERT_EQ_FMTm("and was not dropped on top of that", 0, log.dropped, "%d");
    PASS();
}

/* epoll does not order timers with one deadline: a round records which ran first, never asserts it. */
typedef struct {
    int second_id;
    int first_ran;
    int fired_after_delete;
    int ran_before_the_delete;
} pair_t;

static void arm_pair_first(firc_loop_t *loop, void *ud)
{
    pair_t *p = ud;
    p->first_ran = 1;
    firc_loop_del_timer(loop, p->second_id);
}

static void arm_pair_second(firc_loop_t *loop, void *ud)
{
    (void)loop;
    pair_t *p = ud;
    if (p->first_ran) {
        p->fired_after_delete = 1;
    } else {
        p->ran_before_the_delete = 1;
    }
}

/* Catches: a timer deleted by a callback in the same batch still fired. */
TEST a_watch_deleted_mid_batch_is_not_dispatched(void)
{
    int informative = 0;
    for (int round = 0; round < 20; round++) {
        firc_loop_t *loop = NULL;
        ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
        pair_t p = {0, 0, 0, 0};
        ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 5, 0, arm_pair_first, &p, NULL));
        ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 5, 0, arm_pair_second, &p, &p.second_id));
        ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 40, 0, stop_after, NULL, NULL));
        ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
        ASSERT_EQ_FMTm("a deleted timer fired", 0, p.fired_after_delete, "%d");
        if (p.first_ran && !p.ran_before_the_delete) { informative++; }
        firc_loop_destroy(loop);
    }
    ASSERTm("every round ran the victim first -- no deletion was ever tested",
            informative > 0);
    PASS();
}

typedef struct {
    firc_loop_t *loop;
    int victim_fd;
    bool kill_it;
    int ran;
    void **victim_ud;
} killer_t;

static int victim_ran;

static void victim_cb(firc_loop_t *loop, int fd, uint32_t events, void *ud) {
    (void)events;
    victim_ran++;
    firc_loop_del_fd(loop, fd);
    int *ran = ud;
    victim_ran += *ran;
}

static void killer_cb(firc_loop_t *loop, int fd, uint32_t events, void *ud) {
    (void)events;
    killer_t *k = ud;
    k->ran++;
    firc_loop_del_fd(loop, fd);
    if (!k->kill_it) { return; }
    firc_loop_del_fd(loop, k->victim_fd);
    free(*k->victim_ud);
    *k->victim_ud = NULL;
}

TEST an_fd_watch_deleted_mid_batch_is_not_dispatched(void)
{
    for (int round = 0; round < 20; round++) {
        firc_loop_t *loop = NULL;
        ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
        int a[2], b[2];
        ASSERT_EQ(0, pipe(a));
        ASSERT_EQ(0, pipe(b));
        ASSERT_EQ(1, write(a[1], "x", 1));
        ASSERT_EQ(1, write(b[1], "x", 1));
        int *owned = calloc(1, sizeof(int));
        ASSERT(owned != NULL);
        void *victim_ud = owned;
        victim_ran = 0;
        killer_t k = {loop, b[0], round > 0, 0, &victim_ud};
        ASSERT_EQ(FIRC_OK, firc_loop_add_fd(loop, a[0], EPOLLIN, killer_cb, &k));
        ASSERT_EQ(FIRC_OK, firc_loop_add_fd(loop, b[0], EPOLLIN, victim_cb, owned));
        ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 30, 0, stop_after, NULL, NULL));
        ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
        ASSERT_EQ_FMTm("the killer's own event was delivered", 1, k.ran, "%d");
        if (round == 0) {
            ASSERT_EQ_FMTm("the control round: both events are in one batch, so the victim ran", 1, victim_ran,
                           "%d");
            free(victim_ud);
        } else {
            ASSERT_EQ_FMTm("a deleted fd watch's callback ran, on memory that is gone", 0, victim_ran, "%d");
        }
        firc_loop_destroy(loop);
        close(a[0]);
        close(a[1]);
        close(b[0]);
        close(b[1]);
    }
    PASS();
}

TEST del_timer_prevents_firing(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    int fired = 0;
    int cancel_id = 0;
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 50, 0, stop_timer_cb, &fired,
                                       &cancel_id));
    ASSERT_EQ(FIRC_OK, firc_loop_del_timer(loop, cancel_id));
    int stop_fired = 0;
    ASSERT_EQ(FIRC_OK,
              firc_loop_add_timer(loop, 80, 0, stop_timer_cb, &stop_fired,
                                NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ(0, fired);
    ASSERT_EQ(1, stop_fired);
    firc_loop_destroy(loop);
    PASS();
}

/* A thread that outlives the call, doing nothing. */
static void *idle_thread(void *ud) {
    int *stop = ud;
    struct timespec ts = {0, 1000000};
    while (!__atomic_load_n(stop, __ATOMIC_ACQUIRE)) { nanosleep(&ts, NULL); }
    return NULL;
}

static void signal_cb(firc_loop_t *loop, int signo, void *ud) {
    int *got = ud;
    *got = signo;
    firc_loop_stop(loop);
}

/* Catches: a signal blocked only after other threads exist, so one of them dies of it. */
TEST a_signal_blocked_before_a_thread_starts_reaches_the_loop(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    ASSERT_EQ(FIRC_OK, firc_loop_block_signals(&set));

    int stop = 0;
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, idle_thread, &stop));

    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    int got = 0;
    ASSERT_EQ(FIRC_OK, firc_loop_add_signals(loop, &set, signal_cb, &got));
    ASSERT_EQ(0, kill(getpid(), SIGTERM));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ_FMTm("the loop read it, the process did not die of it", SIGTERM, got, "%d");

    __atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
    pthread_join(th, NULL);
    firc_loop_destroy(loop);
    PASS();
}

static void count_timer_cb(firc_loop_t *loop, void *ud) {
    (void)loop;
    (*(int *)ud)++;
}

static size_t open_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) { return 0; }
    size_t n = 0;
    while (readdir(d) != NULL) { n++; }
    closedir(d);
    return n;
}

typedef struct {
    firc_loop_t *loop;
    size_t fds_at_the_end;
    int fired;
} fd_probe_t;

static void probe_stop_cb(firc_loop_t *loop, void *ud) {
    fd_probe_t *p = ud;
    p->fds_at_the_end = open_fds();
    firc_loop_stop(loop);
}

static void probe_fire_cb(firc_loop_t *loop, void *ud) {
    (void)loop;
    ((fd_probe_t *)ud)->fired++;
}

TEST a_one_shot_timer_that_has_fired_is_retired(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    fd_probe_t p = {loop, 0, 0};
    size_t before = open_fds();
    for (int i = 0; i < 50; i++) {
        ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 1 + (uint64_t)(i % 5), 0, probe_fire_cb, &p, NULL));
    }
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 120, 0, probe_stop_cb, &p, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ_FMTm("all fifty fired", 50, p.fired, "%d");
    ASSERTm("the fired timers left their descriptors behind", p.fds_at_the_end <= before + 2);
    firc_loop_destroy(loop);
    PASS();
}

TEST a_periodic_timer_survives_its_first_firing(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    int fired = 0;
    int id = 0;
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 1, 1, count_timer_cb, &fired, &id));
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 40, 0, stop_timer_cb, &fired, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERTm("it fired more than once", fired > 2);
    ASSERT_EQ_FMTm("and is still there to be deleted", FIRC_OK, firc_loop_del_timer(loop, id), "%d");
    firc_loop_destroy(loop);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(oneshot_timer_fires_and_stops);
    RUN_TEST(a_stop_ends_one_run_only);
    RUN_TEST(periodic_timer_fires_repeatedly);
    RUN_TEST(fd_readable_event_delivers_data);
    RUN_TEST(cross_thread_post_executes_on_loop);
    RUN_TEST(an_undispatched_post_is_dropped_with_its_payload);
    RUN_TEST(a_dispatched_post_is_not_dropped);
    RUN_TEST(a_watch_deleted_mid_batch_is_not_dispatched);
    RUN_TEST(an_fd_watch_deleted_mid_batch_is_not_dispatched);
    RUN_TEST(del_timer_prevents_firing);
    RUN_TEST(a_one_shot_timer_that_has_fired_is_retired);
    RUN_TEST(a_periodic_timer_survives_its_first_firing);
    RUN_TEST(a_signal_blocked_before_a_thread_starts_reaches_the_loop);
    GREATEST_MAIN_END();
}
