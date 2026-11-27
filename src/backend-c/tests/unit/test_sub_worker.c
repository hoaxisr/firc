#include "greatest.h"

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "firc/hash.h"
#include "firc/httpd.h"
#include "firc/listcache.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/sub_fetch.h"
#include "firc/sub_worker.h"
#include "firc/subparse.h"

#define TEST_PORT 18120

#define BIG_LINES 100000u

typedef struct list_ud {
    const char *body;
} list_ud_t;

static void h_list(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    list_ud_t *l = ud;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)l->body, strlen(l->body));
}

static void h_notfound(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "nope";
    firc_http_res_write(res, 404, "text/plain", (const uint8_t *)body, sizeof(body) - 1);
}

/* Answers after 300 ms, blocking the stub's loop, so a fetch is still in flight when cancelled. */
static void h_slow(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 300 * 1000 * 1000L};
    nanosleep(&ts, NULL);
    static const char body[] = "slow.example";
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, sizeof(body) - 1);
}

static list_ud_t g_list_a = {.body = "one.example\ntwo.example"};
static list_ud_t g_list_b = {.body = "three.example"};
static list_ud_t g_list_big = {.body = NULL};

static list_ud_t g_list_mix = {
    .body = "{\"rules\":[{\"domain\":[\"a.com\"],\"network\":\"udp\"},{\"bogus\":1}]}"};

static list_ud_t g_list_html = {.body = "<!DOCTYPE html><html></html>"};

static char *build_big_list(void) {
    size_t cap = (size_t)BIG_LINES * 16 + 1;
    char *s = malloc(cap);
    if (s == NULL) { return NULL; }
    size_t off = 0;
    for (unsigned i = 0; i < BIG_LINES; i++) {
        int n = snprintf(s + off, cap - off, "d%u.example\n", i);
        if (n <= 0) {
            free(s);
            return NULL;
        }
        off += (size_t)n;
    }
    if (off > 0) { s[off - 1] = '\0'; }
    return s;
}

typedef struct sink {
    pthread_mutex_t mu;
    firc_sub_event_t *ev[64];
    size_t n;
    size_t n_fetch;
    size_t n_fetch_partial;
    size_t n_parse;
    uint64_t first_parse_ms;
    firc_cancel_t *raise_on_parse;
    size_t raise_at_lines;
    size_t refuse_results;
    bool refuse_progress;
    bool refuse_all;
    size_t result_offers;
    size_t progress_refused;
    bool offered_twice;
} sink_t;

static sink_t *g_open_sink = NULL;

static uint64_t mono_ms(void);

static void sink_init(sink_t *s) {
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->mu, NULL);
    g_open_sink = s;
}

static bool sink_refuses(sink_t *s, firc_sub_event_t *ev) {
    if (ev->http_status == -1) { s->offered_twice = true; }
    if (ev->kind == FIRC_SUB_EV_RESULT) { s->result_offers++; }
    bool refuse = s->refuse_all || (ev->kind == FIRC_SUB_EV_PROGRESS && s->refuse_progress);
    if (!refuse && ev->kind == FIRC_SUB_EV_RESULT && s->refuse_results > 0) {
        s->refuse_results--;
        refuse = true;
    }
    if (refuse && ev->kind == FIRC_SUB_EV_PROGRESS) {
        s->progress_refused++;
        ev->http_status = -1;
    }
    return refuse;
}

static bool sink_emit(void *ud, firc_sub_event_t *ev) {
    sink_t *s = ud;
    pthread_mutex_lock(&s->mu);
    if (sink_refuses(s, ev)) {
        pthread_mutex_unlock(&s->mu);
        return false;
    }
    if (ev->kind == FIRC_SUB_EV_PROGRESS) {
        if (ev->stage == FIRC_SUB_STAGE_FETCH) {
            s->n_fetch++;
            if (!(ev->total > 0 && ev->bytes == ev->total)) { s->n_fetch_partial++; }
        } else {
            s->n_parse++;
            if (s->first_parse_ms == 0) { s->first_parse_ms = mono_ms(); }
            if (s->raise_on_parse != NULL && ev->lines == s->raise_at_lines) {
                firc_cancel_raise(s->raise_on_parse);
            }
        }
    }
    if (s->n < 64) {
        s->ev[s->n++] = ev;
    } else {
        firc_sub_event_free(ev);
    }
    pthread_mutex_unlock(&s->mu);
    return true;
}

static void sink_free(sink_t *s) {
    if (g_open_sink == s) { g_open_sink = NULL; }
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->n; i++) { firc_sub_event_free(s->ev[i]); }
    s->n = 0;
    pthread_mutex_unlock(&s->mu);
    pthread_mutex_destroy(&s->mu);
}

static size_t sink_count(sink_t *s, firc_sub_event_kind_t kind) {
    size_t c = 0;
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->n; i++) {
        if (s->ev[i]->kind == kind) { c++; }
    }
    pthread_mutex_unlock(&s->mu);
    return c;
}

/* The i-th event of `kind`; the pointer stays good until sink_free. */
static const firc_sub_event_t *sink_nth(sink_t *s, firc_sub_event_kind_t kind, size_t idx) {
    const firc_sub_event_t *found = NULL;
    size_t c = 0;
    pthread_mutex_lock(&s->mu);
    for (size_t i = 0; i < s->n; i++) {
        if (s->ev[i]->kind == kind && c++ == idx) {
            found = s->ev[i];
            break;
        }
    }
    pthread_mutex_unlock(&s->mu);
    return found;
}

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void sleep_ms(unsigned ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Polls until `n` events of `kind` have arrived, or `ms` pass. */
static bool wait_events(sink_t *s, firc_sub_event_kind_t kind, size_t n, unsigned ms) {
    uint64_t deadline = mono_ms() + ms;
    for (;;) {
        if (sink_count(s, kind) >= n) { return true; }
        if (mono_ms() >= deadline) { return sink_count(s, kind) >= n; }
        sleep_ms(5);
    }
}

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *srv;
    pthread_t thread;
} harness_t;

static void *loop_thread(void *ud) {
    harness_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

static void harness_stop(harness_t *h);
static harness_t *g_open_harness = NULL;
static firc_sub_worker_t *g_open_worker = NULL;

static void stop_open_harness(void *unused) {
    (void)unused;
    if (g_open_worker != NULL) {
        firc_sub_worker_t *w = g_open_worker;
        g_open_worker = NULL;
        firc_sub_worker_free(w);
    }
    if (g_open_harness != NULL) {
        harness_t *h = g_open_harness;
        g_open_harness = NULL;
        harness_stop(h);
    }
    if (g_open_sink != NULL) { sink_free(g_open_sink); }
}

/* firc_sub_worker_new, recorded so a failed test's worker is still freed. */
static firc_sub_worker_t *worker_new(size_t capacity, firc_sub_event_fn emit, void *ud) {
    g_open_worker = firc_sub_worker_new(capacity, emit, ud, NULL);
    return g_open_worker;
}

static firc_sub_worker_t *worker_new_in(const char *dir, firc_sub_event_fn emit, void *ud) {
    g_open_worker = firc_sub_worker_new(FIRC_SUB_WORKER_CAPACITY, emit, ud, dir);
    return g_open_worker;
}

static void worker_free(firc_sub_worker_t *w) {
    if (g_open_worker == w) { g_open_worker = NULL; }
    firc_sub_worker_free(w);
}

/* Frees a half-built harness: the fixed port may still be held by an earlier failed test. */
static void harness_abandon(harness_t *h) {
    if (h == NULL) { return; }
    if (h->srv != NULL) { firc_httpd_destroy(h->srv); }
    if (h->loop != NULL) { firc_loop_destroy(h->loop); }
    free(h);
}

static harness_t *harness_start(void) {
    harness_t *h = calloc(1, sizeof(*h));
    if (h == NULL) { return NULL; }
    if (firc_loop_create(&h->loop) != FIRC_OK) {
        harness_abandon(h);
        return NULL;
    }
    if (firc_httpd_create(h->loop, &h->srv) != FIRC_OK) {
        harness_abandon(h);
        return NULL;
    }
    firc_httpd_route(h->srv, "GET", "/a", h_list, &g_list_a);
    firc_httpd_route(h->srv, "GET", "/b", h_list, &g_list_b);
    firc_httpd_route(h->srv, "GET", "/big", h_list, &g_list_big);
    firc_httpd_route(h->srv, "GET", "/slow", h_slow, NULL);
    firc_httpd_route(h->srv, "GET", "/404", h_notfound, NULL);
    firc_httpd_route(h->srv, "GET", "/mix", h_list, &g_list_mix);
    firc_httpd_route(h->srv, "GET", "/html", h_list, &g_list_html);
    if (firc_httpd_listen_tcp(h->srv, "127.0.0.1", TEST_PORT) != FIRC_OK) {
        harness_abandon(h);
        return NULL;
    }
    pthread_create(&h->thread, NULL, loop_thread, h);
    g_open_harness = h;
    return h;
}

static void harness_stop(harness_t *h) {
    if (g_open_harness == h) { g_open_harness = NULL; }
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->srv);
    firc_loop_destroy(h->loop);
    free(h);
}

static char g_url[128];
static const char *url_for(const char *path) {
    snprintf(g_url, sizeof(g_url), "http://127.0.0.1:%d%s", TEST_PORT, path);
    return g_url;
}

static firc_id_t id_of(uint8_t b) {
    firc_id_t id = {{b, b, b, b}};
    return id;
}

static firc_sub_job_t job_for(uint8_t id_byte, const char *path, uint64_t seq) {
    firc_sub_job_t j;
    memset(&j, 0, sizeof(j));
    j.group_id = id_of(id_byte);
    j.url = strdup(url_for(path));
    j.seq = seq;
    return j;
}

/* Catches: no started event, parsed rules dropped, or a result for a job other than the one run. */
TEST a_job_posts_started_then_a_parsed_result(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_job_t job = job_for(0x11, "/a", 1);
    firc_sub_job_run(&job, NULL, NULL, sink_emit, &s);
    free(job.url);

    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_STARTED));
    const firc_sub_event_t *st = sink_nth(&s, FIRC_SUB_EV_STARTED, 0);
    ASSERT(st != NULL);
    ASSERT_EQ(FIRC_SUB_EV_STARTED, st->kind);
    ASSERTm("the first event is the one that says the job was taken", s.ev[0] == st);

    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_RESULT));
    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT_EQ(2u, r->rules.n);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&r->rules, 0));
    ASSERT_STR_EQ("two.example", firc_sub_rules_text(&r->rules, 1));
    ASSERT_EQ(0u, r->dropped);
    ASSERT_EQ((uint64_t)1, r->seq);
    ASSERT_MEM_EQ(id_of(0x11).b, r->group_id.b, sizeof(r->group_id.b));

    sink_free(&s);
    harness_stop(h);
    PASS();
}

TEST a_sing_box_body_reports_unconstrained_and_dropped(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_job_t job = job_for(0x55, "/mix", 1);
    firc_sub_job_run(&job, NULL, NULL, sink_emit, &s);
    free(job.url);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT_EQ_FMT((size_t)1, r->rules.n, "%zu");
    ASSERT_STR_EQ("a.com", firc_sub_rules_text(&r->rules, 0));
    ASSERT_EQ_FMTm("the name taken without its network/port", (size_t)1, r->unconstrained, "%zu");
    ASSERT_EQ_FMTm("the object nothing could be made of", (size_t)1, r->dropped, "%zu");

    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: a parse refusal losing its reason on the way to the result. */
TEST an_html_body_is_an_error_with_the_reason(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_job_t job = job_for(0x66, "/html", 1);
    firc_sub_job_run(&job, NULL, NULL, sink_emit, &s);
    free(job.url);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_ERROR, r->result);
    ASSERT_EQm("a parse refusal, not a fetch one", FIRC_ERR_INVAL, r->err);
    ASSERT(r->why != NULL);
    ASSERTm("the reason names the raw-file fix", strstr(r->why, "raw") != NULL);
    ASSERT_EQ(0u, r->rules.n);

    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: a hash not of the body, or a known body parsed again. */
TEST the_same_bytes_are_unchanged_and_carry_no_rules(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static const uint8_t want[FIRC_SHA256_DIGEST_LEN] = {
        0x67, 0xc9, 0x27, 0x1d, 0x2a, 0x37, 0xe1, 0x56, 0x90, 0x77, 0x3c,
        0xb6, 0xa4, 0xeb, 0xfa, 0xf9, 0xef, 0x74, 0x4e, 0x54, 0x4d, 0x61,
        0x1d, 0x45, 0xd0, 0x40, 0x69, 0x6b, 0x2b, 0xf3, 0x2a, 0x4f};

    static sink_t s;
    sink_init(&s);
    firc_sub_job_t first = job_for(0x22, "/a", 1);
    firc_sub_job_run(&first, NULL, NULL, sink_emit, &s);
    free(first.url);
    const firc_sub_event_t *r1 = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r1 != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r1->result);
    ASSERT_MEM_EQ(want, r1->hash, sizeof(want));

    static sink_t s2;
    sink_init(&s2);
    firc_sub_job_t second = job_for(0x22, "/a", 2);
    second.has_hash = true;
    memcpy(second.expected_hash, want, sizeof(want));
    firc_sub_job_run(&second, NULL, NULL, sink_emit, &s2);
    free(second.url);

    const firc_sub_event_t *r2 = sink_nth(&s2, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r2 != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_UNCHANGED, r2->result);
    ASSERT_EQ(0u, r2->rules.n);
    ASSERT_EQ(0u, s2.n_parse);
    ASSERT_MEM_EQm("an unchanged result still carries the hash it fetched", want, r2->hash,
                   sizeof(want));

    static sink_t s3;
    sink_init(&s3);
    firc_sub_job_t third = job_for(0x22, "/a", 3);
    third.has_hash = true;
    memset(third.expected_hash, 0xAB, sizeof(third.expected_hash));
    firc_sub_job_run(&third, NULL, NULL, sink_emit, &s3);
    free(third.url);
    const firc_sub_event_t *r3 = sink_nth(&s3, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r3 != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r3->result);
    ASSERT_EQ(2u, r3->rules.n);

    sink_free(&s);
    sink_free(&s2);
    sink_free(&s3);
    harness_stop(h);
    PASS();
}

/* Catches: a 404 reported as a transport failure without its status. */
TEST a_404_is_an_error_with_the_status(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_job_t job = job_for(0x33, "/404", 7);
    firc_sub_job_run(&job, NULL, NULL, sink_emit, &s);
    free(job.url);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_ERROR, r->result);
    ASSERT_EQm("a server that answered is not a transport failure", FIRC_ERR_PROTO, r->err);
    ASSERT_EQ(404L, r->http_status);
    ASSERT_EQ(0u, r->rules.n);
    ASSERT_EQ((uint64_t)7, r->seq);

    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: an unusable url reported like a 404 or a network failure. */
TEST an_unusable_url_is_an_error_with_no_status(void) {
    static sink_t s;
    sink_init(&s);

    firc_sub_job_t job;
    memset(&job, 0, sizeof(job));
    job.group_id = id_of(0x77);
    job.url = strdup("ftp://127.0.0.1/list");
    job.seq = 9;
    firc_sub_job_run(&job, NULL, NULL, sink_emit, &s);
    free(job.url);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_ERROR, r->result);
    ASSERT_EQm("a url that is not http(s) is a bad argument", FIRC_ERR_INVAL, r->err);
    ASSERT_EQm("nothing answered, so there is no code to show", 0L, r->http_status);
    ASSERT_EQ((uint64_t)9, r->seq);

    sink_free(&s);
    PASS();
}

TEST progress_is_posted_and_rate_limited(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_job_t job = job_for(0x44, "/big", 1);
    uint64_t t0 = mono_ms();
    firc_sub_job_run(&job, NULL, NULL, sink_emit, &s);
    free(job.url);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT_EQ((size_t)BIG_LINES, r->rules.n);

    ASSERTm("the fetch reported at least once", s.n_fetch >= 1);
    ASSERT_EQm("100 000 lines is five reports of every 20 000",
               (size_t)(BIG_LINES / FIRC_SUB_PARSE_PROGRESS_LINES), s.n_parse);
    ASSERTm("the parse reported, so there is a fetch span to measure", s.first_parse_ms != 0);
    uint64_t fetch_ms = s.first_parse_ms - t0;
    size_t allowed = (size_t)(fetch_ms / 200) + 1;
    ASSERT_GTEm("the fetch progress is rate-limited", allowed, s.n_fetch_partial);

    sink_free(&s);
    harness_stop(h);
    PASS();
}

TEST a_stalled_fetch_is_rate_limited_too(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_job_t job = job_for(0x46, "/slow", 1);
    uint64_t t0 = mono_ms();
    firc_sub_job_run(&job, NULL, NULL, sink_emit, &s);
    uint64_t elapsed = mono_ms() - t0;
    free(job.url);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);

    size_t allowed = (size_t)(elapsed / 200) + 1;
    ASSERT_GTEm("a fetch that has received nothing reports no more often than one that has",
                allowed, s.n_fetch_partial);

    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: a cancelled job posting its result, or a free that waits out the fetch timeout. */
TEST cancel_mid_fetch_posts_no_result(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_worker_t *w = worker_new(FIRC_SUB_WORKER_CAPACITY, sink_emit, &s);
    ASSERT(w != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));
    firc_sub_job_t job = job_for(0x55, "/slow", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &job));

    ASSERTm("the worker took the job", wait_events(&s, FIRC_SUB_EV_STARTED, 1, 2000));
    uint64_t t0 = mono_ms();
    worker_free(w);
    uint64_t took = mono_ms() - t0;

    ASSERT_EQm("a cancelled job posts no result", 0u, sink_count(&s, FIRC_SUB_EV_RESULT));
    ASSERTm("the free did not wait out the fetch timeout", took < 1000);

    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: enqueue appending a second job for a waiting id instead of replacing it. */
TEST enqueue_folds_by_id_while_waiting(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_worker_t *w = worker_new(2, sink_emit, &s);
    ASSERT(w != NULL);

    firc_sub_job_t a1 = job_for(0xA1, "/a", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &a1));
    ASSERT_EQ(1u, firc_sub_worker_waiting_for_test(w));

    firc_sub_job_t a2 = job_for(0xA1, "/b", 2);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &a2));
    ASSERT_EQm("a second job for a waiting id takes its slot", 1u,
               firc_sub_worker_waiting_for_test(w));

    firc_sub_job_t b1 = job_for(0xB2, "/a", 3);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &b1));
    ASSERT_EQ(2u, firc_sub_worker_waiting_for_test(w));

    firc_sub_job_t c1 = job_for(0xC3, "/a", 4);
    ASSERT_EQm("a full queue refuses the next id", FIRC_ERR_LIMIT,
               firc_sub_worker_enqueue(w, &c1));
    ASSERT_EQ(2u, firc_sub_worker_waiting_for_test(w));

    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));
    ASSERT(wait_events(&s, FIRC_SUB_EV_RESULT, 2, 5000));
    ASSERT_EQ(2u, sink_count(&s, FIRC_SUB_EV_RESULT));

    const firc_sub_event_t *first = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(first != NULL);
    ASSERT_MEM_EQm("the folded job kept its place in line", id_of(0xA1).b, first->group_id.b,
                   sizeof(first->group_id.b));
    ASSERT_EQm("the newer seq is the one that ran", (uint64_t)2, first->seq);
    ASSERT_EQm("...with the newer url: /b is one rule, /a is two", 1u, first->rules.n);
    ASSERT_STR_EQ("three.example", firc_sub_rules_text(&first->rules, 0));

    const firc_sub_event_t *second = sink_nth(&s, FIRC_SUB_EV_RESULT, 1);
    ASSERT(second != NULL);
    ASSERT_MEM_EQ(id_of(0xB2).b, second->group_id.b, sizeof(second->group_id.b));
    ASSERT_EQ((uint64_t)3, second->seq);

    worker_free(w);
    sink_free(&s);
    harness_stop(h);
    PASS();
}

TEST a_follow_up_enqueued_while_running_runs_once_after(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_worker_t *w = worker_new(FIRC_SUB_WORKER_CAPACITY, sink_emit, &s);
    ASSERT(w != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));

    firc_sub_job_t slow = job_for(0xD4, "/slow", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &slow));
    ASSERTm("the slow job is running", wait_events(&s, FIRC_SUB_EV_STARTED, 1, 2000));

    firc_sub_job_t f2 = job_for(0xD4, "/a", 2);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &f2));
    firc_sub_job_t f3 = job_for(0xD4, "/b", 3);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &f3));
    ASSERT_EQm("two follow-ups for one id are one job", 1u, firc_sub_worker_waiting_for_test(w));

    ASSERT(wait_events(&s, FIRC_SUB_EV_RESULT, 2, 5000));
    sleep_ms(300);
    ASSERT_EQm("exactly the two jobs ran", 2u, sink_count(&s, FIRC_SUB_EV_RESULT));

    const firc_sub_event_t *r1 = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    const firc_sub_event_t *r2 = sink_nth(&s, FIRC_SUB_EV_RESULT, 1);
    ASSERT(r1 != NULL && r2 != NULL);
    ASSERT_EQ((uint64_t)1, r1->seq);
    ASSERT_EQ(1u, r1->rules.n);
    ASSERT_STR_EQ("slow.example", firc_sub_rules_text(&r1->rules, 0));
    ASSERT_EQm("the second follow-up replaced the first", (uint64_t)3, r2->seq);
    ASSERT_EQ(1u, r2->rules.n);
    ASSERT_STR_EQ("three.example", firc_sub_rules_text(&r2->rules, 0));

    worker_free(w);
    sink_free(&s);
    harness_stop(h);
    PASS();
}

static firc_sub_job_t job_for_list(uint8_t group_byte, uint32_t list_no, const char *path,
                                   uint64_t seq) {
    firc_sub_job_t j = job_for(group_byte, path, seq);
    firc_id_t l = {{0x10, 0x20, (uint8_t)(list_no >> 8), (uint8_t)list_no}};
    j.list_id = l;
    return j;
}

/* Catches: two lists of one group folding into one slot. */
TEST two_lists_of_one_group_wait_in_two_slots(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_worker_t *w = worker_new(8, sink_emit, &s);
    ASSERT(w != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));

    firc_sub_job_t slow = job_for_list(0x31, 9, "/slow", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &slow));
    ASSERT(wait_events(&s, FIRC_SUB_EV_STARTED, 1, 2000));

    firc_sub_job_t a = job_for_list(0x32, 1, "/a", 2);
    firc_sub_job_t b = job_for_list(0x32, 2, "/b", 3);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &a));
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &b));
    ASSERT_EQ(2u, firc_sub_worker_waiting_for_test(w));

    ASSERT(wait_events(&s, FIRC_SUB_EV_RESULT, 3, 5000));
    const firc_sub_event_t *r1 = sink_nth(&s, FIRC_SUB_EV_RESULT, 1);
    const firc_sub_event_t *r2 = sink_nth(&s, FIRC_SUB_EV_RESULT, 2);
    ASSERT(r1 != NULL && r2 != NULL);
    ASSERT_EQ((uint64_t)2, r1->seq);
    ASSERT_EQ(2u, r1->rules.n);
    ASSERT_EQ((uint64_t)3, r2->seq);
    ASSERT_EQ(1u, r2->rules.n);
    ASSERT(r1->list_id.b[3] == 1 && r2->list_id.b[3] == 2);

    worker_free(w);
    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: the same (group, list) queued twice running twice. */
TEST the_same_list_twice_folds_into_one(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_worker_t *w = worker_new(8, sink_emit, &s);
    ASSERT(w != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));

    firc_sub_job_t slow = job_for_list(0x41, 9, "/slow", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &slow));
    ASSERT(wait_events(&s, FIRC_SUB_EV_STARTED, 1, 2000));

    firc_sub_job_t a = job_for_list(0x42, 1, "/a", 2);
    firc_sub_job_t b = job_for_list(0x42, 1, "/b", 3);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &a));
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &b));
    ASSERT_EQ(1u, firc_sub_worker_waiting_for_test(w));

    ASSERT(wait_events(&s, FIRC_SUB_EV_RESULT, 2, 5000));
    sleep_ms(300);
    ASSERT_EQ(2u, sink_count(&s, FIRC_SUB_EV_RESULT));
    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 1);
    ASSERT(r != NULL);
    ASSERT_EQ((uint64_t)3, r->seq);

    worker_free(w);
    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: another list of the running group taking the running list's follow-up slot. */
TEST a_list_of_the_running_group_is_not_its_follow_up(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_worker_t *w = worker_new(8, sink_emit, &s);
    ASSERT(w != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));

    firc_sub_job_t slow = job_for_list(0x51, 1, "/slow", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &slow));
    ASSERT(wait_events(&s, FIRC_SUB_EV_STARTED, 1, 2000));

    firc_sub_job_t b = job_for_list(0x51, 2, "/a", 2);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &b));
    firc_sub_job_t a2 = job_for_list(0x51, 1, "/b", 3);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &a2));
    ASSERT_EQm("B waits and A's follow-up holds its own slot", 2u,
               firc_sub_worker_waiting_for_test(w));

    ASSERT(wait_events(&s, FIRC_SUB_EV_RESULT, 3, 5000));
    sleep_ms(200);
    ASSERT_EQ(3u, sink_count(&s, FIRC_SUB_EV_RESULT));
    const firc_sub_event_t *r1 = sink_nth(&s, FIRC_SUB_EV_RESULT, 1);
    const firc_sub_event_t *r2 = sink_nth(&s, FIRC_SUB_EV_RESULT, 2);
    ASSERT(r1 != NULL && r2 != NULL);
    ASSERT_EQm("A's follow-up goes to the front", (uint64_t)3, r1->seq);
    ASSERT_EQ((uint64_t)2, r2->seq);
    ASSERT_EQ(2, r2->list_id.b[3]);

    worker_free(w);
    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: a capacity other than 4096 waiting (group, list) jobs. */
TEST capacity_is_4096_waiting_jobs(void) {
    static sink_t s;
    sink_init(&s);
    firc_sub_worker_t *w = worker_new(FIRC_SUB_WORKER_CAPACITY, sink_emit, &s);
    ASSERT(w != NULL);

    for (uint32_t i = 0; i < 4096; i++) {
        firc_sub_job_t j = job_for_list(0x62, i, "/a", 2 + i);
        ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &j));
    }
    ASSERT_EQ(4096u, firc_sub_worker_waiting_for_test(w));
    firc_sub_job_t extra = job_for_list(0x62, 4096, "/a", 9999);
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_sub_worker_enqueue(w, &extra));

    worker_free(w);
    sink_free(&s);
    PASS();
}

/* Catches: a result posted after the cancel was raised at the end of the parse. */
TEST nothing_is_posted_once_the_cancel_is_raised(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_cancel_t *cancel = firc_cancel_new();
    ASSERT(cancel != NULL);
    s.raise_on_parse = cancel;
    s.raise_at_lines = BIG_LINES;

    firc_sub_job_t job = job_for(0x66, "/big", 1);
    firc_sub_job_run(&job, NULL, cancel, sink_emit, &s);
    free(job.url);

    ASSERT_EQm("the parse ran to its last line", (size_t)(BIG_LINES / FIRC_SUB_PARSE_PROGRESS_LINES),
               s.n_parse);
    ASSERT_EQm("and the result it produced was never posted", 0u,
               sink_count(&s, FIRC_SUB_EV_RESULT));

    firc_cancel_free(cancel);
    sink_free(&s);
    harness_stop(h);
    PASS();
}

typedef struct bounded_run {
    firc_sub_job_t *job;
    firc_cancel_t *cancel;
    sink_t *sink;
    sem_t done;
} bounded_run_t;

static void *bounded_run_thread(void *ud) {
    bounded_run_t *r = ud;
    firc_sub_job_run(r->job, NULL, r->cancel, sink_emit, r->sink);
    sem_post(&r->done);
    return NULL;
}

static bool run_job_within(firc_sub_job_t *job, firc_cancel_t *cancel, sink_t *sink, unsigned raise_after_ms,
                           unsigned ms) {
    static bounded_run_t r;
    r = (bounded_run_t){.job = job, .cancel = cancel, .sink = sink};
    sem_init(&r.done, 0, 0);
    pthread_t t;
    if (pthread_create(&t, NULL, bounded_run_thread, &r) != 0) { return false; }
    if (raise_after_ms > 0) {
        sleep_ms(raise_after_ms);
        firc_cancel_raise(cancel);
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    if (sem_timedwait(&r.done, &ts) != 0) { return false; }
    pthread_join(t, NULL);
    sem_destroy(&r.done);
    return true;
}

/* Catches: a refused result freed instead of offered again. */
TEST a_refused_result_is_offered_again(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    s.refuse_results = 3;

    firc_sub_job_t job = job_for(0x71, "/a", 1);
    firc_cancel_t *cancel = firc_cancel_new();
    ASSERT(cancel != NULL);
    bool ended = run_job_within(&job, cancel, &s, 0, 5000);
    free(job.url);
    firc_cancel_free(cancel);
    ASSERT(ended);

    ASSERT_EQ_FMT((size_t)4, s.result_offers, "%zu");
    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_RESULT));
    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT_EQ_FMT((size_t)2, r->rules.n, "%zu");

    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: a refused progress event offered again, which holds the job back for a bar. */
TEST a_refused_progress_is_not_offered_again(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    s.refuse_progress = true;

    firc_sub_job_t job = job_for(0x72, "/big", 1);
    firc_cancel_t *cancel = firc_cancel_new();
    ASSERT(cancel != NULL);
    bool ended = run_job_within(&job, cancel, &s, 0, 10000);
    free(job.url);
    firc_cancel_free(cancel);
    ASSERT(ended);

    ASSERTm("progress was refused", s.progress_refused >= (size_t)(BIG_LINES / FIRC_SUB_PARSE_PROGRESS_LINES));
    ASSERT_FALSE(s.offered_twice);
    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_RESULT));

    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: a worker that keeps offering a refused event after the cancel. */
TEST a_cancel_ends_the_offers(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    s.refuse_all = true;

    firc_sub_job_t job = job_for(0x73, "/a", 1);
    firc_cancel_t *cancel = firc_cancel_new();
    ASSERT(cancel != NULL);
    uint64_t t0 = mono_ms();
    bool ended = run_job_within(&job, cancel, &s, 100, 3000);
    uint64_t took = mono_ms() - t0;
    free(job.url);
    if (ended) { firc_cancel_free(cancel); }
    ASSERT(ended);
    ASSERTm("ended soon after the raise", took < 1000);
    ASSERT_EQ(0u, sink_count(&s, FIRC_SUB_EV_RESULT));

    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: a follow-up dropped because other ids filled the queue while its job ran. */
TEST a_follow_up_is_never_dropped_by_a_full_queue(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_worker_t *w = worker_new(1, sink_emit, &s);
    ASSERT(w != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));

    firc_sub_job_t a1 = job_for(0xF1, "/slow", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &a1));
    ASSERTm("A is running", wait_events(&s, FIRC_SUB_EV_STARTED, 1, 2000));

    firc_sub_job_t b2 = job_for(0xF2, "/a", 2);
    ASSERT_EQm("the one waiting slot is B's", FIRC_OK, firc_sub_worker_enqueue(w, &b2));
    firc_sub_job_t a3 = job_for(0xF1, "/b", 3);
    ASSERT_EQm("...and the follow-up still has one of its own", FIRC_OK,
               firc_sub_worker_enqueue(w, &a3));
    ASSERT_EQ(2u, firc_sub_worker_waiting_for_test(w));

    firc_sub_job_t c4 = job_for(0xF3, "/a", 4);
    ASSERT_EQm("a queued follow-up counts against the capacity", FIRC_ERR_LIMIT,
               firc_sub_worker_enqueue(w, &c4));

    ASSERT(wait_events(&s, FIRC_SUB_EV_RESULT, 3, 5000));
    sleep_ms(200);
    ASSERT_EQm("all three jobs ran, and no more", 3u, sink_count(&s, FIRC_SUB_EV_RESULT));

    const firc_sub_event_t *r0 = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    const firc_sub_event_t *r1 = sink_nth(&s, FIRC_SUB_EV_RESULT, 1);
    const firc_sub_event_t *r2 = sink_nth(&s, FIRC_SUB_EV_RESULT, 2);
    ASSERT(r0 != NULL && r1 != NULL && r2 != NULL);
    ASSERT_EQ((uint64_t)1, r0->seq);
    ASSERT_MEM_EQ(id_of(0xF1).b, r0->group_id.b, sizeof(r0->group_id.b));
    ASSERT_EQm("the follow-up goes to the front: it waited on its own id", (uint64_t)3, r1->seq);
    ASSERT_MEM_EQ(id_of(0xF1).b, r1->group_id.b, sizeof(r1->group_id.b));
    ASSERT_EQ((uint64_t)2, r2->seq);
    ASSERT_MEM_EQ(id_of(0xF2).b, r2->group_id.b, sizeof(r2->group_id.b));

    worker_free(w);
    sink_free(&s);
    harness_stop(h);
    PASS();
}

TEST a_queued_follow_up_counts_against_the_capacity(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);

    firc_sub_worker_t *w = worker_new(2, sink_emit, &s);
    ASSERT(w != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));

    firc_sub_job_t a1 = job_for(0x91, "/slow", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &a1));
    ASSERTm("A is running", wait_events(&s, FIRC_SUB_EV_STARTED, 1, 2000));

    firc_sub_job_t b2 = job_for(0x92, "/a", 2);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &b2));
    ASSERT_EQm("one job waits", 1u, firc_sub_worker_waiting_for_test(w));

    firc_sub_job_t a3 = job_for(0x91, "/b", 3);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &a3));
    ASSERT_EQm("the follow-up is the second of the two", 2u, firc_sub_worker_waiting_for_test(w));

    firc_sub_job_t c4 = job_for(0x93, "/a", 4);
    ASSERT_EQm("so the queue is full", FIRC_ERR_LIMIT, firc_sub_worker_enqueue(w, &c4));

    ASSERT(wait_events(&s, FIRC_SUB_EV_RESULT, 3, 5000));
    sleep_ms(200);
    ASSERT_EQm("the refused job never ran", 3u, sink_count(&s, FIRC_SUB_EV_RESULT));
    for (size_t i = 0; i < 3; i++) {
        const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, i);
        ASSERT(r != NULL);
        ASSERT(r->seq != (uint64_t)4);
    }

    worker_free(w);
    sink_free(&s);
    harness_stop(h);
    PASS();
}

/* Catches: queued jobs leaked by a worker freed before its thread starts (seen under sanitize). */
TEST a_worker_freed_before_it_starts_frees_what_it_holds(void) {
    static sink_t s;
    sink_init(&s);
    firc_sub_worker_t *w = worker_new(FIRC_SUB_WORKER_CAPACITY, sink_emit, &s);
    ASSERT(w != NULL);
    firc_sub_job_t j = job_for(0xE5, "/a", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &j));
    ASSERT_EQ(1u, firc_sub_worker_waiting_for_test(w));
    worker_free(w);
    ASSERT_EQm("nothing ran", 0u, sink_count(&s, FIRC_SUB_EV_STARTED));
    sink_free(&s);
    PASS();
}

static const uint8_t g_hash_a[FIRC_SHA256_DIGEST_LEN] = {
    0x67, 0xc9, 0x27, 0x1d, 0x2a, 0x37, 0xe1, 0x56, 0x90, 0x77, 0x3c,
    0xb6, 0xa4, 0xeb, 0xfa, 0xf9, 0xef, 0x74, 0x4e, 0x54, 0x4d, 0x61,
    0x1d, 0x45, 0xd0, 0x40, 0x69, 0x6b, 0x2b, 0xf3, 0x2a, 0x4f};
static const char g_body_a[] = "one.example\ntwo.example";

static char g_cdir[64];

static bool cdir_make(void) {
    snprintf(g_cdir, sizeof g_cdir, "/tmp/firc_sw_XXXXXX");
    return mkdtemp(g_cdir) != NULL;
}

static void cdir_remove(void) {
    DIR *d = opendir(g_cdir);
    if (d != NULL) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) { continue; }
            char p[512];
            snprintf(p, sizeof p, "%s/%s", g_cdir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(g_cdir);
}

static void cache_path(const char *url, const char *hash16, char *out, size_t cap) {
    char key[17];
    firc_listcache_key(url, key);
    snprintf(out, cap, "%s/%s-%s", g_cdir, key, hash16);
}

static bool cache_put(const char *url, const char *body, const uint8_t hash[32]) {
    char key[17];
    firc_listcache_key(url, key);
    return firc_listcache_write(g_cdir, key, (const uint8_t *)body, strlen(body), hash) == FIRC_OK;
}

static bool cache_holds(const char *url, const char *body) {
    char key[17];
    firc_listcache_key(url, key);
    uint8_t *got = NULL;
    size_t len = 0;
    uint8_t h[32];
    time_t mt;
    if (firc_listcache_read(g_cdir, key, &got, &len, h, &mt) != FIRC_OK) { return false; }
    bool same = len == strlen(body) && memcmp(got, body, len) == 0;
    free(got);
    return same;
}

static bool path_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

static bool room_no(uint64_t t, uint64_t f, uint64_t held, uint64_t size) {
    (void)t;
    (void)f;
    (void)held;
    (void)size;
    return false;
}

/* Catches: a cached list fetched anyway, or its result missing the cache flag, date or hash. */
TEST cache_first_with_a_file_parses_it_and_fetches_nothing(void) {
    ASSERT(cdir_make());
    static sink_t s;
    sink_init(&s);
    firc_sub_job_t job = job_for(0xC1, "/a", 1);
    job.cache_first = true;
    ASSERT(cache_put(job.url, g_body_a, g_hash_a));
    char path[256];
    cache_path(job.url, "67c9271d2a37e156", path, sizeof path);
    struct timeval tv[2] = {{1700000000, 0}, {1700000000, 0}};
    ASSERT_EQ(0, utimes(path, tv));

    firc_sub_job_run(&job, g_cdir, NULL, sink_emit, &s);
    free(job.url);

    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_STARTED));
    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_RESULT));
    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT(r->from_cache);
    ASSERT_EQ((int64_t)1700000000, r->cached_at);
    ASSERT_MEM_EQ(g_hash_a, r->hash, sizeof(g_hash_a));
    ASSERT_EQ(2u, r->rules.n);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&r->rules, 0));
    ASSERT_STR_EQ("two.example", firc_sub_rules_text(&r->rules, 1));
    ASSERT_EQm("no stub listens, so any fetch would have reported", 0u, s.n_fetch);

    sink_free(&s);
    cdir_remove();
    PASS();
}

/* Catches: a missing cache file ending the job instead of falling through to the fetch. */
TEST cache_first_without_a_file_fetches(void) {
    ASSERT(cdir_make());
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_job_t job = job_for(0xC2, "/a", 1);
    job.cache_first = true;

    firc_sub_job_run(&job, g_cdir, NULL, sink_emit, &s);
    free(job.url);

    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_RESULT));
    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT_FALSE(r->from_cache);
    ASSERT_EQ((int64_t)0, r->cached_at);
    ASSERT_EQ(2u, r->rules.n);
    ASSERT(s.n_fetch >= 1);

    sink_free(&s);
    harness_stop(h);
    cdir_remove();
    PASS();
}

/* Catches: a cached body that fails to parse reported as the job's error instead of fetching. */
TEST cache_first_with_an_unparsable_file_fetches(void) {
    ASSERT(cdir_make());
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_job_t job = job_for(0xC3, "/a", 1);
    job.cache_first = true;
    static const uint8_t html_hash[FIRC_SHA256_DIGEST_LEN] = {
        0x16, 0x23, 0xf1, 0xd0, 0x81, 0x16, 0x0d, 0x97, 0x6d, 0xd6, 0x58,
        0x83, 0x73, 0xdd, 0x6e, 0x73, 0xe2, 0x4a, 0xf9, 0xa6, 0xff, 0x05,
        0x6a, 0x65, 0x3e, 0xbd, 0x0f, 0xba, 0x2f, 0x35, 0x5b, 0xcd};
    ASSERT(cache_put(job.url, g_list_html.body, html_hash));

    firc_sub_job_run(&job, g_cdir, NULL, sink_emit, &s);
    free(job.url);

    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_RESULT));
    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT_FALSE(r->from_cache);
    ASSERT_EQ(2u, r->rules.n);

    sink_free(&s);
    harness_stop(h);
    cdir_remove();
    PASS();
}

/* Catches: the cache read for a job that did not ask for it. */
TEST without_cache_first_the_file_is_not_read(void) {
    ASSERT(cdir_make());
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_job_t job = job_for(0xC4, "/a", 1);
    static const uint8_t cached_hash[FIRC_SHA256_DIGEST_LEN] = {
        0x01, 0x73, 0x9c, 0xdc, 0x46, 0x82, 0x10, 0x45, 0x32, 0xe2, 0x51,
        0xe3, 0xe6, 0xf7, 0xd4, 0x8d, 0x56, 0x28, 0x23, 0x89, 0x2a, 0x74,
        0xda, 0x20, 0xa0, 0x7b, 0x43, 0xf3, 0x2d, 0xba, 0x7f, 0xec};
    ASSERT(cache_put(job.url, "cached.example", cached_hash));

    firc_sub_job_run(&job, g_cdir, NULL, sink_emit, &s);
    free(job.url);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT_FALSE(r->from_cache);
    ASSERT_EQ(2u, r->rules.n);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&r->rules, 0));

    sink_free(&s);
    harness_stop(h);
    cdir_remove();
    PASS();
}

/* Catches: a parsed fetch not kept, or kept under another key or hash. */
TEST a_parsed_fetch_is_written_to_the_cache(void) {
    ASSERT(cdir_make());
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_job_t job = job_for(0xC5, "/a", 1);
    char path[256];
    cache_path(job.url, "67c9271d2a37e156", path, sizeof path);

    firc_sub_job_run(&job, g_cdir, NULL, sink_emit, &s);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    ASSERT(path_exists(path));
    ASSERT(cache_holds(job.url, g_body_a));
    free(job.url);

    sink_free(&s);
    harness_stop(h);
    cdir_remove();
    PASS();
}

/* Catches: an unchanged body left unwritten for a key that has no file (a url change). */
TEST an_unchanged_fetch_writes_a_missing_file(void) {
    ASSERT(cdir_make());
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_job_t job = job_for(0xC6, "/a", 1);
    job.has_hash = true;
    memcpy(job.expected_hash, g_hash_a, sizeof(g_hash_a));
    char path[256];
    cache_path(job.url, "67c9271d2a37e156", path, sizeof path);

    firc_sub_job_run(&job, g_cdir, NULL, sink_emit, &s);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_UNCHANGED, r->result);
    ASSERT(path_exists(path));
    ASSERT(cache_holds(job.url, g_body_a));
    free(job.url);

    sink_free(&s);
    harness_stop(h);
    cdir_remove();
    PASS();
}

static int g_wlog[2] = {-1, -1};

static void wlog_start(void) {
    if (pipe(g_wlog) != 0) { return; }
    fcntl(g_wlog[0], F_SETFL, O_NONBLOCK);
    firc_log_set_output_floor(FIRC_LOG_WARN);
    firc_log_set_fd(g_wlog[1]);
}

static int wlog_count(const char *needle) {
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_output_floor(FIRC_LOG_ERROR);
    close(g_wlog[1]);
    static char buf[65536];
    ssize_t n = read(g_wlog[0], buf, sizeof(buf) - 1);
    close(g_wlog[0]);
    buf[n > 0 ? n : 0] = '\0';
    int count = 0;
    for (const char *at = buf; (at = strstr(at, needle)) != NULL; at += strlen(needle)) { count++; }
    return count;
}

/* Catches: a refused write failing the sync, warning on every sync, or not warning at all. */
TEST a_refused_write_warns_once_and_still_parses(void) {
    ASSERT(cdir_make());
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_worker_t *w = worker_new_in(g_cdir, sink_emit, &s);
    ASSERT(w != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_start(w));
    firc_listcache_room_hook_for_test = room_no;
    wlog_start();

    firc_sub_job_t j1 = job_for(0xC7, "/a", 1);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &j1));
    bool first = wait_events(&s, FIRC_SUB_EV_RESULT, 1, 5000);
    firc_sub_job_t j2 = job_for(0xC7, "/a", 2);
    ASSERT_EQ(FIRC_OK, firc_sub_worker_enqueue(w, &j2));
    bool second = wait_events(&s, FIRC_SUB_EV_RESULT, 2, 5000);
    worker_free(w);
    int warned = wlog_count("not kept on disk");
    firc_listcache_room_hook_for_test = NULL;

    ASSERT(first);
    ASSERT(second);
    for (size_t i = 0; i < 2; i++) {
        const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, i);
        ASSERT(r != NULL);
        ASSERT_EQ(FIRC_SUB_RESULT_PARSED, r->result);
    }
    ASSERT_EQ(1, warned);
    ASSERT_FALSE(cache_holds(url_for("/a"), g_body_a));

    sink_free(&s);
    harness_stop(h);
    cdir_remove();
    PASS();
}

/* Catches: a stale temp file kept at worker creation, or a cache file swept with it. */
TEST a_new_worker_removes_temp_files_only(void) {
    ASSERT(cdir_make());
    static sink_t s;
    sink_init(&s);
    char tmp[256], kept[256];
    snprintf(tmp, sizeof tmp, "%s/0123456789abcdef-0123456789abcdef.tmp.Ab12Cd", g_cdir);
    snprintf(kept, sizeof kept, "%s/0123456789abcdef-fedcba9876543210", g_cdir);
    FILE *f = fopen(tmp, "w");
    ASSERT(f != NULL);
    fclose(f);
    f = fopen(kept, "w");
    ASSERT(f != NULL);
    fclose(f);

    firc_sub_worker_t *w = worker_new_in(g_cdir, sink_emit, &s);
    ASSERT(w != NULL);
    worker_free(w);

    ASSERT_FALSE(path_exists(tmp));
    ASSERT(path_exists(kept));
    sink_free(&s);
    cdir_remove();
    PASS();
}

/* Catches: an unparsable cached body kept on disk and parsed again at every start. */
TEST an_unparsable_cached_body_is_removed(void) {
    ASSERT(cdir_make());
    static sink_t s;
    sink_init(&s);
    firc_sub_job_t job = job_for(0xC8, "/a", 1);
    job.cache_first = true;
    static const uint8_t html_hash[FIRC_SHA256_DIGEST_LEN] = {
        0x16, 0x23, 0xf1, 0xd0, 0x81, 0x16, 0x0d, 0x97, 0x6d, 0xd6, 0x58,
        0x83, 0x73, 0xdd, 0x6e, 0x73, 0xe2, 0x4a, 0xf9, 0xa6, 0xff, 0x05,
        0x6a, 0x65, 0x3e, 0xbd, 0x0f, 0xba, 0x2f, 0x35, 0x5b, 0xcd};
    ASSERT(cache_put(job.url, g_list_html.body, html_hash));
    char path[256];
    cache_path(job.url, "1623f1d081160d97", path, sizeof path);
    ASSERT(path_exists(path));

    firc_sub_job_run(&job, g_cdir, NULL, sink_emit, &s);
    free(job.url);

    ASSERT_EQ(1u, sink_count(&s, FIRC_SUB_EV_RESULT));
    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_ERROR, r->result);
    ASSERT_FALSE(path_exists(path));

    sink_free(&s);
    cdir_remove();
    PASS();
}

/* Catches: a fetched body that failed to parse written to the cache. */
TEST an_unparsable_fetch_is_not_written(void) {
    ASSERT(cdir_make());
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static sink_t s;
    sink_init(&s);
    firc_sub_job_t job = job_for(0xC9, "/html", 1);

    firc_sub_job_run(&job, g_cdir, NULL, sink_emit, &s);
    free(job.url);

    const firc_sub_event_t *r = sink_nth(&s, FIRC_SUB_EV_RESULT, 0);
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_SUB_RESULT_ERROR, r->result);
    ASSERT_EQ(FIRC_ERR_INVAL, r->err);
    DIR *d = opendir(g_cdir);
    ASSERT(d != NULL);
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0) { n++; }
    }
    closedir(d);
    ASSERT_EQ(0, n);

    sink_free(&s);
    harness_stop(h);
    cdir_remove();
    PASS();
}

/* Catches: a cache parse cancelled midway that still posts, fetches, leaks its result or drops the file. */
TEST cancel_during_a_cache_parse_posts_no_result(void) {
    ASSERT(cdir_make());
    static sink_t s;
    sink_init(&s);
    firc_cancel_t *cancel = firc_cancel_new();
    ASSERT(cancel != NULL);
    s.raise_on_parse = cancel;
    s.raise_at_lines = FIRC_SUB_PARSE_PROGRESS_LINES;
    firc_sub_job_t job = job_for(0xCA, "/a", 1);
    job.cache_first = true;
    uint8_t big_hash[FIRC_SHA256_DIGEST_LEN];
    firc_sha256((const uint8_t *)g_list_big.body, strlen(g_list_big.body), big_hash);
    ASSERT(cache_put(job.url, g_list_big.body, big_hash));

    firc_sub_job_run(&job, g_cdir, cancel, sink_emit, &s);
    bool kept = cache_holds(job.url, g_list_big.body);
    free(job.url);

    ASSERT(s.n_parse >= 1);
    ASSERT_EQ(0u, sink_count(&s, FIRC_SUB_EV_RESULT));
    ASSERT_EQ(0u, s.n_fetch);
    ASSERT(kept);

    firc_cancel_free(cancel);
    sink_free(&s);
    cdir_remove();
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    firc_log_set_output_floor(FIRC_LOG_ERROR);
    firc_sub_fetch_global_init();
    char *big = build_big_list();
    if (big == NULL) { return 1; }
    g_list_big.body = big;

    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(stop_open_harness, NULL);
    RUN_TEST(a_job_posts_started_then_a_parsed_result);
    RUN_TEST(a_sing_box_body_reports_unconstrained_and_dropped);
    RUN_TEST(an_html_body_is_an_error_with_the_reason);
    RUN_TEST(the_same_bytes_are_unchanged_and_carry_no_rules);
    RUN_TEST(a_404_is_an_error_with_the_status);
    RUN_TEST(an_unusable_url_is_an_error_with_no_status);
    RUN_TEST(progress_is_posted_and_rate_limited);
    RUN_TEST(a_stalled_fetch_is_rate_limited_too);
    RUN_TEST(cancel_mid_fetch_posts_no_result);
    RUN_TEST(enqueue_folds_by_id_while_waiting);
    RUN_TEST(a_follow_up_enqueued_while_running_runs_once_after);
    RUN_TEST(a_follow_up_is_never_dropped_by_a_full_queue);
    RUN_TEST(a_queued_follow_up_counts_against_the_capacity);
    RUN_TEST(two_lists_of_one_group_wait_in_two_slots);
    RUN_TEST(the_same_list_twice_folds_into_one);
    RUN_TEST(a_list_of_the_running_group_is_not_its_follow_up);
    RUN_TEST(capacity_is_4096_waiting_jobs);
    RUN_TEST(nothing_is_posted_once_the_cancel_is_raised);
    RUN_TEST(a_refused_result_is_offered_again);
    RUN_TEST(a_refused_progress_is_not_offered_again);
    RUN_TEST(a_cancel_ends_the_offers);
    RUN_TEST(a_worker_freed_before_it_starts_frees_what_it_holds);
    RUN_TEST(cache_first_with_a_file_parses_it_and_fetches_nothing);
    RUN_TEST(cache_first_without_a_file_fetches);
    RUN_TEST(cache_first_with_an_unparsable_file_fetches);
    RUN_TEST(without_cache_first_the_file_is_not_read);
    RUN_TEST(a_parsed_fetch_is_written_to_the_cache);
    RUN_TEST(an_unparsable_cached_body_is_removed);
    RUN_TEST(an_unparsable_fetch_is_not_written);
    RUN_TEST(cancel_during_a_cache_parse_posts_no_result);
    RUN_TEST(an_unchanged_fetch_writes_a_missing_file);
    RUN_TEST(a_refused_write_warns_once_and_still_parses);
    RUN_TEST(a_new_worker_removes_temp_files_only);
    GREATEST_MAIN_END();
}
