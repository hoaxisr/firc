#include "greatest.h"
#include "test_ids.h"

#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "firc/app.h"
#include "firc/dnspipeline.h"
#include "firc/httpd.h"
#include "firc/events.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/rulesnap.h"
#include "firc/sub_fetch.h"
#include "firc/sub_worker.h"
#include "firc/subparse.h"
#include "test_group_lists_util.h"
#include "test_app_lists_util.h"

#define TEST_PORT 18110

typedef struct list_ud {
    const char *body;
} list_ud_t;

static void h_list(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    list_ud_t *l = ud;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)l->body, strlen(l->body));
}

static _Atomic int g_hits_a;
static void h_list_counted(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    atomic_fetch_add(&g_hits_a, 1);
    h_list(req, res, ud);
}

static void h_notfound(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "nope";
    firc_http_res_write(res, 404, "text/plain", (const uint8_t *)body, sizeof(body) - 1);
}

static bool g_toggle_state = false;
static void h_toggle(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    g_toggle_state = !g_toggle_state;
    const char *body = g_toggle_state ? "one.example\ntwo.example" : "three.example";
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, strlen(body));
}

typedef struct status_ud {
    int status;
    const char *body;
} status_ud_t;

static status_ud_t g_two[2];

static void h_status(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    status_ud_t *s = ud;
    firc_http_res_write(res, s->status, "text/plain", (const uint8_t *)s->body, strlen(s->body));
}

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *srv;
    pthread_t thread;
    firc_config_t cfg;
    firc_dns_pipeline_t *pipeline;
    firc_app_t *app;
} harness_t;

static void *loop_thread(void *ud) {
    harness_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

static list_ud_t g_list_a = {.body = "one.example\ntwo.example"};
static list_ud_t g_list_b = {.body = "three.example"};
static list_ud_t g_list_a_twin = {.body = "one.example\ntwo.example"};
static list_ud_t g_list_a_len = {.body = "uno.example\ndos.example"};
static list_ud_t g_list_empty = {.body = "# nothing routable here\n"};

static void harness_stop(harness_t *h);
static harness_t *g_open_harness = NULL;
static void stop_open_orphan(void);

static void stop_open_harness(void *unused) {
    (void)unused;
    stop_open_orphan();
    if (g_open_harness != NULL) {
        harness_t *h = g_open_harness;
        g_open_harness = NULL;
        harness_stop(h);
    }
}

typedef void (*loop_fn_t)(harness_t *h, void *arg);

typedef struct loop_call {
    harness_t *h;
    loop_fn_t fn;
    void *arg;
    sem_t done;
} loop_call_t;

static void loop_call_cb(firc_loop_t *loop, void *ud) {
    (void)loop;
    loop_call_t *c = ud;
    c->fn(c->h, c->arg);
    sem_post(&c->done);
}

static bool on_loop(harness_t *h, loop_fn_t fn, void *arg) {
    loop_call_t c = {.h = h, .fn = fn, .arg = arg};
    if (sem_init(&c.done, 0, 0) != 0) { return false; }
    if (firc_loop_post(h->loop, loop_call_cb, &c) != FIRC_OK) {
        sem_destroy(&c.done);
        return false;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 10;
    bool ok = sem_timedwait(&c.done, &ts) == 0;
    sem_destroy(&c.done);
    return ok;
}

static void noop_fn(harness_t *h, void *arg) {
    (void)h;
    (void)arg;
}

static harness_t *harness_start(void) {
    harness_t *h = calloc(1, sizeof(*h));
    firc_config_init_defaults(&h->cfg);

    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    if (firc_httpd_create(h->loop, &h->srv) != FIRC_OK) { return NULL; }
    firc_httpd_route(h->srv, "GET", "/a", h_list_counted, &g_list_a);
    firc_httpd_route(h->srv, "GET", "/b", h_list, &g_list_b);
    firc_httpd_route(h->srv, "GET", "/a-twin", h_list, &g_list_a_twin);
    firc_httpd_route(h->srv, "GET", "/a-len", h_list, &g_list_a_len);
    firc_httpd_route(h->srv, "GET", "/empty", h_list, &g_list_empty);
    firc_httpd_route(h->srv, "GET", "/404", h_notfound, NULL);
    firc_httpd_route(h->srv, "GET", "/toggle", h_toggle, NULL);
    firc_httpd_route(h->srv, "GET", "/two0", h_status, &g_two[0]);
    firc_httpd_route(h->srv, "GET", "/two1", h_status, &g_two[1]);
    if (firc_httpd_listen_tcp(h->srv, "127.0.0.1", TEST_PORT) != FIRC_OK) { return NULL; }
    pthread_create(&h->thread, NULL, loop_thread, h);

    h->pipeline = firc_dns_pipeline_create();
    if (h->pipeline == NULL) { return NULL; }
    firc_app_deps_t deps = {.cfg = &h->cfg, .loop = h->loop, .pipeline = h->pipeline};
    h->app = firc_app_create(&deps);
    if (h->app == NULL) { return NULL; }
    if (firc_app_start_list_worker(h->app) != FIRC_OK) { return NULL; }
    g_open_harness = h;
    return h;
}

static void harness_stop(harness_t *h) {
    if (g_open_harness == h) { g_open_harness = NULL; }
    firc_app_stop_list_worker(h->app);
    (void)on_loop(h, noop_fn, NULL);
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->srv);
    firc_loop_destroy(h->loop);
    firc_app_destroy(h->app);
    firc_dns_pipeline_destroy(h->pipeline);
    firc_config_clear(&h->cfg);
    free(h);
}

static char g_url[128];
static const char *url_for(const char *path) {
    snprintf(g_url, sizeof(g_url), "http://127.0.0.1:%d%s", TEST_PORT, path);
    return g_url;
}

/* The live group `id` names, or NULL. */
static const firc_group_t *find_group(firc_app_t *app, firc_id_t id) {
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, id);
    return rs != NULL ? firc_ruleset_group(rs) : NULL;
}

typedef struct sub_view {
    firc_id_t id;
    bool found;
    firc_sub_sync_state_t state;
    char error[256];
    size_t rules_n;
    bool has_body_hash;
    uint32_t last_check;
    uint32_t last_update;
    uint64_t seq;
    char rule[2][64];
    char type[2][32];
    bool enable[2];
} sub_view_t;

static void read_sub_fn(harness_t *h, void *arg) {
    sub_view_t *v = arg;
    const firc_group_t *s = find_group(h->app, v->id);
    if (s == NULL) {
        v->found = false;
        return;
    }
    v->found = true;
    v->state = s->lists[0]->sync_state;
    snprintf(v->error, sizeof(v->error), "%s", s->lists[0]->sync_error);
    v->rules_n = s->lists[0]->rules.n;
    v->has_body_hash = s->lists[0]->has_body_hash;
    v->last_check = s->lists[0]->last_check;
    v->last_update = s->lists[0]->last_update;
    v->seq = s->lists[0]->sync_seq;
    for (size_t i = 0; i < 2 && i < s->lists[0]->rules.n; i++) {
        snprintf(v->rule[i], sizeof(v->rule[i]), "%s", firc_sub_rules_text(&s->lists[0]->rules, i));
        snprintf(v->type[i], sizeof(v->type[i]), "%s", firc_sub_rules_type(&s->lists[0]->rules, i));
        v->enable[i] = firc_sub_rules_enable(&s->lists[0]->rules, i);
    }
}

static sub_view_t sub_view(harness_t *h, firc_id_t id) {
    sub_view_t v;
    memset(&v, 0, sizeof(v));
    v.id = id;
    if (!on_loop(h, read_sub_fn, &v)) { memset(&v, 0, sizeof(v)); }
    return v;
}

/* Polls through the loop until the list is neither queued nor fetching, or gone. */
static bool wait_settled(harness_t *h, firc_id_t id, int timeout_ms) {
    for (int waited = 0; waited <= timeout_ms; waited += 5) {
        sub_view_t v = sub_view(h, id);
        if (!v.found) { return true; }
        if (v.state != FIRC_SUB_SYNC_QUEUED && v.state != FIRC_SUB_SYNC_FETCHING) { return true; }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return false;
}

typedef struct request_call {
    firc_id_t id;
    firc_err_t err;
    firc_sub_sync_state_t state_after;
} request_call_t;

static void request_sync_fn(harness_t *h, void *arg) {
    request_call_t *r = arg;
    r->err = firc_app_request_sync(h->app, r->id, list0(h->app, r->id));
    const firc_group_t *s = find_group(h->app, r->id);
    r->state_after = s != NULL ? s->lists[0]->sync_state : FIRC_SUB_SYNC_IDLE;
}

typedef struct sweep_call {
    int64_t now;
    size_t n;
    firc_id_t ids[4];
    firc_sub_sync_state_t states[4];
} sweep_call_t;

static void read_states(harness_t *h, sweep_call_t *s) {
    for (size_t i = 0; i < s->n; i++) {
        const firc_group_t *sub = find_group(h->app, s->ids[i]);
        s->states[i] = sub != NULL ? sub->lists[0]->sync_state : FIRC_SUB_SYNC_ERROR;
    }
}

static void request_due_fn(harness_t *h, void *arg) {
    sweep_call_t *s = arg;
    firc_app_request_sync_due(h->app, s->now);
    read_states(h, s);
}

static void request_missing_fn(harness_t *h, void *arg) {
    sweep_call_t *s = arg;
    firc_app_request_sync_missing(h->app);
    read_states(h, s);
}

static void remove_group_fn(harness_t *h, void *arg) {
    firc_id_t *id = arg;
    (void)firc_app_remove_group_by_id(h->app, *id);
}

typedef struct count_call {
    size_t n;
} count_call_t;

static void count_groups_fn(harness_t *h, void *arg) {
    count_call_t *c = arg;
    c->n = firc_app_user_group_count(h->app);
}

static size_t group_count(harness_t *h) {
    count_call_t c = {.n = (size_t)-1};
    if (!on_loop(h, count_groups_fn, &c)) { return (size_t)-1; }
    return c.n;
}

static firc_sub_event_t *event_new(firc_sub_event_kind_t kind, firc_id_t id, firc_id_t list_id, uint64_t seq) {
    firc_sub_event_t *ev = calloc(1, sizeof(*ev));
    ev->kind = kind;
    ev->group_id = id;
    ev->list_id = list_id;
    ev->seq = seq;
    firc_sub_rules_init(&ev->rules);
    return ev;
}

static firc_sub_event_t *parsed_event(firc_id_t id, firc_id_t list_id, uint64_t seq, const char *rule) {
    firc_sub_event_t *ev = event_new(FIRC_SUB_EV_RESULT, id, list_id, seq);
    ev->result = FIRC_SUB_RESULT_PARSED;
    firc_sub_rules_push(&ev->rules, rule, "namespace", true, test_random_id());
    return ev;
}

typedef struct feed_call {
    firc_sub_event_t *ev;
    int64_t now;
} feed_call_t;

static void feed_event_fn(harness_t *h, void *arg) {
    feed_call_t *f = arg;
    firc_app_on_sync_event(h->app, f->ev, f->now);
}

typedef struct apply_call {
    firc_sub_event_t *ev;
    int64_t now;
    bool changed;
    firc_err_t err;
} apply_call_t;

static void apply_result_fn(harness_t *h, void *arg) {
    apply_call_t *a = arg;
    a->err = firc_app_apply_sync_result(h->app, a->ev, a->now, &a->changed);
}

/* An enabled group on eth0 with a list at `path` (NULL: no url). */
static firc_group_t *make_list_group(const char *path) {
    firc_group_t *g = firc_group_new();
    g->id = test_random_id();
    firc_strset(&g->name, "");
    firc_strset(&g->iface, "eth0");
    test_group_set_list(g);
    if (path != NULL) { firc_strset(&g->lists[0]->url, url_for(path)); }
    g->enable = true;
    return g;
}

/* firc_app_add_group without the first sync: the url is set after the add, so no job runs. */
static firc_err_t add_list_group(firc_app_t *app, firc_group_t *g) {
    char *url = g->lists[0]->url;
    g->lists[0]->url = NULL;
    firc_err_t err = firc_strset(&g->lists[0]->url, "");
    firc_id_t id = g->id;
    if (err == FIRC_OK) { err = firc_app_add_group(app, g); } else { firc_group_free(g); }
    if (err == FIRC_OK && url != NULL && url[0] != '\0') { err = firc_app_set_list_url(app, id, list0(app, id), url); }
    free(url);
    return err;
}

TEST first_sync_fetches_and_marks_changed(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    const firc_group_t *cur = find_group(h->app, id);
    ASSERT(cur != NULL);
    ASSERT_EQ(2u, cur->lists[0]->rules.n);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&cur->lists[0]->rules, 0));
    ASSERT_STR_EQ("two.example", firc_sub_rules_text(&cur->lists[0]->rules, 1));
    ASSERT_EQ((uint32_t)1000, cur->lists[0]->last_update);
    ASSERT_EQ((uint32_t)1000, cur->lists[0]->last_check);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, cur->lists[0]->sync_state);

    harness_stop(h);
    PASS();
}

TEST resync_same_content_is_unchanged_but_bumps_last_check(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = true;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    changed = true;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 2000, NULL, &changed));
    ASSERT_FALSE(changed);

    const firc_group_t *cur = find_group(h->app, id);
    ASSERT_EQ((uint32_t)1000, cur->lists[0]->last_update);
    ASSERT_EQ((uint32_t)2000, cur->lists[0]->last_check);
    ASSERT_EQ(2u, cur->lists[0]->rules.n);

    harness_stop(h);
    PASS();
}

/* Whether the event ring holds a line containing `needle`. */
static bool ring_says(const char *needle) {
    firc_event_t *kept = malloc(sizeof(*kept) * FIRC_EVENTS_RING);
    if (kept == NULL) { return false; }
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, kept, FIRC_EVENTS_RING, &next, &dropped);
    for (size_t i = 0; i < n; i++) {
        if (kept[i].kind != FIRC_EVENT_LOG) { continue; }
        if (strstr(kept[i].u.log.text, needle) != NULL) {
            free(kept);
            return true;
        }
    }
    free(kept);
    return false;
}

/* Catches: a sync that parses bytes it already holds, or a first sync that claims it skipped. */
TEST the_same_body_is_not_parsed_twice(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    firc_event_reset_for_test();

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);
    ASSERT_FALSE(ring_says("not parsed"));

    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 2000, NULL, &changed));
    ASSERT_FALSE(changed);
    ASSERT(ring_says("not parsed"));
    const firc_group_t *cur = find_group(h->app, id);
    ASSERT_EQ(2u, cur->lists[0]->rules.n);
    ASSERT_EQ((uint32_t)2000, cur->lists[0]->last_check);

    firc_event_reset_for_test();
    ASSERT_EQ(FIRC_OK,
              firc_app_sync_list_now(h->app, id, list0(h->app, id), 2500, url_for("/a-twin"), &changed));
    ASSERT(ring_says("not parsed"));
    firc_event_reset_for_test();
    ASSERT_EQ(FIRC_OK,
              firc_app_sync_list_now(h->app, id, list0(h->app, id), 2600, url_for("/a-len"), &changed));
    ASSERTm("same length, other bytes: a change", changed);
    ASSERT_FALSE(ring_says("not parsed"));
    cur = find_group(h->app, id);
    ASSERT_STR_EQ("uno.example", firc_sub_rules_text(&cur->lists[0]->rules, 0));

    firc_event_reset_for_test();
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 3000, url_for("/b"), &changed));
    ASSERT(changed);
    ASSERT_FALSE(ring_says("not parsed"));
    cur = find_group(h->app, id);
    ASSERT_EQ(1u, cur->lists[0]->rules.n);
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 4000, url_for("/b"), &changed));
    ASSERT_FALSE(changed);
    ASSERT(ring_says("not parsed"));

    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    harness_stop(h);
    PASS();
}

TEST the_scheduled_check_does_not_parse_the_same_bytes_either(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int64_t base = (int64_t)time(NULL);
    firc_group_t *sub = make_list_group("/a");
    sub->lists[0]->interval = 60;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    firc_event_reset_for_test();

    sweep_call_t s = {.now = base, .n = 1, .ids = {id}};
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT(wait_settled(h, id, 5000));
    sub_view_t v = sub_view(h, id);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, v.state);
    ASSERT_EQ(2u, v.rules_n);
    ASSERT_FALSE(ring_says("not parsed"));

    firc_event_reset_for_test();
    s.now = base + 3600;
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT(wait_settled(h, id, 5000));
    ASSERT(ring_says("not parsed"));
    v = sub_view(h, id);
    ASSERT_EQ(2u, v.rules_n);
    ASSERT(v.last_check >= (uint32_t)base);

    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    harness_stop(h);
    PASS();
}

/* Catches: a scheduled change leaving the old hash, so a later manual sync keeps stale rules. */
TEST a_scheduled_change_is_one_the_manual_sync_knows_about(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    g_toggle_state = false;
    int64_t base = (int64_t)time(NULL);
    firc_group_t *sub = make_list_group("/toggle");
    sub->lists[0]->interval = 60;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), base - 1000, NULL, &changed));
    ASSERT(changed);
    ASSERT_EQ(2u, (find_group(h->app, id))->lists[0]->rules.n);

    sweep_call_t s = {.now = base - 900, .n = 1, .ids = {id}};
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT(wait_settled(h, id, 5000));
    sub_view_t v = sub_view(h, id);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, v.state);
    ASSERT_EQ(1u, v.rules_n);

    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), base, NULL, &changed));
    ASSERTm("back to A is a change, not the bytes the manual sync last saw", changed);
    ASSERT_EQ(2u, (find_group(h->app, id))->lists[0]->rules.n);

    harness_stop(h);
    PASS();
}

TEST resync_different_content_updates_rules_and_last_update(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 2000, url_for("/b"), &changed));
    ASSERT(changed);

    const firc_group_t *cur = find_group(h->app, id);
    ASSERT_EQ(1u, cur->lists[0]->rules.n);
    ASSERT_STR_EQ("three.example", firc_sub_rules_text(&cur->lists[0]->rules, 0));
    ASSERT_STR_EQ(url_for("/b"), cur->lists[0]->url);
    ASSERT_EQ((uint32_t)2000, cur->lists[0]->last_update);
    ASSERT_EQ((uint32_t)2000, cur->lists[0]->last_check);

    harness_stop(h);
    PASS();
}

TEST unknown_id_is_noent(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    bool changed = false;
    firc_id_t bogus = test_random_id();
    ASSERT_EQ(FIRC_ERR_NOENT, firc_app_sync_list_now(h->app, bogus, list0(h->app, bogus), 1000, NULL, &changed));
    ASSERT_FALSE(changed);

    request_call_t r = {.id = bogus};
    ASSERT(on_loop(h, request_sync_fn, &r));
    ASSERT_EQ(FIRC_ERR_NOENT, r.err);

    harness_stop(h);
    PASS();
}

TEST empty_url_and_no_override_is_inval(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group(NULL);
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = true;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT_FALSE(changed);

    request_call_t r = {.id = id};
    ASSERT(on_loop(h, request_sync_fn, &r));
    ASSERT_EQm("nothing to fetch is not a job", FIRC_ERR_INVAL, r.err);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, r.state_after);

    harness_stop(h);
    PASS();
}

TEST fetch_failure_is_upstream_error(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/404");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = true;
    ASSERT_EQ(FIRC_ERR_UPSTREAM, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT_FALSE(changed);

    const firc_group_t *cur = find_group(h->app, id);
    ASSERT_EQ(0u, cur->lists[0]->rules.n);
    ASSERT_EQ((uint32_t)1000, cur->lists[0]->last_check);

    harness_stop(h);
    PASS();
}

/* Catches: a fetch error flattened to one text instead of the list's own state with the status. */
TEST a_fetch_error_is_the_list_state(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/404");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = true;
    ASSERT_EQ(FIRC_ERR_UPSTREAM, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT_FALSE(changed);

    const firc_group_t *cur = find_group(h->app, id);
    ASSERT_EQ(FIRC_SUB_SYNC_ERROR, cur->lists[0]->sync_state);
    ASSERT_STR_EQ("error", firc_sub_sync_state_name(cur->lists[0]->sync_state));
    ASSERTm("the status the server answered is in the text",
            strstr(cur->lists[0]->sync_error, "404") != NULL);
    ASSERT_EQ((uint32_t)1000, cur->lists[0]->last_check);

    harness_stop(h);
    PASS();
}

static firc_id_t add_two_list_group(harness_t *h, const char *path0, const char *path1) {
    firc_id_t none = {{0, 0, 0, 0}};
    firc_group_t *g = make_list_group(NULL);
    if (g == NULL) { return none; }
    firc_strset(&g->lists[0]->url, "");
    g->lists[0]->interval = 3600;
    firc_id_t id = g->id;
    if (firc_app_add_group(h->app, g) != FIRC_OK) { return none; }
    firc_group_list_t *second = test_group_add_list_at(g, url_for(path1));
    if (second == NULL) { return none; }
    second->interval = 3600;
    if (firc_app_set_list_url(h->app, id, list_at(h->app, id, 0), url_for(path0)) != FIRC_OK) { return none; }
    return id;
}

static const firc_group_list_t *list_of(harness_t *h, firc_id_t id, size_t at) {
    const firc_group_t *g = find_group(h->app, id);
    return g != NULL && at < g->n_lists ? g->lists[at] : NULL;
}

static firc_err_t sync_at(harness_t *h, firc_id_t id, size_t at, int64_t now) {
    bool changed = false;
    return firc_app_sync_list_now(h->app, id, list_at(h->app, id, at), now, NULL, &changed);
}

TEST a_url_another_list_of_the_group_holds_is_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_id_t id = add_two_list_group(h, "/two0", "/two1");
    ASSERT(list_of(h, id, 1) != NULL);
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_set_list_url(h->app, id, list_at(h->app, id, 1), url_for("/two0")));
    ASSERT_STR_EQ(url_for("/two1"), list_of(h, id, 1)->url);
    ASSERT_EQm("its own url again is no change", FIRC_OK,
               firc_app_set_list_url(h->app, id, list_at(h->app, id, 1), url_for("/two1")));
    harness_stop(h);
    PASS();
}

static void group_syncing_fn(harness_t *h, void *arg) {
    bool *out = arg;
    *out = h->cfg.n_groups != 0 && firc_app_group_syncing(h->cfg.groups[0]);
}

static bool wait_group_settled(harness_t *h, int timeout_ms) {
    for (int waited = 0; waited <= timeout_ms; waited += 5) {
        bool syncing = true;
        if (!on_loop(h, group_syncing_fn, &syncing)) { return false; }
        if (!syncing) { return true; }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return false;
}

typedef struct two_missing_call {
    firc_id_t id;
    firc_sub_sync_state_t states[2];
} two_missing_call_t;

static void request_missing_two_fn(harness_t *h, void *arg) {
    two_missing_call_t *c = arg;
    firc_app_request_sync_missing(h->app);
    for (size_t i = 0; i < 2; i++) { c->states[i] = list_of(h, c->id, i)->sync_state; }
}

TEST a_boot_request_covers_every_list_of_a_group(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    g_two[0] = (status_ud_t){200, "a.com"};
    g_two[1] = (status_ud_t){200, "b.com"};
    firc_id_t id = add_two_list_group(h, "/two0", "/two1");
    ASSERT(list_of(h, id, 1) != NULL);
    two_missing_call_t c = {.id = id};
    ASSERT(on_loop(h, request_missing_two_fn, &c));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, c.states[0]);
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, c.states[1]);
    ASSERT(wait_group_settled(h, 5000));
    harness_stop(h);
    PASS();
}

TEST a_failed_list_keeps_its_rules_while_the_other_updates(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    g_two[0] = (status_ud_t){200, "a.com"};
    g_two[1] = (status_ud_t){200, "b.com"};
    firc_id_t id = add_two_list_group(h, "/two0", "/two1");
    ASSERT(list_of(h, id, 1) != NULL);
    ASSERT_EQ(FIRC_OK, sync_at(h, id, 0, 1000));
    ASSERT_EQ(FIRC_OK, sync_at(h, id, 1, 1000));

    g_two[0].status = 500;
    g_two[1].body = "c.com";
    ASSERT_EQ(FIRC_ERR_UPSTREAM, sync_at(h, id, 0, 2000));
    ASSERT_EQ(FIRC_OK, sync_at(h, id, 1, 2000));

    const firc_group_list_t *l0 = list_of(h, id, 0), *l1 = list_of(h, id, 1);
    ASSERT_EQ_FMT((size_t)1, l0->rules.n, "%zu");
    ASSERT_STR_EQ("a.com", firc_sub_rules_text(&l0->rules, 0));
    ASSERT_EQ(FIRC_SUB_SYNC_ERROR, l0->sync_state);
    ASSERT_EQ_FMT(1u, (unsigned)l0->failed_fetches, "%u");
    ASSERT_EQ_FMT((size_t)1, l1->rules.n, "%zu");
    ASSERT_STR_EQ("c.com", firc_sub_rules_text(&l1->rules, 0));
    ASSERT_EQ_FMT(0u, (unsigned)l1->failed_fetches, "%u");

    harness_stop(h);
    PASS();
}

typedef struct two_due_call {
    int64_t now;
    firc_id_t id;
    firc_sub_sync_state_t states[2];
} two_due_call_t;

static void request_due_two_fn(harness_t *h, void *arg) {
    two_due_call_t *c = arg;
    firc_app_request_sync_due(h->app, c->now);
    for (size_t i = 0; i < 2; i++) { c->states[i] = list_of(h, c->id, i)->sync_state; }
}

TEST a_never_loaded_list_backs_off_alone(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    g_two[1] = (status_ud_t){200, "b.com"};
    firc_id_t id = add_two_list_group(h, "/404", "/two1");
    ASSERT(list_of(h, id, 1) != NULL);
    int64_t base = (int64_t)time(NULL) - 100000;
    ASSERT_EQ(FIRC_ERR_UPSTREAM, sync_at(h, id, 0, base));
    ASSERT_EQ(FIRC_OK, sync_at(h, id, 1, base));
    const firc_group_list_t *l0 = list_of(h, id, 0), *l1 = list_of(h, id, 1);

    ASSERTm("list 0 a minute after its failure", firc_sub_is_due(true, l0, base + 60));
    ASSERT_FALSEm("list 1 holds rules", firc_sub_is_due(true, l1, base + 60));
    ASSERT_EQ(FIRC_ERR_UPSTREAM, sync_at(h, id, 0, base + 60));
    ASSERT_FALSEm("the delay doubled", firc_sub_is_due(true, l0, base + 120));
    ASSERT_FALSE(firc_sub_is_due(true, l1, base + 120));
    ASSERTm("list 0 again at three minutes", firc_sub_is_due(true, l0, base + 180));
    ASSERT_FALSE(firc_sub_is_due(true, l1, base + 180));
    ASSERT_FALSEm("list 1 waits its interval", firc_sub_is_due(true, l1, base + 3599));

    two_due_call_t c = {.now = base + 3600, .id = id};
    ASSERT(on_loop(h, request_due_two_fn, &c));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, c.states[0]);
    ASSERT_EQm("list 1 at its interval", FIRC_SUB_SYNC_QUEUED, c.states[1]);
    ASSERT(wait_group_settled(h, 5000));

    harness_stop(h);
    PASS();
}

TEST a_result_for_another_list_of_the_group_is_not_applied(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    g_two[0] = (status_ud_t){200, "a.com"};
    g_two[1] = (status_ud_t){200, "b.com"};
    firc_id_t id = add_two_list_group(h, "/two0", "/two1");
    ASSERT(list_of(h, id, 1) != NULL);
    ASSERT_EQ(FIRC_OK, sync_at(h, id, 0, 1000));
    ASSERT_EQ(FIRC_OK, sync_at(h, id, 1, 1000));
    uint64_t seq0 = list_of(h, id, 0)->sync_seq;
    ASSERT(seq0 != list_of(h, id, 1)->sync_seq);

    apply_call_t a = {.ev = parsed_event(id, list_at(h->app, id, 1), seq0, "x.example"), .now = 2000,
                      .changed = true};
    ASSERT(on_loop(h, apply_result_fn, &a));
    ASSERT_EQ(FIRC_OK, a.err);
    ASSERT_FALSE(a.changed);
    firc_sub_event_free(a.ev);
    ASSERT_STR_EQ("a.com", firc_sub_rules_text(&list_of(h, id, 0)->rules, 0));
    ASSERT_STR_EQ("b.com", firc_sub_rules_text(&list_of(h, id, 1)->rules, 0));

    harness_stop(h);
    PASS();
}

/* Catches: a result for a deleted list written through a pointer into the freed group. */
TEST a_result_for_a_deleted_list_is_dropped(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;
    firc_id_t lid = sub->lists[0]->id;

    request_call_t r = {.id = id};
    ASSERT(on_loop(h, request_sync_fn, &r));
    ASSERT_EQ(FIRC_OK, r.err);
    ASSERT(wait_settled(h, id, 5000));

    ASSERT(on_loop(h, remove_group_fn, &id));
    ASSERT_EQ(0u, group_count(h));

    feed_call_t f = {.ev = parsed_event(id, lid, 1, "x.example"), .now = 1000};
    ASSERT(on_loop(h, feed_event_fn, &f));

    ASSERT_EQ_FMTm("nothing came back from the dead", 0u, (unsigned)group_count(h), "%u");

    harness_stop(h);
    PASS();
}

/* Catches: an older sync's result overwriting a newer one. */
TEST a_result_with_a_stale_seq_is_dropped(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    request_call_t r = {.id = id};
    ASSERT(on_loop(h, request_sync_fn, &r));
    ASSERT_EQ(FIRC_OK, r.err);
    ASSERT(wait_settled(h, id, 5000));
    sub_view_t before = sub_view(h, id);
    ASSERT_EQ(2u, before.rules_n);
    ASSERT(before.seq > 0);

    apply_call_t a = {.ev = parsed_event(id, list0(h->app, id), before.seq - 1, "x.example"), .now = 2000,
                      .changed = true};
    ASSERT(on_loop(h, apply_result_fn, &a));
    ASSERT_EQ(FIRC_OK, a.err);
    ASSERT_FALSEm("a superseded result changes nothing", a.changed);
    firc_sub_event_free(a.ev);

    sub_view_t after = sub_view(h, id);
    ASSERT_EQ_FMTm("the list the newer job installed is still there", 2u,
                   (unsigned)after.rules_n, "%u");
    ASSERT_STR_EQ("one.example", after.rule[0]);
    ASSERT_EQ(before.last_check, after.last_check);

    harness_stop(h);
    PASS();
}

/* Catches: a request not leaving the list queued, or a started event not marking it fetching. */
TEST a_request_marks_queued_and_a_started_event_marks_fetching(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/404");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    request_call_t r = {.id = id};
    ASSERT(on_loop(h, request_sync_fn, &r));
    ASSERT_EQ(FIRC_OK, r.err);
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, r.state_after);
    ASSERT_STR_EQ("queued", firc_sub_sync_state_name(r.state_after));

    ASSERT(wait_settled(h, id, 5000));
    sub_view_t v = sub_view(h, id);
    ASSERT_EQm("/404 is an error, and the job is over", FIRC_SUB_SYNC_ERROR, v.state);
    uint64_t seq = v.seq;

    feed_call_t stale = {.ev = event_new(FIRC_SUB_EV_STARTED, id, list0(h->app, id), seq - 1), .now = 1000};
    ASSERT(on_loop(h, feed_event_fn, &stale));
    v = sub_view(h, id);
    ASSERT_EQm("a superseded start says nothing about the state", FIRC_SUB_SYNC_ERROR, v.state);

    feed_call_t f = {.ev = event_new(FIRC_SUB_EV_STARTED, id, list0(h->app, id), seq), .now = 1000};
    ASSERT(on_loop(h, feed_event_fn, &f));
    v = sub_view(h, id);
    ASSERT_EQ(FIRC_SUB_SYNC_FETCHING, v.state);
    ASSERT_STR_EQ("fetching", firc_sub_sync_state_name(v.state));

    harness_stop(h);
    PASS();
}

/* Catches: a boot request fetching lists that already have a body, or missing one that has none. */
TEST a_boot_request_covers_every_enabled_list_that_has_no_body(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);

    firc_group_t *wanted = make_list_group(NULL);
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, wanted));

    firc_group_t *disabled = make_list_group(NULL);
    disabled->enable = false;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, disabled));

    firc_group_t *no_url = make_list_group(NULL);
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, no_url));

    firc_group_t *already = make_list_group(NULL);
    already->lists[0]->has_body_hash = true;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, already));

    ASSERT_EQ(FIRC_OK, firc_app_set_list_url(h->app, wanted->id, list0(h->app, wanted->id), url_for("/a")));
    ASSERT_EQ(FIRC_OK, firc_app_set_list_url(h->app, disabled->id, list0(h->app, disabled->id), url_for("/a")));
    ASSERT_EQ(FIRC_OK, firc_app_set_list_url(h->app, already->id, list0(h->app, already->id), url_for("/a")));

    sweep_call_t s = {.n = 4, .ids = {wanted->id, disabled->id, no_url->id, already->id}};
    ASSERT(on_loop(h, request_missing_fn, &s));
    ASSERT_EQm("enabled, a url, and no list yet", FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT_EQm("disabled", FIRC_SUB_SYNC_IDLE, s.states[1]);
    ASSERT_EQm("no url to fetch", FIRC_SUB_SYNC_IDLE, s.states[2]);
    ASSERT_EQm("it already has a list", FIRC_SUB_SYNC_IDLE, s.states[3]);

    ASSERT(wait_settled(h, wanted->id, 5000));
    ASSERT_EQ(2u, sub_view(h, wanted->id).rules_n);

    harness_stop(h);
    PASS();
}

TEST due_lists_are_fetched_and_others_skipped(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int64_t base = (int64_t)time(NULL);

    firc_group_t *due = make_list_group("/a");
    due->lists[0]->interval = 60;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, due));
    firc_id_t due_id = due->id;

    firc_group_t *not_due = make_list_group("/b");
    not_due->lists[0]->interval = 3600;
    not_due->lists[0]->last_check = (uint32_t)(base - 50);
    firc_sub_rules_push(&not_due->lists[0]->rules, "already.example", "namespace", true, test_random_id());
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, not_due));
    firc_id_t not_due_id = not_due->id;

    ASSERT(wait_settled(h, due_id, 5000));
    int hits_before = atomic_load(&g_hits_a);

    sweep_call_t s = {.now = base + 120, .n = 2, .ids = {due_id, not_due_id}};
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT_EQm("not due: not asked for", FIRC_SUB_SYNC_IDLE, s.states[1]);

    ASSERT(wait_settled(h, due_id, 5000));
    ASSERT_EQm("the sweep fetched the due list again", hits_before + 1, atomic_load(&g_hits_a));
    sub_view_t due_cur = sub_view(h, due_id);
    ASSERT_EQ(2u, due_cur.rules_n);
    ASSERT(due_cur.last_check >= (uint32_t)base);
    ASSERT(due_cur.last_update >= (uint32_t)base);

    sub_view_t nd = sub_view(h, not_due_id);
    ASSERT_EQ_FMTm("not fetched: it still holds what it had", 1u, (unsigned)nd.rules_n, "%u");
    ASSERT_STR_EQ("already.example", nd.rule[0]);
    ASSERT_EQ((uint32_t)(base - 50), nd.last_check);

    harness_stop(h);
    PASS();
}

TEST due_but_unchanged_bumps_last_check_without_touching_the_rules(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int64_t base = (int64_t)time(NULL);
    firc_group_t *sub = make_list_group("/a");
    sub->lists[0]->interval = 60;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), base - 1000, NULL, &changed));
    ASSERT(changed);

    sweep_call_t s = {.now = base - 980, .n = 1, .ids = {id}};
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, s.states[0]);
    ASSERT_EQ((uint32_t)(base - 1000), sub_view(h, id).last_check);

    s.now = base - 900;
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT(wait_settled(h, id, 5000));

    sub_view_t v = sub_view(h, id);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, v.state);
    ASSERT_EQ(2u, v.rules_n);
    ASSERT(v.last_check >= (uint32_t)base);
    ASSERT_EQ_FMTm("nothing moved, so nothing was updated", (unsigned)(base - 1000),
                   (unsigned)v.last_update, "%u");

    harness_stop(h);
    PASS();
}

/* Catches: a changed scheduled sync leaking the rule array it replaced (seen under sanitize). */
TEST due_lists_repeated_content_changes_leak_nothing(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int64_t base = (int64_t)time(NULL);
    g_toggle_state = false;
    firc_group_t *sub = make_list_group("/toggle");
    sub->lists[0]->interval = 1;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    sweep_call_t s = {.now = base, .n = 1, .ids = {id}};
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT(wait_settled(h, id, 5000));
    ASSERT_EQ(2u, sub_view(h, id).rules_n);

    s.now = base + 3600;
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT(wait_settled(h, id, 5000));
    sub_view_t v = sub_view(h, id);
    ASSERT_EQ(1u, v.rules_n);
    ASSERT_STR_EQ("three.example", v.rule[0]);

    harness_stop(h);
    PASS();
}

TEST no_due_lists_queues_nothing(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int64_t base = (int64_t)time(NULL);
    firc_group_t *sub = make_list_group("/a");
    sub->lists[0]->interval = 3600;
    sub->lists[0]->last_check = (uint32_t)(base - 10);
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    sweep_call_t s = {.now = base, .n = 1, .ids = {id}};
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, s.states[0]);
    ASSERT_EQ((uint32_t)(base - 10), sub_view(h, id).last_check);

    harness_stop(h);
    PASS();
}

/* Catches: overrides not applied to fetched rules, or applied after the change check. */
TEST a_sync_applies_the_overrides_to_what_it_fetched(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           sub->lists[0], &(firc_sub_rule_key_t){.text = "two.example"}, "domain", &off));
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    const firc_group_t *cur = find_group(h->app, id);
    ASSERT(cur != NULL);
    ASSERT_EQ(2u, cur->lists[0]->rules.n);
    ASSERT_STR_EQm("the untouched line keeps the guesser's type", "namespace",
                   firc_sub_rules_type(&cur->lists[0]->rules, 0));
    ASSERTm("and stays enabled", firc_sub_rules_enable(&cur->lists[0]->rules, 0));
    ASSERT_STR_EQm("the edited line carries the override's type", "domain",
                   firc_sub_rules_type(&cur->lists[0]->rules, 1));
    ASSERT_FALSEm("and the override's enable", firc_sub_rules_enable(&cur->lists[0]->rules, 1));

    harness_stop(h);
    PASS();
}

/* Catches: a list not due at start because of last_update, though nothing is stored. */
TEST a_daemon_that_has_not_checked_is_due(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool enable = true;
    firc_strset(&l->url, "https://example.invalid/l.txt");
    l->interval = 86400;
    l->last_update = 1000;
    l->last_check = 0;

    ASSERTm("a fresh daemon is due inside the interval", firc_sub_is_due(enable, l, 1001));

    l->last_check = 1001;
    ASSERT_FALSEm("and not due again until the interval elapses", firc_sub_is_due(enable, l, 1002));
    ASSERTm("but due when it does", firc_sub_is_due(enable, l, 1001 + 86400));

    firc_group_list_free(l);
    PASS();
}

/* Catches: a fetch that yields no rules leaving the list due on every tick. */
TEST a_fetch_that_yielded_nothing_still_counts_as_a_check(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool enable = true;
    firc_strset(&l->url, "https://example.invalid/empty.txt");
    l->interval = 3600;
    l->last_check = 1000;
    l->last_update = 0;

    ASSERT_EQ_FMTm("no rules, and that is the point", 0u, (unsigned)l->rules.n, "%u");
    ASSERT_FALSEm("a minute later it is NOT due again", firc_sub_is_due(enable, l, 1060));
    ASSERT_FALSEm("nor ten minutes later", firc_sub_is_due(enable, l, 1600));
    ASSERTm("the interval still governs it", firc_sub_is_due(enable, l, 1000 + 3600));

    firc_group_list_free(l);
    PASS();
}

/* Catches: a disabled list, one without a url, or interval 0 after the first fetch being fetched. */
TEST no_rules_does_not_override_the_other_refusals(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool enable = false;
    firc_strset(&l->url, "https://example.invalid/l.txt");
    l->interval = 86400;
    ASSERT_FALSEm("disabled", firc_sub_is_due(enable, l, 1000));

    enable = true;
    firc_strset(&l->url, "");
    ASSERT_FALSEm("no url", firc_sub_is_due(enable, l, 1000));

    firc_strset(&l->url, "https://example.invalid/l.txt");
    l->interval = 0;
    l->last_check = 1000;
    ASSERT_FALSEm("no interval, once it has been fetched", firc_sub_is_due(enable, l, 2000));

    firc_group_list_free(l);
    PASS();
}

/* Catches: the scheduled sync not applying the overrides. */
TEST the_scheduled_sync_applies_the_overrides_too(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int64_t base = (int64_t)time(NULL);
    firc_group_t *sub = make_list_group("/a");
    sub->lists[0]->interval = 3600;
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           sub->lists[0], &(firc_sub_rule_key_t){.text = "two.example"}, "domain", &off));
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    sweep_call_t s = {.now = base, .n = 1, .ids = {id}};
    ASSERT(on_loop(h, request_due_fn, &s));
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, s.states[0]);
    ASSERT(wait_settled(h, id, 5000));

    sub_view_t v = sub_view(h, id);
    ASSERT_EQ(2u, v.rules_n);
    ASSERT_STR_EQm("the untouched line keeps the guesser's type", "namespace", v.type[0]);
    ASSERTm("and stays enabled", v.enable[0]);
    ASSERT_STR_EQm("the edited line carries the override's type", "domain", v.type[1]);
    ASSERT_FALSEm("and the override's enable", v.enable[1]);

    harness_stop(h);
    PASS();
}

/* Catches: interval 0 read as never fetch, so the list is never loaded. */
TEST an_interval_of_zero_does_not_mean_never_fetch(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool enable = true;
    firc_strset(&l->url, "https://example.invalid/l.txt");
    l->interval = 0;
    l->last_check = 0;

    ASSERTm("a daemon that has never checked must fetch", firc_sub_is_due(enable, l, 1000));

    l->last_check = 1000;
    ASSERT_FALSEm("and then never again on a timer", firc_sub_is_due(enable, l, 1001));
    ASSERT_FALSEm("not even much later", firc_sub_is_due(enable, l, 1000 + 86400 * 30));

    firc_group_list_free(l);
    PASS();
}

/* Catches: a list that never loaded waiting a whole interval after a failed fetch. */
TEST a_list_that_never_loaded_is_retried_with_a_growing_delay(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool enable = true;
    firc_strset(&l->url, "https://example.invalid/l.txt");
    l->interval = 86400;
    l->last_check = 1000;

    l->failed_fetches = 1;
    ASSERT_FALSEm("not before a minute", firc_sub_is_due(enable, l, 1059));
    ASSERTm("a minute after the first failure", firc_sub_is_due(enable, l, 1060));
    l->failed_fetches = 2;
    ASSERT_FALSEm("the delay doubles", firc_sub_is_due(enable, l, 1119));
    ASSERT(firc_sub_is_due(enable, l, 1120));
    l->failed_fetches = 3;
    ASSERT_FALSE(firc_sub_is_due(enable, l, 1239));
    ASSERT(firc_sub_is_due(enable, l, 1240));
    l->failed_fetches = 200;
    ASSERT_FALSEm("capped at an hour", firc_sub_is_due(enable, l, 4599));
    ASSERT(firc_sub_is_due(enable, l, 4600));

    l->interval = 0;
    l->failed_fetches = 1;
    ASSERTm("retried even with no timer", firc_sub_is_due(enable, l, 1060));

    firc_group_list_free(l);
    PASS();
}

/* Catches: a list that holds rules retried before its interval. */
TEST a_list_that_holds_rules_waits_its_interval_after_a_failure(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool enable = true;
    firc_strset(&l->url, "https://example.invalid/l.txt");
    l->interval = 7200;
    l->last_check = 1000;
    l->has_body_hash = true;
    l->failed_fetches = 3;

    ASSERT_FALSE(firc_sub_is_due(enable, l, 1240));
    ASSERT_FALSE(firc_sub_is_due(enable, l, 4600));
    ASSERT(firc_sub_is_due(enable, l, 8200));

    firc_group_list_free(l);
    PASS();
}

/* Catches: failed fetches not counted, or the count lost when the group is saved. */
TEST failed_fetches_are_counted_and_survive_a_save(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/404");
    sub->lists[0]->interval = 86400;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_ERR_UPSTREAM, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    const firc_group_t *cur = find_group(h->app, id);
    ASSERT_FALSE(firc_sub_is_due(cur->enable, cur->lists[0], 1059));
    ASSERT(firc_sub_is_due(cur->enable, cur->lists[0], 1060));

    ASSERT_EQ(FIRC_ERR_UPSTREAM, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1060, NULL, &changed));

    firc_group_t **arr = calloc(1, sizeof(*arr));
    arr[0] = make_list_group("/404");
    arr[0]->id = id;
    arr[0]->lists[0]->id = list0(h->app, id);
    arr[0]->lists[0]->interval = 86400;
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(h->app, arr, 1));

    cur = find_group(h->app, id);
    ASSERT_FALSEm("the second failure waits two minutes", firc_sub_is_due(cur->enable, cur->lists[0], 1179));
    ASSERT(firc_sub_is_due(cur->enable, cur->lists[0], 1180));

    harness_stop(h);
    PASS();
}

static firc_group_t *make_replacement(firc_app_t *app, firc_id_t id, const char *path) {
    firc_group_t *nw = make_list_group(path);
    nw->id = id;
    nw->lists[0]->id = list0(app, id);
    return nw;
}

TEST a_replace_with_the_same_id_and_url_keeps_the_list(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    firc_group_t *nw = make_replacement(h->app, id, "/a");
    firc_group_t **arr = calloc(1, sizeof(*arr));
    arr[0] = nw;
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(h->app, arr, 1));

    sub_view_t v = sub_view(h, id);
    ASSERTm("the replaced group is still there under its id", v.found);
    ASSERT_EQ_FMTm("the fetched list moved across instead of the reload starting it empty", 2u,
                   (unsigned)v.rules_n, "%u");
    ASSERTm("its body hash moved too, so a resync of the same bytes is still a no-op",
            v.has_body_hash);
    ASSERT_EQ_FMTm("last_check moved with it", (uint32_t)1000, v.last_check, "%u");
    ASSERT_EQm("nothing is mid-fetch: idle, not left queued or fetching", FIRC_SUB_SYNC_IDLE,
               v.state);

    harness_stop(h);
    PASS();
}

TEST a_replace_with_a_changed_url_starts_empty(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    firc_group_t *nw = make_replacement(h->app, id, "/b");
    firc_group_t **arr = calloc(1, sizeof(*arr));
    arr[0] = nw;
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(h->app, arr, 1));

    sub_view_t v = sub_view(h, id);
    ASSERTm("the replaced group is still there under its id", v.found);
    ASSERT_EQ_FMTm("a changed url names a different list, not the one that was fetched", 0u,
                   (unsigned)v.rules_n, "%u");
    ASSERT_FALSEm("and carries none of the old list's hash either", v.has_body_hash);

    harness_stop(h);
    PASS();
}

TEST overrides_from_the_new_file_apply_to_the_carried_list(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    firc_group_t *nw = make_replacement(h->app, id, "/a");
    bool enable_false = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           nw->lists[0], &(firc_sub_rule_key_t){.text = "one.example"}, NULL, &enable_false));
    firc_group_t **arr = calloc(1, sizeof(*arr));
    arr[0] = nw;
    ASSERT_EQ(FIRC_OK, firc_app_replace_groups(h->app, arr, 1));

    sub_view_t v = sub_view(h, id);
    ASSERTm("the replaced group is still there under its id", v.found);
    ASSERT_EQ_FMTm("the moved list is still the one that was fetched, not refetched empty", 2u,
                   (unsigned)v.rules_n, "%u");
    ASSERT_STR_EQ("one.example", v.rule[0]);
    ASSERT_FALSEm(
        "the new file's override reached the carried-over arena, not just a freshly fetched one",
        v.enable[0]);

    harness_stop(h);
    PASS();
}

/* Reads whether the pipeline's snapshot is provisional (-1 when there is none). */
static void read_provisional_fn(harness_t *h, void *arg) {
    int *out = arg;
    firc_ruleset_snapshot_t *snap = firc_dns_pipeline_snapshot(h->pipeline);
    *out = snap == NULL ? -1 : (snap->provisional ? 1 : 0);
}

static int snapshot_provisional(harness_t *h) {
    int v = -1;
    if (!on_loop(h, read_provisional_fn, &v)) { return -1; }
    return v;
}

/* Catches: a first sync that changes nothing leaving the snapshot provisional. */
TEST an_equal_first_list_clears_provisional(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/empty");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    ASSERT_EQ_FMTm("fixture: no list yet, so the published snapshot is provisional", 1,
                   snapshot_provisional(h), "%d");

    bool changed = true;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT_FALSEm("nothing routable in it: the arena did not move", changed);

    const firc_group_t *cur = find_group(h->app, id);
    ASSERT(cur != NULL);
    ASSERT_EQ_FMTm("the list arrived and was parsed to nothing", 0u, (unsigned)cur->lists[0]->rules.n, "%u");
    ASSERTm("the first list landed: the hash is stored", cur->lists[0]->has_body_hash);

    ASSERT_EQ_FMTm("the list arrived, so nothing is provisional any more", 0,
                   snapshot_provisional(h), "%d");

    harness_stop(h);
    PASS();
}

typedef struct put_mid_sync {
    firc_id_t id;
    firc_err_t request_err;
    firc_sub_sync_state_t state_after_request;
    uint64_t seq_after_request;
    firc_err_t replace_err;
    uint64_t seq_after_replace;
} put_mid_sync_t;

/* Requests a sync and replaces the groups in one loop callback, so the worker cannot post between. */
static void request_then_put_fn(harness_t *h, void *arg) {
    put_mid_sync_t *p = arg;
    p->request_err = firc_app_request_sync(h->app, p->id, list0(h->app, p->id));

    const firc_group_t *existing = find_group(h->app, p->id);
    p->state_after_request = existing->lists[0]->sync_state;
    p->seq_after_request = existing->lists[0]->sync_seq;

    firc_group_t *nw = firc_group_new();
    nw->id = existing->id;
    firc_strset(&nw->name, "renamed");
    firc_strset(&nw->iface, existing->iface);
    test_group_set_list(nw);
    firc_strset(&nw->lists[0]->url, existing->lists[0]->url);
    nw->lists[0]->id = existing->lists[0]->id;
    nw->enable = true;

    firc_group_t **arr = calloc(1, sizeof(*arr));
    arr[0] = nw;
    p->replace_err = firc_app_replace_groups(h->app, arr, 1);

    const firc_group_t *cur = find_group(h->app, p->id);
    p->seq_after_replace = cur != NULL ? cur->lists[0]->sync_seq : 0;
}

TEST a_metadata_put_mid_sync_keeps_the_running_job(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    ASSERT_EQ(FIRC_OK, firc_app_set_list_url(h->app, id, list0(h->app, id), url_for("/b")));

    put_mid_sync_t p = {.id = id};
    ASSERT(on_loop(h, request_then_put_fn, &p));
    ASSERT_EQ(FIRC_OK, p.request_err);
    ASSERT_EQm("fixture: a job really was asked for", FIRC_SUB_SYNC_QUEUED, p.state_after_request);
    ASSERT(p.seq_after_request > 0);
    ASSERT_EQ(FIRC_OK, p.replace_err);
    ASSERT_EQ_FMTm("the replacement inherited the in-flight sync seq",
                   (unsigned long long)p.seq_after_request,
                   (unsigned long long)p.seq_after_replace, "%llu");

    bool landed = false;
    for (int waited = 0; waited <= 5000 && !landed; waited += 5) {
        sub_view_t v = sub_view(h, id);
        landed = v.found && v.rules_n == 1 && strcmp(v.rule[0], "three.example") == 0;
        if (landed) { break; }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    ASSERTm("the running job's result was applied, not dropped as superseded", landed);

    sub_view_t v = sub_view(h, id);
    ASSERT_EQm("and the sync ended rather than being left in flight for ever",
               FIRC_SUB_SYNC_IDLE, v.state);
    ASSERTm("last_check moved off the synchronous sync's 1000", v.last_check > 1000);

    harness_stop(h);
    PASS();
}

typedef struct unchanged_after_put {
    firc_id_t id;
    firc_err_t replace_err;
    uint64_t carried_seq;
    bool hash_after_put;
    firc_err_t apply_err;
    bool has_hash_after;
    firc_sub_sync_state_t state_after;
    size_t rules_after;
} unchanged_after_put_t;

static void put_rules_then_unchanged_fn(harness_t *h, void *arg) {
    unchanged_after_put_t *n = arg;
    const firc_group_t *existing = find_group(h->app, n->id);
    uint8_t told[32];
    memcpy(told, existing->lists[0]->body_hash, sizeof(told));
    uint64_t seq = existing->lists[0]->sync_seq;

    firc_group_list_t *l = (firc_ruleset_group_mut(firc_app_find_group_by_id(h->app, n->id)))->lists[0];
    firc_sub_rules_free(&l->rules);
    firc_sub_rules_init(&l->rules);
    n->replace_err = firc_sub_rules_push(&l->rules, "custom.example", "namespace", true,
                                         test_random_id());
    l->has_body_hash = false;
    memset(l->body_hash, 0, sizeof(l->body_hash));

    const firc_group_t *cur = find_group(h->app, n->id);
    n->carried_seq = cur->lists[0]->sync_seq;
    n->hash_after_put = cur->lists[0]->has_body_hash;

    firc_sub_event_t *ev = event_new(FIRC_SUB_EV_RESULT, n->id, list0(h->app, n->id), seq);
    ev->result = FIRC_SUB_RESULT_UNCHANGED;
    memcpy(ev->hash, told, sizeof(ev->hash));
    bool changed = false;
    n->apply_err = firc_app_apply_sync_result(h->app, ev, 2000, &changed);
    firc_sub_event_free(ev);

    cur = find_group(h->app, n->id);
    n->has_hash_after = cur->lists[0]->has_body_hash;
    n->state_after = cur->lists[0]->sync_state;
    n->rules_after = cur->lists[0]->rules.n;
}

TEST an_unchanged_answer_to_a_list_the_daemon_no_longer_holds_is_parsed_again(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    firc_id_t id = sub->id;

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(h->app, id, list0(h->app, id), 1000, NULL, &changed));
    ASSERT(changed);

    unchanged_after_put_t n = {.id = id};
    ASSERT(on_loop(h, put_rules_then_unchanged_fn, &n));
    ASSERT_EQ(FIRC_OK, n.replace_err);
    ASSERT_FALSEm("fixture: rules no body produced carry no hash",
                  n.hash_after_put);
    ASSERTm("fixture: and the in-flight job's seq is still the list's, so its answer is taken",
            n.carried_seq > 0);
    ASSERT_EQ(FIRC_OK, n.apply_err);

    ASSERT_FALSEm("the hash is NOT stored against rules no body produced", n.has_hash_after);
    ASSERT_EQm("a parse was asked for instead", FIRC_SUB_SYNC_QUEUED, n.state_after);
    ASSERT_EQ_FMTm("and the PUT's own rules are still what it holds meanwhile", 1u,
                   (unsigned)n.rules_after, "%u");

    bool landed = false;
    for (int waited = 0; waited <= 5000; waited += 5) {
        sub_view_t v = sub_view(h, id);
        if (v.found && v.rules_n == 2 && v.has_body_hash) {
            landed = strcmp(v.rule[0], "one.example") == 0;
            break;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    ASSERTm("the list was fetched and parsed again, hash and all", landed);

    harness_stop(h);
    PASS();
}

typedef struct orphan_fixture {
    firc_loop_t *app_loop;
    firc_loop_t *stub_loop;
    firc_httpd_t *stub;
    pthread_t stub_thread;
    firc_config_t cfg;
    firc_app_t *app;
    char dir[64];
    char conf[128];
} orphan_fixture_t;

static void *orphan_stub_thread(void *ud) {
    firc_loop_run(ud);
    return NULL;
}

#define ORPHAN_PORT 18111

static void orphan_fixture_stop(orphan_fixture_t *f) {
    if (f->app != NULL) {
        firc_app_stop_list_worker(f->app);
        firc_app_destroy(f->app);
        f->app = NULL;
    }
    if (f->app_loop != NULL) {
        firc_loop_destroy(f->app_loop);
        f->app_loop = NULL;
    }
    if (f->stub_loop != NULL) {
        firc_loop_stop(f->stub_loop);
        pthread_join(f->stub_thread, NULL);
        firc_httpd_destroy(f->stub);
        firc_loop_destroy(f->stub_loop);
        f->stub_loop = NULL;
    }
    firc_config_clear(&f->cfg);
    if (f->dir[0] != '\0') {
        char groups[160];
        snprintf(groups, sizeof(groups), "%s/groups.yaml", f->dir);
        unlink(groups);
        rmdir(f->dir);
        f->dir[0] = '\0';
    }
}

static orphan_fixture_t g_orphan;
static bool g_orphan_open = false;

static void stop_open_orphan(void) {
    if (!g_orphan_open) { return; }
    g_orphan_open = false;
    orphan_fixture_stop(&g_orphan);
}

TEST a_result_the_loop_never_read_gives_its_rules_back(void) {
    memset(&g_orphan, 0, sizeof(g_orphan));
    orphan_fixture_t *f = &g_orphan;
    firc_config_init_defaults(&f->cfg);
    g_orphan_open = true;

    ASSERT_EQ(FIRC_OK, firc_loop_create(&f->stub_loop));
    ASSERT_EQ(FIRC_OK, firc_httpd_create(f->stub_loop, &f->stub));
    firc_httpd_route(f->stub, "GET", "/a", h_list, &g_list_a);
    ASSERT_EQ(FIRC_OK, firc_httpd_listen_tcp(f->stub, "127.0.0.1", ORPHAN_PORT));
    ASSERT_EQ(0, pthread_create(&f->stub_thread, NULL, orphan_stub_thread, f->stub_loop));

    ASSERT_EQ(FIRC_OK, firc_loop_create(&f->app_loop));
    firc_app_deps_t deps = {.cfg = &f->cfg, .loop = f->app_loop};
    f->app = firc_app_create(&deps);
    ASSERT(f->app != NULL);
    ASSERT_EQ(FIRC_OK, firc_app_start_list_worker(f->app));

    firc_group_t *sub = firc_group_new();
    ASSERT(sub != NULL);
    sub->id = (firc_id_t){{0x0e, 0x0e, 0x0e, 0x0e}};
    sub->enable = true;
    test_group_set_list(sub);
    ASSERT(sub->n_lists != 0);
    char url[128];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/a", ORPHAN_PORT);
    ASSERT_EQ(FIRC_OK, firc_strset(&sub->lists[0]->url, url));
    ASSERT_EQ(FIRC_OK, firc_strset(&sub->iface, "br0"));
    firc_id_t sid = sub->id;
    ASSERT_EQ(FIRC_OK, add_list_group(f->app, sub));

    size_t posted_before = 0, results_before = 0, dropped_before = 0;
    firc_app_sync_event_counts_for_test(&posted_before, &results_before, &dropped_before);
    ASSERT_EQ(FIRC_OK, firc_app_request_sync(f->app, sid, list0(f->app, sid)));

    size_t results = results_before;
    for (int i = 0; i < 2000 && results == results_before; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000 * 1000};
        nanosleep(&ts, NULL);
        firc_app_sync_event_counts_for_test(NULL, &results, NULL);
    }
    ASSERT_EQ_FMTm("the worker posted its result", results_before + 1, results, "%zu");

    size_t dropped_mid = 0;
    firc_app_sync_event_counts_for_test(NULL, NULL, &dropped_mid);
    ASSERT_EQ_FMTm("and nothing has run or been dropped yet: the loop never ran",
                   dropped_before, dropped_mid, "%zu");

    firc_app_stop_list_worker(f->app);
    size_t posted_final = 0;
    firc_app_sync_event_counts_for_test(&posted_final, NULL, NULL);
    ASSERTm("a start, the result, and whatever progress there was",
            posted_final >= posted_before + 2);

    g_orphan_open = false;
    orphan_fixture_stop(f);

    size_t dropped_after = 0;
    firc_app_sync_event_counts_for_test(NULL, NULL, &dropped_after);
    ASSERT_EQ_FMTm("every post the loop never read is counted as dropped once the worker stops",
                   posted_final - posted_before, dropped_after - dropped_before, "%zu");
    PASS();
}

static list_ud_t g_list_many = {.body = NULL};

static bool idle_loop_fixture_start(orphan_fixture_t *f, bool with_conf) {
    memset(f, 0, sizeof(*f));
    firc_config_init_defaults(&f->cfg);
    g_orphan_open = true;
    if (firc_loop_create(&f->stub_loop) != FIRC_OK) { return false; }
    if (firc_httpd_create(f->stub_loop, &f->stub) != FIRC_OK) { return false; }
    firc_httpd_route(f->stub, "GET", "/a", h_list, &g_list_a);
    firc_httpd_route(f->stub, "GET", "/two0", h_status, &g_two[0]);
    firc_httpd_route(f->stub, "GET", "/two1", h_status, &g_two[1]);
    firc_httpd_route(f->stub, "GET", "/many", h_list, &g_list_many);
    if (firc_httpd_listen_tcp(f->stub, "127.0.0.1", ORPHAN_PORT) != FIRC_OK) { return false; }
    if (pthread_create(&f->stub_thread, NULL, orphan_stub_thread, f->stub_loop) != 0) { return false; }
    if (firc_loop_create(&f->app_loop) != FIRC_OK) { return false; }
    if (with_conf) {
        snprintf(f->dir, sizeof(f->dir), "/tmp/firc-subsync-XXXXXX");
        if (mkdtemp(f->dir) == NULL) {
            f->dir[0] = '\0';
            return false;
        }
        snprintf(f->conf, sizeof(f->conf), "%s/firc.conf", f->dir);
    }
    firc_app_deps_t deps = {.cfg = &f->cfg, .loop = f->app_loop, .config_path = with_conf ? f->conf : NULL};
    f->app = firc_app_create(&deps);
    return f->app != NULL && firc_app_start_list_worker(f->app) == FIRC_OK;
}

static const char *orphan_url(const char *path) {
    snprintf(g_url, sizeof(g_url), "http://127.0.0.1:%d%s", ORPHAN_PORT, path);
    return g_url;
}

static firc_id_t idle_loop_group(orphan_fixture_t *f, const char *path0, const char *path1) {
    firc_id_t none = {{0, 0, 0, 0}};
    firc_group_t *g = firc_group_new();
    if (g == NULL) { return none; }
    g->id = test_random_id();
    firc_strset(&g->name, "");
    firc_strset(&g->iface, "eth0");
    g->enable = true;
    test_group_set_list(g);
    firc_strset(&g->lists[0]->url, "");
    firc_id_t id = g->id;
    if (firc_app_add_group(f->app, g) != FIRC_OK) { return none; }
    if (path1 != NULL && test_group_add_list_at(g, orphan_url(path1)) == NULL) { return none; }
    if (firc_app_set_list_url(f->app, id, list_at(f->app, id, 0), orphan_url(path0)) != FIRC_OK) { return none; }
    return id;
}

static void noop_post(firc_loop_t *loop, void *ud) {
    (void)loop;
    (void)ud;
}

static void stop_post(firc_loop_t *loop, void *ud) {
    (void)ud;
    firc_loop_stop(loop);
}

static size_t fill_post_queue(firc_loop_t *loop) {
    size_t n = 0;
    while (firc_loop_post(loop, noop_post, NULL) == FIRC_OK) { n++; }
    return n;
}

static void *app_loop_thread(void *ud) {
    firc_loop_run(ud);
    return NULL;
}

static void sleep_ms(unsigned ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

typedef struct list_probe {
    firc_app_t *app;
    firc_id_t id;
    firc_sub_sync_state_t state;
    size_t rules;
    sem_t done;
} list_probe_t;

static void list_probe_cb(firc_loop_t *loop, void *ud) {
    (void)loop;
    list_probe_t *p = ud;
    const firc_group_t *g = find_group(p->app, p->id);
    p->state = g != NULL ? g->lists[0]->sync_state : FIRC_SUB_SYNC_IDLE;
    p->rules = g != NULL ? g->lists[0]->rules.n : 0;
    sem_post(&p->done);
}

static bool probe_list(firc_loop_t *loop, list_probe_t *p) {
    sem_init(&p->done, 0, 0);
    if (firc_loop_post(loop, list_probe_cb, p) != FIRC_OK) {
        sem_destroy(&p->done);
        return false;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    bool ok = sem_timedwait(&p->done, &ts) == 0;
    sem_destroy(&p->done);
    return ok;
}

TEST a_result_reaches_the_list_when_the_loop_queue_is_full(void) {
    orphan_fixture_t *f = &g_orphan;
    ASSERT(idle_loop_fixture_start(f, false));
    firc_id_t id = idle_loop_group(f, "/a", NULL);
    ASSERT(find_group(f->app, id) != NULL);

    ASSERT(fill_post_queue(f->app_loop) > 0);
    ASSERT_EQ(FIRC_OK, firc_app_request_sync(f->app, id, list0(f->app, id)));
    sleep_ms(300);

    pthread_t loop_thread_id;
    ASSERT_EQ(0, pthread_create(&loop_thread_id, NULL, app_loop_thread, f->app_loop));
    list_probe_t p = {.app = f->app, .id = id};
    bool landed = false;
    for (int waited = 0; waited <= 3000 && !landed; waited += 10) {
        if (probe_list(f->app_loop, &p)) { landed = p.state == FIRC_SUB_SYNC_IDLE && p.rules == 2; }
        if (!landed) { sleep_ms(10); }
    }
    while (firc_loop_post(f->app_loop, stop_post, NULL) != FIRC_OK) { sleep_ms(5); }
    pthread_join(loop_thread_id, NULL);
    ASSERTm("the list took its rules once the queue drained", landed);

    g_orphan_open = false;
    orphan_fixture_stop(f);
    PASS();
}

TEST results_of_one_iteration_build_and_save_once(void) {
    orphan_fixture_t *f = &g_orphan;
    g_two[0] = (status_ud_t){200, "a.com"};
    g_two[1] = (status_ud_t){200, "b.com"};
    ASSERT(idle_loop_fixture_start(f, true));
    firc_id_t id = idle_loop_group(f, "/two0", "/two1");
    ASSERT(find_group(f->app, id) != NULL);

    uint64_t snaps_before = 0, saves_before = 0;
    firc_app_publish_counts_for_test(f->app, &snaps_before, &saves_before);
    size_t results_before = 0;
    firc_app_sync_event_counts_for_test(NULL, &results_before, NULL);
    size_t queued = 0;
    ASSERT_EQ(FIRC_OK, firc_app_request_sync_group(f->app, id, &queued));
    ASSERT_EQ_FMT((size_t)2, queued, "%zu");

    size_t results = results_before;
    for (int i = 0; i < 1000 && results < results_before + 2; i++) {
        sleep_ms(5);
        firc_app_sync_event_counts_for_test(NULL, &results, NULL);
    }
    ASSERT_EQ_FMT(results_before + 2, results, "%zu");

    ASSERT_EQ(FIRC_OK, firc_loop_post(f->app_loop, stop_post, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(f->app_loop));

    uint64_t snaps = 0, saves = 0;
    firc_app_publish_counts_for_test(f->app, &snaps, &saves);
    ASSERT_EQ_FMT((unsigned long long)snaps_before + 1, (unsigned long long)snaps, "%llu");
    ASSERT_EQ_FMT((unsigned long long)saves_before + 1, (unsigned long long)saves, "%llu");
    const firc_group_t *g = find_group(f->app, id);
    ASSERT(g != NULL && g->n_lists == 2);
    for (size_t i = 0; i < 2; i++) {
        ASSERT_EQ(FIRC_SUB_SYNC_IDLE, g->lists[i]->sync_state);
        ASSERT(g->lists[i]->has_body_hash);
        ASSERT_EQ_FMT((size_t)1, g->lists[i]->rules.n, "%zu");
    }
    ASSERT_STR_EQ("a.com", firc_sub_rules_text(&g->lists[0]->rules, 0));
    ASSERT_STR_EQ("b.com", firc_sub_rules_text(&g->lists[1]->rules, 0));

    g_orphan_open = false;
    orphan_fixture_stop(f);
    PASS();
}

typedef struct heard {
    size_t n;
    firc_id_t list[16];
    bool done[16];
    firc_sub_sync_state_t state[16];
} heard_t;

static void hear_sync(void *ud, firc_id_t owner, const firc_group_list_t *list, bool done) {
    (void)owner;
    heard_t *h = ud;
    if (h->n >= 16) { return; }
    h->list[h->n] = list->id;
    h->done[h->n] = done;
    h->state[h->n] = list->sync_state;
    h->n++;
}

TEST a_batch_ends_the_group_stream_at_its_last_result(void) {
    orphan_fixture_t *f = &g_orphan;
    g_two[0] = (status_ud_t){200, "a.com"};
    g_two[1] = (status_ud_t){200, "b.com"};
    ASSERT(idle_loop_fixture_start(f, false));
    firc_id_t id = idle_loop_group(f, "/two0", "/two1");
    ASSERT(find_group(f->app, id) != NULL);
    static heard_t heard;
    memset(&heard, 0, sizeof(heard));
    firc_app_set_sync_listener(f->app, hear_sync, &heard);

    size_t results_before = 0;
    firc_app_sync_event_counts_for_test(NULL, &results_before, NULL);
    size_t queued = 0;
    ASSERT_EQ(FIRC_OK, firc_app_request_sync_group(f->app, id, &queued));
    size_t results = results_before;
    for (int i = 0; i < 1000 && results < results_before + 2; i++) {
        sleep_ms(5);
        firc_app_sync_event_counts_for_test(NULL, &results, NULL);
    }
    ASSERT_EQ_FMT(results_before + 2, results, "%zu");
    ASSERT_EQ(FIRC_OK, firc_loop_post(f->app_loop, stop_post, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(f->app_loop));

    size_t done = 0, final0 = 0, final1 = 0;
    firc_id_t l0 = list_at(f->app, id, 0), l1 = list_at(f->app, id, 1);
    for (size_t i = 0; i < heard.n; i++) {
        if (heard.done[i]) { done++; }
        if (heard.state[i] == FIRC_SUB_SYNC_IDLE && firc_id_equal(heard.list[i], l0)) { final0++; }
        if (heard.state[i] == FIRC_SUB_SYNC_IDLE && firc_id_equal(heard.list[i], l1)) { final1++; }
    }
    ASSERT(heard.n > 0);
    ASSERT_EQ_FMT((size_t)1, done, "%zu");
    ASSERTm("the stream ends with the last word", heard.done[heard.n - 1]);
    ASSERT_EQ_FMT((size_t)1, final0, "%zu");
    ASSERT_EQ_FMT((size_t)1, final1, "%zu");

    firc_app_set_sync_listener(f->app, NULL, NULL);
    g_orphan_open = false;
    orphan_fixture_stop(f);
    PASS();
}

TEST progress_waiting_for_the_loop_is_kept_once_per_job(void) {
    orphan_fixture_t *f = &g_orphan;
    ASSERT(g_list_many.body != NULL);
    ASSERT(idle_loop_fixture_start(f, false));
    firc_id_t id = idle_loop_group(f, "/many", NULL);
    ASSERT(find_group(f->app, id) != NULL);

    size_t posted_before = 0, results_before = 0;
    firc_app_sync_event_counts_for_test(&posted_before, &results_before, NULL);
    ASSERT_EQ(FIRC_OK, firc_app_request_sync(f->app, id, list0(f->app, id)));
    size_t results = results_before;
    for (int i = 0; i < 2000 && results == results_before; i++) {
        sleep_ms(5);
        firc_app_sync_event_counts_for_test(NULL, &results, NULL);
    }
    ASSERT_EQ_FMT(results_before + 1, results, "%zu");
    size_t posted = 0;
    firc_app_sync_event_counts_for_test(&posted, NULL, NULL);
    ASSERT_EQ_FMTm("a start, one progress, the result", posted_before + 3, posted, "%zu");

    g_orphan_open = false;
    orphan_fixture_stop(f);
    PASS();
}

typedef struct stop_call {
    firc_app_t *app;
    sem_t done;
} stop_call_t;

static void *stop_worker_thread(void *ud) {
    stop_call_t *c = ud;
    firc_app_stop_list_worker(c->app);
    sem_post(&c->done);
    return NULL;
}

TEST a_stop_ends_a_worker_waiting_on_a_full_loop_queue(void) {
    orphan_fixture_t *f = &g_orphan;
    ASSERT(idle_loop_fixture_start(f, false));
    firc_id_t id = idle_loop_group(f, "/a", NULL);
    ASSERT(find_group(f->app, id) != NULL);
    ASSERT(fill_post_queue(f->app_loop) > 0);
    ASSERT_EQ(FIRC_OK, firc_app_request_sync(f->app, id, list0(f->app, id)));
    sleep_ms(200);

    static stop_call_t c;
    c.app = f->app;
    sem_init(&c.done, 0, 0);
    pthread_t t;
    ASSERT_EQ(0, pthread_create(&t, NULL, stop_worker_thread, &c));
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 2;
    bool stopped = sem_timedwait(&c.done, &ts) == 0;
    ASSERTm("the stop returned while the queue was still full", stopped);
    pthread_join(t, NULL);
    sem_destroy(&c.done);

    g_orphan_open = false;
    orphan_fixture_stop(f);
    PASS();
}

typedef struct fetching_due {
    firc_id_t id;
    bool due;
    uint64_t seq_after;
    firc_sub_sync_state_t state_after;
} fetching_due_t;

static void due_while_fetching_fn(harness_t *h, void *arg) {
    fetching_due_t *c = arg;
    const firc_group_t *g = find_group(h->app, c->id);
    firc_group_list_t *l = g->lists[0];
    int64_t now = (int64_t)time(NULL);
    l->sync_state = FIRC_SUB_SYNC_FETCHING;
    l->sync_seq = 777;
    c->due = firc_sub_is_due(true, l, now);
    firc_app_request_sync_due(h->app, now);
    c->seq_after = l->sync_seq;
    c->state_after = l->sync_state;
    l->sync_state = FIRC_SUB_SYNC_IDLE;
}

TEST a_due_sweep_leaves_the_list_being_fetched_alone(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *sub = make_list_group("/a");
    firc_id_t id = sub->id;
    ASSERT_EQ(FIRC_OK, add_list_group(h->app, sub));
    fetching_due_t c = {.id = id};
    ASSERT(on_loop(h, due_while_fetching_fn, &c));
    ASSERTm("the list is due", c.due);
    ASSERT_EQ_FMT((unsigned long long)777, (unsigned long long)c.seq_after, "%llu");
    ASSERT_EQ(FIRC_SUB_SYNC_FETCHING, c.state_after);
    harness_stop(h);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    firc_log_set_output_floor(FIRC_LOG_ERROR);
    firc_sub_fetch_global_init();
    char *many = malloc(5u * FIRC_SUB_PARSE_PROGRESS_LINES * 16u);
    if (many != NULL) {
        size_t off = 0;
        for (unsigned i = 0; i < 5u * FIRC_SUB_PARSE_PROGRESS_LINES; i++) {
            off += (size_t)sprintf(many + off, "m%u.example\n", i);
        }
        g_list_many.body = many;
    }
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(stop_open_harness, NULL);
    RUN_TEST(a_result_the_loop_never_read_gives_its_rules_back);
    RUN_TEST(a_result_reaches_the_list_when_the_loop_queue_is_full);
    RUN_TEST(results_of_one_iteration_build_and_save_once);
    RUN_TEST(a_batch_ends_the_group_stream_at_its_last_result);
    RUN_TEST(progress_waiting_for_the_loop_is_kept_once_per_job);
    RUN_TEST(a_stop_ends_a_worker_waiting_on_a_full_loop_queue);
    RUN_TEST(a_due_sweep_leaves_the_list_being_fetched_alone);
    RUN_TEST(first_sync_fetches_and_marks_changed);
    RUN_TEST(a_sync_applies_the_overrides_to_what_it_fetched);
    RUN_TEST(the_scheduled_sync_applies_the_overrides_too);
    RUN_TEST(a_daemon_that_has_not_checked_is_due);
    RUN_TEST(a_fetch_that_yielded_nothing_still_counts_as_a_check);
    RUN_TEST(no_rules_does_not_override_the_other_refusals);
    RUN_TEST(an_interval_of_zero_does_not_mean_never_fetch);
    RUN_TEST(a_list_that_never_loaded_is_retried_with_a_growing_delay);
    RUN_TEST(a_list_that_holds_rules_waits_its_interval_after_a_failure);
    RUN_TEST(failed_fetches_are_counted_and_survive_a_save);
    RUN_TEST(resync_same_content_is_unchanged_but_bumps_last_check);
    RUN_TEST(resync_different_content_updates_rules_and_last_update);
    RUN_TEST(the_same_body_is_not_parsed_twice);
    RUN_TEST(the_scheduled_check_does_not_parse_the_same_bytes_either);
    RUN_TEST(a_scheduled_change_is_one_the_manual_sync_knows_about);
    RUN_TEST(unknown_id_is_noent);
    RUN_TEST(empty_url_and_no_override_is_inval);
    RUN_TEST(fetch_failure_is_upstream_error);
    RUN_TEST(a_fetch_error_is_the_list_state);
    RUN_TEST(a_result_for_a_deleted_list_is_dropped);
    RUN_TEST(a_url_another_list_of_the_group_holds_is_refused);
    RUN_TEST(a_boot_request_covers_every_list_of_a_group);
    RUN_TEST(a_failed_list_keeps_its_rules_while_the_other_updates);
    RUN_TEST(a_never_loaded_list_backs_off_alone);
    RUN_TEST(a_result_for_another_list_of_the_group_is_not_applied);
    RUN_TEST(a_result_with_a_stale_seq_is_dropped);
    RUN_TEST(a_request_marks_queued_and_a_started_event_marks_fetching);
    RUN_TEST(a_boot_request_covers_every_enabled_list_that_has_no_body);
    RUN_TEST(due_lists_are_fetched_and_others_skipped);
    RUN_TEST(due_but_unchanged_bumps_last_check_without_touching_the_rules);
    RUN_TEST(due_lists_repeated_content_changes_leak_nothing);
    RUN_TEST(no_due_lists_queues_nothing);
    RUN_TEST(a_replace_with_the_same_id_and_url_keeps_the_list);
    RUN_TEST(a_replace_with_a_changed_url_starts_empty);
    RUN_TEST(overrides_from_the_new_file_apply_to_the_carried_list);
    RUN_TEST(an_equal_first_list_clears_provisional);
    RUN_TEST(a_metadata_put_mid_sync_keeps_the_running_job);
    RUN_TEST(an_unchanged_answer_to_a_list_the_daemon_no_longer_holds_is_parsed_again);
    free(many);
    GREATEST_MAIN_END();
}
