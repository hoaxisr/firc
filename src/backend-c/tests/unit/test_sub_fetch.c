#include "greatest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <curl/curl.h>

#include "firc/loop.h"
#include "firc/httpd.h"
#include "firc/sub_fetch.h"
#include "firc/version.h"

#define TEST_PORT 18100

static void h_list(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "example.com\nexample.org";
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, sizeof(body) - 1);
}

/* A body with a NUL in the middle. */
static void h_nul(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "good1.example.com\n\0after.example.com\nmore.example.com\n";
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, sizeof(body) - 1);
}

static const char k_srs_body[] = "SRS\x02x\x9c\x00\x01\x00";

static void h_srs(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write(res, 200, "application/octet-stream", (const uint8_t *)k_srs_body, sizeof(k_srs_body) - 1);
}

static void h_empty(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write(res, 200, "text/plain", NULL, 0);
}

static void h_notfound_status(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "nope";
    firc_http_res_write(res, 404, "text/plain", (const uint8_t *)body, sizeof(body) - 1);
}

static char g_big_body[FIRC_SUB_FETCH_MAX_BODY_BYTES + 1024];

static void h_big(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)g_big_body, sizeof(g_big_body));
}

#define BIG300K_LEN 300000
static char g_big300k_body[BIG300K_LEN];

static void h_big300k(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)g_big300k_body, sizeof(g_big300k_body));
}

static void h_ua(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    const char *ua = firc_http_req_header(req, "User-Agent");
    const char *body = ua != NULL ? ua : "";
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, strlen(body));
}

static void h_hdr(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    const char *ua = firc_http_req_header(req, "User-Agent");
    const char *hwid = firc_http_req_header(req, "X-HWID");
    char body[256];
    snprintf(body, sizeof body, "%s|%s", ua != NULL ? ua : "-", hwid != NULL ? hwid : "-");
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, strlen(body));
}

static void h_hdr2(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    const char *hwid = firc_http_req_header(req, "X-HWID");
    const char *auth = firc_http_req_header(req, "Authorization");
    const char *cookie = firc_http_req_header(req, "Cookie");
    char body[256];
    snprintf(body, sizeof body, "%s|%s|%s", hwid != NULL ? hwid : "-", auth != NULL ? auth : "-",
             cookie != NULL ? cookie : "-");
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, strlen(body));
}

static int g_hits_target;
static int g_hits_counted;

static void h_target(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    g_hits_target++;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)"target", 6);
}

static void h_counted(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    g_hits_counted++;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)"counted", 7);
}

static void h_payload(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)"payload", 7);
}

static void h_moved(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    char loc[128];
    snprintf(loc, sizeof(loc), "http://127.0.0.1:%d/payload", TEST_PORT);
    firc_http_res_set_header(res, "Location", loc);
    firc_http_res_write(res, 302, "text/html", (const uint8_t *)"MOVED", 5);
}

static void h_accept(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    const char *v = firc_http_req_header(req, "Accept");
    const char *body = v != NULL ? v : "";
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, strlen(body));
}

static void h_limited(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_set_header(res, "X-RateLimit-Remaining", "0");
    firc_http_res_set_header(res, "X-RateLimit-Reset", "1791831689");
    firc_http_res_write(res, 403, "text/plain", (const uint8_t *)"rate limited", 12);
}

static void h_big_refusal(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write(res, 403, "text/plain", (const uint8_t *)g_big_body, sizeof(g_big_body));
}

static void h_big_redirect(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    char loc[128];
    snprintf(loc, sizeof(loc), "http://127.0.0.1:%d/payload", TEST_PORT);
    firc_http_res_set_header(res, "Location", loc);
    firc_http_res_write(res, 302, "text/html", (const uint8_t *)g_big_body, sizeof(g_big_body));
}

static firc_http_deferred_t *g_deferred;

static void on_deferred_close(void *ud) {
    (void)ud;
    firc_http_deferred_drop(g_deferred);
    g_deferred = NULL;
}

static void h_never(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    g_deferred = firc_http_res_defer(res, on_deferred_close, NULL);
}

static void on_chunked_close(void *ud) { (void)ud; }

static void h_chunked(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_stream_t *st = firc_http_res_hold(res, on_chunked_close, NULL);
    if (st == NULL) { return; }
    firc_http_stream_write(st, "abc", 3);
    firc_http_stream_close(st);
}

static firc_http_stream_t *g_trickle;
static int g_trickle_timer;
static firc_loop_t *g_trickle_loop;

static void on_trickle_close(void *ud) {
    (void)ud;
    g_trickle = NULL;
    firc_loop_del_timer(g_trickle_loop, g_trickle_timer);
}

static void trickle_tick(firc_loop_t *loop, void *ud) {
    (void)loop;
    (void)ud;
    if (g_trickle != NULL) { firc_http_stream_write(g_trickle, "x", 1); }
}

static void h_trickle(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    g_trickle_loop = firc_http_res_loop(res);
    g_trickle = firc_http_res_hold(res, on_trickle_close, NULL);
    if (g_trickle == NULL) { return; }
    firc_loop_add_timer(g_trickle_loop, 100, 100, trickle_tick, NULL, &g_trickle_timer);
}

typedef struct redirect_ud {
    int status;
    char location[128];
} redirect_ud_t;

static void h_redirect(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    redirect_ud_t *r = ud;
    firc_http_res_set_header(res, "Location", r->location);
    firc_http_res_write(res, r->status, NULL, NULL, 0);
}

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *srv;
    pthread_t thread;
    redirect_ud_t redirects[32];
    size_t n_redirects;
} harness_t;

static void h_slow_hop(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    struct timespec ts = {0, 700 * 1000000L};
    nanosleep(&ts, NULL);
    char loc[128];
    snprintf(loc, sizeof(loc), "http://127.0.0.1:%d%s", TEST_PORT, (const char *)ud);
    firc_http_res_set_header(res, "Location", loc);
    firc_http_res_write(res, 302, "text/html", (const uint8_t *)"MOVED", 5);
}

static void h_slow_list(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    struct timespec ts = {0, 700 * 1000000L};
    nanosleep(&ts, NULL);
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)"slow", 4);
}

static void *loop_thread(void *ud) {
    harness_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

static void add_redirect(harness_t *h, const char *path, int status, const char *location_path) {
    redirect_ud_t *r = &h->redirects[h->n_redirects++];
    r->status = status;
    snprintf(r->location, sizeof(r->location), "http://127.0.0.1:%d%s", TEST_PORT, location_path);
    firc_httpd_route(h->srv, "GET", path, h_redirect, r);
}

static void add_redirect_to(harness_t *h, const char *path, const char *location) {
    redirect_ud_t *r = &h->redirects[h->n_redirects++];
    r->status = 302;
    snprintf(r->location, sizeof(r->location), "%s", location);
    firc_httpd_route(h->srv, "GET", path, h_redirect, r);
}

static harness_t *other_origin_start(void) {
    harness_t *h = calloc(1, sizeof(*h));
    if (h == NULL) { return NULL; }
    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    if (firc_httpd_create(h->loop, &h->srv) != FIRC_OK) { return NULL; }
    firc_httpd_route(h->srv, "GET", "/hdr2", h_hdr2, NULL);
    if (firc_httpd_listen_tcp(h->srv, "127.0.0.1", TEST_PORT + 1) != FIRC_OK) { return NULL; }
    pthread_create(&h->thread, NULL, loop_thread, h);
    return h;
}

static harness_t *harness_start(void) {
    harness_t *h = calloc(1, sizeof(*h));
    memset(g_big_body, 'a', sizeof(g_big_body));
    memset(g_big300k_body, 'b', sizeof(g_big300k_body));

    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    if (firc_httpd_create(h->loop, &h->srv) != FIRC_OK) { return NULL; }

    firc_httpd_route(h->srv, "GET", "/list", h_list, NULL);
    firc_httpd_route(h->srv, "GET", "/empty", h_empty, NULL);
    firc_httpd_route(h->srv, "GET", "/nul", h_nul, NULL);
    firc_httpd_route(h->srv, "GET", "/srs", h_srs, NULL);
    firc_httpd_route(h->srv, "GET", "/notfound", h_notfound_status, NULL);
    firc_httpd_route(h->srv, "GET", "/404", h_notfound_status, NULL);
    firc_httpd_route(h->srv, "GET", "/big", h_big, NULL);
    firc_httpd_route(h->srv, "GET", "/big300k", h_big300k, NULL);
    firc_httpd_route(h->srv, "GET", "/ua", h_ua, NULL);
    firc_httpd_route(h->srv, "GET", "/hdr", h_hdr, NULL);
    firc_httpd_route(h->srv, "GET", "/hdr2", h_hdr2, NULL);
    add_redirect_to(h, "/same_origin_hdr2", "http://127.0.0.1:18100/hdr2");
    add_redirect_to(h, "/other_port_hdr2", "http://127.0.0.1:18101/hdr2");
    firc_httpd_route(h->srv, "GET", "/target", h_target, NULL);
    firc_httpd_route(h->srv, "GET", "/counted", h_counted, NULL);
    firc_httpd_route(h->srv, "GET", "/payload", h_payload, NULL);
    firc_httpd_route(h->srv, "GET", "/moved", h_moved, NULL);
    firc_httpd_route(h->srv, "GET", "/accept", h_accept, NULL);
    firc_httpd_route(h->srv, "GET", "/limited", h_limited, NULL);
    firc_httpd_route(h->srv, "GET", "/never", h_never, NULL);
    firc_httpd_route(h->srv, "GET", "/trickle", h_trickle, NULL);
    firc_httpd_route(h->srv, "GET", "/chunked", h_chunked, NULL);
    firc_httpd_route(h->srv, "GET", "/big_refusal", h_big_refusal, NULL);
    firc_httpd_route(h->srv, "GET", "/big_redirect", h_big_redirect, NULL);
    add_redirect(h, "/to_target", 302, "/target");
    add_redirect(h, "/redirect_accept", 302, "/accept");

    add_redirect(h, "/redirect301", 301, "/list");
    add_redirect(h, "/redirect302", 302, "/list");
    add_redirect(h, "/redirect303", 303, "/list");
    add_redirect(h, "/redirect307", 307, "/list");
    add_redirect(h, "/redirect308", 308, "/list");
    firc_httpd_route(h->srv, "GET", "/slow_hop", h_slow_hop, "/slow_list");
    firc_httpd_route(h->srv, "GET", "/slow_list", h_slow_list, NULL);
    add_redirect(h, "/redirect_ua", 302, "/ua");
    add_redirect(h, "/loopA", 302, "/loopB");
    add_redirect(h, "/loopB", 302, "/loopA");
    add_redirect(h, "/chain_ok0", 302, "/chain_ok1");
    add_redirect(h, "/chain_ok1", 302, "/chain_ok2");
    add_redirect(h, "/chain_ok2", 302, "/chain_ok3");
    add_redirect(h, "/chain_ok3", 302, "/chain_ok4");
    add_redirect(h, "/chain_ok4", 302, "/list");
    add_redirect(h, "/chain_over0", 302, "/chain_over1");
    add_redirect(h, "/chain_over1", 302, "/chain_over2");
    add_redirect(h, "/chain_over2", 302, "/chain_over3");
    add_redirect(h, "/chain_over3", 302, "/chain_over4");
    add_redirect(h, "/chain_over4", 302, "/chain_over5");
    add_redirect(h, "/chain_over5", 302, "/list");

    if (firc_httpd_listen_tcp(h->srv, "127.0.0.1", TEST_PORT) != FIRC_OK) { return NULL; }
    pthread_create(&h->thread, NULL, loop_thread, h);
    return h;
}

static void harness_stop(harness_t *h) {
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

TEST fetches_plain_200(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list(url_for("/list"), &body, &len));
    ASSERT_STR_EQ("example.com\nexample.org", body);
    ASSERT_EQ(strlen(body), len);
    free(body);
    harness_stop(h);
    PASS();
}

TEST a_body_with_a_nul_in_it_is_not_a_list(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ_FMTm("refused, not silently truncated at the NUL", (int)FIRC_ERR_PROTO,
                   (int)firc_sub_fetch_list(url_for("/nul"), &body, &len), "%d");
    ASSERTm("and nothing handed back to parse", body == NULL);
    harness_stop(h);
    PASS();
}

TEST a_compiled_rule_set_is_fetched_with_its_nul_bytes(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ_FMT((int)FIRC_OK, (int)firc_sub_fetch_list(url_for("/srs"), &body, &len), "%d");
    ASSERT_EQ_FMT(sizeof(k_srs_body) - 1, len, "%zu");
    ASSERT_MEM_EQ(k_srs_body, body, len);
    free(body);
    harness_stop(h);
    PASS();
}

TEST fetches_empty_body(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = (size_t)-1;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list(url_for("/empty"), &body, &len));
    ASSERT(body != NULL);
    ASSERT_EQ(0u, len);
    ASSERT_STR_EQ("", body);
    free(body);
    harness_stop(h);
    PASS();
}

TEST follows_301_and_302(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list(url_for("/redirect301"), &body, &len));
    ASSERT_STR_EQ("example.com\nexample.org", body);
    free(body);

    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list(url_for("/redirect302"), &body, &len));
    ASSERT_STR_EQ("example.com\nexample.org", body);
    free(body);
    harness_stop(h);
    PASS();
}

/* Catches: 303, 307 or 308 answered as a refusal instead of followed. */
TEST follows_303_307_and_308(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static const char *const paths[] = {"/redirect303", "/redirect307", "/redirect308"};
    for (size_t i = 0; i < 3; i++) {
        char *body = NULL;
        size_t len = 0;
        ASSERT_EQ_FMTm(paths[i], FIRC_OK, firc_sub_fetch_list(url_for(paths[i]), &body, &len), "%d");
        ASSERT_STR_EQ("example.com\nexample.org", body);
        free(body);
    }
    harness_stop(h);
    PASS();
}

TEST detects_redirect_loop(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_sub_fetch_list(url_for("/loopA"), &body, &len));
    ASSERT(body == NULL);
    harness_stop(h);
    PASS();
}

TEST allows_exactly_five_redirects(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list(url_for("/chain_ok0"), &body, &len));
    ASSERT_STR_EQ("example.com\nexample.org", body);
    free(body);
    harness_stop(h);
    PASS();
}

TEST rejects_six_redirects(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_sub_fetch_list(url_for("/chain_over0"), &body, &len));
    ASSERT(body == NULL);
    harness_stop(h);
    PASS();
}

TEST non_2xx_is_proto_error(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_sub_fetch_list(url_for("/notfound"), &body, &len));
    ASSERT(body == NULL);
    harness_stop(h);
    PASS();
}

TEST oversized_body_is_limit_error(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_sub_fetch_list(url_for("/big"), &body, &len));
    ASSERT(body == NULL);
    harness_stop(h);
    PASS();
}

TEST unsupported_scheme_is_inval(void) {
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_sub_fetch_list("ftp://example.com/list.txt", &body, &len));
    ASSERT(body == NULL);
    PASS();
}

TEST malformed_url_is_inval(void) {
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_sub_fetch_list("not a url at all", &body, &len));
    ASSERT(body == NULL);
    PASS();
}

typedef struct prog {
    size_t calls;
    size_t last_bytes;
    size_t last_total;
} prog_t;

static bool note_progress(void *ud, size_t bytes, size_t total) {
    prog_t *p = ud;
    p->calls++;
    p->last_bytes = bytes;
    p->last_total = total;
    return true;
}

static bool abort_at_once(void *ud, size_t bytes, size_t total) {
    (void)ud;
    (void)bytes;
    (void)total;
    return false;
}

/* Catches: no progress callback wired, or no final (len, len) call after a transfer. */
TEST fetch_reports_progress_with_the_declared_total(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    prog_t p = {0};
    long status = 0;
    ASSERT_EQ(FIRC_OK,
              firc_sub_fetch_list_ex(url_for("/big300k"), &body, &len, note_progress, &p, &status));
    ASSERT_EQ(200L, status);
    ASSERT_EQ(300000u, len);
    ASSERT(p.calls >= 1);
    ASSERT_EQ(300000u, p.last_bytes);
    ASSERT_EQ(300000u, p.last_total);
    free(body);
    harness_stop(h);
    PASS();
}

TEST a_404_reports_its_status(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    long status = 0;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_sub_fetch_list_ex(url_for("/404"), &body, &len, NULL, NULL, &status));
    ASSERT_EQ(404L, status);
    harness_stop(h);
    PASS();
}

/* Catches: the callback's stop ignored, or its abort classified as IO or LIMIT. */
TEST fetch_aborted_by_the_callback_is_canceled_and_leaves_no_body(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = (char *)1;
    size_t len = 7;
    ASSERT_EQ(FIRC_ERR_CANCELED,
              firc_sub_fetch_list_ex(url_for("/big300k"), &body, &len, abort_at_once, NULL, NULL));
    ASSERT_EQ(NULL, body);
    ASSERT_EQ(0u, len);
    harness_stop(h);
    PASS();
}

/* Catches: a body over the cap with a live progress callback classified as CANCELED, not LIMIT. */
TEST the_cap_beats_a_live_progress_callback(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = (char *)1;
    size_t len = 7;
    prog_t p = {0};
    long status = 0;
    ASSERT_EQ_FMTm("too big is too big, not cancelled", (int)FIRC_ERR_LIMIT,
                   (int)firc_sub_fetch_list_ex(url_for("/big"), &body, &len, note_progress, &p,
                                               &status),
                   "%d");
    ASSERT_EQ(NULL, body);
    ASSERT_EQ(0u, len);
    ASSERTm("and the callback really was live", p.calls >= 1);
    harness_stop(h);
    PASS();
}

/* catches: a fetch sent with curl's default User-Agent or none, on the first hop or after a redirect */
TEST every_fetch_names_firc_and_its_version(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list(url_for("/ua"), &body, &len));
    ASSERT_STR_EQ("firc/" FIRC_VERSION, body);
    free(body);
    body = NULL;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_mark_ex(url_for("/redirect_ua"), 0, NULL, &body, &len, NULL, NULL, NULL));
    ASSERT_STR_EQ("firc/" FIRC_VERSION, body);
    free(body);
    harness_stop(h);
    PASS();
}

/* Catches: the caller's User-Agent or X-HWID line not sent, curl's agent sent instead of the caller's, "User-Agent:" not removing it, or a rule list sent anything but the agent. */
TEST a_marked_fetch_sends_the_callers_lines(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    const char *const set[] = {"User-Agent: sing-box/1.12.0", "X-HWID: 6e58d9776d738a31", NULL};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_mark_ex(url_for("/hdr"), 0, set, &body, &len, NULL, NULL, NULL));
    ASSERT_STR_EQ("sing-box/1.12.0|6e58d9776d738a31", body);
    free(body);
    body = NULL;
    const char *const removed[] = {"X-HWID: 6e58d9776d738a31", "User-Agent:", NULL};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_mark_ex(url_for("/hdr"), 0, removed, &body, &len, NULL, NULL, NULL));
    ASSERT_STR_EQ("-|6e58d9776d738a31", body);
    free(body);
    body = NULL;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list(url_for("/hdr"), &body, &len));
    ASSERT_STR_EQ("firc/" FIRC_VERSION "|-", body);
    free(body);
    harness_stop(h);
    PASS();
}

/* Catches: a same-origin redirect dropping any caller line, Authorization and Cookie included. */
TEST a_same_origin_redirect_keeps_every_line(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    const char *const set[] = {"X-HWID: 6e58d9776d738a31", "Authorization: Bearer t0k", "Cookie: a=b", NULL};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_mark_ex(url_for("/same_origin_hdr2"), 0, set, &body, &len, NULL, NULL, NULL));
    ASSERT_STR_EQ("6e58d9776d738a31|Bearer t0k|a=b", body);
    free(body);
    harness_stop(h);
    PASS();
}

/* Catches: Authorization or Cookie reaching another origin (a different port counts), or X-HWID not following the redirect. */
TEST a_cross_origin_redirect_drops_only_credentials(void) {
    harness_t *h = harness_start();
    harness_t *o = other_origin_start();
    ASSERT(h != NULL);
    ASSERT(o != NULL);
    char *body = NULL;
    size_t len = 0;
    const char *const set[] = {"X-HWID: 6e58d9776d738a31", "Authorization: Bearer t0k", "Cookie: a=b", NULL};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_mark_ex(url_for("/other_port_hdr2"), 0, set, &body, &len, NULL, NULL, NULL));
    ASSERT_STR_EQ("6e58d9776d738a31|-|-", body);
    free(body);
    harness_stop(o);
    harness_stop(h);
    PASS();
}

TEST connection_refused_is_io_error(void) {
    char *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_list("http://127.0.0.1:1/list", &body, &len));
    ASSERT(body == NULL);
    PASS();
}

typedef struct collect {
    char data[512];
    size_t len;
    int calls;
    bool stop;
} collect_t;

static bool collect_sink(void *ud, const uint8_t *data, size_t len) {
    collect_t *c = ud;
    c->calls++;
    if (c->stop) { return false; }
    size_t room = sizeof(c->data) - 1 - c->len;
    size_t n = len < room ? len : room;
    memcpy(c->data + c->len, data, n);
    c->len += n;
    c->data[c->len] = '\0';
    return true;
}

static bool refuse_target(void *ud, const char *url) {
    int *calls = ud;
    (*calls)++;
    return strstr(url, "/target") == NULL;
}

static bool refuse_all(void *ud, const char *url) {
    (void)url;
    int *calls = ud;
    (*calls)++;
    return false;
}

typedef struct seen_headers {
    char remaining[32];
    char reset[32];
} seen_headers_t;

static void note_header(void *ud, const char *name, const char *value) {
    seen_headers_t *s = ud;
    if (strcasecmp(name, "x-ratelimit-remaining") == 0) { snprintf(s->remaining, sizeof(s->remaining), "%s", value); }
    if (strcasecmp(name, "x-ratelimit-reset") == 0) { snprintf(s->reset, sizeof(s->reset), "%s", value); }
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Catches: a redirect's HTML landing at the head of the downloaded ipk. */
TEST a_redirects_body_never_reaches_the_sink(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_opts_t o = {0};
    collect_t c = {0};
    long status = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/moved"), &o, collect_sink, &c, &status));
    ASSERT_EQ(200L, status);
    ASSERT_STR_EQ("payload", c.data);
    harness_stop(h);
    PASS();
}

/* Catches: the policy checked after fetching, a request already sent off the allowlist. */
TEST a_refused_redirect_is_never_fetched(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    g_hits_target = 0;
    int calls = 0;
    firc_sub_fetch_opts_t o = {.url_ok = refuse_target, .url_ud = &calls};
    collect_t c = {0};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_sub_fetch_to(url_for("/to_target"), &o, collect_sink, &c, NULL));
    ASSERT_EQ(0, g_hits_target);
    ASSERT_EQ(2, calls);
    ASSERT_EQ(0u, c.len);
    harness_stop(h);
    PASS();
}

/* Catches: url_ok consulted only for redirect targets, the first URL sent unjudged. */
TEST the_first_url_is_judged_too(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    g_hits_counted = 0;
    int calls = 0;
    firc_sub_fetch_opts_t o = {.url_ok = refuse_all, .url_ud = &calls};
    collect_t c = {0};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_sub_fetch_to(url_for("/counted"), &o, collect_sink, &c, NULL));
    ASSERT_EQ(0, g_hits_counted);
    ASSERT_EQ(1, calls);
    harness_stop(h);
    PASS();
}

/* Catches: request headers never set, or set on the first hop only. */
TEST request_headers_are_sent(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    const char *const hdrs[] = {"Accept: application/vnd.github+json", NULL};
    firc_sub_fetch_opts_t o = {.headers = hdrs};
    collect_t c = {0};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/accept"), &o, collect_sink, &c, NULL));
    ASSERT_STR_EQ("application/vnd.github+json", c.data);
    collect_t r = {0};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/redirect_accept"), &o, collect_sink, &r, NULL));
    ASSERT_STR_EQ("application/vnd.github+json", r.data);
    harness_stop(h);
    PASS();
}

/* Catches: the rate-limit reset lost, which would make every 403 a 502. */
TEST a_refusals_headers_reach_the_caller(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    seen_headers_t seen = {0};
    firc_sub_fetch_opts_t o = {.on_header = note_header, .header_ud = &seen};
    collect_t c = {0};
    long status = 0;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_sub_fetch_to(url_for("/limited"), &o, collect_sink, &c, &status));
    ASSERT_EQ(403L, status);
    ASSERT_STR_EQ("0", seen.remaining);
    ASSERT_STR_EQ("1791831689", seen.reset);
    ASSERT_EQ(0u, c.len);
    harness_stop(h);
    PASS();
}

/* Catches: a sink's stop ignored or reported as an I/O error. */
TEST a_sink_saying_stop_is_canceled(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_opts_t o = {0};
    collect_t c = {.stop = true};
    ASSERT_EQ(FIRC_ERR_CANCELED, firc_sub_fetch_to(url_for("/big300k"), &o, collect_sink, &c, NULL));
    ASSERT_EQ(1, c.calls);
    harness_stop(h);
    PASS();
}

/* Catches: the operator seeing "I/O error" instead of libcurl's reason. */
TEST a_transport_failure_carries_libcurls_words(void) {
    char err[256] = "unset";
    firc_sub_fetch_opts_t o = {.errbuf = err, .errbuf_cap = sizeof(err)};
    collect_t c = {0};
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_to("http://127.0.0.1:1/list", &o, collect_sink, &c, NULL));
    ASSERT(err[0] != '\0');
    ASSERT(strcmp(err, "unset") != 0);
    ASSERT(strcmp(err, firc_err_str(FIRC_ERR_IO)) != 0);
    ASSERT(strstr(err, "127.0.0.1") != NULL);
    PASS();
}

/* Catches: max_redirects ignored in favour of the fixed cap of five. */
TEST the_redirect_cap_is_per_call(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_opts_t o = {.max_redirects = 4};
    collect_t c = {0};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/chain_ok1"), &o, collect_sink, &c, NULL));
    ASSERT_STR_EQ("example.com\nexample.org", c.data);
    collect_t d = {0};
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_sub_fetch_to(url_for("/chain_ok0"), &o, collect_sink, &d, NULL));
    ASSERT_EQ(0u, d.len);
    harness_stop(h);
    PASS();
}

/* Catches: timeout_s ignored, the fixed 15 s left in charge. */
TEST the_timeout_is_per_call(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_opts_t o = {.timeout_s = 1};
    collect_t c = {0};
    double t0 = now_s();
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_to(url_for("/never"), &o, collect_sink, &c, NULL));
    ASSERT(now_s() - t0 < 3.0);
    harness_stop(h);
    PASS();
}

/* Catches: each redirect hop given the whole timeout again. */
TEST one_timeout_covers_the_whole_redirect_chain(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_opts_t o = {.timeout_s = 1};
    collect_t c = {0};
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_to(url_for("/slow_hop"), &o, collect_sink, &c, NULL));
    o.timeout_s = 3;
    collect_t ok = {0};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/slow_hop"), &o, collect_sink, &ok, NULL));
    harness_stop(h);
    PASS();
}

/* Catches: CURLOPT_LOW_SPEED_* never set, the 300 s timeout left the only guard. */
TEST a_transfer_below_the_floor_is_given_up(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char err[256] = "";
    firc_sub_fetch_opts_t o = {.low_speed_bytes = 100000, .low_speed_s = 1, .errbuf = err, .errbuf_cap = sizeof(err)};
    collect_t c = {0};
    double t0 = now_s();
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_to(url_for("/trickle"), &o, collect_sink, &c, NULL));
    ASSERT(now_s() - t0 < 3.0);
    ASSERT(strstr(err, "too slow") != NULL);
    harness_stop(h);
    PASS();
}

/* Catches: no closing progress call, an undeclared length left reported as total 0. */
TEST the_last_progress_call_names_the_whole_body(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    prog_t p = {0};
    firc_sub_fetch_opts_t o = {.progress = note_progress, .progress_ud = &p};
    collect_t c = {0};
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/chunked"), &o, collect_sink, &c, NULL));
    ASSERT_STR_EQ("abc", c.data);
    ASSERT_EQ(3u, p.last_bytes);
    ASSERT_EQ(3u, p.last_total);
    harness_stop(h);
    PASS();
}

/* Catches: a refusal's or redirect's body drained without a cap, a flood read until the timeout. */
TEST a_refusal_or_redirect_body_past_the_cap_is_limit(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_opts_t o = {0};
    collect_t c = {0};
    long status = 0;
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_sub_fetch_to(url_for("/big_refusal"), &o, collect_sink, &c, &status));
    ASSERT_EQ(403L, status);
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_sub_fetch_to(url_for("/big_redirect"), &o, collect_sink, &c, &status));
    ASSERT_EQ(302L, status);
    ASSERT_EQ(0, c.calls);
    harness_stop(h);
    PASS();
}

static bool discard(void *ud, const uint8_t *p, size_t n) {
    (void)ud;
    (void)p;
    (void)n;
    return true;
}

TEST a_fetch_told_not_to_follow_answers_the_redirect(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_opts_t o = {.no_redirects = true};
    long status = 0;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_sub_fetch_to(url_for("/redirect302"), &o, discard, NULL, &status));
    ASSERT_EQ(302, status);
    harness_stop(h);
    PASS();
}

TEST a_pinned_address_takes_a_name_no_resolver_knows(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char pin[64], url[96];
    snprintf(pin, sizeof(pin), "check.test:%d:127.0.0.1", TEST_PORT);
    snprintf(url, sizeof(url), "http://check.test:%d/list", TEST_PORT);
    firc_sub_fetch_opts_t o = {.resolve = pin};
    long status = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url, &o, discard, NULL, &status));
    ASSERT_EQ(200, status);
    harness_stop(h);
    PASS();
}

TEST a_url_whose_authority_is_missing_is_refused(void) {
    ASSERT_FALSE(firc_sub_url_is_supported("http:///x"));
    ASSERT_FALSE(firc_sub_url_is_supported("http:/x"));
    ASSERT_FALSE(firc_sub_url_is_supported("https:///list"));
    ASSERT(firc_sub_url_is_supported("HTTPS://a.example/list"));
    ASSERT(firc_sub_url_is_supported("http://[::1]:8080/list"));
    PASS();
}

/* Catches: a fetch reason that drops the status, libcurl's words or the size verdict. */
TEST a_fetch_reason_says_what_went_wrong(void) {
    char out[128];
    firc_sub_fetch_reason(FIRC_ERR_PROTO, 404, "", out, sizeof out);
    ASSERT_STR_EQ("the server answered 404", out);
    firc_sub_fetch_reason(FIRC_ERR_PROTO, 0, "", out, sizeof out);
    ASSERT_STR_EQ(firc_err_str(FIRC_ERR_PROTO), out);
    firc_sub_fetch_reason(FIRC_ERR_IO, 0, "Failed to connect", out, sizeof out);
    ASSERT_STR_EQ("Failed to connect", out);
    firc_sub_fetch_reason(FIRC_ERR_IO, 0, "", out, sizeof out);
    ASSERT_STR_EQ("i/o error", out);
    firc_sub_fetch_reason(FIRC_ERR_LIMIT, 0, "", out, sizeof out);
    ASSERT_STR_EQ("the list is too big", out);
    firc_sub_fetch_reason(FIRC_ERR_LIMIT, 200, "", out, sizeof out);
    ASSERT_STR_EQ("the list is too big", out);
    firc_sub_fetch_reason(FIRC_ERR_LIMIT, 302, "", out, sizeof out);
    ASSERT_STR_EQ("too many redirects", out);
    firc_sub_fetch_reason(FIRC_ERR_PROTO, 200, "", out, sizeof out);
    ASSERT_STR_EQ("the list is not text", out);
    firc_sub_fetch_reason(FIRC_ERR_PROTO, 500, "", out, sizeof out);
    ASSERT_STR_EQ("the server answered 500", out);
    firc_sub_fetch_reason(FIRC_ERR_NOMEM, 0, "", out, sizeof out);
    ASSERT_STR_EQ("out of memory", out);
    PASS();
}

/* Catches: a per-call cap ignored in favour of the global one. */
TEST a_fetch_with_its_own_cap_is_limit_past_it(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char *body = NULL;
    size_t len = 0;
    long status = 0;
    char errbuf[CURL_ERROR_SIZE] = "";
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_sub_fetch_list_opts(url_for("/big300k"), 1024, &body, &len, NULL, NULL, &status,
                                                       errbuf, sizeof errbuf));
    ASSERT_EQ(NULL, body);
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_opts(url_for("/list"), 1024, &body, &len, NULL, NULL, &status, errbuf,
                                                sizeof errbuf));
    free(body);
    harness_stop(h);
    PASS();
}

/* Catches: libcurl's words not reaching the caller's buffer. */
TEST a_fetch_with_its_own_cap_fills_the_errbuf_on_a_transport_failure(void) {
    char *body = NULL;
    size_t len = 0;
    char errbuf[CURL_ERROR_SIZE] = "";
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_list_opts("http://127.0.0.1:1/list", 1024, &body, &len, NULL, NULL, NULL,
                                                    errbuf, sizeof errbuf));
    ASSERT(errbuf[0] != '\0');
    PASS();
}

static bool count_sink(void *ud, const uint8_t *data, size_t len) {
    (void)data;
    *(size_t *)ud += len;
    return true;
}

TEST info_reports_a_connect_without_tls_over_plain_http(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_info_t info = {false, true, true, true, false, false};
    firc_sub_fetch_opts_t o = {.info = &info};
    size_t got = 0;
    long status = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/list"), &o, count_sink, &got, &status));
    harness_stop(h);
    ASSERT(info.connected);
    ASSERT_FALSE(info.tls_done);
    ASSERT_FALSE(info.reset);
    PASS();
}

TEST info_reports_no_connect_when_refused(void) {
    firc_sub_fetch_info_t info = {true, true, true, true, false, false};
    firc_sub_fetch_opts_t o = {.info = &info};
    size_t got = 0;
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_to("http://127.0.0.1:1/list", &o, count_sink, &got, NULL));
    ASSERT_FALSE(info.connected);
    ASSERT_FALSE(info.tls_done);
    ASSERT_FALSE(info.reset);
    PASS();
}

TEST info_reports_a_refused_connect(void) {
    firc_sub_fetch_info_t info = {true, true, true, true, false, true};
    firc_sub_fetch_opts_t o = {.info = &info};
    size_t got = 0;
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_to("http://127.0.0.1:1/list", &o, count_sink, &got, NULL));
    ASSERT(info.refused);
    ASSERT_FALSE(info.unreachable);
    ASSERT_FALSE(info.timed_out);
    ASSERT_FALSE(info.connected);
    PASS();
}

static bool no_v6_route(void) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) { return false; }
    struct sockaddr_in6 sa = {.sin6_family = AF_INET6, .sin6_port = htons(80)};
    inet_pton(AF_INET6, "2001:db8::1", &sa.sin6_addr);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    int e = errno;
    close(fd);
    return rc != 0 && (e == ENETUNREACH || e == EHOSTUNREACH);
}

TEST info_reports_an_unreachable_network(void) {
    if (!no_v6_route()) { SKIPm("no IPv6, or a routable 2001:db8::1 on this host"); }
    firc_sub_fetch_info_t info = {true, true, true, true, true, false};
    firc_sub_fetch_opts_t o = {.info = &info, .timeout_s = 2};
    size_t got = 0;
    ASSERT_EQ(FIRC_ERR_IO, firc_sub_fetch_to("http://[2001:db8::1]/", &o, count_sink, &got, NULL));
    ASSERT(info.unreachable);
    ASSERT_FALSE(info.refused);
    ASSERT_FALSE(info.connected);
    PASS();
}

TEST a_successful_fetch_is_neither_refused_nor_unreachable(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_info_t info = {false, false, false, false, true, true};
    firc_sub_fetch_opts_t o = {.info = &info};
    size_t got = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/list"), &o, count_sink, &got, NULL));
    harness_stop(h);
    ASSERT_FALSE(info.refused);
    ASSERT_FALSE(info.unreachable);
    PASS();
}

static void *reset_one(void *ud) {
    int lfd = *(int *)ud;
    struct pollfd pf = {.fd = lfd, .events = POLLIN};
    if (poll(&pf, 1, 5000) != 1) { return NULL; }
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0) { return NULL; }
    char buf[512];
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)recv(fd, buf, sizeof(buf), 0);
    struct linger lg = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    close(fd);
    return NULL;
}

static firc_err_t fetch_from_a_resetting_peer(const char *scheme, firc_sub_fetch_info_t *info) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { return FIRC_ERR_SYS; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(TEST_PORT + 5),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    pthread_t t;
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(lfd, 1) != 0 ||
        pthread_create(&t, NULL, reset_one, &lfd) != 0) {
        close(lfd);
        return FIRC_ERR_SYS;
    }
    char url[64];
    snprintf(url, sizeof(url), "%s://127.0.0.1:%d/", scheme, TEST_PORT + 5);
    firc_sub_fetch_opts_t o = {.info = info, .timeout_s = 5};
    size_t got = 0;
    firc_err_t err = firc_sub_fetch_to(url, &o, count_sink, &got, NULL);
    pthread_join(t, NULL);
    close(lfd);
    return err;
}

TEST info_reports_a_reset_by_the_peer(void) {
    firc_sub_fetch_info_t info = {false, true, false, true, false, false};
    ASSERT_EQ(FIRC_ERR_IO, fetch_from_a_resetting_peer("http", &info));
    ASSERT(info.connected);
    ASSERT_FALSE(info.tls_done);
    ASSERT(info.reset);
    ASSERT_FALSE(info.timed_out);
    PASS();
}

TEST info_reports_a_reset_during_the_handshake(void) {
    firc_sub_fetch_info_t info = {false, true, false, true, false, false};
    ASSERT_EQ(FIRC_ERR_IO, fetch_from_a_resetting_peer("https", &info));
    ASSERT(info.connected);
    ASSERT_FALSE(info.tls_done);
    ASSERT(info.reset);
    ASSERT_FALSE(info.timed_out);
    PASS();
}

TEST info_reports_a_timeout(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_info_t info = {false, true, true, false, false, false};
    firc_sub_fetch_opts_t o = {.info = &info, .timeout_s = 1};
    size_t got = 0;
    firc_err_t err = firc_sub_fetch_to(url_for("/never"), &o, count_sink, &got, NULL);
    harness_stop(h);
    ASSERT_EQ(FIRC_ERR_IO, err);
    ASSERT(info.connected);
    ASSERT_FALSE(info.tls_done);
    ASSERT_FALSE(info.reset);
    ASSERT(info.timed_out);
    PASS();
}

TEST info_is_cleared_when_the_first_url_is_refused(void) {
    firc_sub_fetch_info_t info = {true, true, true, true, false, false};
    firc_sub_fetch_opts_t o = {.info = &info};
    size_t got = 0;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_sub_fetch_to("ftp://127.0.0.1/", &o, count_sink, &got, NULL));
    ASSERT_FALSE(info.connected);
    ASSERT_FALSE(info.tls_done);
    ASSERT_FALSE(info.reset);
    ASSERT_FALSE(info.timed_out);
    PASS();
}

TEST a_fetch_without_info_still_works(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_sub_fetch_opts_t o = {.info = NULL};
    size_t got = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_to(url_for("/list"), &o, count_sink, &got, NULL));
    harness_stop(h);
    ASSERT_EQ(strlen("example.com\nexample.org"), got);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    firc_sub_fetch_global_init();
    GREATEST_MAIN_BEGIN();
    RUN_TEST(fetches_plain_200);
    RUN_TEST(a_body_with_a_nul_in_it_is_not_a_list);
    RUN_TEST(a_compiled_rule_set_is_fetched_with_its_nul_bytes);
    RUN_TEST(fetches_empty_body);
    RUN_TEST(follows_301_and_302);
    RUN_TEST(follows_303_307_and_308);
    RUN_TEST(detects_redirect_loop);
    RUN_TEST(allows_exactly_five_redirects);
    RUN_TEST(rejects_six_redirects);
    RUN_TEST(non_2xx_is_proto_error);
    RUN_TEST(oversized_body_is_limit_error);
    RUN_TEST(unsupported_scheme_is_inval);
    RUN_TEST(malformed_url_is_inval);
    RUN_TEST(connection_refused_is_io_error);
    RUN_TEST(every_fetch_names_firc_and_its_version);
    RUN_TEST(a_marked_fetch_sends_the_callers_lines);
    RUN_TEST(a_same_origin_redirect_keeps_every_line);
    RUN_TEST(a_cross_origin_redirect_drops_only_credentials);
    RUN_TEST(fetch_reports_progress_with_the_declared_total);
    RUN_TEST(a_404_reports_its_status);
    RUN_TEST(fetch_aborted_by_the_callback_is_canceled_and_leaves_no_body);
    RUN_TEST(the_cap_beats_a_live_progress_callback);
    RUN_TEST(a_redirects_body_never_reaches_the_sink);
    RUN_TEST(a_refused_redirect_is_never_fetched);
    RUN_TEST(the_first_url_is_judged_too);
    RUN_TEST(request_headers_are_sent);
    RUN_TEST(a_refusals_headers_reach_the_caller);
    RUN_TEST(a_sink_saying_stop_is_canceled);
    RUN_TEST(a_transport_failure_carries_libcurls_words);
    RUN_TEST(the_redirect_cap_is_per_call);
    RUN_TEST(the_timeout_is_per_call);
    RUN_TEST(one_timeout_covers_the_whole_redirect_chain);
    RUN_TEST(a_transfer_below_the_floor_is_given_up);
    RUN_TEST(the_last_progress_call_names_the_whole_body);
    RUN_TEST(a_refusal_or_redirect_body_past_the_cap_is_limit);
    RUN_TEST(a_fetch_told_not_to_follow_answers_the_redirect);
    RUN_TEST(a_pinned_address_takes_a_name_no_resolver_knows);
    RUN_TEST(a_url_whose_authority_is_missing_is_refused);
    RUN_TEST(a_fetch_reason_says_what_went_wrong);
    RUN_TEST(a_fetch_with_its_own_cap_is_limit_past_it);
    RUN_TEST(a_fetch_with_its_own_cap_fills_the_errbuf_on_a_transport_failure);
    RUN_TEST(info_reports_a_connect_without_tls_over_plain_http);
    RUN_TEST(info_reports_no_connect_when_refused);
    RUN_TEST(info_reports_a_refused_connect);
    RUN_TEST(info_reports_an_unreachable_network);
    RUN_TEST(a_successful_fetch_is_neither_refused_nor_unreachable);
    RUN_TEST(info_reports_a_reset_by_the_peer);
    RUN_TEST(info_reports_a_reset_during_the_handshake);
    RUN_TEST(info_reports_a_timeout);
    RUN_TEST(info_is_cleared_when_the_first_url_is_refused);
    RUN_TEST(a_fetch_without_info_still_works);
    GREATEST_MAIN_END();
}
