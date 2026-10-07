#include "greatest.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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

static harness_t *harness_start(void) {
    harness_t *h = calloc(1, sizeof(*h));
    memset(g_big_body, 'a', sizeof(g_big_body));
    memset(g_big300k_body, 'b', sizeof(g_big300k_body));

    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    if (firc_httpd_create(h->loop, &h->srv) != FIRC_OK) { return NULL; }

    firc_httpd_route(h->srv, "GET", "/list", h_list, NULL);
    firc_httpd_route(h->srv, "GET", "/empty", h_empty, NULL);
    firc_httpd_route(h->srv, "GET", "/nul", h_nul, NULL);
    firc_httpd_route(h->srv, "GET", "/notfound", h_notfound_status, NULL);
    firc_httpd_route(h->srv, "GET", "/404", h_notfound_status, NULL);
    firc_httpd_route(h->srv, "GET", "/big", h_big, NULL);
    firc_httpd_route(h->srv, "GET", "/big300k", h_big300k, NULL);
    firc_httpd_route(h->srv, "GET", "/ua", h_ua, NULL);

    add_redirect(h, "/redirect301", 301, "/list");
    add_redirect(h, "/redirect302", 302, "/list");
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
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_mark_ex(url_for("/redirect_ua"), 0, &body, &len, NULL, NULL, NULL));
    ASSERT_STR_EQ("firc/" FIRC_VERSION, body);
    free(body);
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

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    firc_sub_fetch_global_init();
    GREATEST_MAIN_BEGIN();
    RUN_TEST(fetches_plain_200);
    RUN_TEST(a_body_with_a_nul_in_it_is_not_a_list);
    RUN_TEST(fetches_empty_body);
    RUN_TEST(follows_301_and_302);
    RUN_TEST(detects_redirect_loop);
    RUN_TEST(allows_exactly_five_redirects);
    RUN_TEST(rejects_six_redirects);
    RUN_TEST(non_2xx_is_proto_error);
    RUN_TEST(oversized_body_is_limit_error);
    RUN_TEST(unsupported_scheme_is_inval);
    RUN_TEST(malformed_url_is_inval);
    RUN_TEST(connection_refused_is_io_error);
    RUN_TEST(every_fetch_names_firc_and_its_version);
    RUN_TEST(fetch_reports_progress_with_the_declared_total);
    RUN_TEST(a_404_reports_its_status);
    RUN_TEST(fetch_aborted_by_the_callback_is_canceled_and_leaves_no_body);
    RUN_TEST(the_cap_beats_a_live_progress_callback);
    GREATEST_MAIN_END();
}
