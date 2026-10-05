#include "greatest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "firc/httpd.h"
#include "firc/loop.h"

static void h_hello(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "method", firc_http_req_method(req));
    cJSON_AddStringToObject(obj, "path", firc_http_req_path(req));
    if (firc_http_req_query_is_true(req, "with_rules")) {
        cJSON_AddBoolToObject(obj, "withRules", true);
    }
    firc_http_res_write_json(res, 200, obj);
}

static void h_param(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    const char *id = firc_http_req_param(req, "groupID");
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "id", id ? id : "");
    firc_http_res_write_json(res, 200, obj);
}

static void h_echo_body(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    size_t len;
    const uint8_t *body = firc_http_req_body(req, &len);
    firc_http_res_write(res, 200, "application/json; charset=utf-8", body, len);
}

static void h_not_found(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    (void)req;
    firc_http_res_write(res, 404, "text/html", (const uint8_t *)"<h1>nope</h1>", 13);
}

static bool mw_reject_blocked(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    if (strcmp(firc_http_req_path(req), "/blocked") == 0) {
        firc_http_res_write_error(res, 401, "Unauthorized");
        return false;
    }
    return true;
}

static void nap_ms(int ms) {
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static firc_http_stream_t *g_stream;
static int g_closed;

static _Atomic int g_probe_seq;
static _Atomic int g_probe_closed;
static _Atomic int g_probe_stream_null;
static _Atomic int g_probe_write_err;
static _Atomic int g_flood_done;
static _Atomic int g_flood_err;
static _Atomic int g_flood_writes;
static _Atomic int g_loop_parked;
static _Atomic int g_client_gone;

static void on_stream_close(void *ud) {
    (void)ud;
    g_closed++;
    g_stream = NULL;
}

static void h_hold(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_set_header(res, "Content-Type", "text/event-stream");
    g_stream = firc_http_res_hold(res, on_stream_close, NULL);
}

/* Holds the response and ends it before returning, as an events stream for an idle list does. */
static void h_hold_and_close(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_set_header(res, "Content-Type", "text/event-stream");
    g_stream = firc_http_res_hold(res, on_stream_close, NULL);
    if (g_stream == NULL) { return; }
    firc_http_stream_write(g_stream, "event: done\ndata: {}\n\n", 22);
    firc_http_stream_close(g_stream);
    g_stream = NULL;
}

static void set_fat_headers(firc_http_res_t *res) {
    char value[512];
    memset(value, 'v', sizeof(value) - 1);
    value[sizeof(value) - 1] = '\0';
    for (int i = 0; i < 4; i++) {
        char name[16];
        snprintf(name, sizeof(name), "X-Pad-%d", i);
        firc_http_res_set_header(res, name, value);
    }
}

static void h_fat_headers(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    set_fat_headers(res);
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)"ok", 2);
}

/* The oversized head on the hold path: the hold returns NULL and the handler answers instead. */
static void h_hold_fat(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    set_fat_headers(res);
    firc_http_stream_t *s = firc_http_res_hold(res, on_stream_close, NULL);
    if (s == NULL) {
        firc_http_res_write_error(res, 500, "could not hold");
        return;
    }
    g_stream = s;
}

static void post_write(firc_loop_t *l, void *ud) {
    (void)l;
    firc_http_stream_write(g_stream, ud, strlen(ud));
}

static void post_close(firc_loop_t *l, void *ud) {
    (void)l;
    (void)ud;
    firc_http_stream_close(g_stream);
}

static void post_probe(firc_loop_t *l, void *ud) {
    (void)l;
    (void)ud;
    atomic_store(&g_probe_closed, g_closed);
    atomic_store(&g_probe_stream_null, g_stream == NULL ? 1 : 0);
    atomic_fetch_add(&g_probe_seq, 1);
}

static void post_write_probe(firc_loop_t *l, void *ud) {
    atomic_store(&g_probe_write_err, (int)firc_http_stream_write(g_stream, "x", 1));
    post_probe(l, ud);
}

#define FLOOD_CHUNK 4096
#define FLOOD_MAX 8192
static void post_flood(firc_loop_t *l, void *ud) {
    (void)l;
    (void)ud;
    static char chunk[FLOOD_CHUNK];
    memset(chunk, 'x', sizeof(chunk));
    int writes = 0;
    firc_err_t e = FIRC_OK;
    for (int i = 0; i < FLOOD_MAX; i++) {
        e = firc_http_stream_write(g_stream, chunk, sizeof(chunk));
        if (e != FIRC_OK) { break; }
        writes++;
    }
    atomic_store(&g_flood_writes, writes);
    atomic_store(&g_flood_err, (int)e);
    atomic_store(&g_flood_done, 1);
}

/* Parks the loop until the client is gone, so the stream write is what finds it gone. */
static void post_write_after_client_left(firc_loop_t *l, void *ud) {
    atomic_store(&g_loop_parked, 1);
    for (int i = 0; i < 200 && !atomic_load(&g_client_gone); i++) { nap_ms(10); }

    firc_err_t e = FIRC_OK;
    int writes = 0;
    for (int i = 0; i < 20; i++) {
        e = firc_http_stream_write(g_stream, "data: x\n\n", 9);
        writes++;
        if (e != FIRC_OK || g_stream == NULL) { break; }
        nap_ms(5);
    }
    atomic_store(&g_probe_write_err, (int)e);
    atomic_store(&g_flood_writes, writes);
    post_probe(l, ud);
}

static size_t g_sized_len;
static _Atomic int g_sized_err;

static void post_sized_write(firc_loop_t *l, void *ud) {
    char *buf = malloc(g_sized_len);
    firc_err_t e = FIRC_ERR_NOMEM;
    if (buf != NULL) {
        memset(buf, 'x', g_sized_len);
        e = firc_http_stream_write(g_stream, buf, g_sized_len);
        free(buf);
    }
    atomic_store(&g_sized_err, (int)e);
    post_probe(l, ud);
}

/* Resets the stream fixture; called before the loop thread exists. */
static void stream_fixture_reset(void) {
    g_stream = NULL;
    g_closed = 0;
    atomic_store(&g_probe_seq, 0);
    atomic_store(&g_probe_closed, -1);
    atomic_store(&g_probe_stream_null, -1);
    atomic_store(&g_probe_write_err, -1);
    atomic_store(&g_flood_done, 0);
    atomic_store(&g_flood_err, -1);
    atomic_store(&g_flood_writes, -1);
    atomic_store(&g_loop_parked, 0);
    atomic_store(&g_client_gone, 0);
    atomic_store(&g_sized_err, -1);
}

#define BIG_BODY (32u * 1024u * 1024u)
static _Atomic int g_after_sent;

static void count_sent(void *ud) {
    (void)ud;
    atomic_fetch_add(&g_after_sent, 1);
}

static void h_big(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    uint8_t *body = malloc(BIG_BODY);
    if (body == NULL) {
        firc_http_res_write_error(res, 500, "no memory");
        return;
    }
    memset(body, 'x', BIG_BODY);
    firc_http_res_take(res, 200, "text/plain", body, BIG_BODY);
    firc_http_res_after_sent(res, count_sent, NULL);
}

static void h_small_after(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write(res, 202, "application/json", (const uint8_t *)"{}", 2);
    firc_http_res_after_sent(res, count_sent, NULL);
}

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    firc_httpd_t *unix_srv;
    pthread_t thread;
} harness_t;

static void *loop_thread(void *ud) {
    harness_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

#define TEST_PORT 18080
#define TEST_UNIX_PATH "/tmp/firc_httpd_test.sock"

static harness_t *harness_start(void) {
    harness_t *h = calloc(1, sizeof(*h));
    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }

    if (firc_httpd_create(h->loop, &h->tcp) != FIRC_OK) { return NULL; }
    firc_httpd_route(h->tcp, "GET", "/hello", h_hello, NULL);
    firc_httpd_route(h->tcp, "GET", "/groups/{groupID}", h_param, NULL);
    firc_httpd_route(h->tcp, "POST", "/echo", h_echo_body, NULL);
    firc_httpd_route(h->tcp, "GET", "/blocked", h_hello, NULL);
    firc_httpd_route(h->tcp, "GET", "/hold", h_hold, NULL);
    firc_httpd_route(h->tcp, "GET", "/hold-close", h_hold_and_close, NULL);
    firc_httpd_route(h->tcp, "GET", "/fat", h_fat_headers, NULL);
    firc_httpd_route(h->tcp, "GET", "/hold-fat", h_hold_fat, NULL);
    firc_httpd_route(h->tcp, "GET", "/big", h_big, NULL);
    firc_httpd_route(h->tcp, "POST", "/small-after", h_small_after, NULL);
    firc_httpd_set_not_found(h->tcp, h_not_found, NULL);
    firc_httpd_set_middleware(h->tcp, mw_reject_blocked, NULL);
    if (firc_httpd_listen_tcp(h->tcp, "127.0.0.1", TEST_PORT) != FIRC_OK) { return NULL; }

    if (firc_httpd_create(h->loop, &h->unix_srv) != FIRC_OK) { return NULL; }
    firc_httpd_route(h->unix_srv, "GET", "/hello", h_hello, NULL);
    if (firc_httpd_listen_unix(h->unix_srv, TEST_UNIX_PATH) != FIRC_OK) { return NULL; }

    pthread_create(&h->thread, NULL, loop_thread, h);
    return h;
}

static void harness_stop(harness_t *h) {
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->tcp);
    firc_httpd_destroy(h->unix_srv);
    firc_loop_destroy(h->loop);
    free(h);
}

/* Connects to `port`; `rcvbuf` > 0 shrinks the receive buffer so the server's writes fill up fast. */
static int connect_tcp_rcvbuf(uint16_t port, int rcvbuf) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (rcvbuf > 0) { setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)); }
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { return fd; }
        struct timespec ts = {0, 10000000}; nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

static int connect_tcp(uint16_t port) { return connect_tcp_rcvbuf(port, 0); }

static int connect_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa = {0};
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { return fd; }
        struct timespec ts = {0, 10000000}; nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

/* Reads until the declared Content-Length is consumed (or 2 s pass); returns the bytes read. */
static ssize_t recv_response(int fd, char *buf, size_t cap) {
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t total = 0;
    char *body_start = NULL;
    long content_length = -1;
    for (;;) {
        if (total >= cap - 1) { break; }
        ssize_t n = recv(fd, buf + total, cap - 1 - total, 0);
        if (n <= 0) { break; }
        total += (size_t)n;
        buf[total] = '\0';
        if (!body_start) {
            char *marker = strstr(buf, "\r\n\r\n");
            if (marker) {
                body_start = marker + 4;
                char *cl = strstr(buf, "Content-Length:");
                if (cl && cl < marker) { content_length = strtol(cl + 15, NULL, 10); }
            }
        }
        if (body_start && content_length >= 0) {
            size_t body_have = (size_t)(buf + total - body_start);
            if ((long)body_have >= content_length) { break; }
        }
    }
    return (ssize_t)total;
}

static int status_code_of(const char *resp) {
    int code = 0;
    sscanf(resp, "HTTP/1.1 %d", &code);
    return code;
}

static const char *body_of(const char *resp) {
    const char *marker = strstr(resp, "\r\n\r\n");
    return marker ? marker + 4 : "";
}

static ssize_t recv_some(int fd, char *buf, size_t cap, int timeout_ms) {
    size_t total = 0;
    bool eof = false;
    while (total < cap - 1) {
        struct pollfd p = {fd, POLLIN, 0};
        int r = poll(&p, 1, total == 0 ? timeout_ms : 50);
        if (r <= 0) { break; }
        ssize_t n = recv(fd, buf + total, cap - 1 - total, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            break;
        }
        if (n == 0) {
            eof = true;
            break;
        }
        total += (size_t)n;
    }
    buf[total] = '\0';
    if (total == 0 && eof) { return -1; }
    return (ssize_t)total;
}

/* Waits (about 2 s at most) for the loop's probe to publish past `before`. */
static bool wait_probe(int before, int tries) {
    for (int i = 0; i < tries; i++) {
        if (atomic_load(&g_probe_seq) != before) { return true; }
        nap_ms(10);
    }
    return false;
}

static bool post_and_wait(harness_t *h, firc_post_cb cb, void *ud) {
    int before = atomic_load(&g_probe_seq);
    if (firc_loop_post(h->loop, cb, ud) != FIRC_OK) { return false; }
    return wait_probe(before, 200);
}

/* Catches: the after-sent hook run before the last byte of the answer is in the kernel. */
TEST after_sent_waits_for_the_last_byte(void) {
    atomic_store(&g_after_sent, 0);
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp_rcvbuf(TEST_PORT, 2048);
    ASSERT(fd >= 0);
    const char *req = "GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    nap_ms(300);
    ASSERT_EQm("32 MiB cannot be in the kernel while the client reads nothing", 0,
               atomic_load(&g_after_sent));
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t got = 0;
    char buf[65536];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) { break; }
        got += (size_t)n;
    }
    ASSERT(got > BIG_BODY);
    for (int i = 0; i < 200 && atomic_load(&g_after_sent) == 0; i++) { nap_ms(10); }
    ASSERT_EQ(1, atomic_load(&g_after_sent));
    close(fd);
    harness_stop(h);
    PASS();
}

/* Catches: a connection that ends before its answer is out dropping the after-sent hook. */
TEST after_sent_runs_when_the_client_leaves_first(void) {
    atomic_store(&g_after_sent, 0);
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp_rcvbuf(TEST_PORT, 2048);
    ASSERT(fd >= 0);
    const char *req = "GET /big HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    nap_ms(300);
    ASSERT_EQ(0, atomic_load(&g_after_sent));
    close(fd);
    for (int i = 0; i < 200 && atomic_load(&g_after_sent) == 0; i++) { nap_ms(10); }
    ASSERT_EQ(1, atomic_load(&g_after_sent));
    harness_stop(h);
    PASS();
}

/* Catches: the after-sent hook fired while the server is being destroyed. */
TEST after_sent_does_not_run_when_the_server_goes_away(void) {
    atomic_store(&g_after_sent, 0);
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp_rcvbuf(TEST_PORT, 2048);
    ASSERT(fd >= 0);
    const char *req = "GET /big HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    nap_ms(300);
    harness_stop(h);
    ASSERT_EQ(0, atomic_load(&g_after_sent));
    close(fd);
    PASS();
}

/* Catches: an answer with an after-sent hook leaving its connection keep-alive. */
TEST an_answer_with_after_sent_closes_its_connection(void) {
    atomic_store(&g_after_sent, 0);
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "POST /small-after HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[2048];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT(strstr(resp, "Connection: close\r\n") != NULL);
    char more[16];
    ASSERT_EQm("the server closed it", 0, (int)recv(fd, more, sizeof(more), 0));
    for (int i = 0; i < 200 && atomic_load(&g_after_sent) == 0; i++) { nap_ms(10); }
    ASSERT_EQ(1, atomic_load(&g_after_sent));
    close(fd);
    harness_stop(h);
    PASS();
}

TEST get_with_query_param(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);

    const char *req = "GET /hello?with_rules=true HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[4096];
    ssize_t n = recv_response(fd, resp, sizeof(resp));
    ASSERT(n > 0);
    ASSERT_EQ(200, status_code_of(resp));
    ASSERT(strstr(body_of(resp), "\"method\":\"GET\"") != NULL);
    ASSERT(strstr(body_of(resp), "\"withRules\":true") != NULL);
    close(fd);
    harness_stop(h);
    PASS();
}

TEST path_param_extraction(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /groups/aabbccdd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[4096];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    ASSERT(strstr(body_of(resp), "\"id\":\"aabbccdd\"") != NULL);
    close(fd);
    harness_stop(h);
    PASS();
}

TEST post_body_roundtrip(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *body = "{\"name\":\"test\"}";
    char req[512];
    snprintf(req, sizeof(req),
            "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
            "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
            strlen(body), body);
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[4096];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    ASSERT_STR_EQ(body, body_of(resp));
    close(fd);
    harness_stop(h);
    PASS();
}

TEST not_found_fallback(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[4096];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(404, status_code_of(resp));
    ASSERT_STR_EQ("<h1>nope</h1>", body_of(resp));
    close(fd);
    harness_stop(h);
    PASS();
}

TEST middleware_can_short_circuit(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /blocked HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[4096];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(401, status_code_of(resp));
    ASSERT(strstr(body_of(resp), "Unauthorized") != NULL);
    close(fd);
    harness_stop(h);
    PASS();
}

TEST keep_alive_multiple_requests_one_connection(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);

    const char *req1 = "GET /hello HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req1, strlen(req1), 0) > 0);
    char resp[4096];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));

    const char *req2 = "GET /groups/deadbeef HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd, req2, strlen(req2), 0) > 0);
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    ASSERT(strstr(body_of(resp), "\"id\":\"deadbeef\"") != NULL);

    close(fd);
    harness_stop(h);
    PASS();
}

TEST unix_socket_serves_same_routes(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_unix(TEST_UNIX_PATH);
    ASSERT(fd >= 0);
    const char *req = "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[4096];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    close(fd);
    harness_stop(h);
    PASS();
}

/* Catches: a held response answered 500, given a length, or written late without chunk framing. */
TEST a_held_response_is_written_after_the_handler_returned(void) {
    stream_fixture_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);

    const char *req = "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);

    char buf[4096];
    ASSERT(recv_some(fd, buf, sizeof(buf), 2000) > 0);
    ASSERT_EQ(200, status_code_of(buf));
    ASSERT(strstr(buf, "Transfer-Encoding: chunked\r\n") != NULL);
    ASSERT(strstr(buf, "Content-Type: text/event-stream\r\n") != NULL);
    ASSERT(strstr(buf, "Connection: close\r\n") != NULL);
    ASSERT(strstr(buf, "Content-Length") == NULL);
    ASSERT_STR_EQ("", body_of(buf));

    ASSERT_EQ(0, recv_some(fd, buf, sizeof(buf), 200));

    char payload[] = "data: one\n\n";
    ASSERT_EQ(FIRC_OK, firc_loop_post(h->loop, post_write, payload));
    ASSERT(recv_some(fd, buf, sizeof(buf), 2000) > 0);
    ASSERT_STR_EQ("b\r\ndata: one\n\n\r\n", buf);

    ASSERT_EQ(FIRC_OK, firc_loop_post(h->loop, post_close, NULL));
    ASSERT(recv_some(fd, buf, sizeof(buf), 2000) > 0);
    ASSERT_STR_EQ("0\r\n\r\n", buf);
    ASSERT_EQ(-1, recv_some(fd, buf, sizeof(buf), 2000));

    ASSERT(post_and_wait(h, post_probe, NULL));
    ASSERT_EQ(0, atomic_load(&g_probe_closed));

    close(fd);
    harness_stop(h);
    PASS();
}

/* Catches: the dispatcher finishing a response the handler already ended (use after free). */
TEST a_handler_may_end_its_held_stream_before_returning(void) {
    stream_fixture_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);

    const char *req = "GET /hold-close HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);

    char buf[4096];
    size_t total = 0;
    for (int i = 0; i < 20 && total < sizeof(buf) - 1; i++) {
        ssize_t n = recv_some(fd, buf + total, sizeof(buf) - total, 2000);
        if (n <= 0) { break; }
        total += (size_t)n;
        if (strstr(buf, "0\r\n\r\n") != NULL) { break; }
    }
    buf[total] = '\0';
    ASSERT(total > 0);
    ASSERT_EQ(200, status_code_of(buf));
    ASSERT(strstr(buf, "Transfer-Encoding: chunked\r\n") != NULL);
    ASSERT(strstr(buf, "16\r\nevent: done\ndata: {}\n\n\r\n0\r\n\r\n") != NULL);
    ASSERT_EQ(-1, recv_some(fd, buf, sizeof(buf), 2000));

    ASSERT(post_and_wait(h, post_probe, NULL));
    ASSERT_EQ(0, atomic_load(&g_probe_closed));

    close(fd);
    harness_stop(h);
    PASS();
}

/* Catches: a client leaving without on_close, a stale handle written to, or the server wedged. */
TEST a_client_that_leaves_removes_the_stream(void) {
    stream_fixture_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char buf[4096];
    ASSERT(recv_some(fd, buf, sizeof(buf), 2000) > 0);
    ASSERT_EQ(200, status_code_of(buf));

    close(fd);

    bool reported = false;
    for (int i = 0; i < 50 && !reported; i++) {
        ASSERT(post_and_wait(h, post_probe, NULL));
        reported = atomic_load(&g_probe_closed) == 1;
        if (!reported) { nap_ms(10); }
    }
    ASSERT(reported);
    ASSERT_EQ(1, atomic_load(&g_probe_stream_null));

    ASSERT(post_and_wait(h, post_write_probe, NULL));
    ASSERT_EQ(FIRC_ERR_NOENT, atomic_load(&g_probe_write_err));
    ASSERT_EQ(1, atomic_load(&g_probe_closed));

    int fd2 = connect_tcp(TEST_PORT);
    ASSERT(fd2 >= 0);
    const char *req2 = "GET /hello HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd2, req2, strlen(req2), 0) > 0);
    char resp[4096];
    ASSERT(recv_response(fd2, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    close(fd2);

    harness_stop(h);
    PASS();
}

/* Catches: a stream to a client that stops reading growing its buffer without bound. */
TEST a_stream_that_does_not_drain_is_closed_at_the_buffer_limit(void) {
    stream_fixture_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp_rcvbuf(TEST_PORT, 2048);
    ASSERT(fd >= 0);
    const char *req = "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);

    bool held = false;
    for (int i = 0; i < 200 && !held; i++) {
        ASSERT(post_and_wait(h, post_probe, NULL));
        held = atomic_load(&g_probe_stream_null) == 0;
        if (!held) { nap_ms(10); }
    }
    ASSERT(held);

    ASSERT_EQ(FIRC_OK, firc_loop_post(h->loop, post_flood, NULL));
    bool done = false;
    for (int i = 0; i < 1000 && !done; i++) {
        done = atomic_load(&g_flood_done) == 1;
        if (!done) { nap_ms(10); }
    }
    ASSERT(done);
    ASSERT_EQ(FIRC_ERR_LIMIT, atomic_load(&g_flood_err));
    ASSERT(atomic_load(&g_flood_writes) > 0);
    ASSERT(atomic_load(&g_flood_writes) < FLOOD_MAX);

    ASSERT(post_and_wait(h, post_probe, NULL));
    ASSERT_EQ(1, atomic_load(&g_probe_closed));
    ASSERT_EQ(1, atomic_load(&g_probe_stream_null));

    close(fd);
    harness_stop(h);
    PASS();
}

TEST a_server_going_away_reports_every_held_stream(void) {
    stream_fixture_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char buf[4096];
    ASSERT(recv_some(fd, buf, sizeof(buf), 2000) > 0);
    ASSERT_EQ(200, status_code_of(buf));

    ASSERT(post_and_wait(h, post_probe, NULL));
    ASSERT_EQ(0, atomic_load(&g_probe_closed));
    ASSERT_EQ(0, atomic_load(&g_probe_stream_null));

    harness_stop(h);

    ASSERT_EQ(1, g_closed);
    ASSERT(g_stream == NULL);
    close(fd);
    PASS();
}

/* Catches: a write that finds the client gone returning FIRC_OK. */
TEST a_write_that_lost_its_client_says_so(void) {
    stream_fixture_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    struct linger lg = {1, 0};
    ASSERT_EQ(0, setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)));

    const char *req = "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char buf[4096];
    ASSERT(recv_some(fd, buf, sizeof(buf), 2000) > 0);
    ASSERT_EQ(200, status_code_of(buf));

    int before = atomic_load(&g_probe_seq);
    ASSERT_EQ(FIRC_OK, firc_loop_post(h->loop, post_write_after_client_left, NULL));
    bool parked = false;
    for (int i = 0; i < 200 && !parked; i++) {
        parked = atomic_load(&g_loop_parked) == 1;
        if (!parked) { nap_ms(10); }
    }
    ASSERT(parked);

    close(fd);
    atomic_store(&g_client_gone, 1);

    ASSERT(wait_probe(before, 500));
    ASSERT_EQ(FIRC_ERR_NOENT, atomic_load(&g_probe_write_err));
    ASSERT(atomic_load(&g_flood_writes) > 0);
    ASSERT_EQ(1, atomic_load(&g_probe_closed));
    ASSERT_EQ(1, atomic_load(&g_probe_stream_null));

    harness_stop(h);
    PASS();
}

TEST a_head_too_large_for_its_buffer_is_refused_not_overrun(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /fat HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[16384];
    ssize_t got = recv_response(fd, resp, sizeof(resp));
    close(fd);

    ASSERT(got > 0);
    ASSERT_EQ_FMTm("refused rather than half-written", 500, status_code_of(resp), "%d");
    ASSERTm("and it says which way it failed", strstr(resp, "headers too large") != NULL);
    ASSERTm("none of the handler's oversized headers reached the client",
            strstr(resp, "X-Pad-") == NULL);
    harness_stop(h);
    PASS();
}

/* Catches: a failed hold leaving the connection marked to close. */
TEST a_hold_that_could_not_build_its_head_leaves_the_connection_alone(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = connect_tcp(TEST_PORT);
    ASSERT(fd >= 0);
    const char *req = "GET /hold-fat HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT(send(fd, req, strlen(req), 0) > 0);
    char resp[16384];
    ssize_t got = recv_response(fd, resp, sizeof(resp));
    close(fd);

    ASSERT(got > 0);
    ASSERT_EQ_FMTm("the hold failed and the handler answered", 500, status_code_of(resp), "%d");
    ASSERTm("on a connection the request asked to keep",
            strstr(resp, "Connection: keep-alive") != NULL);
    ASSERT_FALSEm("and not one the failed hold marked for closing",
                  strstr(resp, "Connection: close") != NULL);
    harness_stop(h);
    PASS();
}

#define STREAM_EXACT_FILL 65528u

static bool write_one_chunk(harness_t *h, size_t len, int *out_err) {
    stream_fixture_reset();
    int fd = connect_tcp(TEST_PORT);
    if (fd < 0) { return false; }
    const char *req = "GET /hold HTTP/1.1\r\nHost: x\r\n\r\n";
    if (send(fd, req, strlen(req), 0) <= 0) {
        close(fd);
        return false;
    }
    char head[4096];
    bool got_head = recv_some(fd, head, sizeof(head), 2000) > 0;
    bool held = false;
    for (int i = 0; i < 200 && !held; i++) {
        if (!post_and_wait(h, post_probe, NULL)) { break; }
        held = atomic_load(&g_probe_stream_null) == 0;
        if (!held) { nap_ms(10); }
    }
    bool ok = got_head && held;
    if (ok) {
        g_sized_len = len;
        ok = post_and_wait(h, post_sized_write, NULL);
        *out_err = atomic_load(&g_sized_err);
    }
    close(fd);
    return ok;
}

TEST the_stream_buffer_keeps_room_for_its_own_terminator(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);

    int err = -1;
    ASSERT(write_one_chunk(h, STREAM_EXACT_FILL - 6, &err));
    ASSERT_EQ_FMTm("a chunk that leaves the terminator room is queued", (int)FIRC_OK, err, "%d");

    err = -1;
    ASSERT(write_one_chunk(h, STREAM_EXACT_FILL, &err));
    ASSERT_EQ_FMTm("one that would fill the buffer to the brim is refused: the last chunk "
                   "has to fit too",
                   (int)FIRC_ERR_LIMIT, err, "%d");

    harness_stop(h);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(get_with_query_param);
    RUN_TEST(path_param_extraction);
    RUN_TEST(post_body_roundtrip);
    RUN_TEST(not_found_fallback);
    RUN_TEST(middleware_can_short_circuit);
    RUN_TEST(keep_alive_multiple_requests_one_connection);
    RUN_TEST(unix_socket_serves_same_routes);
    RUN_TEST(a_held_response_is_written_after_the_handler_returned);
    RUN_TEST(a_handler_may_end_its_held_stream_before_returning);
    RUN_TEST(a_client_that_leaves_removes_the_stream);
    RUN_TEST(a_stream_that_does_not_drain_is_closed_at_the_buffer_limit);
    RUN_TEST(a_server_going_away_reports_every_held_stream);
    RUN_TEST(a_write_that_lost_its_client_says_so);
    RUN_TEST(a_head_too_large_for_its_buffer_is_refused_not_overrun);
    RUN_TEST(a_hold_that_could_not_build_its_head_leaves_the_connection_alone);
    RUN_TEST(the_stream_buffer_keeps_room_for_its_own_terminator);
    RUN_TEST(after_sent_waits_for_the_last_byte);
    RUN_TEST(after_sent_runs_when_the_client_leaves_first);
    RUN_TEST(after_sent_does_not_run_when_the_server_goes_away);
    RUN_TEST(an_answer_with_after_sent_closes_its_connection);
    GREATEST_MAIN_END();
}
