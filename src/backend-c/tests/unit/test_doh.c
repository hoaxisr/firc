#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */
#include "greatest.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "firc/doh.h"
#include "firc/loop.h"
#include "firc/sub_fetch.h"

#define MAX_CONNS 8

typedef struct conn {
    pthread_t t;
    int fd;
    struct srv *s;
} conn_t;

typedef struct srv {
    int lfd;
    uint16_t port;
    pthread_t acceptor;
    _Atomic bool stop;
    _Atomic int accepts;
    _Atomic int replies;
    _Atomic bool h2;
    _Atomic int swallow;
    int status;
    const char *ctype;
    _Atomic int delay_ms;
    int accept_delay_ms;
    uint8_t reply[64];
    size_t reply_len;
    pthread_mutex_t mu;
    char method[8];
    char req_ctype[64];
    char req_accept[64];
    uint8_t body[512];
    size_t body_len;
    int n_conns;
    conn_t conns[MAX_CONNS];
} srv_t;

static void nap_ms(int ms)
{
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

static bool nap_unless_stop(srv_t *s, int ms)
{
    for (int i = 0; i < ms / 10; i++) {
        if (atomic_load(&s->stop)) {
            return false;
        }
        nap_ms(10);
    }
    return !atomic_load(&s->stop);
}

static void header_value(const char *hdrs, const char *name, char *out, size_t cap)
{
    out[0] = '\0';
    size_t nl = strlen(name);
    for (const char *p = hdrs; p != NULL && *p != '\0';) {
        if (strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1;
            while (*v == ' ') {
                v++;
            }
            size_t n = strcspn(v, "\r\n");
            snprintf(out, cap, "%.*s", (int)n, v);
            return;
        }
        p = strstr(p, "\r\n");
        if (p != NULL) {
            p += 2;
        }
    }
}

static bool read_some(srv_t *s, int fd, char *buf, size_t *len, size_t cap)
{
    while (!atomic_load(&s->stop)) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int r = poll(&pfd, 1, 20);
        if (r < 0) {
            return false;
        }
        if (r == 0) {
            continue;
        }
        ssize_t n = recv(fd, buf + *len, cap - *len, 0);
        if (n <= 0) {
            return false;
        }
        *len += (size_t)n;
        return true;
    }
    return false;
}

static bool read_upto(srv_t *s, int fd, char *buf, size_t *len, size_t cap, size_t need)
{
    while (*len < need) {
        if (need > cap || !read_some(s, fd, buf, len, cap)) {
            return false;
        }
    }
    return true;
}

static bool send_frame(int fd, uint8_t type, uint8_t flags, const uint8_t stream[4], const void *body, size_t n)
{
    uint8_t f[256] = {0, 0, (uint8_t)n, type, flags};
    memcpy(f + 5, stream, 4);
    if (n > 0) {
        memcpy(f + 9, body, n);
    }
    return send(fd, f, 9 + n, MSG_NOSIGNAL) == (ssize_t)(9 + n);
}

static void h2_serve(srv_t *s, int fd)
{
    static const uint8_t zero[4] = {0};
    static const uint8_t hdrs[] = "\x88\x0f\x10\x17"
                                  "application/dns-message";
    char buf[4096];
    size_t len = 0;
    if (!read_upto(s, fd, buf, &len, sizeof buf, 24)) {
        return;
    }
    memmove(buf, buf + 24, len -= 24);
    if (!send_frame(fd, 4, 0, zero, NULL, 0)) {
        return;
    }
    while (read_upto(s, fd, buf, &len, sizeof buf, 9)) {
        size_t need = 9 + (size_t)((uint8_t)buf[1] << 8 | (uint8_t)buf[2]);
        if (!read_upto(s, fd, buf, &len, sizeof buf, need)) {
            return;
        }
        uint8_t type = (uint8_t)buf[3], flags = (uint8_t)buf[4], stream[4];
        memcpy(stream, buf + 5, 4);
        memmove(buf, buf + need, len -= need);
        if (type == 4 && (flags & 1) == 0 && !send_frame(fd, 4, 1, zero, NULL, 0)) {
            return;
        }
        if (type > 1 || (flags & 1) == 0) {
            continue;
        }
        if (atomic_load(&s->swallow) > 0) {
            atomic_fetch_sub(&s->swallow, 1);
            continue;
        }
        if (!nap_unless_stop(s, s->delay_ms) || !send_frame(fd, 1, 4, stream, hdrs, sizeof hdrs - 1) ||
            !send_frame(fd, 0, 1, stream, s->reply, s->reply_len)) {
            return;
        }
        atomic_fetch_add(&s->replies, 1);
    }
}

static void *conn_main(void *ud)
{
    conn_t *c = ud;
    srv_t *s = c->s;
    if (s->h2) {
        h2_serve(s, c->fd);
        return NULL;
    }
    char buf[4096];
    size_t len = 0;
    for (;;) {
        char *end;
        while ((end = memmem(buf, len, "\r\n\r\n", 4)) == NULL) {
            if (len == sizeof buf - 1 || !read_some(s, c->fd, buf, &len, sizeof buf - 1)) {
                return NULL;
            }
        }
        size_t head = (size_t)(end - buf) + 4;
        char hdrs[2048];
        snprintf(hdrs, sizeof hdrs, "%.*s", (int)head, buf);
        char cl[16];
        header_value(hdrs, "Content-Length", cl, sizeof cl);
        size_t body = (size_t)strtoul(cl, NULL, 10);
        while (len < head + body) {
            if (!read_some(s, c->fd, buf, &len, sizeof buf - 1)) {
                return NULL;
            }
        }
        pthread_mutex_lock(&s->mu);
        snprintf(s->method, sizeof s->method, "%.*s", (int)strcspn(hdrs, " "), hdrs);
        header_value(hdrs, "Content-Type", s->req_ctype, sizeof s->req_ctype);
        header_value(hdrs, "Accept", s->req_accept, sizeof s->req_accept);
        s->body_len = body < sizeof s->body ? body : sizeof s->body;
        memcpy(s->body, buf + head, s->body_len);
        pthread_mutex_unlock(&s->mu);
        memmove(buf, buf + head + body, len - head - body);
        len -= head + body;
        if (!nap_unless_stop(s, s->delay_ms)) {
            return NULL;
        }
        char out[512];
        int n = snprintf(out, sizeof out, "HTTP/1.1 %d X\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n",
                         s->status, s->ctype, s->reply_len);
        memcpy(out + n, s->reply, s->reply_len);
        if (send(c->fd, out, (size_t)n + s->reply_len, MSG_NOSIGNAL) < 0) {
            return NULL;
        }
        atomic_fetch_add(&s->replies, 1);
    }
}

static void *accept_main(void *ud)
{
    srv_t *s = ud;
    while (!atomic_load(&s->stop)) {
        struct pollfd pfd = {.fd = s->lfd, .events = POLLIN};
        if (poll(&pfd, 1, 20) <= 0) {
            continue;
        }
        if (!nap_unless_stop(s, s->accept_delay_ms)) {
            break;
        }
        int fd = accept4(s->lfd, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            continue;
        }
        atomic_fetch_add(&s->accepts, 1);
        pthread_mutex_lock(&s->mu);
        if (s->n_conns == MAX_CONNS) {
            pthread_mutex_unlock(&s->mu);
            close(fd);
            continue;
        }
        conn_t *c = &s->conns[s->n_conns++];
        c->fd = fd;
        c->s = s;
        pthread_create(&c->t, NULL, conn_main, c);
        pthread_mutex_unlock(&s->mu);
    }
    return NULL;
}

static const uint8_t k_query[] = {0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
static const uint8_t k_reply[] = {0x00, 0x00, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};

static bool srv_start(srv_t *s, int status, const char *ctype, int delay_ms, int accept_delay_ms)
{
    memset(s, 0, sizeof *s);
    pthread_mutex_init(&s->mu, NULL);
    s->status = status;
    s->ctype = ctype;
    s->delay_ms = delay_ms;
    s->accept_delay_ms = accept_delay_ms;
    memcpy(s->reply, k_reply, sizeof k_reply);
    s->reply_len = sizeof k_reply;
    s->lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    socklen_t al = sizeof a;
    if (s->lfd < 0 || bind(s->lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(s->lfd, 8) != 0 ||
        getsockname(s->lfd, (struct sockaddr *)&a, &al) != 0) {
        return false;
    }
    s->port = ntohs(a.sin_port);
    return pthread_create(&s->acceptor, NULL, accept_main, s) == 0;
}

static void srv_stop(srv_t *s)
{
    atomic_store(&s->stop, true);
    pthread_join(s->acceptor, NULL);
    for (int i = 0; i < s->n_conns; i++) {
        shutdown(s->conns[i].fd, SHUT_RDWR);
        pthread_join(s->conns[i].t, NULL);
        close(s->conns[i].fd);
    }
    close(s->lfd);
    pthread_mutex_destroy(&s->mu);
}

typedef struct waiter {
    bool (*cond)(void *);
    void *ud;
    bool met;
} waiter_t;

static void tick(firc_loop_t *loop, void *ud)
{
    waiter_t *w = ud;
    if (w->cond != NULL && w->cond(w->ud)) {
        w->met = true;
        firc_loop_stop(loop);
    }
}

static void deadline(firc_loop_t *loop, void *ud)
{
    (void)ud;
    firc_loop_stop(loop);
}

static bool run_until(firc_loop_t *loop, bool (*cond)(void *), void *ud, int ms)
{
    waiter_t w = {.cond = cond, .ud = ud};
    if (cond != NULL && cond(ud)) {
        return true;
    }
    int t1 = 0, t2 = 0;
    firc_loop_add_timer(loop, 5, 5, tick, &w, &t1);
    firc_loop_add_timer(loop, (uint64_t)ms, 0, deadline, NULL, &t2);
    firc_loop_run(loop);
    firc_loop_del_timer(loop, t1);
    firc_loop_del_timer(loop, t2);
    return w.met;
}

static void run_for(firc_loop_t *loop, int ms) { (void)run_until(loop, NULL, NULL, ms); }

typedef struct got {
    int calls;
    bool ok;
    uint8_t resp[512];
    size_t len;
    int replies_at_call;
    srv_t *s;
} got_t;

static void on_done(void *ud, const uint8_t *resp, size_t len, bool ok)
{
    got_t *g = ud;
    g->calls++;
    g->ok = ok;
    g->len = len < sizeof g->resp ? len : sizeof g->resp;
    if (resp != NULL) {
        memcpy(g->resp, resp, g->len);
    }
    g->replies_at_call = g->s != NULL ? atomic_load(&g->s->replies) : -1;
}

static bool called(void *ud) { return ((got_t *)ud)->calls > 0; }

typedef struct pair {
    got_t *a, *b;
} pair_t;

static bool both_called(void *ud)
{
    pair_t *p = ud;
    return p->a->calls > 0 && p->b->calls > 0;
}

static bool replied_once(void *ud) { return atomic_load(&((srv_t *)ud)->replies) >= 1; }

static bool wait_replied(srv_t *s, int ms)
{
    for (int i = 0; i < ms / 10; i++) {
        if (atomic_load(&s->replies) >= 1) {
            return true;
        }
        nap_ms(10);
    }
    return false;
}

CURLcode __real_curl_easy_setopt(CURL *e, CURLoption opt, ...);
CURLcode __wrap_curl_easy_setopt(CURL *e, CURLoption opt, ...);
CURLMcode __real_curl_multi_poll(CURLM *m, struct curl_waitfd fds[], unsigned n, int ms, int *ret);
CURLMcode __wrap_curl_multi_poll(CURLM *m, struct curl_waitfd fds[], unsigned n, int ms, int *ret);

static _Atomic bool g_h2c;
static _Atomic long g_cap_ms;
static _Atomic int g_poll_ms;

CURLcode __wrap_curl_easy_setopt(CURL *e, CURLoption opt, ...)
{
    va_list ap;
    va_start(ap, opt);
    CURLcode rc;
    if (opt >= CURLOPTTYPE_OFF_T) {
        rc = __real_curl_easy_setopt(e, opt, va_arg(ap, curl_off_t));
    } else if (opt >= CURLOPTTYPE_OBJECTPOINT) {
        rc = __real_curl_easy_setopt(e, opt, va_arg(ap, void *));
    } else {
        long v = va_arg(ap, long);
        long cap = atomic_load(&g_cap_ms);
        rc = __real_curl_easy_setopt(e, opt, opt == CURLOPT_TIMEOUT_MS && cap > 0 ? cap : v);
    }
    va_end(ap);
    if (opt == CURLOPT_URL && atomic_load(&g_h2c)) {
        (void)__real_curl_easy_setopt(e, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }
    return rc;
}

CURLMcode __wrap_curl_multi_poll(CURLM *m, struct curl_waitfd fds[], unsigned n, int ms, int *ret)
{
    atomic_store(&g_poll_ms, ms);
    return __real_curl_multi_poll(m, fds, n, ms, ret);
}

typedef struct env {
    srv_t s;
    firc_loop_t *loop;
    firc_doh_t *d;
    uint16_t id;
} env_t;

static bool env_up(env_t *e, int status, const char *ctype, int delay_ms, int accept_delay_ms)
{
    memset(e, 0, sizeof *e);
    atomic_store(&g_h2c, false);
    atomic_store(&g_cap_ms, 0);
    if (!srv_start(&e->s, status, ctype, delay_ms, accept_delay_ms) || firc_loop_create(&e->loop) != FIRC_OK) {
        return false;
    }
    e->d = firc_doh_new(e->loop);
    if (e->d == NULL || firc_doh_start(e->d) != FIRC_OK) {
        return false;
    }
    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%u/dns-query", e->s.port);
    e->id = firc_doh_intern(e->d, url);
    return e->id != 0;
}

static void env_down(env_t *e)
{
    firc_doh_free(e->d);
    firc_loop_destroy(e->loop);
    srv_stop(&e->s);
}

static firc_err_t ask(env_t *e, uint32_t mark, uint32_t timeout_ms, got_t *g, uint64_t *ticket)
{
    g->s = &e->s;
    uint8_t q[sizeof k_query];
    memcpy(q, k_query, sizeof q);
    firc_err_t err = firc_doh_query(e->d, e->id, mark, q, sizeof q, timeout_ms, on_done, g, ticket);
    memset(q, 0xee, sizeof q);
    return err;
}

TEST a_query_is_posted_as_rfc8484(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 0));
    got_t g = {0};
    uint64_t t = 0;
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &g, &t));
    ASSERT(t != 0);
    ASSERT(run_until(e.loop, called, &g, 5000));
    pthread_mutex_lock(&e.s.mu);
    ASSERT_STR_EQ("POST", e.s.method);
    ASSERT_STR_EQ("application/dns-message", e.s.req_ctype);
    ASSERT_STR_EQ("application/dns-message", e.s.req_accept);
    uint8_t want_body[sizeof k_query];
    memcpy(want_body, k_query, sizeof want_body);
    want_body[0] = 0;
    want_body[1] = 0;
    ASSERT_EQ(sizeof want_body, e.s.body_len);
    ASSERT_MEM_EQ(want_body, e.s.body, sizeof want_body);
    pthread_mutex_unlock(&e.s.mu);
    ASSERT_EQ(1, g.calls);
    ASSERT(g.ok);
    uint8_t want[sizeof k_reply];
    memcpy(want, k_reply, sizeof want);
    want[0] = 0xab;
    want[1] = 0xcd;
    ASSERT_EQ(sizeof want, g.len);
    ASSERT_MEM_EQ(want, g.resp, sizeof want);
    env_down(&e);
    PASS();
}

TEST a_non_200_is_a_failure(void)
{
    env_t e;
    ASSERT(env_up(&e, 503, "application/dns-message", 0, 0));
    got_t g = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &g, NULL));
    ASSERT(run_until(e.loop, called, &g, 5000));
    ASSERT_EQ(1, g.calls);
    ASSERT_FALSE(g.ok);
    env_down(&e);
    PASS();
}

TEST a_wrong_content_type_is_a_failure(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "text/plain", 0, 0));
    got_t g = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &g, NULL));
    ASSERT(run_until(e.loop, called, &g, 5000));
    ASSERT_EQ(1, g.calls);
    ASSERT_FALSE(g.ok);
    env_down(&e);
    PASS();
}

TEST a_slow_server_times_out(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 1000, 0));
    got_t g = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 200, &g, NULL));
    ASSERT(run_until(e.loop, called, &g, 5000));
    ASSERT_EQ(1, g.calls);
    ASSERT_FALSE(g.ok);
    ASSERT_EQ(0, g.replies_at_call);
    ASSERT(run_until(e.loop, replied_once, &e.s, 5000));
    run_for(e.loop, 200);
    ASSERT_EQ(1, g.calls);
    env_down(&e);
    PASS();
}

TEST two_sequential_queries_share_a_connection(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 0));
    got_t a = {0}, b = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &a, NULL));
    ASSERT(run_until(e.loop, called, &a, 5000));
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &b, NULL));
    ASSERT(run_until(e.loop, called, &b, 5000));
    ASSERT(a.ok && b.ok);
    ASSERT_EQ(1, atomic_load(&e.s.accepts));
    env_down(&e);
    PASS();
}

TEST two_concurrent_queries_over_http1_open_two_connections(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 300, 0));
    got_t w = {0}, c = {0}, d = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &w, NULL));
    ASSERT(run_until(e.loop, called, &w, 5000));
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &c, NULL));
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &d, NULL));
    pair_t p = {&c, &d};
    ASSERT(run_until(e.loop, both_called, &p, 5000));
    ASSERT(c.ok && d.ok);
    ASSERT_EQ(2, atomic_load(&e.s.accepts));
    env_down(&e);
    PASS();
}

TEST a_cancelled_query_never_calls_back(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 50, 0));
    got_t a = {0}, b = {0};
    uint64_t ta = 0, tb = 0;
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &a, &ta));
    firc_doh_cancel(e.d, ta);
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &b, &tb));
    ASSERT(ta != tb);
    ASSERT(run_until(e.loop, called, &b, 5000));
    run_for(e.loop, 100);
    ASSERT_EQ(2, atomic_load(&e.s.replies));
    ASSERT_EQ(0, a.calls);
    ASSERT_EQ(1, b.calls);
    ASSERT(b.ok);
    env_down(&e);
    PASS();
}

TEST a_cancelled_transfer_still_warms_its_connection(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 1000));
    got_t a = {0}, b = {0};
    uint64_t ta = 0;
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 5000, &a, &ta));
    run_for(e.loop, 100);
    firc_doh_cancel(e.d, ta);
    run_for(e.loop, 1400);
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 5000, &b, NULL));
    ASSERT(run_until(e.loop, called, &b, 5000));
    ASSERT(b.ok);
    ASSERT_EQ(0, a.calls);
    ASSERT_EQ(1, atomic_load(&e.s.accepts));
    env_down(&e);
    PASS();
}

static pthread_mutex_t g_set_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_set_calls;
static int g_set_fd;
static uint32_t g_set_mark;

static int record_mark(int fd, int level, int name, const void *val, socklen_t len)
{
    if (level != SOL_SOCKET || name != SO_MARK || len != sizeof(uint32_t)) {
        return setsockopt(fd, level, name, val, len);
    }
    pthread_mutex_lock(&g_set_mu);
    g_set_calls++;
    g_set_fd = fd;
    memcpy(&g_set_mark, val, sizeof g_set_mark);
    pthread_mutex_unlock(&g_set_mu);
    return 0;
}

TEST different_marks_never_share_a_connection(void)
{
    g_set_calls = 0;
    firc_sub_fetch_set_setsockopt_for_test(record_mark);
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 200, 0));
    got_t a = {0}, b = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &a, NULL));
    ASSERT_EQ(FIRC_OK, ask(&e, 7, 3000, &b, NULL));
    pair_t p = {&a, &b};
    ASSERT(run_until(e.loop, both_called, &p, 5000));
    ASSERT(a.ok && b.ok);
    ASSERT_EQ(2, atomic_load(&e.s.accepts));
    pthread_mutex_lock(&g_set_mu);
    ASSERT_EQ(1, g_set_calls);
    ASSERT_EQ(7u, g_set_mark);
    ASSERT(g_set_fd >= 0);
    pthread_mutex_unlock(&g_set_mu);
    env_down(&e);
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    PASS();
}

TEST a_forgotten_mark_opens_a_new_connection(void)
{
    firc_sub_fetch_set_setsockopt_for_test(record_mark);
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 0));
    got_t a = {0}, b = {0}, c = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 7, 2000, &a, NULL));
    ASSERT(run_until(e.loop, called, &a, 5000));
    ASSERT_EQ(FIRC_OK, ask(&e, 7, 2000, &b, NULL));
    ASSERT(run_until(e.loop, called, &b, 5000));
    ASSERT_EQ(1, atomic_load(&e.s.accepts));
    firc_doh_forget_mark(e.d, 7);
    ASSERT_EQ(FIRC_OK, ask(&e, 7, 2000, &c, NULL));
    ASSERT(run_until(e.loop, called, &c, 5000));
    ASSERT(a.ok && b.ok && c.ok);
    ASSERT_EQ(2, atomic_load(&e.s.accepts));
    env_down(&e);
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    PASS();
}

TEST a_mark_forgotten_mid_transfer_drops_its_share_after(void)
{
    firc_sub_fetch_set_setsockopt_for_test(record_mark);
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 300, 0));
    got_t a = {0}, b = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 7, 3000, &a, NULL));
    run_for(e.loop, 50);
    firc_doh_forget_mark(e.d, 7);
    ASSERT(run_until(e.loop, called, &a, 5000));
    ASSERT(a.ok);
    ASSERT_EQ(FIRC_OK, ask(&e, 7, 3000, &b, NULL));
    ASSERT(run_until(e.loop, called, &b, 5000));
    ASSERT(b.ok);
    ASSERT_EQ(2, atomic_load(&e.s.accepts));
    env_down(&e);
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    PASS();
}

TEST a_forgotten_mark_drops_every_server_of_it(void)
{
    firc_sub_fetch_set_setsockopt_for_test(record_mark);
    env_t e;
    srv_t other;
    ASSERT(srv_start(&other, 200, "application/dns-message", 0, 0));
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 0));
    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%u/dns-query", other.port);
    uint16_t ids[2] = {e.id, firc_doh_intern(e.d, url)};
    for (int round = 0; round < 2; round++) {
        for (int i = 0; i < 2; i++) {
            got_t g = {0};
            e.id = ids[i];
            ASSERT_EQ(FIRC_OK, ask(&e, 7, 2000, &g, NULL));
            ASSERT(run_until(e.loop, called, &g, 5000));
            ASSERT(g.ok);
        }
        firc_doh_forget_mark(e.d, 7);
    }
    ASSERT_EQ(2, atomic_load(&e.s.accepts));
    ASSERT_EQ(2, atomic_load(&other.accepts));
    env_down(&e);
    srv_stop(&other);
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    PASS();
}

static bool h2_up(env_t *e)
{
    bool up = env_up(e, 200, "application/dns-message", 0, 0);
    atomic_store(&g_h2c, true);
    atomic_store(&e->s.h2, true);
    return up;
}

TEST a_silent_connection_is_left_after_a_timeout(void)
{
    env_t e;
    ASSERT(h2_up(&e));
    got_t a = {0}, b = {0}, c = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &a, NULL));
    ASSERT(run_until(e.loop, called, &a, 5000));
    ASSERT(a.ok);
    atomic_store(&e.s.swallow, 1);
    atomic_store(&g_cap_ms, 300);
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &b, NULL));
    ASSERT(run_until(e.loop, called, &b, 5000));
    ASSERT_FALSE(b.ok);
    ASSERT_EQ(1, atomic_load(&e.s.accepts));
    atomic_store(&g_cap_ms, 0);
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &c, NULL));
    ASSERT(run_until(e.loop, called, &c, 5000));
    ASSERT(c.ok);
    ASSERT_EQ(2, atomic_load(&e.s.accepts));
    env_down(&e);
    PASS();
}

TEST a_timeout_leaves_another_server_its_connection(void)
{
    env_t e;
    srv_t other;
    ASSERT(srv_start(&other, 200, "application/dns-message", 0, 0));
    atomic_store(&other.h2, true);
    ASSERT(h2_up(&e));
    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%u/dns-query", other.port);
    uint16_t id = e.id, other_id = firc_doh_intern(e.d, url);
    got_t a = {0}, b = {0}, c = {0};
    e.id = other_id;
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &a, NULL));
    ASSERT(run_until(e.loop, called, &a, 5000));
    ASSERT(a.ok);
    atomic_store(&e.s.swallow, 1);
    atomic_store(&g_cap_ms, 300);
    e.id = id;
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &b, NULL));
    ASSERT(run_until(e.loop, called, &b, 5000));
    ASSERT_FALSE(b.ok);
    atomic_store(&g_cap_ms, 0);
    e.id = other_id;
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &c, NULL));
    ASSERT(run_until(e.loop, called, &c, 5000));
    ASSERT(c.ok);
    ASSERT_EQ(1, atomic_load(&other.accepts));
    env_down(&e);
    srv_stop(&other);
    PASS();
}

static bool swallowed(void *ud) { return atomic_load(&((srv_t *)ud)->swallow) == 0; }

TEST a_query_beside_a_timed_out_one_is_still_answered(void)
{
    env_t e;
    ASSERT(h2_up(&e));
    got_t a = {0}, b = {0}, c = {0}, d = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &a, NULL));
    ASSERT(run_until(e.loop, called, &a, 5000));
    atomic_store(&e.s.swallow, 1);
    atomic_store(&e.s.delay_ms, 1500);
    atomic_store(&g_cap_ms, 1000);
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &b, NULL));
    ASSERT(run_until(e.loop, swallowed, &e.s, 900));
    atomic_store(&g_cap_ms, 0);
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &c, NULL));
    ASSERT(run_until(e.loop, called, &b, 5000));
    ASSERT_FALSE(b.ok);
    ASSERT_EQ(0, c.calls);
    ASSERT(run_until(e.loop, called, &c, 5000));
    ASSERT(c.ok);
    ASSERT_EQ(1, atomic_load(&e.s.accepts));
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &d, NULL));
    ASSERT(run_until(e.loop, called, &d, 5000));
    ASSERT(d.ok);
    ASSERT_EQ(2, atomic_load(&e.s.accepts));
    env_down(&e);
    PASS();
}

TEST an_idle_client_does_not_wake(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 0));
    got_t g = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 2000, &g, NULL));
    ASSERT(run_until(e.loop, called, &g, 5000));
    run_for(e.loop, 200);
    ASSERT(atomic_load(&g_poll_ms) > 60000);
    env_down(&e);
    PASS();
}

static void noop_post(firc_loop_t *loop, void *ud)
{
    (void)loop;
    (void)ud;
}

TEST a_full_loop_queue_delays_the_answer_not_loses_it(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 0));
    int filled = 0;
    while (filled < 4096 && firc_loop_post(e.loop, noop_post, NULL) == FIRC_OK) {
        filled++;
    }
    ASSERT(filled < 4096);
    got_t g = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &g, NULL));
    ASSERT(wait_replied(&e.s, 5000));
    nap_ms(200);
    ASSERT(run_until(e.loop, called, &g, 5000));
    ASSERT_EQ(1, g.calls);
    ASSERT(g.ok);
    env_down(&e);
    PASS();
}

TEST the_same_url_interns_to_one_id(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_doh_t *d = firc_doh_new(loop);
    ASSERT(d != NULL);
    char url[64];
    snprintf(url, sizeof url, "https://a.example/dns-query");
    uint16_t a = firc_doh_intern(d, url);
    url[8] = 'b';
    uint16_t b = firc_doh_intern(d, url);
    uint16_t a2 = firc_doh_intern(d, "https://a.example/dns-query");
    ASSERT(a != 0);
    ASSERT(b != 0);
    ASSERT(a != b);
    ASSERT_EQ(a, a2);
    ASSERT_STR_EQ("https://a.example/dns-query", firc_doh_url(d, a));
    ASSERT_STR_EQ("https://b.example/dns-query", firc_doh_url(d, b));
    ASSERT_EQ(NULL, firc_doh_url(d, 0));
    for (int i = 2; i < FIRC_DOH_MAX_URLS; i++) {
        snprintf(url, sizeof url, "https://h%d.example/q", i);
        ASSERT(firc_doh_intern(d, url) != 0);
    }
    ASSERT_EQ(0, firc_doh_intern(d, "https://full.example/q"));
    ASSERT_EQ(a, firc_doh_intern(d, "https://a.example/dns-query"));
    ASSERT_EQ(0, firc_doh_intern(d, NULL));
    got_t g = {0};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_doh_query(d, 0, 0, k_query, sizeof k_query, 1000, on_done, &g, NULL));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_doh_query(d, a, 0, k_query, 11, 1000, on_done, &g, NULL));
    firc_doh_free(d);
    firc_loop_destroy(loop);
    PASS();
}

TEST free_with_a_query_in_flight_calls_nothing(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 500, 0));
    got_t g = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &g, NULL));
    run_for(e.loop, 100);
    firc_doh_free(e.d);
    e.d = NULL;
    run_for(e.loop, 800);
    ASSERT_EQ(0, g.calls);
    firc_loop_destroy(e.loop);
    srv_stop(&e.s);
    PASS();
}

TEST free_with_a_result_queued_calls_nothing(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 0));
    got_t g = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &g, NULL));
    ASSERT(wait_replied(&e.s, 5000));
    nap_ms(200);
    firc_doh_free(e.d);
    run_for(e.loop, 100);
    ASSERT_EQ(0, g.calls);
    firc_loop_destroy(e.loop);
    srv_stop(&e.s);
    PASS();
}

TEST a_result_queued_at_loop_destroy_is_dropped(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 0, 0));
    got_t g = {0};
    ASSERT_EQ(FIRC_OK, ask(&e, 0, 3000, &g, NULL));
    ASSERT(wait_replied(&e.s, 5000));
    nap_ms(200);
    firc_doh_free(e.d);
    firc_loop_destroy(e.loop);
    ASSERT_EQ(0, g.calls);
    srv_stop(&e.s);
    PASS();
}

TEST the_ops_seam_reaches_the_client(void)
{
    env_t e;
    ASSERT(env_up(&e, 200, "application/dns-message", 50, 0));
    firc_doh_ops_t ops = firc_doh_ops(e.d);
    ASSERT_EQ(e.d, ops.ud);
    got_t a = {.s = &e.s}, b = {.s = &e.s};
    uint64_t ta = 0;
    ASSERT_EQ(FIRC_OK, ops.query(ops.ud, e.id, 0, k_query, sizeof k_query, 2000, on_done, &a, &ta));
    ops.cancel(ops.ud, ta);
    ASSERT_EQ(FIRC_OK, ops.query(ops.ud, e.id, 0, k_query, sizeof k_query, 2000, on_done, &b, NULL));
    ASSERT(run_until(e.loop, called, &b, 5000));
    ASSERT(b.ok);
    ASSERT_EQ(0, a.calls);
    env_down(&e);
    PASS();
}

SUITE(doh)
{
    RUN_TEST(a_query_is_posted_as_rfc8484);
    RUN_TEST(a_non_200_is_a_failure);
    RUN_TEST(a_wrong_content_type_is_a_failure);
    RUN_TEST(a_slow_server_times_out);
    RUN_TEST(two_sequential_queries_share_a_connection);
    RUN_TEST(two_concurrent_queries_over_http1_open_two_connections);
    RUN_TEST(a_cancelled_query_never_calls_back);
    RUN_TEST(a_cancelled_transfer_still_warms_its_connection);
    RUN_TEST(different_marks_never_share_a_connection);
    RUN_TEST(a_forgotten_mark_opens_a_new_connection);
    RUN_TEST(a_mark_forgotten_mid_transfer_drops_its_share_after);
    RUN_TEST(a_forgotten_mark_drops_every_server_of_it);
    RUN_TEST(a_silent_connection_is_left_after_a_timeout);
    RUN_TEST(a_timeout_leaves_another_server_its_connection);
    RUN_TEST(a_query_beside_a_timed_out_one_is_still_answered);
    RUN_TEST(an_idle_client_does_not_wake);
    RUN_TEST(a_full_loop_queue_delays_the_answer_not_loses_it);
    RUN_TEST(the_same_url_interns_to_one_id);
    RUN_TEST(free_with_a_query_in_flight_calls_nothing);
    RUN_TEST(free_with_a_result_queued_calls_nothing);
    RUN_TEST(a_result_queued_at_loop_destroy_is_dropped);
    RUN_TEST(the_ops_seam_reaches_the_client);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    firc_sub_fetch_global_init();
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(doh);
    GREATEST_MAIN_END();
}
