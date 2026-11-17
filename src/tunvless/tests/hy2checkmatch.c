#define _GNU_SOURCE
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <dirent.h>

#include "../src/proto/transport/trdial.c"
#include "quic.h"
#include "hy2conn.h"
#include "hy2node.h"
#include "hy2link.h"
#include "hy2run.h"
#include "hy2check.h"
#include "client.h"
#include "roots.h"
#include "scrypto.h"
#include "certgen.h"
#include "unit.h"

static uint64_t ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t hp_ms(void) { return ms_now(); }

#include "hy2peer.h"

static unsigned g_tx = 1;
static uint8_t g_pat[4096];
static unsigned char g_ca[2048], g_leaf[2048], g_key[512];
static size_t g_ca_n, g_leaf_n, g_key_n;
static char g_ca_pem[4096];
static char g_roots[64];

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_prep[64];
static unsigned g_prep_n;
struct crec { char ip[46]; uint16_t port; int prepared; };
static struct crec g_conn[64];
static unsigned g_conn_n;

int __real_tr_sock_prepare(int fd);
int __wrap_tr_sock_prepare(int fd) {
    pthread_mutex_lock(&g_mu);
    if (g_prep_n < 64) g_prep[g_prep_n++] = fd;
    pthread_mutex_unlock(&g_mu);
    return __real_tr_sock_prepare(fd);
}

int __real_connect(int fd, const struct sockaddr *a, socklen_t n);
int __wrap_connect(int fd, const struct sockaddr *a, socklen_t n) {
    int type = 0;
    socklen_t tl = sizeof type;
    if (a && getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 && type == SOCK_DGRAM) {
        pthread_mutex_lock(&g_mu);
        if (g_conn_n < 64) {
            struct crec *r = &g_conn[g_conn_n++];
            memset(r, 0, sizeof *r);
            if (a->sa_family == AF_INET) {
                const struct sockaddr_in *s4 = (const struct sockaddr_in *)a;
                inet_ntop(AF_INET, &s4->sin_addr, r->ip, sizeof r->ip);
                r->port = ntohs(s4->sin_port);
            } else if (a->sa_family == AF_INET6) {
                const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)a;
                inet_ntop(AF_INET6, &s6->sin6_addr, r->ip, sizeof r->ip);
                r->port = ntohs(s6->sin6_port);
            }
            for (unsigned i = 0; i < g_prep_n; i++)
                if (g_prep[i] == fd) {
                    r->prepared = 1;
                    g_prep[i] = g_prep[--g_prep_n];
                    break;
                }
        }
        pthread_mutex_unlock(&g_mu);
    }
    return __real_connect(fd, a, n);
}

static unsigned g_tfd_calls, g_tfd_abs_zero;

static const struct itimerspec *tfd_seen(int fl, const struct itimerspec *v, struct itimerspec *one) {
    g_tfd_calls++;
    if (!(fl & TFD_TIMER_ABSTIME) || !v || v->it_value.tv_sec || v->it_value.tv_nsec) return v;
    g_tfd_abs_zero++;
    *one = *v;
    one->it_value.tv_nsec = 1;
    return one;
}

int __real_timerfd_settime(int fd, int fl, const struct itimerspec *v, struct itimerspec *o);
int __wrap_timerfd_settime(int fd, int fl, const struct itimerspec *v, struct itimerspec *o) {
    struct itimerspec one;
    return __real_timerfd_settime(fd, fl, tfd_seen(fl, v, &one), o);
}

#if (defined(__GLIBC__) && defined(__USE_TIME_BITS64) && __TIMESIZE == 32) || (defined(_REDIR_TIME64) && _REDIR_TIME64)
int __real___timerfd_settime64(int fd, int fl, const struct itimerspec *v, struct itimerspec *o);
int __wrap___timerfd_settime64(int fd, int fl, const struct itimerspec *v, struct itimerspec *o);
int __wrap___timerfd_settime64(int fd, int fl, const struct itimerspec *v, struct itimerspec *o) {
    struct itimerspec one;
    return __real___timerfd_settime64(fd, fl, tfd_seen(fl, v, &one), o);
}
#endif

static int g_tfd_fail;
int __real_timerfd_create(int clock, int flags);
int __wrap_timerfd_create(int clock, int flags) {
    if (__atomic_exchange_n(&g_tfd_fail, 0, __ATOMIC_SEQ_CST)) {
        errno = EMFILE;
        return -1;
    }
    return __real_timerfd_create(clock, flags);
}

static unsigned g_ctx_loads;
void *__real_qcssl_ctx_client(int load_roots, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file);
void *__wrap_qcssl_ctx_client(int load_roots, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file);
void *__wrap_qcssl_ctx_client(int load_roots, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file) {
    g_ctx_loads++;
    return __real_qcssl_ctx_client(load_roots, ca_pem, ca_pem_n, ca_file);
}

static unsigned g_qo_calls;
static struct qc_cfg g_qo;

int __real_qc_open(const struct qc_cfg *cfg, const struct qc_ops *ops, void *user, struct qc **out);
int __wrap_qc_open(const struct qc_cfg *cfg, const struct qc_ops *ops, void *user, struct qc **out) {
    pthread_mutex_lock(&g_mu);
    g_qo_calls++;
    g_qo = *cfg;
    pthread_mutex_unlock(&g_mu);
    return __real_qc_open(cfg, ops, user, out);
}

static void rec_reset(void) {
    g_qo_calls = 0;
    pthread_mutex_lock(&g_mu);
    g_prep_n = 0;
    g_conn_n = 0;
    pthread_mutex_unlock(&g_mu);
}

static unsigned conns_to(uint16_t port, const char *ip, unsigned *prepared) {
    unsigned n = 0;
    if (prepared) *prepared = 0;
    pthread_mutex_lock(&g_mu);
    for (unsigned i = 0; i < g_conn_n; i++)
        if (g_conn[i].port == port && (!ip || !strcmp(g_conn[i].ip, ip))) {
            n++;
            if (prepared) *prepared += (unsigned)g_conn[i].prepared;
        }
    pthread_mutex_unlock(&g_mu);
    return n;
}

static const char *conn_ip(uint16_t port, unsigned k) {
    for (unsigned i = 0; i < g_conn_n; i++)
        if (g_conn[i].port == port && k-- == 0) return g_conn[i].ip;
    return "";
}

struct srv {
    struct hy2peer p;
    pthread_t th;
    int stop, running;
    unsigned delay_ms;
};

static struct srv g_srv;
static const struct qc_filter *g_srv_filter;

static void *srv_main(void *arg) {
    struct srv *s = arg;
    if (s->delay_ms) usleep(s->delay_ms * 1000u);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(s->p.q), &ev);
    while (!__atomic_load_n(&s->stop, __ATOMIC_ACQUIRE)) {
        int t = qc_timeout_ms(s->p.q);
        if (t < 0 || t > 10) t = 10;
        struct epoll_event e;
        if (epoll_wait(ep, &e, 1, t) > 0) (void)qc_on_readable(s->p.q);
        if (qc_timeout_ms(s->p.q) == 0) (void)qc_on_timer(s->p.q);
        hp_drain(&s->p);
        qc_flush(s->p.q);
    }
    close(ep);
    return NULL;
}

static uint16_t srv_start(struct srv *s, const char *bind, unsigned delay_ms) {
    memset(&s->th, 0, sizeof s->th);
    s->stop = 0;
    s->running = 0;
    s->delay_ms = delay_ms;
    hp_init(&s->p, g_pat);
    s->p.keep = 1;
    struct qc_srv_cfg sc;
    memset(&sc, 0, sizeof sc);
    sc.bind_host = bind;
    sc.alpn = "h3";
    sc.cert_der = g_leaf;
    sc.cert_n = g_leaf_n;
    sc.key_der = g_key;
    sc.key_n = g_key_n;
    sc.datagram_max = 1200;
    sc.filter = g_srv_filter;
    if (hp_listen(&s->p, &sc) != 0) return 0;
    if (pthread_create(&s->th, NULL, srv_main, s) != 0) return 0;
    s->running = 1;
    return qc_local_port(s->p.q);
}

static void srv_end(struct srv *s) {
    if (s->running) {
        __atomic_store_n(&s->stop, 1, __ATOMIC_RELEASE);
        pthread_join(s->th, NULL);
        s->running = 0;
    }
}

static void srv_free(struct srv *s) {
    srv_end(s);
    hp_free(&s->p);
}

static int targets_of(struct hy2peer *p, const char *out[4]) {
    int n = 0;
    for (int i = 0; i < HP_MAXST && n < 4; i++)
        if (p->st[i].used && p->st[i].addr[0]) out[n++] = p->st[i].addr;
    return n;
}

static struct hp_st *target_st(struct hy2peer *p, int k) {
    for (int i = 0; i < HP_MAXST; i++)
        if (p->st[i].used && p->st[i].addr[0] && k-- == 0) return &p->st[i];
    return NULL;
}

static void node_make(struct vless_node *n, const char *host, uint16_t port) {
    memset(n, 0, sizeof *n);
    snprintf(n->name, sizeof n->name, "hy2-test");
    snprintf(n->host, sizeof n->host, "%s", host);
    n->port = port;
    n->proto = VLESS_PROTO_HY2;
    snprintf(n->type, sizeof n->type, "quic");
    snprintf(n->security, sizeof n->security, "tls");
    snprintf(n->sni, sizeof n->sni, "node.test");
    n->auth = "secret";
}

static uint16_t silent_bind(const char *ip, uint16_t port, int *fd) {
    *fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    inet_pton(AF_INET, ip, &a.sin_addr);
    socklen_t al = sizeof a;
    if (*fd < 0 || bind(*fd, (struct sockaddr *)&a, sizeof a) != 0 ||
        getsockname(*fd, (struct sockaddr *)&a, &al) != 0) return 0;
    return ntohs(a.sin_port);
}

static const char GET_1111[] = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";

static void a_probe_passes_on_the_targets_first_byte_and_measures(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 300);
    check("first byte: peer listens", 1, port != 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    rec_reset();
    char why[256] = "";
    int hs = -2, ttfb = -2;
    int rc = hy2_probe_timed(&n, 8, why, sizeof why, &hs, &ttfb);
    srv_end(&g_srv);
    printf("     why: %s, handshake %d ms, first byte %d ms\n", why, hs, ttfb);
    check("first byte: rc 0", 0, rc);
    check("first byte: handshake covers the peer's 300 ms delay", 1, hs >= 300);
    check("first byte: ttfb measured", 1, ttfb >= 0);
    check("first byte: ttfb counts from the request, not the start", 1, ttfb >= 0 && ttfb < hs);
    const char *tg[4];
    int nt = targets_of(&g_srv.p, tg);
    check("first byte: one target asked", 1, nt);
    check_str("first byte: the target is 1.1.1.1:80", "1.1.1.1:80", nt > 0 ? tg[0] : "");
    struct hp_st *s = target_st(&g_srv.p, 0);
    check("first byte: payload length", (long)strlen(GET_1111), s ? (long)s->seen.n : -1);
    check("first byte: payload is the GET", 1,
          s && s->seen.n == strlen(GET_1111) && !memcmp(s->seen.p, GET_1111, s->seen.n));
    unsigned prep = 0;
    check("first byte: one connection to the node", 1, conns_to(port, NULL, &prep));
    check("first byte: its socket went through the hook", 1, prep);
    srv_free(&g_srv);
}

static void an_ok_without_data_is_not_a_pass(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv.p.mute[0] = "1.1.1.1:80";
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    rec_reset();
    char why[256] = "";
    int rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
    srv_end(&g_srv);
    printf("     why: %s\n", why);
    check("ok, then silence: the second target passes", 0, rc);
    const char *tg[4];
    int nt = targets_of(&g_srv.p, tg);
    check("ok, then silence: two targets asked", 2, nt);
    check_str("ok, then silence: 1.1.1.1:80 first", "1.1.1.1:80", nt > 0 ? tg[0] : "");
    check_str("ok, then silence: 8.8.8.8:80 second", "8.8.8.8:80", nt > 1 ? tg[1] : "");
    check("ok, then silence: one connection", 1, conns_to(port, NULL, NULL));
    srv_free(&g_srv);

    port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv.p.mute[0] = "1.1.1.1:80";
    g_srv.p.mute[1] = "8.8.8.8:80";
    node_make(&n, "127.0.0.1", port);
    why[0] = 0;
    uint64_t t0 = ms_now();
    rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
    uint64_t el = ms_now() - t0;
    srv_end(&g_srv);
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("silent on both: fails", 1, rc != 0);
    check("silent on both: why says no data", 1, strstr(why, "no data") != NULL);
    check("silent on both: both targets asked", 2, targets_of(&g_srv.p, tg));
    check("silent on both: the budget is spent, not more", 1, el >= 5500 && el <= 7000u * g_tx);
    srv_free(&g_srv);
}

static void a_wrong_password_fails_fast_with_the_status(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    n.auth = "wrong";
    rec_reset();
    char why[256] = "";
    uint64_t t0 = ms_now();
    int rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
    uint64_t el = ms_now() - t0;
    srv_end(&g_srv);
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("wrong password: fails", 1, rc != 0);
    check("wrong password: within 1000 ms", 1, el < 1000u * g_tx);
    check("wrong password: why has the status", 1, strstr(why, "auth failed code 404") != NULL);
    check("wrong password: one connection", 1, conns_to(port, NULL, NULL));
    const char *tg[4];
    check("wrong password: no target asked", 0, targets_of(&g_srv.p, tg));
    srv_free(&g_srv);
}

static void probe6_needs_the_targets_answer(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv.p.mute[0] = "[2606:4700:4700::1111]:80";
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    char why[256] = "";
    int rc = hy2_probe6(&n, 6, why, sizeof why);
    srv_end(&g_srv);
    printf("     why: %s\n", why);
    check("v6, ok then silence: the second target passes", 0, rc);
    const char *tg[4];
    int nt = targets_of(&g_srv.p, tg);
    check("v6, ok then silence: two targets asked", 2, nt);
    check_str("v6: the first target", "[2606:4700:4700::1111]:80", nt > 0 ? tg[0] : "");
    check_str("v6: the second target", "[2001:4860:4860::8888]:80", nt > 1 ? tg[1] : "");
    struct hp_st *s = target_st(&g_srv.p, 0);
    static const char want[] = "GET / HTTP/1.1\r\nHost: [2606:4700:4700::1111]\r\nConnection: close\r\n\r\n";
    check("v6: payload is the GET with the bracketed host", 1,
          s && s->seen.n == strlen(want) && !memcmp(s->seen.p, want, s->seen.n));
    srv_free(&g_srv);

    port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv.p.mute[0] = "[2606:4700:4700::1111]:80";
    g_srv.p.mute[1] = "[2001:4860:4860::8888]:80";
    node_make(&n, "127.0.0.1", port);
    why[0] = 0;
    rc = hy2_probe6(&n, 6, why, sizeof why);
    srv_end(&g_srv);
    printf("     why: %s\n", why);
    check("v6, silent on both: fails", 1, rc != 0);
    check("v6, silent on both: why says no data", 1, strstr(why, "no data") != NULL);
    srv_free(&g_srv);
}

static void a_probe_that_cannot_watch_its_socket_says_so(void) {
    int fd;
    uint16_t port = silent_bind("127.0.0.1", 0, &fd);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    char why[256] = "";
    g_tfd_fail = 1;
    uint64_t t0 = ms_now();
    int rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
    g_tfd_fail = 0;
    check("no watch: fails", 1, rc != 0);
    check("no watch: at once", 1, ms_now() - t0 < 1000u * g_tx);
    check_str("no watch: why says the probe could not watch", "cannot watch the socket to 127.0.0.1", why);
    close(fd);
}

static void a_silent_node_fails_by_the_budget(void) {
    int fd;
    uint16_t port = silent_bind("127.0.0.1", 0, &fd);
    check("silent: socket bound", 1, port != 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    char why[256] = "";
    uint64_t t0 = ms_now();
    int rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
    uint64_t el = ms_now() - t0;
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("silent: fails", 1, rc != 0);
    check("silent: after 3000 ms without a datagram, not 8000", 1, el >= 3000 && el <= 3000 + 500u * g_tx);
    check("silent: why says no answer", 1, strstr(why, "no answer") != NULL);
    why[0] = 0;
    t0 = ms_now();
    rc = hy2_probe_timed(&n, 2, why, sizeof why, NULL, NULL);
    el = ms_now() - t0;
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("silent, 2 s budget: fails", 1, rc != 0);
    check("silent, 2 s budget: between 1900 and 2500 ms", 1, el >= 1900 && el <= 2500u * g_tx);
    check_str("silent, 2 s budget: a node without a list names the address", "no answer from 127.0.0.1", why);
    snprintf(n.ports, sizeof n.ports, "%u,%u", port, port);
    n.hop_mode = HY2_HOP_REMOTE;
    why[0] = 0;
    rc = hy2_probe_timed(&n, 2, why, sizeof why, NULL, NULL);
    char want[64];
    snprintf(want, sizeof want, "no answer from 127.0.0.1 on port %u", port);
    check("silent, a port list: fails", 1, rc != 0);
    check_str("silent, a port list: the drawn port is named", want, why);
    close(fd);

    port = silent_bind("127.0.0.1", 0, &fd);
    close(fd);
    node_make(&n, "127.0.0.1", port);
    why[0] = 0;
    t0 = ms_now();
    rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
    el = ms_now() - t0;
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("closed port: fails", 1, rc != 0);
    check("closed port: within 1000 ms", 1, el < 1000u * g_tx);
    check("closed port: why says refused", 1, strstr(why, "connection refused") != NULL);
}

static unsigned g_stub_calls;

static unsigned two_addrs(const char *host, struct tr_ip out[ADDR_MAX]) {
    if (strcmp(host, "n.test")) return resolve(host, out);
    g_stub_calls++;
    memset(out, 0, 2 * sizeof out[0]);
    inet_pton(AF_INET, "127.0.0.2", out[0].b);
    inet_pton(AF_INET, "127.0.0.1", out[1].b);
    return 2;
}

static void addresses_are_tried_in_turn(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    int fd;
    check("in turn: the silent address is bound", 1, silent_bind("127.0.0.2", port, &fd) == port);
    struct vless_node n;
    node_make(&n, "n.test", port);
    g_resolve = two_addrs;
    rec_reset();
    char why[256] = "";
    uint64_t t0 = ms_now();
    int rc = hy2_probe_timed(&n, 16, why, sizeof why, NULL, NULL);
    uint64_t el = ms_now() - t0;
    srv_end(&g_srv);
    g_resolve = resolve;
    close(fd);
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("in turn: passes on the second address", 0, rc);
    check("in turn: the stub resolved the name", 1, g_stub_calls > 0);
    check("in turn: within the budget, after the silent one", 1, el >= 3000 && el < 16000u * g_tx);
    check("in turn: two connections", 2, conns_to(port, NULL, NULL));
    check_str("in turn: the silent address first", "127.0.0.2", conn_ip(port, 0));
    check_str("in turn: the peer second", "127.0.0.1", conn_ip(port, 1));
    check("in turn: the silent address once", 1, conns_to(port, "127.0.0.2", NULL));
    srv_free(&g_srv);

    port = srv_start(&g_srv, "127.0.0.1", 0);
    node_make(&n, "localhost", port);
    rec_reset();
    why[0] = 0;
    rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
    srv_end(&g_srv);
    printf("     why: %s\n", why);
    check("localhost, no pin: resolved and probed", 0, rc);
    check("localhost: connected to 127.0.0.1", 1, conns_to(port, "127.0.0.1", NULL));
    srv_free(&g_srv);
}

struct runner { int calls, at, ret, ready; };

static void r_ready(void *u, uint64_t rx, int udp) { (void)rx; (void)udp; ((struct runner *)u)->ready = 1; }
static void r_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) { (void)u; (void)sid; (void)d; (void)n; (void)fin; }
static void r_sid(void *u, int64_t sid) { (void)u; (void)sid; }
static void r_none(void *u) { (void)u; }
static void r_refused(void *u, int64_t sid, const char *m) { (void)u; (void)sid; (void)m; }
static void r_sclose(void *u, int64_t sid, int how) { (void)u; (void)sid; (void)how; }
static void r_udp(void *u, uint32_t s, const char *a, size_t an, const uint8_t *d, size_t n) { (void)u; (void)s; (void)a; (void)an; (void)d; (void)n; }
static void r_closed(void *u, int reason, const char *why) { (void)u; (void)reason; (void)why; }

static const struct hy2c_ops g_rops = {
    .on_ready = r_ready, .on_stream_data = r_data, .on_stream_writable = r_sid, .on_streams_open = r_none,
    .on_stream_refused = r_refused, .on_stream_close = r_sclose, .on_udp = r_udp, .on_closed = r_closed,
};

static int count_step(void *u) {
    struct runner *r = u;
    return ++r->calls == r->at ? r->ret : 0;
}

static uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static void run_returns_the_step_value_or_the_deadline(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    static struct hy2_nodecfg cfg;
    check("run: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    struct runner r = { 0, 3, 7, 0 };
    struct hy2c *c = NULL;
    check("run: session opens", 0, hy2c_open(&cfg.c, &g_rops, &r, &c));
    struct hy2_run_stats st = { 0, 0 };
    int rc = c ? hy2_run(c, ns_now() + 5000000000ull * g_tx, count_step, &r, &st) : -1;
    check("run: the step's 7 comes back", 7, rc);
    check("run: on the third call", 3, r.calls);

    r.calls = 0;
    r.at = 0;
    g_tfd_calls = 0;
    uint64_t t0 = ms_now();
    rc = c ? hy2_run(c, ns_now() + 200000000ull, count_step, &r, &st) : -1;
    uint64_t el = ms_now() - t0;
    check("run: a quiet step times out", HY2_RUN_TIMEOUT, rc);
    check("run: at the deadline, between 190 and 400 ms", 1, el >= 190 && el <= 400u * g_tx);
    check("run: the timer was armed", 1, g_tfd_calls > 0);

    if (c) hy2c_close(c);
    check("run: a closing session is due at once", 1, c && hy2c_deadline_ns(c) <= ns_now());
    g_tfd_abs_zero = 0;
    t0 = ms_now();
    rc = c ? hy2_run(c, ns_now() + 2000000000ull * g_tx, count_step, &r, &st) : -1;
    el = ms_now() - t0;
    check("run: the closed session is reported", HY2_RUN_CLOSED, rc);
    check("run: no timer armed at an absolute 0", 0, g_tfd_abs_zero);
    check("run: closed without waiting", 1, el < 500u * g_tx);
    t0 = ms_now();
    rc = c ? hy2_run(c, ns_now() + 2000000000ull, count_step, &r, &st) : -1;
    el = ms_now() - t0;
    check("run: an already closed session is reported", HY2_RUN_CLOSED, rc);
    check("run: at once, not at the deadline", 1, el < 100u * g_tx);
    rc = c ? hy2_run(c, UINT64_MAX, count_step, &r, &st) : -1;
    check("run: a closed session with no deadline returns", HY2_RUN_CLOSED, rc);
    check("run: no session is a closed one", HY2_RUN_CLOSED, hy2_run(NULL, UINT64_MAX, count_step, &r, &st));
    hy2c_free(c);
    srv_free(&g_srv);
}

static void one_tls_context_per_process(void) {
    struct vless_node n;
    int ok = 0;
    for (int i = 0; i < 2; i++) {
        uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
        node_make(&n, "127.0.0.1", port);
        char why[256] = "";
        ok += hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL) == 0;
        srv_free(&g_srv);
    }
    check("one context: both probes pass", 2, ok);
    struct qc_tls *t = hy2_tls();
    check("one context: hy2_tls is one pointer", 1, t != NULL && t == hy2_tls());
    static struct hy2_nodecfg cfg;
    node_make(&n, "127.0.0.1", 443);
    check("one context: a node config carries it", 1, hy2_nodecfg(&n, 0, &cfg) == 1 && cfg.c.qc.tls == t);
    check("one context: the roots were loaded once", 1, g_ctx_loads);
}

static void hex32(const uint8_t *b, char *out) {
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static void no_ca_bundle_still_gives_a_context(void) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        tls_set_cert_roots("/nonexistent");
        check("no bundle: a context exists", 1, hy2_tls() != NULL);
        uint8_t h[32];
        char pin[65];
        sc_hash(SC_SHA256, g_leaf, g_leaf_n, h);
        hex32(h, pin);
        uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
        struct vless_node n;
        node_make(&n, "127.0.0.1", port);
        n.pcs = pin;
        char why[256] = "";
        int rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
        printf("     why: %s\n", why);
        check("no bundle: a pinned node probes ok", 0, rc);
        srv_free(&g_srv);
        port = srv_start(&g_srv, "127.0.0.1", 0);
        node_make(&n, "127.0.0.1", port);
        why[0] = 0;
        rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
        printf("     why: %s\n", why);
        check("no bundle: a CA-checked node fails", 1, rc != 0);
        check("no bundle: why names the chain", 1, strstr(why, "chain") != NULL);
        srv_free(&g_srv);
        port = srv_start(&g_srv, "127.0.0.1", 0);
        node_make(&n, "127.0.0.1", port);
        n.insecure = 1;
        why[0] = 0;
        rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
        printf("     why: %s\n", why);
        check("no bundle: an insecure node probes ok", 0, rc);
        srv_free(&g_srv);
        fflush(stdout);
        _exit(unit_fail ? 1 : 0);
    }
    int status = -1;
    if (pid > 0) waitpid(pid, &status, 0);
    check("no bundle: the child passed", 1, pid > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void a_refusal_text_cannot_break_the_line(void) {
    static const uint8_t raw[] = { 'a', '\n', 'b', '\r', 'c', '\t', 'd', 0, 'e' };
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv.p.refuse = 1;
    g_srv.p.refuse_raw = raw;
    g_srv.p.refuse_raw_n = sizeof raw;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    char why[256] = "";
    int rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
    srv_end(&g_srv);
    printf("     why: %s\n", why);
    check("hostile refusal: fails", 1, rc != 0);
    check("hostile refusal: no line break, return or tab", 1, !strpbrk(why, "\n\r\t"));
    check("hostile refusal: the text after the NUL is kept, blanked", 1, strstr(why, "a b c d e") != NULL);
    srv_free(&g_srv);
}

static void refusals_and_ends_move_to_the_second_target(void) {
    struct vless_node n;
    char why[256];
    const char *tg[4];
    for (int k = 0; k < 4; k++) {
        uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
        if (k == 0) g_srv.p.refuse_addr = "1.1.1.1:80";
        if (k == 1) g_srv.p.refuse = 1;
        if (k == 2) g_srv.p.fin_addr = "1.1.1.1:80";
        if (k == 3) g_srv.p.fin_first = 1;
        node_make(&n, "127.0.0.1", port);
        why[0] = 0;
        int rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
        srv_end(&g_srv);
        printf("     why: %s\n", why);
        int nt = targets_of(&g_srv.p, tg);
        if (k == 0) {
            check("refused first target: the second passes", 0, rc);
            check("refused first target: two targets asked", 2, nt);
        } else if (k == 1) {
            check("refused on both: fails", 1, rc != 0);
            check("refused on both: both asked", 2, nt);
            check("refused on both: why names the refusal", 1, strstr(why, "refused: connection refused") != NULL);
        } else if (k == 2) {
            check("first target ends at once: the second passes", 0, rc);
            check("first target ends at once: two targets asked", 2, nt);
        } else {
            check("both end at once: fails", 1, rc != 0);
            check("both end at once: why says ended with no data", 1, strstr(why, "ended the stream with no data") != NULL);
        }
        srv_free(&g_srv);
    }
}

static unsigned fd_count(void) {
    unsigned n = 0;
    DIR *d = opendir("/proc/self/fd");
    if (!d) return 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static void probes_leave_no_descriptors(void) {
    unsigned before = fd_count();
    struct vless_node n;
    char why[256];
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    node_make(&n, "127.0.0.1", port);
    int ok = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL) == 0;
    srv_free(&g_srv);
    port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv.p.mute[0] = "1.1.1.1:80";
    g_srv.p.mute[1] = "8.8.8.8:80";
    node_make(&n, "127.0.0.1", port);
    int muted = hy2_probe_timed(&n, 2, why, sizeof why, NULL, NULL) != 0;
    srv_free(&g_srv);
    int fd;
    port = silent_bind("127.0.0.1", 0, &fd);
    node_make(&n, "127.0.0.1", port);
    int silent = hy2_probe_timed(&n, 1, why, sizeof why, NULL, NULL) != 0;
    close(fd);
    check("descriptors: a pass, a mute and a silent probe ran", 3, ok + muted + silent);
    check("descriptors: as many open as before", (long)before, (long)fd_count());
}

static unsigned two_silent(const char *host, struct tr_ip out[ADDR_MAX]) {
    if (strcmp(host, "s.test")) return resolve(host, out);
    memset(out, 0, 2 * sizeof out[0]);
    inet_pton(AF_INET, "127.0.0.2", out[0].b);
    inet_pton(AF_INET, "127.0.0.3", out[1].b);
    return 2;
}

static void two_silent_addresses_share_one_budget(void) {
    int f1, f2;
    uint16_t port = silent_bind("127.0.0.2", 0, &f1);
    check("shared budget: both silent addresses bound", 1, port && silent_bind("127.0.0.3", port, &f2) == port);
    struct vless_node n;
    node_make(&n, "s.test", port);
    g_resolve = two_silent;
    rec_reset();
    char why[256] = "";
    uint64_t t0 = ms_now();
    int rc = hy2_probe_timed(&n, 4, why, sizeof why, NULL, NULL);
    uint64_t el = ms_now() - t0;
    g_resolve = resolve;
    close(f1);
    close(f2);
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("shared budget: fails", 1, rc != 0);
    check("shared budget: both addresses tried", 2, conns_to(port, NULL, NULL));
    check("shared budget: ends with the 4 s budget, not 3 + 3", 1, el >= 3500 && el <= 4500u * g_tx);
}

static void the_budget_counts_from_the_start_not_the_handshake(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 2000);
    g_srv.p.mute[0] = "1.1.1.1:80";
    g_srv.p.mute[1] = "8.8.8.8:80";
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    char why[256] = "";
    uint64_t t0 = ms_now();
    int rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
    uint64_t el = ms_now() - t0;
    srv_end(&g_srv);
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("slow handshake: fails on the targets", 1, rc != 0 && strstr(why, "no data") != NULL);
    check("slow handshake: within the 6 s budget", 1, el >= 5500 && el <= 6500u * g_tx);
    srv_free(&g_srv);
}

static void a_node_that_answers_keeps_the_budget(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv.p.auth_mode = HP_AUTH_SILENT;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    char why[256] = "";
    uint64_t t0 = ms_now();
    int rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
    uint64_t el = ms_now() - t0;
    srv_end(&g_srv);
    printf("     why: %s, %llu ms\n", why, (unsigned long long)el);
    check("stalled after the first flight: fails", 1, rc != 0);
    check("stalled after the first flight: by the 6 s budget, not 3 s", 1, el >= 5500 && el <= 6500u * g_tx);
    srv_free(&g_srv);
}

struct sal { struct hy2_salamander s; };

static size_t sal_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    uint8_t salt[8];
    if (os_rand_seed(salt, sizeof salt) != 0) return 0;
    return hy2_salamander_wrap(&((struct sal *)u)->s, salt, dst, src, n);
}

static size_t sal_rx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    return hy2_salamander_unwrap(&((struct sal *)u)->s, dst, src, n);
}

static void node_fields_reach_the_session(void) {
    static struct sal ps;
    hy2_salamander_init(&ps.s, "obfs-pass");
    struct qc_filter pf = { sal_tx, sal_rx, &ps, 8 };
    g_srv_filter = &pf;
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv_filter = NULL;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    snprintf(n.obfs, sizeof n.obfs, "salamander");
    n.obfs_pw = "obfs-pass";
    char why[256] = "";
    int rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
    printf("     why: %s\n", why);
    check("salamander node: the password reaches the session", 0, rc);
    srv_free(&g_srv);

    port = srv_start(&g_srv, "127.0.0.1", 0);
    node_make(&n, "127.0.0.1", port);
    snprintf(n.sni, sizeof n.sni, "other.test");
    n.vcn = "node.test";
    why[0] = 0;
    rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
    printf("     why: %s\n", why);
    check("vcn names the certificate: passes", 0, rc);
    srv_free(&g_srv);

    port = srv_start(&g_srv, "127.0.0.1", 0);
    node_make(&n, "127.0.0.1", port);
    n.vcn = "wrong.test";
    why[0] = 0;
    rc = hy2_probe_timed(&n, 6, why, sizeof why, NULL, NULL);
    printf("     why: %s\n", why);
    check("vcn names another host: fails", 1, rc != 0);
    check("vcn names another host: why says name", 1, strstr(why, "name mismatch") != NULL);
    srv_free(&g_srv);
}

static const char *hdr_value(const struct hy2peer *p, const char *name) {
    for (int i = 0; i < p->nhdr; i++)
        if (!strcmp(p->hdr[i].name, name)) return p->hdr[i].value;
    return "";
}

static void rx_header_round(const char *tag, const char *qp, unsigned down_mbps, const char *want) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    n.qp = qp;
    n.down_mbps = down_mbps;
    char why[256] = "";
    int rc = hy2_probe_timed(&n, 8, why, sizeof why, NULL, NULL);
    srv_end(&g_srv);
    char b[128];
    snprintf(b, sizeof b, "down rate %s: the probe passes", tag);
    check(b, 0, rc);
    snprintf(b, sizeof b, "down rate %s: hysteria-cc-rx", tag);
    check_str(b, want, hdr_value(&g_srv.p, "hysteria-cc-rx"));
    srv_free(&g_srv);
}

static void the_node_asks_for_its_down_rate(void) {
    rx_header_round("link", NULL, 40, "5000000");
    rx_header_round("brutalDown", "{\"brutalDown\":\"50 mbps\"}", 0, "6553600");
    rx_header_round("none", NULL, 0, "0");
}

static void window_check(const char *qp, long ms, long msw, long md, long mdw, long ign) {
    struct vless_node n;
    node_make(&n, "127.0.0.1", 4433);
    n.qp = qp;
    static struct hy2_nodecfg cfg;
    check("windows: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    char b[160];
    snprintf(b, sizeof b, "windows %s: stream window", qp ? qp : "none");
    check(b, ms, (long)cfg.c.qc.max_stream_data);
    snprintf(b, sizeof b, "windows %s: stream ceiling", qp ? qp : "none");
    check(b, msw, (long)cfg.c.qc.max_stream_win);
    snprintf(b, sizeof b, "windows %s: connection window", qp ? qp : "none");
    check(b, md, (long)cfg.c.qc.max_data);
    snprintf(b, sizeof b, "windows %s: connection ceiling", qp ? qp : "none");
    check(b, mdw, (long)cfg.c.qc.max_data_win);
    snprintf(b, sizeof b, "windows %s: ignored flags", qp ? qp : "none");
    check(b, ign, (long)cfg.qp_ignored);
}

#define NP "\"disableChromeParrot\":true,"

static void named_windows_are_honoured_and_unnamed_stay(void) {
    window_check(NULL, 2097152, 0, 12582912, 0, 0);
    window_check("{" NP "\"initStreamReceiveWindow\":1048576}", 1048576, 0, 12582912, 0, 0);
    window_check("{" NP "\"maxConnectionReceiveWindow\":67108864}", 2097152, 0, 12582912, 20971520, 0);
    window_check("{" NP "\"initStreamReceiveWindow\":16777216}", 8388608, 0, 12582912, 0, 0);
    window_check("{" NP "\"maxStreamReceiveWindow\":1048576}", 1048576, 1048576, 12582912, 0, 0);
    window_check("{" NP "\"maxIdleTimeout\":60}", 2097152, 0, 12582912, 0, 0);
    window_check("{" NP "\"debug\":true}", 2097152, 0, 12582912, 0, HY2_QP_IGN_DEBUG);
}

static void a_parroting_node_ignores_its_idle_and_windows(void) {
    window_check("{\"initStreamReceiveWindow\":1048576}", 2097152, 0, 12582912, 0, HY2_QP_IGN_CHROME);
    window_check("{\"maxConnectionReceiveWindow\":67108864}", 2097152, 0, 12582912, 0, HY2_QP_IGN_CHROME);
    window_check("{\"maxIdleTimeout\":60}", 2097152, 0, 12582912, 0, HY2_QP_IGN_CHROME);
    window_check("{\"initConnectionReceiveWindow\":8388608}", 2097152, 0, 12582912, 0, HY2_QP_IGN_CHROME);
    window_check("{" NP "\"initConnectionReceiveWindow\":8388608}", 2097152, 0, 8388608, 0, 0);
    window_check("{\"disableChromeParrot\":false,\"maxStreamReceiveWindow\":1048576}", 2097152, 0, 12582912, 0, HY2_QP_IGN_CHROME);
    window_check("{\"keepAlivePeriod\":20,\"disablePathMTUDiscovery\":true}", 2097152, 0, 12582912, 0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", 4433);
    n.qp = "{\"maxIdleTimeout\":4,\"keepAlivePeriod\":60,\"disablePathMTUDiscovery\":true}";
    static struct hy2_nodecfg cfg;
    check("parrot: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    check("parrot: idle stays the default", 0, (long)cfg.c.qc.idle_ms);
    check("parrot: keep-alive is honoured", 60000, (long)cfg.c.qc.keepalive_ms);
    check("parrot: path MTU discovery is off", 1, cfg.c.qc.no_pmtud);
    check("parrot: the idle is reported ignored", HY2_QP_IGN_CHROME, (long)cfg.qp_ignored);
}

static void cc_check(const char *qp, uint32_t up_mbps, int cc, long up, int nlc, int qcc, long unparroted) {
    struct vless_node n;
    node_make(&n, "127.0.0.1", 4433);
    n.qp = qp;
    n.up_mbps = up_mbps;
    static struct hy2_nodecfg cfg;
    char b[200];
    snprintf(b, sizeof b, "controller %s: node config", qp ? qp : "none");
    check(b, 1, hy2_nodecfg(&n, 0, &cfg));
    snprintf(b, sizeof b, "controller %s: choice", qp ? qp : "none");
    check(b, cc, cfg.c.cc);
    snprintf(b, sizeof b, "controller %s: up rate", qp ? qp : "none");
    check(b, up, (long)cfg.c.up_bps);
    snprintf(b, sizeof b, "controller %s: loss compensation off", qp ? qp : "none");
    check(b, nlc, cfg.c.no_loss_comp);
    snprintf(b, sizeof b, "controller %s: controller at open", qp ? qp : "none");
    check(b, qcc, cfg.c.qc.cc);
    snprintf(b, sizeof b, "controller %s: parrot fields named", qp ? qp : "none");
    check(b, unparroted, (long)cfg.qp_unparroted);
}

static void the_node_hands_its_controller_to_the_session(void) {
    cc_check(NULL, 0, HY2_CC_AUTO, 0, 0, QC_CC_BBR, 0);
    cc_check(NULL, 100, HY2_CC_AUTO, 12500000, 0, QC_CC_BBR, 0);
    cc_check("{\"congestion\":\"reno\",\"brutalUp\":\"100 mbps\"}", 0, HY2_CC_RENO, 13107200, 0, QC_CC_RENO, 0);
    cc_check("{\"congestion\":\"bbr\"}", 0, HY2_CC_BBR, 0, 0, QC_CC_BBR, 0);
    cc_check("{\"congestion\":\"force-brutal\",\"brutalUp\":\"50 mbps\",\"brutalDisableLossCompensation\":true}", 0,
             HY2_CC_FORCE, 6553600, 1, QC_CC_BBR, 0);
    cc_check("{\"maxConnectionReceiveWindow\":67108864,\"maxIdleTimeout\":60,\"initStreamReceiveWindow\":1048576}", 0,
             HY2_CC_AUTO, 0, 0, QC_CC_BBR, 1 | 8 | 16);
    cc_check("{" NP "\"maxIdleTimeout\":60}", 0, HY2_CC_AUTO, 0, 0, QC_CC_BBR, 0);
}

struct idle_obs { int ready, closed, reason; char why[96]; uint64_t drop_ms, closed_ms; int64_t sid; int dropped; };

static void io_ready(void *u, uint64_t rx, int udp) { (void)rx; (void)udp; ((struct idle_obs *)u)->ready = 1; }
static void io_closed(void *u, int reason, const char *why) {
    struct idle_obs *o = u;
    o->closed = 1;
    o->reason = reason;
    o->closed_ms = ms_now();
    snprintf(o->why, sizeof o->why, "%s", why ? why : "");
}

static const struct hy2c_ops g_iops = {
    .on_ready = io_ready, .on_stream_data = r_data, .on_stream_writable = r_sid, .on_streams_open = r_none,
    .on_stream_refused = r_refused, .on_stream_close = r_sclose, .on_udp = r_udp, .on_closed = io_closed,
};

struct idle_run { struct idle_obs o; struct hy2c *c; };

static int idle_step(void *u) {
    struct idle_run *r = u;
    if (r->o.closed) return 1;
    if (r->o.ready && !r->o.dropped) {
        if (hy2c_tcp_open(r->c, "1.1.1.1", 80, &r->o.sid) != 0) return 0;
        r->o.dropped = 1;
        r->o.drop_ms = ms_now();
        __atomic_store_n(&g_srv.p.drop, HP_DROP_ALL, __ATOMIC_SEQ_CST);
    }
    return 0;
}

static int quiet_step(void *u) {
    struct idle_run *r = u;
    if (r->o.closed) return 1;
    if (r->o.ready && !r->o.dropped) {
        if (hy2c_tcp_open(r->c, "1.1.1.1", 80, &r->o.sid) != 0) return 0;
        r->o.dropped = 1;
    }
    return 0;
}

static void a_long_keep_alive_is_clamped_by_the_nodes_idle(void) {
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    unsigned idle_s = 4 * g_tx < 120 ? 4 * g_tx : 120;
    static char qp[96];
    snprintf(qp, sizeof qp, "{" NP "\"maxIdleTimeout\":%u,\"keepAlivePeriod\":60}", idle_s);
    n.qp = qp;
    static struct hy2_nodecfg cfg;
    check("quiet: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    static struct idle_run r;
    memset(&r, 0, sizeof r);
    check("quiet: session opens", 0, hy2c_open(&cfg.c, &g_iops, &r.o, &r.c));
    struct hy2_run_stats st = { 0, 0 };
    if (r.c) (void)hy2_run(r.c, ns_now() + (idle_s + 2) * 1000000000ull, quiet_step, &r, &st);
    srv_end(&g_srv);
    printf("     closed %d, reason %d, why %s\n", r.o.closed, r.o.reason, r.o.why);
    check("quiet: a stream was opened", 1, r.o.dropped);
    check("quiet: the link is still open 2 s past its idle time", 0, r.o.closed);
    check("quiet: and still ready", 1, r.c && hy2c_ready(r.c));
    hy2c_free(r.c);
    srv_free(&g_srv);
}

static void idle_and_keepalive_follow_quic_params(void) {
    struct vless_node n;
    node_make(&n, "127.0.0.1", 4433);
    static struct hy2_nodecfg cfg;
    check("idle: no qp, node config", 1, hy2_nodecfg(&n, 0, &cfg));
    check("idle: no qp, idle left to the default", 0, (long)cfg.c.qc.idle_ms);
    check("idle: no qp, keep-alive 10 s", 10000, (long)cfg.c.qc.keepalive_ms);
    n.qp = "{" NP "\"maxIdleTimeout\":4,\"keepAlivePeriod\":60}";
    check("idle: qp, node config", 1, hy2_nodecfg(&n, 0, &cfg));
    check("idle: qp, idle 4 s", 4000, (long)cfg.c.qc.idle_ms);
    check("idle: qp, keep-alive 60 s", 60000, (long)cfg.c.qc.keepalive_ms);

    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    node_make(&n, "127.0.0.1", port);
    n.qp = "{" NP "\"maxIdleTimeout\":4,\"keepAlivePeriod\":60}";
    check("idle: node config for the peer", 1, hy2_nodecfg(&n, 0, &cfg));
    static struct idle_run r;
    memset(&r, 0, sizeof r);
    check("idle: session opens", 0, hy2c_open(&cfg.c, &g_iops, &r.o, &r.c));
    struct hy2_run_stats st = { 0, 0 };
    if (r.c) (void)hy2_run(r.c, ns_now() + 14000000000ull * g_tx, idle_step, &r, &st);
    srv_end(&g_srv);
    long el = r.o.closed ? (long)(r.o.closed_ms - r.o.drop_ms) : -1;
    printf("     closed %d, reason %d, why %s, %ld ms after the drop\n", r.o.closed, r.o.reason, r.o.why, el);
    check("idle: a stream was open when the peer went quiet", 1, r.o.dropped);
    check("idle: the link closed", 1, r.o.closed);
    check("idle: closed as a link error", QC_CLOSE_ERROR, r.o.reason);
    check_str("idle: said as a silent node", "the node stopped answering", r.o.why);
    check("idle: after 3900 ms and within 6000 x g_tx", 1, el >= 3900 && el <= 6000 * (long)g_tx);
    hy2c_free(r.c);
    srv_free(&g_srv);
}

static int certs_make(void) {
    struct tcg_key *k1 = tcg_key_new(), *kl = tcg_key_new();
    int rc = -1;
    if (!k1 || !kl) goto out;
    if (tcg_issue(k1, "Test CA One", NULL, 1, NULL, NULL, 0, g_ca, sizeof g_ca, &g_ca_n) != 0) goto out;
    if (tcg_issue(kl, "node.test", NULL, 0, k1, g_ca, g_ca_n, g_leaf, sizeof g_leaf, &g_leaf_n) != 0) goto out;
    if (tcg_key_der(kl, g_key, sizeof g_key, &g_key_n) != 0) goto out;
    if (tcg_der_to_pem(g_ca, g_ca_n, g_ca_pem, sizeof g_ca_pem) != 0) goto out;
    snprintf(g_roots, sizeof g_roots, "%s", "/tmp/hy2checkmatch-roots-XXXXXX");
    int fd = mkstemp(g_roots);
    if (fd < 0) goto out;
    size_t len = strlen(g_ca_pem);
    rc = write(fd, g_ca_pem, len) == (ssize_t)len ? 0 : -1;
    close(fd);
out:
    tcg_key_free(k1);
    tcg_key_free(kl);
    return rc;
}

static uint32_t g_os_value;
static unsigned g_os_calls;
static int g_os_on;
int __real_os_rand_seed(unsigned char *out, unsigned int n);

int __wrap_os_rand_seed(unsigned char *out, unsigned int n) {
    if (!g_os_on) return __real_os_rand_seed(out, n);
    g_os_calls++;
    memset(out, 0, n);
    memcpy(out, &g_os_value, n < sizeof g_os_value ? n : sizeof g_os_value);
    return 0;
}

static uint32_t g_seq[8];
static unsigned g_seq_n;

static uint32_t seq_rand(void) {
    return g_seq[g_seq_n++ % 8];
}

static unsigned dial_port(const struct vless_node *n, uint32_t x) {
    static struct hy2_nodecfg cfg;
    g_seq[0] = x;
    g_seq_n = 0;
    return hy2_nodecfg(n, 0, &cfg) == 1 ? cfg.c.qc.port : 0;
}

static void a_port_list_starts_on_a_random_port(void) {
    uint32_t (*saved)(void) = g_hy2_rand;
    g_hy2_rand = seq_rand;
    struct vless_node n;
    check("random port: link parses", 0, vless_parse_url("hysteria2://pw@203.0.113.9:443,20000-20002/?sni=s", &n));
    static const unsigned want[] = { 443, 20000, 20001, 20002, 443 };
    for (unsigned x = 0; x < 5; x++) {
        char b[64];
        snprintf(b, sizeof b, "a_port_list_starts_on_a_random_port: x %u", x);
        check(b, want[x], dial_port(&n, x));
    }
    check("random port: the largest value stays inside the list", 20002, dial_port(&n, 0xffffffffu));

    struct vless_node x[2];
    memset(x, 0, sizeof x);
    static const char *const body =
        "{\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"x\",\"settings\":{\"version\":2,\"address\":\"203.0.113.9\","
        "\"port\":443},\"streamSettings\":{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":"
        "{\"serverName\":\"s.example\"},\"hysteriaSettings\":{\"version\":2,\"auth\":\"pw\"},\"finalmask\":{\"udp\":"
        "[{\"type\":\"udphop\",\"settings\":{\"mode\":\"%s\",\"remotePorts\":\"%s\"}}]}}}]}";
    static const struct { const char *mode, *ports; unsigned x, want; } xr[] = {
        { "intervalRemote", "20000-20010", 5, 20005 },
        { "intervalRemote", "20000-20010", 11, 20000 },
        { "perConnRemote", "20000-20010", 6, 20006 },
        { "intervalLocal,intervalRemote", "20000-20010", 1, 20001 },
        { "intervalLocal", "20000-20010", 5, 443 },
        { "IntervalLocal", "20000-20010", 0, 443 },
        { "intervalRemote", "5000", 3, 5000 },
        { "intervalLocal", "5000", 3, 443 },
        { "intervalRemote", "", 3, 443 },
        { "intervalRemote", "443,20000-20002", 3, 20002 },
    };
    for (size_t i = 0; i < sizeof xr / sizeof *xr; i++) {
        char js[900], b[96];
        snprintf(js, sizeof js, body, xr[i].mode, xr[i].ports);
        memset(x, 0, sizeof x);
        size_t got = vless_parse_sub(js, x, 2, NULL);
        snprintf(b, sizeof b, "xray_hop_modes_are_kept: %s %s parsed", xr[i].mode, xr[i].ports);
        check(b, 1, (long)got);
        if (!got) continue;
        snprintf(b, sizeof b, "xray_hop_modes_are_kept: %s %s x %u dials", xr[i].mode, xr[i].ports, xr[i].x);
        check(b, xr[i].want, dial_port(&x[0], xr[i].x));
    }

    check("random port: a mode without a remote hop dials the first listed port",
          0, vless_parse_url("hysteria2://pw@203.0.113.9:443,20000-20002/?sni=s&hopmode=local", &n));
    check("random port: local only, x 3", 443, dial_port(&n, 3));
    check("random port: once picks too", 0, vless_parse_url("hysteria2://pw@203.0.113.9:443,20000-20002/?sni=s&hopmode=once", &n));
    check("random port: once, x 3", 20002, dial_port(&n, 3));
    check("random port: no list", 0, vless_parse_url("hysteria2://pw@203.0.113.9:443/?sni=s", &n));
    check("random port: no list, x 3", 443, dial_port(&n, 3));
    g_hy2_rand = saved;
}

static void the_production_random_source_picks_the_port(void) {
    struct vless_node n;
    check("production random: link parses", 0, vless_parse_url("hysteria2://pw@203.0.113.9:443,20000-20002/?sni=s", &n));
    static const struct { uint32_t v; unsigned want; } rows[] = { { 3, 20002 }, { 1, 20000 }, { 0, 443 }, { 6, 20001 } };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        static struct hy2_nodecfg cfg;
        char b[80];
        g_os_value = rows[i].v;
        g_os_calls = 0;
        g_os_on = 1;
        int rc = hy2_nodecfg(&n, 0, &cfg);
        g_os_on = 0;
        snprintf(b, sizeof b, "the_production_random_source_picks_the_port: value %u", (unsigned)rows[i].v);
        check(b, rows[i].want, rc == 1 ? cfg.c.qc.port : 0);
        snprintf(b, sizeof b, "the_production_random_source_picks_the_port: value %u asked once", (unsigned)rows[i].v);
        check(b, 1, g_os_calls);
    }
    check("production random: no list asks nothing", 0, vless_parse_url("hysteria2://pw@203.0.113.9:443/?sni=s", &n));
    static struct hy2_nodecfg cfg;
    g_os_calls = 0;
    g_os_on = 1;
    hy2_nodecfg(&n, 0, &cfg);
    g_os_on = 0;
    check("production random: no list asks nothing: calls", 0, g_os_calls);
}

static uint32_t g_sc[4];
static unsigned g_sc_n;

static uint32_t sc_rand(void) {
    return g_sc[g_sc_n++ % 4];
}

static void hop_node(struct vless_node *n, uint16_t port, const char *ports, unsigned mode, unsigned from, unsigned to) {
    node_make(n, "127.0.0.1", port);
    snprintf(n->ports, sizeof n->ports, "%s", ports);
    n->hop_mode = (uint8_t)mode;
    n->hop_from = (uint16_t)from;
    n->hop_to = (uint16_t)to;
}

static void a_hopping_node_hands_its_hops_to_the_session(void) {
    uint32_t (*saved)(void) = g_hy2_rand;
    g_hy2_rand = sc_rand;
    static struct hy2_nodecfg cfg;
    struct vless_node n;
    hop_node(&n, 4433, "20000-20002,443", HY2_HOP_LOCAL | HY2_HOP_REMOTE, 7, 9);
    g_sc[0] = 0;
    g_sc_n = 0;
    check("hop config: both modes: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    const struct qc_cfg *q = &cfg.c.qc;
    check("hop config: both modes: the mode", QC_HOP_LOCAL | QC_HOP_REMOTE, (long)q->hop_mode);
    check("hop config: both modes: the interval", 1, q->hop_min_s == 7 && q->hop_max_s == 9);
    check("hop config: both modes: two ranges", 2, (long)q->hop_n);
    check("hop config: both modes: the first range", 1, q->hop_ports[0].lo == 20000 && q->hop_ports[0].hi == 20002);
    check("hop config: both modes: the second range", 1, q->hop_ports[1].lo == 443 && q->hop_ports[1].hi == 443);
    check("hop config: both modes: the random source is the node's", 1, q->rand32 == sc_rand);
    check("hop config: both modes: the first port is the pick", 20000, q->port);

    hop_node(&n, 4433, "20000-20002", HY2_HOP_REMOTE, 0, 0);
    check("hop config: remote: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    check("hop config: remote: the mode", QC_HOP_REMOTE, (long)cfg.c.qc.hop_mode);
    check("hop config: remote: 0-0 stays for the session to read", 1, cfg.c.qc.hop_min_s == 0 && cfg.c.qc.hop_max_s == 0);

    hop_node(&n, 4433, "", HY2_HOP_LOCAL, 5, 6);
    check("hop config: local: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    check("hop config: local: the mode", QC_HOP_LOCAL, (long)cfg.c.qc.hop_mode);
    check("hop config: local: no ports", 0, (long)cfg.c.qc.hop_n);

    hop_node(&n, 4433, "20000-20002", HY2_HOP_ONCE, 5, 6);
    check("hop config: once: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    check("hop config: once: no hop timer", 1, cfg.c.qc.hop_mode == 0 && cfg.c.qc.hop_n == 0);
    check("hop config: once: no interval or source handed over", 1,
          cfg.c.qc.hop_min_s == 0 && cfg.c.qc.hop_max_s == 0 && cfg.c.qc.rand32 == NULL);

    hop_node(&n, 4433, "20000-20002", HY2_HOP_IPS, 5, 6);
    check("hop config: remoteIPs alone: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    check("hop config: remoteIPs alone: no hop mode, no ports", 1, cfg.c.qc.hop_mode == 0 && cfg.c.qc.hop_n == 0);
    check("hop config: remoteIPs alone: no interval or source handed over", 1,
          cfg.c.qc.hop_min_s == 0 && cfg.c.qc.hop_max_s == 0 && cfg.c.qc.rand32 == NULL);
    check("hop config: remoteIPs alone: the node's own port", 4433, cfg.c.qc.port);

    node_make(&n, "127.0.0.1", 4433);
    check("hop config: no hops: node config", 1, hy2_nodecfg(&n, 0, &cfg));
    check("hop config: no hops: nothing set", 1,
          cfg.c.qc.hop_mode == 0 && cfg.c.qc.hop_n == 0 && cfg.c.qc.hop_min_s == 0 && cfg.c.qc.hop_max_s == 0 &&
          cfg.c.qc.rand32 == NULL);
    g_hy2_rand = saved;
}

static void the_probe_never_hops_and_asks_the_down_rate(void) {
    uint32_t (*saved)(void) = g_hy2_rand;
    g_hy2_rand = sc_rand;
    uint16_t port = srv_start(&g_srv, "127.0.0.1", 0);
    g_srv.p.mute[0] = "1.1.1.1:80";
    g_srv.p.mute[1] = "8.8.8.8:80";
    struct vless_node n;
    char ports[64];
    snprintf(ports, sizeof ports, "%u,%u", 5001, port);
    hop_node(&n, 4433, ports, HY2_HOP_LOCAL | HY2_HOP_REMOTE, 5, 5);
    n.down_mbps = 40;
    g_sc[0] = 1;
    g_sc_n = 0;
    rec_reset();
    char why[256] = "";
    int rc = hy2_probe_timed(&n, 4, why, sizeof why, NULL, NULL);
    srv_end(&g_srv);
    printf("     why: %s\n", why);
    check("probe hops: the probe fails on a target that answers nothing", 1, rc != 0);
    check("probe hops: why says the node relayed no data", 1,
          strstr(why, "the node relayed no data from 8.8.8.8") != NULL);
    check("probe hops: one session opened", 1, (long)g_qo_calls);
    check("probe hops: no hop mode", 0, (long)g_qo.hop_mode);
    check("probe hops: the picked port", port, g_qo.port);
    check("probe hops: one random draw, the port's", 1, (long)g_sc_n);
    check_str("probe hops: the down rate is asked", "5000000", hdr_value(&g_srv.p, "hysteria-cc-rx"));
    srv_free(&g_srv);
    g_hy2_rand = saved;
}

static void budget_check(const char *tag, uint64_t mib, long total, long buf, long span) {
    struct vless_node n;
    node_make(&n, "127.0.0.1", 4433);
    static struct hy2_nodecfg cfg;
    char b[120];
    hy2_budget_set(mib << 20);
    snprintf(b, sizeof b, "budgets %s: node config", tag);
    check(b, 1, hy2_nodecfg(&n, 0, &cfg));
    snprintf(b, sizeof b, "budgets %s: per connection", tag);
    check(b, total, (long)cfg.c.qc.send_total);
    snprintf(b, sizeof b, "budgets %s: per stream", tag);
    check(b, buf, (long)cfg.c.qc.send_buf);
    snprintf(b, sizeof b, "budgets %s: Brutal's stream ceiling", tag);
    check(b, span, (long)cfg.c.qc.brutal_span);
}

static void meminfo_round(const char *tag, const char *text, const char *want) {
    char path[64], line[200], b[120];
    snprintf(path, sizeof path, "%s", "/tmp/hy2checkmatch-meminfo-XXXXXX");
    int fd = mkstemp(path);
    size_t len = strlen(text);
    int ok = fd >= 0 && write(fd, text, len) == (ssize_t)len;
    if (fd >= 0) close(fd);
    snprintf(b, sizeof b, "meminfo %s: written", tag);
    check(b, 1, ok);
    hy2_budget_init(path, line, sizeof line);
    unlink(path);
    snprintf(b, sizeof b, "meminfo %s: the line", tag);
    check_str(b, want, line);
}

static void the_budgets_read_the_machines_memory(void) {
    meminfo_round("256 MB router",
                  "MemTotal:         250844 kB\nMemFree:           31416 kB\nMemAvailable:      91224 kB\n",
                  "Hysteria2 send budgets: 8 MiB per link, 2 MiB per stream, Brutal up to 4 MiB per stream and 8 MiB "
                  "per link (memory 244 MiB)");
    meminfo_round("1 GB router",
                  "MemTotal:        1015232 kB\nMemFree:          612340 kB\n",
                  "Hysteria2 send budgets: 16 MiB per link, 2 MiB per stream, Brutal up to 16 MiB per stream and 32 MiB "
                  "per link (memory 991 MiB)");
    meminfo_round("no MemTotal line", "MemFree:          612340 kB\n",
                  "Hysteria2 send budgets: 8 MiB per link, 2 MiB per stream, Brutal up to 4 MiB per stream and 8 MiB "
                  "per link (memory size unknown, the small tier)");
    char line[200];
    hy2_budget_init("/nonexistent/meminfo", line, sizeof line);
    check_str("meminfo unreadable: the line",
              "Hysteria2 send budgets: 8 MiB per link, 2 MiB per stream, Brutal up to 4 MiB per stream and 8 MiB "
              "per link (memory size unknown, the small tier)", line);
    check("meminfo unreadable: the small tier", 8L << 20, (long)g_hy2_budget.send_total);
    hy2_budget_set(384ull << 20);
}

static void the_send_budgets_follow_the_memory(void) {
    budget_check("245 MiB", 245, 8L << 20, 2L << 20, 4L << 20);
    budget_check("383 MiB", 383, 8L << 20, 2L << 20, 4L << 20);
    budget_check("384 MiB", 384, 16L << 20, 2L << 20, 16L << 20);
    budget_check("1024 MiB", 1024, 16L << 20, 2L << 20, 16L << 20);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *tx = getenv("QC_TEST_TIME_X");
    if (tx && atoi(tx) > 0) g_tx = (unsigned)atoi(tx);
    for (size_t i = 0; i < sizeof g_pat; i++) g_pat[i] = (uint8_t)((i * 31 + 7) % 251);
    check("certificates issued", 0, certs_make());
    no_ca_bundle_still_gives_a_context();
    tls_set_cert_roots(g_roots);
    a_probe_passes_on_the_targets_first_byte_and_measures();
    an_ok_without_data_is_not_a_pass();
    a_wrong_password_fails_fast_with_the_status();
    probe6_needs_the_targets_answer();
    a_probe_that_cannot_watch_its_socket_says_so();
    a_silent_node_fails_by_the_budget();
    addresses_are_tried_in_turn();
    run_returns_the_step_value_or_the_deadline();
    one_tls_context_per_process();
    a_refusal_text_cannot_break_the_line();
    refusals_and_ends_move_to_the_second_target();
    probes_leave_no_descriptors();
    two_silent_addresses_share_one_budget();
    the_budget_counts_from_the_start_not_the_handshake();
    a_node_that_answers_keeps_the_budget();
    node_fields_reach_the_session();
    the_node_asks_for_its_down_rate();
    named_windows_are_honoured_and_unnamed_stay();
    the_node_hands_its_controller_to_the_session();
    a_parroting_node_ignores_its_idle_and_windows();
    idle_and_keepalive_follow_quic_params();
    a_long_keep_alive_is_clamped_by_the_nodes_idle();
    a_port_list_starts_on_a_random_port();
    the_production_random_source_picks_the_port();
    a_hopping_node_hands_its_hops_to_the_session();
    the_probe_never_hops_and_asks_the_down_rate();
    the_send_budgets_follow_the_memory();
    the_budgets_read_the_machines_memory();
    if (g_roots[0]) unlink(g_roots);
    return unit_done("hy2checkmatch");
}
