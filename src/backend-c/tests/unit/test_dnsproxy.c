#include "greatest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#include "firc/dnsproxy.h"
#include "firc/anscache.h"
#include "firc/events.h"
#include "firc/dnswire.h"
#include "firc/fakeip.h"
#include "firc/log.h"
#include "firc/loop.h"

static bool bind_loopback(int fd, uint16_t port, uint16_t *got) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { return false; }
    if (got != NULL) {
        socklen_t l = sizeof(a);
        if (getsockname(fd, (struct sockaddr *)&a, &l) != 0) { return false; }
        *got = ntohs(a.sin_port);
    }
    return true;
}

/* Probes UDP and TCP, holding both ports open until both are known, or the proxy may get the stub's port. */
static bool free_ports(uint16_t *a_out, uint16_t *b_out) {
    int ua = socket(AF_INET, SOCK_DGRAM, 0);
    int ub = socket(AF_INET, SOCK_DGRAM, 0);
    int ta = socket(AF_INET, SOCK_STREAM, 0);
    int tb = socket(AF_INET, SOCK_STREAM, 0);
    bool ok = ua >= 0 && ub >= 0 && ta >= 0 && tb >= 0 && bind_loopback(ua, 0, a_out) &&
              bind_loopback(ub, 0, b_out) && bind_loopback(ta, *a_out, NULL) &&
              bind_loopback(tb, *b_out, NULL);
    if (ua >= 0) { close(ua); }
    if (ub >= 0) { close(ub); }
    if (ta >= 0) { close(ta); }
    if (tb >= 0) { close(tb); }
    return ok;
}

static size_t build_query_for(uint8_t *buf, uint16_t id, uint16_t edns_size, char first) {
    size_t p = 0;
    buf[p++] = (uint8_t)(id >> 8);
    buf[p++] = (uint8_t)id;
    buf[p++] = 0x01;
    buf[p++] = 0x00;
    buf[p++] = 0x00; buf[p++] = 0x01;
    buf[p++] = 0x00; buf[p++] = 0x00;
    buf[p++] = 0x00; buf[p++] = 0x00;
    buf[p++] = 0x00; buf[p++] = edns_size ? 0x01 : 0x00;
    const char first_label[2] = {first, '\0'};
    const char *labels[] = {first_label, "example", "com"};
    for (size_t i = 0; i < 3; i++) {
        size_t l = strlen(labels[i]);
        buf[p++] = (uint8_t)l;
        memcpy(buf + p, labels[i], l);
        p += l;
    }
    buf[p++] = 0;
    buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_A;
    buf[p++] = 0x00; buf[p++] = 0x01;
    if (edns_size) {
        buf[p++] = 0;
        buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_OPT;
        buf[p++] = (uint8_t)(edns_size >> 8); buf[p++] = (uint8_t)edns_size;
        buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 0;
        buf[p++] = 0; buf[p++] = 0;
    }
    return p;
}

/* A query for a.example.com IN A, with an OPT record advertising `edns_size` when it is not 0. */
static size_t build_query(uint8_t *buf, uint16_t id, uint16_t edns_size) {
    return build_query_for(buf, id, edns_size, 'a');
}

static size_t build_ptr_query(uint8_t *buf, uint16_t id, const firc_ip_t *ip, bool edns) {
    size_t p = 0;
    const uint8_t head[12] = {(uint8_t)(id >> 8), (uint8_t)id, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, edns ? 1 : 0};
    memcpy(buf, head, sizeof(head));
    p = sizeof(head);
    static const char hex[] = "0123456789abcdef";
    for (int i = ip->len - 1; i >= 0; i--) {
        if (ip->len == 4) {
            int n = snprintf((char *)buf + p + 1, 4, "%u", ip->b[i]);
            buf[p] = (uint8_t)n;
            p += 1 + (size_t)n;
            continue;
        }
        buf[p++] = 1;
        buf[p++] = (uint8_t)hex[ip->b[i] & 0x0f];
        buf[p++] = 1;
        buf[p++] = (uint8_t)hex[ip->b[i] >> 4];
    }
    const char *zone = ip->len == 4 ? "\007in-addr\004arpa" : "\003ip6\004arpa";
    size_t zl = strlen(zone) + 1;
    memcpy(buf + p, zone, zl);
    p += zl;
    buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_PTR;
    buf[p++] = 0x00; buf[p++] = 0x01;
    if (edns) {
        const uint8_t opt[11] = {0, 0, FIRC_DNS_TYPE_OPT, 0x04, 0xd0, 0, 0, 0, 0, 0, 0};
        memcpy(buf + p, opt, sizeof(opt));
        p += sizeof(opt);
    }
    return p;
}

#define BIG_A_OVER_512 40
static unsigned g_big_a;
static unsigned g_big_aaaa;
static bool g_padded_opt;
#define STUB_BUF 2048

static _Atomic int g_tcp_bad_len_once;
static _Atomic int g_tcp_sink_a_once;
static _Atomic int g_tcp_wrong_id_once;

/* The query echoed back as an answer with one A record, 10.1.2.3, and no OPT record. */
static size_t build_answer(const uint8_t *q, size_t qlen, uint8_t *buf) {
    size_t qd_end = 12;
    while (q[qd_end] != 0) { qd_end += 1 + q[qd_end]; }
    qd_end += 1 + 4;
    memcpy(buf, q, qd_end);
    buf[2] = 0x81;
    buf[3] = 0x80;
    buf[10] = 0; buf[11] = 0;
    qlen = qd_end;
    if (g_big_a) {
        buf[6] = 0x00; buf[7] = (uint8_t)(g_big_a + g_big_aaaa);
        size_t p = qlen;
        for (unsigned i = 0; i < g_big_a; i++) {
            buf[p++] = 0xc0; buf[p++] = 0x0c;
            buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_A;
            buf[p++] = 0x00; buf[p++] = 0x01;
            buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x01; buf[p++] = 0x2c;
            buf[p++] = 0x00; buf[p++] = 0x04;
            buf[p++] = 10; buf[p++] = 1; buf[p++] = 2; buf[p++] = (uint8_t)(3 + i);
        }
        for (unsigned i = 0; i < g_big_aaaa; i++) {
            buf[p++] = 0xc0; buf[p++] = 0x0c;
            buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_AAAA;
            buf[p++] = 0x00; buf[p++] = 0x01;
            buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x01; buf[p++] = 0x2c;
            buf[p++] = 0x00; buf[p++] = 0x10;
            buf[p++] = 0x20; buf[p++] = 0x01; buf[p++] = 0x0d; buf[p++] = 0xb8;
            for (int k = 0; k < 11; k++) { buf[p++] = 0; }
            buf[p++] = (uint8_t)(1 + i);
        }
        if (g_padded_opt) {
            buf[10] = 0; buf[11] = 1;
            buf[p++] = 0;
            buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_OPT;
            buf[p++] = 0x10; buf[p++] = 0x00;
            buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 0;
            buf[p++] = 0x01; buf[p++] = 0xe4;
            buf[p++] = 0x00; buf[p++] = 12;
            buf[p++] = 0x01; buf[p++] = 0xe0;
            memset(buf + p, 0, 480);
            p += 480;
        }
        return p;
    }
    buf[6] = 0x00; buf[7] = 0x02;
    size_t p = qlen;
    buf[p++] = 0xc0; buf[p++] = 0x0c;
    buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_A;
    buf[p++] = 0x00; buf[p++] = 0x01;
    buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x01; buf[p++] = 0x2c;
    buf[p++] = 0x00; buf[p++] = 0x04;
    buf[p++] = 10; buf[p++] = 1; buf[p++] = 2; buf[p++] = 3;

    memcpy(buf + p, q + 12, qd_end - 4 - 12);
    p += qd_end - 4 - 12;
    buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_AAAA;
    buf[p++] = 0x00; buf[p++] = 0x01;
    buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x01; buf[p++] = 0x2c;
    buf[p++] = 0x00; buf[p++] = 0x10;
    buf[p++] = 0x20; buf[p++] = 0x01; buf[p++] = 0x0d; buf[p++] = 0xb8;
    for (int i = 0; i < 11; i++) { buf[p++] = 0; }
    buf[p++] = 0x01;
    return p;
}

typedef struct {
    firc_loop_t *loop;
    int upstream_fd;
    int upstream_tcp_fd;
    bool rewrite;
    bool report;
    bool hold;
    bool retime;
    int hook_calls;
    bool saw_client;
    uint8_t last_client[4];
} fixture_t;

/* Stands in for the pipeline: rewrites the answer's address. */
static firc_dns_verdict_t hook(firc_dns_msg_t *msg, const firc_ip_t *client, const char *network,
                               firc_dns_resolver_t resolver, void *ud) {
    fixture_t *fx = (fixture_t *)ud;
    (void)network;
    (void)resolver;
    fx->hook_calls++;
    if (client != NULL && client->len == 4) {
        memcpy(fx->last_client, client->b, 4);
        fx->saw_client = true;
    }
    if (fx->retime) {
        for (size_t i = 0; i < msg->n_answers; i++) {
            if (msg->answers[i].rtype == FIRC_DNS_TYPE_A ||
                msg->answers[i].rtype == FIRC_DNS_TYPE_AAAA) {
                msg->answers[i].ttl = 60;
            }
        }
        return FIRC_DNS_RETIMED;
    }
    if (!fx->rewrite) { return FIRC_DNS_PASS; }
    for (size_t i = 0; i < msg->n_answers; i++) {
        if (msg->answers[i].rtype == FIRC_DNS_TYPE_A && msg->answers[i].rdata_len == 4) {
            msg->answers[i].rdata[0] = 198;
            msg->answers[i].rdata[1] = 18;
            msg->answers[i].rdata[2] = 0;
            msg->answers[i].rdata[3] = 7;
        }
    }
    if (!fx->report) { return FIRC_DNS_PASS; }
    return fx->hold ? FIRC_DNS_HOLD : FIRC_DNS_REWRITTEN;
}

typedef struct {
    _Atomic int opens, marks, connects, sends;
    _Atomic uint32_t last_mark;
    _Atomic int fail_open, fail_open_next, fail_mark, fail_connect, fail_send;
    _Atomic int marked_fd;
    _Atomic int connects_marked;
} rec_t;

static rec_t g_rec;

static void rec_reset(void) {
    memset(&g_rec, 0, sizeof(g_rec));
    atomic_store(&g_rec.marked_fd, -1);
}

static int rec_open(void *ud, int family, int type) {
    rec_t *r = ud;
    atomic_fetch_add(&r->opens, 1);
    int e = atomic_exchange(&r->fail_open_next, 0);
    if (e == 0) { e = atomic_load(&r->fail_open); }
    if (e != 0) {
        errno = e;
        return -1;
    }
    int fd = firc_dnsproxy_sock_ops_real.open(NULL, family, type);
    int was = fd;
    if (fd >= 0) { atomic_compare_exchange_strong(&r->marked_fd, &was, -1); }
    return fd;
}

static int rec_mark(void *ud, int fd, uint32_t mark) {
    rec_t *r = ud;
    atomic_fetch_add(&r->marks, 1);
    atomic_store(&r->last_mark, mark);
    atomic_store(&r->marked_fd, fd);
    int e = atomic_load(&r->fail_mark);
    if (e != 0) {
        errno = e;
        return -1;
    }
    return 0;
}

static int rec_connect(void *ud, int fd, const struct sockaddr *sa, socklen_t len) {
    rec_t *r = ud;
    atomic_fetch_add(&r->connects, 1);
    bool marked = fd == atomic_load(&r->marked_fd);
    if (marked) { atomic_fetch_add(&r->connects_marked, 1); }
    int e = marked ? atomic_load(&r->fail_connect) : 0;
    if (e != 0) {
        errno = e;
        return -1;
    }
    return firc_dnsproxy_sock_ops_real.connect(NULL, fd, sa, len);
}

static ssize_t rec_send(void *ud, int fd, const void *buf, size_t len, int flags) {
    rec_t *r = ud;
    atomic_fetch_add(&r->sends, 1);
    int e = fd == atomic_load(&r->marked_fd) ? atomic_load(&r->fail_send) : 0;
    if (e != 0) {
        errno = e;
        return -1;
    }
    return firc_dnsproxy_sock_ops_real.send(NULL, fd, buf, len, flags);
}

static const firc_dnsproxy_sock_ops_t REC_OPS = {
    .open = rec_open, .set_mark = rec_mark, .connect = rec_connect, .send = rec_send, .ud = &g_rec,
};

static const firc_dnsproxy_sock_ops_t *g_live_ops;

typedef struct {
    bool take;
    uint32_t mark;
    uint16_t ports[4];
    size_t n;
    uint64_t gen;
    uint8_t group;
    _Atomic int asked;
    _Atomic int saw_client;
} troute_t;

static troute_t g_troute;

static bool test_route(void *ud, const firc_dns_msg_t *q, const firc_ip_t *client, firc_dnsproxy_route_t *out) {
    troute_t *t = ud;
    (void)q;
    atomic_fetch_add(&t->asked, 1);
    if (client != NULL && client->len == 4 && client->b[0] == 127 && client->b[3] == 1) {
        atomic_store(&t->saw_client, 1);
    }
    if (!t->take) { return false; }
    memset(out, 0, sizeof(*out));
    out->group_id.b[3] = t->group ? t->group : 7;
    out->mark = t->mark;
    out->gen = t->gen != 0 ? t->gen : 1;
    out->n_servers = t->n;
    for (size_t i = 0; i < t->n; i++) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&out->servers[i];
        s4->sin_family = AF_INET;
        s4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        s4->sin_port = htons(t->ports[i]);
        out->server_lens[i] = sizeof(*s4);
    }
    return true;
}

static troute_t *g_live_route;
static uint32_t g_live_timeout_ms;
static uint32_t g_live_max_concurrent;
static uint32_t g_live_rest_ms;

static long ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* A free loopback UDP port outside the ephemeral range, so no socket of the test can be handed it. */
static uint16_t closed_udp_port(void) {
    unsigned lo = 32768, hi = 60999;
    FILE *f = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
    if (f != NULL) {
        if (fscanf(f, "%u %u", &lo, &hi) != 2) { lo = 32768, hi = 60999; }
        fclose(f);
    }
    for (unsigned cand = hi >= 65535 ? 1024 : hi + 1; cand != lo; cand = cand >= 65535 ? 1024 : cand + 1) {
        if (cand >= lo && cand <= hi) { continue; }
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { return 0; }
        bool ok = bind_loopback(fd, (uint16_t)cand, NULL);
        close(fd);
        if (ok) { return (uint16_t)cand; }
    }
    return 0;
}

/* The in-flight count once it settles to `want` (or 500 ms pass): the slot returns after the reply. */
static uint64_t inflight_settled(const firc_dnsproxy_t *p, uint64_t want) {
    for (int i = 0; i < 100 && firc_dnsproxy_inflight(p) != want; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return firc_dnsproxy_inflight(p);
}

/* The UDP stub upstream: one query in, one canned answer out, on the loop. */
static void on_upstream_query(firc_loop_t *loop, int fd, uint32_t events, void *ud) {
    (void)loop;
    (void)events;
    (void)ud;
    uint8_t q[512], a[STUB_BUF];
    struct sockaddr_storage from;
    socklen_t fl = sizeof(from);
    ssize_t n = recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
    if (n <= 0) { return; }
    size_t alen = build_answer(q, (size_t)n, a);
    sendto(fd, a, alen, 0, (struct sockaddr *)&from, fl);
}

/* The TCP stub runs on its own thread: on the loop it would block the proxy's send and deadlock. */
static void *serve_upstream_tcp(void *arg) {
    int c = (int)(intptr_t)arg;
    uint8_t hdr[2];
    if (recv(c, hdr, 2, MSG_WAITALL) != 2) {
        close(c);
        return NULL;
    }
    size_t qlen = ((size_t)hdr[0] << 8) | hdr[1];
    uint8_t q[512], a[STUB_BUF];
    if (qlen > sizeof(q) || recv(c, q, qlen, MSG_WAITALL) != (ssize_t)qlen) {
        close(c);
        return NULL;
    }
    if (atomic_exchange(&g_tcp_bad_len_once, 0)) {
        uint8_t bad[2] = {0, 0};
        send(c, bad, sizeof(bad), 0);
        close(c);
        return NULL;
    }
    size_t alen = build_answer(q, qlen, a);
    if (atomic_exchange(&g_tcp_sink_a_once, 0)) {
        a[43] = 0; a[44] = 0; a[45] = 0; a[46] = 0;
    }
    if (atomic_exchange(&g_tcp_wrong_id_once, 0)) {
        a[0] ^= 0xff;
        a[1] ^= 0xff;
    }
    uint8_t framed[STUB_BUF + 2];
    framed[0] = (uint8_t)(alen >> 8);
    framed[1] = (uint8_t)alen;
    memcpy(framed + 2, a, alen);
    send(c, framed, alen + 2, 0);
    close(c);
    return NULL;
}

static void on_upstream_accept(firc_loop_t *loop, int fd, uint32_t events, void *ud) {
    (void)loop;
    (void)events;
    (void)ud;
    int c = accept(fd, NULL, NULL);
    if (c < 0) { return; }
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    pthread_t th;
    if (pthread_create(&th, NULL, serve_upstream_tcp, (void *)(intptr_t)c) != 0) {
        close(c);
        return;
    }
    pthread_detach(th);
}

static void *loop_thread(void *ud) {
    firc_loop_run((firc_loop_t *)ud);
    return NULL;
}

typedef struct {
    uint8_t a[4];
    bool saw_a, saw_aaaa;
    uint32_t aaaa_ttl;
    bool tc;
    bool has_opt;
    long waited_ms;
    bool arrived_before_release;
    bool second_replied;
    bool saw_client;
    uint8_t client[4];
    bool second_before_release;
    size_t held_at_end;
    size_t n_answers;
    size_t wire_len;
    uint64_t inflight_at_end;
    unsigned rcode;
    bool aa, ra, rd;
    bool saw_ptr;
    uint32_t ptr_ttl;
    uint8_t ptr[256];
    size_t ptr_len;
} reply_t;

typedef struct {
    bool over_tcp;
    bool rewrite;
    bool report;
    bool retime;
    bool disable_drop_aaaa;
    unsigned big_a;
    unsigned big_aaaa;
    bool padded_opt;
    uint16_t edns_size;
    bool hold;
    uint32_t hold_ms;
    uint32_t release_after_ms;
    const char *listen_addr;
    bool release_declines;
    uint32_t client_wait_ms;
    bool tcp_client_leaves_mid_hold;
    uint32_t max_concurrent;
    bool second_client;
    uint32_t max_held;
    bool tunnel;
    int tunnel_fail_connect;
    bool tunnel_bad_len;
    bool tunnel_sink_a;
    bool tunnel_wrong_id;
    uint32_t timeout_ms;
    uint32_t tcp_send_after_ms;
    uint32_t linger_ms;
    const firc_ip_t *ptr;
    bool ptr_no_rd;
    const firc_fakeip_t *pool;
    uint32_t pool_ttl;
} xopts_t;

/* Waits until the proxy holds at least `n` answers, or two seconds. */
static void wait_held(firc_dnsproxy_t *proxy, size_t n) {
    for (int i = 0; i < 200 && firc_dnsproxy_held(proxy) < n; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
}

static bool never_ready(const firc_dns_msg_t *msg, void *ud) {
    (void)msg;
    (void)ud;
    return false;
}

typedef struct {
    firc_dnsproxy_t *proxy;
    bool decline;
} release_t;

/* Posted onto the loop: the proxy's held list is loop state. */
static void release_all(firc_loop_t *loop, void *ud) {
    (void)loop;
    release_t *r = ud;
    firc_dnsproxy_release(r->proxy, r->decline ? never_ready : NULL, NULL);
}

static int run_exchange(const xopts_t *o, reply_t *out, int *hook_calls) {
    bool rewrite = o->rewrite, report = o->report, disable_drop_aaaa = o->disable_drop_aaaa,
         over_tcp = o->over_tcp;
    g_big_a = o->big_a;
    g_big_aaaa = o->big_aaaa;
    g_padded_opt = o->padded_opt;
    atomic_store(&g_tcp_bad_len_once, o->tunnel_bad_len ? 1 : 0);
    atomic_store(&g_tcp_sink_a_once, o->tunnel_sink_a ? 1 : 0);
    atomic_store(&g_tcp_wrong_id_once, o->tunnel_wrong_id ? 1 : 0);
    fixture_t fx;
    memset(&fx, 0, sizeof(fx));
    fx.rewrite = rewrite;
    fx.report = report;
    fx.hold = o->hold;
    fx.retime = o->retime;

    if (firc_loop_create(&fx.loop) != FIRC_OK) { return -2; }

    uint16_t up_port = 0, proxy_port = 0;
    if (!free_ports(&up_port, &proxy_port)) {
        firc_loop_destroy(fx.loop);
        return -2;
    }

    fx.upstream_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fx.upstream_fd < 0) {
        firc_loop_destroy(fx.loop);
        return -2;
    }
    struct sockaddr_in ua;
    memset(&ua, 0, sizeof(ua));
    ua.sin_family = AF_INET;
    ua.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ua.sin_port = htons(up_port);
    if (bind(fx.upstream_fd, (struct sockaddr *)&ua, sizeof(ua)) != 0) {
        close(fx.upstream_fd);
        firc_loop_destroy(fx.loop);
        return -2;
    }
    firc_loop_add_fd(fx.loop, fx.upstream_fd, EPOLLIN, on_upstream_query, &fx);

    fx.upstream_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fx.upstream_tcp_fd < 0 || !bind_loopback(fx.upstream_tcp_fd, up_port, NULL) ||
        listen(fx.upstream_tcp_fd, 4) != 0) {
        if (fx.upstream_tcp_fd >= 0) { close(fx.upstream_tcp_fd); }
        firc_loop_del_fd(fx.loop, fx.upstream_fd);
        close(fx.upstream_fd);
        firc_loop_destroy(fx.loop);
        return -2;
    }
    firc_loop_add_fd(fx.loop, fx.upstream_tcp_fd, EPOLLIN, on_upstream_accept, &fx);

    firc_dnsproxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_addr = o->listen_addr ? o->listen_addr : "127.0.0.1";
    cfg.listen_port = proxy_port;
    cfg.upstream_addr = "127.0.0.1";
    cfg.upstream_port = up_port;
    cfg.timeout_ms = o->timeout_ms ? o->timeout_ms : 3000;
    cfg.max_concurrent = o->max_concurrent ? o->max_concurrent : 16;
    cfg.max_idle_conns = 2;
    cfg.disable_drop_aaaa = disable_drop_aaaa;
    cfg.hold_ms = o->hold_ms;
    cfg.max_held = o->max_held;

    firc_dnsproxy_t *proxy = NULL;
    if (firc_dnsproxy_create(&cfg, fx.loop, hook, &fx, &proxy) != FIRC_OK) { return -2; }
    if (o->pool != NULL) { firc_dnsproxy_set_pool(proxy, o->pool, o->pool_ttl); }
    if (o->tunnel) {
        rec_reset();
        memset(&g_troute, 0, sizeof(g_troute));
        g_troute.take = true;
        g_troute.mark = 0x40010000u;
        g_troute.n = 1;
        g_troute.ports[0] = up_port;
        firc_dnsproxy_set_sock_ops(proxy, &REC_OPS);
        firc_dnsproxy_set_router(proxy, test_route, &g_troute);
        atomic_store(&g_rec.fail_connect, o->tunnel_fail_connect);
    }
    if (firc_dnsproxy_start(proxy) != FIRC_OK) {
        firc_dnsproxy_destroy(proxy);
        firc_loop_del_fd(fx.loop, fx.upstream_fd);
        close(fx.upstream_fd);
        firc_loop_destroy(fx.loop);
        return -2;
    }

    pthread_t th;
    pthread_create(&th, NULL, loop_thread, fx.loop);

    int cfd = socket(AF_INET, over_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in pa;
    memset(&pa, 0, sizeof(pa));
    pa.sin_family = AF_INET;
    pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    pa.sin_port = htons(proxy_port);

    uint8_t q[512];
    size_t qlen = o->ptr != NULL ? build_ptr_query(q, 0x2468, o->ptr, o->edns_size != 0)
                                 : build_query(q, 0x2468, o->edns_size);
    if (o->ptr != NULL && o->ptr_no_rd) { q[2] = 0x00; }
    uint8_t r[2048];
    ssize_t rn = -1;
    release_t rel = {.proxy = proxy, .decline = o->release_declines};
    int cfd2 = -1;
    if (o->second_client) {
        cfd2 = socket(AF_INET, SOCK_DGRAM, 0);
        setsockopt(cfd2, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (over_tcp) {
        if (connect(cfd, (struct sockaddr *)&pa, sizeof(pa)) == 0) {
            uint8_t framed[520];
            framed[0] = (uint8_t)(qlen >> 8);
            framed[1] = (uint8_t)qlen;
            memcpy(framed + 2, q, qlen);
            if (o->tcp_send_after_ms > 0) {
                struct timespec ts = {.tv_sec = o->tcp_send_after_ms / 1000,
                                      .tv_nsec = (o->tcp_send_after_ms % 1000) * 1000000L};
                nanosleep(&ts, NULL);
            }
            if (o->tcp_client_leaves_mid_hold &&
                send(cfd, framed, qlen + 2, 0) == (ssize_t)(qlen + 2)) {
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 300 * 1000000L};
                wait_held(proxy, 1);
                struct linger lg = {.l_onoff = 1, .l_linger = 0};
                setsockopt(cfd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
                close(cfd);
                cfd = socket(AF_INET, SOCK_STREAM, 0);
                nanosleep(&ts, NULL);
                firc_loop_post(fx.loop, release_all, &rel);
                nanosleep(&ts, NULL);
            } else if (send(cfd, framed, qlen + 2, 0) == (ssize_t)(qlen + 2)) {
                uint8_t hdr[2];
                if (recv(cfd, hdr, 2, MSG_WAITALL) == 2) {
                    size_t want = ((size_t)hdr[0] << 8) | hdr[1];
                    if (want <= sizeof(r) && recv(cfd, r, want, MSG_WAITALL) == (ssize_t)want) {
                        rn = (ssize_t)want;
                    }
                }
            }
        }
    } else {
        sendto(cfd, q, qlen, 0, (struct sockaddr *)&pa, sizeof(pa));
        if (cfd2 >= 0) {
            wait_held(proxy, 1);
            uint8_t q2[512];
            size_t q2len = build_query(q2, 0x2469, 0);
            sendto(cfd2, q2, q2len, 0, (struct sockaddr *)&pa, sizeof(pa));
        }
        if (o->release_after_ms > 0) {
            struct timespec ts = {.tv_sec = o->release_after_ms / 1000,
                                  .tv_nsec = (o->release_after_ms % 1000) * 1000000L};
            nanosleep(&ts, NULL);
            uint8_t probe[16];
            out->arrived_before_release = recv(cfd, probe, sizeof(probe), MSG_DONTWAIT | MSG_PEEK) > 0;
            if (cfd2 >= 0) {
                out->second_before_release = recv(cfd2, probe, sizeof(probe), MSG_DONTWAIT | MSG_PEEK) > 0;
            }
            firc_loop_post(fx.loop, release_all, &rel);
        }
        if (o->client_wait_ms > 0) {
            struct timeval w = {.tv_sec = o->client_wait_ms / 1000,
                                .tv_usec = (o->client_wait_ms % 1000) * 1000};
            setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &w, sizeof(w));
        }
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        rn = recv(cfd, r, sizeof(r), 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        out->waited_ms = (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
    }
    if (cfd2 >= 0) {
        uint8_t r2[512];
        out->second_replied = recv(cfd2, r2, sizeof(r2), 0) > 0;
        close(cfd2);
    }
    out->held_at_end = firc_dnsproxy_held(proxy);
    if (o->linger_ms > 0) {
        struct timespec ts = {.tv_sec = o->linger_ms / 1000, .tv_nsec = (o->linger_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL);
        out->inflight_at_end = firc_dnsproxy_inflight(proxy);
    }
    int rc = -1;
    if (rn > 0) {
        firc_dns_msg_t *msg = NULL;
        if (firc_dns_msg_parse(r, (size_t)rn, &msg) == FIRC_OK) {
            rc = 0;
            out->wire_len = (size_t)rn;
            out->tc = (msg->flags & FIRC_DNS_FLAG_TC) != 0;
            out->rcode = msg->flags & 0x0fu;
            out->aa = (msg->flags & 0x0400u) != 0;
            out->ra = (msg->flags & FIRC_DNS_FLAG_RA) != 0;
            out->rd = (msg->flags & FIRC_DNS_FLAG_RD) != 0;
            out->n_answers = msg->n_answers;
            for (size_t i = 0; i < msg->n_additional; i++) {
                if (msg->additional[i].rtype == FIRC_DNS_TYPE_OPT) { out->has_opt = true; }
            }
            for (size_t i = 0; i < msg->n_answers; i++) {
                if (msg->answers[i].rtype == FIRC_DNS_TYPE_A && msg->answers[i].rdata_len == 4) {
                    memcpy(out->a, msg->answers[i].rdata, 4);
                    out->saw_a = true;
                }
                if (msg->answers[i].rtype == FIRC_DNS_TYPE_AAAA) {
                    out->saw_aaaa = true;
                    out->aaaa_ttl = msg->answers[i].ttl;
                }
                if (msg->answers[i].rtype == FIRC_DNS_TYPE_PTR && msg->answers[i].rdata_len <= sizeof(out->ptr)) {
                    out->saw_ptr = true;
                    out->ptr_ttl = msg->answers[i].ttl;
                    out->ptr_len = msg->answers[i].rdata_len;
                    memcpy(out->ptr, msg->answers[i].rdata, out->ptr_len);
                }
            }
            firc_dns_msg_free(msg);
        }
    }
    *hook_calls = fx.hook_calls;
    out->saw_client = fx.saw_client;
    memcpy(out->client, fx.last_client, 4);

    close(cfd);
    firc_loop_stop(fx.loop);
    pthread_join(th, NULL);
    firc_dnsproxy_destroy(proxy);
    firc_loop_del_fd(fx.loop, fx.upstream_tcp_fd);
    close(fx.upstream_tcp_fd);
    firc_loop_del_fd(fx.loop, fx.upstream_fd);
    close(fx.upstream_fd);
    firc_loop_destroy(fx.loop);
    return rc;
}

/* Retries a harness that could not be set up, never one that gave a wrong or missing answer. */
static int exchange_opts(const xopts_t *o, reply_t *out, int *hook_calls) {
    for (int attempt = 0; attempt < 8; attempt++) {
        memset(out, 0, sizeof(*out));
        int rc = run_exchange(o, out, hook_calls);
        if (rc != -2) { return rc; }
    }
    return -2;
}

static int exchange_on(bool over_tcp, bool rewrite, bool report, bool disable_drop_aaaa,
                       reply_t *out, int *hook_calls) {
    xopts_t o = {.over_tcp = over_tcp,
                 .rewrite = rewrite,
                 .report = report,
                 .disable_drop_aaaa = disable_drop_aaaa};
    return exchange_opts(&o, out, hook_calls);
}

static int exchange(bool rewrite, bool report, bool disable_drop_aaaa, reply_t *out,
                    int *hook_calls) {
    return exchange_on(false, rewrite, report, disable_drop_aaaa, out, hook_calls);
}

typedef struct {
    int fd;
    uint16_t port;
    _Atomic uint8_t mark;
    _Atomic int received;
    _Atomic int hold;
    _Atomic int go;
    _Atomic int stop;
    pthread_t th;
    _Atomic int rcode;
    _Atomic int a_set;
    _Atomic uint32_t a_ip;
    _Atomic int aaaa_loopback;
    _Atomic int garbage;
    _Atomic int aaaa_custom_set;
    _Atomic uint64_t aaaa_hi;
    _Atomic uint64_t aaaa_lo;
    _Atomic int second_a_sink;
    _Atomic int hold_ms;
    _Atomic int decoy_first;
    _Atomic int drop;
    _Atomic int tc;
    _Atomic int replied;
} stub_t;

#define STUB_A_LAST_OCTET 46

static void *stub_serve(void *arg) {
    stub_t *s = arg;
    uint8_t q[512], a[STUB_BUF];
    while (!atomic_load(&s->stop)) {
        struct sockaddr_storage from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(s->fd, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) { continue; }
        atomic_fetch_add(&s->received, 1);
        int drops = atomic_load(&s->drop);
        if (drops > 0) {
            atomic_store(&s->drop, drops - 1);
            continue;
        }
        while (atomic_load(&s->hold) && !atomic_load(&s->go) && !atomic_load(&s->stop)) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
            nanosleep(&ts, NULL);
        }
        int hm = atomic_load(&s->hold_ms);
        if (hm > 0) {
            struct timespec ts = {.tv_sec = hm / 1000, .tv_nsec = (hm % 1000) * 1000000L};
            nanosleep(&ts, NULL);
        }
        size_t alen = build_answer(q, (size_t)n, a);
        a[STUB_A_LAST_OCTET] = atomic_load(&s->mark);
        if (atomic_load(&s->tc)) { a[2] |= 0x02; }
        int rc = atomic_load(&s->rcode);
        if (rc != 0) { a[3] = (uint8_t)((a[3] & 0xf0) | (rc & 0x0f)); }
        if (atomic_load(&s->a_set)) {
            uint32_t ip = atomic_load(&s->a_ip);
            a[43] = (uint8_t)(ip >> 24);
            a[44] = (uint8_t)(ip >> 16);
            a[45] = (uint8_t)(ip >> 8);
            a[46] = (uint8_t)ip;
        }
        if (atomic_load(&s->aaaa_loopback)) {
            memset(a + 72, 0, 15);
            a[87] = 1;
        }
        if (atomic_load(&s->aaaa_custom_set)) {
            uint64_t hi = atomic_load(&s->aaaa_hi);
            uint64_t lo = atomic_load(&s->aaaa_lo);
            for (int k = 0; k < 8; k++) { a[72 + k] = (uint8_t)(hi >> (56 - 8 * k)); }
            for (int k = 0; k < 8; k++) { a[80 + k] = (uint8_t)(lo >> (56 - 8 * k)); }
        }
        if (atomic_load(&s->second_a_sink)) {
            a[7] = (uint8_t)(a[7] + 1);
            size_t p = alen;
            a[p++] = 0xc0; a[p++] = 0x0c;
            a[p++] = 0x00; a[p++] = FIRC_DNS_TYPE_A;
            a[p++] = 0x00; a[p++] = 0x01;
            a[p++] = 0x00; a[p++] = 0x00; a[p++] = 0x00; a[p++] = 0x00;
            a[p++] = 0x00; a[p++] = 0x04;
            a[p++] = 0; a[p++] = 0; a[p++] = 0; a[p++] = 0;
            alen = p;
        }
        if (atomic_load(&s->garbage)) { alen = 5; }
        int decoy = atomic_load(&s->decoy_first);
        if (decoy != 0 && alen > STUB_A_LAST_OCTET) {
            uint8_t d[STUB_BUF];
            memcpy(d, a, alen);
            d[STUB_A_LAST_OCTET] = 99;
            if (decoy == 1) {
                d[0] ^= 0xff;
                d[1] ^= 0xff;
            } else {
                d[13] = 'b';
            }
            sendto(s->fd, d, alen, 0, (struct sockaddr *)&from, fl);
        }
        sendto(s->fd, a, alen, 0, (struct sockaddr *)&from, fl);
        atomic_fetch_add(&s->replied, 1);
    }
    return NULL;
}

static bool stub_start(stub_t *s, uint8_t mark) {
    memset(s, 0, sizeof(*s));
    atomic_store(&s->mark, mark);
    s->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s->fd < 0) { return false; }
    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (!bind_loopback(s->fd, 0, &s->port) || pthread_create(&s->th, NULL, stub_serve, s) != 0) {
        close(s->fd);
        return false;
    }
    return true;
}

static void stub_stop(stub_t *s) {
    atomic_store(&s->stop, 1);
    pthread_join(s->th, NULL);
    close(s->fd);
}

typedef struct {
    firc_loop_t *loop;
    firc_dnsproxy_t *proxy;
    uint16_t proxy_port;
    stub_t a, b, c;
    pthread_t th;
} live_t;

static bool g_live_hold;
static bool g_live_cache;
static _Atomic uint64_t g_cache_skew_ms;
static _Atomic int g_live_hook_calls;

static uint64_t skewed_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u + atomic_load(&g_cache_skew_ms);
}

static _Atomic int g_live_resolver = -1;

static firc_dns_verdict_t live_hook(firc_dns_msg_t *msg, const firc_ip_t *client,
                                    const char *network, firc_dns_resolver_t resolver, void *ud) {
    (void)msg;
    (void)client;
    (void)network;
    (void)ud;
    atomic_fetch_add(&g_live_hook_calls, 1);
    atomic_store(&g_live_resolver, (int)resolver);
    return g_live_hold ? FIRC_DNS_HOLD : FIRC_DNS_PASS;
}

/* False when the harness could not be set up, such as a port taken between probing and binding. */
static bool live_start(live_t *lv) {
    memset(lv, 0, sizeof(*lv));
    g_big_a = 0;
    g_big_aaaa = 0;
    g_padded_opt = false;
    uint16_t unused = 0;
    if (!free_ports(&lv->proxy_port, &unused)) { return false; }
    if (firc_loop_create(&lv->loop) != FIRC_OK) { return false; }
    if (!stub_start(&lv->a, 1)) {
        firc_loop_destroy(lv->loop);
        return false;
    }
    if (!stub_start(&lv->b, 2)) {
        stub_stop(&lv->a);
        firc_loop_destroy(lv->loop);
        return false;
    }
    if (!stub_start(&lv->c, 3)) {
        stub_stop(&lv->b);
        stub_stop(&lv->a);
        firc_loop_destroy(lv->loop);
        return false;
    }
    firc_dnsproxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_addr = "127.0.0.1";
    cfg.listen_port = lv->proxy_port;
    cfg.upstream_addr = "127.0.0.1";
    cfg.upstream_port = lv->a.port;
    cfg.timeout_ms = g_live_timeout_ms ? g_live_timeout_ms : 3000;
    cfg.max_concurrent = g_live_max_concurrent ? g_live_max_concurrent : 16;
    cfg.max_idle_conns = 2;
    cfg.hold_ms = 200;
    if (firc_dnsproxy_create(&cfg, lv->loop, live_hook, NULL, &lv->proxy) != FIRC_OK) {
        stub_stop(&lv->c);
        stub_stop(&lv->b);
        stub_stop(&lv->a);
        firc_loop_destroy(lv->loop);
        return false;
    }
    if (g_live_ops != NULL) { firc_dnsproxy_set_sock_ops(lv->proxy, g_live_ops); }
    if (g_live_cache) {
        firc_dnsproxy_set_cache_clock_for_test(lv->proxy, skewed_ms);
    } else {
        firc_dnsproxy_set_cache(lv->proxy, 0, 0);
    }
    atomic_store(&g_live_hook_calls, 0);
    if (g_live_route != NULL) { firc_dnsproxy_set_router(lv->proxy, test_route, g_live_route); }
    firc_ip_t v4 = {.b = {198, 18, 0, 0}, .len = 4};
    firc_ip_t v6 = {.b = {0xfd, 0x00, 0x12, 0x34}, .len = 16};
    firc_dnsproxy_set_pool_prefixes(lv->proxy, &v4, 15, &v6, 48);
    if (g_live_rest_ms != 0) { firc_dnsproxy_set_health(lv->proxy, 0, g_live_rest_ms); }
    if (firc_dnsproxy_start(lv->proxy) != FIRC_OK) {
        firc_dnsproxy_destroy(lv->proxy);
        stub_stop(&lv->c);
        stub_stop(&lv->b);
        stub_stop(&lv->a);
        firc_loop_destroy(lv->loop);
        return false;
    }
    pthread_create(&lv->th, NULL, loop_thread, lv->loop);
    return true;
}

static void live_stop(live_t *lv) {
    firc_loop_stop(lv->loop);
    pthread_join(lv->th, NULL);
    firc_dnsproxy_destroy(lv->proxy);
    stub_stop(&lv->c);
    stub_stop(&lv->b);
    stub_stop(&lv->a);
    firc_loop_destroy(lv->loop);
    g_live_ops = NULL;
    g_live_route = NULL;
    g_live_timeout_ms = 0;
    g_live_max_concurrent = 0;
    g_live_rest_ms = 0;
    g_live_cache = false;
    atomic_store(&g_cache_skew_ms, 0);
}

typedef struct {
    firc_dnsproxy_t *proxy;
    const char *addr;
    uint16_t port;
    firc_err_t err;
    _Atomic int done;
} set_t;

static void set_upstream_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    set_t *s = ud;
    s->err = firc_dnsproxy_set_upstream(s->proxy, s->addr, s->port);
    atomic_store(&s->done, 1);
}

/* Sets the upstream on the loop thread, where the daemon calls it, and waits up to two seconds. */
static firc_err_t live_set_upstream(live_t *lv, const char *addr, uint16_t port) {
    set_t s = {.proxy = lv->proxy, .addr = addr, .port = port, .err = FIRC_ERR_TIMEOUT};
    if (firc_loop_post(lv->loop, set_upstream_on_loop, &s) != FIRC_OK) { return FIRC_ERR_STATE; }
    for (int i = 0; i < 200 && !atomic_load(&s.done); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return atomic_load(&s.done) ? s.err : FIRC_ERR_TIMEOUT;
}

static int ask_send_for(uint16_t port, uint16_t id, uint16_t edns, char first) {
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    if (c < 0) { return -1; }
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in pa;
    memset(&pa, 0, sizeof(pa));
    pa.sin_family = AF_INET;
    pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    pa.sin_port = htons(port);
    uint8_t q[512];
    size_t qlen = build_query_for(q, id, edns, first);
    if (sendto(c, q, qlen, 0, (struct sockaddr *)&pa, sizeof(pa)) != (ssize_t)qlen) {
        close(c);
        return -1;
    }
    return c;
}

static int ask_send(uint16_t port, uint16_t id) {
    return ask_send_for(port, id, 0, 'a');
}

/* The last octet of the A record in the answer on `c`, or -1. Closes `c`. */
static int ask_read(int c) {
    uint8_t r[2048];
    ssize_t n = recv(c, r, sizeof(r), 0);
    close(c);
    if (n <= 0) { return -1; }
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(r, (size_t)n, &msg) != FIRC_OK) { return -1; }
    int mark = -1;
    for (size_t i = 0; i < msg->n_answers; i++) {
        if (msg->answers[i].rtype == FIRC_DNS_TYPE_A && msg->answers[i].rdata_len == 4) {
            mark = msg->answers[i].rdata[3];
        }
    }
    firc_dns_msg_free(msg);
    return mark;
}

static int ask(uint16_t port, uint16_t id) {
    int c = ask_send(port, id);
    return c < 0 ? -1 : ask_read(c);
}

static int ask_for(uint16_t port, uint16_t id, uint16_t edns, char first) {
    int c = ask_send_for(port, id, edns, first);
    return c < 0 ? -1 : ask_read(c);
}

static long ask_a_ttl(uint16_t port, uint16_t id) {
    int c = ask_send(port, id);
    if (c < 0) { return -1; }
    uint8_t r[2048];
    ssize_t n = recv(c, r, sizeof(r), 0);
    close(c);
    if (n <= 0) { return -1; }
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(r, (size_t)n, &msg) != FIRC_OK) { return -1; }
    long ttl = -1;
    for (size_t i = 0; i < msg->n_answers; i++) {
        if (msg->answers[i].rtype == FIRC_DNS_TYPE_A) { ttl = (long)msg->answers[i].ttl; }
    }
    firc_dns_msg_free(msg);
    return ttl;
}

/* A TCP connection to the proxy with three-second send and receive timeouts, or -1. */
static int tcp_open(uint16_t port) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) { return -1; }
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in pa;
    memset(&pa, 0, sizeof(pa));
    pa.sin_family = AF_INET;
    pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    pa.sin_port = htons(port);
    if (connect(c, (struct sockaddr *)&pa, sizeof(pa)) != 0) {
        close(c);
        return -1;
    }
    return c;
}

/* One length-prefixed query on a new TCP connection; the answer's last A octet, or -1. */
static int ask_tcp(uint16_t port, uint16_t id) {
    int c = tcp_open(port);
    if (c < 0) { return -1; }
    uint8_t q[512];
    size_t qlen = build_query(q, id, 0);
    uint8_t framed[514];
    framed[0] = (uint8_t)(qlen >> 8);
    framed[1] = (uint8_t)qlen;
    memcpy(framed + 2, q, qlen);
    if (send(c, framed, qlen + 2, MSG_NOSIGNAL) != (ssize_t)(qlen + 2)) {
        close(c);
        return -1;
    }
    uint8_t hdr[2];
    if (recv(c, hdr, 2, MSG_WAITALL) != 2) {
        close(c);
        return -1;
    }
    size_t want = ((size_t)hdr[0] << 8) | hdr[1];
    uint8_t r[2048];
    ssize_t got = (want <= sizeof(r)) ? recv(c, r, want, MSG_WAITALL) : -1;
    close(c);
    if (got != (ssize_t)want) { return -1; }
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(r, want, &msg) != FIRC_OK) { return -1; }
    int last = -1;
    for (size_t i = 0; i < msg->n_answers; i++) {
        if (msg->answers[i].rtype == FIRC_DNS_TYPE_A && msg->answers[i].rdata_len == 4) {
            last = msg->answers[i].rdata[3];
        }
    }
    firc_dns_msg_free(msg);
    return last;
}

static bool live_start_retrying(live_t *lv) {
    for (int attempt = 0; attempt < 8; attempt++) {
        if (live_start(lv)) { return true; }
    }
    return false;
}

/* Catches: a TCP read with no deadline, or one that closes the connection but keeps the in-flight slot. */
TEST a_tcp_client_that_never_finishes_its_request_gives_its_slot_back(void) {
    g_live_timeout_ms = 300;
    g_live_max_concurrent = 2;
    live_t lv;
    ASSERT(live_start_retrying(&lv));
    int a = tcp_open(lv.proxy_port);
    int b = tcp_open(lv.proxy_port);
    ASSERT(a >= 0 && b >= 0);
    ASSERT_EQ(1, send(a, "\0", 1, MSG_NOSIGNAL));
    static const uint8_t partial[3] = {0, 20, 1};
    ASSERT_EQ(3, send(b, partial, sizeof(partial), MSG_NOSIGNAL));
    ASSERT_EQm("both connections hold a slot", (uint64_t)2, inflight_settled(lv.proxy, 2));
    uint8_t r[16];
    ASSERT_EQm("the proxy closes the first at its deadline", 0, recv(a, r, sizeof(r), 0));
    ASSERT_EQm("and the second", 0, recv(b, r, sizeof(r), 0));
    close(a);
    close(b);
    ASSERT_EQm("both slots are back", (uint64_t)0, inflight_settled(lv.proxy, 0));
    ASSERT_EQm("a UDP query is answered", 1, ask(lv.proxy_port, 0x0a01));
    live_stop(&lv);
    PASS();
}

/* Catches: a read timer left armed after the request is whole, closing a held answer's connection. */
TEST a_tcp_request_sent_just_in_time_is_answered_past_the_read_deadline(void) {
    xopts_t o = {.over_tcp = true,
                 .rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .hold = true,
                 .hold_ms = 200,
                 .timeout_ms = 400,
                 .tcp_send_after_ms = 300};
    reply_t got;
    int calls = 0;
    ASSERT_EQm("answered, not closed at the read deadline", 0, exchange_opts(&o, &got, &calls));
    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQm("the rewritten answer, as held", want, got.a, 4);
    PASS();
}

/* Catches: a read timer left armed after the exchange, firing on freed memory. */
TEST no_read_deadline_fires_after_a_tcp_exchange_ends(void) {
    xopts_t o = {.over_tcp = true, .rewrite = true, .report = true, .disable_drop_aaaa = true,
                 .timeout_ms = 200, .linger_ms = 500};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQ(want, got.a, 4);
    ASSERT_EQm("the one slot came back once", (uint64_t)0, got.inflight_at_end);
    PASS();
}

/* Catches: a new upstream address that keeps the idle sockets, or closes them but keeps the old sockaddr. */
TEST a_changed_upstream_answers_the_next_query(void) {
    live_t lv;
    ASSERT(live_start_retrying(&lv));
    ASSERT_EQm("A answers before the change, and leaves an idle socket to A", 1,
               ask(lv.proxy_port, 0x1001));
    ASSERT_EQ(FIRC_OK, live_set_upstream(&lv, "127.0.0.1", lv.b.port));
    ASSERT_EQm("B answers after it", 2, ask(lv.proxy_port, 0x1002));
    ASSERT_EQm("and A was not asked again", 1, atomic_load(&lv.a.received));
    live_stop(&lv);
    PASS();
}

/* Catches: an exchange that ends returning its old-upstream socket to the idle pool. */
static enum greatest_test_res in_flight_finishes_on_the_old_upstream(bool hold) {
    g_live_hold = hold;
    live_t lv;
    ASSERT(live_start_retrying(&lv));
    atomic_store(&lv.a.hold, 1);
    int c1 = ask_send(lv.proxy_port, 0x2001);
    ASSERT(c1 >= 0);
    for (int i = 0; i < 200 && atomic_load(&lv.a.received) == 0; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQm("the first query is at A, held", 1, atomic_load(&lv.a.received));
    ASSERT_EQ(FIRC_OK, live_set_upstream(&lv, "127.0.0.1", lv.b.port));
    atomic_store(&lv.a.go, 1);
    ASSERT_EQm("the held query is answered by A", 1, ask_read(c1));
    ASSERT_EQm("the next one by B", 2, ask(lv.proxy_port, 0x2002));
    ASSERT_EQm("A saw only the first", 1, atomic_load(&lv.a.received));
    live_stop(&lv);
    g_live_hold = false;
    PASS();
}

TEST a_query_in_flight_finishes_on_the_old_upstream(void) {
    CHECK_CALL(in_flight_finishes_on_the_old_upstream(false));
    PASS();
}

TEST a_held_query_in_flight_finishes_on_the_old_upstream(void) {
    CHECK_CALL(in_flight_finishes_on_the_old_upstream(true));
    PASS();
}

/* Catches: a setter that stores the new upstream text before it knows the text parses. */
TEST an_upstream_that_does_not_parse_changes_nothing(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_dnsproxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_addr = "127.0.0.1";
    cfg.listen_port = 1;
    cfg.upstream_addr = "127.0.0.1";
    cfg.upstream_port = 53;
    cfg.timeout_ms = 1000;
    cfg.max_concurrent = 4;
    cfg.max_idle_conns = 2;
    firc_dnsproxy_t *p = NULL;
    ASSERT_EQ(FIRC_OK, firc_dnsproxy_create(&cfg, loop, live_hook, NULL, &p));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_dnsproxy_set_upstream(p, "dns.example", 5353));
    uint16_t port = 0;
    ASSERT_STR_EQ("127.0.0.1", firc_dnsproxy_upstream(p, &port));
    ASSERT_EQ(53, port);
    firc_dnsproxy_destroy(p);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: the proxy keeping the caller's upstream pointer, which a settings PUT frees. */
TEST the_proxy_keeps_its_own_copy_of_the_upstream(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    char *text = strdup("127.0.0.1");
    ASSERT(text != NULL);
    firc_dnsproxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_addr = "127.0.0.1";
    cfg.listen_port = 1;
    cfg.upstream_addr = text;
    cfg.upstream_port = 53;
    cfg.timeout_ms = 1000;
    cfg.max_concurrent = 4;
    cfg.max_idle_conns = 2;
    firc_dnsproxy_t *p = NULL;
    ASSERT_EQ(FIRC_OK, firc_dnsproxy_create(&cfg, loop, live_hook, NULL, &p));
    memset(text, 'x', strlen(text));
    free(text);
    ASSERT_STR_EQ("127.0.0.1", firc_dnsproxy_upstream(p, NULL));
    firc_dnsproxy_destroy(p);
    firc_loop_destroy(loop);
    PASS();
}

static firc_fakeip_t *ptr_pool(firc_ip_t *v4, firc_ip_t *v6) {
    firc_fakeip_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    const uint8_t v6base[6] = {0xfd, 0x37, 0x9a, 0x5c, 0xbe, 0x10};
    memcpy(c.v6.base.b, v6base, sizeof(v6base));
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *f = NULL;
    if (firc_fakeip_new(&c, &f) != FIRC_OK) { abort(); }
    if (firc_fakeip_get(f, "Shop.Example.com", "g1", 1000, v4, v6) != FIRC_OK) { abort(); }
    return f;
}

static const uint8_t SHOP_WIRE[] = "\004shop\007example\003com";

TEST a_ptr_for_a_mapped_pool_address_names_its_domain(void) {
    firc_ip_t v4, v6;
    firc_fakeip_t *pool = ptr_pool(&v4, &v6);
    for (int fam = 0; fam < 2; fam++) {
        for (int tcp = 0; tcp < 2; tcp++) {
            reply_t got;
            int calls = 0;
            xopts_t o = {.over_tcp = tcp != 0, .ptr = fam == 0 ? &v4 : &v6, .pool = pool, .pool_ttl = 300};
            ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
            ASSERT_EQ_FMTm("answered by the proxy, not the upstream", 0, calls, "%d");
            ASSERT_EQ_FMT(0u, got.rcode, "%u");
            ASSERT_FALSE(got.aa);
            ASSERT(got.ra);
            ASSERT(got.saw_ptr);
            ASSERT_EQ_FMT(300u, got.ptr_ttl, "%u");
            ASSERT_EQ_FMT(sizeof(SHOP_WIRE), got.ptr_len, "%zu");
            ASSERT_MEM_EQ(SHOP_WIRE, got.ptr, sizeof(SHOP_WIRE));
        }
    }
    reply_t got;
    int calls = 0;
    xopts_t o = {.ptr = &v4, .pool = pool, .pool_ttl = 300, .edns_size = 1232};
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERTm("an EDNS query is answered with an OPT", got.has_opt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_ptr_answer_copies_rd_from_the_query(void) {
    firc_ip_t v4, v6;
    firc_fakeip_t *pool = ptr_pool(&v4, &v6);
    for (int no_rd = 0; no_rd < 2; no_rd++) {
        reply_t got;
        int calls = 0;
        xopts_t o = {.ptr = &v4, .ptr_no_rd = no_rd != 0, .pool = pool, .pool_ttl = 300};
        ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
        ASSERT(got.saw_ptr);
        ASSERT_EQ(no_rd == 0, got.rd);
    }
    firc_fakeip_free(pool);
    PASS();
}

TEST a_pool_name_that_cannot_be_packed_is_answered_nxdomain(void) {
    firc_ip_t v4, v6, l4, l6;
    firc_fakeip_t *pool = ptr_pool(&v4, &v6);
    char name[80];
    memset(name, 'a', 64);
    memcpy(name + 64, ".example.com", 13);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, name, "g1", 1000, &l4, &l6));
    reply_t got;
    int calls = 0;
    xopts_t o = {.ptr = &l4, .pool = pool, .pool_ttl = 300};
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_EQ_FMT(0, calls, "%d");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_RCODE_NXDOMAIN, got.rcode, "%u");
    ASSERT_EQ_FMT((size_t)0, got.n_answers, "%zu");
    firc_fakeip_free(pool);
    PASS();
}

TEST a_ptr_for_an_unmapped_pool_address_is_nxdomain(void) {
    firc_ip_t v4, v6;
    firc_fakeip_t *pool = ptr_pool(&v4, &v6);
    firc_ip_t free4 = v4;
    free4.b[3] = 200;
    firc_ip_t blackhole = {{198, 19, 255, 1}, 4};
    const firc_ip_t *asks[] = {&free4, &blackhole};
    for (size_t i = 0; i < 2; i++) {
        reply_t got;
        int calls = 0;
        xopts_t o = {.ptr = asks[i], .pool = pool, .pool_ttl = 300};
        ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
        ASSERT_EQ_FMT(0, calls, "%d");
        ASSERT_EQ_FMT((unsigned)FIRC_DNS_RCODE_NXDOMAIN, got.rcode, "%u");
        ASSERT_EQ_FMT((size_t)0, got.n_answers, "%zu");
    }
    firc_fakeip_free(pool);
    PASS();
}

TEST a_ptr_outside_the_pool_goes_to_the_upstream(void) {
    firc_ip_t v4, v6;
    firc_fakeip_t *pool = ptr_pool(&v4, &v6);
    firc_ip_t lan = {{192, 168, 1, 5}, 4};
    const firc_fakeip_t *pools[] = {pool, NULL};
    const firc_ip_t *asks[] = {&lan, &v4};
    for (size_t i = 0; i < 2; i++) {
        reply_t got;
        int calls = 0;
        xopts_t o = {.ptr = asks[i], .pool = pools[i], .pool_ttl = 300};
        ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
        ASSERT_EQ_FMTm("the upstream answered", 1, calls, "%d");
        ASSERT_EQ_FMT(0u, got.rcode, "%u");
        ASSERTm("the stub's own answer", got.saw_a);
    }
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a rewritten answer dropped and the real address forwarded when AAAA stripping is off. */
TEST a_rewritten_answer_reaches_the_client(void) {
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange(true, true, true, &got, &calls));
    ASSERT_EQ_FMTm("the hook must have run", 1, calls, "%d");

    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQm("the client must see the rewritten address, not the upstream's", want, got.a, 4);
    PASS();
}

TEST a_rewritten_answer_reaches_the_client_when_stripping_too(void) {
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange(true, true, false, &got, &calls));
    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQ(want, got.a, 4);
    ASSERTm("the rewritten AAAA must survive the AAAA-stripping default", got.saw_aaaa);
    PASS();
}

/* Catches: a RETIMED answer treated as a rewrite, skipping the default AAAA strip. */
TEST a_retimed_answer_is_still_stripped_by_the_aaaa_default(void) {
    reply_t got;
    int calls = 0;
    xopts_t o = {.retime = true, .disable_drop_aaaa = false};
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_EQ_FMTm("the hook must have run", 1, calls, "%d");
    static const uint8_t want[4] = {10, 1, 2, 3};
    ASSERT_MEM_EQm("the real address, untouched by RETIMED", want, got.a, 4);
    ASSERT_FALSEm("the AAAA is dropped, the same as any other real answer under the default",
                 got.saw_aaaa);
    PASS();
}

/* Catches: a RETIMED answer losing its AAAA with stripping off, or its lowered TTL not reaching the wire. */
TEST a_retimed_answer_keeps_its_aaaa_and_ttl_when_stripping_is_off(void) {
    reply_t got;
    int calls = 0;
    xopts_t o = {.retime = true, .disable_drop_aaaa = true};
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERTm("the AAAA survives with stripping off", got.saw_aaaa);
    ASSERT_EQ_FMTm("the lowered TTL reached the wire", 60u, got.aaaa_ttl, "%u");
    PASS();
}

/* Catches: an answer the hook did not change being repacked or altered. */
TEST an_untouched_answer_is_forwarded_as_it_arrived(void) {
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange(false, false, true, &got, &calls));
    ASSERT_EQ_FMT(1, calls, "%d");
    static const uint8_t want[4] = {10, 1, 2, 3};
    ASSERT_MEM_EQm("the upstream's own address", want, got.a, 4);

    size_t forwarded = got.wire_len;
    reply_t repacked;
    int c2 = 0;
    ASSERT_EQ(0, exchange(true, true, true, &repacked, &c2));
    ASSERTm("a re-packed answer is shorter, because the packer compresses the name the stub wrote out",
            repacked.wire_len < forwarded);
    PASS();
}

/* Catches: the proxy forwarding a change the hook made but did not report. */
TEST an_unreported_change_is_not_forwarded(void) {
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange(true, false, true, &got, &calls));
    static const uint8_t want[4] = {10, 1, 2, 3};
    ASSERT_MEM_EQm("unreported means unpacked, so the upstream's bytes go out", want, got.a, 4);
    PASS();
}

/* Catches: the TCP branch forwarding the upstream's bytes after a rewrite, or a swapped length prefix. */
TEST a_rewritten_answer_reaches_a_tcp_client(void) {
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_on( true, true, true, true, &got,
                             &calls));
    ASSERT_EQ_FMT(1, calls, "%d");
    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQm("over TCP too", want, got.a, 4);
    ASSERTm("and the framed length must match what was sent, or the parse above would "
            "have failed on a short read",
            got.wire_len > 0);
    PASS();
}

/* Catches: a repacked answer over 512 bytes sent to a client without EDNS instead of a TC reply. */
TEST a_rewritten_answer_too_big_for_a_client_without_edns_is_truncated(void) {
    xopts_t o = {.rewrite = true, .report = true, .disable_drop_aaaa = true, .big_a = BIG_A_OVER_512};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERTm("no more than 512 bytes to a client that advertised nothing", got.wire_len <= 512);
    ASSERTm("and told so, or the client would take the empty answer as final", got.tc);
    ASSERT_EQ_FMTm("a truncated reply carries no answers", (size_t)0, got.n_answers, "%zu");
    PASS();
}

/* Catches: a truncated reply that keeps an OPT record too big to fit in 512 bytes. */
TEST a_truncated_reply_drops_an_opt_that_does_not_fit(void) {
    xopts_t o = {.rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .big_a = BIG_A_OVER_512,
                 .padded_opt = true};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT(got.tc);
    ASSERTm("cut for a 512-byte limit, it is under 512", got.wire_len <= 512);
    ASSERTm("the OPT stays, emptied: a reply to an EDNS query must carry one (RFC 6891 §7)",
            got.has_opt);
    PASS();
}

/* Catches: an answer truncated although it fits the EDNS size the client advertised. */
TEST a_rewritten_answer_fits_the_size_the_client_advertised(void) {
    xopts_t o = {.rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .big_a = BIG_A_OVER_512,
                 .edns_size = 1232};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_FALSEm("nothing to truncate: 1232 bytes were offered", got.tc);
    ASSERT_EQ_FMT((size_t)BIG_A_OVER_512, got.n_answers, "%zu");
    ASSERTm("the re-pack really did exceed 512 — otherwise the test above proves nothing",
            got.wire_len > 512);
    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQ(want, got.a, 4);
    PASS();
}

/* Catches: an answer with no AAAA to strip being repacked and truncated under the default config. */
TEST an_untouched_big_answer_is_not_truncated(void) {
    xopts_t o = {.disable_drop_aaaa = false, .big_a = BIG_A_OVER_512};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_FALSEm("the upstream chose to send it; a transparent proxy passes it on", got.tc);
    ASSERT_EQ_FMT((size_t)BIG_A_OVER_512, got.n_answers, "%zu");
    PASS();
}

/* Catches: an AAAA strip repacked without name compression, overflowing 512 bytes. */
TEST a_stripped_big_answer_still_fits_a_client_without_edns(void) {
    xopts_t o = {.disable_drop_aaaa = false, .big_a = 17, .big_aaaa = 7};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_FALSE(got.tc);
    ASSERT_EQ_FMTm("the AAAA records went, the A records stayed", (size_t)17, got.n_answers, "%zu");
    ASSERTm("stripped, re-packed, and still within what the client may be sent",
            got.wire_len <= 512);
    PASS();
}

/* Catches: a big rewritten answer truncated for a TCP client, which has no 512-byte limit. */
TEST a_rewritten_big_answer_reaches_a_tcp_client_whole(void) {
    xopts_t o = {.over_tcp = true,
                 .rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .big_a = BIG_A_OVER_512};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_FALSE(got.tc);
    ASSERT_EQ_FMT((size_t)BIG_A_OVER_512, got.n_answers, "%zu");
    ASSERT(got.wire_len > 512);
    PASS();
}

/* Catches: the hook not told the client's address over UDP or TCP, or given it in v4-mapped form. */
TEST the_hook_is_told_which_device_asked(void) {
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange(false, false, true, &got, &calls));
    ASSERT(got.saw_client);
    static const uint8_t lo[4] = {127, 0, 0, 1};
    ASSERT_MEM_EQ(lo, got.client, 4);

    ASSERT_EQ(0, exchange_on( true, false, false, true, &got, &calls));
    ASSERTm("over TCP the peer address is captured at accept", got.saw_client);
    ASSERT_MEM_EQ(lo, got.client, 4);
    PASS();
}

/* Catches: a v4 client on the [::] socket reported as ::ffff:a.b.c.d, so a v4 allow list matches nobody. */
TEST a_v4_client_on_a_dual_stack_socket_is_reported_unmapped(void) {
    reply_t got;
    int calls = 0;
    static const uint8_t lo[4] = {127, 0, 0, 1};
    int probe = socket(AF_INET6, SOCK_DGRAM, 0);
    int off = 0;
    struct sockaddr_in6 any6;
    memset(&any6, 0, sizeof(any6));
    any6.sin6_family = AF_INET6;
    bool dual = probe >= 0 && setsockopt(probe, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) == 0 &&
                bind(probe, (struct sockaddr *)&any6, sizeof(any6)) == 0;
    if (probe >= 0) { close(probe); }
    if (!dual) { SKIPm("no dual-stack v6 socket on this host"); }
    xopts_t o = {.disable_drop_aaaa = true, .listen_addr = "::"};
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT(got.saw_client);
    ASSERT_MEM_EQm("UDP: the 4-byte form", lo, got.client, 4);
    o.over_tcp = true;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT(got.saw_client);
    ASSERT_MEM_EQm("TCP: the 4-byte form", lo, got.client, 4);
    PASS();
}

/* Catches: a held answer sent before its release, or not at once after it. */
TEST a_held_answer_goes_out_when_released(void) {
    xopts_t o = {.rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .hold = true,
                 .hold_ms = 5000,
                 .release_after_ms = 400};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_FALSEm("nothing before the release", got.arrived_before_release);
    ASSERTm("and released at once, not at the deadline", got.waited_ms < 2000);
    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQm("the rewritten answer, as held", want, got.a, 4);
    PASS();
}

/* Catches: a held answer never sent when no release comes before the deadline. */
TEST a_held_answer_goes_out_at_the_deadline(void) {
    xopts_t o = {.rewrite = true, .report = true, .disable_drop_aaaa = true, .hold = true, .hold_ms = 300};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERTm("held until the deadline", got.waited_ms >= 250);
    ASSERTm("and released there", got.waited_ms < 2500);
    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQ(want, got.a, 4);
    PASS();
}

/* Catches: a release sending held answers its predicate declined. */
TEST a_release_sends_only_what_it_approves(void) {
    xopts_t o = {.rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .hold = true,
                 .hold_ms = 700,
                 .release_after_ms = 200,
                 .release_declines = true};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_FALSE(got.arrived_before_release);
    ASSERTm("declined at the release, so it went at the deadline", got.waited_ms >= 400);
    PASS();
}

/* Catches: a TCP client reset while its answer is held, leaving freed memory on the held list. */
TEST a_tcp_client_gone_mid_hold_is_forgotten(void) {
    xopts_t o = {.over_tcp = true,
                 .rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .hold = true,
                 .hold_ms = 5000,
                 .tcp_client_leaves_mid_hold = true};
    reply_t got;
    int calls = 0;
    int rc = exchange_opts(&o, &got, &calls);
    ASSERT_EQ_FMTm("no reply: the client left", -1, rc, "%d");
    ASSERT_EQ_FMTm("and nothing is still held for it", (size_t)0, got.held_at_end, "%zu");
    PASS();
}

/* Catches: a held answer counted in flight, so a second client's query is refused. */
TEST held_answers_do_not_hold_the_inflight_budget(void) {
    xopts_t o = {.rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .hold = true,
                 .hold_ms = 5000,
                 .release_after_ms = 400,
                 .max_concurrent = 1,
                 .second_client = true};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERTm("the second client was served, not dropped for a budget the hold took", got.second_replied);
    PASS();
}

/* Catches: a HOLD past the held-answer ceiling dropped instead of sent at once. */
TEST past_the_ceiling_a_held_answer_is_sent_at_once(void) {
    xopts_t o = {.rewrite = true,
                 .report = true,
                 .disable_drop_aaaa = true,
                 .hold = true,
                 .hold_ms = 5000,
                 .release_after_ms = 400,
                 .max_held = 1,
                 .second_client = true};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERT_FALSEm("the first is held", got.arrived_before_release);
    ASSERTm("the second, past the ceiling, was answered without waiting", got.second_before_release);
    PASS();
}

/* Catches: a zero deadline holding an answer instead of sending it at once. */
TEST a_zero_deadline_sends_a_held_answer_at_once(void) {
    xopts_t o = {.rewrite = true, .report = true, .disable_drop_aaaa = true, .hold = true, .hold_ms = 0};
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_opts(&o, &got, &calls));
    ASSERTm("no wait", got.waited_ms < 200);
    static const uint8_t want[4] = {198, 18, 0, 7};
    ASSERT_MEM_EQ(want, got.a, 4);
    PASS();
}

TEST a_tcp_answer_is_forwarded_when_untouched(void) {
    reply_t got;
    int calls = 0;
    ASSERT_EQ(0, exchange_on( true, false, false, true, &got,
                             &calls));
    static const uint8_t want[4] = {10, 1, 2, 3};
    ASSERT_MEM_EQ(want, got.a, 4);
    size_t forwarded = got.wire_len;

    reply_t repacked;
    int c2 = 0;
    ASSERT_EQ(0, exchange_on(true, true, true, true, &repacked, &c2));
    ASSERTm("the framing must follow the body's length, not the upstream's",
            repacked.wire_len < forwarded);
    PASS();
}

/* Catches: an upstream path that bypasses the socket ops, or a mark set on the common upstream's socket. */
TEST every_upstream_socket_goes_through_the_ops(void) {
    rec_reset();
    g_live_ops = &REC_OPS;
    live_t lv;
    ASSERT(live_start_retrying(&lv));
    ASSERT_EQ(1, ask(lv.proxy_port, 0x4101));
    ASSERT_EQ(1, atomic_load(&g_rec.opens));
    ASSERT_EQ(1, atomic_load(&g_rec.connects));
    ASSERT_EQ(1, atomic_load(&g_rec.sends));
    ASSERT_EQ(0, atomic_load(&g_rec.marks));
    ASSERT_EQ(1, ask(lv.proxy_port, 0x4102));
    ASSERT_EQ(1, atomic_load(&g_rec.opens));
    ASSERT_EQ(2, atomic_load(&g_rec.sends));
    live_stop(&lv);
    PASS();
}

/* Catches: a failed common-upstream open swallowed, so the proxy sends on fd -1. */
TEST a_common_upstream_that_cannot_open_is_no_answer(void) {
    rec_reset();
    atomic_store(&g_rec.fail_open, EMFILE);
    g_live_ops = &REC_OPS;
    live_t lv;
    ASSERT(live_start_retrying(&lv));
    ASSERT_EQ(-1, ask(lv.proxy_port, 0x4103));
    ASSERT_EQ(0, atomic_load(&g_rec.sends));
    ASSERT_EQ(0, (int)inflight_settled(lv.proxy, 0));
    live_stop(&lv);
    PASS();
}

/* Catches: the TCP upstream branch opening or connecting its socket outside the socket ops. */
TEST a_tcp_upstream_socket_goes_through_the_ops(void) {
    rec_reset();
    g_live_ops = &REC_OPS;
    live_t lv;
    ASSERT(live_start_retrying(&lv));
    ASSERT_EQ(-1, ask_tcp(lv.proxy_port, 0x4105));
    ASSERT_EQ(1, atomic_load(&g_rec.opens));
    ASSERT_EQ(1, atomic_load(&g_rec.connects));
    ASSERT_EQ(0, atomic_load(&g_rec.marks));
    live_stop(&lv);
    PASS();
}

static void tunnel_setup(uint16_t port) {
    rec_reset();
    memset(&g_troute, 0, sizeof(g_troute));
    g_troute.take = true;
    g_troute.mark = 0x40010000u;
    g_troute.n = 1;
    g_troute.ports[0] = port;
    g_live_ops = &REC_OPS;
    g_live_route = &g_troute;
}

/* Catches: a routed query sent to the common upstream, unmarked, marked wrongly, or marked after connect. */
TEST an_owned_covered_query_goes_through_the_tunnel(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x5101));
    ASSERT_EQ(1, atomic_load(&g_rec.marks));
    ASSERT_EQ(0x40010000u, atomic_load(&g_rec.last_mark));
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    ASSERT_EQ(1, atomic_load(&g_troute.saw_client));
    live_stop(&lv);
    PASS();
}

static uint64_t live_fallbacks(live_t *lv);

/* Catches: a tunnel datagram with another id or question delivered, or taken for a failure. */
TEST a_tunnel_datagram_that_answers_another_query_is_ignored(void) {
    for (int kind = 1; kind <= 2; kind++) {
        live_t lv;
        tunnel_setup(0);
        ASSERT(live_start_retrying(&lv));
        g_troute.ports[0] = lv.b.port;
        atomic_store(&lv.b.decoy_first, kind);
        ASSERT_EQm(kind == 1 ? "wrong id" : "wrong question", 2,
                   ask(lv.proxy_port, (uint16_t)(0x5190 + kind)));
        ASSERT_EQ(1, atomic_load(&g_rec.opens));
        ASSERT_EQ(1, atomic_load(&g_rec.marks));
        ASSERT_EQ(0, atomic_load(&lv.a.received));
        ASSERT_EQ(0u, live_fallbacks(&lv));
        live_stop(&lv);
    }
    PASS();
}

/* Catches: a late or spoofed datagram on a pooled common socket answering the next query. */
TEST a_common_datagram_that_answers_another_query_is_ignored(void) {
    for (int kind = 1; kind <= 2; kind++) {
        live_t lv;
        tunnel_setup(0);
        g_troute.take = false;
        ASSERT(live_start_retrying(&lv));
        atomic_store(&lv.a.decoy_first, kind);
        ASSERT_EQm(kind == 1 ? "wrong id" : "wrong question", 1,
                   ask(lv.proxy_port, (uint16_t)(0x51a0 + kind)));
        ASSERT_EQ(1, atomic_load(&g_rec.opens));
        ASSERT_EQ(1, atomic_load(&lv.a.received));
        live_stop(&lv);
    }
    PASS();
}

/* Catches: a query the router declines being marked or sent to a tunnel resolver. */
TEST a_query_the_router_declines_goes_to_the_common_upstream(void) {
    live_t lv;
    tunnel_setup(0);
    g_troute.take = false;
    ASSERT(live_start_retrying(&lv));
    ASSERT_EQ(1, ask(lv.proxy_port, 0x5102));
    ASSERT_EQ(1, atomic_load(&g_troute.asked));
    ASSERT_EQ(0, atomic_load(&g_rec.marks));
    ASSERT_EQ(0, atomic_load(&lv.b.received));
    live_stop(&lv);
    PASS();
}

/* Catches: a socket whose mark failed still used (the query leaves by the WAN), or no fallback. */
TEST a_mark_that_cannot_be_set_is_never_used(void) {
    live_t lv;
    tunnel_setup(0);
    atomic_store(&g_rec.fail_mark, EPERM);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(1, ask(lv.proxy_port, 0x5103));
    ASSERT_EQ(1, atomic_load(&g_rec.marks));
    ASSERT_EQ(0, atomic_load(&g_rec.connects_marked));
    ASSERT_EQ(0, atomic_load(&lv.b.received));
    ASSERT_EQ(1, atomic_load(&lv.a.received));
    live_stop(&lv);
    PASS();
}

/* Catches: an open, connect or send failure on the tunnel leg ending the exchange instead of falling back. */
TEST a_tunnel_that_cannot_start_falls_back(void) {
    for (int which = 0; which < 3; which++) {
        live_t lv;
        tunnel_setup(0);
        if (which == 0) { atomic_store(&g_rec.fail_open_next, EMFILE); }
        if (which == 1) { atomic_store(&g_rec.fail_connect, ENETUNREACH); }
        if (which == 2) { atomic_store(&g_rec.fail_send, EPERM); }
        ASSERT(live_start_retrying(&lv));
        g_troute.ports[0] = lv.b.port;
        ASSERT_EQm(which == 0 ? "open" : which == 1 ? "connect" : "send", 1,
                   ask(lv.proxy_port, (uint16_t)(0x5110 + which)));
        ASSERT_EQ(0, atomic_load(&lv.b.received));
        ASSERT_EQ(which == 0 ? 0 : 1, atomic_load(&g_rec.marks));
        ASSERT_EQ(0, (int)inflight_settled(lv.proxy, 0));
        live_stop(&lv);
    }
    PASS();
}

/* Catches: a refused tunnel resolver waited out to its timeout instead of falling back at once. */
TEST a_tunnel_resolver_that_refuses_falls_back_at_once(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = closed_udp_port();
    ASSERT(g_troute.ports[0] != 0);
    long t0 = ms_now();
    ASSERT_EQ(1, ask(lv.proxy_port, 0x5104));
    ASSERT_LT(ms_now() - t0, 700);
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    live_stop(&lv);
    PASS();
}

/* Catches: a silent tunnel resolver holding the client for the whole deadline, or no fallback. */
TEST a_silent_tunnel_resolver_falls_back_after_the_tunnel_timeout(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    long t0 = ms_now();
    ASSERT_EQ(1, ask(lv.proxy_port, 0x5105));
    long took = ms_now() - t0;
    ASSERT_GTE(took, (long)FIRC_DNSPROXY_TUNNEL_TIMEOUT_MS - 50);
    ASSERT_LT(took, 2000);
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    atomic_store(&lv.b.go, 1);
    live_stop(&lv);
    PASS();
}

/* Catches: an unusable tunnel answer kept, NXDOMAIN refused, or a pool bounds check off by one bit, the cache on or off. */
TEST each_unusable_tunnel_answer_falls_back(void) {
    struct {
        const char *what;
        int rcode;
        bool a_set;
        uint32_t a_ip;
        bool aaaa_loopback;
        bool garbage;
        bool aaaa_custom_set;
        uint64_t aaaa_hi;
        uint64_t aaaa_lo;
        bool second_a_sink;
        int want;
    } cases[] = {
        {"servfail", 2, false, 0, false, false, false, 0, 0, false, 1},
        {"refused", 5, false, 0, false, false, false, 0, 0, false, 1},
        {"0.0.0.0", 0, true, 0x00000000u, false, false, false, 0, 0, false, 1},
        {"127.0.0.2", 0, true, 0x7f000002u, false, false, false, 0, 0, false, 1},
        {"pool 198.19.255.1", 0, true, 0xc613ff01u, false, false, false, 0, 0, false, 1},
        {"::1", 0, false, 0, true, false, false, 0, 0, false, 1},
        {"not dns", 0, false, 0, false, true, false, 0, 0, false, 1},
        {"198.17.255.255 is just below the pool", 0, true, 0xc611ffffu, false, false, false, 0, 0, false, 255},
        {"198.20.0.5 is just above the pool", 0, true, 0xc6140005u, false, false, false, 0, 0, false, 5},
        {"nxdomain", 3, false, 0, false, false, false, 0, 0, false, 2},
        {"aaaa fd00:1234::1 is inside the pool", 0, false, 0, false, false, true, 0xfd00123400000000ULL, 1ULL,
         false, 1},
        {"aaaa fd00:1235::1 is just outside the pool", 0, false, 0, false, false, true, 0xfd00123500000000ULL,
         1ULL, false, 2},
        {"a sink second A record after a good first one", 0, false, 0, false, false, false, 0, 0, true, 1},
    };
    for (int cached = 0; cached < 2; cached++) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            live_t lv;
            tunnel_setup(0);
            g_live_cache = cached != 0;
            ASSERT(live_start_retrying(&lv));
            g_troute.ports[0] = lv.b.port;
            atomic_store(&lv.b.rcode, cases[i].rcode);
            atomic_store(&lv.b.a_set, cases[i].a_set ? 1 : 0);
            atomic_store(&lv.b.a_ip, cases[i].a_ip);
            atomic_store(&lv.b.aaaa_loopback, cases[i].aaaa_loopback ? 1 : 0);
            atomic_store(&lv.b.garbage, cases[i].garbage ? 1 : 0);
            atomic_store(&lv.b.aaaa_custom_set, cases[i].aaaa_custom_set ? 1 : 0);
            atomic_store(&lv.b.aaaa_hi, cases[i].aaaa_hi);
            atomic_store(&lv.b.aaaa_lo, cases[i].aaaa_lo);
            atomic_store(&lv.b.second_a_sink, cases[i].second_a_sink ? 1 : 0);
            int got = ask(lv.proxy_port, (uint16_t)(0x6100 + i));
            ASSERT_EQm(cases[i].what, cases[i].want, got);
            ASSERT_EQm(cases[i].what, cases[i].want == 1 ? 1 : 0, atomic_load(&lv.a.received));
            ASSERT_EQm(cases[i].what, 1, atomic_load(&lv.b.received));
            live_stop(&lv);
        }
    }
    PASS();
}

/* Catches: a fallback armed with a fresh window instead of what remains of the deadline. */
TEST the_fallback_gets_what_remains_of_the_deadline(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.a.hold, 1);
    atomic_store(&lv.b.hold, 1);
    long t0 = ms_now();
    int c = ask_send(lv.proxy_port, 0x6201);
    ASSERT(c >= 0);
    while (firc_dnsproxy_inflight(lv.proxy) == 0 && ms_now() - t0 < 1000) {
        struct timespec ts5 = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts5, NULL);
    }
    while (firc_dnsproxy_inflight(lv.proxy) != 0 && ms_now() - t0 < 6000) {
        struct timespec ts10 = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&ts10, NULL);
    }
    long took = ms_now() - t0;
    close(c);
    ASSERT_GTE(took, 2900);
    ASSERT_LT(took, 3500);
    ASSERT_EQ(1, atomic_load(&lv.a.received));
    atomic_store(&lv.a.go, 1);
    atomic_store(&lv.b.go, 1);
    live_stop(&lv);
    PASS();
}

/* Catches: a short deadline leaving the fallback less than its floor, or the tunnel leg the whole of it. */
TEST a_short_deadline_still_leaves_the_fallback_its_floor(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_timeout_ms = 800;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    atomic_store(&lv.a.hold_ms, 150);
    long t0 = ms_now();
    ASSERT_EQ(1, ask(lv.proxy_port, 0x6202));
    long took = ms_now() - t0;
    ASSERT_GTE(took, 620);
    ASSERT_LT(took, 850);
    atomic_store(&lv.b.go, 1);
    live_stop(&lv);
    PASS();
}

/* Catches: the TCP tunnel leg skipping the mark or framing the request twice. */
TEST a_tcp_query_goes_through_the_tunnel_over_tcp(void) {
    xopts_t o;
    memset(&o, 0, sizeof(o));
    o.over_tcp = true;
    o.tunnel = true;
    reply_t out;
    memset(&out, 0, sizeof(out));
    int hook_calls = 0;
    int rc = run_exchange(&o, &out, &hook_calls);
    if (rc == -2) { SKIPm("could not bind the harness's ports"); }
    ASSERT_EQ(0, rc);
    ASSERT(out.saw_a);
    ASSERT_EQ(3, out.a[3]);
    ASSERT_EQ(1, atomic_load(&g_rec.marks));
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    PASS();
}

/* Catches: a TCP fallback that frames the request a second time, or is not tried. */
TEST a_tcp_query_that_falls_back_is_framed_once(void) {
    xopts_t o;
    memset(&o, 0, sizeof(o));
    o.over_tcp = true;
    o.tunnel = true;
    o.tunnel_fail_connect = ENETUNREACH;
    reply_t out;
    memset(&out, 0, sizeof(out));
    int hook_calls = 0;
    int rc = run_exchange(&o, &out, &hook_calls);
    if (rc == -2) { SKIPm("could not bind the harness's ports"); }
    ASSERT_EQ(0, rc);
    ASSERT(out.saw_a);
    ASSERT_EQ(3, out.a[3]);
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    ASSERT_EQ(2, atomic_load(&g_rec.connects));
    PASS();
}

/* Catches: a zero TCP length prefix from the tunnel dropping the exchange instead of falling back. */
TEST a_tcp_tunnel_answer_with_a_bad_length_prefix_falls_back(void) {
    xopts_t o;
    memset(&o, 0, sizeof(o));
    o.over_tcp = true;
    o.tunnel = true;
    o.tunnel_bad_len = true;
    reply_t out;
    memset(&out, 0, sizeof(out));
    int hook_calls = 0;
    int rc = run_exchange(&o, &out, &hook_calls);
    if (rc == -2) { SKIPm("could not bind the harness's ports"); }
    ASSERT_EQ(0, rc);
    ASSERT(out.saw_a);
    ASSERT_EQ(3, out.a[3]);
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    ASSERT_EQ(2, atomic_load(&g_rec.connects));
    PASS();
}

/* Catches: the sink-answer check reached only from the UDP path. */
TEST a_tcp_tunnel_sink_answer_falls_back(void) {
    xopts_t o;
    memset(&o, 0, sizeof(o));
    o.over_tcp = true;
    o.tunnel = true;
    o.tunnel_sink_a = true;
    reply_t out;
    memset(&out, 0, sizeof(out));
    int hook_calls = 0;
    int rc = run_exchange(&o, &out, &hook_calls);
    if (rc == -2) { SKIPm("could not bind the harness's ports"); }
    ASSERT_EQ(0, rc);
    ASSERT(out.saw_a);
    ASSERT_EQ(3, out.a[3]);
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    ASSERT_EQ(2, atomic_load(&g_rec.connects));
    PASS();
}

/* Catches: a TCP tunnel answer with another id delivered, ending the exchange, or ignored until timeout. */
TEST a_tcp_tunnel_answer_with_another_id_falls_back(void) {
    xopts_t o;
    memset(&o, 0, sizeof(o));
    o.over_tcp = true;
    o.tunnel = true;
    o.tunnel_wrong_id = true;
    reply_t out;
    memset(&out, 0, sizeof(out));
    int hook_calls = 0;
    long t0 = ms_now();
    int rc = run_exchange(&o, &out, &hook_calls);
    long took = ms_now() - t0;
    if (rc == -2) { SKIPm("could not bind the harness's ports"); }
    ASSERT_EQ(0, rc);
    ASSERT(out.saw_a);
    ASSERTm("fell back at once", took < 700);
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    ASSERT_EQ(2, atomic_load(&g_rec.connects));
    PASS();
}

#define BIG_TXT_RECORDS 230
typedef struct {
    int lfd;
    uint16_t port;
    pthread_t th;
} big_stub_t;

static void *big_stub_serve(void *arg) {
    big_stub_t *s = arg;
    int c = accept(s->lfd, NULL, NULL);
    if (c < 0) { return NULL; }
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    uint8_t hdr[2], q[512];
    size_t qlen = 0;
    if (recv(c, hdr, 2, MSG_WAITALL) == 2) { qlen = ((size_t)hdr[0] << 8) | hdr[1]; }
    if (qlen == 0 || qlen > sizeof(q) || recv(c, q, qlen, MSG_WAITALL) != (ssize_t)qlen) {
        close(c);
        return NULL;
    }
    size_t qd_end = 12;
    while (qd_end < qlen && q[qd_end] != 0) { qd_end += 1 + q[qd_end]; }
    qd_end += 1 + 4;
    uint8_t *a = calloc(1, 2 + 65535);
    if (a == NULL || qd_end > qlen) {
        free(a);
        close(c);
        return NULL;
    }
    uint8_t *m = a + 2;
    memcpy(m, q, qd_end);
    m[2] = 0x81;
    m[3] = 0x80;
    m[6] = 0;
    m[7] = BIG_TXT_RECORDS;
    m[10] = 0;
    m[11] = 0;
    size_t p = qd_end;
    for (int i = 0; i < BIG_TXT_RECORDS; i++) {
        const uint8_t rr[] = {0xc0, 0x0c, 0x00, 16 , 0x00, 0x01, 0, 0, 0x01, 0x2c, 0x01, 0x00, 255};
        memcpy(m + p, rr, sizeof(rr));
        p += sizeof(rr);
        memset(m + p, 'a' + i % 26, 255);
        p += 255;
    }
    a[0] = (uint8_t)(p >> 8);
    a[1] = (uint8_t)p;
    (void)send(c, a, p + 2, MSG_NOSIGNAL);
    free(a);
    while (recv(c, hdr, sizeof(hdr), 0) > 0) {}
    close(c);
    return NULL;
}

static bool big_stub_start(big_stub_t *s) {
    memset(s, 0, sizeof(*s));
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->lfd < 0) { return false; }
    if (!bind_loopback(s->lfd, 0, &s->port) || listen(s->lfd, 1) != 0 ||
        pthread_create(&s->th, NULL, big_stub_serve, s) != 0) {
        close(s->lfd);
        return false;
    }
    return true;
}

/* Gives the proxy's TCP listener a small locked send buffer, so a write to a slow client stays pending. */
static bool shrink_listener_sndbuf(uint16_t port) {
    for (int fd = 3; fd < 1024; fd++) {
        int type = 0, listening = 0;
        socklen_t l = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &l) != 0 || type != SOCK_STREAM) { continue; }
        l = sizeof(listening);
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &l) != 0 || !listening) { continue; }
        struct sockaddr_in sa;
        socklen_t sl = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *)&sa, &sl) != 0 || sa.sin_family != AF_INET ||
            ntohs(sa.sin_port) != port) {
            continue;
        }
        int sndbuf = 4096;
        return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == 0;
    }
    return false;
}

/* Catches: the tunnel timer firing during a slow client's write and starting a fallback. */
TEST a_tunnel_answer_the_client_reads_slowly_is_not_asked_again(void) {
    big_stub_t big;
    ASSERT(big_stub_start(&big));
    live_t lv;
    tunnel_setup(big.port);
    ASSERT(live_start_retrying(&lv));
    ASSERT(shrink_listener_sndbuf(lv.proxy_port));

    int c = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT(c >= 0);
    int rcvbuf = 1024;
    setsockopt(c, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in pa;
    memset(&pa, 0, sizeof(pa));
    pa.sin_family = AF_INET;
    pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    pa.sin_port = htons(lv.proxy_port);
    ASSERT_EQ(0, connect(c, (struct sockaddr *)&pa, sizeof(pa)));
    uint8_t q[512], framed[514];
    size_t qlen = build_query(q, 0x5120, 0);
    framed[0] = (uint8_t)(qlen >> 8);
    framed[1] = (uint8_t)qlen;
    memcpy(framed + 2, q, qlen);
    ASSERT_EQ((ssize_t)(qlen + 2), send(c, framed, qlen + 2, MSG_NOSIGNAL));

    struct timespec pause = {.tv_sec = 1, .tv_nsec = 300 * 1000000L};
    nanosleep(&pause, NULL);

    uint8_t hdr[2];
    ASSERT_EQ(2, recv(c, hdr, 2, MSG_WAITALL));
    size_t want = ((size_t)hdr[0] << 8) | hdr[1];
    uint8_t *r = malloc(65535);
    ASSERT(r != NULL);
    ssize_t got = recv(c, r, want, MSG_WAITALL);
    uint8_t extra;
    ssize_t more = recv(c, &extra, 1, 0);
    close(c);
    firc_dns_msg_t *msg = NULL;
    bool parsed = got == (ssize_t)want && firc_dns_msg_parse(r, want, &msg) == FIRC_OK;
    size_t n_answers = parsed ? msg->n_answers : 0;
    firc_dns_msg_free(msg);
    free(r);

    int opens = atomic_load(&g_rec.opens), connects = atomic_load(&g_rec.connects);
    live_stop(&lv);
    pthread_join(big.th, NULL);
    close(big.lfd);

    ASSERT_EQm("the common upstream was opened", 1, opens);
    ASSERT_EQm("the common upstream was connected", 1, connects);
    ASSERTm("one whole answer", parsed);
    ASSERT_EQ((size_t)BIG_TXT_RECORDS, n_answers);
    ASSERT_EQ(0, more);
    PASS();
}

typedef struct {
    firc_dnsproxy_t *proxy;
    firc_id_t id;
    _Atomic uint64_t out;
    _Atomic int done;
} fb_t;

static void fallbacks_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    fb_t *f = ud;
    atomic_store(&f->out, firc_dnsproxy_group_fallbacks(f->proxy, f->id));
    atomic_store(&f->done, 1);
}

/* The proxy's counters are loop state, so they are read on the loop. */
static uint64_t live_fallbacks(live_t *lv) {
    fb_t f = {.proxy = lv->proxy};
    f.id.b[3] = 7;
    if (firc_loop_post(lv->loop, fallbacks_on_loop, &f) != FIRC_OK) { return UINT64_MAX; }
    for (int i = 0; i < 200 && !atomic_load(&f.done); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return atomic_load(&f.out);
}

/* Catches: an unreachable resolver failing a query another resolver of the group answers. */
TEST an_unreachable_resolver_beside_a_working_one_costs_nothing(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.n = 2;
    g_troute.ports[0] = closed_udp_port();
    g_troute.ports[1] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x7101));
    ASSERT_EQ(2, ask(lv.proxy_port, 0x7102));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    ASSERT_EQ(0u, live_fallbacks(&lv));
    live_stop(&lv);
    PASS();
}

static int g_log_pipe[2] = {-1, -1};
static firc_log_level_t g_log_prev_level;

/* Sends everything logged at INFO and above to a pipe. */
static void log_capture_start(void) {
    if (pipe(g_log_pipe) != 0) { return; }
    fcntl(g_log_pipe[0], F_SETFL, O_NONBLOCK);
    g_log_prev_level = firc_log_level();
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(g_log_pipe[1]);
}

static int occurrences(const char *hay, const char *needle) {
    int count = 0;
    for (const char *at = hay; (at = strstr(at, needle)) != NULL; at += strlen(needle)) { count++; }
    return count;
}

/* Stops the capture, restores the log level, and counts two phrases in what was logged. */
static void log_capture_counts(const char *a, int *na, const char *b, int *nb) {
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_level(g_log_prev_level);
    close(g_log_pipe[1]);
    static char buf[65536];
    ssize_t n = read(g_log_pipe[0], buf, sizeof(buf) - 1);
    close(g_log_pipe[0]);
    buf[n > 0 ? n : 0] = '\0';
    *na = occurrences(buf, a);
    *nb = occurrences(buf, b);
}

TEST the_health_gate_rests_a_failing_group_and_probes_once(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_rest_ms = 300;
    log_capture_start();
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask(lv.proxy_port, (uint16_t)(0x7200 + i))); }
    ASSERT_EQ(3, atomic_load(&g_rec.marks));
    ASSERT_EQ(1, ask(lv.proxy_port, 0x7203));
    ASSERT_EQm("resting: no tunnel attempt", 3, atomic_load(&g_rec.marks));

    struct timespec rest_wait1 = {.tv_sec = 0, .tv_nsec = 350 * 1000000L};
    nanosleep(&rest_wait1, NULL);
    ASSERT_EQ(1, ask(lv.proxy_port, 0x7204));
    ASSERT_EQ(4, atomic_load(&g_rec.marks));
    ASSERT_EQ(1, ask(lv.proxy_port, 0x7205));
    ASSERT_EQm("a failed probe rests again", 4, atomic_load(&g_rec.marks));

    g_troute.ports[0] = lv.b.port;
    struct timespec rest_wait2 = {.tv_sec = 0, .tv_nsec = 350 * 1000000L};
    nanosleep(&rest_wait2, NULL);
    ASSERT_EQ(2, ask(lv.proxy_port, 0x7206));
    ASSERT_EQ(2, ask(lv.proxy_port, 0x7207));
    ASSERT_EQm("0x7207 reuses the probe's socket", 5, atomic_load(&g_rec.marks));
    ASSERT_EQm("both went to the resolver", 2, atomic_load(&lv.b.received));
    ASSERT_EQ(6u, live_fallbacks(&lv));
    live_stop(&lv);
    int warned = 0, reopened = 0;
    log_capture_counts("consecutive failures", &warned, "answering again", &reopened);
    ASSERT_EQm("one warning for the closing, none for the failed probe", 1, warned);
    ASSERT_EQm("one line for the opening", 1, reopened);
    PASS();
}

/* Catches: an exchange re-reading the router mid-flight instead of finishing on its copied route. */
TEST a_publish_mid_exchange_keeps_the_copied_route(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0x7301);
    ASSERT(c >= 0);
    for (int i = 0; i < 100 && atomic_load(&lv.b.received) == 0; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    g_troute.take = false;
    g_troute.ports[0] = closed_udp_port();
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    live_stop(&lv);
    PASS();
}

/* Catches: a late tunnel answer delivered as well as, or instead of, the fallback's. */
TEST a_late_tunnel_answer_is_not_delivered_after_the_fallback(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0x7401);
    ASSERT(c >= 0);
    uint8_t r[2048];
    ssize_t n = recv(c, r, sizeof(r), 0);
    ASSERT(n > 0);
    ASSERT_EQ(1, r[STUB_A_LAST_OCTET]);
    atomic_store(&lv.b.go, 1);
    struct timeval tv = {.tv_sec = 0, .tv_usec = 400000};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ASSERT_EQm("one answer, not two", -1, (int)recv(c, r, sizeof(r), 0));
    close(c);
    live_stop(&lv);
    PASS();
}

/* Catches: a stale generation's failure resetting the health of the newer generation of its group. */
TEST a_stale_generations_failure_does_not_reopen_a_newer_generations_gate(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));

    g_troute.gen = 1;
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c1 = ask_send(lv.proxy_port, 0x7501);
    ASSERT(c1 >= 0);
    for (int i = 0; i < 200 && atomic_load(&lv.b.received) == 0; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    ASSERT_EQ(1, atomic_load(&g_rec.marks));

    g_troute.gen = 2;
    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask(lv.proxy_port, (uint16_t)(0x7510 + i))); }
    ASSERT_EQ(4, atomic_load(&g_rec.marks));

    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c1));

    ASSERT_EQ(1, ask(lv.proxy_port, 0x7520));
    ASSERT_EQm("gen 2's gate must still be closed", 4, atomic_load(&g_rec.marks));
    ASSERT_EQ(4u, live_fallbacks(&lv));
    live_stop(&lv);
    PASS();
}

/* Catches: a stale generation's probe ending and clearing the newer generation's probe flag. */
TEST a_stale_generations_probe_ending_does_not_clear_a_newer_generations_probing(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_rest_ms = 300;
    ASSERT(live_start_retrying(&lv));

    g_troute.gen = 1;
    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask(lv.proxy_port, (uint16_t)(0x7530 + i))); }
    ASSERT_EQ(3, atomic_load(&g_rec.marks));
    struct timespec rw1 = {.tv_sec = 0, .tv_nsec = 350 * 1000000L};
    nanosleep(&rw1, NULL);
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c1 = ask_send(lv.proxy_port, 0x7540);
    ASSERT(c1 >= 0);
    for (int i = 0; i < 200 && atomic_load(&lv.b.received) == 0; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    ASSERT_EQ(4, atomic_load(&g_rec.marks));

    g_troute.gen = 2;
    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask(lv.proxy_port, (uint16_t)(0x7550 + i))); }
    ASSERT_EQ(7, atomic_load(&g_rec.marks));
    struct timespec rw2 = {.tv_sec = 0, .tv_nsec = 350 * 1000000L};
    nanosleep(&rw2, NULL);

    int blackhole = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(blackhole >= 0);
    uint16_t bh_port = 0;
    ASSERT(bind_loopback(blackhole, 0, &bh_port));
    g_troute.ports[0] = bh_port;
    int c2 = ask_send(lv.proxy_port, 0x7560);
    ASSERT(c2 >= 0);
    for (int i = 0; i < 200 && atomic_load(&g_rec.marks) < 8; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(8, atomic_load(&g_rec.marks));

    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c1));

    ASSERT_EQ(1, ask(lv.proxy_port, 0x7570));
    ASSERT_EQm("gen 2's one probe is still out: no second one", 8, atomic_load(&g_rec.marks));

    uint8_t drain[512];
    struct timeval dtv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(c2, SOL_SOCKET, SO_RCVTIMEO, &dtv, sizeof(dtv));
    ssize_t drained = recv(c2, drain, sizeof(drain), 0);
    ASSERT(drained > 0);

    close(blackhole);
    close(c2);
    live_stop(&lv);
    PASS();
}

/* Catches: a second query let through to the tunnel while a probe is still in flight. */
TEST only_one_query_probes_at_a_time(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_rest_ms = 300;
    ASSERT(live_start_retrying(&lv));

    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask(lv.proxy_port, (uint16_t)(0x7600 + i))); }
    ASSERT_EQ(3, atomic_load(&g_rec.marks));
    struct timespec rw = {.tv_sec = 0, .tv_nsec = 350 * 1000000L};
    nanosleep(&rw, NULL);

    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c1 = ask_send(lv.proxy_port, 0x7610);
    ASSERT(c1 >= 0);
    for (int i = 0; i < 200 && atomic_load(&lv.b.received) == 0; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    ASSERT_EQ(4, atomic_load(&g_rec.marks));

    ASSERT_EQ(1, ask(lv.proxy_port, 0x7611));
    ASSERT_EQm("no second probe: no new mark or tunnel open", 4, atomic_load(&g_rec.marks));

    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c1));
    live_stop(&lv);
    PASS();
}

/* Catches: a success not clearing the failure count, so one later failure closes the gate. */
TEST a_success_clears_the_failure_count(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));

    g_troute.ports[0] = closed_udp_port();
    ASSERT_EQ(1, ask(lv.proxy_port, 0x7620));
    ASSERT_EQ(1, ask(lv.proxy_port, 0x7621));
    ASSERT_EQ(2, atomic_load(&g_rec.marks));

    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x7622));
    ASSERT_EQ(3, atomic_load(&g_rec.marks));

    g_troute.ports[0] = closed_udp_port();
    ASSERT_EQ(1, ask(lv.proxy_port, 0x7623));
    ASSERT_EQ(4, atomic_load(&g_rec.marks));

    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x7624));
    ASSERT_EQm("the earlier success reset the count: the gate never closed", 2,
              atomic_load(&lv.b.received));
    ASSERT_EQ(4, atomic_load(&g_rec.marks));
    live_stop(&lv);
    PASS();
}

/* Catches: a gate closed on one generation carried into the next. */
TEST a_new_generation_starts_health_afresh(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));

    g_troute.gen = 1;
    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask(lv.proxy_port, (uint16_t)(0x7640 + i))); }
    ASSERT_EQ(3, atomic_load(&g_rec.marks));
    ASSERT_EQ(1, ask(lv.proxy_port, 0x7643));
    ASSERT_EQ(3, atomic_load(&g_rec.marks));

    g_troute.gen = 2;
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x7650));
    ASSERT_EQm("a new generation must not inherit gen 1's rest", 4, atomic_load(&g_rec.marks));
    live_stop(&lv);
    PASS();
}

typedef struct {
    _Atomic int received;
    _Atomic int go;
} tcp_probe_t;
static tcp_probe_t g_tcp_probe;

static void *tcp_probe_conn(void *arg) {
    int c = (int)(intptr_t)arg;
    uint8_t hdr[2];
    if (recv(c, hdr, 2, MSG_WAITALL) == 2) {
        size_t qlen = ((size_t)hdr[0] << 8) | hdr[1];
        uint8_t q[512];
        if (qlen <= sizeof(q) && recv(c, q, qlen, MSG_WAITALL) == (ssize_t)qlen) {
            atomic_fetch_add(&g_tcp_probe.received, 1);
            while (!atomic_load(&g_tcp_probe.go)) {
                struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
                nanosleep(&ts, NULL);
            }
            uint8_t a[STUB_BUF];
            size_t alen = build_answer(q, qlen, a);
            uint8_t framed[STUB_BUF + 2];
            framed[0] = (uint8_t)(alen >> 8);
            framed[1] = (uint8_t)alen;
            memcpy(framed + 2, a, alen);
            send(c, framed, alen + 2, MSG_NOSIGNAL);
        }
    }
    close(c);
    return NULL;
}

static void tcp_probe_on_accept(firc_loop_t *loop, int fd, uint32_t events, void *ud) {
    (void)loop;
    (void)events;
    (void)ud;
    int c = accept(fd, NULL, NULL);
    if (c < 0) { return; }
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    pthread_t th;
    if (pthread_create(&th, NULL, tcp_probe_conn, (void *)(intptr_t)c) != 0) {
        close(c);
        return;
    }
    pthread_detach(th);
}

typedef struct {
    int lfd;
    _Atomic int done;
} tcp_probe_listen_t;

static void tcp_probe_add_listener(firc_loop_t *loop, void *ud) {
    tcp_probe_listen_t *s = ud;
    firc_loop_add_fd(loop, s->lfd, EPOLLIN, tcp_probe_on_accept, NULL);
    atomic_store(&s->done, 1);
}

/* Binds a TCP listener and registers it on the running loop via a post; the caller closes `*lfd_out`. */
static uint16_t tcp_probe_listen(firc_loop_t *loop, int *lfd_out) {
    memset(&g_tcp_probe, 0, sizeof(g_tcp_probe));
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { return 0; }
    uint16_t port = 0;
    if (!bind_loopback(lfd, 0, &port) || listen(lfd, 4) != 0) {
        close(lfd);
        return 0;
    }
    tcp_probe_listen_t s = {.lfd = lfd};
    if (firc_loop_post(loop, tcp_probe_add_listener, &s) != FIRC_OK) {
        close(lfd);
        return 0;
    }
    for (int i = 0; i < 200 && !atomic_load(&s.done); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
    *lfd_out = lfd;
    return port;
}

/* Catches: a probe ending without a verdict leaving the gate shut for ever. */
TEST a_probe_that_ends_without_a_verdict_frees_the_probe_slot(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_rest_ms = 300;
    ASSERT(live_start_retrying(&lv));

    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask(lv.proxy_port, (uint16_t)(0x7700 + i))); }
    ASSERT_EQ(3, atomic_load(&g_rec.marks));
    struct timespec rw = {.tv_sec = 0, .tv_nsec = 350 * 1000000L};
    nanosleep(&rw, NULL);

    int probe_lfd = -1;
    uint16_t probe_port = tcp_probe_listen(lv.loop, &probe_lfd);
    ASSERT(probe_port != 0);
    g_troute.ports[0] = probe_port;

    int c = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT(c >= 0);
    struct sockaddr_in pa;
    memset(&pa, 0, sizeof(pa));
    pa.sin_family = AF_INET;
    pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    pa.sin_port = htons(lv.proxy_port);
    ASSERT_EQ(0, connect(c, (struct sockaddr *)&pa, sizeof(pa)));
    uint8_t q[512];
    size_t qlen = build_query(q, 0x7710, 0);
    uint8_t framed[514];
    framed[0] = (uint8_t)(qlen >> 8);
    framed[1] = (uint8_t)qlen;
    memcpy(framed + 2, q, qlen);
    ASSERT_EQ((ssize_t)(qlen + 2), send(c, framed, qlen + 2, MSG_NOSIGNAL));

    for (int i = 0; i < 200 && atomic_load(&g_tcp_probe.received) == 0; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(1, atomic_load(&g_tcp_probe.received));
    ASSERT_EQ(4, atomic_load(&g_rec.marks));

    struct linger lg = {.l_onoff = 1, .l_linger = 0};
    setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    close(c);
    struct timespec settle = {.tv_sec = 0, .tv_nsec = 100 * 1000000L};
    nanosleep(&settle, NULL);

    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x7720));
    ASSERT_EQm("the freed probe slot let the next query try the tunnel", 5,
              atomic_load(&g_rec.marks));

    atomic_store(&g_tcp_probe.go, 1);
    struct timespec drain = {.tv_sec = 0, .tv_nsec = 50 * 1000000L};
    nanosleep(&drain, NULL);
    close(probe_lfd);
    live_stop(&lv);
    PASS();
}

/* Catches: the callback given a constant source, or the failed leg instead of why it failed. */
TEST the_callback_is_told_where_each_answer_came_from(void) {
    struct { const char *what; bool take; int fail_mark; bool silent; int rcode; int want; } cases[] = {
        {"declined", false, 0, false, 0, FIRC_DNS_RESOLVER_UPSTREAM},
        {"tunnel", true, 0, false, 0, FIRC_DNS_RESOLVER_GROUP},
        {"mark refused", true, EPERM, false, 0, FIRC_DNS_RESOLVER_FALLBACK_UNREACHABLE},
        {"silent", true, 0, true, 0, FIRC_DNS_RESOLVER_FALLBACK_TIMEOUT},
        {"servfail", true, 0, false, 2, FIRC_DNS_RESOLVER_FALLBACK_SERVFAIL},
        {"refused", true, 0, false, 5, FIRC_DNS_RESOLVER_FALLBACK_REFUSED},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        live_t lv;
        tunnel_setup(0);
        g_troute.take = cases[i].take;
        atomic_store(&g_rec.fail_mark, cases[i].fail_mark);
        atomic_store(&g_live_resolver, -1);
        ASSERT(live_start_retrying(&lv));
        g_troute.ports[0] = lv.b.port;
        atomic_store(&lv.b.hold, cases[i].silent ? 1 : 0);
        atomic_store(&lv.b.rcode, cases[i].rcode);
        ASSERT(ask(lv.proxy_port, (uint16_t)(0x8100 + i)) > 0);
        ASSERT_EQm(cases[i].what, cases[i].want, atomic_load(&g_live_resolver));
        atomic_store(&lv.b.go, 1);
        live_stop(&lv);
    }
    PASS();
}

typedef struct {
    firc_dnsproxy_t *proxy;
    uint8_t group;
    bool forget;
    _Atomic int done;
} close_t;

static void close_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    close_t *c = ud;
    firc_id_t id = {{0}};
    id.b[3] = c->group;
    if (c->forget) {
        firc_dnsproxy_forget_group(c->proxy, id);
    } else {
        firc_dnsproxy_close_group_pools(c->proxy, id);
    }
    atomic_store(&c->done, 1);
}

static void live_group_call(live_t *lv, uint8_t group, bool forget) {
    close_t c = {.proxy = lv->proxy, .group = group, .forget = forget};
    if (firc_loop_post(lv->loop, close_on_loop, &c) != FIRC_OK) { return; }
    for (int i = 0; i < 200 && !atomic_load(&c.done); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
}

static void live_close_group(live_t *lv, uint8_t group) { live_group_call(lv, group, false); }
static void live_forget_group(live_t *lv, uint8_t group) { live_group_call(lv, group, true); }

/* Catches: tunnel sockets not pooled, shared between groups, or placed in the common pool. */
TEST idle_tunnel_sockets_are_pooled_per_group(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9101));
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9102));
    ASSERT_EQ(1, atomic_load(&g_rec.opens));
    g_troute.group = 8;
    g_troute.mark = 0x40020000u;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9103));
    ASSERT_EQ(2, atomic_load(&g_rec.opens));
    ASSERT_EQ(0x40020000u, atomic_load(&g_rec.last_mark));
    g_troute.take = false;
    ASSERT_EQ(1, ask(lv.proxy_port, 0x9104));
    ASSERT_EQ(3, atomic_load(&g_rec.opens));
    ASSERT_EQ(2, atomic_load(&g_rec.marks));
    live_stop(&lv);
    PASS();
}

/* Catches: a tunnel query taking the common pool's socket or another resolver's socket. */
TEST a_tunnel_query_never_takes_the_common_pool_or_another_resolvers_socket(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    g_troute.take = false;
    ASSERT_EQ(1, ask(lv.proxy_port, 0x9401));
    ASSERT_EQ(1, atomic_load(&g_rec.opens));
    g_troute.take = true;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9402));
    ASSERT_EQm("the tunnel opened its own", 2, atomic_load(&g_rec.opens));
    ASSERT_EQm("and marked it", 1, atomic_load(&g_rec.marks));

    g_troute.ports[0] = lv.a.port;
    ASSERT_EQ(1, ask(lv.proxy_port, 0x9403));
    ASSERT_EQm("another resolver, another socket", 3, atomic_load(&g_rec.opens));
    ASSERT_EQ(2, atomic_load(&g_rec.marks));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQm("B's socket is still B's", 2, ask(lv.proxy_port, 0x9404));
    ASSERT_EQ(3, atomic_load(&g_rec.opens));
    live_stop(&lv);
    PASS();
}

/* Catches: a group pool close missing an idle or in-flight socket, or touching another group. */
TEST closing_a_groups_pool_closes_idle_and_in_flight_sockets(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9201));
    live_close_group(&lv, 7);
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9202));
    ASSERT_EQm("the idle one was closed", 2, atomic_load(&g_rec.opens));

    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0x9203);
    ASSERT(c >= 0);
    for (int i = 0; i < 100 && atomic_load(&lv.b.received) < 3; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(3, atomic_load(&lv.b.received));
    ASSERT_EQm("0x9203 went out on the pooled socket", 2, atomic_load(&g_rec.opens));
    live_close_group(&lv, 7);
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c));
    atomic_store(&lv.b.hold, 0);
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9204));
    ASSERT_EQm("the in-flight one was not pooled", 3, atomic_load(&g_rec.opens));

    live_close_group(&lv, 9);
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9205));
    ASSERT_EQ(3, atomic_load(&g_rec.opens));
    live_stop(&lv);
    PASS();
}

/* Catches: a socket opened for one route generation handed to a query routed with the next. */
TEST a_new_generation_does_not_reuse_the_old_sockets(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9301));
    g_troute.gen = 2;
    g_troute.mark = 0x40050000u;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9302));
    ASSERT_EQ(2, atomic_load(&g_rec.opens));
    ASSERT_EQ(0x40050000u, atomic_load(&g_rec.last_mark));
    live_stop(&lv);
    PASS();
}

/* Catches: a socket released after a new generation returned to the pool with the old mark. */
TEST a_socket_of_an_older_generation_is_not_pooled_on_release(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0x9501);
    ASSERT(c >= 0);
    for (int i = 0; i < 100 && atomic_load(&lv.b.received) < 1; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    g_troute.gen = 2;
    g_troute.mark = 0x40050000u;
    int c2 = ask_send(lv.proxy_port, 0x9502);
    ASSERT(c2 >= 0);
    for (int i = 0; i < 100 && atomic_load(&g_rec.opens) < 2; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(2, atomic_load(&g_rec.opens));
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c));
    ASSERT_EQ(2, ask_read(c2));
    atomic_store(&lv.b.hold, 0);
    atomic_store(&lv.b.go, 0);
    atomic_store(&lv.b.hold, 1);
    int d1 = ask_send(lv.proxy_port, 0x9503);
    int d2 = ask_send(lv.proxy_port, 0x9504);
    ASSERT(d1 >= 0 && d2 >= 0);
    for (int i = 0; i < 100 && atomic_load(&g_rec.opens) < 3; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(d1));
    ASSERT_EQ(2, ask_read(d2));
    atomic_store(&lv.b.hold, 0);
    ASSERT_EQm("gen 1's socket was closed: one new one for the pair", 3, atomic_load(&g_rec.opens));
    ASSERT_EQm("every socket gen 2 opened carries gen 2's mark", 0x40050000u, atomic_load(&g_rec.last_mark));
    live_stop(&lv);
    PASS();
}

/* Catches: forget keeping health or sockets, or close dropping the group's fallback count. */
TEST a_forgotten_group_leaves_no_health_and_a_closed_one_keeps_it(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = closed_udp_port();
    ASSERT_EQ(1, ask(lv.proxy_port, 0x9601));
    ASSERT_EQ(1u, live_fallbacks(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9602));
    ASSERT_EQ(3, atomic_load(&g_rec.opens));
    live_close_group(&lv, 7);
    ASSERT_EQm("closing keeps the record", 1u, live_fallbacks(&lv));
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9603));
    ASSERT_EQm("closing closed the idle socket", 4, atomic_load(&g_rec.opens));
    live_forget_group(&lv, 7);
    ASSERT_EQm("forgetting drops it", 0u, live_fallbacks(&lv));
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9604));
    ASSERT_EQm("forgetting closed the idle socket", 5, atomic_load(&g_rec.opens));

    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0x9605);
    ASSERT(c >= 0);
    for (int i = 0; i < 100 && atomic_load(&lv.b.received) < 4; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    ASSERT_EQ(4, atomic_load(&lv.b.received));
    ASSERT_EQm("0x9605 went out on the pooled socket", 5, atomic_load(&g_rec.opens));
    live_forget_group(&lv, 7);
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c));
    atomic_store(&lv.b.hold, 0);
    ASSERT_EQ(2, ask(lv.proxy_port, 0x9606));
    ASSERT_EQm("the in-flight socket was closed on release, not kept", 6, atomic_load(&g_rec.opens));
    live_stop(&lv);
    PASS();
}

/* Catches: a repeat query sent to the resolver again, or journalled as the resolver's own answer. */
TEST a_repeat_query_is_answered_from_the_cache(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa101));
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    long t0 = ms_now();
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa102));
    ASSERT_LT(ms_now() - t0, 100);
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    ASSERT_EQ(1, atomic_load(&g_rec.sends));
    ASSERT_EQ(FIRC_DNS_RESOLVER_CACHE, atomic_load(&g_live_resolver));
    ASSERT_EQm("the hit went through the pipeline", 2, atomic_load(&g_live_hook_calls));
    live_stop(&lv);
    PASS();
}

/* Catches: a cached answer handed out with the TTLs it arrived with. */
TEST a_cached_answer_is_handed_out_with_its_age_taken_off(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(300, ask_a_ttl(lv.proxy_port, 0xa201));
    atomic_store(&g_cache_skew_ms, 100000);
    ASSERT_EQ(200, ask_a_ttl(lv.proxy_port, 0xa202));
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    live_stop(&lv);
    PASS();
}

/* Catches: the route generation left out of the key. */
TEST a_rewired_route_does_not_hit_the_old_generations_answer(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    g_troute.gen = 1;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa301));
    g_troute.gen = 2;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa302));
    ASSERT_EQ(2, atomic_load(&lv.b.received));
    live_stop(&lv);
    PASS();
}

/* Catches: closing or forgetting a group leaving its answers to be served, or dropping another group's. */
TEST closing_or_forgetting_a_group_drops_its_cached_answers(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    g_troute.group = 8;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa401));
    g_troute.group = 7;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa402));
    ASSERT_EQ(2, atomic_load(&lv.b.received));
    live_close_group(&lv, 7);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa403));
    ASSERT_EQm("closed: asked again", 3, atomic_load(&lv.b.received));
    live_forget_group(&lv, 7);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa404));
    ASSERT_EQm("forgotten: asked again", 4, atomic_load(&lv.b.received));
    g_troute.group = 8;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa405));
    ASSERT_EQm("group 8 kept its answer", 4, atomic_load(&lv.b.received));
    live_stop(&lv);
    PASS();
}

/* Catches: the health gate consulted before the cache, so a resting group loses answers it holds. */
TEST a_resting_group_still_answers_from_its_cache(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xa501, 0, 'a'));
    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask_for(lv.proxy_port, (uint16_t)(0xa510 + i), 0, (char)('b' + i))); }
    ASSERT_EQ(4, atomic_load(&g_rec.marks));
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xa520, 0, 'a'));
    ASSERT_EQ(FIRC_DNS_RESOLVER_CACHE, atomic_load(&g_live_resolver));
    ASSERT_EQ(1, ask_for(lv.proxy_port, 0xa521, 0, 'z'));
    ASSERT_EQ(FIRC_DNS_RESOLVER_HEALTH_SKIP, atomic_load(&g_live_resolver));
    ASSERT_EQ(4, atomic_load(&g_rec.marks));
    live_stop(&lv);
    PASS();
}

/* Catches: a refused, failed, sink or fallen-back answer cached, so the next query skips the group's resolver. */
TEST only_the_group_resolvers_good_answer_is_cached(void) {
    struct { const char *what; int rcode; bool sink; int want; } cases[] = {
        {"refused", 5, false, 1}, {"servfail", 2, false, 1}, {"sink", 0, true, 1}, {"nxdomain without soa", 3, false, 2},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        live_t lv;
        tunnel_setup(0);
        g_live_cache = true;
        ASSERT(live_start_retrying(&lv));
        g_troute.ports[0] = lv.b.port;
        atomic_store(&lv.b.rcode, cases[i].rcode);
        atomic_store(&lv.b.a_set, cases[i].sink ? 1 : 0);
        atomic_store(&lv.b.a_ip, 0u);
        ASSERT_EQm(cases[i].what, cases[i].want, ask(lv.proxy_port, (uint16_t)(0xa600 + 2 * i)));
        atomic_store(&lv.b.rcode, 0);
        atomic_store(&lv.b.a_set, 0);
        ASSERT_EQm(cases[i].what, 2, ask(lv.proxy_port, (uint16_t)(0xa601 + 2 * i)));
        ASSERT_EQm(cases[i].what, 2, atomic_load(&lv.b.received));
        live_stop(&lv);
    }
    PASS();
}

/* Catches: a truncated answer from the group's resolver cached, so a later asker never sees the whole one. */
TEST a_truncated_group_answer_is_delivered_but_not_cached(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.tc, 1);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xac01));
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    atomic_store(&lv.b.tc, 0);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xac02));
    ASSERT_EQm("the second ask reached the resolver", 2, atomic_load(&lv.b.received));
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

/* Catches: a TCP client sent to the resolver though the answer is cached, or the cached answer sent unframed. */
TEST a_tcp_client_is_answered_from_the_cache(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xa701));
    ASSERT_EQ(2, ask_tcp(lv.proxy_port, 0xa702));
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    ASSERT_EQ(FIRC_DNS_RESOLVER_CACHE, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

/* Catches: a cached answer larger than the asker's UDP size sent to it anyway. */
TEST an_answer_too_big_for_the_asker_is_asked_again(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    g_big_a = 40;
    ASSERT(ask_for(lv.proxy_port, 0xa801, 1232, 'a') > 0);
    ASSERT(ask_for(lv.proxy_port, 0xa802, 512, 'a') > 0);
    ASSERT_EQm("671 bytes do not fit 512", 2, atomic_load(&lv.b.received));
    ASSERT(ask_for(lv.proxy_port, 0xa803, 1232, 'a') > 0);
    ASSERT_EQm("they fit 1232", 2, atomic_load(&lv.b.received));
    g_big_a = 0;
    live_stop(&lv);
    PASS();
}

/* Catches: an EDNS client's cached answer, OPT and all, handed to a client that sent no OPT. */
TEST a_client_without_edns_is_not_given_an_edns_clients_answer(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xa901, 1232, 'a'));
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xa902, 0, 'a'));
    ASSERT_EQ(2, atomic_load(&lv.b.received));
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xa903, 0, 'a'));
    ASSERT_EQ(2, atomic_load(&lv.b.received));
    live_stop(&lv);
    PASS();
}

/* Catches: a hit carrying the first asker's name case or id to a 0x20 forwarder, which then drops it. */
TEST a_cached_answer_echoes_the_askers_case(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xaa01, 0, 'a'));
    int c = ask_send_for(lv.proxy_port, 0xaa02, 0, 'A');
    ASSERT(c >= 0);
    uint8_t r[2048];
    ssize_t n = recv(c, r, sizeof(r), 0);
    close(c);
    ASSERT(n > 13);
    ASSERT_EQ(0xaa, r[0]);
    ASSERT_EQ(0x02, r[1]);
    ASSERT_EQ('A', r[13]);
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    live_stop(&lv);
    PASS();
}

/* Catches: the cache read before the router's owner and coverage decision. */
TEST a_query_the_router_declines_never_reads_the_cache(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xab01));
    g_troute.take = false;
    ASSERT_EQ(1, ask(lv.proxy_port, 0xab02));
    ASSERT_EQ(1, atomic_load(&lv.a.received));
    ASSERT_EQ(FIRC_DNS_RESOLVER_UPSTREAM, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

static bool await_received(stub_t *s, int n) {
    for (int i = 0; i < 400 && atomic_load(&s->received) < n; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return atomic_load(&s->received) >= n;
}

static bool await_replied(stub_t *s, int n) {
    for (int i = 0; i < 400 && atomic_load(&s->replied) < n; i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 5 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return atomic_load(&s->replied) >= n;
}

static void pause_ms(long ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Catches: resolvers asked one after another, or a slower resolver's answer chosen over the first. */
TEST every_group_resolver_is_asked_at_once_and_the_first_good_answer_wins(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.n = 2;
    g_troute.ports[0] = lv.b.port;
    g_troute.ports[1] = lv.c.port;
    atomic_store(&lv.b.hold_ms, 600);
    long t0 = ms_now();
    ASSERT_EQ(3, ask(lv.proxy_port, 0xb101));
    ASSERT_LT(ms_now() - t0, 400);
    ASSERT(await_received(&lv.b, 1));
    ASSERT_EQ(1, atomic_load(&lv.c.received));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    ASSERT_EQ(0u, live_fallbacks(&lv));
    pause_ms(700);
    live_stop(&lv);
    PASS();
}

/* Catches: a sink from one resolver ending the exchange or falling back while another can still answer well. */
TEST a_sink_from_one_resolver_and_a_good_answer_from_another_delivers_the_good_one(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.n = 2;
    g_troute.ports[0] = lv.b.port;
    g_troute.ports[1] = lv.c.port;
    atomic_store(&lv.b.a_set, 1);
    atomic_store(&lv.b.a_ip, 0u);
    atomic_store(&lv.c.hold_ms, 100);
    ASSERT_EQ(3, ask(lv.proxy_port, 0xb201));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    ASSERT_EQ(0u, live_fallbacks(&lv));
    live_stop(&lv);
    PASS();
}

/* Catches: the first failing resolver's reason journalled instead of the last, or a fallback before all failed. */
TEST every_resolver_failing_falls_back_with_the_last_reason(void) {
    for (int order = 0; order < 2; order++) {
        live_t lv;
        tunnel_setup(0);
        ASSERT(live_start_retrying(&lv));
        g_troute.n = 2;
        g_troute.ports[0] = lv.b.port;
        g_troute.ports[1] = lv.c.port;
        atomic_store(&lv.b.rcode, order == 0 ? 5 : 2);
        atomic_store(&lv.c.rcode, order == 0 ? 2 : 5);
        atomic_store(&lv.c.hold_ms, 100);
        ASSERT_EQ(1, ask(lv.proxy_port, (uint16_t)(0xb301 + order)));
        ASSERT_EQ(1, atomic_load(&lv.a.received));
        ASSERT_EQ(order == 0 ? FIRC_DNS_RESOLVER_FALLBACK_SERVFAIL : FIRC_DNS_RESOLVER_FALLBACK_REFUSED,
                  atomic_load(&g_live_resolver));
        ASSERT_EQ(1u, live_fallbacks(&lv));
        live_stop(&lv);
    }
    PASS();
}

/* Catches: a silent resolver beside a failed one falling back early, or with the failed one's reason. */
TEST a_silent_resolver_beside_a_failed_one_falls_back_at_the_timeout(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.n = 2;
    g_troute.ports[0] = lv.b.port;
    g_troute.ports[1] = lv.c.port;
    atomic_store(&lv.b.rcode, 5);
    atomic_store(&lv.c.hold, 1);
    long t0 = ms_now();
    ASSERT_EQ(1, ask(lv.proxy_port, 0xb401));
    long took = ms_now() - t0;
    ASSERT_GTE(took, (long)FIRC_DNSPROXY_TUNNEL_TIMEOUT_MS - 50);
    ASSERT_LT(took, 2000);
    ASSERT_EQ(FIRC_DNS_RESOLVER_FALLBACK_TIMEOUT, atomic_load(&g_live_resolver));
    atomic_store(&lv.c.go, 1);
    live_stop(&lv);
    PASS();
}

/* Catches: a losing resolver's socket closed instead of pooled, or its late answer delivered to the next query. */
TEST a_losing_resolvers_socket_is_pooled_and_its_late_answer_ignored(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.n = 2;
    g_troute.ports[0] = lv.b.port;
    g_troute.ports[1] = lv.c.port;
    atomic_store(&lv.c.hold_ms, 150);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xb501));
    ASSERT(await_replied(&lv.c, 1));
    pause_ms(50);
    atomic_store(&lv.c.mark, 4);
    atomic_store(&lv.c.hold_ms, 0);
    atomic_store(&lv.b.hold, 1);
    ASSERT_EQ(4, ask(lv.proxy_port, 0xb502));
    ASSERT_EQm("both sockets came back from their pools", 2, atomic_load(&g_rec.opens));
    atomic_store(&lv.b.go, 1);
    live_stop(&lv);
    PASS();
}

/* Catches: health counted per leg, so two failing resolvers rest the group after two queries instead of three. */
TEST health_counts_one_failure_per_exchange(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    uint16_t closed = closed_udp_port();
    ASSERT(closed != 0);
    g_troute.n = 2;
    g_troute.ports[0] = closed;
    g_troute.ports[1] = closed;
    ASSERT_EQ(1, ask(lv.proxy_port, 0xb601));
    ASSERT_EQ(1, ask(lv.proxy_port, 0xb602));
    ASSERT_EQ(4, atomic_load(&g_rec.marks));
    ASSERT_EQ(1, ask(lv.proxy_port, 0xb603));
    ASSERT_EQm("two failures so far: the third query still tries", 6, atomic_load(&g_rec.marks));
    ASSERT_EQ(1, ask(lv.proxy_port, 0xb604));
    ASSERT_EQm("three: resting", 6, atomic_load(&g_rec.marks));
    ASSERT_EQ(4u, live_fallbacks(&lv));
    live_stop(&lv);
    PASS();
}

/* Catches: a lost datagram to a lone resolver costing the tunnel timeout, or more than one resend. */
TEST a_lone_resolver_is_asked_again_once_after_300_ms(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.drop, 1);
    long t0 = ms_now();
    ASSERT_EQ(2, ask(lv.proxy_port, 0xb701));
    long took = ms_now() - t0;
    ASSERT_GTE(took, (long)FIRC_DNSPROXY_RETRY_MS - 20);
    ASSERT_LT(took, 900);
    ASSERT_EQ(2, atomic_load(&lv.b.received));
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    atomic_store(&lv.b.drop, 2);
    ASSERT_EQ(1, ask(lv.proxy_port, 0xb702));
    ASSERT_EQm("one resend, not one every 300 ms", 4, atomic_load(&lv.b.received));
    ASSERT_EQ(1u, live_fallbacks(&lv));
    live_stop(&lv);
    PASS();
}

/* Catches: the resend's late twin, read by the next query on the pooled socket, taken for its answer or a failure. */
TEST a_resends_late_twin_is_ignored_by_the_next_query(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold_ms, 400);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xbb01));
    ASSERT(await_received(&lv.b, 2));
    pause_ms(500);
    atomic_store(&lv.b.hold_ms, 0);
    atomic_store(&lv.b.mark, 6);
    ASSERT_EQ(6, ask(lv.proxy_port, 0xbb02));
    ASSERT_EQ(0u, live_fallbacks(&lv));
    ASSERT_EQ(1, atomic_load(&g_rec.opens));
    live_stop(&lv);
    PASS();
}

/* Catches: a TCP query sent to every resolver at once instead of the preferred one. */
TEST a_tcp_query_still_asks_one_resolver(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    int lfd = -1;
    uint16_t port = tcp_probe_listen(lv.loop, &lfd);
    ASSERT(port != 0);
    atomic_store(&g_tcp_probe.go, 1);
    g_troute.n = 2;
    g_troute.ports[0] = port;
    g_troute.ports[1] = lv.b.port;
    ASSERT_EQ(3, ask_tcp(lv.proxy_port, 0xb801));
    ASSERT_EQ(1, atomic_load(&g_tcp_probe.received));
    ASSERT_EQ(1, atomic_load(&g_rec.connects_marked));
    pause_ms(50);
    close(lfd);
    live_stop(&lv);
    PASS();
}

/* Catches: a failed TCP query not moving the group's TCP queries to its next resolver. */
TEST a_failed_tcp_query_moves_the_group_to_its_next_resolver(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    int lfd = -1;
    uint16_t port = tcp_probe_listen(lv.loop, &lfd);
    ASSERT(port != 0);
    atomic_store(&g_tcp_probe.go, 1);
    g_troute.n = 2;
    g_troute.ports[0] = closed_udp_port();
    g_troute.ports[1] = port;
    (void)ask_tcp(lv.proxy_port, 0xb901);
    ASSERT_EQ(0, atomic_load(&g_tcp_probe.received));
    ASSERT_EQ(3, ask_tcp(lv.proxy_port, 0xb902));
    ASSERT_EQ(1, atomic_load(&g_tcp_probe.received));
    pause_ms(50);
    close(lfd);
    live_stop(&lv);
    PASS();
}

/* Catches: an answer fetched over TCP from the group's resolver left out of the cache UDP askers read. */
TEST a_tcp_tunnel_answer_is_served_from_the_cache_to_a_udp_asker(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    int lfd = -1;
    uint16_t port = tcp_probe_listen(lv.loop, &lfd);
    ASSERT(port != 0);
    atomic_store(&g_tcp_probe.go, 1);
    g_troute.ports[0] = port;
    ASSERT_EQ(3, ask_tcp(lv.proxy_port, 0xbc01));
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    ASSERT_EQ(3, ask(lv.proxy_port, 0xbc02));
    ASSERT_EQ(FIRC_DNS_RESOLVER_CACHE, atomic_load(&g_live_resolver));
    ASSERT_EQ(1, atomic_load(&g_tcp_probe.received));
    ASSERT_EQ(1, atomic_load(&g_rec.marks));
    pause_ms(50);
    close(lfd);
    live_stop(&lv);
    PASS();
}

/* Catches: a tunnel answer landing after its group was forgotten cached again under the dead generation. */
TEST a_tunnel_answer_after_its_group_is_forgotten_is_not_cached(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0xbd01);
    ASSERT(c >= 0);
    ASSERT(await_received(&lv.b, 1));
    live_forget_group(&lv, 7);
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c));
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    ASSERT_EQ(2, ask(lv.proxy_port, 0xbd02));
    ASSERT_EQm("asked the resolver, not the cache", FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

/* Catches: a silent resolver's socket closed at the tunnel timeout instead of pooled, so every query costs a new flow. */
TEST a_silent_resolvers_socket_is_pooled_at_the_timeout(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    ASSERT_EQ(1, ask(lv.proxy_port, 0xbe01));
    ASSERT_EQ(FIRC_DNS_RESOLVER_FALLBACK_TIMEOUT, atomic_load(&g_live_resolver));
    ASSERT_EQ(2, atomic_load(&g_rec.opens));
    atomic_store(&lv.b.hold, 0);
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xbe02));
    ASSERT_EQm("the tunnel socket came back from its pool", 2, atomic_load(&g_rec.opens));
    live_stop(&lv);
    PASS();
}

/* Catches: a late answer cached under a generation that is no longer live once its group came back. */
TEST a_late_answer_after_its_group_came_back_is_not_cached(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0xbf01);
    ASSERT(c >= 0);
    ASSERT(await_received(&lv.b, 1));
    live_forget_group(&lv, 7);
    g_troute.gen = 2;
    g_troute.ports[0] = lv.c.port;
    ASSERT_EQ(3, ask_for(lv.proxy_port, 0xbf02, 0, 'z'));
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c));
    atomic_store(&lv.b.hold, 0);
    g_troute.gen = 1;
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xbf03));
    ASSERT_EQm("the dead generation's answer was not kept", FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

/* Catches: an answer on a socket whose pool was closed mid-flight cached after the close dropped the group's answers. */
TEST an_answer_landing_after_its_pool_was_closed_is_not_cached(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0xbf11);
    ASSERT(c >= 0);
    ASSERT(await_received(&lv.b, 1));
    live_close_group(&lv, 7);
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c));
    atomic_store(&lv.b.hold, 0);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xbf12));
    ASSERT_EQm("asked the resolver, not the cache", FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

/* Catches: a full send buffer on a resolver's socket taken for an unreachable resolver instead of a send to retry. */
TEST a_send_that_would_block_is_covered_by_the_resend(void) {
    live_t lv;
    tunnel_setup(0);
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&g_rec.fail_send, EAGAIN);
    long t0 = ms_now();
    int c = ask_send(lv.proxy_port, 0xbf21);
    ASSERT(c >= 0);
    pause_ms(100);
    atomic_store(&g_rec.fail_send, 0);
    ASSERT_EQ(2, ask_read(c));
    ASSERT_GTE(ms_now() - t0, (long)FIRC_DNSPROXY_RETRY_MS - 20);
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    ASSERT_EQ(1, atomic_load(&lv.b.received));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    live_stop(&lv);
    PASS();
}

/* Catches: a late answer cached for a generation the group has since left, while its socket's pool is untouched. */
TEST a_late_answer_from_a_replaced_generation_is_not_cached(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    atomic_store(&lv.b.hold, 1);
    int c = ask_send(lv.proxy_port, 0xbf31);
    ASSERT(c >= 0);
    ASSERT(await_received(&lv.b, 1));
    g_troute.gen = 2;
    g_troute.ports[0] = lv.c.port;
    ASSERT_EQ(3, ask_for(lv.proxy_port, 0xbf32, 0, 'z'));
    atomic_store(&lv.b.go, 1);
    ASSERT_EQ(2, ask_read(c));
    atomic_store(&lv.b.hold, 0);
    g_troute.gen = 1;
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xbf33));
    ASSERT_EQm("the replaced generation's answer was not kept", FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

typedef struct {
    firc_dnsproxy_t *proxy;
    _Atomic size_t out;
    _Atomic int done;
} pfq_t;

static void prefetching_on_loop(firc_loop_t *loop, void *ud) {
    (void)loop;
    pfq_t *q = ud;
    atomic_store(&q->out, firc_dnsproxy_prefetching(q->proxy));
    atomic_store(&q->done, 1);
}

static size_t live_prefetching(live_t *lv) {
    pfq_t q = {.proxy = lv->proxy};
    if (firc_loop_post(lv->loop, prefetching_on_loop, &q) != FIRC_OK) { return SIZE_MAX; }
    for (int i = 0; i < 200 && !atomic_load(&q.done); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return atomic_load(&q.done) ? atomic_load(&q.out) : SIZE_MAX;
}

static bool await_no_prefetch(live_t *lv) {
    for (int i = 0; i < 300; i++) {
        if (live_prefetching(lv) == 0) { return true; }
        pause_ms(10);
    }
    return false;
}

/* Catches: a failed refresh counted as a group failure, resting a group no client saw fail. */
TEST failed_refreshes_never_rest_the_group(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    for (int i = 0; i < 4; i++) { ASSERT_EQ(2, ask_for(lv.proxy_port, (uint16_t)(0xc500 + i), 0, (char)('a' + i))); }
    atomic_store(&g_cache_skew_ms, 271000);
    atomic_store(&lv.b.rcode, 2);
    for (int i = 0; i < 4; i++) {
        ASSERT_EQ(2, ask_for(lv.proxy_port, (uint16_t)(0xc510 + i), 0, (char)('a' + i)));
        ASSERT(await_received(&lv.b, 5 + i));
        ASSERT(await_no_prefetch(&lv));
    }
    atomic_store(&lv.b.rcode, 0);
    int before = atomic_load(&lv.b.received);
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xc520, 0, 'z'));
    ASSERT_EQm("a fresh name still goes through the tunnel", before + 1, atomic_load(&lv.b.received));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    live_stop(&lv);
    PASS();
}

/* Catches: a successful refresh not clearing the group's failure count, so later client failures rest it early. */
TEST a_successful_refresh_clears_the_failure_count(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xca01, 0, 'a'));
    atomic_store(&lv.b.rcode, 2);
    for (int i = 0; i < 2; i++) { ASSERT_EQ(1, ask_for(lv.proxy_port, (uint16_t)(0xca10 + i), 0, (char)('b' + i))); }
    atomic_store(&lv.b.rcode, 0);
    atomic_store(&g_cache_skew_ms, 271000);
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xca20, 0, 'a'));
    ASSERT(await_received(&lv.b, 4));
    ASSERT(await_no_prefetch(&lv));
    atomic_store(&lv.b.rcode, 2);
    for (int i = 0; i < 2; i++) { ASSERT_EQ(1, ask_for(lv.proxy_port, (uint16_t)(0xca30 + i), 0, (char)('d' + i))); }
    atomic_store(&lv.b.rcode, 0);
    int a0 = atomic_load(&lv.a.received);
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xca40, 0, 'z'));
    ASSERT_EQm("two failures since the refresh: still through the tunnel", a0, atomic_load(&lv.a.received));
    ASSERT_EQ(FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

/* Catches: a hit in the last tenth not refreshing the entry, refreshing it through the pipeline, or twice at once. */
TEST a_hit_in_the_last_tenth_refreshes_the_entry_once(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.n = 2;
    g_troute.ports[0] = lv.b.port;
    g_troute.ports[1] = lv.c.port;
    atomic_store(&lv.c.mark, 2);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc101));
    atomic_store(&g_cache_skew_ms, 269000);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc102));
    ASSERT_EQm("31 s of 300 left: no refresh", 2, atomic_load(&g_rec.sends));
    atomic_store(&g_cache_skew_ms, 271000);
    atomic_store(&lv.b.hold, 1);
    atomic_store(&lv.c.hold, 1);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc103));
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc104));
    ASSERT_EQm("29 s left: one refresh of two legs, not one per hit", 4, atomic_load(&g_rec.sends));
    atomic_store(&lv.b.mark, 5);
    atomic_store(&lv.c.mark, 5);
    atomic_store(&lv.b.go, 1);
    atomic_store(&lv.c.go, 1);
    ASSERT(await_no_prefetch(&lv));
    ASSERT_EQ(5, ask(lv.proxy_port, 0xc105));
    ASSERT_EQ(FIRC_DNS_RESOLVER_CACHE, atomic_load(&g_live_resolver));
    ASSERT_EQm("the refresh never reached the pipeline", 5, atomic_load(&g_live_hook_calls));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    live_stop(&lv);
    PASS();
}

/* Catches: a failed refresh dropping the entry, falling back to the common upstream, or blocking the next refresh. */
TEST a_failed_refresh_leaves_the_entry_and_a_later_hit_tries_again(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc201));
    atomic_store(&g_cache_skew_ms, 271000);
    atomic_store(&lv.b.rcode, 2);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc202));
    ASSERT(await_received(&lv.b, 2));
    ASSERT(await_no_prefetch(&lv));
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc203));
    ASSERT_EQ(FIRC_DNS_RESOLVER_CACHE, atomic_load(&g_live_resolver));
    ASSERT(await_received(&lv.b, 3));
    ASSERT(await_no_prefetch(&lv));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    ASSERT_EQ(0u, live_fallbacks(&lv));
    live_stop(&lv);
    PASS();
}

/* Catches: more than 16 refreshes in flight at once, or a capped hit keeping its entry from asking again. */
TEST refreshes_are_capped_at_sixteen(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.n = 2;
    g_troute.ports[0] = lv.b.port;
    g_troute.ports[1] = lv.c.port;
    for (int i = 0; i < 17; i++) { ASSERT(ask_for(lv.proxy_port, (uint16_t)(0xc300 + i), 0, (char)('a' + i)) > 0); }
    atomic_store(&g_cache_skew_ms, 271000);
    atomic_store(&lv.b.hold, 1);
    atomic_store(&lv.c.hold, 1);
    int s0 = atomic_load(&g_rec.sends);
    for (int i = 0; i < 17; i++) { ASSERT(ask_for(lv.proxy_port, (uint16_t)(0xc320 + i), 0, (char)('a' + i)) > 0); }
    ASSERT_EQm("16 refreshes of two legs each", 32, atomic_load(&g_rec.sends) - s0);
    ASSERT_EQ((size_t)FIRC_DNSPROXY_MAX_PREFETCH, live_prefetching(&lv));
    atomic_store(&lv.b.go, 1);
    atomic_store(&lv.c.go, 1);
    ASSERT(await_no_prefetch(&lv));
    int s1 = atomic_load(&g_rec.sends);
    ASSERT(ask_for(lv.proxy_port, 0xc340, 0, (char)('a' + 16)) > 0);
    ASSERT_EQm("the capped entry may ask again", 2, atomic_load(&g_rec.sends) - s1);
    ASSERT(await_no_prefetch(&lv));
    live_stop(&lv);
    PASS();
}

/* Catches: refreshes taking the client in-flight budget, so they crowd out client queries. */
TEST refreshes_do_not_take_the_client_budget(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    g_live_max_concurrent = 2;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    for (int i = 0; i < 3; i++) { ASSERT_EQ(2, ask_for(lv.proxy_port, (uint16_t)(0xc400 + i), 0, (char)('a' + i))); }
    atomic_store(&g_cache_skew_ms, 271000);
    atomic_store(&lv.b.hold, 1);
    for (int i = 0; i < 3; i++) { ASSERT_EQ(2, ask_for(lv.proxy_port, (uint16_t)(0xc410 + i), 0, (char)('a' + i))); }
    ASSERT_EQ(3u, live_prefetching(&lv));
    g_troute.take = false;
    ASSERT_EQ(1, ask_for(lv.proxy_port, 0xc420, 0, 'z'));
    atomic_store(&lv.b.go, 1);
    ASSERT(await_no_prefetch(&lv));
    live_stop(&lv);
    PASS();
}

/* Catches: a refresh started while the group rests, or while another query is its probe. */
TEST no_refresh_starts_while_the_group_rests_or_probes(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    g_live_rest_ms = 1000;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xc601, 0, 'a'));
    g_troute.ports[0] = closed_udp_port();
    for (int i = 0; i < 3; i++) { ASSERT_EQ(1, ask_for(lv.proxy_port, (uint16_t)(0xc610 + i), 0, (char)('b' + i))); }
    atomic_store(&g_cache_skew_ms, 271000);
    int s0 = atomic_load(&g_rec.sends);
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xc620, 0, 'a'));
    ASSERT_EQ(FIRC_DNS_RESOLVER_CACHE, atomic_load(&g_live_resolver));
    pause_ms(50);
    ASSERT_EQm("resting: no refresh", s0, atomic_load(&g_rec.sends));
    ASSERT_EQ(0u, live_prefetching(&lv));

    pause_ms(1050);
    g_troute.n = 2;
    g_troute.ports[0] = lv.b.port;
    g_troute.ports[1] = lv.c.port;
    atomic_store(&lv.b.hold, 1);
    atomic_store(&lv.c.hold, 1);
    int c = ask_send_for(lv.proxy_port, 0xc630, 0, 'y');
    ASSERT(c >= 0);
    ASSERT(await_received(&lv.b, 2));
    ASSERT(await_received(&lv.c, 1));
    int s1 = atomic_load(&g_rec.sends);
    ASSERT_EQ(2, ask_for(lv.proxy_port, 0xc631, 0, 'a'));
    pause_ms(50);
    ASSERT_EQm("probing: no refresh", s1, atomic_load(&g_rec.sends));
    ASSERT_EQ(0u, live_prefetching(&lv));
    atomic_store(&lv.b.go, 1);
    atomic_store(&lv.c.go, 1);
    ASSERT(ask_read(c) > 1);
    live_stop(&lv);
    PASS();
}

/* Catches: a refresh whose resolver stays silent never ending, or ending by dropping the entry or asking the common upstream. */
TEST a_silent_refresh_ends_at_the_timeout_and_leaves_the_entry(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc701));
    atomic_store(&g_cache_skew_ms, 271000);
    atomic_store(&lv.b.hold, 1);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc702));
    ASSERT_EQ(1u, live_prefetching(&lv));
    ASSERT(await_no_prefetch(&lv));
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc703));
    ASSERT_EQ(FIRC_DNS_RESOLVER_CACHE, atomic_load(&g_live_resolver));
    ASSERT_EQ(0, atomic_load(&lv.a.received));
    ASSERT_EQ(0u, live_fallbacks(&lv));
    atomic_store(&lv.b.go, 1);
    ASSERT(await_no_prefetch(&lv));
    live_stop(&lv);
    PASS();
}

/* Catches: a refresh in flight at shutdown left allocated (LSan) or its sockets left open. */
TEST a_refresh_in_flight_at_shutdown_is_freed(void) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.n = 2;
    g_troute.ports[0] = lv.b.port;
    g_troute.ports[1] = lv.c.port;
    ASSERT(ask(lv.proxy_port, 0xc801) > 1);
    atomic_store(&g_cache_skew_ms, 271000);
    atomic_store(&lv.b.hold, 1);
    atomic_store(&lv.c.hold, 1);
    ASSERT(ask(lv.proxy_port, 0xc802) > 1);
    ASSERT_EQ(1u, live_prefetching(&lv));
    live_stop(&lv);
    PASS();
}

static enum greatest_test_res refresh_cut_mid_flight(bool forget) {
    live_t lv;
    tunnel_setup(0);
    g_live_cache = true;
    ASSERT(live_start_retrying(&lv));
    g_troute.ports[0] = lv.b.port;
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc901));
    atomic_store(&g_cache_skew_ms, 271000);
    atomic_store(&lv.b.hold, 1);
    ASSERT_EQ(2, ask(lv.proxy_port, 0xc902));
    ASSERT(await_received(&lv.b, 2));
    live_group_call(&lv, 7, forget);
    atomic_store(&lv.b.mark, 5);
    atomic_store(&lv.b.go, 1);
    ASSERT(await_no_prefetch(&lv));
    ASSERT_EQ(5, ask(lv.proxy_port, 0xc903));
    ASSERT_EQm("the cut group's refresh was not stored", FIRC_DNS_RESOLVER_GROUP, atomic_load(&g_live_resolver));
    live_stop(&lv);
    PASS();
}

/* Catches: a refresh landing after its group was forgotten stored again, or never released. */
TEST a_refresh_for_a_forgotten_group_ends_unstored(void) {
    CHECK_CALL(refresh_cut_mid_flight(true));
    PASS();
}

/* Catches: a refresh landing after its group's pools were closed stored again, or never released. */
TEST a_refresh_for_a_closed_group_ends_unstored(void) {
    CHECK_CALL(refresh_cut_mid_flight(false));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_rewritten_answer_reaches_the_client);
    RUN_TEST(a_ptr_for_a_mapped_pool_address_names_its_domain);
    RUN_TEST(a_ptr_answer_copies_rd_from_the_query);
    RUN_TEST(a_pool_name_that_cannot_be_packed_is_answered_nxdomain);
    RUN_TEST(a_ptr_for_an_unmapped_pool_address_is_nxdomain);
    RUN_TEST(a_ptr_outside_the_pool_goes_to_the_upstream);
    RUN_TEST(a_rewritten_answer_reaches_the_client_when_stripping_too);
    RUN_TEST(a_retimed_answer_is_still_stripped_by_the_aaaa_default);
    RUN_TEST(a_retimed_answer_keeps_its_aaaa_and_ttl_when_stripping_is_off);
    RUN_TEST(an_untouched_answer_is_forwarded_as_it_arrived);
    RUN_TEST(an_unreported_change_is_not_forwarded);
    RUN_TEST(a_rewritten_answer_reaches_a_tcp_client);
    RUN_TEST(a_rewritten_answer_too_big_for_a_client_without_edns_is_truncated);
    RUN_TEST(a_truncated_reply_drops_an_opt_that_does_not_fit);
    RUN_TEST(a_rewritten_answer_fits_the_size_the_client_advertised);
    RUN_TEST(an_untouched_big_answer_is_not_truncated);
    RUN_TEST(a_stripped_big_answer_still_fits_a_client_without_edns);
    RUN_TEST(a_rewritten_big_answer_reaches_a_tcp_client_whole);
    RUN_TEST(the_hook_is_told_which_device_asked);
    RUN_TEST(a_v4_client_on_a_dual_stack_socket_is_reported_unmapped);
    RUN_TEST(a_held_answer_goes_out_when_released);
    RUN_TEST(a_held_answer_goes_out_at_the_deadline);
    RUN_TEST(a_release_sends_only_what_it_approves);
    RUN_TEST(a_tcp_client_gone_mid_hold_is_forgotten);
    RUN_TEST(held_answers_do_not_hold_the_inflight_budget);
    RUN_TEST(past_the_ceiling_a_held_answer_is_sent_at_once);
    RUN_TEST(a_zero_deadline_sends_a_held_answer_at_once);
    RUN_TEST(a_tcp_answer_is_forwarded_when_untouched);
    RUN_TEST(a_tcp_client_that_never_finishes_its_request_gives_its_slot_back);
    RUN_TEST(a_tcp_request_sent_just_in_time_is_answered_past_the_read_deadline);
    RUN_TEST(no_read_deadline_fires_after_a_tcp_exchange_ends);
    RUN_TEST(a_changed_upstream_answers_the_next_query);
    RUN_TEST(a_query_in_flight_finishes_on_the_old_upstream);
    RUN_TEST(a_held_query_in_flight_finishes_on_the_old_upstream);
    RUN_TEST(an_upstream_that_does_not_parse_changes_nothing);
    RUN_TEST(the_proxy_keeps_its_own_copy_of_the_upstream);
    RUN_TEST(an_owned_covered_query_goes_through_the_tunnel);
    RUN_TEST(a_tunnel_datagram_that_answers_another_query_is_ignored);
    RUN_TEST(a_common_datagram_that_answers_another_query_is_ignored);
    RUN_TEST(a_query_the_router_declines_goes_to_the_common_upstream);
    RUN_TEST(a_mark_that_cannot_be_set_is_never_used);
    RUN_TEST(a_tunnel_that_cannot_start_falls_back);
    RUN_TEST(a_tunnel_resolver_that_refuses_falls_back_at_once);
    RUN_TEST(a_silent_tunnel_resolver_falls_back_after_the_tunnel_timeout);
    RUN_TEST(each_unusable_tunnel_answer_falls_back);
    RUN_TEST(the_fallback_gets_what_remains_of_the_deadline);
    RUN_TEST(a_short_deadline_still_leaves_the_fallback_its_floor);
    RUN_TEST(a_tcp_query_goes_through_the_tunnel_over_tcp);
    RUN_TEST(a_tcp_query_that_falls_back_is_framed_once);
    RUN_TEST(a_tcp_tunnel_answer_with_a_bad_length_prefix_falls_back);
    RUN_TEST(a_tcp_tunnel_sink_answer_falls_back);
    RUN_TEST(a_tcp_tunnel_answer_with_another_id_falls_back);
    RUN_TEST(a_tunnel_answer_the_client_reads_slowly_is_not_asked_again);
    RUN_TEST(every_upstream_socket_goes_through_the_ops);
    RUN_TEST(a_common_upstream_that_cannot_open_is_no_answer);
    RUN_TEST(a_tcp_upstream_socket_goes_through_the_ops);
    RUN_TEST(an_unreachable_resolver_beside_a_working_one_costs_nothing);
    RUN_TEST(the_health_gate_rests_a_failing_group_and_probes_once);
    RUN_TEST(a_publish_mid_exchange_keeps_the_copied_route);
    RUN_TEST(a_late_tunnel_answer_is_not_delivered_after_the_fallback);
    RUN_TEST(a_stale_generations_failure_does_not_reopen_a_newer_generations_gate);
    RUN_TEST(a_stale_generations_probe_ending_does_not_clear_a_newer_generations_probing);
    RUN_TEST(only_one_query_probes_at_a_time);
    RUN_TEST(a_success_clears_the_failure_count);
    RUN_TEST(a_new_generation_starts_health_afresh);
    RUN_TEST(a_probe_that_ends_without_a_verdict_frees_the_probe_slot);
    RUN_TEST(the_callback_is_told_where_each_answer_came_from);
    RUN_TEST(idle_tunnel_sockets_are_pooled_per_group);
    RUN_TEST(a_tunnel_query_never_takes_the_common_pool_or_another_resolvers_socket);
    RUN_TEST(closing_a_groups_pool_closes_idle_and_in_flight_sockets);
    RUN_TEST(a_new_generation_does_not_reuse_the_old_sockets);
    RUN_TEST(a_socket_of_an_older_generation_is_not_pooled_on_release);
    RUN_TEST(a_forgotten_group_leaves_no_health_and_a_closed_one_keeps_it);
    RUN_TEST(a_repeat_query_is_answered_from_the_cache);
    RUN_TEST(a_cached_answer_is_handed_out_with_its_age_taken_off);
    RUN_TEST(a_rewired_route_does_not_hit_the_old_generations_answer);
    RUN_TEST(closing_or_forgetting_a_group_drops_its_cached_answers);
    RUN_TEST(a_resting_group_still_answers_from_its_cache);
    RUN_TEST(only_the_group_resolvers_good_answer_is_cached);
    RUN_TEST(a_truncated_group_answer_is_delivered_but_not_cached);
    RUN_TEST(a_tcp_client_is_answered_from_the_cache);
    RUN_TEST(an_answer_too_big_for_the_asker_is_asked_again);
    RUN_TEST(a_client_without_edns_is_not_given_an_edns_clients_answer);
    RUN_TEST(a_cached_answer_echoes_the_askers_case);
    RUN_TEST(a_query_the_router_declines_never_reads_the_cache);
    RUN_TEST(every_group_resolver_is_asked_at_once_and_the_first_good_answer_wins);
    RUN_TEST(a_sink_from_one_resolver_and_a_good_answer_from_another_delivers_the_good_one);
    RUN_TEST(every_resolver_failing_falls_back_with_the_last_reason);
    RUN_TEST(a_silent_resolver_beside_a_failed_one_falls_back_at_the_timeout);
    RUN_TEST(a_losing_resolvers_socket_is_pooled_and_its_late_answer_ignored);
    RUN_TEST(health_counts_one_failure_per_exchange);
    RUN_TEST(a_lone_resolver_is_asked_again_once_after_300_ms);
    RUN_TEST(a_resends_late_twin_is_ignored_by_the_next_query);
    RUN_TEST(a_tcp_query_still_asks_one_resolver);
    RUN_TEST(a_failed_tcp_query_moves_the_group_to_its_next_resolver);
    RUN_TEST(a_tcp_tunnel_answer_is_served_from_the_cache_to_a_udp_asker);
    RUN_TEST(a_tunnel_answer_after_its_group_is_forgotten_is_not_cached);
    RUN_TEST(a_silent_resolvers_socket_is_pooled_at_the_timeout);
    RUN_TEST(a_late_answer_after_its_group_came_back_is_not_cached);
    RUN_TEST(an_answer_landing_after_its_pool_was_closed_is_not_cached);
    RUN_TEST(a_send_that_would_block_is_covered_by_the_resend);
    RUN_TEST(a_late_answer_from_a_replaced_generation_is_not_cached);
    RUN_TEST(failed_refreshes_never_rest_the_group);
    RUN_TEST(a_successful_refresh_clears_the_failure_count);
    RUN_TEST(a_hit_in_the_last_tenth_refreshes_the_entry_once);
    RUN_TEST(a_failed_refresh_leaves_the_entry_and_a_later_hit_tries_again);
    RUN_TEST(refreshes_are_capped_at_sixteen);
    RUN_TEST(refreshes_do_not_take_the_client_budget);
    RUN_TEST(no_refresh_starts_while_the_group_rests_or_probes);
    RUN_TEST(a_silent_refresh_ends_at_the_timeout_and_leaves_the_entry);
    RUN_TEST(a_refresh_in_flight_at_shutdown_is_freed);
    RUN_TEST(a_refresh_for_a_forgotten_group_ends_unstored);
    RUN_TEST(a_refresh_for_a_closed_group_ends_unstored);
    GREATEST_MAIN_END();
}
