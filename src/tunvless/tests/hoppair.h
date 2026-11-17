#ifndef TUNVLESS_HOPPAIR_H
#define TUNVLESS_HOPPAIR_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "quic.h"

struct hop_pair { struct qc *cli, *srv; int ep; uint64_t opened_ns; };

struct hpr_end {
    struct qc *q;
    int hs, closed, echo, in_ep;
    int64_t sid, out_sid;
    size_t got, bad;
    int fin;
    uint8_t *out;
    size_t out_n, out_cap, out_off;
    int out_fin, out_done;
};

static struct hpr_end g_hpr_c, g_hpr_s;
static void (*g_hpr_tick)(struct hop_pair *p);
static uint64_t g_hpr_rx_min[2];

static void hop_pair_cfg(struct qc_cfg *cc, struct qc_srv_cfg *sc);
static unsigned hop_pair_ms(unsigned ms);

static uint64_t hpr_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint8_t hpr_pat(size_t i) { return (uint8_t)((i * 31 + 7) % 251); }

static int hpr_room(struct hpr_end *e, size_t n) {
    if (e->out_n + n <= e->out_cap) return 0;
    size_t cap = (e->out_n + n) * 2;
    uint8_t *b = realloc(e->out, cap);
    if (!b) return -1;
    e->out = b;
    e->out_cap = cap;
    return 0;
}

static void hpr_out_reset(struct hpr_end *e, int64_t sid) {
    e->out_sid = sid;
    e->out_n = e->out_off = 0;
    e->out_fin = e->out_done = 0;
}

static void hpr_in_reset(struct hpr_end *e, int64_t sid) {
    e->sid = sid;
    e->got = e->bad = 0;
    e->fin = 0;
}

static void hpr_drain(struct hpr_end *e) {
    if (!e->q || e->closed || e->out_done || e->out_sid < 0) return;
    if (e->out_off == e->out_n && !e->out_fin) return;
    ssize_t w = qc_stream_send(e->q, e->out_sid, e->out + e->out_off, e->out_n - e->out_off, e->out_fin);
    if (w < 0) return;
    e->out_off += (size_t)w;
    if (e->out_fin && e->out_off == e->out_n) e->out_done = 1;
}

static void hpr_hs(void *u) { ((struct hpr_end *)u)->hs = 1; }

static void hpr_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct hpr_end *e = u;
    if (e->sid < 0) e->sid = sid;
    if (sid == e->sid) {
        for (size_t i = 0; i < n; i++)
            if (d[i] != hpr_pat(e->got + i)) e->bad++;
        e->got += n;
        if (fin) e->fin = 1;
        if (e->echo && hpr_room(e, n) == 0) {
            memcpy(e->out + e->out_n, d, n);
            e->out_n += n;
            e->out_sid = sid;
            if (fin) e->out_fin = 1;
        }
    }
    qc_stream_consumed(e->q, sid, n);
}

static void hpr_closed(void *u, int reason, int app, uint64_t code, const char *why) {
    (void)reason; (void)app; (void)code; (void)why;
    ((struct hpr_end *)u)->closed = 1;
}

static const struct qc_ops hpr_ops = { .on_handshake = hpr_hs, .on_stream_data = hpr_data, .on_closed = hpr_closed };

static void hpr_watch(struct hop_pair *p, struct hpr_end *e) {
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = e };
    if (epoll_ctl(p->ep, EPOLL_CTL_ADD, qc_fd(e->q), &ev) == 0) e->in_ep = 1;
}

static void hpr_read(struct hpr_end *e) {
    if (e != &g_hpr_c) {
        (void)qc_on_readable(e->q);
        return;
    }
    uint16_t cur, pre;
    int pre_fd;
    struct qc_stats a, b;
    qc_sock_ports(e->q, &cur, &pre, &pre_fd);
    qc_stats_get(e->q, &a);
    (void)qc_on_readable(e->q);
    qc_stats_get(e->q, &b);
    uint64_t d = b.rx_calls - a.rx_calls;
    int k = pre_fd >= 0;
    if (d < g_hpr_rx_min[k]) g_hpr_rx_min[k] = d;
}

static void hpr_pass(struct hop_pair *p, unsigned cap_ms, int cli) {
    struct hpr_end *ends[2] = { &g_hpr_c, &g_hpr_s };
    int t = cap_ms < 50 ? (int)cap_ms : 50;
    for (int i = !cli; i < 2; i++) {
        if (ends[i]->closed) continue;
        int k = qc_timeout_ms(ends[i]->q);
        if (k >= 0 && k < t) t = k;
    }
    struct epoll_event ev[4];
    int n = epoll_wait(p->ep, ev, 4, t);
    for (int i = 0; i < n; i++) {
        struct hpr_end *e = ev[i].data.ptr;
        if (!e->closed && (cli || e != &g_hpr_c)) hpr_read(e);
    }
    for (int i = !cli; i < 2; i++) {
        struct hpr_end *e = ends[i];
        if (!e->closed && qc_timeout_ms(e->q) == 0) (void)qc_on_timer(e->q);
        if (e->closed && e->in_ep) {
            epoll_ctl(p->ep, EPOLL_CTL_DEL, qc_fd(e->q), NULL);
            e->in_ep = 0;
        }
        hpr_drain(e);
        qc_flush(e->q);
    }
    if (g_hpr_tick) g_hpr_tick(p);
}

static void hop_pair_pump(struct hop_pair *p, unsigned ms) {
    uint64_t now = hpr_ms(), end = now + hop_pair_ms(ms);
    for (; now < end; now = hpr_ms()) hpr_pass(p, (unsigned)(end - now), 1);
}

static int hop_pair_start(struct hop_pair *p, unsigned hop_mode, const struct port_range *r, size_t n,
                          uint32_t (*rand32)(void)) {
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    memset(p, 0, sizeof *p);
    memset(&g_hpr_c, 0, sizeof g_hpr_c);
    memset(&g_hpr_s, 0, sizeof g_hpr_s);
    hpr_in_reset(&g_hpr_c, -1);
    hpr_in_reset(&g_hpr_s, -1);
    hpr_out_reset(&g_hpr_c, -1);
    hpr_out_reset(&g_hpr_s, -1);
    g_hpr_s.echo = 1;
    g_hpr_tick = NULL;
    g_hpr_rx_min[0] = g_hpr_rx_min[1] = UINT64_MAX;
    p->ep = epoll_create1(EPOLL_CLOEXEC);
    if (p->ep < 0) return -1;
    hop_pair_cfg(&cc, &sc);
    sc.follow_peer = 1;
    if (qc_listen(&sc, &hpr_ops, &g_hpr_s, &p->srv) != 0) return -1;
    g_hpr_s.q = p->srv;
    hpr_watch(p, &g_hpr_s);
    cc.port = qc_local_port(p->srv);
    cc.hop_mode = hop_mode;
    cc.hop_n = n;
    if (n) memcpy(cc.hop_ports, r, n * sizeof *r);
    cc.rand32 = rand32;
    if (qc_open(&cc, &hpr_ops, &g_hpr_c, &p->cli) != 0) return -2;
    g_hpr_c.q = p->cli;
    p->opened_ns = qc_opened_ns(p->cli);
    hpr_watch(p, &g_hpr_c);
    return 0;
}

static int hop_pair_open(struct hop_pair *p, unsigned hop_mode, const struct port_range *r, size_t n,
                         uint32_t (*rand32)(void)) {
    int rc = hop_pair_start(p, hop_mode, r, n, rand32);
    if (rc != 0) return rc;
    uint64_t end = hpr_ms() + hop_pair_ms(10000);
    while (!(g_hpr_c.hs && g_hpr_s.hs) && !g_hpr_c.closed && hpr_ms() < end) hpr_pass(p, 50, 1);
    return g_hpr_c.hs && g_hpr_s.hs ? 0 : -3;
}

static int hpr_fill(struct hpr_end *e, int64_t sid, size_t bytes) {
    hpr_out_reset(e, sid);
    if (hpr_room(e, bytes) != 0) return -1;
    for (size_t i = 0; i < bytes; i++) e->out[i] = hpr_pat(i);
    e->out_n = bytes;
    e->out_fin = 1;
    hpr_drain(e);
    return 0;
}

static int hop_pair_echo(struct hop_pair *p, size_t bytes, unsigned ms) {
    uint64_t now = hpr_ms(), end = now + hop_pair_ms(ms);
    int64_t sid = -1;
    int rc;
    while ((rc = qc_stream_open(p->cli, &sid)) == QC_EAGAIN && hpr_ms() < end) hpr_pass(p, 50, 1);
    if (rc != 0) return -1;
    hpr_in_reset(&g_hpr_c, sid);
    hpr_in_reset(&g_hpr_s, -1);
    hpr_out_reset(&g_hpr_s, -1);
    if (hpr_fill(&g_hpr_c, sid, bytes) != 0) return -1;
    for (now = hpr_ms(); now < end && !(g_hpr_c.fin && g_hpr_c.got == bytes) && !g_hpr_c.closed && !g_hpr_s.closed;
         now = hpr_ms())
        hpr_pass(p, (unsigned)(end - now), 1);
    return g_hpr_c.got == bytes && g_hpr_c.bad == 0 && g_hpr_c.fin ? 0 : -1;
}

static int hpr_srv_send(struct hop_pair *p, size_t bytes) {
    int64_t sid = -1;
    if (qc_stream_open(p->srv, &sid) != 0) return -1;
    hpr_in_reset(&g_hpr_c, -1);
    return hpr_fill(&g_hpr_s, sid, bytes);
}

static void hop_pair_free(struct hop_pair *p) {
    qc_free(p->cli);
    qc_free(p->srv);
    if (p->ep >= 0) close(p->ep);
    free(g_hpr_c.out);
    free(g_hpr_s.out);
    memset(&g_hpr_c, 0, sizeof g_hpr_c);
    memset(&g_hpr_s, 0, sizeof g_hpr_s);
    g_hpr_tick = NULL;
    memset(p, 0, sizeof *p);
    p->ep = -1;
}

#endif
