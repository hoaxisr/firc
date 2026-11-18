#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "quic.h"
#include "hoppair.h"
#include "certgen.h"
#include "scrypto.h"
#include "unit.h"

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

#define MIB 1048576
#define MAXST 1024
#define MAXOUT 1024

static uint8_t *g_pat;
static unsigned char g_ca1[2048], g_ca2[2048], g_leaf[2048], g_leaf_ip[2048], g_key[512];
static size_t g_ca1_n, g_ca2_n, g_leaf_n, g_leaf_ip_n, g_key_n;
static char g_ca1_pem[4096], g_ca2_pem[4096], g_leaf_pem[4096];
static const unsigned char *g_srv_der;
static size_t g_srv_n;
static int g_nb;
static int g_fail_seg_probe;
static unsigned g_seg_cmsgs;
static size_t g_emsg_over, g_largest;
static unsigned g_emsg_n;
static unsigned long g_clk_n, g_clk_calls;
static struct end *g_quiet, *g_clk_end;
static unsigned g_tx = 1;

int __real_getsockopt(int fd, int level, int name, void *val, socklen_t *len);
int __real_connect(int fd, const struct sockaddr *a, socklen_t n);
ssize_t __real_sendmsg(int fd, const struct msghdr *mh, int flags);
int __real_sendmmsg(int fd, struct mmsghdr *mm, unsigned n, int flags);
int __real_recvmmsg(int fd, struct mmsghdr *mm, unsigned n, int flags, struct timespec *t);

static int g_rx_log[2], g_rx_log_n, g_rx_log_on;

static void rx_note(int fd) {
    if (g_rx_log_on && g_rx_log_n < 2) g_rx_log[g_rx_log_n++] = fd;
}

int __wrap_recvmmsg(int fd, struct mmsghdr *mm, unsigned n, int flags, struct timespec *t) {
    rx_note(fd);
    return __real_recvmmsg(fd, mm, n, flags, t);
}

static int seg_probe_refused(int level, int name) {
    if (!(g_fail_seg_probe && level == SOL_UDP && name == UDP_SEGMENT)) return 0;
    errno = ENOPROTOOPT;
    return 1;
}

static int g_connects, g_connect_after_hook, g_hook_fd = -1;
static int g_conn_fd, g_conn_failed;
static uint16_t g_conn_port, g_conn_fail_port;

static uint16_t sa_port_of(const struct sockaddr *a) {
    if (a->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)a)->sin6_port);
    return ntohs(((const struct sockaddr_in *)a)->sin_port);
}

int __wrap_connect(int fd, const struct sockaddr *a, socklen_t n) {
    g_connects++;
    if (fd == g_hook_fd) g_connect_after_hook++;
    g_conn_fd = fd;
    g_conn_port = sa_port_of(a);
    if (g_conn_fail_port && g_conn_port == g_conn_fail_port) {
        g_conn_failed++;
        errno = EACCES;
        return -1;
    }
    return __real_connect(fd, a, n);
}

int __wrap_getsockopt(int fd, int level, int name, void *val, socklen_t *len) {
    return seg_probe_refused(level, name) ? -1 : __real_getsockopt(fd, level, name, val, len);
}

static void seg_scan(const struct msghdr *mh) {
    if (!mh->msg_control || mh->msg_controllen < sizeof(struct cmsghdr)) return;
    for (struct cmsghdr *c = CMSG_FIRSTHDR((struct msghdr *)mh); c; c = CMSG_NXTHDR((struct msghdr *)mh, c))
        if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_SEGMENT) g_seg_cmsgs++;
}

static size_t mh_len(const struct msghdr *mh) {
    size_t n = 0;
    for (size_t i = 0; i < mh->msg_iovlen; i++) n += mh->msg_iov[i].iov_len;
    return n;
}

static size_t mh_seg(const struct msghdr *mh) {
    if (!mh->msg_control || mh->msg_controllen < sizeof(struct cmsghdr)) return 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR((struct msghdr *)mh); c; c = CMSG_NXTHDR((struct msghdr *)mh, c))
        if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_SEGMENT) {
            uint16_t v;
            memcpy(&v, CMSG_DATA(c), sizeof v);
            return v;
        }
    return 0;
}

static size_t mh_dgram(const struct msghdr *mh) {
    size_t seg = mh_seg(mh), n = mh_len(mh);
    return seg && seg < n ? seg : n;
}

static int sendmsg_refused(const struct msghdr *mh) {
    seg_scan(mh);
    size_t d = mh_dgram(mh);
    if (g_emsg_over && d > g_emsg_over) {
        g_emsg_n++;
        errno = EMSGSIZE;
        return 1;
    }
    if (d > g_largest) g_largest = d;
    return 0;
}

static unsigned sendmmsg_taken(struct mmsghdr *mm, unsigned n) {
    for (unsigned i = 0; i < n; i++) seg_scan(&mm[i].msg_hdr);
    unsigned k = 0;
    while (k < n && !(g_emsg_over && mh_dgram(&mm[k].msg_hdr) > g_emsg_over)) k++;
    if (k == 0 && n > 0) {
        g_emsg_n++;
        errno = EMSGSIZE;
        return 0;
    }
    for (unsigned i = 0; i < k; i++)
        if (mh_dgram(&mm[i].msg_hdr) > g_largest) g_largest = mh_dgram(&mm[i].msg_hdr);
    return k;
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr *mh, int flags) {
    return sendmsg_refused(mh) ? -1 : __real_sendmsg(fd, mh, flags);
}

int __wrap_sendmmsg(int fd, struct mmsghdr *mm, unsigned n, int flags) {
    unsigned k = sendmmsg_taken(mm, n);
    return k == 0 && n > 0 ? -1 : __real_sendmmsg(fd, mm, k, flags);
}

#if (defined(__GLIBC__) && defined(__USE_TIME_BITS64) && __TIMESIZE == 32) || (defined(_REDIR_TIME64) && _REDIR_TIME64)
int __real___getsockopt64(int fd, int level, int name, void *val, socklen_t *len);
ssize_t __real___sendmsg64(int fd, const struct msghdr *mh, int flags);
int __real___sendmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags);
int __wrap___getsockopt64(int fd, int level, int name, void *val, socklen_t *len);
ssize_t __wrap___sendmsg64(int fd, const struct msghdr *mh, int flags);
int __wrap___sendmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags);
int __real___recvmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags, void *t);
int __wrap___recvmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags, void *t);

int __wrap___recvmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags, void *t) {
    rx_note(fd);
    return __real___recvmmsg64(fd, mm, n, flags, t);
}

int __wrap___getsockopt64(int fd, int level, int name, void *val, socklen_t *len) {
    return seg_probe_refused(level, name) ? -1 : __real___getsockopt64(fd, level, name, val, len);
}

ssize_t __wrap___sendmsg64(int fd, const struct msghdr *mh, int flags) {
    return sendmsg_refused(mh) ? -1 : __real___sendmsg64(fd, mh, flags);
}

int __wrap___sendmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags) {
    unsigned k = sendmmsg_taken(mm, n);
    return k == 0 && n > 0 ? -1 : __real___sendmmsg64(fd, mm, k, flags);
}
#endif

static int kernel_takes_segment(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int v = 0;
    socklen_t l = sizeof v;
    int ok = fd >= 0 && __real_getsockopt(fd, SOL_UDP, UDP_SEGMENT, &v, &l) == 0;
    if (fd >= 0) close(fd);
    return ok;
}

static uint64_t ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint8_t pat(size_t i) { return (uint8_t)((i * 31 + 7) % 251); }

struct strm {
    int64_t sid;
    size_t got, consumed, bad;
    int fin, closed, rx_reset, tx_stopped, responded;
    long send_in_close;
    uint64_t rx_err, tx_err;
    unsigned writable;
};

struct out {
    int used, own, fin, fin_done, dead;
    int64_t sid;
    uint8_t *buf;
    size_t n, cap, off;
};

struct end {
    struct qc *q;
    int hs, closed, reason, app;
    uint64_t code, closed_ms;
    char why[160];
    struct strm st[MAXST];
    int nst;
    struct out ob[MAXOUT];
    int echo, echo_nofin, consume_in_cb;
    size_t respond;
    unsigned dg_n;
    size_t dg_len;
    uint8_t dg[2048];
    int in_ep;
    struct end *fwd;
    int64_t fwd_sid;
    unsigned sopen;
    unsigned aborts;
    int64_t ab_sid;
    int ab_reset, ab_stopped;
    uint64_t ab_rx, ab_tx;
};

struct pair {
    struct end c, s;
    int ep;
};

struct fstate {
    unsigned tx_n, bad;
    size_t largest;
};

static struct strm *strm_find(struct end *e, int64_t sid) {
    for (int i = 0; i < e->nst; i++)
        if (e->st[i].sid == sid) return &e->st[i];
    return NULL;
}

static struct strm *strm_get(struct end *e, int64_t sid) {
    for (int i = 0; i < e->nst; i++)
        if (e->st[i].sid == sid) return &e->st[i];
    if (e->nst == MAXST) return NULL;
    struct strm *s = &e->st[e->nst++];
    memset(s, 0, sizeof *s);
    s->sid = sid;
    return s;
}

static struct out *out_for(struct end *e, int64_t sid) {
    for (int i = 0; i < MAXOUT; i++)
        if (e->ob[i].used && e->ob[i].sid == sid) return &e->ob[i];
    for (int i = 0; i < MAXOUT; i++)
        if (!e->ob[i].used) {
            memset(&e->ob[i], 0, sizeof e->ob[i]);
            e->ob[i].used = 1;
            e->ob[i].sid = sid;
            return &e->ob[i];
        }
    return NULL;
}

static void out_static(struct end *e, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct out *o = out_for(e, sid);
    if (!o) return;
    o->buf = (uint8_t *)d;
    o->n = n;
    o->fin = fin;
}

static void out_append(struct end *e, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct out *o = out_for(e, sid);
    if (!o) return;
    o->own = 1;
    if (o->n + n > o->cap) {
        size_t cap = (o->n + n) * 2 + 64;
        uint8_t *b = realloc(o->buf, cap);
        if (!b) return;
        o->buf = b;
        o->cap = cap;
    }
    memcpy(o->buf + o->n, d, n);
    o->n += n;
    if (fin) o->fin = 1;
}

static void drain(struct end *e) {
    if (!e->q) return;
    for (int i = 0; i < MAXOUT; i++) {
        struct out *o = &e->ob[i];
        if (!o->used || o->dead) continue;
        if (o->off == o->n && (!o->fin || o->fin_done)) continue;
        ssize_t w = qc_stream_send(e->q, o->sid, o->buf + o->off, o->n - o->off, o->fin);
        if (w == QC_EAGAIN) continue;
        if (w < 0) { o->dead = 1; continue; }
        o->off += (size_t)w;
        if (o->fin && o->off == o->n) o->fin_done = 1;
    }
}

static void ends_free_out(struct end *e) {
    for (int i = 0; i < MAXOUT; i++)
        if (e->ob[i].used && e->ob[i].own) free(e->ob[i].buf);
    memset(e->ob, 0, sizeof e->ob);
}

static void cb_hs(void *u) { ((struct end *)u)->hs++; }

static void cb_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct end *e = u;
    struct strm *s = strm_get(e, sid);
    if (!s) return;
    for (size_t i = 0; i < n; i++)
        if (d[i] != pat(s->got + i)) s->bad++;
    s->got += n;
    if (fin) s->fin = 1;
    if (e->echo) out_append(e, sid, d, n, fin && !e->echo_nofin);
    if (e->respond && !s->responded) {
        s->responded = 1;
        out_static(e, sid, g_pat, e->respond, 0);
    }
    if (e->consume_in_cb) {
        qc_stream_consumed(e->q, sid, n);
        s->consumed += n;
    }
    if (e->fwd) {
        out_append(e->fwd, e->fwd_sid, d, n, fin);
        drain(e->fwd);
        (void)qc_on_readable(e->fwd->q);
    }
}

static void cb_writable(void *u, int64_t sid) {
    struct strm *s = strm_get(u, sid);
    if (s) s->writable++;
}

static void cb_sclose(void *u, int64_t sid, int rx_reset, uint64_t rx_err, int tx_stopped, uint64_t tx_err) {
    struct strm *s = strm_find(u, sid);
    if (!s) return;
    s->closed++;
    s->send_in_close = qc_stream_send(((struct end *)u)->q, sid, (const uint8_t *)"z", 1, 0);
    s->rx_reset = rx_reset;
    s->rx_err = rx_err;
    s->tx_stopped = tx_stopped;
    s->tx_err = tx_err;
}

static void cb_dg(void *u, const uint8_t *d, size_t n) {
    struct end *e = u;
    e->dg_n++;
    e->dg_len = n;
    memcpy(e->dg, d, n < sizeof e->dg ? n : sizeof e->dg);
    if (e->echo) (void)qc_datagram_send(e->q, d, n);
}

static void cb_closed(void *u, int reason, int app, uint64_t code, const char *why) {
    struct end *e = u;
    e->closed++;
    e->reason = reason;
    e->app = app;
    e->code = code;
    e->closed_ms = ms_now();
    snprintf(e->why, sizeof e->why, "%s", why ? why : "");
}

static void cb_sopen(void *u) { ((struct end *)u)->sopen++; }

static void cb_abort(void *u, int64_t sid, int reset, uint64_t rx_err, int stopped, uint64_t tx_err) {
    struct end *e = u;
    e->aborts++;
    e->ab_sid = sid;
    e->ab_reset = reset;
    e->ab_rx = rx_err;
    e->ab_stopped = stopped;
    e->ab_tx = tx_err;
}

static const struct qc_ops g_ops = {
    .on_handshake = cb_hs, .on_stream_data = cb_data, .on_stream_writable = cb_writable,
    .on_streams_open = cb_sopen, .on_stream_peer_abort = cb_abort, .on_stream_close = cb_sclose,
    .on_datagram = cb_dg, .on_closed = cb_closed,
};

static void srv_cfg(struct qc_srv_cfg *sc, const char *alpn) {
    memset(sc, 0, sizeof *sc);
    sc->bind_host = "127.0.0.1";
    sc->alpn = alpn;
    sc->cert_der = g_srv_der;
    sc->cert_n = g_srv_n;
    sc->key_der = g_key;
    sc->key_n = g_key_n;
    sc->no_batch = g_nb;
}

static void cli_cfg(struct qc_cfg *c, const char *alpn) {
    memset(c, 0, sizeof *c);
    c->host = "127.0.0.1";
    c->sni = "node.test";
    c->alpn = alpn;
    c->ca_pem = (const uint8_t *)g_ca1_pem;
    c->ca_pem_n = strlen(g_ca1_pem);
    c->no_batch = g_nb;
}

static void ep_add(struct pair *p, struct end *e) {
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = e };
    if (epoll_ctl(p->ep, EPOLL_CTL_ADD, qc_fd(e->q), &ev) == 0) e->in_ep = 1;
}

static int pair_open(struct pair *p, struct qc_cfg *cc, const struct qc_srv_cfg *sc) {
    memset(p, 0, sizeof *p);
    p->ep = epoll_create1(0);
    if (qc_listen(sc, &g_ops, &p->s, &p->s.q) != 0) return -1;
    ep_add(p, &p->s);
    cc->port = qc_local_port(p->s.q);
    if (qc_open(cc, &g_ops, &p->c, &p->c.q) != 0) return -2;
    ep_add(p, &p->c);
    return 0;
}

static void pair_free(struct pair *p) {
    qc_free(p->c.q);
    qc_free(p->s.q);
    ends_free_out(&p->c);
    ends_free_out(&p->s);
    close(p->ep);
    p->c.q = p->s.q = NULL;
}

static void pass_ends(int ep, struct end **ends, int cnt) {
    int t = 50;
    for (int i = 0; i < cnt; i++) {
        if (!ends[i]->q || ends[i]->closed) continue;
        int k = qc_timeout_ms(ends[i]->q);
        if (k >= 0 && k < t) t = k;
    }
    struct epoll_event ev[4];
    int n = epoll_wait(ep, ev, 4, t);
    for (int i = 0; i < n; i++) {
        struct end *e = ev[i].data.ptr;
        if (e->closed) continue;
        unsigned long c0 = qc_clock_reads();
        (void)qc_on_readable(e->q);
        if (e == g_clk_end) {
            g_clk_n += qc_clock_reads() - c0;
            g_clk_calls++;
        }
    }
    for (int i = 0; i < cnt; i++) {
        struct end *e = ends[i];
        if (!e->q) continue;
        if (!e->closed && qc_timeout_ms(e->q) == 0) {
            unsigned long c0 = qc_clock_reads();
            (void)qc_on_timer(e->q);
            if (e == g_clk_end) {
                g_clk_n += qc_clock_reads() - c0;
                g_clk_calls++;
            }
        }
        if (e->closed && e->in_ep) {
            epoll_ctl(ep, EPOLL_CTL_DEL, qc_fd(e->q), NULL);
            e->in_ep = 0;
        }
        if (!e->closed) drain(e);
        if (e != g_quiet) qc_flush(e->q);
    }
}

static void pass(struct pair *p) {
    struct end *ends[2] = { &p->c, &p->s };
    pass_ends(p->ep, ends, 2);
}

typedef int (*cond_fn)(struct pair *p, void *arg);

static int pump_until(struct pair *p, cond_fn cond, void *arg, unsigned limit_ms) {
    uint64_t end = ms_now() + (uint64_t)limit_ms * g_tx;
    while (ms_now() < end) {
        if (cond(p, arg)) return 1;
        pass(p);
    }
    return cond(p, arg);
}

static void pump_for(struct pair *p, unsigned ms) {
    uint64_t end = ms_now() + (uint64_t)ms * g_tx;
    while (ms_now() < end) pass(p);
}

static int c_both_hs(struct pair *p, void *a) { (void)a; return p->c.hs && p->s.hs; }
static int c_cli_closed(struct pair *p, void *a) { (void)a; return p->c.closed != 0; }
static int c_srv_closed(struct pair *p, void *a) { (void)a; return p->s.closed != 0; }
static int c_cli_dg(struct pair *p, void *a) { (void)a; return p->c.dg_n > 0; }

static int c_cli_closed_or_hs(struct pair *p, void *a) { (void)a; return p->c.closed || p->c.hs; }

struct want { struct end *e; int64_t sid; size_t n; };

static int c_got(struct pair *p, void *a) {
    (void)p;
    struct want *w = a;
    struct strm *s = strm_get(w->e, w->sid);
    return s && s->got >= w->n;
}

static int c_closed_st(struct pair *p, void *a) {
    (void)p;
    struct want *w = a;
    struct strm *s = strm_get(w->e, w->sid);
    return s && s->closed;
}

static int c_writable(struct pair *p, void *a) {
    (void)p;
    struct want *w = a;
    struct strm *s = strm_get(w->e, w->sid);
    return s && s->writable;
}

static int open_stream(struct pair *p, int64_t *sid) {
    int rc = QC_EAGAIN;
    uint64_t end = ms_now() + 10000ull * g_tx;
    while ((rc = qc_stream_open(p->c.q, sid)) == QC_EAGAIN && ms_now() < end) pass(p);
    return rc;
}

static void name(char *buf, size_t cap, const char *what) {
    snprintf(buf, cap, "%s%s", what, g_nb ? " [no_batch]" : "");
}

static void handshake_completes_only_on_the_same_alpn(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("alpn: pair opens", 0, pair_open(&p, &cc, &sc));
    check("alpn h3/h3: both handshakes", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("alpn h3/h3: client on_handshake once", 1, p.c.hs);
    check("alpn h3/h3: server on_handshake once", 1, p.s.hs);
    pair_free(&p);

    cli_cfg(&cc, "hq");
    srv_cfg(&sc, "h3");
    check("alpn hq/h3: pair opens", 0, pair_open(&p, &cc, &sc));
    check("alpn hq/h3: client closed", 1, pump_until(&p, c_cli_closed, NULL, 10000));
    check("alpn hq/h3: reason handshake", QC_CLOSE_HANDSHAKE, p.c.reason);
    check("alpn hq/h3: no client on_handshake", 0, p.c.hs);
    pair_free(&p);
}

static void a_megabyte_on_a_stream_arrives_intact_both_ways(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    g_seg_cmsgs = 0;
    name(nm, sizeof nm, "1 MiB echo: stream opens");
    check(nm, 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    name(nm, sizeof nm, "1 MiB echo: client stream closes");
    check(nm, 1, pump_until(&p, c_closed_st, &w, 10000));
    struct strm *s = strm_get(&p.c, sid);
    name(nm, sizeof nm, "1 MiB echo: bytes back");
    check(nm, MIB, (long)s->got);
    name(nm, sizeof nm, "1 MiB echo: bytes intact");
    check(nm, 0, (long)s->bad);
    name(nm, sizeof nm, "1 MiB echo: FIN seen");
    check(nm, 1, s->fin);
    name(nm, sizeof nm, "1 MiB echo: close rx_reset 0");
    check(nm, 0, s->rx_reset);
    name(nm, sizeof nm, "1 MiB echo: close rx_err 0");
    check(nm, 0, (long)s->rx_err);
    name(nm, sizeof nm, "1 MiB echo: close tx_stopped 0");
    check(nm, 0, s->tx_stopped);
    name(nm, sizeof nm, "1 MiB echo: close tx_err 0");
    check(nm, 0, (long)s->tx_err);
    name(nm, sizeof nm, "1 MiB echo: no peer abort on a clean FIN");
    check(nm, 0, (long)(p.c.aborts + p.s.aborts));
    struct qc_stats st;
    qc_stats_get(p.c.q, &st);
    if (g_nb) {
        check("1 MiB echo: no_batch leaves GSO off", 0, st.gso);
        check("1 MiB echo: no_batch leaves GRO off", 0, st.gro);
    } else {
        int probe = kernel_takes_segment();
        printf("     batched path: probe %d gso %d gro %d rcvbuf %u sndbuf %u\n", probe, st.gso, st.gro, st.rcvbuf, st.sndbuf);
        check("1 MiB echo: the send buffer obtained is reported", 1, st.sndbuf > 0);
        check("1 MiB echo: GSO on exactly when the kernel answers UDP_SEGMENT", probe, st.gso);
        check("1 MiB echo: segmented sends seen exactly when GSO is on", probe, g_seg_cmsgs > 0);
    }
    pair_free(&p);
}

static void a_kernel_without_udp_segment_gets_plain_datagrams(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    g_fail_seg_probe = 1;
    g_seg_cmsgs = 0;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("no UDP_SEGMENT: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("no UDP_SEGMENT: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("no UDP_SEGMENT: stream opens", 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    check("no UDP_SEGMENT: echo stream closes", 1, pump_until(&p, c_closed_st, &w, 10000));
    struct strm *s = strm_get(&p.c, sid);
    check("no UDP_SEGMENT: 1 MiB back", MIB, (long)s->got);
    check("no UDP_SEGMENT: intact", 0, (long)s->bad);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    qc_stats_get(p.s.q, &b);
    check("no UDP_SEGMENT: client gso 0", 0, a.gso);
    check("no UDP_SEGMENT: server gso 0", 0, b.gso);
    check("no UDP_SEGMENT: no send carried UDP_SEGMENT", 0, (long)g_seg_cmsgs);
    pair_free(&p);
    g_fail_seg_probe = 0;
}

static void a_datagram_arrives_intact_and_an_oversized_one_is_refused(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.datagram_max = 1200;
    sc.datagram_max = 1200;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    uint8_t d[1000];
    for (size_t i = 0; i < sizeof d; i++) d[i] = pat(i);
    int ok = 0;
    for (int i = 0; i < 20 && !ok; i++) {
        (void)qc_datagram_send(p.c.q, d, sizeof d);
        ok = pump_until(&p, c_cli_dg, NULL, 500);
    }
    name(nm, sizeof nm, "datagram: echo arrives");
    check(nm, 1, ok);
    name(nm, sizeof nm, "datagram: length 1000");
    check(nm, 1000, (long)p.c.dg_len);
    name(nm, sizeof nm, "datagram: bytes intact");
    check(nm, 1, memcmp(p.c.dg, d, sizeof d) == 0);
    size_t max = qc_datagram_max(p.c.q);
    name(nm, sizeof nm, "datagram: max holds 1000");
    check(nm, 1, max >= 1000);
    uint8_t *big = calloc(1, max + 1);
    name(nm, sizeof nm, "datagram: max+1 refused");
    check(nm, QC_ETOOBIG, qc_datagram_send(p.c.q, big, max + 1));
    free(big);
    pair_free(&p);
}

static void window_round(const char *tag, uint64_t max_data, uint64_t max_stream_data, size_t stall) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.max_data = max_data;
    cc.max_stream_data = max_stream_data;
    pair_open(&p, &cc, &sc);
    p.s.respond = MIB;
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    snprintf(nm, sizeof nm, "%s: stream opens", tag);
    check(nm, 0, open_stream(&p, &sid));
    out_static(&p.c, sid, (const uint8_t *)"x", 1, 0);
    struct want w = { &p.c, sid, stall };
    snprintf(nm, sizeof nm, "%s: %zu bytes arrive", tag, stall);
    check(nm, 1, pump_until(&p, c_got, &w, 10000));
    pump_for(&p, 300);
    struct strm *s = strm_get(&p.c, sid);
    snprintf(nm, sizeof nm, "%s: and stay at %zu", tag, stall);
    check(nm, (long)stall, (long)s->got);
    uint64_t t0 = ms_now(), moved = 0, end = t0 + 10000ull * g_tx;
    while (s->got < MIB && ms_now() < end) {
        if (s->got > s->consumed) {
            qc_stream_consumed(p.c.q, sid, s->got - s->consumed);
            s->consumed = s->got;
            qc_flush(p.c.q);
        }
        pass(&p);
        if (!moved && s->got > stall) moved = ms_now();
    }
    snprintf(nm, sizeof nm, "%s: count moves within 2 s of the first consume", tag);
    check(nm, 1, moved && moved - t0 <= 2000ull * g_tx);
    snprintf(nm, sizeof nm, "%s: 1 MiB in the end", tag);
    check(nm, MIB, (long)s->got);
    snprintf(nm, sizeof nm, "%s: intact", tag);
    check(nm, 0, (long)s->bad);
    pair_free(&p);
}

static void unread_stream_data_stops_at_the_window(void) {
    window_round("stream window", 0, 65536, 65536);
    window_round("connection window", 131072, 0, 131072);
}

static void a_pin_decides_alone(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    uint8_t pins[64];
    memset(pins, 0, sizeof pins);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.pin_sha256 = pins;
    cc.pin_n = 1;
    check("pin zeros: pair opens", 0, pair_open(&p, &cc, &sc));
    check("pin zeros: client closed", 1, pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
    check("pin zeros: reason handshake", QC_CLOSE_HANDSHAKE, p.c.reason);
    check("pin zeros: why says pin", 1, strstr(p.c.why, "pin") != NULL);
    check("pin zeros: no on_handshake", 0, p.c.hs);
    pair_free(&p);

    struct qc_tls *t = qc_tls_new(0, (const uint8_t *)g_ca1_pem, strlen(g_ca1_pem), NULL);
    check("pin zeros, shared roots: context", 1, t != NULL);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.tls = t;
    cc.pin_sha256 = pins;
    cc.pin_n = 1;
    check("pin zeros, shared roots: pair opens", 0, pair_open(&p, &cc, &sc));
    check("pin zeros, shared roots: client closed", 1, pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
    check("pin zeros, shared roots: why says pin", 1, strstr(p.c.why, "pin") != NULL);
    check("pin zeros, shared roots: no on_handshake", 0, p.c.hs);
    pair_free(&p);
    qc_tls_free(t);

    sc_hash(SC_SHA256, g_leaf, g_leaf_n, pins + 32);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.ca_pem = NULL;
    cc.ca_pem_n = 0;
    cc.ca_file = "/nonexistent/roots.pem";
    cc.pin_sha256 = pins;
    cc.pin_n = 2;
    check("pin second matches: pair opens", 0, pair_open(&p, &cc, &sc));
    check("pin second matches: completes", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("pin second matches: not closed", 0, p.c.closed);
    pair_free(&p);

    char chain[8192];
    snprintf(chain, sizeof chain, "%s%s", g_leaf_pem, g_ca2_pem);
    sc_hash(SC_SHA256, g_ca2, g_ca2_n, pins);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.chain_pem = chain;
    sc.chain_pem_n = strlen(chain);
    cc.pin_sha256 = pins;
    cc.pin_n = 1;
    check("pin of a chain certificate only: pair opens", 0, pair_open(&p, &cc, &sc));
    check("pin of a chain certificate only: client closed", 1,
          pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
    check("pin of a chain certificate only: why says pin", 1, strstr(p.c.why, "pin") != NULL);
    check("pin of a chain certificate only: no on_handshake", 0, p.c.hs);
    pair_free(&p);
}

static void one_check(const char *what, const char *sni, const char *vname, const char *pem, int insecure,
                      int ip_leaf, int want_hs, const char *want_why) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.sni = sni;
    cc.verify_name = vname;
    cc.ca_pem = (const uint8_t *)pem;
    cc.ca_pem_n = strlen(pem);
    cc.insecure = insecure;
    if (ip_leaf) {
        sc.cert_der = g_leaf_ip;
        sc.cert_n = g_leaf_ip_n;
    }
    snprintf(nm, sizeof nm, "%s: pair opens", what);
    check(nm, 0, pair_open(&p, &cc, &sc));
    if (want_hs) {
        snprintf(nm, sizeof nm, "%s: completes", what);
        check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000) && !p.c.closed);
    } else {
        snprintf(nm, sizeof nm, "%s: closed", what);
        check(nm, 1, pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
        snprintf(nm, sizeof nm, "%s: reason handshake", what);
        check(nm, QC_CLOSE_HANDSHAKE, p.c.reason);
        snprintf(nm, sizeof nm, "%s: why says %s", what, want_why);
        check(nm, 1, strstr(p.c.why, want_why) != NULL);
        snprintf(nm, sizeof nm, "%s: no on_handshake", what);
        check(nm, 0, p.c.hs);
    }
    pair_free(&p);
}

static void chain_and_name_are_checked_without_a_pin(void) {
    one_check("sni other.test", "other.test", NULL, g_ca1_pem, 0, 0, 0, "name");
    one_check("verify_name node.test", "other.test", "node.test", g_ca1_pem, 0, 0, 1, NULL);
    one_check("unrelated CA", "node.test", NULL, g_ca2_pem, 0, 0, 0, "chain");
    one_check("unrelated CA, insecure", "node.test", NULL, g_ca2_pem, 1, 0, 1, NULL);
    one_check("no names, IP SAN 127.0.0.1", NULL, NULL, g_ca1_pem, 0, 1, 1, NULL);
    one_check("no names, no IP SAN", NULL, NULL, g_ca1_pem, 0, 0, 0, "name");
}

static void a_server_without_alpn_is_refused(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "");
    check("no alpn from server: pair opens", 0, pair_open(&p, &cc, &sc));
    check("no alpn from server: client closed", 1, pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
    check("no alpn from server: reason handshake", QC_CLOSE_HANDSHAKE, p.c.reason);
    check("no alpn from server: why says alpn", 1, strstr(p.c.why, "alpn") != NULL);
    check("no alpn from server: no on_handshake", 0, p.c.hs);
    pair_free(&p);
}

static void a_refused_port_is_fatal_only_before_the_handshake(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    check("refused after handshake: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    open_stream(&p, &sid);
    qc_free(p.s.q);
    p.s.q = NULL;
    out_static(&p.c, sid, g_pat, 65536, 0);
    pump_for(&p, 500);
    check("refused after handshake: connection stays", 0, p.c.closed);
    pair_free(&p);

    srv_cfg(&sc, "h3");
    struct qc *dead = NULL;
    qc_listen(&sc, &g_ops, NULL, &dead);
    uint16_t port = qc_local_port(dead);
    qc_free(dead);
    memset(&p, 0, sizeof p);
    p.ep = epoll_create1(0);
    cli_cfg(&cc, "h3");
    cc.port = port;
    check("refused before handshake: open", 0, qc_open(&cc, &g_ops, &p.c, &p.c.q));
    ep_add(&p, &p.c);
    check("refused before handshake: closed", 1, pump_until(&p, c_cli_closed, NULL, 3000));
    check("refused before handshake: reason error", QC_CLOSE_ERROR, p.c.reason);
    check("refused before handshake: why says refused", 1, strstr(p.c.why, "refused") != NULL);
    pair_free(&p);
}

static void an_oversized_filter_overhead_is_refused(void) {
    struct fstate f;
    struct qc_filter fl = { NULL, NULL, &f, 65 };
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc *q = NULL;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.port = 9;
    cc.filter = &fl;
    sc.filter = &fl;
    check("overhead 65: qc_open refuses", QC_EINVAL, qc_open(&cc, &g_ops, NULL, &q));
    check("overhead 65: qc_listen refuses", QC_EINVAL, qc_listen(&sc, &g_ops, NULL, &q));
}

static int g_hook_calls, g_hook_type, g_hook_rc, g_hook_connects_seen;

static int hook_probe(int fd) {
    int t = 0;
    socklen_t l = sizeof t;
    g_hook_calls++;
    g_hook_fd = fd;
    g_hook_connects_seen = g_connects;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &t, &l) == 0) g_hook_type = t;
    return g_hook_rc;
}

static int open_fds(void) {
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static void prepare_runs_before_connect_and_can_refuse(void) {
    struct qc_cfg cc;
    struct qc *q = NULL;
    cli_cfg(&cc, "h3");
    cc.port = 9;
    cc.prepare = hook_probe;
    g_hook_rc = 0;
    int c0 = g_connects;
    check("prepare ok: qc_open succeeds", 0, qc_open(&cc, &g_ops, NULL, &q));
    check("prepare ok: the hook ran once", 1, g_hook_calls);
    check("prepare ok: it saw a datagram socket", SOCK_DGRAM, g_hook_type);
    check("prepare ok: no connect had happened yet", c0, g_hook_connects_seen);
    check("prepare ok: connect was reached", c0 + 1, g_connects);
    check("prepare ok: connect used the hook's socket", 1, g_connect_after_hook);
    qc_free(q);

    q = NULL;
    g_hook_rc = -1;
    int fds = open_fds();
    c0 = g_connects;
    check("prepare refuses: QC_ESOCK", QC_ESOCK, qc_open(&cc, &g_ops, NULL, &q));
    check("prepare refuses: the hook ran again", 2, g_hook_calls);
    check("prepare refuses: no connect", c0, g_connects);
    check("prepare refuses: no connection returned", 1, q == NULL);
    check("prepare refuses: no fd leaked", fds, open_fds());
}

static size_t f_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct fstate *f = u;
    memset(dst, 0xA5, 8);
    for (size_t i = 0; i < n; i++) dst[8 + i] = src[i] ^ 0x5C;
    f->tx_n++;
    if (n + 8 > f->largest) f->largest = n + 8;
    return n + 8;
}

static size_t f_rx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct fstate *f = u;
    int ok = n >= 8;
    for (size_t i = 0; ok && i < 8; i++)
        if (src[i] != 0xA5) ok = 0;
    if (!ok) { f->bad++; return 0; }
    for (size_t i = 8; i < n; i++) dst[i - 8] = src[i] ^ 0x5C;
    return n - 8;
}

static size_t f_id_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct fstate *f = u;
    memcpy(dst, src, n);
    f->tx_n++;
    if (n > f->largest) f->largest = n;
    return n;
}

static size_t f_id_rx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    (void)u;
    memcpy(dst, src, n);
    return n;
}

static size_t echo_largest(int no_pmtud, int overhead) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct fstate fc, fs;
    memset(&fc, 0, sizeof fc);
    memset(&fs, 0, sizeof fs);
    struct qc_filter fid = { f_id_tx, f_id_rx, &fc, 0 }, flc = { f_tx, f_rx, &fc, 8 }, fls = { f_tx, f_rx, &fs, 8 };
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.no_pmtud = no_pmtud;
    cc.filter = overhead ? &flc : &fid;
    if (overhead) sc.filter = &fls;
    size_t got = 0;
    int64_t sid = -1;
    if (pair_open(&p, &cc, &sc) == 0 && pump_until(&p, c_both_hs, NULL, 10000)) {
        p.s.echo = 1;
        p.s.consume_in_cb = 1;
        p.c.consume_in_cb = 1;
        open_stream(&p, &sid);
        out_static(&p.c, sid, g_pat, MIB, 1);
        struct want w = { &p.c, sid, 0 };
        pump_until(&p, c_closed_st, &w, 10000);
        struct strm *s = strm_get(&p.c, sid);
        got = s->got == MIB && s->bad == 0 ? fc.largest : 0;
    }
    pair_free(&p);
    return got;
}

static void no_pmtud_holds_1250_byte_packets(void) {
    char nm[128];
    name(nm, sizeof nm, "no_pmtud: bare packets are exactly 1250");
    check(nm, 1250, (long)echo_largest(1, 0));
    name(nm, sizeof nm, "no_pmtud: with an 8-byte filter 1250 + 8 is exactly 1258 on the wire");
    check(nm, 1258, (long)echo_largest(1, 8));
    name(nm, sizeof nm, "pmtud on: packets grow past 1280");
    check(nm, 1, echo_largest(0, 0) > 1280);
}

static void a_filter_wraps_every_datagram_on_the_wire(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    struct fstate fc, fs;
    memset(&fc, 0, sizeof fc);
    memset(&fs, 0, sizeof fs);
    struct qc_filter flc = { f_tx, f_rx, &fc, 8 }, fls = { f_tx, f_rx, &fs, 8 };
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &flc;
    sc.filter = &fls;
    name(nm, sizeof nm, "filter: pair opens");
    check(nm, 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    name(nm, sizeof nm, "filter: handshake");
    check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000));
    open_stream(&p, &sid);
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    pump_until(&p, c_closed_st, &w, 10000);
    struct strm *s = strm_get(&p.c, sid);
    name(nm, sizeof nm, "filter: 1 MiB echo back intact");
    check(nm, 1, s->got == MIB && s->bad == 0 && s->fin);
    qc_close(p.c.q, 7);
    name(nm, sizeof nm, "filter: server sees the close");
    check(nm, 1, pump_until(&p, c_srv_closed, NULL, 10000));
    name(nm, sizeof nm, "filter: close is an application close");
    check(nm, 1, p.s.app);
    name(nm, sizeof nm, "filter: close code 7");
    check(nm, 7, (long)p.s.code);
    name(nm, sizeof nm, "filter: no datagram without the prefix");
    check(nm, 0, (long)fs.bad);
    name(nm, sizeof nm, "filter: largest output <= 1452");
    check(nm, 1, fc.largest <= 1452);
    name(nm, sizeof nm, "filter: largest output > 1280");
    check(nm, 1, fc.largest > 1280);
    struct qc_stats st;
    qc_stats_get(p.c.q, &st);
    name(nm, sizeof nm, "filter: dg_tx equals the tx hook calls");
    check(nm, (long)fc.tx_n, (long)st.dg_tx);
    pair_free(&p);

    memset(&fc, 0, sizeof fc);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &flc;
    cc.handshake_ms = 500;
    uint64_t t0 = ms_now();
    pair_open(&p, &cc, &sc);
    name(nm, sizeof nm, "filter on one side: client closed");
    check(nm, 1, pump_until(&p, c_cli_closed, NULL, 10000));
    uint64_t dt = p.c.closed_ms - t0;
    name(nm, sizeof nm, "filter on one side: no handshake");
    check(nm, 0, p.c.hs + p.s.hs);
    name(nm, sizeof nm, "filter on one side: reason handshake");
    check(nm, QC_CLOSE_HANDSHAKE, p.c.reason);
    name(nm, sizeof nm, "filter on one side: closed in 400..3000 ms");
    check(nm, 1, dt >= 400 && dt <= 3000ull * g_tx);
    pair_free(&p);
}

static void an_idle_connection_closes_at_the_idle_limit(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.idle_ms = 1000;
    sc.idle_ms = 1000;
    pair_open(&p, &cc, &sc);
    check("idle: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    uint64_t last = ms_now(), seen = 0, end = last + 10000ull * g_tx;
    while (!p.c.closed && ms_now() < end) {
        struct qc_stats a, b;
        qc_stats_get(p.c.q, &a);
        qc_stats_get(p.s.q, &b);
        uint64_t sum = a.pkt_sent + a.pkt_recv + b.pkt_sent + b.pkt_recv;
        if (sum != seen) { seen = sum; last = ms_now(); }
        pass(&p);
    }
    check("idle: client closed", 1, p.c.closed);
    check("idle: reason idle", QC_CLOSE_IDLE, p.c.reason);
    uint64_t dt = p.c.closed_ms - last;
    check("idle: 900..5000 ms after the last packet", 1, dt >= 900 && dt <= 5000ull * g_tx);
    pair_free(&p);
}

static int c_cli_rx_grew(struct pair *p, void *a) {
    struct qc_stats st;
    qc_stats_get(p->c.q, &st);
    return st.pkt_recv > *(const uint64_t *)a;
}

static void keepalive_can_be_switched_at_run_time(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.idle_ms = 1500;
    sc.idle_ms = 1500;
    check("keepalive switch: pair opens", 0, pair_open(&p, &cc, &sc));
    check("keepalive switch: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    qc_keepalive(p.c.q, 500);
    pump_for(&p, 300);
    struct qc_stats a, b;
    qc_stats_get(p.s.q, &a);
    pump_for(&p, 4000);
    qc_stats_get(p.s.q, &b);
    check("keepalive switch: both alive after 4000 ms of silence", 1, !p.c.closed && !p.s.closed);
    check("keepalive switch: the server received at least 6 packets", 1, b.pkt_recv - a.pkt_recv >= 6);
    qc_stats_get(p.c.q, &a);
    uint64_t r0 = a.pkt_recv;
    check("keepalive switch: the client receives", 1, pump_until(&p, c_cli_rx_grew, &r0, 2000));
    qc_keepalive(p.c.q, 0);
    uint64_t t = ms_now();
    check("keepalive switch: off, the client closes", 1, pump_until(&p, c_cli_closed, NULL, 10000));
    check("keepalive switch: by idle", QC_CLOSE_IDLE, p.c.reason);
    uint64_t dt = p.c.closed_ms - t;
    check("keepalive switch: 1300..5000 ms after the switch", 1, dt >= 1300 && dt <= 5000ull * g_tx);
    pair_free(&p);
}

static void clamp_round(unsigned ka, const char *tag) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char b[128];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.idle_ms = 1500;
    sc.idle_ms = 1500;
    snprintf(b, sizeof b, "%s: pair opens", tag);
    check(b, 0, pair_open(&p, &cc, &sc));
    snprintf(b, sizeof b, "%s: handshake", tag);
    check(b, 1, pump_until(&p, c_both_hs, NULL, 10000));
    qc_keepalive(p.c.q, ka);
    pump_for(&p, 300);
    struct qc_stats a, z;
    qc_stats_get(p.s.q, &a);
    uint64_t t0 = ms_now();
    pump_for(&p, 4000);
    uint64_t el = ms_now() - t0;
    qc_stats_get(p.s.q, &z);
    uint64_t n = z.pkt_recv - a.pkt_recv, most = 2 * (el / 500) + 2;
    snprintf(b, sizeof b, "%s: both alive after 4000 ms", tag);
    check(b, 1, !p.c.closed && !p.s.closed);
    snprintf(b, sizeof b, "%s: 6..%llu server packets (%llu)", tag, (unsigned long long)most, (unsigned long long)n);
    check(b, 1, n >= 6 && n <= most);
    pair_free(&p);
}

static void keepalive_is_clamped_to_the_idle_and_floored(void) {
    clamp_round(10000, "keepalive 10000, idle 1500");
    clamp_round(100, "keepalive 100");
}

static void stop_and_reset_reach_the_peer_with_their_codes(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1, sid2 = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.echo_nofin = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("stop: stream opens", 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, 3, 1);
    struct want wc = { &p.c, sid, 3 }, ws = { &p.s, sid, 0 };
    check("stop: echo arrives", 1, pump_until(&p, c_got, &wc, 10000));
    check("stop: qc_stream_stop", 0, qc_stream_stop(p.c.q, sid, 5));
    check("stop: server stream closes", 1, pump_until(&p, c_closed_st, &ws, 10000));
    struct strm *s = strm_get(&p.s, sid);
    check("stop: server tx_stopped 1", 1, s->tx_stopped);
    check("stop: server tx_err 5", 5, (long)s->tx_err);
    check("stop: server rx_reset 0", 0, s->rx_reset);
    check("stop: a server send after it fails", 1, qc_stream_send(p.s.q, sid, (const uint8_t *)"z", 1, 0) < 0);
    check("stop: a send from inside on_stream_close fails", QC_ENOSTREAM, s->send_in_close);

    check("reset: stream opens", 0, open_stream(&p, &sid2));
    out_static(&p.c, sid2, g_pat, 3, 0);
    struct want ws2 = { &p.s, sid2, 3 };
    check("reset: server got the bytes", 1, pump_until(&p, c_got, &ws2, 10000));
    check("reset: qc_stream_reset", 0, qc_stream_reset(p.c.q, sid2, 7));
    check("reset: server stream closes", 1, pump_until(&p, c_closed_st, &ws2, 10000));
    s = strm_get(&p.s, sid2);
    check("reset: server rx_reset 1", 1, s->rx_reset);
    check("reset: server rx_err 7", 7, (long)s->rx_err);
    pair_free(&p);
}

static void room_coming_back_is_announced(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_buf = 65536;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("room: stream opens", 0, open_stream(&p, &sid));
    ssize_t w = qc_stream_send(p.c.q, sid, g_pat, 100000, 0);
    check("room: send returns short", 65536, (long)w);
    check("room: no room left", 0, (long)qc_stream_room(p.c.q, sid));
    struct strm *s = strm_get(&p.c, sid);
    check("room: nothing announced yet", 0, (long)s->writable);
    struct want ww = { &p.c, sid, 0 };
    check("room: on_stream_writable fires", 1, pump_until(&p, c_writable, &ww, 10000));
    check("room: a further send succeeds", 1, qc_stream_send(p.c.q, sid, g_pat + 65536, 1000, 0) > 0);
    check("room: none on a stream that does not exist", 0, (long)qc_stream_room(p.c.q, sid + 400));
    pair_free(&p);
}

static void suite_round(int chacha, unsigned want) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.prefer_chacha = chacha;
    pair_open(&p, &cc, &sc);
    snprintf(nm, sizeof nm, "suite prefer_chacha %d: handshake", chacha);
    check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000));
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    qc_stats_get(p.s.q, &b);
    snprintf(nm, sizeof nm, "suite prefer_chacha %d: client 0x%04x", chacha, want);
    check(nm, (long)want, (long)a.cipher);
    snprintf(nm, sizeof nm, "suite prefer_chacha %d: server 0x%04x", chacha, want);
    check(nm, (long)want, (long)b.cipher);
    pair_free(&p);
}

static void the_preferred_suite_is_negotiated(void) {
    suite_round(1, 0x1303);
    suite_round(0, 0x1301);
}

static void credit_round(int give_back) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    const char *tag = give_back ? "credit returned" : "credit kept";
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.max_data = MIB;
    cc.max_stream_data = 262144;
    pair_open(&p, &cc, &sc);
    p.s.respond = 131072;
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    int ok = 1;
    for (int i = 0; i < 8; i++) {
        int64_t sid = -1;
        if (open_stream(&p, &sid) != 0) { ok = 0; break; }
        out_static(&p.c, sid, (const uint8_t *)"x", 1, 0);
        struct want w = { &p.c, sid, 131072 };
        if (!pump_until(&p, c_got, &w, 10000)) { ok = 0; break; }
        if (qc_stream_reset(p.c.q, sid, 1) != 0) ok = 0;
        if (give_back) qc_conn_consumed(p.c.q, 131072);
    }
    snprintf(nm, sizeof nm, "%s: eight streams of 128 KiB each", tag);
    check(nm, 1, ok);
    p.s.respond = 262144;
    int64_t sid9 = -1;
    snprintf(nm, sizeof nm, "%s: ninth stream opens", tag);
    check(nm, 0, open_stream(&p, &sid9));
    out_static(&p.c, sid9, (const uint8_t *)"x", 1, 0);
    struct want w9 = { &p.c, sid9, give_back ? 262144 : 0 };
    snprintf(nm, sizeof nm, "%s: ninth stream reaches %d bytes", tag, give_back ? 262144 : 0);
    check(nm, 1, pump_until(&p, c_got, &w9, 10000));
    pump_for(&p, 300);
    struct strm *s = strm_get(&p.c, sid9);
    snprintf(nm, sizeof nm, "%s: and stays there", tag);
    check(nm, give_back ? 262144 : 0, s ? (long)s->got : 0);
    snprintf(nm, sizeof nm, "%s: connection alive", tag);
    check(nm, 0, p.c.closed);
    pair_free(&p);
}

static void connection_credit_of_a_dead_stream_comes_back(void) {
    credit_round(1);
    credit_round(0);
}

static int certs_make(void) {
    struct tcg_key *k1 = tcg_key_new(), *k2 = tcg_key_new(), *kl = tcg_key_new();
    int rc = -1;
    if (!k1 || !k2 || !kl) goto out;
    if (tcg_issue(k1, "Test CA One", NULL, 1, NULL, NULL, 0, g_ca1, sizeof g_ca1, &g_ca1_n) != 0) goto out;
    if (tcg_issue(k2, "Test CA Two", NULL, 1, NULL, NULL, 0, g_ca2, sizeof g_ca2, &g_ca2_n) != 0) goto out;
    if (tcg_issue(kl, "node.test", NULL, 0, k1, g_ca1, g_ca1_n, g_leaf, sizeof g_leaf, &g_leaf_n) != 0) goto out;
    static const unsigned char lo[4] = { 127, 0, 0, 1 };
    if (tcg_issue_ip4(kl, "node.test", lo, k1, g_ca1, g_ca1_n, g_leaf_ip, sizeof g_leaf_ip, &g_leaf_ip_n) != 0) goto out;
    if (tcg_key_der(kl, g_key, sizeof g_key, &g_key_n) != 0) goto out;
    if (tcg_der_to_pem(g_leaf, g_leaf_n, g_leaf_pem, sizeof g_leaf_pem) != 0) goto out;
    g_srv_der = g_leaf;
    g_srv_n = g_leaf_n;
    if (tcg_der_to_pem(g_ca1, g_ca1_n, g_ca1_pem, sizeof g_ca1_pem) != 0) goto out;
    if (tcg_der_to_pem(g_ca2, g_ca2_n, g_ca2_pem, sizeof g_ca2_pem) != 0) goto out;
    rc = 0;
out:
    tcg_key_free(k1);
    tcg_key_free(k2);
    tcg_key_free(kl);
    return rc;
}

static void forget(struct end *e, int64_t sid) {
    for (int i = 0; i < e->nst; i++)
        if (e->st[i].sid == sid) {
            e->st[i] = e->st[--e->nst];
            break;
        }
    for (int i = 0; i < MAXOUT; i++)
        if (e->ob[i].used && e->ob[i].sid == sid) {
            if (e->ob[i].own) free(e->ob[i].buf);
            memset(&e->ob[i], 0, sizeof e->ob[i]);
        }
}

static int c_open_ok(struct pair *p, void *a) {
    int64_t *sid = a;
    return qc_stream_open(p->c.q, sid) == 0;
}

static void streams_come_back_after_they_close(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 4;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("stream limit: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    int done = 0;
    for (int i = 0; i < 40; i++) {
        int64_t sid = -1;
        if (!pump_until(&p, c_open_ok, &sid, 10000)) break;
        out_static(&p.c, sid, g_pat, 3, 1);
        struct want w = { &p.c, sid, 3 };
        if (!pump_until(&p, c_closed_st, &w, 10000)) break;
        struct strm *s = strm_get(&p.c, sid);
        if (s->got == 3 && s->bad == 0 && s->fin) done++;
        forget(&p.c, sid);
        forget(&p.s, sid);
    }
    check("stream limit 4: 40 streams in turn all echo", 40, done);
    pair_free(&p);

    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 4;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    int64_t ids[4];
    int opened = 0;
    for (int i = 0; i < 4; i++)
        if (qc_stream_open(p.c.q, &ids[i]) == 0) {
            opened++;
            out_static(&p.c, ids[i], g_pat, 1, 0);
        }
    check("stream limit 4: four open at once", 4, opened);
    int64_t fifth = -1;
    check("stream limit 4: the fifth waits", QC_EAGAIN, qc_stream_open(p.c.q, &fifth));
    pump_for(&p, 300);
    check("stream limit 4: and still waits while four stay open", QC_EAGAIN, qc_stream_open(p.c.q, &fifth));
    check("stream limit 4: closing one", 0, (long)qc_stream_send(p.c.q, ids[0], NULL, 0, 1));
    check("stream limit 4: the fifth opens after one closed", 1, pump_until(&p, c_open_ok, &fifth, 10000));
    pair_free(&p);
}

static void unsent_counts_only_what_no_packet_carried(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1, sid2 = -1;
    const size_t window = 16384, sent = 40000, small = 100;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_stream_data = window;
    pair_open(&p, &cc, &sc);
    pump_until(&p, c_both_hs, NULL, 10000);
    check("unsent: stream opens", 0, open_stream(&p, &sid));
    check("unsent: unknown stream is 0", 0, (long)qc_stream_unsent(p.c.q, sid + 400));
    check("unsent: all accepted", (long)sent, (long)qc_stream_send(p.c.q, sid, g_pat, sent, 0));
    struct want ws = { &p.s, sid, window };
    check("unsent: the peer gets its window", 1, pump_until(&p, c_got, &ws, 10000));
    pump_for(&p, 300);
    struct strm *ss = strm_get(&p.s, sid);
    check("unsent: and no more", (long)window, (long)ss->got);
    check("unsent: sent minus the window", (long)(sent - window), (long)qc_stream_unsent(p.c.q, sid));
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (ss->got < sent && ms_now() < end) {
        if (ss->got > ss->consumed) {
            qc_stream_consumed(p.s.q, sid, ss->got - ss->consumed);
            ss->consumed = ss->got;
        }
        pass(&p);
    }
    pump_for(&p, 300);
    check("unsent: the peer read everything", (long)sent, (long)ss->got);
    check("unsent: acknowledged, room is back to the default eighth of the 16 MiB budget", 2097152, (long)qc_stream_room(p.c.q, sid));
    check("unsent: 0 after the peer read it", 0, (long)qc_stream_unsent(p.c.q, sid));
    check("unsent: second stream opens", 0, open_stream(&p, &sid2));
    pump_for(&p, 300);
    check("unsent: small send accepted", (long)small, (long)qc_stream_send(p.c.q, sid2, g_pat, small, 0));
    check("unsent: still unacknowledged", (long)(2097152 - small), (long)qc_stream_room(p.c.q, sid2));
    check("unsent: 0 once it went out", 0, (long)qc_stream_unsent(p.c.q, sid2));
    pair_free(&p);
}

struct tagf {
    uint8_t tag[4];
    unsigned foreign;
};

static size_t tag_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct tagf *t = u;
    memcpy(dst, t->tag, 4);
    memcpy(dst + 4, src, n);
    return n + 4;
}

static size_t tag_rx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct tagf *t = u;
    if (n < 4 || memcmp(src, t->tag, 4) != 0) {
        t->foreign++;
        return 0;
    }
    memcpy(dst, src + 4, n - 4);
    return n - 4;
}

static void a_callback_may_drive_another_connection(void) {
    static struct pair pa, pb;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sa = -1, sb = -1;
    struct tagf ta = { { 0xA1, 0xA2, 0xA3, 0xA4 }, 0 }, tb = { { 0xB1, 0xB2, 0xB3, 0xB4 }, 0 };
    struct qc_filter fa = { tag_tx, tag_rx, &ta, 4 }, fb = { tag_tx, tag_rx, &tb, 4 };
    unsigned long n0, n1;
    size_t max0, max1;
    qc_nested_stats(&n0, &max0);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = sc.filter = &fa;
    check("two connections: A opens", 0, pair_open(&pa, &cc, &sc));
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = sc.filter = &fb;
    check("two connections: B opens", 0, pair_open(&pb, &cc, &sc));
    int ep = epoll_create1(0);
    struct end *ends[4] = { &pa.c, &pa.s, &pb.c, &pb.s };
    for (int i = 0; i < 4; i++) {
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = ends[i] };
        epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(ends[i]->q), &ev);
    }
    pa.s.echo = pb.s.echo = 1;
    pa.s.consume_in_cb = pb.s.consume_in_cb = pa.c.consume_in_cb = pb.c.consume_in_cb = 1;
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (!(pa.c.hs && pb.c.hs && pa.s.hs && pb.s.hs) && ms_now() < end) pass_ends(ep, ends, 4);
    check("two connections: both handshakes", 1, pa.c.hs && pb.c.hs);
    check("two connections: A stream", 0, qc_stream_open(pa.c.q, &sa));
    check("two connections: B stream", 0, qc_stream_open(pb.c.q, &sb));
    pa.c.fwd = &pb.c;
    pa.c.fwd_sid = sb;
    out_static(&pa.c, sa, g_pat, MIB, 1);
    struct strm *a = strm_get(&pa.c, sa), *b = strm_get(&pb.c, sb);
    end = ms_now() + 20000ull * g_tx;
    while (!(a->closed && b->closed) && ms_now() < end) pass_ends(ep, ends, 4);
    check("two connections: A got 1 MiB back", MIB, (long)a->got);
    check("two connections: A intact", 0, (long)a->bad);
    check("two connections: B got 1 MiB back", MIB, (long)b->got);
    check("two connections: B intact", 0, (long)b->bad);
    check("two connections: both streams closed cleanly", 1, a->closed && b->closed && a->fin && b->fin);
    check("two connections: neither connection closed", 0, pa.c.closed + pb.c.closed);
    check("two connections: no datagram of B reached pair A", 0, (long)ta.foreign);
    check("two connections: no datagram of A reached pair B", 0, (long)tb.foreign);
    qc_nested_stats(&n1, &max1);
    (void)n0;
    (void)max0;
    printf("     nested receives: %lu, largest %zu B\n", n1, max1);
    check("two connections: a nested receive happened", 1, n1 > 0);
    if (g_nb) check("two connections: nested no_batch receive asked for no more than 32 x 2048 + filter + 16 KiB", 1,
                    max1 <= 32 * 2048 + QC_FILTER_RX_MAX + 16384);
    close(ep);
    pair_free(&pa);
    pair_free(&pb);
}

static int c_sopen(struct pair *p, void *a) { (void)a; return p->c.sopen > 0; }

static void the_owner_hears_when_streams_open_again(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t a = -1, b = -1, c = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 2;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("streams open: two allowed", 1, qc_stream_open(p.c.q, &a) == 0 && qc_stream_open(p.c.q, &b) == 0);
    out_static(&p.c, a, g_pat, 1, 0);
    out_static(&p.c, b, g_pat, 1, 0);
    check("streams open: the third waits", QC_EAGAIN, qc_stream_open(p.c.q, &c));
    pump_for(&p, 300);
    check("streams open: nothing announced while both stay open", 0, (long)p.c.sopen);
    qc_stream_send(p.c.q, a, NULL, 0, 1);
    check("streams open: on_streams_open fires after one closed", 1, pump_until(&p, c_sopen, NULL, 10000));
    check("streams open: once", 1, (long)p.c.sopen);
    check("streams open: the next open succeeds", 0, qc_stream_open(p.c.q, &c));
    pair_free(&p);
}

static int c_all_back(struct pair *p, void *a) {
    int64_t *ids = a;
    for (int i = 0; i < 600; i++) {
        struct strm *s = strm_find(&p->c, ids[i]);
        if (!s || !s->closed) return 0;
    }
    return 1;
}

static void six_hundred_streams_at_once(void) {
    static struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    static int64_t ids[600];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 600;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    int opened = 0;
    for (int i = 0; i < 600; i++)
        if (qc_stream_open(p.c.q, &ids[i]) == 0) {
            opened++;
            strm_get(&p.c, ids[i]);
            out_static(&p.c, ids[i], g_pat, 4096, 1);
        }
    check("600 streams: all open at once", 600, opened);
    check("600 streams: all echo and close", 1, pump_until(&p, c_all_back, ids, 20000));
    int good = 0;
    for (int i = 0; i < 600; i++) {
        struct strm *s = strm_find(&p.c, ids[i]);
        if (s && s->got == 4096 && s->bad == 0 && s->fin) good++;
    }
    check("600 streams: 4 KiB each intact", 600, good);
    uint64_t cs, co, ss, so;
    qc_probe_stats(p.c.q, &cs, &co);
    qc_probe_stats(p.s.q, &ss, &so);
    printf("     probes: client %llu steps / %llu ops, server %llu / %llu\n", (unsigned long long)cs,
           (unsigned long long)co, (unsigned long long)ss, (unsigned long long)so);
    check("600 streams: client stream operations counted", 1, co >= 600);
    check("600 streams: server stream operations counted", 1, so >= 600);
    check("600 streams: client under 20 probe steps per operation", 1, cs < 20 * co);
    check("600 streams: server under 20 probe steps per operation", 1, ss < 20 * so);
    pair_free(&p);
}

static int c_ab(struct pair *p, void *a) { (void)a; return p->c.aborts > 0; }

static void a_peer_abort_of_one_direction_is_heard(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1, sid2 = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("peer stop: stream opens", 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, 3, 0);
    struct want ws = { &p.s, sid, 3 };
    check("peer stop: server got the bytes", 1, pump_until(&p, c_got, &ws, 10000));
    check("peer stop: server stops reading", 0, qc_stream_stop(p.s.q, sid, 5));
    check("peer stop: on_stream_peer_abort", 1, pump_until(&p, c_ab, NULL, 10000));
    check("peer stop: once", 1, (long)p.c.aborts);
    check("peer stop: sid", (long)sid, (long)p.c.ab_sid);
    check("peer stop: reset 0", 0, p.c.ab_reset);
    check("peer stop: rx_err 0", 0, (long)p.c.ab_rx);
    check("peer stop: stopped 1", 1, p.c.ab_stopped);
    check("peer stop: tx_err 5", 5, (long)p.c.ab_tx);
    check("peer stop: no on_stream_close yet", 0, strm_get(&p.c, sid)->closed);
    check("peer stop: server still sends", 3, (long)qc_stream_send(p.s.q, sid, g_pat, 3, 0));
    struct want wc = { &p.c, sid, 3 };
    check("peer stop: client still reads", 1, pump_until(&p, c_got, &wc, 10000));

    p.c.aborts = 0;
    check("peer reset: stream opens", 0, open_stream(&p, &sid2));
    out_static(&p.c, sid2, g_pat, 3, 0);
    struct want ws2 = { &p.s, sid2, 3 };
    check("peer reset: server got the bytes", 1, pump_until(&p, c_got, &ws2, 10000));
    check("peer reset: server resets its sending side", 0, qc_stream_reset_write(p.s.q, sid2, 7));
    check("peer reset: on_stream_peer_abort", 1, pump_until(&p, c_ab, NULL, 10000));
    pump_for(&p, 300);
    check("peer reset: once", 1, (long)p.c.aborts);
    check("peer reset: sid", (long)sid2, (long)p.c.ab_sid);
    check("peer reset: reset 1", 1, p.c.ab_reset);
    check("peer reset: rx_err 7", 7, (long)p.c.ab_rx);
    check("peer reset: stopped 0", 0, p.c.ab_stopped);
    check("peer reset: tx_err 0", 0, (long)p.c.ab_tx);
    check("peer reset: client can still send", 3, (long)qc_stream_send(p.c.q, sid2, g_pat + 3, 3, 0));
    struct want ws3 = { &p.s, sid2, 6 };
    check("peer reset: server gets it", 1, pump_until(&p, c_got, &ws3, 10000));
    pair_free(&p);
}

static void a_reset_stream_forgets_what_it_had_to_send(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_buf = 65536;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("reset unsent: stream opens", 0, open_stream(&p, &sid));
    check("reset unsent: send returns short", 65536, (long)qc_stream_send(p.c.q, sid, g_pat, 100000, 0));
    check("reset unsent: something still unsent", 1, qc_stream_unsent(p.c.q, sid) > 0);
    check("reset unsent: reset", 0, qc_stream_reset(p.c.q, sid, 3));
    check("reset unsent: unsent 0 at once", 0, (long)qc_stream_unsent(p.c.q, sid));
    pump_for(&p, 500);
    struct strm *s = strm_get(&p.c, sid);
    check("reset unsent: no on_stream_writable for a reset stream", 0, (long)s->writable);
    pair_free(&p);
}

static int c_srv_all_100(struct pair *p, void *a) {
    int64_t *ids = a;
    for (int i = 0; i < 600; i++) {
        struct strm *s = strm_find(&p->s, ids[i]);
        if (!s || s->got < 100) return 0;
    }
    return 1;
}

static void acknowledged_data_holds_no_chunk(void) {
    static struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    static int64_t ids[600];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 600;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    int ok = 0;
    for (int i = 0; i < 600; i++)
        if (qc_stream_open(p.c.q, &ids[i]) == 0 && qc_stream_send(p.c.q, ids[i], g_pat, 100, 0) == 100) ok++;
    check("send chunks: 600 streams sent 100 bytes", 600, ok);
    size_t held = qc_send_held(p.c.q);
    printf("     held while unacknowledged: %zu B\n", held);
    check("send chunks: unacknowledged hold at most 600 x 4096", 1, held >= 600 * 100 && held <= 600 * 4096);
    check("send chunks: the server got all 600", 1, pump_until(&p, c_srv_all_100, ids, 10000));
    pump_for(&p, 300);
    check("send chunks: all acknowledged, nothing held", 0, (long)qc_send_held(p.c.q));
    check("send chunks: 5000 bytes accepted", 5000, (long)qc_stream_send(p.c.q, ids[1], g_pat + 100, 5000, 0));
    check("send chunks: a first send of 5000 holds 8192", 8192, (long)qc_send_held(p.c.q));
    out_static(&p.c, ids[0], g_pat, MIB, 0);
    struct want w = { &p.s, ids[0], 100 + MIB };
    check("send chunks: 1 MiB more arrives", 1, pump_until(&p, c_got, &w, 10000));
    pump_for(&p, 300);
    check("send chunks: after 1 MiB acknowledged, nothing held", 0, (long)qc_send_held(p.c.q));
    pair_free(&p);
}


static void dont_fragment_is_set_on_both_families(void) {
    static const char *const host[2] = { "127.0.0.1", "::1" };
    static const int level[2] = { IPPROTO_IP, IPPROTO_IPV6 };
    static const int opt[2] = { IP_MTU_DISCOVER, IPV6_MTU_DISCOVER };
    static const int want[2] = { IP_PMTUDISC_PROBE, IPV6_PMTUDISC_PROBE };
    for (int i = 0; i < 2; i++) {
        struct qc_cfg cc;
        struct qc *q = NULL;
        struct end e;
        char nm[128];
        memset(&e, 0, sizeof e);
        cli_cfg(&cc, "h3");
        cc.host = host[i];
        cc.port = 9;
        snprintf(nm, sizeof nm, "df %s: opens", host[i]);
        check(nm, 0, qc_open(&cc, &g_ops, &e, &q));
        int v = -1;
        socklen_t l = sizeof v;
        snprintf(nm, sizeof nm, "df %s: reads back the probe mode", host[i]);
        check(nm, want[i], q && __real_getsockopt(qc_fd(q), level[i], opt[i], &v, &l) == 0 ? v : -1);
        qc_free(q);
    }
}

static void an_oversized_datagram_is_lost_not_fatal(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    g_emsg_over = 1300;
    g_emsg_n = 0;
    g_largest = 0;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    name(nm, sizeof nm, "EMSGSIZE: handshake");
    check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000));
    open_stream(&p, &sid);
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    name(nm, sizeof nm, "EMSGSIZE: 1 MiB echo closes");
    check(nm, 1, pump_until(&p, c_closed_st, &w, 10000));
    struct strm *s = strm_get(&p.c, sid);
    name(nm, sizeof nm, "EMSGSIZE: 1 MiB back intact with fin");
    check(nm, 1, s->got == MIB && s->bad == 0 && s->fin);
    name(nm, sizeof nm, "EMSGSIZE: connection alive");
    check(nm, 0, p.c.closed + p.s.closed);
    name(nm, sizeof nm, "EMSGSIZE: some datagram was refused");
    check(nm, 1, g_emsg_n > 0);
    printf("     refused %u, largest through %zu\n", g_emsg_n, g_largest);
    name(nm, sizeof nm, "EMSGSIZE: the largest datagram through is at most 1300");
    check(nm, 1, g_largest > 0 && g_largest <= 1300);
    g_emsg_over = 0;
    pair_free(&p);
}

static void credit_round_no_flush(int defer) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.max_stream_data = 65536;
    cc.defer_flush = defer;
    pair_open(&p, &cc, &sc);
    p.s.respond = MIB;
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &sid);
    out_static(&p.c, sid, (const uint8_t *)"x", 1, 0);
    g_quiet = &p.c;
    struct strm *s = strm_get(&p.c, sid);
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (s->got < MIB && ms_now() < end) {
        if (s->got > s->consumed) {
            qc_stream_consumed(p.c.q, sid, s->got - s->consumed);
            s->consumed = s->got;
        }
        pass(&p);
    }
    g_quiet = NULL;
    snprintf(nm, sizeof nm, "credit without qc_flush, defer %d: 1 MiB through a 65536 window", defer);
    check(nm, MIB, (long)s->got);
    snprintf(nm, sizeof nm, "credit without qc_flush, defer %d: intact", defer);
    check(nm, 0, (long)s->bad);
    pair_free(&p);
}

static void credit_needs_no_flush_from_the_owner(void) {
    credit_round_no_flush(0);
    credit_round_no_flush(1);
}

static unsigned long burst_calls(int defer) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t warm = -1, sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.defer_flush = defer;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &warm);
    out_static(&p.c, warm, g_pat, MIB, 0);
    struct want w = { &p.s, warm, MIB };
    pump_until(&p, c_got, &w, 10000);
    open_stream(&p, &sid);
    pump_for(&p, 300);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    int took = 0;
    for (int i = 0; i < 64; i++) took += qc_stream_send(p.c.q, sid, g_pat + (size_t)i * 1024, 1024, 0) == 1024;
    qc_flush(p.c.q);
    qc_stats_get(p.c.q, &b);
    char nm[128];
    snprintf(nm, sizeof nm, "64 sends of 1 KiB, defer %d: all taken", defer);
    check(nm, 64, took);
    struct want w2 = { &p.s, sid, 65536 };
    snprintf(nm, sizeof nm, "64 sends of 1 KiB, defer %d: the peer gets them", defer);
    check(nm, 1, pump_until(&p, c_got, &w2, 10000) && strm_get(&p.s, sid)->bad == 0);
    pair_free(&p);
    printf("     defer %d: %llu send calls\n", defer, (unsigned long long)(b.tx_calls - a.tx_calls));
    return (unsigned long)(b.tx_calls - a.tx_calls);
}

static void deferred_sends_leave_together(void) {
    char nm[128];
    name(nm, sizeof nm, "defer_flush 1: 64 sends cost at most 2 send calls after one qc_flush");
    check(nm, 1, burst_calls(1) <= 2);
    name(nm, sizeof nm, "defer_flush 0: 64 sends cost at least 32 send calls");
    check(nm, 1, burst_calls(0) >= 32);
}

static void four_megabytes_with_bounded_work(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    unsigned rx;
    size_t fl;
    qc_work_stats(p.c.q, &rx, &fl);
    qc_work_stats(p.s.q, &rx, &fl);
    open_stream(&p, &sid);
    out_static(&p.c, sid, g_pat, 4 * MIB, 1);
    struct want w = { &p.c, sid, 0 };
    name(nm, sizeof nm, "4 MiB echo: closes");
    check(nm, 1, pump_until(&p, c_closed_st, &w, 20000));
    struct strm *s = strm_get(&p.c, sid);
    name(nm, sizeof nm, "4 MiB echo: intact with fin");
    check(nm, 1, s->got == 4 * MIB && s->bad == 0 && s->fin);
    unsigned crx, srx;
    size_t cfl, sfl;
    qc_work_stats(p.c.q, &crx, &cfl);
    qc_work_stats(p.s.q, &srx, &sfl);
    printf("     most datagrams in one read call: client %u, server %u; most bytes in one flush: client %zu, server %zu\n",
           crx, srx, cfl, sfl);
    name(nm, sizeof nm, "4 MiB echo: no read call handled more than 128 datagrams");
    check(nm, 1, crx <= 128 && srx <= 128);
    name(nm, sizeof nm, "4 MiB echo: no flush wrote more than 64 KiB and one datagram");
    check(nm, 1, cfl <= 65536 + 1452 && sfl <= 65536 + 1452);
    name(nm, sizeof nm, "4 MiB echo: the work was there to bound");
    check(nm, 1, crx > 0 && cfl > 0);
    pair_free(&p);
}

static void one_clock_read_per_batch(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    int nb = g_nb;
    g_nb = 1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    g_nb = nb;
    pair_open(&p, &cc, &sc);
    p.s.respond = MIB;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &sid);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    g_clk_n = 0;
    g_clk_calls = 0;
    g_clk_end = &p.c;
    out_static(&p.c, sid, (const uint8_t *)"x", 1, 0);
    struct want w = { &p.c, sid, MIB };
    check("clock: 1 MiB received", 1, pump_until(&p, c_got, &w, 10000));
    g_clk_end = NULL;
    qc_stats_get(p.c.q, &b);
    uint64_t dg = b.pkt_recv - a.pkt_recv;
    uint64_t rxc = b.rx_calls - a.rx_calls;
    printf("     clock reads %lu for %llu datagrams received in %lu calls and %llu receive calls\n", g_clk_n,
           (unsigned long long)dg, g_clk_calls, (unsigned long long)rxc);
    check("clock: reads were counted", 1, g_clk_n > 0);
    if (g_tx == 1)
        check("clock: fewer than 1 read per 8 datagrams received", 1, g_clk_n * 8 < dg);
    else
        check("clock: at most 1 read per call and 1 per receive call", 1, g_clk_n <= g_clk_calls + rxc);
    pair_free(&p);
}

static int c_srv_got_all(struct pair *p, void *a) {
    int64_t *ids = a;
    for (int i = 0; i < 8; i++) {
        struct strm *s = strm_find(&p->s, ids[i]);
        if (!s || s->got < MIB || !s->fin) return 0;
    }
    return 1;
}

struct qsend { size_t off; unsigned seen; int waiting; };

static void budget_drain(struct pair *p, int64_t *ids, struct qsend *qs) {
    for (int i = 0; i < 8; i++) {
        struct strm *s = strm_get(&p->c, ids[i]);
        if (qs[i].off >= MIB || (qs[i].waiting && s->writable == qs[i].seen)) continue;
        ssize_t w = qc_stream_send(p->c.q, ids[i], g_pat + qs[i].off, MIB - qs[i].off, 1);
        if (w > 0) qs[i].off += (size_t)w;
        qs[i].waiting = qs[i].off < MIB;
        qs[i].seen = s->writable;
    }
}

static void srv_consume_all(struct end *e) {
    for (int i = 0; i < e->nst; i++) {
        struct strm *s = &e->st[i];
        if (s->got > s->consumed) {
            qc_stream_consumed(e->q, s->sid, s->got - s->consumed);
            s->consumed = s->got;
        }
    }
}

static void the_connection_budget_bounds_what_streams_queue(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t ids[8];
    struct qsend qs[8];
    memset(qs, 0, sizeof qs);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_total = MIB;
    cc.send_buf = MIB;
    sc.max_stream_data = 65536;
    pair_open(&p, &cc, &sc);
    check("budget: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    int opened = 0;
    for (int i = 0; i < 8; i++) {
        if (qc_stream_open(p.c.q, &ids[i]) != 0) break;
        strm_get(&p.c, ids[i]);
        opened++;
    }
    check("budget: eight streams open", 8, opened);
    size_t taken = 0;
    int again = 0;
    for (int i = 0; i < 8; i++) {
        ssize_t w = qc_stream_send(p.c.q, ids[i], g_pat, MIB, 1);
        if (w > 0) { taken += (size_t)w; qs[i].off = (size_t)w; }
        if (w == 4096) again++;
        qs[i].waiting = qs[i].off < MIB;
        qs[i].seen = strm_get(&p.c, ids[i])->writable;
    }
    check("budget: 1048576 plus seven exempt 4096 accepted across eight streams", MIB + 7 * 4096, (long)taken);
    check("budget: seven take only their exempt first 4096", 7, again);
    check("budget: a refused stream has no room", 0, (long)qc_stream_room(p.c.q, ids[1]));
    uint64_t end = ms_now() + 300ull * g_tx;
    while (ms_now() < end) {
        pass(&p);
        budget_drain(&p, ids, qs);
    }
    p.s.consume_in_cb = 1;
    srv_consume_all(&p.s);
    end = ms_now() + 20000ull * g_tx;
    while (!c_srv_got_all(&p, ids) && ms_now() < end) {
        pass(&p);
        budget_drain(&p, ids, qs);
        srv_consume_all(&p.s);
    }
    int told = 0, good = 0;
    for (int i = 1; i < 8; i++) told += strm_get(&p.c, ids[i])->writable > 0;
    for (int i = 0; i < 8; i++) {
        struct strm *s = strm_find(&p.s, ids[i]);
        good += s && s->got == MIB && s->bad == 0 && s->fin;
    }
    check("budget: every refused stream is told it is writable", 7, told);
    check("budget: all 8 MiB arrive intact with fin", 8, good);
    pair_free(&p);
}

static void a_dead_write_side_frees_its_chunks_at_once(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t a = -1, b = -1, c = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_total = MIB;
    cc.send_buf = MIB;
    sc.max_stream_data = 65536;
    pair_open(&p, &cc, &sc);
    pump_until(&p, c_both_hs, NULL, 10000);
    check("dead write side: streams open", 1, open_stream(&p, &a) == 0 && open_stream(&p, &b) == 0);
    check("dead write side: 1 MiB queued", MIB, (long)qc_stream_send(p.c.q, a, g_pat, MIB, 0));
    check("dead write side: the budget is spent, B keeps its exempt 4096", 4096, (long)qc_stream_room(p.c.q, b));
    struct want w = { &p.s, a, 65536 };
    check("dead write side: the peer holds its window", 1, pump_until(&p, c_got, &w, 10000));
    pump_for(&p, 300);
    check("dead write side: chunks held before the reset", 1, qc_send_held(p.c.q) >= MIB - 65536);
    check("dead write side: reset of the write side", 0, qc_stream_reset_write(p.c.q, a, 3));
    check("dead write side: nothing held at once", 0, (long)qc_send_held(p.c.q));
    check("dead write side: nothing unsent", 0, (long)qc_stream_unsent(p.c.q, a));
    check("dead write side: the budget is back", MIB, (long)qc_stream_room(p.c.q, b));
    pump_for(&p, 300);
    check("dead write side: the peer keeps its side open", 0, strm_get(&p.s, a)->closed);
    check("dead write side: still nothing held", 0, (long)qc_send_held(p.c.q));

    check("peer stop: stream opens", 0, open_stream(&p, &c));
    check("peer stop: 1 MiB queued", MIB, (long)qc_stream_send(p.c.q, c, g_pat, MIB, 0));
    struct want w2 = { &p.s, c, 65536 };
    check("peer stop: the peer holds its window", 1, pump_until(&p, c_got, &w2, 10000));
    p.c.aborts = 0;
    check("peer stop: the peer stops", 0, qc_stream_stop(p.s.q, c, 5));
    check("peer stop: heard", 1, pump_until(&p, c_ab, NULL, 10000));
    check("peer stop: nothing held at once", 0, (long)qc_send_held(p.c.q));
    check("peer stop: the budget is back", MIB, (long)qc_stream_room(p.c.q, b));
    pair_free(&p);
}

static void pump_srv_only(struct pair *p, int (*cond)(struct pair *, void *), void *arg, unsigned limit_ms) {
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &p->s };
    epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(p->s.q), &ev);
    uint64_t end = ms_now() + (uint64_t)limit_ms * g_tx;
    while (!cond(p, arg) && ms_now() < end) {
        int t = qc_timeout_ms(p->s.q);
        struct epoll_event got;
        if (epoll_wait(ep, &got, 1, t < 0 || t > 20 ? 20 : t) > 0) (void)qc_on_readable(p->s.q);
        if (qc_timeout_ms(p->s.q) == 0) (void)qc_on_timer(p->s.q);
        qc_flush(p->s.q);
    }
    close(ep);
}

static int c_srv_64x200(struct pair *p, void *a) {
    int64_t *ids = a;
    for (int i = 0; i < 64; i++) {
        struct strm *s = strm_find(&p->s, ids[i]);
        if (!s || s->got < 200) return 0;
    }
    return 1;
}

static int good_64x200(struct pair *p, const int64_t *ids) {
    int good = 0;
    for (int i = 0; i < 64; i++) {
        struct strm *s = strm_find(&p->s, ids[i]);
        good += s && s->got == 200 && s->bad == 0;
    }
    return good;
}

static void small_sends_of_many_streams_share_packets(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t warm = -1, ids[64];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.defer_flush = 1;
    sc.max_streams = 100;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &warm);
    out_static(&p.c, warm, g_pat, MIB, 0);
    struct want w = { &p.s, warm, MIB };
    pump_until(&p, c_got, &w, 10000);
    int opened = 0;
    for (int i = 0; i < 64; i++) opened += qc_stream_open(p.c.q, &ids[i]) == 0;
    pump_for(&p, 300);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    int took = 0;
    for (int i = 0; i < 64; i++) took += qc_stream_send(p.c.q, ids[i], g_pat, 200, 0) == 200;
    qc_flush(p.c.q);
    qc_stats_get(p.c.q, &b);
    name(nm, sizeof nm, "64 x 200 B: 64 streams took 200 bytes each");
    check(nm, 1, opened == 64 && took == 64);
    printf("     64 x 200 B: %llu datagrams in one flush\n", (unsigned long long)(b.dg_tx - a.dg_tx));
    if (g_tx == 1) {
        pump_srv_only(&p, c_srv_64x200, ids, 10000);
        name(nm, sizeof nm, "64 x 200 B: all 12800 bytes left in that one flush");
        check(nm, 64, good_64x200(&p, ids));
    }
    pump_until(&p, c_srv_64x200, ids, 10000);
    struct qc_stats c;
    qc_stats_get(p.c.q, &c);
    printf("     64 x 200 B: %llu datagrams until all arrived\n", (unsigned long long)(c.dg_tx - a.dg_tx));
    name(nm, sizeof nm, "64 x 200 B: all 12800 bytes arrive");
    check(nm, 64, good_64x200(&p, ids));
    name(nm, sizeof nm, "64 x 200 B: in at most 12 datagrams");
    check(nm, 1, c.dg_tx - a.dg_tx >= 1 && c.dg_tx - a.dg_tx <= 12);
    pair_free(&p);
}

static void a_path_that_shrinks_closes_the_connection(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1, sid2 = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &sid);
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    name(nm, sizeof nm, "mtu drop: 1 MiB echo at full size");
    check(nm, 1, pump_until(&p, c_closed_st, &w, 10000) && strm_get(&p.c, sid)->got == MIB);
    struct qc_stats st;
    qc_stats_get(p.c.q, &st);
    g_emsg_n = 0;
    g_emsg_over = 1100;
    open_stream(&p, &sid2);
    out_static(&p.c, sid2, g_pat, 65536, 0);
    name(nm, sizeof nm, "mtu drop: the client closes");
    check(nm, 1, pump_until(&p, c_cli_closed, NULL, 10000));
    g_emsg_over = 0;
    name(nm, sizeof nm, "mtu drop: refused sends seen");
    check(nm, 1, g_emsg_n > 0);
    name(nm, sizeof nm, "mtu drop: a transport close");
    check(nm, 1, p.c.reason == QC_CLOSE_ERROR && !p.c.app);
    name(nm, sizeof nm, "mtu drop: why says path mtu");
    check(nm, 1, strstr(p.c.why, "path mtu") != NULL);
    pair_free(&p);
}

static void idle_flushes_cost_nothing(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    pump_until(&p, c_both_hs, NULL, 10000);
    pump_for(&p, 300);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    unsigned long c0 = qc_clock_reads();
    for (int i = 0; i < 100; i++) qc_flush(p.c.q);
    unsigned long c1 = qc_clock_reads();
    qc_stats_get(p.c.q, &b);
    check("idle qc_flush: 100 calls read the clock 0 times", 0, (long)(c1 - c0));
    check("idle qc_flush: and send nothing", 0, (long)(b.tx_calls - a.tx_calls));
    pair_free(&p);
}

static int c_fifth_mib(struct pair *p, void *a) {
    struct strm *s = strm_find(&p->s, *(int64_t *)a);
    return s && s->got >= MIB;
}

static long offer(struct qc *q, int64_t sid, size_t n) {
    long took = 0;
    while (n > 0) {
        size_t k = n < MIB ? n : MIB;
        ssize_t w = qc_stream_send(q, sid, g_pat + (size_t)took % (251 * 12532), k, 0);
        if (w <= 0) break;
        took += (long)w;
        n -= (size_t)w;
        if ((size_t)w < k) break;
    }
    return took;
}

static void slow_streams_leave_room_for_another(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t ids[5];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_stream_data = 65536;
    pair_open(&p, &cc, &sc);
    check("slow peers: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    int opened = 0;
    for (int i = 0; i < 5; i++) opened += open_stream(&p, &ids[i]) == 0;
    check("slow peers: five streams", 5, opened);
    long full = 0;
    for (int i = 0; i < 4; i++) full += offer(p.c.q, ids[i], 3 * MIB) == 2097152;
    check("slow peers: four fill their 2 MiB send_buf", 4, full);
    check("slow peers: the fifth still takes its 2 MiB at once", 2097152, offer(p.c.q, ids[4], 3 * MIB));
    uint64_t end = ms_now() + 20000ull * g_tx;
    while (!c_fifth_mib(&p, &ids[4]) && ms_now() < end) {
        pass(&p);
        struct strm *s = strm_find(&p.s, ids[4]);
        if (s && s->got > s->consumed) {
            qc_stream_consumed(p.s.q, ids[4], s->got - s->consumed);
            s->consumed = s->got;
        }
    }
    struct strm *f = strm_find(&p.s, ids[4]);
    check("slow peers: the fifth delivers 1 MiB intact", 1, f && f->got >= MIB && f->bad == 0);
    int stuck = 0;
    for (int i = 0; i < 4; i++) {
        struct strm *s = strm_find(&p.s, ids[i]);
        stuck += s && s->got <= 65536;
    }
    check("slow peers: the four stay at their window", 4, stuck);
    pair_free(&p);
}

static uint64_t brutal_window(uint64_t bps, uint64_t srtt_ns, uint64_t mds) {
    uint64_t w = bps * (srtt_ns / 1000) / 500000;
    return w < mds ? mds : w;
}

static int c_cli_idle(struct pair *p, void *a) {
    (void)a;
    struct qc_stats st;
    qc_stats_get(p->c.q, &st);
    return st.in_flight == 0;
}

static int echo_open(struct pair *p, int64_t *sid) {
    if (open_stream(p, sid) != 0) return -1;
    out_static(&p->c, *sid, g_pat, MIB, 1);
    return 0;
}

static int echo_intact(struct pair *p, int64_t sid) {
    struct strm *s = strm_get(&p->c, sid);
    return s && s->got == MIB && s->bad == 0 && s->fin;
}

static void brutal_replaces_the_controller_after_the_handshake(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    int64_t sid = -1;
    struct qc *q = NULL;
    cli_cfg(&cc, "h3");
    cc.port = 443;
    cc.cc = QC_CC_BRUTAL;
    check("brutal: Brutal at open is refused", QC_EINVAL, qc_open(&cc, &g_ops, NULL, &q));
    check("brutal: no connection for it", 1, q == NULL);
    check("brutal: no connection, no swap", QC_EINVAL, qc_cc_brutal(NULL, 1048576, 0));

    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.cc = QC_CC_RENO;
    check("brutal: reno pair opens", 0, pair_open(&p, &cc, &sc));
    qc_stats_get(p.c.q, &st);
    check("brutal: reno at open reports 1", QC_CC_RENO, st.cc);
    check("brutal: reno paces 1024e9 / (512e6 / 38400) at open", 76801920, (long)st.pacing_bps);
    check("brutal: reno is not Brutal", 0, (long)st.ack_q16);
    pair_free(&p);

    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("brutal: pair opens", 0, pair_open(&p, &cc, &sc));
    check("brutal: refused before the handshake", QC_EAGAIN, qc_cc_brutal(p.c.q, 1048576, 0));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("brutal: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    qc_stats_get(p.c.q, &st);
    check("brutal: BBR by default", QC_CC_BBR, st.cc);
    check("brutal: BBR is not Brutal", 0, (long)st.ack_q16);
    check("brutal: 0 B/s refused", QC_EINVAL, qc_cc_brutal(p.c.q, 0, 0));
    qc_stats_get(p.c.q, &st);
    check("brutal: still BBR after the refusal", QC_CC_BBR, st.cc);
    check("brutal: warm-up echo opens", 0, echo_open(&p, &sid));
    struct want w = { &p.c, sid, 0 };
    check("brutal: warm-up echo closes", 1, pump_until(&p, c_closed_st, &w, 10000));
    check("brutal: swap at 1048576 B/s", 0, qc_cc_brutal(p.c.q, 1048576, 0));
    qc_stats_get(p.c.q, &st);
    uint64_t srtt = qc_srtt_ns(p.c.q);
    check("brutal: reports Brutal", QC_CC_BRUTAL, st.cc);
    check("brutal: paces 1024e9 / 976562", 1048576, (long)st.pacing_bps);
    check("brutal: fresh ack rate 1.0", 65536, (long)st.ack_q16);
    check("brutal: window max(1452, 1048576 x srtt_us / 500000) + 1", (long)brutal_window(1048576, srtt, 1452) + 1, (long)st.cwnd);
    qc_close(p.c.q, 0);
    check("brutal: client closes", 1, pump_until(&p, c_cli_closed, NULL, 10000));
    check("brutal: refused once closed", QC_ECLOSED, qc_cc_brutal(p.c.q, 1048576, 0));
    pair_free(&p);
}

static void brutal_widens_the_send_buffers_to_one_second_of_its_rate(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t a = -1, b = -1, c = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("brutal buffers: pair opens", 0, pair_open(&p, &cc, &sc));
    check("brutal buffers: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("brutal buffers: stream A opens", 0, open_stream(&p, &a));
    check("brutal buffers: BBR keeps the eighth of 16 MiB", 2097152, (long)qc_stream_room(p.c.q, a));
    check("brutal buffers: swap at 100000 B/s", 0, qc_cc_brutal(p.c.q, 100000, 0));
    check("brutal buffers: a rate under the default keeps it", 2097152, (long)qc_stream_room(p.c.q, a));
    check("brutal buffers: swap at 12 MiB/s", 0, qc_cc_brutal(p.c.q, 12 * MIB, 0));
    check("brutal buffers: A may hold one second of the rate", 12 * MIB, (long)qc_stream_room(p.c.q, a));
    check("brutal buffers: A takes 12 MiB", 12 * MIB, offer(p.c.q, a, 12 * MIB));
    check("brutal buffers: A is full", 0, (long)qc_stream_room(p.c.q, a));
    check("brutal buffers: stream B opens", 0, open_stream(&p, &b));
    check("brutal buffers: the connection holds two seconds, B gets the second", 12 * MIB, (long)qc_stream_room(p.c.q, b));
    check("brutal buffers: B takes 12 MiB", 12 * MIB, offer(p.c.q, b, 12 * MIB));
    check("brutal buffers: stream C opens", 0, open_stream(&p, &c));
    check("brutal buffers: the 24 MiB budget is spent, C keeps its exempt 4096", 4096, (long)qc_stream_room(p.c.q, c));
    check("brutal buffers: swap at 1 GiB/s", 0, qc_cc_brutal(p.c.q, 1ull << 30, 0));
    check("brutal buffers: C gets the 8 MiB left of 32 MiB and its exempt 4096", 8 * MIB + 4096, (long)qc_stream_room(p.c.q, c));
    check("brutal buffers: A has 16 MiB less its 12", 4 * MIB, (long)qc_stream_room(p.c.q, a));
    pair_free(&p);
}

static void brutal_sizing_stops_at_the_small_budget(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t a = -1, b = -1, c = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_total = 8 * MIB;
    cc.send_buf = 2 * MIB;
    cc.brutal_span = 4 * MIB;
    check("brutal small: pair opens", 0, pair_open(&p, &cc, &sc));
    check("brutal small: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("brutal small: stream A opens", 0, open_stream(&p, &a));
    check("brutal small: A starts at 2 MiB", 2 * MIB, (long)qc_stream_room(p.c.q, a));
    check("brutal small: swap at 1 GiB/s", 0, qc_cc_brutal(p.c.q, 1ull << 30, 0));
    check("brutal small: A stops at 4 MiB", 4 * MIB, (long)qc_stream_room(p.c.q, a));
    check("brutal small: A takes 4 MiB", 4 * MIB, offer(p.c.q, a, 4 * MIB));
    check("brutal small: stream B opens", 0, open_stream(&p, &b));
    check("brutal small: B gets the rest of 8 MiB", 4 * MIB, (long)qc_stream_room(p.c.q, b));
    check("brutal small: B takes 4 MiB", 4 * MIB, offer(p.c.q, b, 4 * MIB));
    check("brutal small: stream C opens", 0, open_stream(&p, &c));
    check("brutal small: the 8 MiB are spent, C keeps its exempt 4096", 4096, (long)qc_stream_room(p.c.q, c));
    pair_free(&p);
}

static void first_window_round(const char *tag, int cc_algo, int no_pmtud, long want) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    char b[120];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.cc = cc_algo;
    cc.no_pmtud = no_pmtud;
    snprintf(b, sizeof b, "first window %s: pair opens", tag);
    check(b, 0, pair_open(&p, &cc, &sc));
    qc_stats_get(p.c.q, &st);
    snprintf(b, sizeof b, "first window %s: 32 packets before any answer", tag);
    check(b, want, (long)st.cwnd);
    pair_free(&p);
}

static void the_first_window_is_32_packets(void) {
    first_window_round("bbr", QC_CC_BBR, 0, 32 * 1200);
    first_window_round("reno", QC_CC_RENO, 0, 32 * 1200);
    first_window_round("bbr without pmtud", QC_CC_BBR, 1, 32 * 1250);
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("first window brutal: pair opens", 0, pair_open(&p, &cc, &sc));
    check("first window brutal: installed at once", 0, qc_cc_brutal_now(p.c.q, 1048576, 0));
    qc_stats_get(p.c.q, &st);
    check("first window brutal: its own window 10240 + 1", 10241, (long)st.cwnd);
    pair_free(&p);
}

static void brutal_without_an_rtt_sample_uses_the_minimum_window(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("brutal no rtt: pair opens", 0, pair_open(&p, &cc, &sc));
    check("brutal no rtt: installed before any sample", 0, qc_cc_brutal_now(p.c.q, 1048576, 0));
    qc_stats_get(p.c.q, &st);
    check("brutal no rtt: window 10240 + 1", 10241, (long)st.cwnd);
    check("brutal no rtt: paces 1024e9 / 976562", 1048576, (long)st.pacing_bps);
    check("brutal no rtt: reports Brutal", QC_CC_BRUTAL, st.cc);
    check("brutal no rtt: handshake completes", 1, pump_until(&p, c_both_hs, NULL, 10000));
    pair_free(&p);
}

struct dropf { unsigned n, dropped; int armed, once; };

static size_t drop_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct dropf *f = u;
    if (f->once || (f->armed && ++f->n % 10 == 0)) {
        f->once = 0;
        f->dropped++;
        return 0;
    }
    memcpy(dst, src, n);
    return n;
}

static unsigned lossy_echo(struct pair *p, struct dropf *df, unsigned *after_loss) {
    struct qc_stats st;
    int64_t sid = -1;
    unsigned under = 0;
    qc_stats_get(p->c.q, &st);
    uint64_t lost0 = st.pkt_lost;
    *after_loss = 0;
    df->armed = 1;
    if (echo_open(p, &sid) != 0) return 1;
    struct want w = { &p->c, sid, 0 };
    uint64_t end = ms_now() + 20000ull * g_tx;
    while (!c_closed_st(p, &w) && ms_now() < end) {
        pass(p);
        qc_stats_get(p->c.q, &st);
        uint64_t want = brutal_window(50000000, qc_srtt_ns(p->c.q), 1200) + 1;
        if (st.pkt_lost > lost0) (*after_loss)++;
        if (st.cwnd < want) {
            if (!under) printf("     first window under: cwnd %llu want %llu\n", (unsigned long long)st.cwnd, (unsigned long long)want);
            under++;
        }
    }
    df->armed = 0;
    return echo_intact(p, sid) ? under : under + 1;
}

struct upseen { struct want w; unsigned up; int full; };

static int c_closed_seen(struct pair *p, void *a) {
    struct upseen *u = a;
    struct qc_bbr_view v;
    if (qc_bbr_view(p->c.q, &v) >= 0) {
        if (v.probe_up_rounds > u->up) u->up = v.probe_up_rounds;
        u->full |= v.full_bw;
    }
    return c_closed_st(p, &u->w);
}

static void loss_never_lowers_the_bbr_model(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    struct qc_bbr_view v;
    struct dropf df = { 0, 0, 0, 0 };
    struct qc_filter fd = { drop_tx, f_id_rx, &df, 0 };
    struct upseen u = { { NULL, 0, 0 }, 0, 0 };
    int intact = 0;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &fd;
    check("bbr loss: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("bbr loss: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    df.armed = 1;
    for (int i = 0; i < 8; i++) {
        int64_t sid = -1;
        if (echo_open(&p, &sid) != 0) break;
        u.w = (struct want){ &p.c, sid, 0 };
        if (!pump_until(&p, c_closed_seen, &u, 20000)) break;
        intact += echo_intact(&p, sid);
    }
    df.armed = 0;
    qc_stats_get(p.c.q, &st);
    check("bbr loss: eight lossy 1 MiB echoes intact", 8, intact);
    check("bbr loss: one datagram in ten dropped", 1, df.dropped > 0);
    check("bbr loss: the controller saw losses", 1, st.pkt_lost > 0);
    check("bbr loss: STARTUP was left", 1, u.full);
    check("bbr loss: PROBE_BW_UP was reached", 1, u.up > 0);
    check("bbr loss: the client runs the loss-blind BBR", 1, qc_bbr_view(p.c.q, &v));
    check("bbr loss: no long-term inflight bound", 1, v.longterm == UINT64_MAX);
    check("bbr loss: no short-term bandwidth bound", 1, v.bw_lo == UINT64_MAX);
    check("bbr loss: no short-term inflight bound", 1, v.inflight_lo == UINT64_MAX);
    check("bbr loss: no probe ended as too high", 0, v.too_high);
    pair_free(&p);
}

static int small_acked(struct pair *p, int64_t sid) {
    if (qc_stream_send(p->c.q, sid, g_pat, 100, 0) != 100) return 0;
    return pump_until(p, c_cli_idle, NULL, 10000);
}

static void the_blind_ack_keeps_ngtcp2s_bookkeeping(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_bbr_view v;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("bbr ack: pair opens", 0, pair_open(&p, &cc, &sc));
    check("bbr ack: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("bbr ack: stream opens", 0, open_stream(&p, &sid));
    check("bbr ack: idle", 1, pump_until(&p, c_cli_idle, NULL, 10000));
    check("bbr ack: view", 1, qc_bbr_view(p.c.q, &v));
    check("bbr ack: still in STARTUP", 1, v.startup);
    check("bbr ack: a loss flag outside a loss round", 0, qc_bbr_poke(p.c.q, UINT64_MAX, 1, UINT64_MAX, 0));
    check("bbr ack: acknowledged", 1, small_acked(&p, sid));
    qc_bbr_view(p.c.q, &v);
    check("bbr ack: the flag survives an ack that starts no loss round", 1, v.loss_in_round);
    check("bbr ack: a loss flag at a loss round start", 0, qc_bbr_poke(p.c.q, UINT64_MAX, 1, 0, 0));
    check("bbr ack: acknowledged again", 1, small_acked(&p, sid));
    qc_bbr_view(p.c.q, &v);
    check("bbr ack: a loss round start clears the flag", 0, v.loss_in_round);
    check("bbr ack: the round moved on", 1, v.loss_round_delivered > 0);
    check("bbr ack: a loss flag in DRAIN", 0, qc_bbr_poke(p.c.q, UINT64_MAX, 1, UINT64_MAX, 1));
    check("bbr ack: acknowledged in DRAIN", 1, small_acked(&p, sid));
    qc_bbr_view(p.c.q, &v);
    check("bbr ack: DRAIN with nothing in flight is left", 0, v.drain);
    check("bbr ack: and not for STARTUP", 0, v.startup);
    check("bbr ack: entering PROBE_BW_DOWN clears the flag", 0, v.loss_in_round);
    check("bbr ack: a loss round start in DRAIN with the flag set", 0, qc_bbr_poke(p.c.q, UINT64_MAX, 1, 0, 1));
    check("bbr ack: acknowledged in DRAIN again", 1, small_acked(&p, sid));
    qc_bbr_view(p.c.q, &v);
    check("bbr ack: DRAIN is left again", 0, v.drain);
    check("bbr ack: no short-term bandwidth bound from that round", 1, v.bw_lo == UINT64_MAX);
    check("bbr ack: no short-term inflight bound from that round", 1, v.inflight_lo == UINT64_MAX);
    check("bbr ack: a long-term cap of four packets", 0, qc_bbr_poke(p.c.q, 4 * 1452, 0, v.loss_round_delivered, 0));
    check("bbr ack: acknowledged under the cap", 1, small_acked(&p, sid));
    qc_bbr_view(p.c.q, &v);
    check("bbr ack: the cap is gone after one ack", 1, v.longterm == UINT64_MAX);
    pair_free(&p);
}

static int c_lost_idle(struct pair *p, void *a) {
    (void)a;
    struct qc_stats st;
    qc_stats_get(p->c.q, &st);
    return st.pkt_lost > 0 && c_cli_idle(p, NULL);
}

static void a_lost_probe_sample_is_hidden_from_bbr(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_bbr_view v;
    struct qc_stats st;
    struct dropf df = { 0, 0, 0, 0 };
    struct qc_filter fd = { drop_tx, f_id_rx, &df, 0 };
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &fd;
    check("bbr probe loss: pair opens", 0, pair_open(&p, &cc, &sc));
    check("bbr probe loss: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("bbr probe loss: stream opens", 0, open_stream(&p, &sid));
    check("bbr probe loss: idle", 1, pump_until(&p, c_cli_idle, NULL, 10000));
    qc_bbr_view(p.c.q, &v);
    check("bbr probe loss: still in STARTUP", 1, v.startup);
    check("bbr probe loss: a probe sample planted", 0, qc_bbr_poke_probe(p.c.q));
    df.once = 1;
    check("bbr probe loss: 100 bytes offered", 100, (long)qc_stream_send(p.c.q, sid, g_pat, 100, 0));
    check("bbr probe loss: the packet is lost and repaired", 1, pump_until(&p, c_lost_idle, NULL, 10000));
    qc_stats_get(p.c.q, &st);
    qc_bbr_view(p.c.q, &v);
    check("bbr probe loss: one datagram dropped", 1, (long)df.dropped);
    check("bbr probe loss: the controller saw the loss", 1, st.pkt_lost > 0);
    check("bbr probe loss: no probe ended as too high", 0, v.too_high);
    check("bbr probe loss: no long-term inflight bound", 1, v.longterm == UINT64_MAX);
    pair_free(&p);
}

static int c_upload_done(struct pair *p, void *a) {
    struct want *w = a;
    struct strm *s = strm_get(&p->s, w->sid);
    return s && s->got == MIB && s->fin && c_cli_idle(p, NULL);
}

struct bigdrop { unsigned n, dropped; int armed; };

static size_t drop_big_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct bigdrop *f = u;
    if (f->armed && n >= 1000 && ++f->n % 10 == 0) {
        f->dropped++;
        return 0;
    }
    memcpy(dst, src, n);
    return n;
}

static void tracked_upload_round(const char *tag, int algo) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats a, b;
    struct bigdrop df = { 0, 0, 0 };
    struct qc_filter fd = { drop_big_tx, f_id_rx, &df, 0 };
    int64_t sid = -1;
    char nm[120];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &fd;
    cc.cc = algo == QC_CC_RENO ? QC_CC_RENO : QC_CC_BBR;
    snprintf(nm, sizeof nm, "tracked %s: pair opens", tag);
    check(nm, 0, pair_open(&p, &cc, &sc));
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    snprintf(nm, sizeof nm, "tracked %s: handshake", tag);
    check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000));
    if (algo == QC_CC_BRUTAL) {
        snprintf(nm, sizeof nm, "tracked %s: swap at 2 MB/s", tag);
        check(nm, 0, qc_cc_brutal(p.c.q, 2000000, 0));
    }
    snprintf(nm, sizeof nm, "tracked %s: idle before the upload", tag);
    check(nm, 1, pump_until(&p, c_cli_idle, NULL, 10000));
    qc_stats_get(p.c.q, &a);
    df.armed = 1;
    snprintf(nm, sizeof nm, "tracked %s: upload opens", tag);
    check(nm, 0, echo_open(&p, &sid));
    struct want w = { &p.c, sid, 0 };
    snprintf(nm, sizeof nm, "tracked %s: 1 MiB arrives through one full drop in ten", tag);
    check(nm, 1, pump_until(&p, c_upload_done, &w, 20000));
    df.armed = 0;
    qc_stats_get(p.c.q, &b);
    uint64_t sent = b.cc_sent - a.cc_sent, lost = b.cc_lost - a.cc_lost;
    printf("     tracked %s: %llu sent, %llu lost, %u dropped, %llu datagrams\n", tag, (unsigned long long)sent,
           (unsigned long long)lost, df.dropped, (unsigned long long)(b.pkt_sent - a.pkt_sent));
    snprintf(nm, sizeof nm, "tracked %s: at least 723 packets for 1 MiB", tag);
    check(nm, 1, sent >= 723);
    snprintf(nm, sizeof nm, "tracked %s: at least 72 full datagrams dropped", tag);
    check(nm, 1, df.dropped >= 72);
    snprintf(nm, sizeof nm, "tracked %s: every dropped one counted lost", tag);
    check(nm, 1, lost >= df.dropped);
    snprintf(nm, sizeof nm, "tracked %s: and little else", tag);
    check(nm, 1, lost * 10 <= df.dropped * 11);
    pair_free(&p);
}

static void a_plain_link_tells_its_socket_port(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("socket port: pair opens", 0, pair_open(&p, &cc, &sc));
    check("socket port: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("socket port: the one the server sees", qc_peer_port(p.s.q), qc_sock_port(p.c.q));
    pair_free(&p);
}

static int upload(struct pair *p) {
    int64_t sid = -1;
    if (echo_open(p, &sid) != 0) return 0;
    struct want w = { &p->c, sid, 0 };
    return pump_until(p, c_upload_done, &w, 20000);
}

static void the_counts_carry_over_a_controller_swap(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats a, b, c;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("tracked swap: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("tracked swap: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("tracked swap: 1 MiB up on BBR", 1, upload(&p));
    qc_stats_get(p.c.q, &a);
    check("tracked swap: BBR counted at least 723 packets", 1, a.cc_sent >= 723);
    check("tracked swap: swap to Brutal at 2 MB/s", 0, qc_cc_brutal(p.c.q, 2000000, 0));
    qc_stats_get(p.c.q, &b);
    check("tracked swap: the swap keeps the sent count", 1, b.cc_sent == a.cc_sent);
    check("tracked swap: 1 MiB up on Brutal", 1, upload(&p));
    qc_stats_get(p.c.q, &c);
    check("tracked swap: Brutal adds at least 723 packets", 1, c.cc_sent >= b.cc_sent + 723);
    check("tracked swap: no packet counted twice", 1, c.cc_sent <= c.pkt_sent);
    pair_free(&p);
}

static void the_controller_counts_what_it_can_lose(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats a, b;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.no_pmtud = 1;
    cc.max_data = cc.max_stream_data = 8 * MIB;
    check("tracked download: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    p.s.respond = MIB;
    check("tracked download: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("tracked download: stream opens", 0, open_stream(&p, &sid));
    check("tracked download: idle", 1, pump_until(&p, c_cli_idle, NULL, 10000));
    qc_stats_get(p.c.q, &a);
    out_static(&p.c, sid, g_pat, 10, 0);
    struct want w = { &p.c, sid, MIB };
    check("tracked download: 1 MiB comes down", 1, pump_until(&p, c_got, &w, 20000));
    check("tracked download: idle after", 1, pump_until(&p, c_cli_idle, NULL, 10000));
    qc_stats_get(p.c.q, &b);
    uint64_t sent = b.cc_sent - a.cc_sent, pkts = b.pkt_sent - a.pkt_sent;
    printf("     tracked download: %llu tracked of %llu sent\n", (unsigned long long)sent, (unsigned long long)pkts);
    check("tracked download: nothing lost", 0, (long)(b.cc_lost - a.cc_lost));
    check("tracked download: the request is tracked", 1, sent >= 1);
    check("tracked download: each tracked past the request leaves an ACK-only", 1, sent * 2 <= pkts + 1);
    pair_free(&p);
    tracked_upload_round("bbr", QC_CC_BBR);
    tracked_upload_round("brutal", QC_CC_BRUTAL);
    tracked_upload_round("reno", QC_CC_RENO);
}

static void the_blind_controller_goes_on_bbr_only_once(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    struct qc_bbr_view v;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("bbr once: pair opens", 0, pair_open(&p, &cc, &sc));
    check("bbr once: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("bbr once: a second install is refused", -1, qc_bbr_blind(p.c.q));
    check("bbr once: still the loss-blind BBR", 1, qc_bbr_view(p.c.q, &v));
    check("bbr once: swap to Brutal at 1048576 B/s", 0, qc_cc_brutal(p.c.q, 1048576, 0));
    check("bbr once: an install over Brutal is refused", -1, qc_bbr_blind(p.c.q));
    qc_stats_get(p.c.q, &st);
    check("bbr once: Brutal stays", QC_CC_BRUTAL, st.cc);
    check("bbr once: Brutal keeps its pace", 1048576, (long)st.pacing_bps);
    pair_free(&p);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.cc = QC_CC_RENO;
    check("bbr once: reno pair opens", 0, pair_open(&p, &cc, &sc));
    check("bbr once: an install over Reno is refused", -1, qc_bbr_blind(p.c.q));
    check("bbr once: Reno has no BBR view", -1, qc_bbr_view(p.c.q, &v));
    pair_free(&p);
}

static void losses_never_shrink_the_brutal_window(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    struct dropf df = { 0, 0, 0, 0 };
    struct qc_filter fd = { drop_tx, f_id_rx, &df, 0 };
    unsigned after = 0;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &fd;
    check("brutal loss: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("brutal loss: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("brutal loss: swap at 50 MB/s", 0, qc_cc_brutal(p.c.q, 50000000, 0));
    check("brutal loss: intact, never under max(1200, 100 x srtt_us) + 1", 0, (long)lossy_echo(&p, &df, &after));
    check("brutal loss: the filter dropped datagrams", 1, df.dropped > 0);
    check("brutal loss: sampled after the first loss", 1, after > 0);
    qc_stats_get(p.c.q, &st);
    printf("     brutal loss: %u dropped, ack_q16 %u, %u samples after a loss\n", df.dropped, st.ack_q16, after);
    check("brutal loss: ack rate 0.88..0.92 for one datagram in ten lost", 1, st.ack_q16 >= 57672 && st.ack_q16 <= 60293);
    check("brutal loss: swap again without compensation", 0, qc_cc_brutal(p.c.q, 50000000, 1));
    qc_stats_get(p.c.q, &st);
    uint64_t lost0 = st.pkt_lost;
    check("brutal loss: no compensation, intact and never under", 0, (long)lossy_echo(&p, &df, &after));
    qc_stats_get(p.c.q, &st);
    check("brutal loss: no compensation still lost packets", 1, st.pkt_lost > lost0);
    check("brutal loss: no compensation keeps the rate at 1.0", 65536, (long)st.ack_q16);
    check("brutal loss: no compensation paces 1024e9 / 20480", 50000000, (long)st.pacing_bps);
    pair_free(&p);
}

static void an_installed_controller_sets_a_window_and_a_pace(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    int64_t warm = -1, sid = -1, sid2 = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.cc = QC_CC_RENO;
    check("brutal install: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("brutal install: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("brutal install: warm-up echo opens", 0, echo_open(&p, &warm));
    struct want w0 = { &p.c, warm, 0 };
    check("brutal install: warm-up echo closes", 1, pump_until(&p, c_closed_st, &w0, 10000));
    uint64_t srtt_us = qc_srtt_ns(p.c.q) / 1000;
    uint64_t bps = 16384ull * 500000 / (srtt_us ? srtt_us : 1);
    printf("     brutal install: srtt %llu us, rate %llu B/s for a 16384-byte window\n", (unsigned long long)srtt_us, (unsigned long long)bps);
    check("brutal install: echo opens", 0, echo_open(&p, &sid));
    struct want w = { &p.c, sid, 0 };
    int swapped = 0;
    uint64_t win = 0, end = ms_now() + 2000ull * g_tx;
    while (!swapped && ms_now() < end) {
        if (qc_timeout_ms(p.c.q) == 0) (void)qc_on_timer(p.c.q);
        drain(&p.c);
        qc_flush(p.c.q);
        qc_stats_get(p.c.q, &st);
        win = brutal_window(bps, qc_srtt_ns(p.c.q), 1452);
        if (st.in_flight > win) swapped = qc_cc_brutal(p.c.q, bps, 0) == 0;
        else usleep(1000);
    }
    qc_stats_get(p.c.q, &st);
    printf("     brutal install: %llu in flight over a window of %llu\n", (unsigned long long)st.in_flight, (unsigned long long)win);
    check("brutal install: swapped with more in flight than the window", 1, swapped);
    check("brutal install: the new window is under what is in flight", 1, st.in_flight > st.cwnd);
    check("brutal install: 1 MiB echo closes within 10 s", 1, pump_until(&p, c_closed_st, &w, 10000));
    check("brutal install: 1 MiB echo intact", 1, echo_intact(&p, sid));
    qc_stats_get(p.c.q, &st);
    check("brutal install: the window follows the RTT", (long)brutal_window(bps, qc_srtt_ns(p.c.q), 1452) + 1, (long)st.cwnd);
    pump_until(&p, c_cli_idle, NULL, 10000);
    qc_stats_get(p.c.q, &st);
    check("brutal install: nothing in flight", 0, (long)st.in_flight);
    check("brutal install: swap again when idle", 0, qc_cc_brutal(p.c.q, bps, 0));
    check("brutal install: second echo opens", 0, echo_open(&p, &sid2));
    struct want w2 = { &p.c, sid2, 0 };
    check("brutal install: second echo closes within 10 s", 1, pump_until(&p, c_closed_st, &w2, 10000));
    check("brutal install: second echo intact", 1, echo_intact(&p, sid2));
    pair_free(&p);
}

static void the_window_floor_lets_a_second_packet_go(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats a, b, c;
    int64_t warm = -1, sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("brutal floor: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("brutal floor: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("brutal floor: warm-up echo opens", 0, echo_open(&p, &warm));
    struct want w = { &p.c, warm, 0 };
    check("brutal floor: warm-up echo closes", 1, pump_until(&p, c_closed_st, &w, 10000));
    check("brutal floor: nothing in flight", 1, pump_until(&p, c_cli_idle, NULL, 10000));
    pump_for(&p, 100);
    check("brutal floor: stream opens", 0, qc_stream_open(p.c.q, &sid));
    check("brutal floor: swap at 1000 B/s", 0, qc_cc_brutal(p.c.q, 1000, 0));
    qc_stats_get(p.c.q, &a);
    check("brutal floor: the window is one packet + 1", 1453, (long)a.cwnd);
    check("brutal floor: 64 KiB queued", 65536, (long)qc_stream_send(p.c.q, sid, g_pat, 65536, 0));
    qc_flush(p.c.q);
    qc_stats_get(p.c.q, &b);
    check("brutal floor: two packets leave with one window in flight", 2, (long)(b.pkt_sent - a.pkt_sent));
    check("brutal floor: two full packets in flight", 2904, (long)b.in_flight);
    check("brutal floor: swap at 50 MB/s", 0, qc_cc_brutal(p.c.q, 50000000, 0));
    check("brutal floor: 64 KiB more queued", 65536, (long)qc_stream_send(p.c.q, sid, g_pat + 65536, 65536, 0));
    qc_flush(p.c.q);
    qc_stats_get(p.c.q, &c);
    check("brutal floor: the old pace does not hold the new one back", 1, c.pkt_sent > b.pkt_sent);
    pair_free(&p);
}

static void a_loss_found_by_the_timer_keeps_the_window(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    struct dropf df = { 0, 0, 0, 0 };
    struct qc_filter fd = { drop_tx, f_id_rx, &df, 0 };
    int64_t warm = -1, sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &fd;
    check("brutal timer loss: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("brutal timer loss: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("brutal timer loss: warm-up echo opens", 0, echo_open(&p, &warm));
    struct want w = { &p.c, warm, 0 };
    check("brutal timer loss: warm-up echo closes", 1, pump_until(&p, c_closed_st, &w, 10000));
    p.s.echo = 0;
    check("brutal timer loss: stream opens", 0, qc_stream_open(p.c.q, &sid));
    check("brutal timer loss: swap at 50 MB/s", 0, qc_cc_brutal(p.c.q, 50000000, 0));
    int found = 0, tries = 0;
    long cwnd = 0, want = 0;
    struct end *ends[2] = { &p.c, &p.s };
    while (!found && tries < 5) {
        tries++;
        if (!pump_until(&p, c_cli_idle, NULL, 10000)) break;
        pump_for(&p, 100);
        qc_stats_get(p.c.q, &st);
        uint64_t lost0 = st.pkt_lost;
        df.once = 1;
        qc_stream_send(p.c.q, sid, g_pat, 100, 0);
        qc_stream_send(p.c.q, sid, g_pat + 100, 100, 0);
        int by_ack = 0;
        uint64_t end = ms_now() + 2000ull * g_tx;
        while (!found && !by_ack && ms_now() < end) {
            struct epoll_event ev[4];
            int t = qc_timeout_ms(p.c.q);
            int k = qc_timeout_ms(p.s.q);
            if (t < 0 || (k >= 0 && k < t)) t = k;
            int n = epoll_wait(p.ep, ev, 4, t < 0 || t > 20 ? 20 : t);
            for (int i = 0; i < n; i++) (void)qc_on_readable(((struct end *)ev[i].data.ptr)->q);
            qc_stats_get(p.c.q, &st);
            if (st.pkt_lost > lost0) { by_ack = 1; break; }
            if (qc_timeout_ms(p.c.q) == 0) {
                (void)qc_on_timer(p.c.q);
                qc_stats_get(p.c.q, &st);
                if (st.pkt_lost > lost0) {
                    found = 1;
                    cwnd = (long)st.cwnd;
                    want = (long)brutal_window(50000000, qc_srtt_ns(p.c.q), 1452) + 1;
                }
            }
            if (qc_timeout_ms(p.s.q) == 0) (void)qc_on_timer(p.s.q);
            for (int i = 0; i < 2; i++) qc_flush(ends[i]->q);
        }
    }
    printf("     brutal timer loss: found on the timer after %d tries\n", tries);
    check("brutal timer loss: a loss found by the timer", 1, found);
    check("brutal timer loss: the window right after it", want, cwnd);
    pair_free(&p);
}

static uint32_t rand_1(void) { return 1; }
static uint32_t rand_3(void) { return 3; }
static uint32_t rand_7(void) { return 7; }
static uint32_t rand_25(void) { return 25; }

static const uint32_t g_rseq_v[] = { 0, 2, 2, 1, 1, 0, 0, 2, 2, 1, 1, 0, 0 };
static unsigned g_rseq;
static uint32_t rand_seq(void) {
    return g_rseq < sizeof g_rseq_v / sizeof g_rseq_v[0] ? g_rseq_v[g_rseq++] : 0;
}

static uint16_t fd_local_port(int fd) {
    struct sockaddr_storage a;
    socklen_t l = sizeof a;
    if (getsockname(fd, (struct sockaddr *)&a, &l) != 0) return 0;
    return sa_port_of((struct sockaddr *)&a);
}

static uint16_t cur_port(const struct qc *q) {
    uint16_t cur = 0, pre = 0;
    int pf = -1;
    qc_sock_ports(q, &cur, &pre, &pf);
    return cur;
}

static int pre_gone(const struct qc *q) {
    uint16_t cur, pre;
    int pf;
    qc_sock_ports(q, &cur, &pre, &pf);
    return pf < 0;
}

static void hop_cfg(struct qc_cfg *c, const struct port_range *r, size_t n, uint32_t (*rand32)(void)) {
    c->hop_mode = QC_HOP_REMOTE;
    c->hop_min_s = c->hop_max_s = 3600;
    c->hop_n = n;
    memcpy(c->hop_ports, r, n * sizeof *r);
    c->rand32 = rand32;
}

static void a_remote_hop_keeps_the_local_port(void) {
    struct qc_cfg cc;
    struct qc_stats st;
    struct qc *q = NULL;
    struct port_range r = { 40000, 40009 };
    uint16_t lp = 0, cur = 0, pre = 0;
    int pf = -1;
    cli_cfg(&cc, "h3");
    cc.port = 40000;
    hop_cfg(&cc, &r, 1, rand_3);
    check("remote hop: qc_open", 0, qc_open(&cc, &g_ops, NULL, &q));
    int ep = qc_fd(q);
    qc_sock_ports(q, &lp, &pre, &pf);
    qc_stats_get(q, &st);
    check("remote hop: the first port is the dialled one", 40000, st.port);
    check("remote hop: a local port", 1, lp != 0);
    int fds = open_fds(), c0 = g_connects;
    g_conn_fd = -1;
    qc_hop_now(q);
    qc_stats_get(q, &st);
    qc_sock_ports(q, &cur, &pre, &pf);
    check("remote hop: one connect", c0 + 1, g_connects);
    check("remote hop: to 40000 + 3 % 10", 40003, g_conn_port);
    check("remote hop: on a new socket", 1, pf >= 0 && g_conn_fd >= 0 && g_conn_fd != pf);
    check("remote hop: the new socket holds the first local port", lp, fd_local_port(g_conn_fd));
    check("remote hop: the current local port stays", lp, cur);
    check("remote hop: the old socket lingers on the same local port", lp, pre);
    check("remote hop: qc_fd stays the inner epoll", ep, qc_fd(q));
    check("remote hop: one more fd while the old one lingers", fds + 1, open_fds());
    check("remote hop: stats.port 40003", 40003, st.port);
    check("remote hop: hops 1", 1, (long)st.hops);
    check("remote hop: hop_fails 0", 0, (long)st.hop_fails);
    qc_free(q);
}

static int c_hop_echo_got(struct pair *p, void *a) {
    struct strm *s = strm_find(&p->c, *(const int64_t *)a);
    return s ? (int)(s->got * 6 / MIB) : 0;
}

static unsigned echo_hopping(struct pair *p, int64_t sid, void (*step)(struct pair *, void *), void *arg, unsigned hops) {
    unsigned done = 0;
    uint64_t end = ms_now() + 20000ull * g_tx;
    struct want w = { &p->c, sid, 0 };
    while (!c_closed_st(p, &w) && ms_now() < end) {
        step(p, arg);
        while (done < hops && (unsigned)c_hop_echo_got(p, &sid) > done) {
            qc_hop_now(p->c.q);
            done++;
        }
    }
    return done;
}

static void step_pass(struct pair *p, void *a) { (void)a; pass(p); }

static void ngtcp2_never_sees_a_remote_hop(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    memset(&p, 0, sizeof p);
    p.ep = epoll_create1(0);
    check("fixed path: server listens", 0, qc_listen(&sc, &g_ops, &p.s, &p.s.q));
    ep_add(&p, &p.s);
    uint16_t sp = qc_local_port(p.s.q);
    struct port_range r[2] = { { sp, sp }, { sp, sp } };
    cc.port = sp;
    hop_cfg(&cc, r, 2, rand_3);
    check("fixed path: client opens", 0, qc_open(&cc, &g_ops, &p.c, &p.c.q));
    ep_add(&p, &p.c);
    uint16_t lp = cur_port(p.c.q);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("fixed path: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("fixed path: echo opens", 0, echo_open(&p, &sid));
    int fds = open_fds();
    check("fixed path: five hops forced during the echo", 5, (long)echo_hopping(&p, sid, step_pass, NULL, 5));
    uint16_t c1 = 0, pr1 = 0;
    int pf1 = 0;
    qc_sock_ports(p.c.q, &c1, &pr1, &pf1);
    check("fixed path: a hop to the same port makes no socket", 1, pf1 == -1 && fds == open_fds() && c1 == lp);
    check("fixed path: 1 MiB echo intact with FIN", 1, echo_intact(&p, sid));
    qc_stats_get(p.c.q, &st);
    check("fixed path: hops 5", 5, (long)st.hops);
    uint16_t nl = 0, nr = 0;
    qc_path_ports(p.c.q, &nl, &nr);
    check("fixed path: ngtcp2 holds the open's local port", lp, nl);
    check("fixed path: ngtcp2 holds the open's remote port", sp, nr);
    pair_free(&p);
}

static void a_failed_remote_hop_keeps_the_link(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    memset(&p, 0, sizeof p);
    p.ep = epoll_create1(0);
    check("failed hop: server listens", 0, qc_listen(&sc, &g_ops, &p.s, &p.s.q));
    ep_add(&p, &p.s);
    uint16_t sp = qc_local_port(p.s.q), bad = (uint16_t)(sp == 65535 ? sp - 1 : sp + 1);
    struct port_range r[2] = { { sp, sp }, { bad, bad } };
    cc.port = sp;
    hop_cfg(&cc, r, 2, rand_1);
    check("failed hop: client opens", 0, qc_open(&cc, &g_ops, &p.c, &p.c.q));
    ep_add(&p, &p.c);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("failed hop: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    int c0 = g_connects, f0 = g_conn_failed, fds = open_fds();
    uint16_t lp = cur_port(p.c.q), pre = 0, cur = 0;
    int pf = 0;
    uint64_t due0 = qc_hop_due_ns(p.c.q);
    g_conn_fail_port = bad;
    qc_hop_now(p.c.q);
    g_conn_fail_port = 0;
    qc_stats_get(p.c.q, &st);
    qc_sock_ports(p.c.q, &cur, &pre, &pf);
    check("failed hop: the hop's connect was refused", f0 + 1, g_conn_failed);
    check("failed hop: no other connect", c0 + 1, g_connects);
    check("failed hop: the refused socket is closed", fds, open_fds());
    check("failed hop: the link keeps its socket", 1, lp != 0 && cur == lp);
    check("failed hop: no previous socket", -1, pf);
    check("failed hop: the next hop is a fresh interval away", 1, qc_hop_due_ns(p.c.q) > due0);
    check("failed hop: stats.port the old one", sp, st.port);
    check("failed hop: hop_fails 1", 1, (long)st.hop_fails);
    check("failed hop: hops 0", 0, (long)st.hops);
    check("failed hop: echo opens", 0, echo_open(&p, &sid));
    struct want w = { &p.c, sid, 0 };
    check("failed hop: echo closes", 1, pump_until(&p, c_closed_st, &w, 10000));
    check("failed hop: 1 MiB echo intact with FIN", 1, echo_intact(&p, sid));
    check("failed hop: the link stays", 0, p.c.closed);
    pair_free(&p);
}

static int c_hops_1(struct pair *p, void *a) {
    (void)a;
    struct qc_stats st;
    qc_stats_get(p->c.q, &st);
    return st.hops >= 1;
}

static unsigned timer_by_deadline(struct qc *q, int (*done)(const struct qc *)) {
    unsigned calls = 0;
    uint64_t end = ms_now() + 5000 + 2000ull * g_tx;
    while (!done(q) && ms_now() < end) {
        int k = qc_timeout_ms(q);
        uint64_t left = end - ms_now();
        if (k < 0 || (uint64_t)k > left) k = (int)left;
        struct epoll_event e;
        if (k > 0) (void)epoll_wait(qc_fd(q), &e, 1, k);
        if (qc_timeout_ms(q) == 0) {
            (void)qc_on_timer(q);
            calls++;
        }
    }
    return calls;
}

static uint64_t g_due0;

static int hop_moved(const struct qc *q) { return qc_hop_due_ns(q) != g_due0; }

static void hops_are_timed(void) {
    struct qc_cfg cc;
    struct qc *q = NULL;
    struct port_range two[2] = { { 40000, 40000 }, { 40001, 40001 } };
    struct port_range one = { 40000, 40000 };
    cli_cfg(&cc, "h3");
    cc.port = 40000;
    hop_cfg(&cc, two, 2, rand_7);
    cc.hop_min_s = 5;
    cc.hop_max_s = 30;
    check("hop timer: qc_open", 0, qc_open(&cc, &g_ops, NULL, &q));
    check("hop timer: due 5 + 7 % 26 = 12 s after the open", 1, qc_hop_due_ns(q) == qc_opened_ns(q) + 12000000000ull);
    qc_free(q);
    cc.rand32 = rand_25;
    check("hop timer: qc_open, rand 25", 0, qc_open(&cc, &g_ops, NULL, &q));
    check("hop timer: due 5 + 25 % 26 = 30 s, the top is drawn", 1, qc_hop_due_ns(q) == qc_opened_ns(q) + 30000000000ull);
    qc_free(q);
    cc.rand32 = rand_7;
    cc.hop_min_s = cc.hop_max_s = 0;
    check("hop timer: qc_open, 0-0", 0, qc_open(&cc, &g_ops, NULL, &q));
    check("hop timer: 0-0 is 30 s", 1, qc_hop_due_ns(q) == qc_opened_ns(q) + 30000000000ull);
    qc_free(q);
    cc.hop_mode = 0;
    check("hop timer: qc_open, mode 0", 0, qc_open(&cc, &g_ops, NULL, &q));
    check("hop timer: mode 0 has none", 1, qc_hop_due_ns(q) == UINT64_MAX);
    int c0 = g_connects;
    qc_hop_now(q);
    struct qc_stats st;
    qc_stats_get(q, &st);
    check("hop timer: mode 0 never reconnects", c0, g_connects);
    check("hop timer: mode 0 counts no hop", 0, (long)st.hops);
    check("hop timer: mode 0 reports the dialled port", 40000, st.port);
    qc_free(q);
    hop_cfg(&cc, &one, 1, rand_7);
    check("hop timer: qc_open, one port", 0, qc_open(&cc, &g_ops, NULL, &q));
    check("hop timer: one port has none", 1, qc_hop_due_ns(q) == UINT64_MAX);
    qc_free(q);

    struct pair p;
    struct qc_srv_cfg sc;
    srv_cfg(&sc, "h3");
    cli_cfg(&cc, "h3");
    memset(&p, 0, sizeof p);
    p.ep = epoll_create1(0);
    check("hop timer run: server listens", 0, qc_listen(&sc, &g_ops, &p.s, &p.s.q));
    ep_add(&p, &p.s);
    uint16_t sp = qc_local_port(p.s.q);
    struct port_range r[2] = { { sp, sp }, { sp, sp } };
    cc.port = sp;
    hop_cfg(&cc, r, 2, rand_7);
    cc.hop_min_s = cc.hop_max_s = 5;
    check("hop timer run: client opens", 0, qc_open(&cc, &g_ops, &p.c, &p.c.q));
    ep_add(&p, &p.c);
    check("hop timer run: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    uint64_t due = qc_hop_due_ns(p.c.q);
    check("hop timer run: due 5 s after the open", 1, due == qc_opened_ns(p.c.q) + 5000000000ull);
    while (qc_deadline_ns(p.c.q) != due && ns_now() < due) pass(&p);
    check("hop timer run: the reported deadline is the hop's", 1, qc_deadline_ns(p.c.q) == due);
    epoll_ctl(p.ep, EPOLL_CTL_DEL, qc_fd(p.c.q), NULL);
    p.c.in_ep = 0;
    g_due0 = due;
    check("hop timer run: one timer call at that deadline", 1, (long)timer_by_deadline(p.c.q, hop_moved));
    check("hop timer run: it ran the hop", 1, c_hops_1(&p, NULL));
    uint64_t next = qc_hop_due_ns(p.c.q);
    check("hop timer run: not before it was due", 1, next >= due + 5000000000ull);
    check("hop timer run: the link stays", 0, p.c.closed);
    pair_free(&p);
}

#define RELAY_N 3

struct relay {
    int front[RELAY_N], up, cur, have;
    uint16_t port[RELAY_N];
    struct sockaddr_in cli;
    unsigned long in[RELAY_N], out[RELAY_N];
};

static struct end g_relay_mark;

static int udp_lo(uint16_t to, uint16_t *bound) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t l = sizeof a;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(fd, (struct sockaddr *)&a, &l) != 0) {
        close(fd);
        return -1;
    }
    *bound = ntohs(a.sin_port);
    a.sin_port = htons(to);
    if (to && __real_connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int relay_open(struct relay *r, int ep, uint16_t srv) {
    uint16_t up = 0;
    memset(r, 0, sizeof *r);
    g_relay_mark.closed = 1;
    r->up = udp_lo(srv, &up);
    int ok = r->up >= 0;
    for (int i = 0; i < RELAY_N; i++) {
        r->front[i] = udp_lo(0, &r->port[i]);
        ok = ok && r->front[i] >= 0;
    }
    for (int i = 0; ok && i <= RELAY_N; i++) {
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &g_relay_mark };
        ok = epoll_ctl(ep, EPOLL_CTL_ADD, i < RELAY_N ? r->front[i] : r->up, &ev) == 0;
    }
    return ok ? 0 : -1;
}

static void relay_close(struct relay *r) {
    for (int i = 0; i < RELAY_N; i++)
        if (r->front[i] >= 0) close(r->front[i]);
    if (r->up >= 0) close(r->up);
}

static void relay_pump(struct relay *r) {
    static uint8_t b[65536];
    for (int moved = 1; moved;) {
        moved = 0;
        for (int i = 0; i < RELAY_N; i++) {
            struct sockaddr_in from;
            socklen_t fl = sizeof from;
            ssize_t n;
            while ((n = recvfrom(r->front[i], b, sizeof b, 0, (struct sockaddr *)&from, &fl)) >= 0) {
                r->cur = i;
                r->cli = from;
                r->have = 1;
                r->in[i]++;
                (void)send(r->up, b, (size_t)n, 0);
                fl = sizeof from;
                moved = 1;
            }
        }
        ssize_t n;
        while ((n = recv(r->up, b, sizeof b, 0)) >= 0) {
            if (r->have && sendto(r->front[r->cur], b, (size_t)n, 0, (struct sockaddr *)&r->cli, sizeof r->cli) >= 0)
                r->out[r->cur]++;
            moved = 1;
        }
    }
}

static void step_relay(struct pair *p, void *a) {
    pass(p);
    relay_pump(a);
}

struct live_snap { uint64_t rx, tx, ka; };

static void live_snap(const struct qc *q, struct live_snap *s) {
    s->rx = qc_rx_last_ns(q);
    s->tx = qc_tx_wait_ns(q);
    s->ka = qc_keepalive_ns(q);
}

static int live_same(const struct live_snap *a, const struct live_snap *b) {
    return a->rx == b->rx && a->tx == b->tx && a->ka == b->ka;
}

static void relay_for(struct pair *p, struct relay *r, unsigned ms) {
    uint64_t end = ms_now() + (uint64_t)ms * g_tx;
    while (ms_now() < end) step_relay(p, r);
}

struct hop_seen { struct pair *p; struct relay *r; uint64_t rx; unsigned long out; int to; };

static int c_heard_after_hop(struct hop_seen *h) {
    return qc_rx_last_ns(h->p->c.q) > h->rx && h->r->out[h->to] > h->out;
}

static void remote_hops_keep_the_link_and_its_liveness_clock(void) {
    static const int want_idx[6] = { 2, 1, 0, 2, 1, 0 };
    struct pair p;
    struct relay r;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_stats st;
    struct live_snap a, b;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.idle_ms = 1500 * g_tx;
    sc.idle_ms = 1500 * g_tx;
    memset(&p, 0, sizeof p);
    p.ep = epoll_create1(0);
    g_rseq = 0;
    check("relay hops: server listens", 0, qc_listen(&sc, &g_ops, &p.s, &p.s.q));
    ep_add(&p, &p.s);
    check("relay hops: relay opens", 0, relay_open(&r, p.ep, qc_local_port(p.s.q)));
    struct port_range pr[RELAY_N];
    for (int i = 0; i < RELAY_N; i++) pr[i].lo = pr[i].hi = r.port[i];
    cc.port = r.port[0];
    hop_cfg(&cc, pr, RELAY_N, rand_seq);
    check("relay hops: client opens", 0, qc_open(&cc, &g_ops, &p.c, &p.c.q));
    ep_add(&p, &p.c);
    uint16_t lp = cur_port(p.c.q);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (!c_both_hs(&p, NULL) && ms_now() < end) step_relay(&p, &r);
    check("relay hops: handshake through port 0", 1, c_both_hs(&p, NULL));
    check("relay hops: echo opens", 0, echo_open(&p, &sid));
    check("relay hops: three hops forced during the echo", 3, (long)echo_hopping(&p, sid, step_relay, &r, 3));
    check("relay hops: 1 MiB echo intact with FIN", 1, echo_intact(&p, sid));
    qc_stats_get(p.c.q, &st);
    check("relay hops: on port 0 after three hops", r.port[0], st.port);
    qc_keepalive(p.c.q, 500);
    relay_for(&p, &r, 300);
    int same = 0, heard = 0, ports = 0, waiting = 0;
    for (int k = 3; k < 6; k++) {
        relay_for(&p, &r, 700);
        qc_ping(p.c.q);
        live_snap(p.c.q, &a);
        waiting += a.tx != 0;
        struct hop_seen h = { &p, &r, a.rx, r.out[want_idx[k]], want_idx[k] };
        qc_hop_now(p.c.q);
        live_snap(p.c.q, &b);
        same += live_same(&a, &b);
        qc_stats_get(p.c.q, &st);
        ports += st.port == r.port[want_idx[k]];
        uint64_t until = ms_now() + 2000ull * g_tx;
        while (!c_heard_after_hop(&h) && ms_now() < until) step_relay(&p, &r);
        heard += c_heard_after_hop(&h);
    }
    check("relay hops: each hop meets an unanswered ping", 3, waiting);
    check("relay hops: a hop leaves rx_last, tx_wait and keep-alive alone", 3, same);
    check("relay hops: each idle hop to the drawn port", 3, ports);
    check("relay hops: an answer through the new port after each hop", 3, heard);
    check("relay hops: each port carried client packets", 1, r.in[0] && r.in[1] && r.in[2]);
    relay_for(&p, &r, 700);
    qc_stats_get(p.c.q, &st);
    check("relay hops: hops 6", 6, (long)st.hops);
    check("relay hops: hop_fails 0", 0, (long)st.hop_fails);
    check("relay hops: the client lives on keep-alive", 0, p.c.closed);
    check("relay hops: the server lives", 0, p.s.closed);
    uint16_t nl = 0, nr = 0;
    qc_path_ports(p.c.q, &nl, &nr);
    check("relay hops: ngtcp2 holds the open's local port", lp, nl);
    check("relay hops: ngtcp2 holds the open's remote port", r.port[0], nr);
    pair_free(&p);
    relay_close(&r);
}

static int (*g_hop_prepare)(int fd);
static unsigned g_hop_s = 3600;

static void hop_pair_cfg(struct qc_cfg *cc, struct qc_srv_cfg *sc) {
    cli_cfg(cc, "h3");
    srv_cfg(sc, "h3");
    cc->prepare = g_hop_prepare;
    cc->hop_min_s = cc->hop_max_s = g_hop_s;
    cc->handshake_ms = 60000;
}

static unsigned hop_pair_ms(unsigned ms) { return ms * g_tx; }

static int epoll_tfds(int ep) {
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", ep);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = 0;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "tfd:", 4)) n++;
    fclose(f);
    return n;
}

static int fd_open(int fd) { return fd >= 0 && fcntl(fd, F_GETFD) >= 0; }

static struct { size_t at; int done, pre_fd, pre_open; uint16_t cur, pre; } g_lh;

static void tick_hop_at(struct hop_pair *p) {
    if (g_lh.done || g_hpr_c.got < g_lh.at) return;
    g_lh.done = 1;
    qc_hop_now(p->cli);
    qc_sock_ports(p->cli, &g_lh.cur, &g_lh.pre, &g_lh.pre_fd);
    g_lh.pre_open = fd_open(g_lh.pre_fd);
}

static void a_local_hop_moves_to_a_new_socket(void) {
    struct hop_pair p;
    struct qc_stats st;
    uint16_t c0 = 0, pre0 = 0;
    int pf0 = 0;
    check("local hop: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    qc_sock_ports(p.cli, &c0, &pre0, &pf0);
    check("local hop: no previous socket before a hop", -1, pf0);
    check("local hop: the server knows the first local port", 1, c0 != 0 && c0 == qc_peer_port(p.srv));
    memset(&g_lh, 0, sizeof g_lh);
    g_lh.at = MIB / 2;
    g_hpr_tick = tick_hop_at;
    check("local hop: 1 MiB echo across the hop intact with FIN", 0, hop_pair_echo(&p, MIB, 20000));
    g_hpr_tick = NULL;
    qc_stats_get(p.cli, &st);
    check("local hop: the hop ran mid-echo", 1, g_lh.done);
    check("local hop: hops 1", 1, (long)st.hops);
    check("local hop: a new current local port", 1, g_lh.cur != 0 && g_lh.cur != c0);
    check("local hop: the old local port is the previous", c0, g_lh.pre);
    check("local hop: the previous socket is open at the hop", 1, g_lh.pre_open);
    check("local hop: the remote port stays the server's", qc_local_port(p.srv), st.port);
    uint64_t end = ms_now() + 2000ull * g_tx;
    while (qc_peer_port(p.srv) != g_lh.cur && ms_now() < end) hpr_pass(&p, 50, 1);
    check("local hop: the server followed to the new local port", g_lh.cur, qc_peer_port(p.srv));
    check("local hop: both ends alive", 0, g_hpr_c.closed + g_hpr_s.closed);
    hop_pair_free(&p);
}

static void ngtcp2_never_sees_a_local_hop(void) {
    struct hop_pair p;
    uint16_t c0 = 0, c1 = 0, pre = 0, nl = 0, nr = 0;
    int pf = -1;
    check("fixed local path: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    qc_sock_ports(p.cli, &c0, &pre, &pf);
    check("fixed local path: the socket port is the first local port", c0, qc_sock_port(p.cli));
    qc_hop_now(p.cli);
    qc_sock_ports(p.cli, &c1, &pre, &pf);
    check("fixed local path: the hop moved the socket", 1, c1 != 0 && c1 != c0);
    check("fixed local path: the socket port follows the hop", c1, qc_sock_port(p.cli));
    check("fixed local path: 1 MiB echo after the hop intact with FIN", 0, hop_pair_echo(&p, MIB, 20000));
    qc_path_ports(p.cli, &nl, &nr);
    check("fixed local path: ngtcp2 holds the open's local port", c0, nl);
    check("fixed local path: ngtcp2 holds the open's remote port", qc_local_port(p.srv), nr);
    hop_pair_free(&p);
}

static int g_prep_n, g_prep_fail_at;

static int prep_count(int fd) {
    (void)fd;
    return ++g_prep_n == g_prep_fail_at ? -1 : 0;
}

static void a_failed_local_hop_keeps_the_link(void) {
    struct hop_pair p;
    struct qc_stats st;
    uint16_t c0 = 0, c1 = 0, pre = 0;
    int pf = 0;
    g_prep_n = 0;
    g_prep_fail_at = 2;
    g_hop_prepare = prep_count;
    check("failed local hop: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    g_hop_prepare = NULL;
    qc_sock_ports(p.cli, &c0, &pre, &pf);
    int fds = open_fds();
    qc_hop_now(p.cli);
    qc_stats_get(p.cli, &st);
    check("failed local hop: prepare ran for the new socket", 2, g_prep_n);
    check("failed local hop: hops 0", 0, (long)st.hops);
    check("failed local hop: hop_fails 1", 1, (long)st.hop_fails);
    check("failed local hop: no fd left behind", fds, open_fds());
    qc_sock_ports(p.cli, &c1, &pre, &pf);
    check("failed local hop: the current socket stays", c0, c1);
    check("failed local hop: no previous socket", -1, pf);
    check("failed local hop: the port stays", qc_local_port(p.srv), st.port);
    check("failed local hop: 1 MiB echo intact with FIN", 0, hop_pair_echo(&p, MIB, 20000));
    check("failed local hop: the link stays", 0, g_hpr_c.closed);
    g_prep_fail_at = 0;
    hop_pair_free(&p);
}

static int old_path_done(const struct hop_pair *p) {
    struct qc_stats s;
    qc_stats_get(p->srv, &s);
    return g_hpr_c.got == 65536 && g_hpr_c.fin && s.in_flight == 0;
}

static unsigned owner_turns(struct hop_pair *p, int ep, int srv, unsigned ms, uint16_t *peer_at_wake) {
    unsigned woke = 0;
    uint64_t end = ms_now() + (uint64_t)ms * g_tx;
    while (ms_now() < end && !(srv && old_path_done(p))) {
        struct epoll_event e;
        if (epoll_wait(ep, &e, 1, srv ? 0 : 5) == 1) {
            if (peer_at_wake && !woke) *peer_at_wake = qc_peer_port(p->srv);
            woke++;
            (void)qc_on_readable(p->cli);
        } else if (!srv) {
            break;
        }
        if (srv) hpr_pass(p, 5, 0);
    }
    return woke;
}

static void the_end_of_the_linger_reads_what_is_queued(void) {
    struct hop_pair p;
    struct qc_stats c0, c1;
    check("linger end: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    hop_pair_pump(&p, 50);
    epoll_ctl(p.ep, EPOLL_CTL_DEL, qc_fd(p.cli), NULL);
    g_hpr_c.in_ep = 0;
    uint16_t old = cur_port(p.cli), cur = 0, pre = 0;
    int pf = -1;
    qc_hop_now(p.cli);
    qc_sock_ports(p.cli, &cur, &pre, &pf);
    int spy = dup(pf);
    qc_stats_get(p.cli, &c0);
    check("linger end: the server sends on the old path", 0, hpr_srv_send(&p, 16384));
    uint64_t end = qc_linger_end_ns(p.cli);
    while (ns_now() < end) hpr_pass(&p, 50, 0);
    check("linger end: the old socket holds it unread", 1, !pre_gone(p.cli) && g_hpr_c.got == 0);
    static const uint8_t junk[40] = { 0x40, 0xa5, 0x5a, 0xa5, 0x5a };
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(old), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    int sent = 0;
    for (int i = 0; i < 300; i++)
        sent += sendto(qc_fd(p.srv), junk, sizeof junk, 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)sizeof junk;
    check("linger end: 300 datagrams more behind it", 300, sent);
    (void)qc_on_timer(p.cli);
    check("linger end: one pass leaves the old socket open", 0, pre_gone(p.cli));
    int asked = 1;
    for (int i = 0; i < 1000 && !pre_gone(p.cli); i++) {
        asked &= qc_deadline_ns(p.cli) == 0;
        (void)qc_on_timer(p.cli);
    }
    qc_stats_get(p.cli, &c1);
    uint8_t b[64];
    errno = 0;
    ssize_t left = recv(spy, b, sizeof b, MSG_DONTWAIT);
    check("linger end: the deadline asks for each next pass at once", 1, asked);
    check("linger end: the old socket is closed", 1, pre_gone(p.cli));
    check("linger end: it was read until empty", 1, left == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
    check("linger end: what it held was read first", 1, c1.pkt_recv > c0.pkt_recv && g_hpr_c.got > 0 && g_hpr_c.bad == 0);
    check("linger end: the link stays", 0, g_hpr_c.closed);
    close(spy);
    hop_pair_free(&p);
}

static void the_old_socket_still_wakes_the_owner(void) {
    struct hop_pair p;
    struct qc_stats c0, c1, s0, s1;
    uint16_t old = 0, pre = 0, at_wake = 0;
    int pf = -1;
    check("old path: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    hop_pair_pump(&p, 50);
    qc_sock_ports(p.cli, &old, &pre, &pf);
    epoll_ctl(p.ep, EPOLL_CTL_DEL, qc_fd(p.cli), NULL);
    g_hpr_c.in_ep = 0;
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    check("old path: the owner watches qc_fd alone", 0, epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(p.cli), &ev));
    qc_hop_now(p.cli);
    qc_stats_get(p.cli, &c0);
    qc_stats_get(p.srv, &s0);
    uint16_t cur = 0;
    qc_sock_ports(p.cli, &cur, &pre, &pf);
    check("old path: the hop moved the socket", 1, old != 0 && cur != 0 && cur != old);
    check("old path: the old socket lingers", 1, fd_open(pf));
    check("old path: the server has not heard the new socket", old, qc_peer_port(p.srv));
    check("old path: the server sends 64 KiB", 0, hpr_srv_send(&p, 65536));
    unsigned woke = owner_turns(&p, ep, 1, 5000, &at_wake);
    owner_turns(&p, ep, 0, 1000, NULL);
    qc_stats_get(p.cli, &c1);
    qc_stats_get(p.srv, &s1);
    check("old path: the owner woke", 1, woke > 0);
    check("old path: the first wake came from the old socket", old, at_wake);
    check("old path: 64 KiB intact with FIN", 1, g_hpr_c.got == 65536 && g_hpr_c.bad == 0 && g_hpr_c.fin);
    check("old path: pkt_recv grew by the server's packets", (long)(s1.pkt_sent - s0.pkt_sent),
          (long)(c1.pkt_recv - c0.pkt_recv));
    close(ep);
    hop_pair_free(&p);
}

static struct { uint64_t end_ns; unsigned early, seen_open, late, closed; } g_lg;

static void tick_linger(struct hop_pair *p) {
    uint16_t cur, pre;
    int pf;
    qc_sock_ports(p->cli, &cur, &pre, &pf);
    if (pf >= 0) {
        g_lg.seen_open++;
        g_lg.late += qc_deadline_ns(p->cli) > g_lg.end_ns;
        return;
    }
    if (qc_now_ns(p->cli) < g_lg.end_ns) g_lg.early++;
    g_lg.closed = 1;
}

static void the_old_socket_lingers_until_its_end(void) {
    struct hop_pair p;
    struct qc_stats st;
    uint16_t cur = 0, pre = 0;
    int pf = -1;
    check("linger: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    check("linger: warm-up echo", 0, hop_pair_echo(&p, 65536, 10000));
    check("linger: the hop is 3600 s away", 1, qc_hop_due_ns(p.cli) == p.opened_ns + 3600000000000ull);
    memset(&g_lg, 0, sizeof g_lg);
    uint64_t t0 = ms_now();
    qc_hop_now(p.cli);
    g_lg.end_ns = qc_linger_end_ns(p.cli);
    check("linger: it ends one linger of the link's srtt after the hop, on the link's clock", 1,
          qc_now_ns(p.cli) && g_lg.end_ns == qc_now_ns(p.cli) + qc_hop_linger_ns(qc_srtt_ns(p.cli), 3600000000000ull));
    qc_sock_ports(p.cli, &cur, &pre, &pf);
    check("linger: the previous socket after the hop", 1, fd_open(pf));
    check("linger: the inner epoll holds both sockets", 2, epoll_tfds(qc_fd(p.cli)));
    g_rx_log_n = 0;
    g_rx_log_on = 1;
    (void)qc_on_readable(p.cli);
    g_rx_log_on = 0;
    check("linger: a receive pass reads the old socket first", pf, g_rx_log[0]);
    check("linger: then the current one", 1, g_rx_log_n == 2 && g_rx_log[1] >= 0 && g_rx_log[1] != pf);
    g_hpr_rx_min[0] = g_hpr_rx_min[1] = UINT64_MAX;
    g_hpr_tick = tick_linger;
    while (!g_lg.closed && ms_now() < t0 + 2000 + 10000ull * g_tx) (void)hop_pair_echo(&p, 256 * 1024, 10000);
    int after = hop_pair_echo(&p, 256 * 1024, 10000);
    g_hpr_tick = NULL;
    int pf_after = 0;
    qc_sock_ports(p.cli, &cur, &pre, &pf_after);
    qc_stats_get(p.cli, &st);
    check("linger: never closed before its end on the link's clock", 1, g_lg.seen_open > 0 && g_lg.early == 0);
    check("linger: the reported deadline never passed its end", 0, (long)g_lg.late);
    check("linger: it closed", 1, (long)g_lg.closed);
    check("linger: no previous socket after it", -1, pf_after);
    check("linger: the old fd is closed", 0, fd_open(pf));
    check("linger: the inner epoll holds one socket", 1, epoll_tfds(qc_fd(p.cli)));
    check("linger: echo after the linger intact", 0, after);
    check("linger: two reads per readable during the linger", 2, (long)g_hpr_rx_min[1]);
    check("linger: one read per readable after it", 1, (long)g_hpr_rx_min[0]);
    check("linger: hops 1", 1, (long)st.hops);
    check("linger: the link stays", 0, g_hpr_c.closed + g_hpr_s.closed);
    hop_pair_free(&p);
}

static int quiet_for(struct hop_pair *p, uint64_t ns) {
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (qc_deadline_ns(p->cli) < ns_now() + ns && ms_now() < end) hpr_pass(p, 50, 1);
    return qc_deadline_ns(p->cli) >= ns_now() + ns;
}

static void the_linger_ends_on_a_quiet_link(void) {
    struct hop_pair p;
    check("quiet linger: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    check("quiet linger: nothing due for 3 s", 1, quiet_for(&p, 3000000000ull));
    epoll_ctl(p.ep, EPOLL_CTL_DEL, qc_fd(p.cli), NULL);
    g_hpr_c.in_ep = 0;
    qc_hop_now(p.cli);
    check("quiet linger: the old socket lingers", 0, pre_gone(p.cli));
    check("quiet linger: the reported deadline is the linger's end", 1,
          qc_deadline_ns(p.cli) == qc_linger_end_ns(p.cli));
    check("quiet linger: one timer call at that deadline", 1, (long)timer_by_deadline(p.cli, pre_gone));
    check("quiet linger: it closed the old socket", 1, pre_gone(p.cli));
    check("quiet linger: the inner epoll holds one socket", 1, epoll_tfds(qc_fd(p.cli)));
    check("quiet linger: the link stays", 0, g_hpr_c.closed);
    hop_pair_free(&p);
}

static void the_linger_is_four_rtts_between_two_seconds_and_the_interval(void) {
    static const struct {
        const char *what;
        uint64_t srtt_ms, interval_ms, want_ms;
    } rows[] = {
        { "no rtt: 2 s", 0, 30000, 2000 },
        { "1 ms: 2 s", 1, 30000, 2000 },
        { "ngtcp2's initial 333 ms, 4 x 333 = 1332: 2 s", 333, 30000, 2000 },
        { "500 ms, 4 x 500 = 2000: 2 s", 500, 30000, 2000 },
        { "800 ms, 4 x 800: 3.2 s", 800, 30000, 3200 },
        { "1250 ms, 4 x 1250 = the 5 s interval: 5 s", 1250, 5000, 5000 },
        { "2 s, 4 x 2 = 8 s over a 5 s interval: 5 s", 2000, 5000, 5000 },
    };
    char nm[128];
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        snprintf(nm, sizeof nm, "linger arithmetic: %s", rows[i].what);
        check(nm, 1, qc_hop_linger_ns(rows[i].srtt_ms * 1000000ull, rows[i].interval_ms * 1000000ull) ==
                         rows[i].want_ms * 1000000ull);
    }
}

static void fds_come_back(void) {
    struct hop_pair p;
    struct qc_stats st;
    int f0 = open_fds();
    check("fds: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    int f1 = open_fds();
    qc_hop_now(p.cli);
    int f2 = open_fds();
    qc_hop_now(p.cli);
    int f3 = open_fds();
    qc_stats_get(p.cli, &st);
    check("fds: hops 2", 2, (long)st.hops);
    check("fds: a hop holds one previous socket", f1 + 1, f2);
    check("fds: the next hop closes the lingering one first", f2, f3);
    check("fds: the inner epoll holds two sockets", 2, epoll_tfds(qc_fd(p.cli)));
    check("fds: 1 MiB echo after two hops intact", 0, hop_pair_echo(&p, MIB, 20000));
    int t = 0;
    socklen_t tl = sizeof t;
    errno = 0;
    int rc = getsockopt(qc_fd(p.cli), SOL_SOCKET, SO_TYPE, &t, &tl);
    check("fds: LOCAL qc_fd is no socket", 1, rc == -1 && errno == ENOTSOCK);
    check("fds: a LOCAL link charges three fds", 3, qc_fd_extra(p.cli));
    hop_pair_free(&p);
    check("fds: every fd comes back after qc_free", f0, open_fds());

    struct qc_cfg cc;
    struct qc *q = NULL;
    struct port_range two[2] = { { 40000, 40000 }, { 40001, 40001 } };
    cli_cfg(&cc, "h3");
    cc.port = 40000;
    hop_cfg(&cc, two, 2, rand_7);
    check("fds: REMOTE qc_open", 0, qc_open(&cc, &g_ops, NULL, &q));
    errno = 0;
    rc = getsockopt(qc_fd(q), SOL_SOCKET, SO_TYPE, &t, &tl);
    check("fds: REMOTE qc_fd is no socket either", 1, rc == -1 && errno == ENOTSOCK);
    check("fds: a REMOTE link charges three fds", 3, qc_fd_extra(q));
    qc_free(q);
    struct port_range one = { 40000, 40000 };
    hop_cfg(&cc, &one, 1, rand_7);
    check("fds: REMOTE with one port qc_open", 0, qc_open(&cc, &g_ops, NULL, &q));
    t = 0;
    tl = sizeof t;
    check("fds: without a hop timer qc_fd is the socket", 0, getsockopt(qc_fd(q), SOL_SOCKET, SO_TYPE, &t, &tl));
    check("fds: a datagram socket", SOCK_DGRAM, t);
    check("fds: a link without a hop timer charges nothing", 0, qc_fd_extra(q));
    qc_free(q);
}

static void no_hop_before_the_handshake(void) {
    struct hop_pair p;
    struct qc_stats st;
    g_hop_s = 5;
    int rc = hop_pair_start(&p, QC_HOP_LOCAL, NULL, 0, rand_7);
    g_hop_s = 3600;
    check("early hop: pair starts", 0, rc);
    epoll_ctl(p.ep, EPOLL_CTL_DEL, qc_fd(p.srv), NULL);
    g_hpr_s.in_ep = 0;
    uint16_t first = cur_port(p.cli);
    uint64_t due = qc_hop_due_ns(p.cli);
    int c0 = g_connects, fds = open_fds();
    uint64_t end = ms_now() + 5000 + 2000ull * g_tx;
    while (qc_hop_due_ns(p.cli) == due && ms_now() < end) hpr_pass(&p, 50, 1);
    end += 5000ull * g_tx;
    while (!pre_gone(p.cli) && ms_now() < end) hpr_pass(&p, 50, 1);
    qc_stats_get(p.cli, &st);
    check("early hop: the handshake is still running", 0, st.handshake_done + g_hpr_c.hs);
    check("early hop: the due hop is re-armed 5 s on", 1, qc_hop_due_ns(p.cli) >= due + 5000000000ull);
    check("early hop: the new due time is ahead", 1, qc_hop_due_ns(p.cli) > qc_now_ns(p.cli));
    check("early hop: hops 0", 0, (long)st.hops);
    check("early hop: hop_fails 0", 0, (long)st.hop_fails);
    check("early hop: no hop socket was made", c0, g_connects);
    check("early hop: no fd more", fds, open_fds());
    hpr_watch(&p, &g_hpr_s);
    end = ms_now() + 10000ull * g_tx;
    while (!(g_hpr_c.hs && g_hpr_s.hs) && !g_hpr_c.closed && ms_now() < end) hpr_pass(&p, 50, 1);
    check("early hop: the handshake completes after it", 1, g_hpr_c.hs && g_hpr_s.hs);
    check("early hop: the server answers the first port", first, qc_peer_port(p.srv));
    hop_pair_free(&p);
}

static void a_quiet_local_hop_moves_the_server_with_its_ping(void) {
    struct hop_pair p;
    struct qc_stats c0, c1, s0, s1;
    check("quiet local hop: pair opens", 0, hop_pair_open(&p, QC_HOP_LOCAL, NULL, 0, rand_7));
    check("quiet local hop: warm-up echo", 0, hop_pair_echo(&p, 65536, 10000));
    qc_keepalive(p.cli, 20000);
    check("quiet local hop: nothing due for 3 s", 1, quiet_for(&p, 3000000000ull));
    (void)qc_on_readable(p.srv);
    uint16_t old = cur_port(p.cli);
    check("quiet local hop: the server holds the first port", old, qc_peer_port(p.srv));
    qc_stats_get(p.cli, &c0);
    qc_stats_get(p.srv, &s0);
    qc_hop_now(p.cli);
    qc_flush(p.cli);
    qc_stats_get(p.cli, &c1);
    uint16_t cur = cur_port(p.cli);
    check("quiet local hop: the hop sends one packet", 1, (long)(c1.pkt_sent - c0.pkt_sent));
    (void)qc_on_readable(p.srv);
    qc_stats_get(p.srv, &s1);
    check("quiet local hop: the server's next read holds that packet", 1, (long)(s1.pkt_recv - s0.pkt_recv));
    check("quiet local hop: it moves the server to the new port", 1, cur != old && cur == qc_peer_port(p.srv));
    (void)timer_by_deadline(p.cli, pre_gone);
    check("quiet local hop: the linger ends with the server silent", 1, pre_gone(p.cli));
    check("quiet local hop: the server sends 64 KiB", 0, hpr_srv_send(&p, 65536));
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (!(g_hpr_c.got == 65536 && g_hpr_c.fin) && !g_hpr_c.closed && ms_now() < end) {
        hpr_pass(&p, 50, 0);
        struct epoll_event e;
        if (epoll_wait(qc_fd(p.cli), &e, 1, 0) == 1) (void)qc_on_readable(p.cli);
    }
    check("quiet local hop: they reach the new socket intact, the client only reading", 1,
          g_hpr_c.got == 65536 && g_hpr_c.bad == 0 && g_hpr_c.fin);
    hop_pair_free(&p);
}

static void a_bad_hop_config_is_refused(void) {
    static const struct {
        const char *what;
        unsigned mode, lo, hi;
        size_t n;
        struct port_range r;
    } bad[] = {
        { "33 ranges", QC_HOP_REMOTE, 5, 5, PORT_RANGES_MAX + 1, { 40000, 40000 } },
        { "a range from port 0", QC_HOP_REMOTE, 5, 5, 1, { 0, 10 } },
        { "a range with hi < lo", QC_HOP_REMOTE, 5, 5, 1, { 40010, 40000 } },
        { "interval 0-5", QC_HOP_LOCAL, 0, 5, 0, { 0, 0 } },
        { "interval 4-4", QC_HOP_LOCAL, 4, 4, 0, { 0, 0 } },
        { "interval 10-5", QC_HOP_LOCAL, 10, 5, 0, { 0, 0 } },
        { "interval 0-UINT_MAX", QC_HOP_REMOTE, 0, UINT_MAX, 1, { 40000, 40001 } },
        { "interval 10-5 without a hop mode", 0, 10, 5, 0, { 0, 0 } },
    };
    char nm[128];
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        struct qc_cfg cc;
        struct qc *q = NULL;
        cli_cfg(&cc, "h3");
        cc.port = 40000;
        cc.hop_mode = bad[i].mode;
        cc.hop_min_s = bad[i].lo;
        cc.hop_max_s = bad[i].hi;
        cc.hop_n = bad[i].n;
        for (size_t k = 0; k < bad[i].n && k < PORT_RANGES_MAX; k++) cc.hop_ports[k] = bad[i].r;
        int fds = open_fds();
        snprintf(nm, sizeof nm, "bad hop config: %s refused", bad[i].what);
        check(nm, QC_EINVAL, qc_open(&cc, &g_ops, NULL, &q));
        snprintf(nm, sizeof nm, "bad hop config: %s leaves nothing", bad[i].what);
        check(nm, 1, q == NULL && fds == open_fds());
    }
    static const unsigned good[][2] = { { 5, 5 }, { 0, 0 }, { 5, UINT_MAX } };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        struct qc_cfg cc;
        struct qc *q = NULL;
        cli_cfg(&cc, "h3");
        cc.port = 40000;
        cc.hop_mode = QC_HOP_LOCAL;
        cc.hop_min_s = good[i][0];
        cc.hop_max_s = good[i][1];
        snprintf(nm, sizeof nm, "good hop config: interval %u-%u taken", good[i][0], good[i][1]);
        check(nm, 0, qc_open(&cc, &g_ops, NULL, &q));
        qc_free(q);
    }
}

static void quiet_open(struct pair *p, struct relay *r, int flows, unsigned mode) {
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.idle_ms = sc.idle_ms = 60000;
    memset(p, 0, sizeof *p);
    p->ep = epoll_create1(0);
    g_rseq = 0;
    check("quiet hop: server listens", 0, qc_listen(&sc, &g_ops, &p->s, &p->s.q));
    ep_add(p, &p->s);
    check("quiet hop: relay opens", 0, relay_open(r, p->ep, qc_local_port(p->s.q)));
    struct port_range pr[RELAY_N];
    for (int i = 0; i < RELAY_N; i++) pr[i].lo = pr[i].hi = r->port[i];
    cc.port = r->port[0];
    hop_cfg(&cc, pr, RELAY_N, rand_seq);
    cc.hop_mode = mode;
    check("quiet hop: client opens", 0, qc_open(&cc, &g_ops, &p->c, &p->c.q));
    ep_add(p, &p->c);
    p->s.echo = 1;
    p->s.consume_in_cb = 1;
    p->c.consume_in_cb = 1;
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (!c_both_hs(p, NULL) && ms_now() < end) step_relay(p, r);
    check("quiet hop: handshake", 1, c_both_hs(p, NULL));
    if (flows) {
        check("quiet hop: a stream opens", 0, open_stream(p, &sid));
        out_static(&p->c, sid, g_pat, 65536, 0);
        struct want w = { &p->c, sid, 65536 };
        end = ms_now() + 10000ull * g_tx;
        while (!c_got(p, &w) && ms_now() < end) step_relay(p, r);
        check("quiet hop: 64 KiB echoed on a stream that stays open", 1, c_got(p, &w));
        qc_keepalive(p->c.q, 20000);
    }
    relay_for(p, r, 400);
}

static void quiet_round(int flows) {
    struct pair p;
    struct relay r;
    struct qc_stats a, b;
    char nm[128];
    const char *tag = flows ? "quiet hop, flows open" : "quiet hop, no flows";
    quiet_open(&p, &r, flows, QC_HOP_REMOTE);
    qc_stats_get(p.c.q, &a);
    qc_hop_now(p.c.q);
    qc_flush(p.c.q);
    qc_stats_get(p.c.q, &b);
    snprintf(nm, sizeof nm, "%s: hops 1", tag);
    check(nm, 1, (long)b.hops);
    snprintf(nm, sizeof nm, "%s: packets the hop sends", tag);
    check(nm, flows, (long)(b.pkt_sent - a.pkt_sent));
    uint64_t end = ms_now() + 2000 + 1000ull * g_tx;
    while (!pre_gone(p.c.q) && ms_now() < end) step_relay(&p, &r);
    snprintf(nm, sizeof nm, "%s: the old socket's linger ends", tag);
    check(nm, 1, pre_gone(p.c.q));
    qc_stats_get(p.c.q, &a);
    if (flows) {
        uint64_t r0 = a.pkt_recv;
        qc_ping(p.s.q);
        end = ms_now() + 1000ull * g_tx;
        while (a.pkt_recv == r0 && ms_now() < end) {
            step_relay(&p, &r);
            qc_stats_get(p.c.q, &a);
        }
        snprintf(nm, sizeof nm, "%s: the server is heard after the linger", tag);
        check(nm, 1, a.pkt_recv > r0);
        epoll_ctl(p.ep, EPOLL_CTL_DEL, qc_fd(p.c.q), NULL);
        p.c.in_ep = 0;
        int ep = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(p.c.q), &ev);
        struct end *srv[1] = { &p.s };
        r0 = a.pkt_recv;
        qc_ping(p.s.q);
        unsigned woke = 0;
        end = ms_now() + 1000ull * g_tx;
        while (a.pkt_recv == r0 && ms_now() < end) {
            pass_ends(p.ep, srv, 1);
            relay_pump(&r);
            struct epoll_event e;
            if (epoll_wait(ep, &e, 1, 0) == 1) {
                woke++;
                (void)qc_on_readable(p.c.q);
            }
            qc_stats_get(p.c.q, &a);
        }
        close(ep);
        snprintf(nm, sizeof nm, "%s: after the linger qc_fd alone wakes the owner", tag);
        check(nm, 1, woke > 0 && a.pkt_recv > r0);
    } else {
        snprintf(nm, sizeof nm, "%s: nothing sent through the linger", tag);
        check(nm, (long)b.pkt_sent, (long)a.pkt_sent);
    }
    pair_free(&p);
    relay_close(&r);
}

static void a_quiet_hop_is_heard_only_with_flows(void) {
    quiet_round(1);
    quiet_round(0);
}

static void a_remote_hop_keeps_the_old_port_readable(void) {
    struct pair p;
    struct relay r;
    struct qc_stats st;
    uint16_t lp, cur = 0, pre = 0;
    int pf = -1;
    quiet_open(&p, &r, 0, QC_HOP_REMOTE);
    lp = cur_port(p.c.q);
    epoll_ctl(p.ep, EPOLL_CTL_DEL, qc_fd(p.c.q), NULL);
    p.c.in_ep = 0;
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN };
    epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(p.c.q), &ev);
    int old = r.cur;
    qc_hop_now(p.c.q);
    qc_sock_ports(p.c.q, &cur, &pre, &pf);
    qc_stats_get(p.c.q, &st);
    check("old port: the hop went to the drawn port", r.port[2], st.port);
    check("old port: the new socket is connected to it", r.port[2], g_conn_port);
    check("old port: the old socket lingers on the same local port", 1, pf >= 0 && pre == lp && cur == lp);
    unsigned long o_old = r.out[old], o_new = r.out[2];
    qc_stats_get(p.c.q, &st);
    uint64_t r0 = st.pkt_recv;
    qc_ping(p.s.q);
    struct end *srv[1] = { &p.s };
    uint64_t end = ms_now() + 2000ull * g_tx;
    while (st.pkt_recv == r0 && ms_now() < end) {
        pass_ends(p.ep, srv, 1);
        relay_pump(&r);
        struct epoll_event e;
        if (epoll_wait(ep, &e, 1, 0) == 1) (void)qc_on_readable(p.c.q);
        qc_stats_get(p.c.q, &st);
    }
    check("old port: the server's answer through the old port is read", 1, st.pkt_recv > r0);
    check("old port: it came through the old port", 1, r.out[old] > o_old && r.out[2] == o_new);
    close(ep);
    pair_free(&p);
    relay_close(&r);
}

static void a_combined_hop_dials_the_new_port_from_a_new_socket(void) {
    struct pair p;
    struct relay r;
    struct qc_stats st;
    uint16_t cur = 0, pre = 0, nl = 0, nr = 0;
    int pf = -1;
    int64_t sid = -1;
    quiet_open(&p, &r, 0, QC_HOP_LOCAL | QC_HOP_REMOTE);
    uint16_t lp = cur_port(p.c.q);
    int c0 = g_connects;
    unsigned long in2 = r.in[2];
    qc_hop_now(p.c.q);
    qc_sock_ports(p.c.q, &cur, &pre, &pf);
    qc_stats_get(p.c.q, &st);
    check("combined hop: one connect", c0 + 1, g_connects);
    check("combined hop: to the drawn port", r.port[2], g_conn_port);
    check("combined hop: stats.port the drawn port", r.port[2], st.port);
    check("combined hop: from a new socket", 1, g_conn_fd >= 0 && g_conn_fd != pf);
    check("combined hop: on a new local port", 1, cur != 0 && cur != lp && fd_local_port(g_conn_fd) == cur);
    check("combined hop: the old socket lingers on the old local port", 1, fd_open(pf) && pre == lp);
    check("combined hop: echo opens", 0, echo_open(&p, &sid));
    struct want w = { &p.c, sid, 0 };
    uint64_t end = ms_now() + 20000ull * g_tx;
    while (!c_closed_st(&p, &w) && ms_now() < end) step_relay(&p, &r);
    check("combined hop: 1 MiB echo intact with FIN", 1, echo_intact(&p, sid));
    check("combined hop: the drawn port carried it", 1, r.in[2] > in2);
    qc_path_ports(p.c.q, &nl, &nr);
    check("combined hop: ngtcp2 holds the open's local port", lp, nl);
    check("combined hop: ngtcp2 holds the open's remote port", r.port[0], nr);
    check("combined hop: the link stays", 0, p.c.closed);
    pair_free(&p);
    relay_close(&r);
    quiet_open(&p, &r, 0, QC_HOP_LOCAL);
    lp = cur_port(p.c.q);
    qc_hop_now(p.c.q);
    qc_stats_get(p.c.q, &st);
    check("local hop with a list: stats.port stays the dialled one", r.port[0], st.port);
    check("local hop with a list: the new socket dials it", r.port[0], g_conn_port);
    check("local hop with a list: on a new local port", 1, cur_port(p.c.q) != lp);
    pair_free(&p);
    relay_close(&r);
}

#define WAIT_T 1000000000000ull
#define WAIT_MS(n) (WAIT_T + (uint64_t)(n) * 1000000ull)

static void check_ns(const char *what, uint64_t want_ms, uint64_t got_ns) {
    uint64_t want = want_ms * 1000000ull;
    check(what, 1, want == got_ns);
    if (want != got_ns) printf("     want ns: %llu\n     got ns:  %llu\n", (unsigned long long)want, (unsigned long long)got_ns);
}

static void waits_are(const char *tag, struct qc *q, uint64_t at, uint64_t cwnd_ms, uint64_t credit_ms, uint64_t budget_ms) {
    uint64_t w[3] = { 1, 1, 1 };
    char b[160];
    qc_wait_get(q, at, w);
    snprintf(b, sizeof b, "%s: %llu ms on the window", tag, (unsigned long long)cwnd_ms);
    check_ns(b, cwnd_ms, w[QC_WAIT_CWND]);
    snprintf(b, sizeof b, "%s: %llu ms on peer credit", tag, (unsigned long long)credit_ms);
    check_ns(b, credit_ms, w[QC_WAIT_CREDIT]);
    snprintf(b, sizeof b, "%s: %llu ms on our budget", tag, (unsigned long long)budget_ms);
    check_ns(b, budget_ms, w[QC_WAIT_BUDGET]);
}

static int c_got_idle(struct pair *p, void *a) { return c_got(p, a) && c_cli_idle(p, NULL); }

static void credit_wait_round(const char *tag, uint64_t max_data, uint64_t max_stream_data, size_t window, size_t total) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char b[160];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_data = max_data;
    sc.max_stream_data = max_stream_data;
    snprintf(b, sizeof b, "%s: pair opens", tag);
    check(b, 0, pair_open(&p, &cc, &sc));
    snprintf(b, sizeof b, "%s: handshake", tag);
    check(b, 1, pump_until(&p, c_both_hs, NULL, 10000));
    qc_clock_set(p.c.q, WAIT_MS(0));
    snprintf(b, sizeof b, "%s: stream opens", tag);
    check(b, 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, total, 0);
    struct want w = { &p.s, sid, window };
    snprintf(b, sizeof b, "%s: the window fills and is acknowledged", tag);
    check(b, 1, pump_until(&p, c_got_idle, &w, 10000));
    pump_for(&p, 100);
    struct strm *s = strm_get(&p.s, sid);
    snprintf(b, sizeof b, "%s: and stays at %zu", tag, window);
    check(b, (long)window, s ? (long)s->got : -1);
    snprintf(b, sizeof b, "%s, held 300 ms", tag);
    waits_are(b, p.c.q, WAIT_MS(300), 0, 300, 0);
    qc_clock_set(p.c.q, WAIT_MS(300));
    p.s.consume_in_cb = 1;
    if (s) {
        qc_stream_consumed(p.s.q, sid, s->got);
        s->consumed = s->got;
        qc_flush(p.s.q);
    }
    w.n = total;
    snprintf(b, sizeof b, "%s: the rest arrives once credit comes", tag);
    check(b, 1, pump_until(&p, c_got_idle, &w, 10000));
    snprintf(b, sizeof b, "%s, read a second in", tag);
    waits_are(b, p.c.q, WAIT_MS(1000), 0, 300, 0);
    pair_free(&p);
}

static void a_closed_peer_window_is_counted_as_credit(void) {
    credit_wait_round("stream credit wait", 0, 65536, 65536, 200000);
    credit_wait_round("connection credit wait", 131072, 0, 131072, 300000);
}

static void a_reset_blocked_stream_ends_the_credit_wait(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_stream_data = 65536;
    check("reset credit wait: pair opens", 0, pair_open(&p, &cc, &sc));
    check("reset credit wait: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    qc_clock_set(p.c.q, WAIT_MS(0));
    check("reset credit wait: stream opens", 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, 200000, 0);
    struct want w = { &p.s, sid, 65536 };
    check("reset credit wait: the window fills and is acknowledged", 1, pump_until(&p, c_got_idle, &w, 10000));
    qc_clock_set(p.c.q, WAIT_MS(300));
    struct out *o = out_for(&p.c, sid);
    if (o) o->dead = 1;
    strm_get(&p.c, sid);
    check("reset credit wait: the blocked stream is reset", 0, qc_stream_reset(p.c.q, sid, 7));
    qc_flush(p.c.q);
    struct want wc = { &p.c, sid, 0 };
    check("reset credit wait: the stream closes", 1, pump_until(&p, c_closed_st, &wc, 10000));
    check("reset credit wait: idle", 1, pump_until(&p, c_cli_idle, NULL, 10000));
    qc_ping(p.c.q);
    pump_for(&p, 50);
    waits_are("reset credit wait, read a second in", p.c.q, WAIT_MS(1000), 0, 300, 0);
    pair_free(&p);
}

static size_t rx_gate(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    if (*(int *)u) return 0;
    memcpy(dst, src, n);
    return n;
}

struct sent_full { int64_t sid; size_t n; };

static int c_sent_full(struct pair *p, void *a) {
    struct sent_full *f = a;
    return qc_stream_unsent(p->c.q, f->sid) == 0 && qc_stream_queued(p->c.q, f->sid) == f->n;
}

static void a_full_send_buffer_is_counted_as_budget(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    int shut = 0;
    struct qc_filter gate = { NULL, rx_gate, &shut, 0 };
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_buf = 16384;
    cc.filter = &gate;
    check("budget wait: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.consume_in_cb = 1;
    check("budget wait: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("budget wait: stream opens", 0, open_stream(&p, &sid));
    check("budget wait: idle", 1, pump_until(&p, c_cli_idle, NULL, 10000));
    qc_clock_set(p.c.q, WAIT_MS(0));
    shut = 1;
    out_static(&p.c, sid, g_pat, 20000, 0);
    struct sent_full f = { sid, 16384 };
    check("budget wait: 16384 bytes queued and all sent", 1, pump_until(&p, c_sent_full, &f, 10000));
    waits_are("budget wait, held 300 ms", p.c.q, WAIT_MS(300), 0, 0, 300);
    qc_clock_set(p.c.q, WAIT_MS(300));
    shut = 0;
    struct want w = { &p.s, sid, 20000 };
    check("budget wait: the rest goes once acknowledgements come", 1, pump_until(&p, c_got_idle, &w, 10000));
    waits_are("budget wait, read a second in", p.c.q, WAIT_MS(1000), 0, 0, 300);
    pair_free(&p);
}

static void a_slow_controller_is_counted_as_the_window(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("window wait: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.consume_in_cb = 1;
    check("window wait: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("window wait: Brutal at 20000 B/s", 0, qc_cc_brutal(p.c.q, 20000, 0));
    check("window wait: stream opens", 0, open_stream(&p, &sid));
    check("window wait: idle", 1, pump_until(&p, c_cli_idle, NULL, 10000));
    qc_clock_set(p.c.q, WAIT_MS(0));
    out_static(&p.c, sid, g_pat, 100000, 0);
    struct want w = { &p.s, sid, 4000 };
    check("window wait: the first bytes arrive", 1, pump_until(&p, c_got, &w, 10000));
    check("window wait: the rest waits unsent", 1, qc_stream_unsent(p.c.q, sid) > 0);
    waits_are("window wait, held 300 ms", p.c.q, WAIT_MS(300), 300, 0, 0);
    qc_clock_set(p.c.q, WAIT_MS(300));
    check("window wait: Brutal at 1 GiB/s", 0, qc_cc_brutal(p.c.q, 1ull << 30, 0));
    w.n = 100000;
    check("window wait: the rest arrives", 1, pump_until(&p, c_got_idle, &w, 10000));
    waits_are("window wait, read a second in", p.c.q, WAIT_MS(1000), 300, 0, 0);
    pair_free(&p);
}

int main(void) {
    g_pat = malloc(4 * MIB);
    for (size_t i = 0; i < 4 * MIB; i++) g_pat[i] = pat(i);
    check("wolfSSL is built for strict alignment", 1, tcg_wolfssl_aligned());
    check("certificates issued", 0, certs_make());
    const char *tx = getenv("QC_TEST_TIME_X");
    if (tx && atoi(tx) > 0) g_tx = (unsigned)atoi(tx);
    const char *env = getenv("QC_TEST_NO_BATCH");
    int only_nb = env && !strcmp(env, "1");
    g_nb = only_nb;
    prepare_runs_before_connect_and_can_refuse();
    handshake_completes_only_on_the_same_alpn();
    for (int m = only_nb; m < 2; m++) {
        g_nb = m;
        a_megabyte_on_a_stream_arrives_intact_both_ways();
        a_datagram_arrives_intact_and_an_oversized_one_is_refused();
        a_filter_wraps_every_datagram_on_the_wire();
        no_pmtud_holds_1250_byte_packets();
        an_oversized_datagram_is_lost_not_fatal();
        deferred_sends_leave_together();
        four_megabytes_with_bounded_work();
        small_sends_of_many_streams_share_packets();
        a_path_that_shrinks_closes_the_connection();
    }
    g_nb = only_nb;
    unread_stream_data_stops_at_the_window();
    a_pin_decides_alone();
    chain_and_name_are_checked_without_a_pin();
    an_idle_connection_closes_at_the_idle_limit();
    keepalive_can_be_switched_at_run_time();
    keepalive_is_clamped_to_the_idle_and_floored();
    stop_and_reset_reach_the_peer_with_their_codes();
    room_coming_back_is_announced();
    the_preferred_suite_is_negotiated();
    connection_credit_of_a_dead_stream_comes_back();
    a_kernel_without_udp_segment_gets_plain_datagrams();
    a_server_without_alpn_is_refused();
    a_refused_port_is_fatal_only_before_the_handshake();
    an_oversized_filter_overhead_is_refused();
    streams_come_back_after_they_close();
    the_owner_hears_when_streams_open_again();
    six_hundred_streams_at_once();
    a_peer_abort_of_one_direction_is_heard();
    a_reset_stream_forgets_what_it_had_to_send();
    acknowledged_data_holds_no_chunk();
    unsent_counts_only_what_no_packet_carried();
    dont_fragment_is_set_on_both_families();
    credit_needs_no_flush_from_the_owner();
    one_clock_read_per_batch();
    the_connection_budget_bounds_what_streams_queue();
    a_dead_write_side_frees_its_chunks_at_once();
    idle_flushes_cost_nothing();
    slow_streams_leave_room_for_another();
    brutal_replaces_the_controller_after_the_handshake();
    brutal_widens_the_send_buffers_to_one_second_of_its_rate();
    brutal_sizing_stops_at_the_small_budget();
    the_first_window_is_32_packets();
    loss_never_lowers_the_bbr_model();
    the_blind_ack_keeps_ngtcp2s_bookkeeping();
    a_lost_probe_sample_is_hidden_from_bbr();
    the_blind_controller_goes_on_bbr_only_once();
    brutal_without_an_rtt_sample_uses_the_minimum_window();
    losses_never_shrink_the_brutal_window();
    the_controller_counts_what_it_can_lose();
    the_counts_carry_over_a_controller_swap();
    a_plain_link_tells_its_socket_port();
    an_installed_controller_sets_a_window_and_a_pace();
    the_window_floor_lets_a_second_packet_go();
    a_loss_found_by_the_timer_keeps_the_window();
    a_closed_peer_window_is_counted_as_credit();
    a_reset_blocked_stream_ends_the_credit_wait();
    a_full_send_buffer_is_counted_as_budget();
    a_slow_controller_is_counted_as_the_window();
    a_remote_hop_keeps_the_local_port();
    ngtcp2_never_sees_a_remote_hop();
    a_failed_remote_hop_keeps_the_link();
    hops_are_timed();
    remote_hops_keep_the_link_and_its_liveness_clock();
    int hop_fds = open_fds();
    a_local_hop_moves_to_a_new_socket();
    ngtcp2_never_sees_a_local_hop();
    a_failed_local_hop_keeps_the_link();
    the_old_socket_still_wakes_the_owner();
    the_end_of_the_linger_reads_what_is_queued();
    the_old_socket_lingers_until_its_end();
    the_linger_is_four_rtts_between_two_seconds_and_the_interval();
    the_linger_ends_on_a_quiet_link();
    fds_come_back();
    no_hop_before_the_handshake();
    a_bad_hop_config_is_refused();
    a_quiet_hop_is_heard_only_with_flows();
    a_remote_hop_keeps_the_old_port_readable();
    a_combined_hop_dials_the_new_port_from_a_new_socket();
    a_quiet_local_hop_moves_the_server_with_its_ping();
    check("local hops: every fd comes back", hop_fds, open_fds());
    for (int m = only_nb; m < 2; m++) {
        g_nb = m;
        a_callback_may_drive_another_connection();
    }
    g_nb = only_nb;
    free(g_pat);
    return unit_done("quicmatch");
}
