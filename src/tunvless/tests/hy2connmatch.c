#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "quic.h"
#include "hy2conn.h"
#include "hy2link.h"
#include "certgen.h"
#include "unit.h"

static uint64_t ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t hp_ms(void) { return ms_now(); }

#include "hy2peer.h"

#define MIB 1048576
#define CMAXST 1024

static uint8_t *g_pat;
static unsigned char g_ca[2048], g_leaf[2048], g_key[512];
static size_t g_ca_n, g_leaf_n, g_key_n;
static char g_ca_pem[4096];
static int g_nb;
static unsigned g_tx = 1;

static uint8_t pat(size_t i) { return (uint8_t)((i * 31 + 7) % 251); }

struct cst {
    int64_t sid;
    size_t got, consumed, bad, data_calls, to_send, sent, conn_ret;
    int fin, refused, closed, how, short_hit, hooked, fin_at_close;
    size_t got_at_close;
    uint64_t t_in, t_ret;
    unsigned writable, wseen;
    char msg[160];
};

struct cl {
    struct hy2c *c;
    int ready, closed, reason, in_ep, consume, cbs, streams_open, udp;
    uint64_t peer_rx, closed_ms;
    char why[160];
    int sclose_total, sclose_before_closed;
    struct cst st[CMAXST];
    int nst;
    unsigned udp_n;
    uint32_t udp_sess;
    char udp_addr[64];
    size_t udp_len;
    int udp_ok;
};

struct pair {
    struct cl c;
    struct hy2peer p;
    int ep, p_in_ep;
};

static struct cst *cst_get(struct cl *c, int64_t sid) {
    for (int i = 0; i < c->nst; i++)
        if (c->st[i].sid == sid) return &c->st[i];
    if (c->nst == CMAXST) return NULL;
    struct cst *s = &c->st[c->nst++];
    memset(s, 0, sizeof *s);
    s->sid = sid;
    return s;
}

static void c_ready(void *u, uint64_t rx, int udp) {
    struct cl *c = u;
    c->cbs++;
    c->ready++;
    c->peer_rx = rx;
    c->udp = udp;
}

static void c_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    ((struct cl *)u)->cbs++;
    struct cst *s = cst_get(u, sid);
    if (!s) return;
    s->data_calls++;
    for (size_t i = 0; i < n; i++)
        if (d[i] != pat(s->got + i)) s->bad++;
    s->got += n;
    if (fin) s->fin = 1;
}

static void c_writable(void *u, int64_t sid) {
    ((struct cl *)u)->cbs++;
    struct cst *s = cst_get(u, sid);
    if (s) s->writable++;
}

static void c_streams_open(void *u) {
    struct cl *c = u;
    c->cbs++;
    c->streams_open++;
}

static void c_refused(void *u, int64_t sid, const char *msg) {
    ((struct cl *)u)->cbs++;
    struct cst *s = cst_get(u, sid);
    if (!s) return;
    s->refused++;
    snprintf(s->msg, sizeof s->msg, "%s", msg ? msg : "");
}

static void c_sclose(void *u, int64_t sid, int how) {
    struct cl *c = u;
    c->cbs++;
    c->sclose_total++;
    struct cst *s = cst_get(c, sid);
    if (!s) return;
    s->closed++;
    s->how = how;
    s->fin_at_close = s->fin;
    s->got_at_close = s->got;
    if (how == HY2C_END_CLEAN && s->got > s->consumed) {
        hy2c_conn_consumed(c->c, s->got - s->consumed);
        s->conn_ret += s->got - s->consumed;
        s->consumed = s->got;
    }
}

static void c_udp(void *u, uint32_t session, const char *addr, size_t addr_n, const uint8_t *d, size_t n) {
    struct cl *c = u;
    c->cbs++;
    c->udp_n++;
    c->udp_sess = session;
    size_t k = addr_n < sizeof c->udp_addr - 1 ? addr_n : sizeof c->udp_addr - 1;
    memcpy(c->udp_addr, addr, k);
    c->udp_addr[k] = 0;
    c->udp_len = n;
    c->udp_ok = n <= 2 * MIB && memcmp(d, g_pat, n) == 0;
}

static void c_closed(void *u, int reason, const char *why) {
    struct cl *c = u;
    c->cbs++;
    c->closed++;
    c->reason = reason;
    c->closed_ms = ms_now();
    c->sclose_before_closed = c->sclose_total;
    snprintf(c->why, sizeof c->why, "%s", why ? why : "");
}

static const struct hy2c_ops g_cops = {
    .on_ready = c_ready,
    .on_stream_data = c_data,
    .on_stream_writable = c_writable,
    .on_streams_open = c_streams_open,
    .on_stream_refused = c_refused,
    .on_stream_close = c_sclose,
    .on_udp = c_udp,
    .on_closed = c_closed,
};

static void credit_hook(void *u, int64_t sid, uint64_t delivered, uint64_t returned) {
    struct cst *s = cst_get(u, sid);
    if (!s) return;
    s->hooked++;
    s->t_in = delivered;
    s->t_ret = returned;
}

static unsigned g_slots_cap = 1000;
unsigned __real_qc_datagram_slots(const struct qc *q);
unsigned __wrap_qc_datagram_slots(const struct qc *q) {
    unsigned n = __real_qc_datagram_slots(q);
    return n < g_slots_cap ? n : g_slots_cap;
}

static void cli_cfg(struct hy2c_cfg *cc) {
    memset(cc, 0, sizeof *cc);
    cc->qc.host = "127.0.0.1";
    cc->qc.sni = "node.test";
    cc->qc.ca_pem = (const uint8_t *)g_ca_pem;
    cc->qc.ca_pem_n = strlen(g_ca_pem);
    cc->qc.no_batch = g_nb;
    cc->auth = "secret";
}

static void srv_cfg(struct qc_srv_cfg *sc) {
    memset(sc, 0, sizeof *sc);
    sc->bind_host = "127.0.0.1";
    sc->alpn = "h3";
    sc->cert_der = g_leaf;
    sc->cert_n = g_leaf_n;
    sc->key_der = g_key;
    sc->key_n = g_key_n;
    sc->no_batch = g_nb;
    sc->datagram_max = 1200;
}

static uint16_t g_hop_dead;

static uint32_t rand_one(void) { return 1; }

static int pair_start(struct pair *x, struct hy2c_cfg *cc, struct qc_srv_cfg *sc) {
    x->ep = epoll_create1(0);
    if (hp_listen(&x->p, sc) != 0) return -1;
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &x->p };
    if (epoll_ctl(x->ep, EPOLL_CTL_ADD, qc_fd(x->p.q), &ev) == 0) x->p_in_ep = 1;
    cc->qc.port = qc_local_port(x->p.q);
    if (g_hop_dead) {
        cc->qc.hop_mode = QC_HOP_REMOTE;
        cc->qc.hop_min_s = cc->qc.hop_max_s = 3600;
        cc->qc.hop_n = 2;
        cc->qc.hop_ports[0].lo = cc->qc.hop_ports[0].hi = cc->qc.port;
        cc->qc.hop_ports[1].lo = cc->qc.hop_ports[1].hi = g_hop_dead;
        cc->qc.rand32 = rand_one;
    }
    if (hy2c_open(cc, &g_cops, &x->c, &x->c.c) != 0) return -2;
    struct epoll_event ev2 = { .events = EPOLLIN, .data.ptr = &x->c };
    if (epoll_ctl(x->ep, EPOLL_CTL_ADD, hy2c_fd(x->c.c), &ev2) == 0) x->c.in_ep = 1;
    return 0;
}

static void pair_init(struct pair *x, struct hy2c_cfg *cc, struct qc_srv_cfg *sc) {
    memset(x, 0, sizeof *x);
    hp_init(&x->p, g_pat);
    cli_cfg(cc);
    srv_cfg(sc);
}

static void peer_drop(struct pair *x) {
    if (x->p_in_ep) epoll_ctl(x->ep, EPOLL_CTL_DEL, qc_fd(x->p.q), NULL);
    x->p_in_ep = 0;
    hp_free(&x->p);
}

static void pair_free(struct pair *x) {
    hy2c_free(x->c.c);
    x->c.c = NULL;
    hp_free(&x->p);
    close(x->ep);
}

static void client_work(struct cl *c) {
    if (c->consume)
        for (int i = 0; i < c->nst; i++) {
            struct cst *s = &c->st[i];
            if (s->got > s->consumed) {
                hy2c_tcp_consumed(c->c, s->sid, s->got - s->consumed);
                s->consumed = s->got;
            }
        }
    for (int i = 0; i < c->nst; i++) {
        struct cst *s = &c->st[i];
        if (s->sent >= s->to_send || (s->short_hit && s->writable == s->wseen)) continue;
        ssize_t w = hy2c_tcp_send(c->c, s->sid, g_pat + s->sent, s->to_send - s->sent);
        if (w > 0) s->sent += (size_t)w;
        if (s->sent < s->to_send) {
            s->short_hit = 1;
            s->wseen = s->writable;
        }
    }
}

static void pass(struct pair *x) {
    int t = 50;
    if (x->c.c && !x->c.closed) {
        int k = hy2c_timeout_ms(x->c.c);
        if (k >= 0 && k < t) t = k;
    }
    if (x->p.q && !x->p.closed) {
        int k = qc_timeout_ms(x->p.q);
        if (k >= 0 && k < t) t = k;
    }
    struct epoll_event ev[2];
    int n = epoll_wait(x->ep, ev, 2, t);
    for (int i = 0; i < n; i++) {
        if (ev[i].data.ptr == &x->c) {
            if (!x->c.closed) (void)hy2c_on_readable(x->c.c);
        } else if (x->p.q && !x->p.closed) {
            (void)qc_on_readable(x->p.q);
        }
    }
    if (x->c.c) {
        if (!x->c.closed && hy2c_timeout_ms(x->c.c) == 0) (void)hy2c_on_timer(x->c.c);
        if (x->c.closed && x->c.in_ep) {
            epoll_ctl(x->ep, EPOLL_CTL_DEL, hy2c_fd(x->c.c), NULL);
            x->c.in_ep = 0;
        }
        if (!x->c.closed) client_work(&x->c);
        hy2c_flush(x->c.c);
    }
    if (x->p.q) {
        if (!x->p.closed && qc_timeout_ms(x->p.q) == 0) (void)qc_on_timer(x->p.q);
        if (x->p.closed && x->p_in_ep) {
            epoll_ctl(x->ep, EPOLL_CTL_DEL, qc_fd(x->p.q), NULL);
            x->p_in_ep = 0;
        }
        hp_drain(&x->p);
        qc_flush(x->p.q);
    }
}

#define PUMP_UNTIL(x, cond) ({ uint64_t e_ = ms_now() + 10000ull * g_tx; while (!(cond) && ms_now() < e_) pass(x); (cond) ? 1 : 0; })

static void pump_for(struct pair *x, unsigned ms) {
    uint64_t e = ms_now() + (uint64_t)ms * g_tx;
    while (ms_now() < e) pass(x);
}

static int open_tcp(struct pair *x, int64_t *sid) {
    int rc = QC_EAGAIN;
    uint64_t e = ms_now() + 10000ull * g_tx;
    while ((rc = hy2c_tcp_open(x->c.c, "example.com", 443, sid)) == QC_EAGAIN && ms_now() < e) pass(x);
    if (rc == 0) cst_get(&x->c, *sid);
    return rc;
}

static void nm(char *buf, size_t cap, const char *what) {
    snprintf(buf, cap, "%s%s", what, g_nb ? " [no_batch]" : "");
}

static int alnum(const char *s) {
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9'))) return 0;
    return 1;
}

static void auth_is_xrays_request(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    char b[128];
    pair_init(&x, &cc, &sc);
    nm(b, sizeof b, "auth: pair opens");
    check(b, 0, pair_start(&x, &cc, &sc));
    check("auth: on_ready", 1, PUMP_UNTIL(&x, x.c.ready));
    check("auth: peer rx from the response", 13107200, (long)x.c.peer_rx);
    check("auth: hy2c_ready", 1, hy2c_ready(x.c.c));
    check("auth: udp 1 with datagrams and hysteria-udp true", 1, x.c.udp);
    pump_for(&x, 300);
    static const char *const want[10][2] = {
        { ":authority", "hysteria" }, { ":method", "POST" }, { ":path", "/auth" }, { ":scheme", "https" },
        { "hysteria-auth", "secret" }, { "hysteria-cc-rx", "0" }, { "hysteria-padding", NULL },
        { "content-length", "0" }, { "accept-encoding", "gzip" }, { "user-agent", "quic-go HTTP/3" },
    };
    check("auth: ten header fields", 10, x.p.nhdr);
    for (int i = 0; i < 10 && i < x.p.nhdr; i++) {
        snprintf(b, sizeof b, "auth: field %d name", i);
        check_str(b, want[i][0], x.p.hdr[i].name);
        if (!want[i][1]) continue;
        snprintf(b, sizeof b, "auth: field %d value", i);
        check_str(b, want[i][1], x.p.hdr[i].value);
    }
    size_t pl = x.p.nhdr > 6 ? strlen(x.p.hdr[6].value) : 0;
    check("auth: padding 256..2047", 1, pl >= 256 && pl <= 2047);
    check("auth: padding alphanumeric", 1, x.p.nhdr > 6 && alnum(x.p.hdr[6].value));
    check("auth: one client uni stream", 1, x.p.ctl_streams);
    check("auth: control stream bytes", 8, (long)x.p.ctl_n);
    check_hex("auth: control stream starts 00 04 05 06 80 a0 00 00", "0004050680a00000", x.p.ctl, 8);
    check("auth: control stream not finished", 0, x.p.ctl_fin);
    check("auth: auth stream finished", 1, x.p.auth_fin);
    pair_free(&x);
}

static void the_controller_is_chosen_as_xray_chooses(void) {
    static const struct { int cc; uint64_t up; const char *rx; int nlc; int want; uint64_t tx; } t[] = {
        { HY2_CC_AUTO, 13107200, "6553600", 1, QC_CC_BRUTAL, 6553600 },
        { HY2_CC_AUTO, 6553600, "13107200", 0, QC_CC_BRUTAL, 6553600 },
        { HY2_CC_AUTO, 0, "6553600", 1, QC_CC_BBR, 0 },
        { HY2_CC_AUTO, 13107200, "0", 0, QC_CC_BBR, 0 },
        { HY2_CC_AUTO, 13107200, "auto", 0, QC_CC_BBR, 0 },
        { HY2_CC_AUTO, 13107200, NULL, 0, QC_CC_BBR, 0 },
        { HY2_CC_AUTO, 13107200, "", 0, QC_CC_BBR, 0 },
        { HY2_CC_AUTO, 13107200, " 5", 0, QC_CC_BBR, 0 },
        { HY2_CC_AUTO, 13107200, "+5", 0, QC_CC_BBR, 0 },
        { HY2_CC_AUTO, 13107200, "18446744073709551616", 0, QC_CC_BRUTAL, 13107200 },
        { HY2_CC_AUTO, 13107200, "99999999999999999999x", 0, QC_CC_BRUTAL, 13107200 },
        { HY2_CC_AUTO, 13107200, "18446744073709551615", 0, QC_CC_BRUTAL, 13107200 },
        { HY2_CC_BBR, 13107200, "6553600", 0, QC_CC_BBR, 0 },
        { HY2_CC_FORCE, 13107200, "0", 0, QC_CC_BRUTAL, 13107200 },
        { HY2_CC_FORCE, 13107200, "6553600", 1, QC_CC_BRUTAL, 13107200 },
        { HY2_CC_RENO, 13107200, "6553600", 0, QC_CC_RENO, 0 },
        { HY2_CC_FORCE, 274877906944ull, "0", 0, QC_CC_BRUTAL, 137438953472 },
    };
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    char b[160];
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        pair_init(&x, &cc, &sc);
        cc.cc = t[i].cc;
        cc.up_bps = t[i].up;
        cc.no_loss_comp = t[i].nlc;
        if (t[i].cc == HY2_CC_RENO) cc.qc.cc = QC_CC_RENO;
        x.p.auth_mode = HP_AUTH_RX;
        x.p.rx_answer = t[i].rx;
        snprintf(b, sizeof b, "cc %zu: ready", i);
        check(b, 1, pair_start(&x, &cc, &sc) == 0 && PUMP_UNTIL(&x, x.c.ready));
        uint64_t tx = 1;
        int got = x.c.c ? hy2c_cc(x.c.c, &tx) : -1;
        struct qc_stats st;
        memset(&st, 0, sizeof st);
        if (x.c.c) hy2c_stats(x.c.c, &st);
        snprintf(b, sizeof b, "cc %zu: the controller", i);
        check(b, t[i].want, got);
        snprintf(b, sizeof b, "cc %zu: the QUIC layer runs it", i);
        check(b, t[i].want, st.cc);
        snprintf(b, sizeof b, "cc %zu: the Brutal rate", i);
        check(b, 1, tx == t[i].tx);
        snprintf(b, sizeof b, "cc %zu: loss compensation as asked", i);
        check(b, t[i].want == QC_CC_BRUTAL && t[i].nlc, st.no_loss_comp);
        pair_free(&x);
    }
}

static void a_wrong_password_reports_the_status_and_closes_with_0x101(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    cc.auth = "wrong";
    check("wrong password: pair opens", 0, pair_start(&x, &cc, &sc));
    check("wrong password: on_closed", 1, PUMP_UNTIL(&x, x.c.closed));
    check("wrong password: reason HY2C_CLOSE_AUTH", HY2C_CLOSE_AUTH, x.c.reason);
    check_str("wrong password: why", "auth failed code 404", x.c.why);
    check("wrong password: peer closed", 1, PUMP_UNTIL(&x, x.p.closed));
    check("wrong password: peer sees an application close", 1, x.p.app);
    check("wrong password: peer sees 0x101", 0x101, (long)x.p.code);
    check("wrong password: on_ready never", 0, x.c.ready);
    check("wrong password: on_closed once", 1, x.c.closed);
    pair_free(&x);

    pair_init(&x, &cc, &sc);
    check("close: pair opens", 0, pair_start(&x, &cc, &sc));
    check("close: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    hy2c_close(x.c.c);
    check("close: peer closed", 1, PUMP_UNTIL(&x, x.p.closed));
    check("close: peer sees an application close", 1, x.p.app);
    check("close: peer sees 0x100", 0x100, (long)x.p.code);
    check("close: client on_closed", 1, PUMP_UNTIL(&x, x.c.closed));
    check("close: reason local", QC_CLOSE_LOCAL, x.c.reason);
    pump_for(&x, 300);
    check("close: on_closed once", 1, x.c.closed);
    pair_free(&x);
}

static void broken_round(int mode, unsigned hs_ms, const char *why) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    char b[128];
    pair_init(&x, &cc, &sc);
    x.p.auth_mode = mode;
    cc.qc.handshake_ms = hs_ms;
    snprintf(b, sizeof b, "%s: pair opens", why);
    check(b, 0, pair_start(&x, &cc, &sc));
    snprintf(b, sizeof b, "%s: on_closed", why);
    check(b, 1, PUMP_UNTIL(&x, x.c.closed));
    snprintf(b, sizeof b, "%s: reason HY2C_CLOSE_AUTH", why);
    check(b, HY2C_CLOSE_AUTH, x.c.reason);
    snprintf(b, sizeof b, "%s: why", why);
    check_str(b, why, x.c.why);
    snprintf(b, sizeof b, "%s: peer sees 0x101", why);
    check(b, 1, PUMP_UNTIL(&x, x.p.closed) && x.p.app == 1 && x.p.code == 0x101);
    snprintf(b, sizeof b, "%s: on_ready never", why);
    check(b, 0, x.c.ready);
    if (mode == HP_AUTH_SILENT) {
        long dt = (long)(x.c.closed_ms - x.p.hs_ms);
        snprintf(b, sizeof b, "%s: 400..3000 ms after the handshake (%ld)", why, dt);
        check(b, 1, x.p.hs && dt >= 400 && (uint64_t)dt <= 3000ull * g_tx);
    }
    pair_free(&x);
}

static void a_broken_auth_exchange_closes_with_0x101(void) {
    broken_round(HP_AUTH_FIN, 0, "auth stream ended");
    broken_round(HP_AUTH_JUNK, 0, "auth response malformed");
    broken_round(HP_AUTH_SILENT, 500, "auth timed out");
}

static void early_payload_round(const char *tag, const char *cpass, const char *ppass);

static void payload_does_not_wait_for_the_response(void) {
    early_payload_round("early payload", NULL, NULL);
}

struct sal { struct hy2_salamander s; };

static size_t sal_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    uint8_t salt[8];
    if (os_rand_seed(salt, sizeof salt) != 0) return 0;
    return hy2_salamander_wrap(&((struct sal *)u)->s, salt, dst, src, n);
}

static uint8_t g_salts[50][8];
static unsigned g_salt_n;

static size_t sal_rx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    if (n >= 8 && g_salt_n < 50) memcpy(g_salts[g_salt_n++], src, 8);
    return hy2_salamander_unwrap(&((struct sal *)u)->s, dst, src, n);
}

static void early_payload_round(const char *tag, const char *cpass, const char *ppass) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    struct sal ps;
    struct qc_filter pf = { sal_tx, sal_rx, &ps, 8 };
    char b[128];
    pair_init(&x, &cc, &sc);
    if (ppass) {
        hy2_salamander_init(&ps.s, ppass);
        sc.filter = &pf;
    }
    cc.obfs_password = cpass;
    x.p.answer_after = 102400;
    snprintf(b, sizeof b, "%s: pair opens", tag);
    check(b, 0, pair_start(&x, &cc, &sc));
    snprintf(b, sizeof b, "%s: ready", tag);
    check(b, 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid = -1;
    snprintf(b, sizeof b, "%s: stream opens", tag);
    check(b, 0, open_tcp(&x, &sid));
    snprintf(b, sizeof b, "%s: 102400 bytes taken at once", tag);
    check(b, 102400, (long)hy2c_tcp_send(x.c.c, sid, g_pat, 102400));
    struct cst *s = cst_get(&x.c, sid);
    x.c.consume = 1;
    snprintf(b, sizeof b, "%s: echo arrives", tag);
    check(b, 1, PUMP_UNTIL(&x, s->got >= 102400));
    snprintf(b, sizeof b, "%s: echo length", tag);
    check(b, 102400, (long)s->got);
    snprintf(b, sizeof b, "%s: echo intact", tag);
    check(b, 0, (long)s->bad);
    struct hp_st *ps2 = hp_st(&x.p, sid);
    snprintf(b, sizeof b, "%s: peer saw the address", tag);
    check_str(b, "example.com:443", ps2 ? ps2->addr : "");
    pair_free(&x);
}

static void a_refused_stream_surfaces_the_message(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    x.p.refuse = 1;
    check("refused: pair opens", 0, pair_start(&x, &cc, &sc));
    check("refused: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid = -1;
    check("refused: stream opens", 0, open_tcp(&x, &sid));
    (void)hy2c_tcp_send(x.c.c, sid, g_pat, 1000);
    struct cst *s = cst_get(&x.c, sid);
    check("refused: on_stream_refused", 1, PUMP_UNTIL(&x, s->refused));
    check_str("refused: message", "connection refused", s->msg);
    pump_for(&x, 300);
    check("refused: no on_stream_data", 0, (long)s->data_calls);
    check("refused: refused once", 1, s->refused);
    check("refused: no on_stream_close after it", 0, s->closed);
    check("refused: connection alive", 0, x.c.closed);
    pair_free(&x);
}

static void closing_and_finishing_a_stream_reach_the_peer(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("finish: pair opens", 0, pair_start(&x, &cc, &sc));
    check("finish: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    x.c.consume = 1;
    int64_t sid = -1;
    check("finish: stream opens", 0, open_tcp(&x, &sid));
    check("finish: 100 KiB taken", 102400, (long)hy2c_tcp_send(x.c.c, sid, g_pat, 102400));
    check("finish: hy2c_tcp_finish", 0, hy2c_tcp_finish(x.c.c, sid));
    struct hp_st *ps = hp_st(&x.p, sid);
    check("finish: peer gets all with fin", 1, PUMP_UNTIL(&x, ps->payload == 102400 && ps->fin));
    struct cst *s = cst_get(&x.c, sid);
    check("finish: client reads the echo", 1, PUMP_UNTIL(&x, s->got >= 102400));
    check("finish: echo intact", 1, s->got == 102400 && s->bad == 0);
    check("finish: no fin from the peer", 0, s->fin);

    int64_t sid2 = -1;
    check("close idle: stream opens", 0, open_tcp(&x, &sid2));
    struct hp_st *ps2 = hp_st(&x.p, sid2);
    check("close idle: peer answered", 1, PUMP_UNTIL(&x, ps2->responded));
    pump_for(&x, 300);
    hy2c_tcp_close(x.c.c, sid2);
    check("close idle: peer stream closed", 1, PUMP_UNTIL(&x, ps2->closed));
    check("close idle: tx_stopped 1", 1, ps2->tx_stopped);
    check("close idle: tx_err 0", 0, (long)ps2->tx_err);
    check("close idle: rx_reset 0", 0, ps2->rx_reset);
    pump_for(&x, 300);
    check("close idle: no on_stream_close for our own close", 0, cst_get(&x.c, sid2)->closed);
    pair_free(&x);

    pair_init(&x, &cc, &sc);
    cc.qc.send_buf = 2 * MIB;
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("close queued: pair opens", 0, pair_start(&x, &cc, &sc));
    check("close queued: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid3 = -1;
    check("close queued: stream opens", 0, open_tcp(&x, &sid3));
    check("close queued: 1 MiB taken", MIB, (long)hy2c_tcp_send(x.c.c, sid3, g_pat, MIB));
    pump_for(&x, 300);
    struct hp_st *ps3 = hp_st(&x.p, sid3);
    check("close queued: peer stalled short of 1 MiB", 1, ps3->payload < MIB / 2);
    hy2c_tcp_close(x.c.c, sid3);
    check("close queued: peer stream closed", 1, PUMP_UNTIL(&x, ps3->closed));
    check("close queued: rx_reset 1", 1, ps3->rx_reset);
    check("close queued: rx_err 0", 0, (long)ps3->rx_err);
    check("close queued: tx_stopped 1", 1, ps3->tx_stopped);
    pair_free(&x);
}

static void a_slow_consumer_holds_at_most_the_stream_window(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    cc.qc.max_stream_data = 65536;
    x.p.echo = 0;
    x.p.send_bytes = MIB;
    check("window: pair opens", 0, pair_start(&x, &cc, &sc));
    check("window: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid = -1;
    check("window: stream opens", 0, open_tcp(&x, &sid));
    struct cst *s = cst_get(&x.c, sid);
    check("window: 65404 bytes delivered", 1, PUMP_UNTIL(&x, s->got >= 65404));
    pump_for(&x, 300);
    check("window: and stays", 65404, (long)s->got);
    x.c.consume = 1;
    check("window: consuming delivers 1 MiB", 1, PUMP_UNTIL(&x, s->got >= MIB));
    check("window: exactly 1 MiB", MIB, (long)s->got);
    check("window: intact", 0, (long)s->bad);
    pair_free(&x);
}

static void unconsumed_bytes_of_closed_streams_do_not_starve_the_connection(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    cc.qc.max_data = MIB;
    cc.qc.max_stream_data = 262144;
    x.p.echo = 0;
    x.p.send_bytes = 65536;
    x.p.ctl_extra = 524288;
    check("dead credit: pair opens", 0, pair_start(&x, &cc, &sc));
    check("dead credit: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int ok = 0;
    for (int i = 0; i < 40; i++) {
        int64_t sid = -1;
        if (open_tcp(&x, &sid) != 0) break;
        struct cst *s = cst_get(&x.c, sid);
        if (!PUMP_UNTIL(&x, s->got >= 65536)) break;
        hy2c_tcp_close(x.c.c, sid);
        ok++;
    }
    check("dead credit: forty streams of 64 KiB", 40, ok);
    check("dead credit: peer control stream acknowledged", 1,
          PUMP_UNTIL(&x, x.p.own.off == x.p.own.n && qc_stream_room(x.p.q, x.p.own_ctl) == 2097152));
    x.p.send_bytes = MIB;
    x.c.consume = 1;
    int64_t sid = -1;
    check("dead credit: 41st opens", 0, open_tcp(&x, &sid));
    struct cst *s = cst_get(&x.c, sid);
    check("dead credit: 41st receives 1 MiB", 1, PUMP_UNTIL(&x, s->got >= MIB));
    check("dead credit: intact", 1, s->got == MIB && s->bad == 0);
    check("dead credit: connection alive", 0, x.c.closed);
    pair_free(&x);
}

static void udp_echoes_whole_and_fragmented(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    cc.udp_sessions = 2;
    x.p.dg_echo = 1;
    check("udp: pair opens", 0, pair_start(&x, &cc, &sc));
    check("udp: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    uint32_t s1 = hy2c_udp_session(x.c.c);
    check("udp: first session 1", 1, (long)s1);
    check("udp: 100 bytes sent", 0, hy2c_udp_send(x.c.c, s1, "1.2.3.4", 53, g_pat, 100));
    check("udp: echo of 100", 1, PUMP_UNTIL(&x, x.c.udp_n >= 1));
    check("udp: session 1", 1, (long)x.c.udp_sess);
    check_str("udp: address", "1.2.3.4:53", x.c.udp_addr);
    check("udp: 100 bytes back", 100, (long)x.c.udp_len);
    check("udp: intact", 1, x.c.udp_ok);
    check("udp: 3000 bytes sent", 0, hy2c_udp_send(x.c.c, s1, "1.2.3.4", 53, g_pat, 3000));
    check("udp: echo of 3000", 1, PUMP_UNTIL(&x, x.c.udp_n >= 2));
    check("udp: peer got four datagrams", 4, (long)x.p.dg_n);
    int same = 1, frags = 0;
    for (int i = 1; i < 4; i++) {
        same &= x.p.dg[i].pkt == x.p.dg[1].pkt && x.p.dg[i].count == 3 && x.p.dg[i].sid == 1;
        frags |= 1 << x.p.dg[i].frag;
    }
    check("udp: one packet id, count 3, session 1", 1, same);
    check("udp: fragments 0, 1, 2", 7, frags);
    check("udp: packet id 1..65535", 1, x.p.dg[1].pkt >= 1);
    check("udp: whole message unfragmented", 1, x.p.dg[0].pkt == 0 && x.p.dg[0].count == 1 && x.p.dg[0].frag == 0);
    check("udp: 3000 back whole", 3000, (long)x.c.udp_len);
    check("udp: 3000 intact", 1, x.c.udp_ok);
    uint32_t s2 = hy2c_udp_session(x.c.c);
    check("udp: second session 2", 2, (long)s2);
    check("udp: second session sends", 0, hy2c_udp_send(x.c.c, s2, "1.2.3.4", 53, g_pat, 10));
    check("udp: peer sees session 2", 1, PUMP_UNTIL(&x, x.p.dg_n >= 5) && x.p.dg[4].sid == 2);
    check("udp: third over the limit is 0", 0, (long)hy2c_udp_session(x.c.c));
    hy2c_udp_end(x.c.c, s1);
    check("udp: after an end the next is 3", 3, (long)hy2c_udp_session(x.c.c));
    check("udp: an ended session cannot send", 1, hy2c_udp_send(x.c.c, s1, "1.2.3.4", 53, g_pat, 10) < 0);
    pair_free(&x);
}

static void a_datagram_for_an_unknown_session_is_dropped(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("unknown session: pair opens", 0, pair_start(&x, &cc, &sc));
    check("unknown session: ready", 1, PUMP_UNTIL(&x, x.c.ready && x.p.hs));
    check("unknown session: client holds session 1", 1, (long)hy2c_udp_session(x.c.c));
    uint8_t d[64];
    size_t k = hy2_udp_header(d, sizeof d, 99, 0, 0, 1, "9.9.9.9", 53);
    memcpy(d + k, g_pat, 10);
    check("unknown session: peer sends session 99", 0, qc_datagram_send(x.p.q, d, k + 10));
    k = hy2_udp_header(d, sizeof d, 1, 0, 0, 1, "9.9.9.9", 53);
    memcpy(d + k, g_pat, 10);
    check("unknown session: peer sends session 1", 0, qc_datagram_send(x.p.q, d, k + 10));
    check("unknown session: session 1 arrives", 1, PUMP_UNTIL(&x, x.c.udp_n >= 1));
    pump_for(&x, 300);
    check("unknown session: only one on_udp", 1, (long)x.c.udp_n);
    check("unknown session: it is session 1", 1, (long)x.c.udp_sess);
    pair_free(&x);
}

static void salamander_on_both_sides_works_and_a_mismatch_fails_the_handshake(void) {
    g_salt_n = 0;
    early_payload_round("salamander", "obfs-pass", "obfs-pass");
    int distinct = g_salt_n == 50;
    for (unsigned i = 0; i < g_salt_n; i++)
        for (unsigned j = i + 1; j < g_salt_n; j++)
            if (!memcmp(g_salts[i], g_salts[j], 8)) distinct = 0;
    check("salamander: 50 datagrams carry 50 distinct salts", 1, distinct);
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    struct sal ps;
    struct qc_filter pf = { sal_tx, sal_rx, &ps, 8 };
    pair_init(&x, &cc, &sc);
    hy2_salamander_init(&ps.s, "other-pass");
    sc.filter = &pf;
    cc.obfs_password = "obfs-pass";
    cc.qc.handshake_ms = 500;
    check("salamander mismatch: pair opens", 0, pair_start(&x, &cc, &sc));
    check("salamander mismatch: on_closed", 1, PUMP_UNTIL(&x, x.c.closed));
    check("salamander mismatch: handshake reason", QC_CLOSE_HANDSHAKE, x.c.reason);
    check("salamander mismatch: never ready", 0, x.c.ready);
    check("salamander mismatch: peer never shook hands", 0, x.p.hs);
    pair_free(&x);
}

static void a_dead_connection_ends_every_stream_first(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    cc.qc.idle_ms = 1000;
    check("dead: pair opens", 0, pair_start(&x, &cc, &sc));
    check("dead: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t a = -1, b = -1;
    check("dead: first stream", 0, open_tcp(&x, &a));
    check("dead: second stream", 0, open_tcp(&x, &b));
    check("dead: both answered", 1, PUMP_UNTIL(&x, hp_st(&x.p, a)->responded && hp_st(&x.p, b)->responded));
    pump_for(&x, 100);
    peer_drop(&x);
    check("dead: on_closed", 1, PUMP_UNTIL(&x, x.c.closed));
    check("dead: two stream closes", 2, x.c.sclose_total);
    check("dead: both before on_closed", 2, x.c.sclose_before_closed);
    check("dead: first ended with the link", HY2C_END_LINK, cst_get(&x.c, a)->how);
    check("dead: second ended with the link", HY2C_END_LINK, cst_get(&x.c, b)->how);
    pump_for(&x, 300);
    check("dead: on_closed once", 1, x.c.closed);
    check("dead: no further stream closes", 2, x.c.sclose_total);
    check("dead: a send on a dead connection", QC_ECLOSED, (long)hy2c_tcp_send(x.c.c, a, g_pat, 10));
    check("dead: a finish on a dead connection", QC_ECLOSED, hy2c_tcp_finish(x.c.c, a));
    pair_free(&x);
}

static void room_is_announced_to_the_consumer(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    cc.qc.send_buf = 65536;
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("room: pair opens", 0, pair_start(&x, &cc, &sc));
    check("room: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid = -1;
    check("room: stream opens", 0, open_tcp(&x, &sid));
    struct cst *s = cst_get(&x.c, sid);
    ssize_t w = hy2c_tcp_send(x.c.c, sid, g_pat, 262144);
    check("room: send returns short", 1, w > 0 && w < 262144);
    s->to_send = 262144;
    s->sent = w > 0 ? (size_t)w : 0;
    s->short_hit = 1;
    s->wseen = s->writable;
    pump_for(&x, 500);
    struct hp_st *ps = hp_st(&x.p, sid);
    check("room: stalled while the peer does not read", 1, ps->payload < 262144 && s->sent < 262144);
    unsigned w0 = s->writable;
    x.p.no_consume = 0;
    hp_consume_all(&x.p);
    check("room: the rest goes out", 1, PUMP_UNTIL(&x, ps->payload >= 262144));
    check("room: on_stream_writable fired after the peer read", 1, s->writable > w0);
    check("room: all sent", 262144, (long)s->sent);
    check("room: peer got exactly all", 262144, (long)ps->payload);
    pair_free(&x);
}

static int credit_ok(struct cst *s) { return s->hooked == 1 && s->t_in > 0 && s->t_in == s->t_ret + s->conn_ret; }

static void close_reasons_reach_the_consumer(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("reasons: pair opens", 0, pair_start(&x, &cc, &sc));
    check("reasons: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    x.c.consume = 1;

    int64_t a = -1;
    check("peer fin: stream opens", 0, open_tcp(&x, &a));
    check("peer fin: 1000 bytes", 1000, (long)hy2c_tcp_send(x.c.c, a, g_pat, 1000));
    struct cst *sa = cst_get(&x.c, a);
    check("peer fin: echo", 1, PUMP_UNTIL(&x, sa->got >= 1000));
    hp_st(&x.p, a)->out.fin = 1;
    check("peer fin: client sees fin", 1, PUMP_UNTIL(&x, sa->fin));
    check("peer fin: client finishes", 0, hy2c_tcp_finish(x.c.c, a));
    check("peer fin: on_stream_close", 1, PUMP_UNTIL(&x, sa->closed));
    pump_for(&x, 300);
    check("peer fin: exactly once", 1, sa->closed);
    check("peer fin: ended clean", HY2C_END_CLEAN, sa->how);
    check("peer fin: credit returned once, all of it", 1, credit_ok(sa));

    int64_t b = -1;
    check("peer reset: stream opens", 0, open_tcp(&x, &b));
    check("peer reset: 1000 bytes", 1000, (long)hy2c_tcp_send(x.c.c, b, g_pat, 1000));
    struct cst *sb = cst_get(&x.c, b);
    check("peer reset: echo", 1, PUMP_UNTIL(&x, sb->got >= 1000));
    check("peer reset: reset sent", 0, qc_stream_reset(x.p.q, b, 0));
    check("peer reset: on_stream_close", 1, PUMP_UNTIL(&x, sb->closed));
    pump_for(&x, 300);
    check("peer reset: exactly once", 1, sb->closed);
    check("peer reset: ended by a reset", HY2C_END_RESET, sb->how);
    check("peer reset: credit returned once, all of it", 1, credit_ok(sb));

    x.p.resp_bad = 1;
    x.p.send_bytes = 4096;
    int64_t m = -1;
    check("bad response: stream opens", 0, open_tcp(&x, &m));
    struct cst *sm = cst_get(&x.c, m);
    check("bad response: on_stream_close", 1, PUMP_UNTIL(&x, sm->closed));
    pump_for(&x, 300);
    check("bad response: exactly once", 1, sm->closed);
    check("bad response: ended by a reset", HY2C_END_RESET, sm->how);
    check("bad response: no on_stream_data", 0, (long)sm->data_calls);
    check("bad response: credit returned once, all of it", 1, credit_ok(sm));
    x.p.resp_bad = 0;
    x.p.send_bytes = 0;

    x.p.fin_first = 1;
    int64_t f = -1;
    check("fin first: stream opens", 0, open_tcp(&x, &f));
    struct cst *sf = cst_get(&x.c, f);
    check("fin first: on_stream_close", 1, PUMP_UNTIL(&x, sf->closed));
    pump_for(&x, 300);
    check("fin first: exactly once", 1, sf->closed);
    check("fin first: ended by a reset", HY2C_END_RESET, sf->how);
    check("fin first: no on_stream_data", 0, (long)sf->data_calls);
    check("fin first: no on_stream_refused", 0, sf->refused);
    x.p.fin_first = 0;

    x.p.answer_after = (size_t)-1;
    x.p.echo = 0;
    int64_t sp = -1;
    check("split response: stream opens", 0, open_tcp(&x, &sp));
    struct hp_st *psp = hp_st(&x.p, sp);
    check("split response: peer parsed", 1, PUMP_UNTIL(&x, psp->parsed == 1));
    uint8_t r[256];
    size_t rn = hy2_tcp_response_put(r, sizeof r, 1, "", 128);
    hp_put(&psp->out, r, 2);
    pump_for(&x, 200);
    hp_put(&psp->out, r + 2, rn - 2);
    hp_put(&psp->out, g_pat, 1000);
    struct cst *ssp = cst_get(&x.c, sp);
    check("split response: payload after it", 1, PUMP_UNTIL(&x, ssp->got >= 1000));
    check("split response: intact", 1, ssp->got == 1000 && ssp->bad == 0);
    hy2c_tcp_close(x.c.c, sp);
    check("split response: credit returned once, all of it", 1, PUMP_UNTIL(&x, ssp->hooked) && credit_ok(ssp));
    x.p.answer_after = 0;
    x.p.echo = 1;

    x.c.consume = 0;
    int64_t k = -1;
    check("clamp: stream opens", 0, open_tcp(&x, &k));
    check("clamp: 1000 bytes", 1000, (long)hy2c_tcp_send(x.c.c, k, g_pat, 1000));
    struct cst *sk = cst_get(&x.c, k);
    check("clamp: echo", 1, PUMP_UNTIL(&x, sk->got >= 1000));
    hy2c_tcp_consumed(x.c.c, k, 1000000);
    hy2c_tcp_close(x.c.c, k);
    check("clamp: returned equals delivered", 1, PUMP_UNTIL(&x, sk->hooked) && credit_ok(sk));
    check("reasons: connection alive", 0, x.c.closed);
    pair_free(&x);
}

static void closing_with_bytes_in_flight_finishes(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    x.p.echo = 0;
    check("in flight: pair opens", 0, pair_start(&x, &cc, &sc));
    check("in flight: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid = -1;
    check("in flight: stream opens", 0, open_tcp(&x, &sid));
    struct hp_st *ps = hp_st(&x.p, sid);
    check("in flight: peer answered", 1, PUMP_UNTIL(&x, ps->responded));
    pump_for(&x, 100);
    check("in flight: 8 KiB taken", 8192, (long)hy2c_tcp_send(x.c.c, sid, g_pat, 8192));
    uint64_t e = ms_now() + 10000ull * g_tx;
    while (hy2c_tcp_unsent(x.c.c, sid) > 0 && ms_now() < e) {
        if (hy2c_timeout_ms(x.c.c) == 0) (void)hy2c_on_timer(x.c.c);
        hy2c_flush(x.c.c);
        if (x.p.q) {
            (void)qc_on_readable(x.p.q);
            if (qc_timeout_ms(x.p.q) == 0) (void)qc_on_timer(x.p.q);
            qc_flush(x.p.q);
        }
    }
    check("in flight: everything handed to the wire", 0, (long)hy2c_tcp_unsent(x.c.c, sid));
    check("in flight: not all acknowledged yet", 1, hy2c_tcp_room(x.c.c, sid) < 2097152);
    hy2c_tcp_close(x.c.c, sid);
    check("in flight: peer stream closed", 1, PUMP_UNTIL(&x, ps->closed));
    check("in flight: peer got all 8 KiB", 8192, (long)ps->payload);
    check("in flight: peer got fin", 1, ps->fin);
    check("in flight: tx_stopped 1", 1, ps->tx_stopped);
    check("in flight: rx_reset 0", 0, ps->rx_reset);
    pair_free(&x);
}

static void six_hundred_streams_share_one_session(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    sc.max_streams = 700;
    check("600 streams: pair opens", 0, pair_start(&x, &cc, &sc));
    check("600 streams: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    x.c.consume = 1;
    int64_t sid[600];
    int opened = 0, sent = 0;
    for (int i = 0; i < 600; i++) {
        if (hy2c_tcp_open(x.c.c, "example.com", 443, &sid[i]) != 0) break;
        cst_get(&x.c, sid[i]);
        opened++;
        sent += hy2c_tcp_send(x.c.c, sid[i], g_pat, 4096) == 4096;
    }
    check("600 streams: all open at once", 600, opened);
    check("600 streams: 4 KiB taken on each", 600, sent);
    int done = PUMP_UNTIL(&x, ({
        int all = 1;
        for (int i = 0; i < opened && all; i++) all = cst_get(&x.c, sid[i])->got >= 4096;
        all;
    }));
    check("600 streams: every echo arrives", 1, done);
    int intact = 0;
    for (int i = 0; i < opened; i++) {
        struct cst *s = cst_get(&x.c, sid[i]);
        intact += s->got == 4096 && s->bad == 0;
    }
    check("600 streams: every echo intact", 600, intact);
    struct hy2c_probe pr;
    hy2c_probe_get(x.c.c, &pr);
    printf("     probes: %llu steps / %llu ops\n", (unsigned long long)pr.steps, (unsigned long long)pr.ops);
    check("600 streams: under 20 probe steps per operation", 1, pr.ops > 600 && pr.steps < 20 * pr.ops);
    pair_free(&x);
}

static void freed_stream_ids_are_announced(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    sc.max_streams = 2;
    check("streams open: pair opens", 0, pair_start(&x, &cc, &sc));
    check("streams open: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    pump_for(&x, 300);
    int64_t a = -1, b = -1, d = -1;
    check("streams open: first opens", 0, hy2c_tcp_open(x.c.c, "example.com", 443, &a));
    check("streams open: second opens", 0, hy2c_tcp_open(x.c.c, "example.com", 443, &b));
    check("streams open: third waits", QC_EAGAIN, hy2c_tcp_open(x.c.c, "example.com", 443, &d));
    pump_for(&x, 300);
    check("streams open: no announcement while both live", 0, x.c.streams_open);
    check("streams open: still waits", QC_EAGAIN, hy2c_tcp_open(x.c.c, "example.com", 443, &d));
    hy2c_tcp_close(x.c.c, a);
    check("streams open: on_streams_open after a close", 1, PUMP_UNTIL(&x, x.c.streams_open));
    check("streams open: next open succeeds", 0, hy2c_tcp_open(x.c.c, "example.com", 443, &d));
    pump_for(&x, 300);
    check("streams open: announced once", 1, x.c.streams_open);
    pair_free(&x);
}

static void refused_streams_return_their_tail_credit(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    cc.qc.max_data = MIB;
    x.p.refuse = 1;
    x.p.refuse_tail = 65536;
    x.p.echo = 0;
    check("refused tail: pair opens", 0, pair_start(&x, &cc, &sc));
    check("refused tail: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int refused = 0, credit = 0;
    for (int i = 0; i < 40; i++) {
        int64_t sid = -1;
        if (open_tcp(&x, &sid) != 0) break;
        struct cst *s = cst_get(&x.c, sid);
        if (!PUMP_UNTIL(&x, s->refused)) break;
        refused++;
        credit += PUMP_UNTIL(&x, s->hooked) && credit_ok(s);
    }
    check("refused tail: forty refusals", 40, refused);
    check("refused tail: each returned all it delivered", 40, credit);
    x.p.refuse = 0;
    x.p.send_bytes = MIB;
    x.c.consume = 1;
    int64_t sid = -1;
    check("refused tail: next stream opens", 0, open_tcp(&x, &sid));
    struct cst *s = cst_get(&x.c, sid);
    check("refused tail: it receives 1 MiB", 1, PUMP_UNTIL(&x, s->got >= MIB));
    check("refused tail: intact", 1, s->got == MIB && s->bad == 0);
    pair_free(&x);
}

static int spray(struct pair *x, uint32_t id, uint16_t pkt, uint8_t frag, uint8_t count, size_t n, size_t off) {
    uint8_t d[1300];
    size_t k = hy2_udp_header(d, sizeof d, id, pkt, frag, count, "9.9.9.9", 53);
    memcpy(d + k, g_pat + off, n);
    uint64_t e = ms_now() + 10000ull * g_tx;
    int rc;
    while ((rc = qc_datagram_send(x->p.q, d, k + n)) == QC_EAGAIN && ms_now() < e) pass(x);
    return rc;
}

static void reassembly_memory_is_bounded(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("reassembly: pair opens", 0, pair_start(&x, &cc, &sc));
    check("reassembly: ready", 1, PUMP_UNTIL(&x, x.c.ready && x.p.hs));
    int held = 0;
    for (int i = 0; i < 200; i++) held += hy2c_udp_session(x.c.c) == (uint32_t)(i + 1);
    check("reassembly: 200 sessions", 200, held);
    struct qc_stats st0, st;
    hy2c_stats(x.c.c, &st0);
    int sent = 0;
    for (uint32_t id = 1; id <= 200; id++) sent += spray(&x, id, (uint16_t)id, 0, 32, 100, 0) == 0;
    check("reassembly: 200 first fragments sent", 200, sent);
    check("reassembly: all arrive", 1, PUMP_UNTIL(&x, (hy2c_stats(x.c.c, &st), st.dg_rx >= st0.dg_rx + 200)));
    struct hy2c_probe pr;
    hy2c_probe_get(x.c.c, &pr);
    check("reassembly: peak never above 1048576", 1, pr.rasm_peak <= 1048576);
    check("reassembly: sixteen newest partials of 32 x 2048 held", 1048576, (long)pr.rasm_bytes);
    check("reassembly: nothing delivered", 0, (long)x.c.udp_n);
    hy2c_stats(x.c.c, &st0);
    sent = 0;
    for (uint8_t fr = 1; fr < 32; fr++) sent += spray(&x, 1, 1, fr, 32, 100, fr * 100) == 0;
    check("reassembly: the rest of session 1's evicted packet sent", 31, sent);
    check("reassembly: it arrives", 1, PUMP_UNTIL(&x, (hy2c_stats(x.c.c, &st), st.dg_rx >= st0.dg_rx + 31)));
    pump_for(&x, 300);
    check("reassembly: the evicted packet assembles nothing", 0, (long)x.c.udp_n);
    for (uint8_t fr = 0; fr < 3; fr++) spray(&x, 2, 7, fr, 3, 100, fr * 100);
    check("reassembly: a complete packet on session 2 assembles", 1, PUMP_UNTIL(&x, x.c.udp_n >= 1));
    check("reassembly: session 2", 2, (long)x.c.udp_sess);
    check("reassembly: 300 bytes intact", 1, x.c.udp_len == 300 && x.c.udp_ok);
    hy2c_probe_get(x.c.c, &pr);
    check("reassembly: still never above 1048576", 1, pr.rasm_peak <= 1048576);
    check("reassembly: budget full again after delivery", 1, pr.rasm_bytes <= 1048576 && pr.rasm_bytes > 0);
    for (uint32_t id = 1; id <= 200; id++) hy2c_udp_end(x.c.c, id);
    hy2c_probe_get(x.c.c, &pr);
    check("reassembly: ending every session frees every buffer", 0, (long)pr.rasm_bytes);
    uint32_t s201 = hy2c_udp_session(x.c.c);
    check("reassembly: session 201", 201, (long)s201);
    check("reassembly: a new partial on 201", 0, spray(&x, s201, 9, 0, 32, 100, 0));
    check("reassembly: partial held", 1, PUMP_UNTIL(&x, (hy2c_probe_get(x.c.c, &pr), pr.rasm_bytes == 65536)));
    hy2c_close(x.c.c);
    check("reassembly: closed", 1, PUMP_UNTIL(&x, x.c.closed));
    hy2c_probe_get(x.c.c, &pr);
    check("reassembly: close frees partials", 0, (long)pr.rasm_bytes);
    pair_free(&x);
}

static void peer_stop_ends_only_the_upload(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("peer stop: pair opens", 0, pair_start(&x, &cc, &sc));
    check("peer stop: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    x.c.consume = 1;

    int64_t a = -1;
    check("stop then 500 and fin: stream opens", 0, open_tcp(&x, &a));
    struct hp_st *pa = hp_st(&x.p, a);
    check("stop then 500 and fin: peer answered", 1, PUMP_UNTIL(&x, pa->responded));
    pump_for(&x, 200);
    check("stop then 500 and fin: peer stops", 0, qc_stream_stop(x.p.q, a, 0));
    hp_put(&pa->out, g_pat, 500);
    pa->out.fin = 1;
    struct cst *sa = cst_get(&x.c, a);
    check("stop then 500 and fin: on_stream_close", 1, PUMP_UNTIL(&x, sa->closed));
    pump_for(&x, 300);
    check("stop then 500 and fin: exactly 500 bytes", 500, (long)sa->got);
    check("stop then 500 and fin: intact", 0, (long)sa->bad);
    check("stop then 500 and fin: fin before the close", 1, sa->fin_at_close && sa->got_at_close == 500);
    check("stop then 500 and fin: closed once", 1, sa->closed);
    check("stop then 500 and fin: ended clean", HY2C_END_CLEAN, sa->how);
    check("stop then 500 and fin: credit balanced", 1, credit_ok(sa));
    check("stop then 500 and fin: the peer sees our reset", 1, PUMP_UNTIL(&x, pa->pa_reset == 1));
    check("stop then 500 and fin: and no stop from us", 0, pa->pa_stopped);

    int64_t b = -1;
    check("stop then 1 MiB: stream opens", 0, open_tcp(&x, &b));
    struct hp_st *pb = hp_st(&x.p, b);
    check("stop then 1 MiB: peer answered", 1, PUMP_UNTIL(&x, pb->responded));
    pump_for(&x, 200);
    check("stop then 1 MiB: peer stops", 0, qc_stream_stop(x.p.q, b, 0));
    pump_for(&x, 300);
    struct cst *sb = cst_get(&x.c, b);
    check("stop then 1 MiB: send says the upload was stopped", HY2C_ESTOPPED, (long)hy2c_tcp_send(x.c.c, b, g_pat, 10));
    check("stop then 1 MiB: finish says the upload was stopped", HY2C_ESTOPPED, hy2c_tcp_finish(x.c.c, b));
    check("stop then 1 MiB: the stop code is none of qc's", 1, HY2C_ESTOPPED < QC_ENOSTREAM || HY2C_ESTOPPED > QC_EINVAL);
    check("stop then 1 MiB: no room", 0, (long)hy2c_tcp_room(x.c.c, b));
    check("stop then 1 MiB: no event for the stop", 0, sb->closed);
    check("stop then 1 MiB: the peer sees our reset", 1, pb->pa_reset);
    hp_put(&pb->out, g_pat, MIB);
    pb->out.fin = 1;
    check("stop then 1 MiB: on_stream_close", 1, PUMP_UNTIL(&x, sb->closed));
    pump_for(&x, 300);
    check("stop then 1 MiB: all of it", MIB, (long)sb->got);
    check("stop then 1 MiB: intact", 0, (long)sb->bad);
    check("stop then 1 MiB: fin before the close", 1, sb->fin_at_close && sb->got_at_close == MIB);
    check("stop then 1 MiB: closed once, clean", 1, sb->closed == 1 && sb->how == HY2C_END_CLEAN);
    check("stop then 1 MiB: credit balanced", 1, credit_ok(sb));
    check("stop then 1 MiB: gone afterwards", QC_ENOSTREAM, (long)hy2c_tcp_send(x.c.c, b, g_pat, 10));

    static const char *const tag[3] = { "reset only", "stop then reset", "reset and stop" };
    char t[128];
    for (int m = 0; m < 3; m++) {
        int64_t sid = -1;
        snprintf(t, sizeof t, "%s: stream opens", tag[m]);
        check(t, 0, open_tcp(&x, &sid));
        hy2c_tcp_send(x.c.c, sid, g_pat, 1000);
        struct cst *s = cst_get(&x.c, sid);
        struct hp_st *ps = hp_st(&x.p, sid);
        snprintf(t, sizeof t, "%s: echo", tag[m]);
        check(t, 1, PUMP_UNTIL(&x, s->got >= 1000));
        int rc;
        if (m == 0) rc = qc_stream_reset_write(x.p.q, sid, 0);
        else if (m == 1) {
            rc = qc_stream_stop(x.p.q, sid, 0);
            pump_for(&x, 200);
            snprintf(t, sizeof t, "%s: nothing after the stop alone", tag[m]);
            check(t, 0, s->closed);
            rc |= qc_stream_reset_write(x.p.q, sid, 0);
        } else rc = qc_stream_reset(x.p.q, sid, 0);
        snprintf(t, sizeof t, "%s: peer sent it", tag[m]);
        check(t, 0, rc);
        snprintf(t, sizeof t, "%s: on_stream_close", tag[m]);
        check(t, 1, PUMP_UNTIL(&x, s->closed));
        snprintf(t, sizeof t, "%s: peer stream closed too", tag[m]);
        check(t, 1, PUMP_UNTIL(&x, ps->closed));
        pump_for(&x, 300);
        snprintf(t, sizeof t, "%s: exactly once, ended by a reset", tag[m]);
        check(t, 1, s->closed == 1 && s->how == HY2C_END_RESET);
        snprintf(t, sizeof t, "%s: credit balanced", tag[m]);
        check(t, 1, credit_ok(s));
        snprintf(t, sizeof t, "%s: gone for the consumer", tag[m]);
        check(t, QC_ENOSTREAM, (long)hy2c_tcp_send(x.c.c, sid, g_pat, 10));
        if (m == 0) {
            check("reset only: the peer sees no stop from us", 0, ps->pa_stopped);
            check("reset only: the peer sees our reset", 1, ps->pa_reset);
        }
    }

    x.p.answer_after = (size_t)-1;
    x.p.echo = 0;
    int64_t w = -1;
    check("stop before response: stream opens", 0, open_tcp(&x, &w));
    hy2c_tcp_send(x.c.c, w, g_pat, 10);
    struct hp_st *pw = hp_st(&x.p, w);
    check("stop before response: peer parsed", 1, PUMP_UNTIL(&x, pw->parsed == 1 && pw->payload == 10));
    check("stop before response: peer stops", 0, qc_stream_stop(x.p.q, w, 0));
    pump_for(&x, 300);
    struct cst *sw = cst_get(&x.c, w);
    check("stop before response: still waiting", 0, sw->closed + sw->refused + (int)sw->data_calls);
    uint8_t r[256];
    size_t rn = hy2_tcp_response_put(r, sizeof r, 1, "", 128);
    hp_put(&pw->out, r, rn);
    hp_put(&pw->out, g_pat, 100);
    pw->out.fin = 1;
    check("stop before response: on_stream_close", 1, PUMP_UNTIL(&x, sw->closed));
    check("stop before response: the response then 100 bytes", 1, sw->got == 100 && sw->bad == 0 && sw->fin_at_close);
    check("stop before response: ended clean", HY2C_END_CLEAN, sw->how);
    check("stop before response: no refusal", 0, sw->refused);

    int64_t v = -1;
    check("reset before response: stream opens", 0, open_tcp(&x, &v));
    hy2c_tcp_send(x.c.c, v, g_pat, 10);
    struct hp_st *pv = hp_st(&x.p, v);
    check("reset before response: peer parsed", 1, PUMP_UNTIL(&x, pv->parsed == 1 && pv->payload == 10));
    check("reset before response: peer resets", 0, qc_stream_reset_write(x.p.q, v, 0));
    struct cst *sv = cst_get(&x.c, v);
    check("reset before response: on_stream_close", 1, PUMP_UNTIL(&x, sv->closed));
    pump_for(&x, 300);
    check("reset before response: once, ended by a reset", 1, sv->closed == 1 && sv->how == HY2C_END_RESET);
    check("reset before response: no refusal, no data", 0, sv->refused + (int)sv->data_calls);
    check("reset before response: credit balanced", 1, sv->hooked == 1 && sv->t_in == sv->t_ret);
    check("peer stop: connection alive", 0, x.c.closed);
    pair_free(&x);
}

static int g_drop_in;

static size_t tf_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    (void)u;
    memcpy(dst, src, n);
    return n;
}

static size_t tf_rx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    (void)u;
    if (g_drop_in > 0) {
        g_drop_in--;
        return 0;
    }
    memcpy(dst, src, n);
    return n;
}

static void a_reset_over_a_gap_gets_no_stop(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    struct qc_filter tf = { tf_tx, tf_rx, NULL, 0 };
    pair_init(&x, &cc, &sc);
    cc.qc.filter = &tf;
    x.p.echo = 0;
    check("reset over a gap: pair opens", 0, pair_start(&x, &cc, &sc));
    check("reset over a gap: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    x.c.consume = 1;
    int64_t sid = -1;
    check("reset over a gap: stream opens", 0, open_tcp(&x, &sid));
    struct hp_st *ps = hp_st(&x.p, sid);
    struct cst *s = cst_get(&x.c, sid);
    check("reset over a gap: peer answered", 1, PUMP_UNTIL(&x, ps->responded));
    pump_for(&x, 200);
    g_drop_in = 1;
    check("reset over a gap: peer sends 1000 bytes", 1000, (long)qc_stream_send(x.p.q, sid, g_pat, 1000, 0));
    check("reset over a gap: peer resets", 0, qc_stream_reset_write(x.p.q, sid, 0));
    check("reset over a gap: on_stream_close", 1, PUMP_UNTIL(&x, s->closed));
    check("reset over a gap: peer stream closed", 1, PUMP_UNTIL(&x, ps->closed));
    pump_for(&x, 300);
    check("reset over a gap: once, ended by a reset", 1, s->closed == 1 && s->how == HY2C_END_RESET);
    check("reset over a gap: one packet was dropped", 0, g_drop_in);
    check("reset over a gap: the data never arrived", 0, (long)s->got);
    check("reset over a gap: the peer sees no stop from us", 0, ps->pa_stopped);
    check("reset over a gap: the peer sees our reset", 1, ps->pa_reset);
    check("reset over a gap: credit balanced", 1, s->hooked == 1 && s->t_in == s->t_ret);
    pair_free(&x);
}

#define DRAIN_D 1000000

static int fill_window(struct pair *x, int64_t *sid) {
    if (open_tcp(x, sid) != 0) return 0;
    if (hy2c_tcp_send(x->c.c, *sid, g_pat, DRAIN_D) != DRAIN_D) return 0;
    struct hp_st *ps = hp_st(&x->p, *sid);
    if (!PUMP_UNTIL(x, ps->got >= 65536)) return 0;
    pump_for(x, 50);
    return hy2c_tcp_finish(x->c.c, *sid) == 0;
}

static void draining_streams_are_bounded(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("drain budget: pair opens", 0, pair_start(&x, &cc, &sc));
    check("drain budget: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid[5];
    struct hy2c_probe pr;
    int ok = 0;
    for (int i = 0; i < 4; i++) {
        if (!fill_window(&x, &sid[i])) break;
        hy2c_tcp_close(x.c.c, sid[i]);
        ok++;
    }
    check("drain budget: four finished and closed", 4, ok);
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    check("drain budget: four draining", 4, (long)pr.drain_n);
    check("drain budget: none reset yet", 0, hp_st(&x.p, sid[0])->rx_reset + hp_st(&x.p, sid[0])->pa_reset);
    check("drain budget: fifth finished", 1, fill_window(&x, &sid[4]));
    hy2c_tcp_close(x.c.c, sid[4]);
    check("drain budget: the first is reset", 1, PUMP_UNTIL(&x, hp_st(&x.p, sid[0])->pa_reset == 1));
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    check("drain budget: four draining after it", 4, (long)pr.drain_n);
    int others = 0;
    for (int i = 1; i < 5; i++) others += hp_st(&x.p, sid[i])->pa_reset + hp_st(&x.p, sid[i])->rx_reset;
    check("drain budget: no other stream reset", 0, others);
    x.p.no_consume = 0;
    hp_consume_all(&x.p);
    int done = PUMP_UNTIL(&x, ({
        int all = 1;
        for (int i = 1; i < 5 && all; i++) {
            struct hp_st *ps = hp_st(&x.p, sid[i]);
            all = ps->payload >= DRAIN_D && ps->fin && ps->closed;
        }
        all;
    }));
    check("drain budget: the other four deliver 1000000 bytes each", 1, done);
    int good = 0;
    for (int i = 1; i < 5; i++) {
        struct hp_st *ps = hp_st(&x.p, sid[i]);
        good += ps->payload == DRAIN_D && ps->pbad == 0 && ps->rx_reset == 0;
    }
    check("drain budget: intact, with fin, not reset", 4, good);
    check("drain budget: the first ends reset", 1, PUMP_UNTIL(&x, hp_st(&x.p, sid[0])->closed) && hp_st(&x.p, sid[0])->rx_reset == 1);
    check("drain budget: list empty at the end", 1, PUMP_UNTIL(&x, (hy2c_probe_get(x.c.c, &pr), pr.drain_n == 0)));
    int events = 0;
    for (int i = 0; i < 5; i++) events += cst_get(&x.c, sid[i])->closed;
    check("drain budget: the consumer heard nothing after its closes", 0, events);
    pair_free(&x);

    pair_init(&x, &cc, &sc);
    cc.qc.idle_ms = 120000;
    sc.idle_ms = 120000;
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("drain deadline: pair opens", 0, pair_start(&x, &cc, &sc));
    check("drain deadline: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t d = -1;
    check("drain deadline: finished", 1, fill_window(&x, &d));
    const uint64_t F = 1000000000000000ull;
    hy2c_clock_set(x.c.c, F);
    hy2c_tcp_close(x.c.c, d);
    hy2c_probe_get(x.c.c, &pr);
    check("drain deadline: draining", 1, (long)pr.drain_n);
    pump_for(&x, 300);
    check("drain deadline: due 30000 ms after the close", 1, hy2c_drain_due_ns(x.c.c) == F + 30000000000ull);
    hy2c_clock_set(x.c.c, F + 29999000000ull);
    check("drain deadline: still due at 30000 ms at 29999", 1, hy2c_drain_due_ns(x.c.c) == F + 30000000000ull);
    pump_for(&x, 300);
    struct hp_st *pd = hp_st(&x.p, d);
    hy2c_probe_get(x.c.c, &pr);
    check("drain deadline: not reset at 29999 ms", 1, pd->pa_reset == 0 && pd->rx_reset == 0 && pr.drain_n == 1);
    hy2c_clock_set(x.c.c, F + 30000000000ull);
    check("drain deadline: due at 30000 ms", 0, hy2c_timeout_ms(x.c.c));
    check("drain deadline: reset at 30000 ms", 1, PUMP_UNTIL(&x, pd->pa_reset == 1));
    hy2c_probe_get(x.c.c, &pr);
    check("drain deadline: list empty", 0, (long)pr.drain_n);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

#define BIG_C 1004000
#define BIG_N 5

static int fill_big_n(struct pair *x, int64_t *sid, int chunks) {
    if (open_tcp(x, sid) != 0) return 0;
    for (int i = 0; i < chunks; i++)
        if (hy2c_tcp_send(x->c.c, *sid, g_pat, BIG_C) != BIG_C) return 0;
    struct hp_st *ps = hp_st(&x->p, *sid);
    if (!PUMP_UNTIL(x, ps->got >= 65536)) return 0;
    pump_for(x, 50);
    return hy2c_tcp_finish(x->c.c, *sid) == 0;
}

static int fill_big(struct pair *x, int64_t *sid) { return fill_big_n(x, sid, BIG_N); }

static void big_pair_at(struct pair *x, struct hy2c_cfg *cc, struct qc_srv_cfg *sc, uint64_t rate) {
    pair_init(x, cc, sc);
    cc->cc = HY2_CC_FORCE;
    cc->up_bps = rate;
    sc->max_stream_data = 65536;
    x->p.auth_mode = HP_AUTH_RX;
    x->p.rx_answer = "0";
    x->p.no_consume = 1;
    x->p.echo = 0;
}

static void big_pair(struct pair *x, struct hy2c_cfg *cc, struct qc_srv_cfg *sc) { big_pair_at(x, cc, sc, 6000000); }

static void capped_round(const char *tag, int small, int chunks) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    struct hy2c_probe pr;
    char b[160];
    int64_t t[2] = { -1, -1 };
    big_pair_at(&x, &cc, &sc, 1ull << 30);
    if (small) {
        cc.qc.send_total = 8u << 20;
        cc.qc.send_buf = 2u << 20;
        cc.qc.brutal_span = 4u << 20;
    }
    snprintf(b, sizeof b, "%s: pair opens", tag);
    check(b, 0, pair_start(&x, &cc, &sc));
    snprintf(b, sizeof b, "%s: ready", tag);
    check(b, 1, PUMP_UNTIL(&x, x.c.ready));
    snprintf(b, sizeof b, "%s: the first full upload finished", tag);
    check(b, 1, fill_big_n(&x, &t[0], chunks));
    hy2c_tcp_close(x.c.c, t[0]);
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    snprintf(b, sizeof b, "%s: it drains", tag);
    check(b, 1, pr.drain_n == 1 && hp_st(&x.p, t[0])->pa_reset == 0);
    snprintf(b, sizeof b, "%s: the second full upload finished", tag);
    check(b, 1, fill_big_n(&x, &t[1], chunks));
    hy2c_tcp_close(x.c.c, t[1]);
    snprintf(b, sizeof b, "%s: the two trip the bound, the first is reset", tag);
    check(b, 1, PUMP_UNTIL(&x, hp_st(&x.p, t[0])->pa_reset == 1));
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    snprintf(b, sizeof b, "%s: the second drains", tag);
    check(b, 1, pr.drain_n == 1 && hp_st(&x.p, t[1])->pa_reset == 0);
    pair_free(&x);
}

static void a_capped_brutal_rate_keeps_a_drain_bound(void) {
    capped_round("capped drain large", 0, 16);
    capped_round("capped drain small", 1, 4);
}

static void a_full_brutal_upload_drains(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    struct hy2c_probe pr;
    uint64_t tx = 0;
    big_pair(&x, &cc, &sc);
    check("brutal drain: pair opens", 0, pair_start(&x, &cc, &sc));
    check("brutal drain: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    check("brutal drain: Brutal at 6000000 B/s", QC_CC_BRUTAL, hy2c_cc(x.c.c, &tx));
    int64_t sid = -1;
    check("brutal drain: 5020000 bytes in a 6000000-byte buffer, finished", 1, fill_big(&x, &sid));
    hy2c_tcp_close(x.c.c, sid);
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    struct hp_st *ps = hp_st(&x.p, sid);
    check("brutal drain: 4954464 queued over a 4194304 quarter, still draining", 1, pr.drain_n == 1 && ps->pa_reset == 0);
    x.p.no_consume = 0;
    hp_consume_all(&x.p);
    check("brutal drain: delivered to the end with its fin", 1, PUMP_UNTIL(&x, ps->payload >= BIG_C * BIG_N && ps->fin && ps->closed));
    check("brutal drain: intact and never reset", 1, ps->payload == BIG_C * BIG_N && ps->pbad == 0 && ps->rx_reset == 0);
    pair_free(&x);

    big_pair(&x, &cc, &sc);
    check("brutal drain three: pair opens", 0, pair_start(&x, &cc, &sc));
    check("brutal drain three: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t t[3];
    int ok = 0;
    for (int i = 0; i < 2; i++) {
        if (!fill_big(&x, &t[i])) break;
        hy2c_tcp_close(x.c.c, t[i]);
        ok++;
    }
    check("brutal drain three: two finished and closed", 2, ok);
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    check("brutal drain three: 9908928 under 10777216, both draining", 1, pr.drain_n == 2 && hp_st(&x.p, t[0])->pa_reset == 0);
    check("brutal drain three: third finished", 1, fill_big(&x, &t[2]));
    hy2c_tcp_close(x.c.c, t[2]);
    check("brutal drain three: 14863392 over 10777216, the first is reset", 1, PUMP_UNTIL(&x, hp_st(&x.p, t[0])->pa_reset == 1));
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    check("brutal drain three: two draining after it", 2, (long)pr.drain_n);
    check("brutal drain three: no other stream reset", 0, hp_st(&x.p, t[1])->pa_reset + hp_st(&x.p, t[2])->pa_reset);
    pair_free(&x);
}

static void a_finished_upload_survives_close(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("finished close: pair opens", 0, pair_start(&x, &cc, &sc));
    check("finished close: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid = -1;
    check("finished close: stream opens", 0, open_tcp(&x, &sid));
    check("finished close: 500000 bytes taken", 500000, (long)hy2c_tcp_send(x.c.c, sid, g_pat, 500000));
    check("finished close: finish", 0, hy2c_tcp_finish(x.c.c, sid));
    hy2c_tcp_close(x.c.c, sid);
    pump_for(&x, 300);
    struct hp_st *ps = hp_st(&x.p, sid);
    check("finished close: peer stalled", 1, ps->payload < 250000);
    x.p.no_consume = 0;
    hp_consume_all(&x.p);
    check("finished close: peer gets all with fin", 1, PUMP_UNTIL(&x, ps->payload >= 500000 && ps->fin));
    check("finished close: exactly 500000", 500000, (long)ps->payload);
    check("finished close: intact", 0, (long)ps->pbad);
    check("finished close: peer stream closed", 1, PUMP_UNTIL(&x, ps->closed));
    check("finished close: rx_reset 0", 0, ps->rx_reset);
    check("finished close: tx_stopped 1", 1, ps->tx_stopped);
    pump_for(&x, 300);
    check("finished close: nothing more for the consumer", 0, cst_get(&x.c, sid)->closed);
    check("finished close: connection alive", 0, x.c.closed);
    pair_free(&x);
}

static void udp_ids_wrap_past_live_sessions(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("udp wrap: pair opens", 0, pair_start(&x, &cc, &sc));
    check("udp wrap: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    check("udp wrap: session 1", 1, (long)hy2c_udp_session(x.c.c));
    hy2c_udp_next_set(x.c.c, 0xFFFFFFFEu);
    check("udp wrap: 0xFFFFFFFE", 1, hy2c_udp_session(x.c.c) == 0xFFFFFFFEu);
    check("udp wrap: 0xFFFFFFFF", 1, hy2c_udp_session(x.c.c) == 0xFFFFFFFFu);
    check("udp wrap: then 2, skipping 0 and the live 1", 2, (long)hy2c_udp_session(x.c.c));
    x.p.dg_echo = 1;
    check("udp wrap: 0xFFFFFFFF sends", 0, hy2c_udp_send(x.c.c, 0xFFFFFFFFu, "1.2.3.4", 53, g_pat, 50));
    check("udp wrap: and its echo comes back", 1, PUMP_UNTIL(&x, x.c.udp_n >= 1));
    check("udp wrap: on that session", 1, x.c.udp_sess == 0xFFFFFFFFu);
    pair_free(&x);
}

static void udp_messages_above_8192_bytes_are_not_sent(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    x.p.dg_echo = 1;
    check("8192: pair opens", 0, pair_start(&x, &cc, &sc));
    check("8192: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    uint32_t s1 = hy2c_udp_session(x.c.c);
    size_t hdr = 8 + 1 + strlen("1.2.3.4:53");
    size_t fit = 8192 - hdr;
    check("8192: header 19 bytes", 19, (long)hdr);
    check("8192: 8173 bytes go", 0, hy2c_udp_send(x.c.c, s1, "1.2.3.4", 53, g_pat, fit));
    check("8192: echoed whole", 1, PUMP_UNTIL(&x, x.c.udp_n >= 1));
    check("8192: 8173 back intact", 1, x.c.udp_len == fit && x.c.udp_ok);
    unsigned seen = x.p.dg_n;
    check("8192: 8174 bytes refused", QC_ETOOBIG, hy2c_udp_send(x.c.c, s1, "1.2.3.4", 53, g_pat, fit + 1));
    pump_for(&x, 300);
    check("8192: no datagram left", (long)seen, (long)x.p.dg_n);
    check("8192: nothing more delivered", 1, (long)x.c.udp_n);
    pair_free(&x);
}

static void a_short_datagram_queue_sends_no_fragment(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("slots: pair opens", 0, pair_start(&x, &cc, &sc));
    check("slots: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    uint32_t s1 = hy2c_udp_session(x.c.c);
    g_slots_cap = 2;
    check("slots: three fragments with two slots", QC_EAGAIN, hy2c_udp_send(x.c.c, s1, "1.2.3.4", 53, g_pat, 3000));
    pump_for(&x, 300);
    check("slots: peer saw nothing", 0, (long)x.p.dg_n);
    check("slots: a whole message still goes", 0, hy2c_udp_send(x.c.c, s1, "1.2.3.4", 53, g_pat, 100));
    g_slots_cap = 3;
    check("slots: three fragments with three slots", 0, hy2c_udp_send(x.c.c, s1, "1.2.3.4", 53, g_pat, 3000));
    check("slots: peer sees four", 1, PUMP_UNTIL(&x, x.p.dg_n >= 4));
    g_slots_cap = 1000;
    pump_for(&x, 300);
    check("slots: exactly four", 4, (long)x.p.dg_n);
    pair_free(&x);
}

static void free_is_silent_and_complete(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("free at open: pair opens", 0, pair_start(&x, &cc, &sc));
    hy2c_free(x.c.c);
    x.c.c = NULL;
    check("free at open: no callback", 0, x.c.cbs);
    pair_free(&x);

    pair_init(&x, &cc, &sc);
    x.p.auth_mode = HP_AUTH_SILENT;
    check("free in auth: pair opens", 0, pair_start(&x, &cc, &sc));
    check("free in auth: peer shook hands", 1, PUMP_UNTIL(&x, x.p.hs && x.p.auth_done));
    if (x.c.in_ep) epoll_ctl(x.ep, EPOLL_CTL_DEL, hy2c_fd(x.c.c), NULL);
    int before = x.c.cbs;
    hy2c_free(x.c.c);
    x.c.c = NULL;
    check("free in auth: no callback", before, x.c.cbs);
    pair_free(&x);

    pair_init(&x, &cc, &sc);
    check("free when ready: pair opens", 0, pair_start(&x, &cc, &sc));
    check("free when ready: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid = -1;
    check("free when ready: a stream", 0, open_tcp(&x, &sid));
    check("free when ready: a session", 1, (long)hy2c_udp_session(x.c.c));
    if (x.c.in_ep) epoll_ctl(x.ep, EPOLL_CTL_DEL, hy2c_fd(x.c.c), NULL);
    before = x.c.cbs;
    hy2c_free(x.c.c);
    x.c.c = NULL;
    check("free when ready: no callback", before, x.c.cbs);
    pump_for(&x, 300);
    check("free when ready: no close frame reaches the peer", 0, x.p.closed);
    pair_free(&x);
}

static int certs_make(void) {
    struct tcg_key *k1 = tcg_key_new(), *kl = tcg_key_new();
    int rc = -1;
    if (!k1 || !kl) goto out;
    if (tcg_issue(k1, "Test CA One", NULL, 1, NULL, NULL, 0, g_ca, sizeof g_ca, &g_ca_n) != 0) goto out;
    if (tcg_issue(kl, "node.test", NULL, 0, k1, g_ca, g_ca_n, g_leaf, sizeof g_leaf, &g_leaf_n) != 0) goto out;
    if (tcg_key_der(kl, g_key, sizeof g_key, &g_key_n) != 0) goto out;
    if (tcg_der_to_pem(g_ca, g_ca_n, g_ca_pem, sizeof g_ca_pem) != 0) goto out;
    rc = 0;
out:
    tcg_key_free(k1);
    tcg_key_free(kl);
    return rc;
}


static void udp_needs_datagrams_and_the_header(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    sc.datagram_max = 0;
    check("no datagrams: pair opens", 0, pair_start(&x, &cc, &sc));
    check("no datagrams: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    check("no datagrams: udp 0", 0, x.c.udp);
    check("no datagrams: no udp session", 0, (long)hy2c_udp_session(x.c.c));
    pair_free(&x);

    pair_init(&x, &cc, &sc);
    x.p.auth_mode = HP_AUTH_NOUDP;
    check("hysteria-udp false: pair opens", 0, pair_start(&x, &cc, &sc));
    check("hysteria-udp false: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    check("hysteria-udp false: udp 0", 0, x.c.udp);
    check("hysteria-udp false: no udp session", 0, (long)hy2c_udp_session(x.c.c));
    pair_free(&x);
}

static void the_auth_budget_counts_from_open(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    x.p.auth_mode = HP_AUTH_SILENT;
    cc.qc.handshake_ms = 10000;
    check("auth budget: pair opens", 0, pair_start(&x, &cc, &sc));
    check("auth budget: the peer has the request", 1, PUMP_UNTIL(&x, x.p.hs && x.p.auth_done));
    uint64_t t0 = hy2c_opened_ns(x.c.c);
    hy2c_clock_set(x.c.c, t0 + 9999000000ull);
    pump_for(&x, 300);
    check("auth budget: still waiting 1 ms before 10000 ms from open", 0, x.c.closed);
    hy2c_clock_set(x.c.c, t0 + 10000000000ull);
    uint64_t e = ms_now() + 1000ull * g_tx;
    while (!x.c.closed && ms_now() < e) pass(&x);
    check("auth budget: closed within 1 s of 10000 ms from open", 1, x.c.closed);
    check("auth budget: reason auth", HY2C_CLOSE_AUTH, x.c.reason);
    check_str("auth budget: why", "auth timed out", x.c.why);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static void closed_streams_hear_nothing_when_the_connection_dies(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("death after close: pair opens", 0, pair_start(&x, &cc, &sc));
    check("death after close: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t p = -1, d = -1, o = -1;
    check("death after close: plain stream", 0, open_tcp(&x, &p));
    check("death after close: answered", 1, PUMP_UNTIL(&x, hp_st(&x.p, p)->responded));
    hy2c_tcp_close(x.c.c, p);
    check("death after close: draining stream", 1, fill_window(&x, &d));
    hy2c_tcp_close(x.c.c, d);
    struct hy2c_probe pr;
    hy2c_probe_get(x.c.c, &pr);
    check("death after close: one draining", 1, (long)pr.drain_n);
    check("death after close: an open stream", 0, open_tcp(&x, &o));
    check("death after close: open one answered", 1, PUMP_UNTIL(&x, hp_st(&x.p, o)->responded));
    qc_close(x.p.q, 0);
    check("death after close: on_closed", 1, PUMP_UNTIL(&x, x.c.closed));
    pump_for(&x, 300);
    check("death after close: nothing for the plain close", 0, cst_get(&x.c, p)->closed);
    check("death after close: nothing for the draining close", 0, cst_get(&x.c, d)->closed);
    check("death after close: the open stream ends with the link", 1,
          cst_get(&x.c, o)->closed == 1 && cst_get(&x.c, o)->how == HY2C_END_LINK);
    pair_free(&x);

    pair_init(&x, &cc, &sc);
    x.p.echo = 0;
    check("reset then death: pair opens", 0, pair_start(&x, &cc, &sc));
    check("reset then death: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t r = -1;
    check("reset then death: stream", 0, open_tcp(&x, &r));
    check("reset then death: answered", 1, PUMP_UNTIL(&x, hp_st(&x.p, r)->responded));
    pump_for(&x, 200);
    check("reset then death: the peer resets", 0, qc_stream_reset_write(x.p.q, r, 0));
    qc_close(x.p.q, 0);
    check("reset then death: on_closed", 1, PUMP_UNTIL(&x, x.c.closed));
    pump_for(&x, 300);
    check("reset then death: one close, by the reset", 1,
          cst_get(&x.c, r)->closed == 1 && cst_get(&x.c, r)->how == HY2C_END_RESET);
    pair_free(&x);
}

static void a_request_and_its_payload_leave_together(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("one packet: pair opens", 0, pair_start(&x, &cc, &sc));
    check("one packet: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    pump_for(&x, 300);
    struct qc_stats a, b, c;
    hy2c_stats(x.c.c, &a);
    int64_t sid = -1;
    check("one packet: stream opens", 0, hy2c_tcp_open(x.c.c, "example.com", 443, &sid));
    cst_get(&x.c, sid);
    check("one packet: 100 bytes taken", 100, (long)hy2c_tcp_send(x.c.c, sid, g_pat, 100));
    hy2c_stats(x.c.c, &b);
    check("one packet: nothing sent before a flush", 0, (long)(b.pkt_sent - a.pkt_sent));
    check("one packet: the deadline says a flush is due", 0, hy2c_timeout_ms(x.c.c));
    hy2c_flush(x.c.c);
    hy2c_stats(x.c.c, &c);
    check("one packet: request and payload in one packet", 1, (long)(c.pkt_sent - b.pkt_sent));
    struct hp_st *ps = hp_st(&x.p, sid);
    check("one packet: the peer gets both", 1, PUMP_UNTIL(&x, ps->parsed == 1 && ps->payload == 100 && ps->pbad == 0));
    pair_free(&x);
}

static void pump_peer_only(struct pair *x, unsigned limit_ms, int (*cond)(struct pair *)) {
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &x->p };
    epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(x->p.q), &ev);
    uint64_t e = ms_now() + (uint64_t)limit_ms * g_tx;
    while (!cond(x) && ms_now() < e) {
        int t = x->p.closed ? 20 : qc_timeout_ms(x->p.q);
        struct epoll_event got;
        if (epoll_wait(ep, &got, 1, t < 0 || t > 20 ? 20 : t) > 0 && !x->p.closed) (void)qc_on_readable(x->p.q);
        if (!x->p.closed && qc_timeout_ms(x->p.q) == 0) (void)qc_on_timer(x->p.q);
        hp_drain(&x->p);
        qc_flush(x->p.q);
    }
    close(ep);
}

static int64_t g_open_ids[20];
static int g_open_n;

static int c_all_parsed(struct pair *x) {
    for (int i = 0; i < g_open_n; i++)
        if (hp_st(&x->p, g_open_ids[i])->parsed != 1) return 0;
    return 1;
}

static void many_opens_leave_in_one_flush(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    sc.max_streams = 400;
    x.p.echo = 0;
    x.p.answer_after = (size_t)-1;
    check("20 opens: pair opens", 0, pair_start(&x, &cc, &sc));
    check("20 opens: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    pump_for(&x, 300);
    g_open_n = 0;
    for (int i = 0; i < 20; i++)
        if (hy2c_tcp_open(x.c.c, "example.com", 443, &g_open_ids[g_open_n]) == 0) g_open_n++;
    check("20 opens: all opened", 20, g_open_n);
    hy2c_flush(x.c.c);
    pump_peer_only(&x, 10000, c_all_parsed);
    int parsed = 0;
    for (int i = 0; i < g_open_n; i++) parsed += hp_st(&x.p, g_open_ids[i])->parsed == 1;
    check("20 opens: every request reaches the peer after one flush", 20, parsed);
    pair_free(&x);
}

static void an_open_needs_no_connection_budget(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    cc.qc.send_total = MIB;
    cc.qc.send_buf = MIB;
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("exempt open: pair opens", 0, pair_start(&x, &cc, &sc));
    check("exempt open: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t a = -1, b = -1;
    check("exempt open: first stream", 0, open_tcp(&x, &a));
    ssize_t wa = hy2c_tcp_send(x.c.c, a, g_pat, MIB);
    check("exempt open: the first spends the budget", 1, wa > 0 && hy2c_tcp_send(x.c.c, a, g_pat, 10) == QC_EAGAIN);
    struct cst *sa = cst_get(&x.c, a);
    sa->to_send = 2 * MIB;
    sa->sent = (size_t)wa;
    sa->short_hit = 1;
    sa->wseen = sa->writable;
    check("exempt open: an open still succeeds", 0, hy2c_tcp_open(x.c.c, "example.com", 443, &b));
    struct cst *sb = cst_get(&x.c, b);
    struct hp_st *pb = hp_st(&x.p, b);
    check("exempt open: its request reaches the peer", 1, PUMP_UNTIL(&x, pb->parsed == 1));
    size_t req = pb->got;
    ssize_t w = hy2c_tcp_send(x.c.c, b, g_pat, 8192);
    check("exempt open: 8 KiB takes exactly what is exempt", (long)(4096 - req), (long)w);
    sb->to_send = 8192;
    sb->sent = w > 0 ? (size_t)w : 0;
    sb->short_hit = 1;
    sb->wseen = sb->writable;
    x.p.no_consume = 0;
    hp_consume_all(&x.p);
    check("exempt open: told writable when budget frees", 1, PUMP_UNTIL(&x, sb->writable > sb->wseen));
    check("exempt open: all 8 KiB arrive", 1, PUMP_UNTIL(&x, pb->payload >= 8192) && pb->payload == 8192 && pb->pbad == 0);
    pair_free(&x);
}

static int c_peer_closed(struct pair *x) { return x->p.closed != 0; }

static void a_close_then_free_still_tells_the_peer(void) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    pair_init(&x, &cc, &sc);
    check("close then free: pair opens", 0, pair_start(&x, &cc, &sc));
    check("close then free: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    pump_for(&x, 300);
    if (x.c.in_ep) epoll_ctl(x.ep, EPOLL_CTL_DEL, hy2c_fd(x.c.c), NULL);
    x.c.in_ep = 0;
    hy2c_close(x.c.c);
    hy2c_free(x.c.c);
    x.c.c = NULL;
    pump_peer_only(&x, 3000, c_peer_closed);
    check("close then free: the peer sees an application close 0x100", 1, x.p.closed && x.p.app && x.p.code == 0x100);
    pair_free(&x);
}

static uint64_t c_rx(struct pair *x) {
    struct qc_stats st;
    hy2c_stats(x->c.c, &st);
    return st.pkt_recv;
}

static int pump_to_receive(struct pair *x) {
    uint64_t r = c_rx(x);
    return PUMP_UNTIL(x, c_rx(x) > r);
}

static void ka_round(const char *tag, int udp, unsigned ka) {
    static struct pair x;
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    char b[128];
    pair_init(&x, &cc, &sc);
    cc.qc.idle_ms = 1500;
    sc.idle_ms = 1500;
    cc.qc.keepalive_ms = ka;
    x.p.echo = 0;
    snprintf(b, sizeof b, "%s: pair opens", tag);
    check(b, 0, pair_start(&x, &cc, &sc));
    snprintf(b, sizeof b, "%s: ready", tag);
    check(b, 1, PUMP_UNTIL(&x, x.c.ready));
    int64_t sid = -1;
    uint32_t u = 0;
    if (udp < 0) {
        uint64_t t = ms_now();
        snprintf(b, sizeof b, "%s: closed with no flow ever open", tag);
        check(b, 1, PUMP_UNTIL(&x, x.c.closed));
        snprintf(b, sizeof b, "%s: by idle", tag);
        check(b, QC_CLOSE_IDLE, x.c.reason);
        snprintf(b, sizeof b, "%s: within 5000 ms", tag);
        check(b, 1, x.c.closed_ms - t <= 5000ull * g_tx);
        pair_free(&x);
        return;
    }
    if (udp == 1) {
        u = hy2c_udp_session(x.c.c);
        snprintf(b, sizeof b, "%s: a udp session", tag);
        check(b, 1, u != 0);
    } else {
        snprintf(b, sizeof b, "%s: a stream", tag);
        check(b, 0, open_tcp(&x, &sid));
        snprintf(b, sizeof b, "%s: answered", tag);
        check(b, 1, PUMP_UNTIL(&x, hp_st(&x.p, sid)->responded));
    }
    if (!ka) {
        uint64_t t = ms_now();
        snprintf(b, sizeof b, "%s: closed with the flow open", tag);
        check(b, 1, PUMP_UNTIL(&x, x.c.closed));
        snprintf(b, sizeof b, "%s: by idle", tag);
        check(b, QC_CLOSE_IDLE, x.c.reason);
        snprintf(b, sizeof b, "%s: within 5000 ms", tag);
        check(b, 1, x.c.closed_ms - t <= 5000ull * g_tx);
        pair_free(&x);
        return;
    }
    pump_for(&x, 4000);
    snprintf(b, sizeof b, "%s: alive after 4000 ms of silence", tag);
    check(b, 0, x.c.closed);
    snprintf(b, sizeof b, "%s: the client receives", tag);
    check(b, 1, pump_to_receive(&x));
    if (udp == 2) {
        qc_stream_reset(x.p.q, sid, 0);
        snprintf(b, sizeof b, "%s: the client hears the reset", tag);
        check(b, 1, PUMP_UNTIL(&x, cst_get(&x.c, sid)->closed) && cst_get(&x.c, sid)->how == HY2C_END_RESET);
    } else if (udp) hy2c_udp_end(x.c.c, u);
    else hy2c_tcp_close(x.c.c, sid);
    uint64_t t = ms_now();
    if (!udp) {
        snprintf(b, sizeof b, "%s: the peer ends its side", tag);
        check(b, 1, PUMP_UNTIL(&x, hp_st(&x.p, sid)->closed || x.c.closed));
    }
    snprintf(b, sizeof b, "%s: closed once the flow is gone", tag);
    check(b, 1, PUMP_UNTIL(&x, x.c.closed));
    snprintf(b, sizeof b, "%s: by idle", tag);
    check(b, QC_CLOSE_IDLE, x.c.reason);
    uint64_t dt = x.c.closed_ms - t;
    snprintf(b, sizeof b, "%s: 1300..5000 ms after the flow went", tag);
    check(b, 1, dt >= 1300 && dt <= 5000ull * g_tx);
    pair_free(&x);
}

static void keepalive_runs_only_while_flows_are_open(void) {
    ka_round("keepalive tcp", 0, 500);
    ka_round("keepalive udp", 1, 500);
    ka_round("keepalive 0", 0, 0);
    ka_round("keepalive before any flow", -1, 500);
    ka_round("keepalive, the node resets", 2, 500);
}

#define LIVE_F 1000000000000000ull
#define LIVE_MS(n) (LIVE_F + (uint64_t)(n) * 1000000ull)

static int never(struct pair *x) { (void)x; return 0; }

static void live_setup_with(struct pair *x, int64_t *sid, const char *tag, unsigned ka, unsigned idle) {
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    char b[128];
    pair_init(x, &cc, &sc);
    cc.qc.idle_ms = idle;
    sc.idle_ms = idle;
    cc.qc.keepalive_ms = ka;
    x->p.echo = 0;
    snprintf(b, sizeof b, "%s: pair opens", tag);
    check(b, 0, pair_start(x, &cc, &sc));
    snprintf(b, sizeof b, "%s: ready", tag);
    check(b, 1, PUMP_UNTIL(x, x->c.ready));
    hy2c_clock_set(x->c.c, LIVE_F);
    snprintf(b, sizeof b, "%s: a stream", tag);
    check(b, 0, open_tcp(x, sid));
    struct hp_st *ps = hp_st(&x->p, *sid);
    snprintf(b, sizeof b, "%s: answered", tag);
    check(b, 1, PUMP_UNTIL(x, ps->responded));
    pump_for(x, 300);
    uint64_t r = c_rx(x);
    snprintf(b, sizeof b, "%s: 100 bytes reach the peer and its answer the client", tag);
    check(b, 1, hy2c_tcp_send(x->c.c, *sid, g_pat, 100) == 100 && PUMP_UNTIL(x, ps->payload >= 100 && c_rx(x) > r));
    pump_for(x, 300);
}

static void live_setup(struct pair *x, int64_t *sid, const char *tag) { live_setup_with(x, sid, tag, 10000, 120000); }

static void unanswered_send(struct pair *x, int64_t sid, unsigned at_ms, size_t total, const char *tag) {
    char b[128];
    struct hp_st *ps = hp_st(&x->p, sid);
    x->p.drop = HP_DROP_ALL;
    hy2c_clock_set(x->c.c, LIVE_MS(at_ms));
    snprintf(b, sizeof b, "%s: a send at +%u reaches the peer", tag, at_ms);
    check(b, 1, hy2c_tcp_send(x->c.c, sid, g_pat + total - 100, 100) == 100 && PUMP_UNTIL(x, ps->payload >= total));
    pump_for(x, 300);
}

static void live_cut_link(struct pair *x, int64_t sid, unsigned at_ms, const char *tag) {
    char b[128];
    hy2c_clock_set(x->c.c, LIVE_MS(at_ms - 1));
    snprintf(b, sizeof b, "%s: the deadline is the limit, at most 1 ms away", tag);
    check(b, 1, hy2c_timeout_ms(x->c.c) <= 1);
    pump_for(x, 300);
    snprintf(b, sizeof b, "%s: open 1 ms before the limit", tag);
    check(b, 1, !x->c.closed && !cst_get(&x->c, sid)->closed);
    hy2c_clock_set(x->c.c, LIVE_MS(at_ms + 1));
    uint64_t e = ms_now() + 1000ull * g_tx;
    while (!x->c.closed && ms_now() < e) pass(x);
    snprintf(b, sizeof b, "%s: closed within 1 s after the limit", tag);
    check(b, 1, x->c.closed);
    snprintf(b, sizeof b, "%s: the stream ends with the link, first", tag);
    check(b, 1, cst_get(&x->c, sid)->closed == 1 && cst_get(&x->c, sid)->how == HY2C_END_LINK &&
                    x->c.sclose_before_closed == x->c.sclose_total && x->c.sclose_total >= 1);
    snprintf(b, sizeof b, "%s: reason error", tag);
    check(b, QC_CLOSE_ERROR, x->c.reason);
    snprintf(b, sizeof b, "%s: why", tag);
    check_str(b, "the node stopped answering", x->c.why);
}

static void live_cut_checks(struct pair *x, int64_t sid, unsigned at_ms, const char *tag) {
    char b[128];
    live_cut_link(x, sid, at_ms, tag);
    snprintf(b, sizeof b, "%s: the peer gets application 0x100, empty reason", tag);
    check(b, 1, PUMP_UNTIL(x, x->p.closed) && x->p.app == 1 && x->p.code == 0x100 && x->p.reason_n == 0);
}

static void cut_round(int mode, const char *tag) {
    static struct pair x;
    int64_t sid = -1;
    live_setup(&x, &sid, tag);
    unanswered_send(&x, sid, 10000, 200, tag);
    x.p.drop = mode;
    live_cut_checks(&x, sid, 15000, tag);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static uint16_t dead_udp_port(void) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t l = sizeof a;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    uint16_t port = bind(fd, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(fd, (struct sockaddr *)&a, &l) == 0
                        ? ntohs(a.sin_port) : 0;
    close(fd);
    return port;
}

static void a_hop_onto_a_dead_port_is_cut_by_the_rule(void) {
    static struct pair x;
    int64_t sid = -1;
    g_hop_dead = dead_udp_port();
    check("dead port: a port nobody serves", 1, g_hop_dead != 0);
    live_setup(&x, &sid, "dead port");
    g_hop_dead = 0;
    hy2c_clock_set(x.c.c, LIVE_MS(10000));
    hy2c_hop_now(x.c.c);
    pump_for(&x, 300);
    live_cut_link(&x, sid, 15000, "dead port");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static void a_silent_node_under_flows_is_cut_at_15_s(void) {
    cut_round(HP_DROP_ALL, "silent node");
    cut_round(HP_DROP_GARBLE, "garbling node");

    static struct pair x;
    int64_t sid = -1, s2 = -1;
    live_setup(&x, &sid, "no flows");
    hy2c_tcp_close(x.c.c, sid);
    check("no flows: the peer ends its side", 1, PUMP_UNTIL(&x, hp_st(&x.p, sid)->closed));
    pump_for(&x, 300);
    x.p.drop = HP_DROP_ALL;
    struct qc_stats n0, n1;
    qc_stats_get(x.p.q, &n0);
    hy2c_clock_set(x.c.c, LIVE_MS(15001));
    pump_for(&x, 1000);
    (void)hy2c_on_timer(x.c.c);
    pump_for(&x, 300);
    qc_stats_get(x.p.q, &n1);
    check("no flows: open at +15001 with keep-alive off, after a timer pass", 0, x.c.closed);
    check("no flows: nothing sent while keep-alive is off", 0, (long)(n1.pkt_recv - n0.pkt_recv));
    check("no flows: a new stream", 0, hy2c_tcp_open(x.c.c, "example.com", 443, &s2));
    cst_get(&x.c, s2);
    hy2c_flush(x.c.c);
    live_cut_checks(&x, s2, 15001 + 15000, "no flows, then a stream");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "late packet");
    struct hp_st *ps = hp_st(&x.p, sid);
    hy2c_clock_set(x.c.c, LIVE_MS(10000));
    uint64_t r = c_rx(&x);
    check("late packet: a send at +10000 reaches the peer and its answer the client", 1,
          hy2c_tcp_send(x.c.c, sid, g_pat + 100, 100) == 100 && PUMP_UNTIL(&x, ps->payload >= 200 && c_rx(&x) > r));
    pump_for(&x, 300);
    unanswered_send(&x, sid, 12000, 300, "late packet");
    live_cut_checks(&x, sid, 25000, "late packet");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup_with(&x, &sid, "clamped interval", 25000, 30000);
    unanswered_send(&x, sid, 10000, 200, "clamped interval");
    live_cut_checks(&x, sid, 15000, "clamped interval");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup_with(&x, &sid, "keepalive 0", 0, 120000);
    unanswered_send(&x, sid, 10000, 200, "keepalive 0");
    hy2c_clock_set(x.c.c, LIVE_MS(15001));
    pump_for(&x, 300);
    (void)hy2c_on_timer(x.c.c);
    hy2c_clock_set(x.c.c, LIVE_MS(60000));
    pump_for(&x, 300);
    (void)hy2c_on_timer(x.c.c);
    pump_for(&x, 300);
    check("keepalive 0: never cut, at +15001 nor at +60000", 1, !x.c.closed && !cst_get(&x.c, sid)->closed);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "own close");
    unanswered_send(&x, sid, 10000, 200, "own close");
    hy2c_clock_set(x.c.c, LIVE_MS(15001));
    hy2c_close(x.c.c);
    check("own close: closed", 1, PUMP_UNTIL(&x, x.c.closed));
    check("own close: reported local", QC_CLOSE_LOCAL, x.c.reason);
    check_str("own close: why", "closed by us", x.c.why);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static void answer_in_socket_round(int timer_first, const char *tag) {
    static struct pair x;
    int64_t sid = -1;
    char b[128];
    live_setup(&x, &sid, tag);
    unanswered_send(&x, sid, 10000, 200, tag);
    hy2c_clock_set(x.c.c, LIVE_MS(15001));
    x.p.drop = HP_DROP_NONE;
    hy2c_tcp_send(x.c.c, sid, g_pat + 200, 100);
    hy2c_flush(x.c.c);
    pump_peer_only(&x, 300, never);
    snprintf(b, sizeof b, "%s: the peer has the data", tag);
    check(b, 1, hp_st(&x.p, sid)->payload >= 300);
    if (timer_first) (void)hy2c_on_timer(x.c.c);
    else (void)hy2c_on_readable(x.c.c);
    hy2c_flush(x.c.c);
    pump_for(&x, 300);
    snprintf(b, sizeof b, "%s: the answer waiting in the socket keeps the link", tag);
    check(b, 1, !x.c.closed && !cst_get(&x.c, sid)->closed);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static void a_late_loop_never_cuts_a_healthy_node(void) {
    answer_in_socket_round(1, "answer waiting, timer first");
    answer_in_socket_round(0, "answer waiting, readable first");

    static struct pair x;
    int64_t sid = -1;
    struct qc_stats a, b;
    live_setup(&x, &sid, "stalled loop");
    qc_stats_get(x.p.q, &a);
    hy2c_clock_set(x.c.c, LIVE_MS(16000));
    (void)hy2c_on_timer(x.c.c);
    hy2c_flush(x.c.c);
    pump_peer_only(&x, 300, never);
    qc_stats_get(x.p.q, &b);
    check("stalled loop: the first pass sends the overdue ping", 1, b.pkt_recv > a.pkt_recv);
    pump_for(&x, 300);
    check("stalled loop: not cut at +16000", 1, !x.c.closed && !cst_get(&x.c, sid)->closed);
    hy2c_clock_set(x.c.c, LIVE_MS(30999));
    pump_for(&x, 300);
    check("stalled loop: the answer moves the limit to +31000", 1, !x.c.closed && !cst_get(&x.c, sid)->closed);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "late wake");
    unanswered_send(&x, sid, 10000, 200, "late wake");
    hy2c_clock_set(x.c.c, LIVE_MS(16500));
    x.p.drop = HP_DROP_NONE;
    (void)hy2c_on_timer(x.c.c);
    hy2c_flush(x.c.c);
    pump_for(&x, 300);
    check("late wake: 1500 ms past the limit is not a verdict", 1, !x.c.closed && !cst_get(&x.c, sid)->closed);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static void forged_and_flapping_round(int forge, const char *tag) {
    static struct pair x;
    int64_t sid = -1, s2 = -1;
    char b[128];
    live_setup(&x, &sid, tag);
    unanswered_send(&x, sid, 10000, 200, tag);
    if (forge) {
        uint8_t d[33];
        memset(d, 0x5a, sizeof d);
        d[0] = 0xc0;
        d[1] = 0; d[2] = 0; d[3] = 0; d[4] = 1;
        d[5] = 0;
        d[6] = 4;
        memcpy(d + 7, x.p.cid, 4);
        d[11] = 0;
        d[12] = 20;
        uint64_t r = c_rx(&x);
        snprintf(b, sizeof b, "%s: the node's id was seen", tag);
        check(b, 4, (long)x.p.cid_n);
        snprintf(b, sizeof b, "%s: ngtcp2 counts the forged initial", tag);
        check(b, 1, send(qc_fd(x.p.q), d, sizeof d, 0) == (ssize_t)sizeof d && PUMP_UNTIL(&x, c_rx(&x) > r));
        live_cut_checks(&x, sid, 15000, tag);
    } else {
        hy2c_tcp_close(x.c.c, sid);
        snprintf(b, sizeof b, "%s: a new stream at +10000", tag);
        check(b, 0, hy2c_tcp_open(x.c.c, "example.com", 443, &s2));
        cst_get(&x.c, s2);
        pump_for(&x, 300);
        live_cut_checks(&x, s2, 15000, tag);
    }
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static void the_limit_waits_for_the_unanswered_send_and_no_longer(void) {
    static struct pair x;
    int64_t sid = -1;
    live_setup(&x, &sid, "send 3 s before the limit");
    unanswered_send(&x, sid, 12000, 200, "send 3 s before the limit");
    hy2c_clock_set(x.c.c, LIVE_MS(15001));
    pump_for(&x, 300);
    check("send 3 s before the limit: not cut at +15001", 0, x.c.closed);
    live_cut_checks(&x, sid, 17000, "send 3 s before the limit");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "own stall after a lost packet");
    unanswered_send(&x, sid, 1000, 200, "own stall after a lost packet");
    hy2c_clock_set(x.c.c, LIVE_MS(15900));
    x.p.drop = HP_DROP_NONE;
    (void)hy2c_on_timer(x.c.c);
    hy2c_flush(x.c.c);
    pump_for(&x, 300);
    check("own stall after a lost packet: 14.9 s without a pass is not the node's silence", 1,
          !x.c.closed && !cst_get(&x.c, sid)->closed);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "own stall, the node stays silent");
    unanswered_send(&x, sid, 1000, 200, "own stall, the node stays silent");
    hy2c_clock_set(x.c.c, LIVE_MS(15900));
    (void)hy2c_on_timer(x.c.c);
    hy2c_flush(x.c.c);
    pump_for(&x, 300);
    check("own stall, the node stays silent: re-armed, not cut, at +15900", 0, x.c.closed);
    hy2c_clock_set(x.c.c, LIVE_MS(18399));
    check("own stall, the node stays silent: the half-way wake is at +18400", 1, hy2c_live_wake_ns(x.c.c) == LIVE_MS(18400));
    hy2c_clock_set(x.c.c, LIVE_MS(18400));
    pump_for(&x, 300);
    hy2c_clock_set(x.c.c, LIVE_MS(20899));
    check("own stall, the node stays silent: the limit is re-armed to +20900", 1, hy2c_live_wake_ns(x.c.c) == LIVE_MS(20900));
    check("own stall, the node stays silent: open at +20899", 0, x.c.closed);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "a punctual wake");
    unanswered_send(&x, sid, 10000, 200, "a punctual wake");
    hy2c_clock_set(x.c.c, LIVE_MS(12500));
    (void)hy2c_on_timer(x.c.c);
    hy2c_flush(x.c.c);
    hy2c_clock_set(x.c.c, LIVE_MS(15001));
    (void)hy2c_on_timer(x.c.c);
    hy2c_flush(x.c.c);
    uint64_t pw = ms_now() + 1000ull * g_tx;
    while (!x.c.closed && ms_now() < pw) pass(&x);
    check("a punctual wake: a pass at +12500 then +15001 cuts within 1 s", 1, x.c.closed);
    check_str("a punctual wake: why", "the node stopped answering", x.c.why);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static void only_the_node_moves_the_limit(void) {
    forged_and_flapping_round(1, "forged initial");
    forged_and_flapping_round(0, "flows come and go");
}

static int64_t g_left_sid;

static int c_peer_saw_stop(struct pair *x) { return hp_st(&x->p, g_left_sid)->pa_stopped != 0; }

static long left_n(struct pair *x) {
    struct hy2c_probe pr = { 0 };
    hy2c_probe_get(x->c.c, &pr);
    return (long)pr.left_n;
}

static void left_cut_checks(struct pair *x, const char *tag) {
    char b[128];
    snprintf(b, sizeof b, "%s: reason error", tag);
    check(b, QC_CLOSE_ERROR, x->c.reason);
    snprintf(b, sizeof b, "%s: why", tag);
    check_str(b, "peer left closed streams open", x->c.why);
    snprintf(b, sizeof b, "%s: the consumer heard nothing of its closed streams", tag);
    check(b, 0, x->c.sclose_total);
    snprintf(b, sizeof b, "%s: the peer gets application 0x100", tag);
    check(b, 1, PUMP_UNTIL(x, x->p.closed) && x->p.app == 1 && x->p.code == 0x100);
}

static int64_t g_left_sid2;

static int c_refused_and_aborted(struct pair *x) {
    return cst_get(&x->c, g_left_sid)->refused && cst_get(&x->c, g_left_sid2)->closed;
}

static void client_until(struct pair *x, int (*cond)(struct pair *)) {
    uint64_t e = ms_now() + 10000ull * g_tx;
    while (!cond(x) && ms_now() < e) {
        (void)hy2c_on_readable(x->c.c);
        if (hy2c_timeout_ms(x->c.c) == 0) (void)hy2c_on_timer(x->c.c);
        hy2c_flush(x->c.c);
    }
}

static void left_bound_checks(struct pair *x, unsigned at_ms, const char *tag) {
    char b[128];
    hy2c_clock_set(x->c.c, LIVE_MS(at_ms + 29999));
    pump_for(x, 300);
    (void)hy2c_on_timer(x->c.c);
    pump_for(x, 300);
    snprintf(b, sizeof b, "%s: open 29999 ms after the close", tag);
    check(b, 0, x->c.closed);
    hy2c_clock_set(x->c.c, LIVE_MS(at_ms + 30000));
    uint64_t e = ms_now() + 1000ull * g_tx;
    while (!x->c.closed && ms_now() < e) pass(x);
    snprintf(b, sizeof b, "%s: closed within 1 s at 30000 ms", tag);
    check(b, 1, x->c.closed);
    left_cut_checks(x, tag);
}

static void closed_streams_the_peer_never_ends_have_a_time_bound(void) {
    static struct pair x;
    int64_t sid = -1;
    live_setup(&x, &sid, "left time");
    x.p.drop = HP_DROP_ALL;
    hy2c_clock_set(x.c.c, LIVE_MS(5000));
    hy2c_tcp_close(x.c.c, sid);
    hy2c_flush(x.c.c);
    struct hp_st *ps = hp_st(&x.p, sid);
    check("left time: the peer sees the stop and the fin", 1, PUMP_UNTIL(&x, ps->pa_stopped && ps->fin));
    pump_for(&x, 300);
    check("left time: one stream left", 1, left_n(&x));
    hy2c_clock_set(x.c.c, LIVE_MS(15001));
    pump_for(&x, 300);
    (void)hy2c_on_timer(x.c.c);
    pump_for(&x, 300);
    check("left time: open at +15001, a left stream is no flow", 0, x.c.closed);
    hy2c_clock_set(x.c.c, LIVE_MS(5000 + 29999));
    check("left time: the deadline is the bound, at most 1 ms away", 1, hy2c_timeout_ms(x.c.c) <= 1);
    pump_for(&x, 300);
    (void)hy2c_on_timer(x.c.c);
    pump_for(&x, 300);
    check("left time: open 29999 ms after the close", 1, !x.c.closed && left_n(&x) == 1);
    hy2c_clock_set(x.c.c, LIVE_MS(5000 + 30000));
    uint64_t e = ms_now() + 1000ull * g_tx;
    while (!x.c.closed && ms_now() < e) pass(&x);
    check("left time: closed within 1 s at 30000 ms after the close", 1, x.c.closed);
    left_cut_checks(&x, "left time");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "left, peer ended first");
    ps = hp_st(&x.p, sid);
    ps->out.fin = 1;
    check("left, peer ended first: the client has the fin", 1, PUMP_UNTIL(&x, cst_get(&x.c, sid)->fin));
    pump_for(&x, 300);
    x.p.drop = HP_DROP_ALL;
    hy2c_clock_set(x.c.c, LIVE_MS(5000));
    hy2c_tcp_close(x.c.c, sid);
    hy2c_flush(x.c.c);
    check("left, peer ended first: the peer sees our fin", 1, PUMP_UNTIL(&x, ps->fin && ps->closed));
    check("left, peer ended first: nothing left", 0, left_n(&x));
    hy2c_clock_set(x.c.c, LIVE_MS(5000 + 30001));
    pump_for(&x, 300);
    (void)hy2c_on_timer(x.c.c);
    pump_for(&x, 300);
    check("left, peer ended first: open at +30001", 0, x.c.closed);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "left, late end");
    hy2c_clock_set(x.c.c, LIVE_MS(5000));
    hy2c_tcp_close(x.c.c, sid);
    hy2c_flush(x.c.c);
    g_left_sid = sid;
    pump_peer_only(&x, 1000, c_peer_saw_stop);
    pump_peer_only(&x, 100, never);
    check("left, late end: the peer saw the stop", 1, hp_st(&x.p, sid)->pa_stopped);
    check("left, late end: still left, the end waits in the socket", 1, left_n(&x));
    hy2c_clock_set(x.c.c, LIVE_MS(5000 + 30001));
    (void)hy2c_on_timer(x.c.c);
    hy2c_flush(x.c.c);
    pump_for(&x, 300);
    check("left, late end: the end waiting in the socket keeps the link", 1, !x.c.closed && left_n(&x) == 0);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "left, own close");
    x.p.drop = HP_DROP_ALL;
    hy2c_tcp_close(x.c.c, sid);
    hy2c_flush(x.c.c);
    check("left, own close: one stream left", 1, left_n(&x));
    hy2c_close(x.c.c);
    check("left, own close: closed", 1, PUMP_UNTIL(&x, x.c.closed));
    check("left, own close: reported local", QC_CLOSE_LOCAL, x.c.reason);
    check("left, own close: nothing left, no deadline after death", 1, left_n(&x) == 0 && hy2c_deadline_ns(x.c.c) == UINT64_MAX);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    live_setup(&x, &sid, "left, the peer only stopped");
    qc_stream_stop(x.p.q, sid, 0);
    qc_flush(x.p.q);
    check("left, the peer only stopped: the client sees the stop", 1, PUMP_UNTIL(&x, hy2c_tcp_send(x.c.c, sid, g_pat, 1) == HY2C_ESTOPPED));
    pump_for(&x, 300);
    x.p.drop = HP_DROP_ALL;
    hy2c_clock_set(x.c.c, LIVE_MS(5000));
    hy2c_tcp_close(x.c.c, sid);
    hy2c_flush(x.c.c);
    pump_for(&x, 300);
    check("left, the peer only stopped: listed", 1, left_n(&x));
    left_bound_checks(&x, 5000, "left, the peer only stopped");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    int64_t r1 = -1, r2 = -1, r3 = -1;
    live_setup(&x, &sid, "left, refused or malformed");
    hy2c_tcp_close(x.c.c, sid);
    check("left, refused or malformed: the first stream ends", 1, PUMP_UNTIL(&x, hp_st(&x.p, sid)->closed && left_n(&x) == 0));
    check("left, refused or malformed: a stream the peer resets", 0, open_tcp(&x, &r3));
    check("left, refused or malformed: it is answered", 1, PUMP_UNTIL(&x, hp_st(&x.p, r3)->responded));
    pump_for(&x, 300);
    qc_stream_reset(x.p.q, r3, 0);
    qc_flush(x.p.q);
    check("left, refused or malformed: the reset reaches the consumer", 1, PUMP_UNTIL(&x, cst_get(&x.c, r3)->closed) && cst_get(&x.c, r3)->how == HY2C_END_RESET);
    hy2c_tcp_close(x.c.c, r3);
    pump_for(&x, 300);
    check("left, refused or malformed: a peer reset is not listed", 0, left_n(&x));
    x.p.answer_after = (size_t)-1;
    check("left, refused or malformed: a stream to refuse", 0, open_tcp(&x, &r1));
    check("left, refused or malformed: a stream to answer badly", 0, open_tcp(&x, &r2));
    check("left, refused or malformed: both parsed", 1, PUMP_UNTIL(&x, hp_st(&x.p, r1)->parsed == 1 && hp_st(&x.p, r2)->parsed == 1));
    pump_for(&x, 300);
    hy2c_clock_set(x.c.c, LIVE_MS(5000));
    uint8_t rb[256];
    static const uint8_t bad[] = { 0x00, 0x4b, 0xb8, 0x00 };
    size_t rn = hy2_tcp_response_put(rb, sizeof rb, 0, "connection refused", 128);
    hp_put(&hp_st(&x.p, r1)->out, rb, rn);
    hp_put(&hp_st(&x.p, r2)->out, bad, sizeof bad);
    hp_drain(&x.p);
    qc_flush(x.p.q);
    x.p.drop = HP_DROP_ALL;
    g_left_sid = r1;
    g_left_sid2 = r2;
    client_until(&x, c_refused_and_aborted);
    check("left, refused or malformed: refused, and the bad answer reset", 1, cst_get(&x.c, r1)->refused == 1 && cst_get(&x.c, r2)->closed == 1 && cst_get(&x.c, r2)->how == HY2C_END_RESET);
    pump_for(&x, 300);
    check("left, refused or malformed: both listed, no fin came", 2, left_n(&x));
    x.c.sclose_total = 0;
    left_bound_checks(&x, 5000, "left, refused or malformed");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    struct hy2c_probe pr;
    pair_init(&x, &cc, &sc);
    cc.qc.idle_ms = 120000;
    sc.idle_ms = 120000;
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("left after a drain: pair opens", 0, pair_start(&x, &cc, &sc));
    check("left after a drain: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    check("left after a drain: finished", 1, fill_window(&x, &sid));
    x.p.drop = HP_DROP_ALL;
    hy2c_clock_set(x.c.c, LIVE_F);
    hy2c_tcp_close(x.c.c, sid);
    hy2c_flush(x.c.c);
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    check("left after a drain: draining, nothing left", 1, pr.drain_n == 1 && pr.left_n == 0);
    hy2c_clock_set(x.c.c, LIVE_MS(30000));
    ps = hp_st(&x.p, sid);
    check("left after a drain: reset at 30000 ms", 1, PUMP_UNTIL(&x, ps->pa_reset == 1));
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    check("left after a drain: left from the reset, open", 1, pr.drain_n == 0 && pr.left_n == 1 && !x.c.closed);
    hy2c_clock_set(x.c.c, LIVE_MS(59999));
    pump_for(&x, 300);
    (void)hy2c_on_timer(x.c.c);
    pump_for(&x, 300);
    check("left after a drain: open 29999 ms after the reset", 0, x.c.closed);
    hy2c_clock_set(x.c.c, LIVE_MS(60000));
    e = ms_now() + 1000ull * g_tx;
    while (!x.c.closed && ms_now() < e) pass(&x);
    check("left after a drain: closed within 1 s at 30000 ms after the reset", 1, x.c.closed);
    left_cut_checks(&x, "left after a drain");
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);

    pair_init(&x, &cc, &sc);
    cc.qc.idle_ms = 120000;
    sc.idle_ms = 120000;
    sc.max_stream_data = 65536;
    x.p.no_consume = 1;
    x.p.echo = 0;
    check("drain, the peer had ended: pair opens", 0, pair_start(&x, &cc, &sc));
    check("drain, the peer had ended: ready", 1, PUMP_UNTIL(&x, x.c.ready));
    check("drain, the peer had ended: finished", 1, fill_window(&x, &sid));
    hy2c_clock_set(x.c.c, LIVE_F);
    hy2c_tcp_close(x.c.c, sid);
    hy2c_flush(x.c.c);
    ps = hp_st(&x.p, sid);
    check("drain, the peer had ended: the peer saw the stop", 1, PUMP_UNTIL(&x, ps->pa_stopped));
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    check("drain, the peer had ended: still draining", 1, pr.drain_n == 1);
    x.p.drop = HP_DROP_ALL;
    hy2c_clock_set(x.c.c, LIVE_MS(30000));
    check("drain, the peer had ended: reset at 30000 ms", 1, PUMP_UNTIL(&x, ps->pa_reset == 1));
    pump_for(&x, 300);
    hy2c_probe_get(x.c.c, &pr);
    check("drain, the peer had ended: nothing left after the reset", 1, pr.drain_n == 0 && pr.left_n == 0);
    hy2c_clock_set(x.c.c, LIVE_MS(60001));
    pump_for(&x, 300);
    (void)hy2c_on_timer(x.c.c);
    pump_for(&x, 300);
    check("drain, the peer had ended: open at +60001", 0, x.c.closed);
    hy2c_clock_set(x.c.c, 0);
    pair_free(&x);
}

static void burst_round(int n, uint64_t max_streams, const char *tag) {
    static struct pair x;
    static int64_t sid[1024];
    struct hy2c_cfg cc;
    struct qc_srv_cfg sc;
    char b[128];
    pair_init(&x, &cc, &sc);
    sc.max_streams = max_streams;
    x.p.echo = 0;
    snprintf(b, sizeof b, "%s: pair opens", tag);
    check(b, 0, pair_start(&x, &cc, &sc));
    snprintf(b, sizeof b, "%s: ready", tag);
    check(b, 1, PUMP_UNTIL(&x, x.c.ready));
    int opened = 0;
    for (int i = 0; i < n; i++) opened += open_tcp(&x, &sid[i]) == 0;
    snprintf(b, sizeof b, "%s: all streams open", tag);
    check(b, n, opened);
    int answered = PUMP_UNTIL(&x, ({
        int all = 1;
        for (int i = 0; i < n && all; i++) all = hp_st(&x.p, sid[i])->responded;
        all;
    }));
    snprintf(b, sizeof b, "%s: every stream answered", tag);
    check(b, 1, answered);
    pump_for(&x, 300);
    for (int i = 0; i < n; i++) hy2c_tcp_close(x.c.c, sid[i]);
    snprintf(b, sizeof b, "%s: all listed at the close", tag);
    check(b, n, left_n(&x));
    hy2c_flush(x.c.c);
    snprintf(b, sizeof b, "%s: the list empties once the peer ends them", tag);
    check(b, 1, PUMP_UNTIL(&x, left_n(&x) == 0 || x.c.closed));
    pump_for(&x, 300);
    snprintf(b, sizeof b, "%s: the list is empty and the link open", tag);
    check(b, 1, left_n(&x) == 0 && !x.c.closed);
    int ended = 0;
    for (int i = 0; i < n; i++) ended += hp_st(&x.p, sid[i])->closed == 1;
    snprintf(b, sizeof b, "%s: the peer closed every stream", tag);
    check(b, n, ended);
    pair_free(&x);
}

static void normal_closes_leave_nothing(void) { burst_round(600, 700, "normal closes"); }

static void a_burst_of_closes_never_cuts_the_node(void) { burst_round(1024, 1100, "burst of 1024 closes"); }

int main(void) {
    g_pat = malloc(2 * MIB);
    for (size_t i = 0; i < 2 * MIB; i++) g_pat[i] = pat(i);
    check("certificates issued", 0, certs_make());
    const char *tx = getenv("QC_TEST_TIME_X");
    if (tx && atoi(tx) > 0) g_tx = (unsigned)atoi(tx);
    const char *env = getenv("QC_TEST_NO_BATCH");
    g_nb = env && !strcmp(env, "1");
    hy2c_credit_hook = credit_hook;
    auth_is_xrays_request();
    the_controller_is_chosen_as_xray_chooses();
    a_wrong_password_reports_the_status_and_closes_with_0x101();
    a_broken_auth_exchange_closes_with_0x101();
    payload_does_not_wait_for_the_response();
    a_refused_stream_surfaces_the_message();
    closing_and_finishing_a_stream_reach_the_peer();
    a_slow_consumer_holds_at_most_the_stream_window();
    unconsumed_bytes_of_closed_streams_do_not_starve_the_connection();
    udp_echoes_whole_and_fragmented();
    a_datagram_for_an_unknown_session_is_dropped();
    salamander_on_both_sides_works_and_a_mismatch_fails_the_handshake();
    a_dead_connection_ends_every_stream_first();
    room_is_announced_to_the_consumer();
    close_reasons_reach_the_consumer();
    closing_with_bytes_in_flight_finishes();
    six_hundred_streams_share_one_session();
    freed_stream_ids_are_announced();
    refused_streams_return_their_tail_credit();
    reassembly_memory_is_bounded();
    a_short_datagram_queue_sends_no_fragment();
    free_is_silent_and_complete();
    peer_stop_ends_only_the_upload();
    a_reset_over_a_gap_gets_no_stop();
    draining_streams_are_bounded();
    a_full_brutal_upload_drains();
    a_capped_brutal_rate_keeps_a_drain_bound();
    a_finished_upload_survives_close();
    udp_ids_wrap_past_live_sessions();
    udp_messages_above_8192_bytes_are_not_sent();
    udp_needs_datagrams_and_the_header();
    the_auth_budget_counts_from_open();
    closed_streams_hear_nothing_when_the_connection_dies();
    a_request_and_its_payload_leave_together();
    many_opens_leave_in_one_flush();
    an_open_needs_no_connection_budget();
    a_close_then_free_still_tells_the_peer();
    keepalive_runs_only_while_flows_are_open();
    a_silent_node_under_flows_is_cut_at_15_s();
    a_hop_onto_a_dead_port_is_cut_by_the_rule();
    a_late_loop_never_cuts_a_healthy_node();
    only_the_node_moves_the_limit();
    the_limit_waits_for_the_unanswered_send_and_no_longer();
    closed_streams_the_peer_never_ends_have_a_time_bound();
    normal_closes_leave_nothing();
    a_burst_of_closes_never_cuts_the_node();
    free(g_pat);
    return unit_done("hy2connmatch");
}
