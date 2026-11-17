#define _GNU_SOURCE
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "../src/proto/transport/trdial.c"
#include "quic.h"
#include "hy2conn.h"
#include "hy2node.h"
#include "hy2link.h"
#include "hy2dial.h"
#include "client.h"
#include "roots.h"
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
#define NS 330
#define NP 3
#define NN 40
#define TOK_PEER 100
#define TOK_LINK 1000
#define CHUNK (TUNNEL_BUF - 2048)
#define HELD_FULL (2097152 - 132)
#define HELD_CAP (4 * (16384 - sizeof(void *) - 8))
#define NEED(p) do { if (!(p)) { end(); return; } } while (0)

static unsigned g_tx = 1;
static int g_nb;
static uint8_t *g_pat;
static unsigned char g_ca[2048], g_leaf[2048], g_key[512];
static size_t g_ca_n, g_leaf_n, g_key_n;
static char g_ca_pem[4096];
static char g_roots[64];

static uint64_t g_credit;
static int peer_q(const struct qc *q);

void __real_qc_stream_consumed(struct qc *q, int64_t sid, size_t n);
void __wrap_qc_stream_consumed(struct qc *q, int64_t sid, size_t n) {
    if (!peer_q(q)) g_credit += n;
    __real_qc_stream_consumed(q, sid, n);
}

void __real_qc_conn_consumed(struct qc *q, size_t n);
void __wrap_qc_conn_consumed(struct qc *q, size_t n) {
    if (!peer_q(q)) g_credit += n;
    __real_qc_conn_consumed(q, n);
}

static int g_fdx;

static void f_fd_extra(int delta) { g_fdx += delta; }

static unsigned g_prep, g_prep_fail_at;
int __real_tr_sock_prepare(int fd);
int __wrap_tr_sock_prepare(int fd) {
    g_prep++;
    if (g_prep_fail_at && g_prep >= g_prep_fail_at) return -1;
    return __real_tr_sock_prepare(fd);
}

struct crec { char ip[46]; uint16_t port; };
static struct crec g_conn[256];
static unsigned g_conn_n;

int __real_connect(int fd, const struct sockaddr *a, socklen_t n);
int __wrap_connect(int fd, const struct sockaddr *a, socklen_t n) {
    int type = 0;
    socklen_t tl = sizeof type;
    if (a && a->sa_family == AF_INET && getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 && type == SOCK_DGRAM &&
        g_conn_n < 256) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)a;
        struct crec *r = &g_conn[g_conn_n++];
        inet_ntop(AF_INET, &s4->sin_addr, r->ip, sizeof r->ip);
        r->port = ntohs(s4->sin_port);
    }
    return __real_connect(fd, a, n);
}

static unsigned conns_to(uint16_t port) {
    unsigned n = 0;
    for (unsigned i = 0; i < g_conn_n; i++) n += g_conn[i].port == port;
    return n;
}

static const char *conn_ip(uint16_t port, unsigned k) {
    for (unsigned i = 0; i < g_conn_n; i++)
        if (g_conn[i].port == port && k-- == 0) return g_conn[i].ip;
    return "";
}

struct wk { uint16_t owner; unsigned what; int rc; };
static struct wk g_wk[16384];
static unsigned g_wk_n;

struct wt { unsigned idx; int fd; unsigned ev; };
static struct wt g_wt[512];
static unsigned g_wt_n;

struct sn { struct xc_ref r; int rc; uint64_t started; };
static struct sn g_sn[64];
static unsigned g_sn_n;

static int g_ep = -1;
static unsigned g_stale_below;
static int g_due;

static int g_room_owner = -1;
static long g_room_at_wake = -1;
static long wake_room(uint16_t owner);

static void f_wake(void *arg, uint16_t owner, unsigned what, int rc) {
    (void)arg;
    if ((what & XW_ROOM) && owner == g_room_owner && g_room_at_wake < 0) g_room_at_wake = wake_room(owner);
    if (g_wk_n < sizeof g_wk / sizeof g_wk[0]) g_wk[g_wk_n++] = (struct wk){ owner, what, rc };
}

static int f_watch(unsigned idx, int fd, unsigned ev) {
    if (g_wt_n < sizeof g_wt / sizeof g_wt[0]) g_wt[g_wt_n++] = (struct wt){ idx, fd, ev };
    if (!ev) return epoll_ctl(g_ep, EPOLL_CTL_DEL, fd, NULL) == 0 ? 0 : -1;
    struct epoll_event e = { .events = ev, .data.u32 = TOK_LINK + idx };
    if (epoll_ctl(g_ep, EPOLL_CTL_MOD, fd, &e) == 0) return 0;
    return epoll_ctl(g_ep, EPOLL_CTL_ADD, fd, &e) == 0 ? 0 : -1;
}

static void f_seen(const struct xc_ref *r, int rc, uint64_t started) {
    if (g_sn_n < sizeof g_sn / sizeof g_sn[0]) g_sn[g_sn_n++] = (struct sn){ *r, rc, started };
}

static int f_stale(const struct xc_ref *r) { return r->gen < g_stale_below; }

static struct mux_host g_h = {
    .watch = f_watch, .wake = f_wake, .loops = 1, .wait_ms = 8000, .idx_base = XC_MAX, .seen = f_seen, .stale = f_stale,
    .fd_extra = f_fd_extra,
};

static unsigned wakes(uint16_t owner, unsigned what) {
    unsigned n = 0;
    for (unsigned i = 0; i < g_wk_n; i++) n += g_wk[i].owner == owner && (g_wk[i].what & what);
    return n;
}

static int wake_rc(uint16_t owner, unsigned what) {
    int rc = 1;
    for (unsigned i = 0; i < g_wk_n; i++)
        if (g_wk[i].owner == owner && (g_wk[i].what & what)) rc = g_wk[i].rc;
    return rc;
}

static unsigned watch_adds(void) {
    unsigned n = 0;
    for (unsigned i = 0; i < g_wt_n; i++) n += g_wt[i].ev != 0;
    return n;
}

static int watch_off(unsigned idx) {
    for (unsigned i = 0; i < g_wt_n; i++)
        if (g_wt[i].idx == idx && !g_wt[i].ev) return 1;
    return 0;
}

static unsigned last_link(void) {
    for (unsigned i = g_wt_n; i-- > 0;)
        if (g_wt[i].ev) return g_wt[i].idx - XC_MAX;
    return 0;
}

static struct hy2peer g_p[NP];
static int g_p_on[NP];

static size_t g_dgmax = 1200;
static uint64_t g_peer_msd;

static int g_follow;

static uint16_t peer_start_cfg(int k, uint16_t port, uint64_t max_streams) {
    hp_init(&g_p[k], g_pat);
    g_p[k].follow_peer = g_follow;
    struct qc_srv_cfg sc;
    memset(&sc, 0, sizeof sc);
    sc.bind_host = "127.0.0.1";
    sc.port = port;
    sc.alpn = "h3";
    sc.cert_der = g_leaf;
    sc.cert_n = g_leaf_n;
    sc.key_der = g_key;
    sc.key_n = g_key_n;
    sc.no_batch = g_nb;
    sc.datagram_max = g_dgmax;
    sc.max_streams = max_streams;
    sc.max_stream_data = g_peer_msd;
    if (hp_listen(&g_p[k], &sc) != 0) return 0;
    struct epoll_event e = { .events = EPOLLIN, .data.u32 = TOK_PEER + (unsigned)k };
    if (epoll_ctl(g_ep, EPOLL_CTL_ADD, qc_fd(g_p[k].q), &e) != 0) return 0;
    g_p_on[k] = 1;
    return qc_local_port(g_p[k].q);
}

static int peer_q(const struct qc *q) {
    for (int k = 0; k < NP; k++)
        if (g_p_on[k] && g_p[k].q == q) return 1;
    return 0;
}

static uint16_t peer_start(int k, uint16_t port) { return peer_start_cfg(k, port, 0); }

static void peer_stop(int k) {
    if (!g_p_on[k]) return;
    epoll_ctl(g_ep, EPOLL_CTL_DEL, qc_fd(g_p[k].q), NULL);
    hp_free(&g_p[k]);
    g_p_on[k] = 0;
}

static struct hp_st *peer_st(int k, const char *addr) {
    for (int i = 0; i < HP_MAXST; i++)
        if (g_p[k].st[i].used && g_p[k].st[i].parsed == 1 && !strcmp(g_p[k].st[i].addr, addr)) return &g_p[k].st[i];
    return NULL;
}

static struct hp_st *peer_sid(int k, int64_t sid) {
    for (int i = 0; i < HP_MAXST; i++)
        if (g_p[k].st[i].used && g_p[k].st[i].sid == sid) return &g_p[k].st[i];
    return NULL;
}

struct sink {
    uint8_t *b;
    size_t n, cap;
    unsigned dgrams;
    size_t last;
    int end, auto_rd;
};

static struct hy2_sess g_s[NS];
static struct flow_key g_k[NS];
static struct sink g_sk[NS];
static int g_used[NS];
static const struct vless_node *g_fnode[NS];

static int emit(void *arg, const unsigned char *p, size_t n) {
    struct sink *k = arg;
    if (k->n + n > k->cap) {
        size_t cap = (k->n + n) * 2 + 4096;
        uint8_t *x = realloc(k->b, cap);
        if (!x) return -1;
        k->b = x;
        k->cap = cap;
    }
    memcpy(k->b + k->n, p, n);
    k->n += n;
    k->dgrams++;
    k->last = n;
    return 0;
}

static size_t rd(int i, size_t max) {
    size_t total = 0;
    unsigned char buf[TUNNEL_BUF];
    for (int k = 0; k < 4096 && total < max && hy2_dialer.has_data(&g_s[i]); k++) {
        const unsigned char *d = buf;
        size_t got = 0, cap = max - total < sizeof buf ? max - total : sizeof buf;
        int rc = hy2_dialer.read(&g_s[i], buf, cap, &d, &got);
        if (rc) {
            g_sk[i].end = rc;
            break;
        }
        if (!got) break;
        if (hy2_dialer.deliver(g_fnode[i], &g_s[i], g_s[i].udp, d, got, emit, &g_sk[i]) != 0) {
            g_sk[i].end = -1000;
            break;
        }
        total += got;
    }
    return total;
}

static void pass_to(int late) {
    int t = 20;
    if (g_due > 0 && g_due < t) t = g_due;
    for (int k = 0; k < NP; k++)
        if (g_p_on[k] && !g_p[k].closed) {
            int x = qc_timeout_ms(g_p[k].q);
            if (x >= 0 && x < t) t = x;
        }
    struct epoll_event ev[64];
    int n = epoll_wait(g_ep, ev, 64, t);
    hy2_mux.pass(ms_now(), MUXP_EARLY);
    for (int i = 0; i < n; i++) {
        uint32_t tok = ev[i].data.u32;
        if (tok >= TOK_LINK) {
            hy2_mux.event(tok - TOK_LINK - XC_MAX, ev[i].events);
        } else if (tok >= TOK_PEER && tok < TOK_PEER + NP) {
            int k = (int)(tok - TOK_PEER);
            if (g_p_on[k] && !g_p[k].closed) (void)qc_on_readable(g_p[k].q);
        }
    }
    for (int k = 0; k < NP; k++) {
        if (!g_p_on[k]) continue;
        if (!g_p[k].closed && qc_timeout_ms(g_p[k].q) == 0) (void)qc_on_timer(g_p[k].q);
        hp_drain(&g_p[k]);
        qc_flush(g_p[k].q);
    }
    for (int i = 0; i < NS; i++)
        if (g_used[i] && g_sk[i].auto_rd) rd(i, (size_t)-1);
    if (late) g_due = hy2_mux.pass(ms_now(), MUXP_LATE);
}

static void pass(void) { pass_to(1); }

#define PUMP_UNTIL(cond) ({ uint64_t e_ = ms_now() + 10000ull * g_tx; while (!(cond) && ms_now() < e_) pass(); (cond) ? 1 : 0; })

static void pump_for(unsigned ms) {
    uint64_t e = ms_now() + (uint64_t)ms * g_tx;
    while (ms_now() < e) pass();
}

static uint32_t g_script[16];
static unsigned g_script_n;

static uint32_t script_rand(void) {
    return g_script[g_script_n++ % 16];
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

static int fl_open(int i, const struct vless_node *n, const char *ip, uint16_t port, int udp) {
    struct flow_key *k = &g_k[i];
    memset(k, 0, sizeof *k);
    if (inet_pton(AF_INET6, ip, k->dst.b) == 1) k->v6 = 1;
    else inet_pton(AF_INET, ip, k->dst.b);
    k->dport = port;
    k->sport = (uint16_t)(40000 + i);
    k->proto = udp ? 17 : 6;
    free(g_sk[i].b);
    memset(&g_sk[i], 0, sizeof g_sk[i]);
    hy2_dialer.clear(&g_s[i]);
    g_used[i] = 1;
    g_fnode[i] = n;
    return hy2_dialer.flow_open(n, &g_s[i], k, udp);
}

static int fl_attach(int i, unsigned gen) {
    struct xc_ref r = { g_fnode[i], 0, gen };
    return hy2_mux.attach(g_fnode[i], &g_s[i], (uint16_t)i, &r);
}

static int fl_send(int i, const uint8_t *d, size_t n) {
    return hy2_dialer.send(g_fnode[i], &g_s[i], &g_k[i], g_s[i].udp, d, n);
}

static long fl_room(int i) { return hy2_dialer.room(g_fnode[i], &g_s[i]); }

static long wake_room(uint16_t owner) { return fl_room(owner); }

static int fl_dgram(int i, const uint8_t *d, size_t n) {
    unsigned char out[UDP_DGRAM_MAX + 64];
    size_t fn = hy2_dialer.dgram_frame(g_fnode[i], &g_s[i], d, n, out, sizeof out);
    if (!fn) return -100;
    return fl_send(i, out, fn);
}

static void fl_close(int i) {
    if (!g_used[i]) return;
    hy2_dialer.close(&g_s[i]);
    hy2_dialer.clear(&g_s[i]);
    g_used[i] = 0;
}

static int why_has(int i, int rc, const char *what) {
    const char *w = hy2_dialer.why(&g_s[i], rc);
    return g_s[i].why_rc == rc && w && strstr(w, what) != NULL;
}

static int ready_flow(int i, const struct vless_node *n, const char *ip, uint16_t port, int udp) {
    if (fl_open(i, n, ip, port, udp) != 0) return -1;
    unsigned before = wakes((uint16_t)i, XW_DONE);
    int a = fl_attach(i, 0);
    if (a == XA_READY) return 0;
    if (a != XA_WAIT) return -2;
    if (!PUMP_UNTIL(wakes((uint16_t)i, XW_DONE) > before)) return -3;
    return wake_rc((uint16_t)i, XW_DONE);
}

static int send_all(int i, const uint8_t *d, size_t n) {
    size_t off = 0;
    uint64_t e = ms_now() + 10000ull * g_tx;
    while (off < n && ms_now() < e) {
        size_t c = n - off < CHUNK ? n - off : CHUNK;
        long room = fl_room(i);
        if (room >= 0 && (size_t)room < c) {
            pass();
            continue;
        }
        int sr = fl_send(i, d + off, c);
        if (sr == SEND_FATAL) return -1;
        if (sr == SEND_OK) off += c;
        else pass();
    }
    return off == n ? 0 : -2;
}

static void begin(void) {
    g_ep = epoll_create1(EPOLL_CLOEXEC);
    g_wk_n = g_wt_n = g_sn_n = 0;
    g_conn_n = 0;
    g_prep = g_prep_fail_at = 0;
    g_stale_below = 0;
    g_due = 0;
    g_room_owner = -1;
    g_room_at_wake = -1;
    hy2_mux.host(&g_h);
    hy2_mux.pass(ms_now(), MUXP_EARLY);
}

static void end(void) {
    for (int i = 0; i < NS; i++) fl_close(i);
    hy2_mux.pass(ms_now(), MUXP_LATE);
    hy2_mux.pass(ms_now(), MUXP_EXIT);
    for (int k = 0; k < NP; k++) peer_stop(k);
    for (int i = 0; i < NS; i++) {
        free(g_sk[i].b);
        memset(&g_sk[i], 0, sizeof g_sk[i]);
    }
    close(g_ep);
    g_ep = -1;
}

static uint16_t silent_bind(const char *ip, int *fd) {
    *fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = { .sin_family = AF_INET };
    inet_pton(AF_INET, ip, &a.sin_addr);
    socklen_t al = sizeof a;
    if (*fd < 0 || bind(*fd, (struct sockaddr *)&a, sizeof a) != 0 ||
        getsockname(*fd, (struct sockaddr *)&a, &al) != 0) return 0;
    return ntohs(a.sin_port);
}

static unsigned dgrams_waiting(int fd) {
    unsigned n = 0;
    uint8_t b[2048];
    while (recv(fd, b, sizeof b, MSG_DONTWAIT) >= 0) n++;
    return n;
}

static int peers_closed_without_a_pass(int a, int b) {
    uint64_t e = ms_now() + 10000ull * g_tx;
    while (!(g_p[a].closed && g_p[b].closed) && ms_now() < e) {
        struct pollfd pf[2] = { { qc_fd(g_p[a].q), POLLIN, 0 }, { qc_fd(g_p[b].q), POLLIN, 0 } };
        if (poll(pf, 2, 20) <= 0) continue;
        if (!g_p[a].closed) (void)qc_on_readable(g_p[a].q);
        if (!g_p[b].closed) (void)qc_on_readable(g_p[b].q);
    }
    return g_p[a].closed && g_p[b].closed;
}

static void a_stop_closes_every_ready_link_and_no_dialling_one(void) {
    begin();
    uint16_t p0 = peer_start(0, 0), p1 = peer_start(1, 0);
    int fd;
    uint16_t ps = silent_bind("127.0.0.1", &fd);
    static struct vless_node a, b, c;
    node_make(&a, "127.0.0.1", p0);
    node_make(&b, "127.0.0.1", p1);
    node_make(&c, "127.0.0.1", ps);
    check("stop pass: the link to A is ready", 0, ready_flow(1, &a, "10.0.0.1", 80, 0));
    check("stop pass: the link to B is ready", 0, ready_flow(2, &b, "10.0.0.2", 80, 0));
    fl_open(3, &c, "10.0.0.3", 80, 0);
    check("stop pass: the link to C dials", XA_WAIT, fl_attach(3, 0));
    check("stop pass: C has the dial's first datagram", 1, dgrams_waiting(fd) > 0);
    check("stop pass: neither peer has a close yet", 0, g_p[0].closed + g_p[1].closed);
    hy2_mux.stop();
    check("stop pass: nothing goes to the dialling C", 0, dgrams_waiting(fd));
    check("stop pass: A and B see a close before any later pass", 1, peers_closed_without_a_pass(0, 1));
    check("stop pass: A's is the application's 0x100", 1, g_p[0].app == 1 && g_p[0].code == 0x100);
    check("stop pass: B's is the application's 0x100", 1, g_p[1].app == 1 && g_p[1].code == 0x100);
    end();
    close(fd);
}

static void attach_waits_and_ready_wakes_every_waiter(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    uint64_t t0 = ms_now();
    hy2_mux.pass(t0, MUXP_EARLY);
    int w = 0;
    for (int i = 1; i <= 3; i++) {
        fl_open(i, &n, "10.0.0.1", 80, 0);
        w += fl_attach(i, 0) == XA_WAIT;
    }
    check("waiters: three attaches wait", 3, w);
    check("waiters: one connection to the node", 1, conns_to(port));
    check("waiters: every waiter woken", 1,
          PUMP_UNTIL(wakes(1, XW_DONE) && wakes(2, XW_DONE) && wakes(3, XW_DONE)));
    pump_for(100);
    for (uint16_t i = 1; i <= 3; i++) {
        char b[96];
        snprintf(b, sizeof b, "waiters: owner %u woken once with rc 0", i);
        check(b, 1, wakes(i, XW_DONE) == 1 && wake_rc(i, XW_DONE) == 0);
    }
    check("waiters: one seen", 1, g_sn_n);
    check("waiters: seen rc 0, its node, the dial's start", 1,
          g_sn_n == 1 && g_sn[0].rc == 0 && g_sn[0].r.node == &n && g_sn[0].started == t0);
    fl_open(4, &n, "10.0.0.1", 80, 0);
    check("waiters: a fourth attach is ready at once", XA_READY, fl_attach(4, 0));
    check("waiters: still one connection", 1, conns_to(port));
    check("waiters: the link was watched past idx_base", 1, g_wt_n > 0 && g_wt[0].idx >= XC_MAX && g_wt[0].ev == EPOLLIN);
    end();
}

static unsigned g_stub_calls;

static unsigned two_addrs(const char *host, struct tr_ip out[ADDR_MAX]) {
    g_stub_calls++;
    if (strcmp(host, "r.test")) return 0;
    memset(out, 0, 2 * sizeof out[0]);
    inet_pton(AF_INET, "127.0.0.2", out[0].b);
    inet_pton(AF_INET, "127.0.0.1", out[1].b);
    return 2;
}

static void a_failed_dial_wakes_waiters_with_the_reason(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    n.auth = "wrong";
    fl_open(1, &n, "10.0.0.1", 80, 0);
    fl_open(2, &n, "10.0.0.2", 80, 0);
    check("wrong password: both wait", 1, fl_attach(1, 0) == XA_WAIT && fl_attach(2, 0) == XA_WAIT);
    check("wrong password: both woken", 1, PUMP_UNTIL(wakes(1, XW_DONE) && wakes(2, XW_DONE)));
    check("wrong password: owner 1 gets HY2_EDIAL", HY2_EDIAL, wake_rc(1, XW_DONE));
    check("wrong password: owner 2 gets HY2_EDIAL", HY2_EDIAL, wake_rc(2, XW_DONE));
    check("wrong password: why names the status", 1,
          why_has(1, HY2_EDIAL, "auth failed code 404") && why_has(2, HY2_EDIAL, "auth failed code 404"));
    check("wrong password: one seen with HY2_EDIAL", 1, g_sn_n == 1 && g_sn[0].rc == HY2_EDIAL);
    unsigned adds = watch_adds();
    fl_open(3, &n, "10.0.0.3", 80, 0);
    check("wrong password: the next attach dials again", XA_WAIT, fl_attach(3, 0));
    check("wrong password: a new link is watched", adds + 1, watch_adds());
    check("wrong password: a second connection", 2, conns_to(port));
    end();

    begin();
    g_resolve = two_addrs;
    port = peer_start(0, 0);
    check("two addresses: the name is pinned with two", 2, transport_pin_host("r.test"));
    node_make(&n, "r.test", port);
    fl_open(1, &n, "10.0.0.1", 80, 0);
    check("two addresses: first attach waits", XA_WAIT, fl_attach(1, 0));
    check("two addresses: the refusing address fails the dial", 1, PUMP_UNTIL(wakes(1, XW_DONE)));
    check("two addresses: with HY2_EDIAL", HY2_EDIAL, wake_rc(1, XW_DONE));
    check_str("two addresses: the first dial went to the first address", "127.0.0.2", conn_ip(port, 0));
    fl_open(2, &n, "10.0.0.1", 80, 0);
    check("two addresses: second attach waits", XA_WAIT, fl_attach(2, 0));
    check("two addresses: the second dial is ready", 1, PUMP_UNTIL(wakes(2, XW_DONE)));
    check("two addresses: with rc 0", 0, wake_rc(2, XW_DONE));
    check_str("two addresses: the second dial went to the second address", "127.0.0.1", conn_ip(port, 1));
    end();

    begin();
    g_stub_calls = 0;
    node_make(&n, "u.test", 443);
    fl_open(1, &n, "10.0.0.1", 80, 0);
    int a = fl_attach(1, 0);
    check("unpinned name: the attach fails at once", HY2_EDIAL, a);
    check("unpinned name: the loop thread resolved nothing", 0, g_stub_calls);
    check("unpinned name: no socket was watched", 0, watch_adds());
    check("unpinned name: why names the host", 1, why_has(1, HY2_EDIAL, "u.test"));
    g_resolve = resolve;
    end();
}

static void a_waiter_closed_before_ready_is_not_woken(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    int w = 0;
    for (int i = 5; i <= 7; i++) {
        fl_open(i, &n, "10.0.0.1", 80, 0);
        w += fl_attach(i, 0) == XA_WAIT;
    }
    check("closed waiter: three wait", 3, w);
    fl_close(5);
    check("closed waiter: 6 and 7 woken", 1, PUMP_UNTIL(wakes(6, XW_DONE) && wakes(7, XW_DONE)));
    pump_for(100);
    check("closed waiter: 5 never woken", 0, wakes(5, XW_DONE | XW_READ | XW_ROOM));
    uint16_t p2 = peer_start(1, 0);
    struct vless_node m;
    node_make(&m, "127.0.0.1", p2);
    fl_open(8, &m, "10.0.0.1", 80, 0);
    fl_open(9, &m, "10.0.0.1", 80, 0);
    check("reused owner: 8 and 9 wait", 1, fl_attach(8, 0) == XA_WAIT && fl_attach(9, 0) == XA_WAIT);
    fl_close(8);
    fl_open(8, &m, "10.0.0.2", 80, 0);
    check("reused owner: a new flow in slot 8 waits", XA_WAIT, fl_attach(8, 0));
    check("reused owner: both woken", 1, PUMP_UNTIL(wakes(8, XW_DONE) && wakes(9, XW_DONE)));
    pump_for(100);
    check("reused owner: 8 hears only its own ready", 1, wakes(8, XW_DONE) == 1 && wake_rc(8, XW_DONE) == 0);
    check("reused owner: 9 once", 1, wakes(9, XW_DONE));
    end();
}

static void links_per_loop_are_bounded(void) {
    begin();
    int fd;
    uint16_t port = silent_bind("127.0.0.1", &fd);
    static struct vless_node n[33];
    int w = 0;
    for (int i = 0; i < 32; i++) {
        node_make(&n[i], "127.0.0.1", port);
        fl_open(i, &n[i], "10.0.0.1", 80, 0);
        w += fl_attach(i, 0) == XA_WAIT;
    }
    check("links: 32 nodes wait on 32 links", 32, w);
    check("links: 32 sockets watched", 32, watch_adds());
    node_make(&n[32], "127.0.0.1", port);
    fl_open(32, &n[32], "10.0.0.1", 80, 0);
    check("links: the 33rd is refused", HY2_ELINKS, fl_attach(32, 0));
    check("links: no 33rd socket", 32, watch_adds());
    const char *e1 = hy2_dialer.strerror(HY2_ELINKS), *e2 = hy2_dialer.strerror(HY2_EDIAL),
               *e3 = hy2_dialer.strerror(HY2_ENOUDP), *e5 = hy2_dialer.strerror(TR_ENONODE),
               *e6 = hy2_dialer.strerror(-12345);
    check("links: every code has its own text", 1,
          strcmp(e1, e6) && strcmp(e2, e6) && strcmp(e3, e6) && strcmp(e5, e6) && strcmp(e1, e2) && strcmp(e2, e3));
    const char *vn = vless_strerror(-12345);
    check("links: no code of the shared attach path means a dialer code", 1,
          !strcmp(vless_strerror(HY2_ELINKS), vn) && !strcmp(vless_strerror(HY2_EDIAL), vn) &&
              !strcmp(vless_strerror(HY2_ENOUDP), vn));
    check("links: the link text says links", 1, strstr(e1, "link") != NULL);
    int crc = hy2_dialer.connect(&n[0], &g_s[40], 8);
    check("links: connect fails with a named code", 1, crc < 0 && strcmp(hy2_dialer.strerror(crc), e6));
    end();
    close(fd);
}

static void a_dead_link_is_freed_outside_callbacks_and_redialed(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("dead link: flow 1 ready", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    check("dead link: flow 2 ready", 0, ready_flow(2, &n, "10.0.0.2", 80, 0));
    check("dead link: both streams open", 1,
          fl_send(1, NULL, 0) == SEND_OK && fl_send(2, NULL, 0) == SEND_OK &&
              PUMP_UNTIL(peer_st(0, "10.0.0.1:80") && peer_st(0, "10.0.0.2:80")));
    unsigned li = last_link();
    qc_close(g_p[0].q, 0x100);
    qc_flush(g_p[0].q);
    check("dead link: the fd leaves epoll", 1, PUMP_UNTIL(watch_off(XC_MAX + li)));
    check("dead link: the slot is free", 1, hy2d_link_conn(li) == NULL);
    check("dead link: the node's own close is no failure", 1, g_sn_n == 1 && g_sn[0].rc == 0);
    fl_close(1);
    fl_close(2);
    peer_stop(0);
    check("dead link: a fresh peer on the port", port, peer_start(0, port));
    check("dead link: the next flow dials a new link", 0, ready_flow(3, &n, "10.0.0.3", 80, 0));
    check("dead link: two connections in all", 2, conns_to(port));
    end();
}

#define LIVE_F 1000000000000000ull
#define LIVE_MS(n) (LIVE_F + (uint64_t)(n) * 1000000ull)

static void a_silence_cut_is_reported_as_a_failed_dial(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("silence cut: flow ready", 0, ready_flow(1, &n, "10.0.0.95", 80, 0));
    g_sk[1].auto_rd = 1;
    check("silence cut: 100 bytes go", SEND_OK, fl_send(1, g_pat, 100));
    check("silence cut: and come back", 1, PUMP_UNTIL(g_sk[1].n == 100));
    struct hy2c *c = hy2d_link_conn(last_link());
    NEED(c);
    hy2c_clock_set(c, LIVE_MS(0));
    check("silence cut: 100 more go", SEND_OK, fl_send(1, g_pat, 100));
    check("silence cut: and come back on the frozen clock", 1, PUMP_UNTIL(g_sk[1].n == 200));
    pump_for(200);
    check("silence cut: so far only the ready is seen", 1, g_sn_n == 1 && g_sn[0].rc == 0);
    g_p[0].drop = HP_DROP_ALL;
    hy2c_clock_set(c, LIVE_MS(1000));
    check("silence cut: a send at +1000", SEND_OK, fl_send(1, g_pat, 100));
    pump_for(200);
    uint64_t t0 = ms_now();
    hy2c_clock_set(c, LIVE_MS(12500));
    (void)hy2c_on_timer(c);
    hy2c_flush(c);
    hy2c_clock_set(c, LIVE_MS(15001));
    (void)hy2c_on_timer(c);
    hy2c_flush(c);
    check("silence cut: the link is cut", 1, PUMP_UNTIL(g_sk[1].end != 0));
    check("silence cut: as a link loss", 1, hy2_mux.cut(&g_s[1]));
    check("silence cut: the pool hears a failure", 2, (long)g_sn_n);
    check("silence cut: as a failed dial, its node, timed at the cut", 1,
          g_sn_n == 2 && g_sn[1].rc == HY2_EDIAL && g_sn[1].r.node == &n && g_sn[1].started >= t0);
    end();
}

static FILE *g_errf;
static int g_err_keep = -1;
static char g_err[65536];

static void err_open(void) {
    fflush(stderr);
    g_errf = tmpfile();
    g_err_keep = dup(2);
    if (g_errf) dup2(fileno(g_errf), 2);
}

static const char *err_close(void) {
    fflush(stderr);
    dup2(g_err_keep, 2);
    close(g_err_keep);
    g_err_keep = -1;
    g_err[0] = 0;
    if (!g_errf) return g_err;
    rewind(g_errf);
    size_t n = fread(g_err, 1, sizeof g_err - 1, g_errf);
    g_err[n] = 0;
    fclose(g_errf);
    g_errf = NULL;
    return g_err;
}

static unsigned err_lines(const char *e, const char *line, int whole) {
    unsigned n = 0;
    size_t ln = strlen(line);
    for (const char *p = e; *p;) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (whole ? len == ln && !memcmp(p, line, ln) : memmem(p, len, line, ln) != NULL) n++;
        p += len + (nl ? 1 : 0);
    }
    return n;
}

static unsigned g_ready_mode;

static void ready_line_round(const char *name, const char *shown, const char *qp, const char *rx, const char *want_tail) {
    begin();
    uint16_t port = peer_start(0, 0);
    if (rx) {
        g_p[0].auth_mode = HP_AUTH_RX;
        g_p[0].rx_answer = rx;
    }
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    snprintf(n.name, sizeof n.name, "%s", name);
    n.qp = qp;
    n.hop_mode = (uint8_t)g_ready_mode;
    char b[400], want[400];
    snprintf(want, sizeof want, "tunvless[info]: hysteria2 %s: link ready on port %u, %s", shown, port, want_tail);
    err_open();
    int rc = ready_flow(1, &n, "10.0.0.1", 80, 0);
    const char *e = err_close();
    snprintf(b, sizeof b, "ready line %s: the flow is ready", want_tail);
    check(b, 0, rc);
    snprintf(b, sizeof b, "ready line %s: exactly the line", want_tail);
    check(b, 1, err_lines(e, want, 1));
    snprintf(b, sizeof b, "ready line %s: no other line of the node", want_tail);
    check(b, 1, err_lines(e, ": link ", 0));
    end();
}

static void a_ready_link_says_how_it_sends(void) {
    ready_line_round("N1", "N1", "{\"brutalUp\":\"100 mbps\",\"brutalDown\":\"50 mbps\",\"disableGSO\":true}", "10000000",
                     "up brutal 10000000 B/s, down asked 6553600 B/s, not applied: disableGSO");
    ready_line_round("N1", "N1", "{\"initConnectionReceiveWindow\":1048576}", NULL,
                     "up bbr, down asked nothing, not applied: initConnectionReceiveWindow");
    ready_line_round("N1", "N1", "{\"maxStreamReceiveWindow\":1048576}", NULL,
                     "up bbr, down asked nothing, not applied: maxStreamReceiveWindow");
    ready_line_round("N1", "N1", NULL, NULL, "up bbr, down asked nothing");
    ready_line_round("a\nb", "a b", NULL, NULL, "up bbr, down asked nothing");
    ready_line_round("N1", "N1", "{\"congestion\":\"reno\",\"brutalDown\":\"40 mbps\"}", NULL, "up reno, down asked 5242880 B/s");
    ready_line_round("N1", "N1",
                     "{\"maxConnectionReceiveWindow\":67108864,\"debug\":true,\"maxIdleTimeout\":60,"
                     "\"initStreamReceiveWindow\":1048576,\"maxIncomingStreams\":64,\"bbrProfile\":\"aggressive\","
                     "\"disableStatelessReset\":true,\"disableGSO\":true}",
                     NULL,
                     "up bbr, down asked nothing, not applied: bbrProfile, debug, initStreamReceiveWindow, "
                     "maxConnectionReceiveWindow, maxIdleTimeout, disableGSO, maxIncomingStreams, disableStatelessReset");
    g_ready_mode = HY2_HOP_REMOTE | HY2_HOP_IPS;
    ready_line_round("N1", "N1", NULL, NULL, "up bbr, down asked nothing, not applied: remoteIPs");
    ready_line_round("N1", "N1", "{\"disableGSO\":true,\"bbrProfile\":\"aggressive\"}", NULL,
                     "up bbr, down asked nothing, not applied: bbrProfile, disableGSO, remoteIPs");
    g_ready_mode = HY2_HOP_REMOTE;
    ready_line_round("N1", "N1", NULL, NULL, "up bbr, down asked nothing");
    g_ready_mode = 0;
    begin();
    uint16_t port = peer_start(0, 0);
    uint16_t other = peer_start(1, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    snprintf(n.name, sizeof n.name, "N2");
    snprintf(n.ports, sizeof n.ports, "%u,%u", port, other);
    n.hop_mode = HY2_HOP_LOCAL | HY2_HOP_REMOTE;
    g_script[0] = g_script[1] = 0;
    g_script[2] = 1;
    g_script_n = 0;
    uint32_t (*saved)(void) = g_hy2_rand;
    g_hy2_rand = script_rand;
    char want[200], want2[200];
    snprintf(want, sizeof want, "tunvless[info]: hysteria2 N2: link ready on port %u, up bbr, down asked nothing", port);
    snprintf(want2, sizeof want2, "tunvless[info]: hysteria2 N2: link ready on port %u, up bbr, down asked nothing", other);
    err_open();
    int r1 = ready_flow(1, &n, "10.0.0.1", 80, 0);
    unsigned li = last_link();
    if (g_p[0].q) {
        qc_close(g_p[0].q, 0x100);
        qc_flush(g_p[0].q);
    }
    int off = PUMP_UNTIL(watch_off(XC_MAX + li));
    fl_close(1);
    int r2 = ready_flow(2, &n, "10.0.0.2", 80, 0);
    pump_for(200);
    const char *e = err_close();
    g_hy2_rand = saved;
    check("ready line twice: both dials ready", 1, r1 == 0 && off && r2 == 0);
    check("ready line twice: one connection to each port", 2, conns_to(port) + conns_to(other));
    check("ready line twice: the second dial went to the other port", 1, conns_to(port) == 1 && conns_to(other) == 1);
    check("ready line twice: the first port is printed", 1, err_lines(e, want, 1));
    check("ready line twice: the second port is not printed again", 0, err_lines(e, want2, 1));
    check("ready line twice: one ready line in all", 1, err_lines(e, ": link ready", 0));
    end();
}

static void a_cut_link_is_named_once(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    snprintf(n.name, sizeof n.name, "N1");
    err_open();
    int r = ready_flow(1, &n, "10.0.0.95", 80, 0);
    g_sk[1].auto_rd = 1;
    int echo = r == 0 && fl_send(1, g_pat, 100) == SEND_OK && PUMP_UNTIL(g_sk[1].n == 100);
    unsigned li = last_link();
    struct hy2c *c = hy2d_link_conn(li);
    int cut = 0, off = 0;
    if (c) {
        hy2c_clock_set(c, LIVE_MS(0));
        echo = echo && fl_send(1, g_pat, 100) == SEND_OK && PUMP_UNTIL(g_sk[1].n == 200);
        pump_for(200);
        g_p[0].drop = HP_DROP_ALL;
        hy2c_clock_set(c, LIVE_MS(1000));
        fl_send(1, g_pat, 100);
        pump_for(200);
        hy2c_clock_set(c, LIVE_MS(12500));
        (void)hy2c_on_timer(c);
        hy2c_flush(c);
        hy2c_clock_set(c, LIVE_MS(15001));
        (void)hy2c_on_timer(c);
        hy2c_flush(c);
        cut = PUMP_UNTIL(g_sk[1].end != 0);
        off = PUMP_UNTIL(watch_off(XC_MAX + li));
        pump_for(200);
    }
    const char *e = err_close();
    check("cut line: a ready link with a flow", 1, echo);
    check("cut line: the link is cut and freed", 1, cut && off);
    check("cut line: exactly the line", 1, err_lines(e, "tunvless[warn]: hysteria2 N1: link cut: the node stopped answering", 1));
    check("cut line: once", 1, err_lines(e, "link cut", 0));
    end();
    begin();
    port = peer_start(0, 0);
    node_make(&n, "127.0.0.1", port);
    snprintf(n.name, sizeof n.name, "N1");
    err_open();
    r = ready_flow(1, &n, "10.0.0.1", 80, 0);
    li = last_link();
    if (g_p[0].q) {
        qc_close(g_p[0].q, 0x100);
        qc_flush(g_p[0].q);
    }
    off = PUMP_UNTIL(watch_off(XC_MAX + li));
    pump_for(200);
    e = err_close();
    check("cut line: a peer close ends the link", 1, r == 0 && off);
    check("cut line: a peer close is no cut", 0, err_lines(e, "link cut", 0));
    end();
    begin();
    port = peer_start(0, 0);
    node_make(&n, "127.0.0.1", port);
    snprintf(n.name, sizeof n.name, "N1");
    err_open();
    r = ready_flow(1, &n, "10.0.0.1", 80, 0);
    li = last_link();
    g_stale_below = 1;
    fl_close(1);
    off = PUMP_UNTIL(watch_off(XC_MAX + li));
    pump_for(200);
    e = err_close();
    check("cut line: the dialer closes a stale link", 1, r == 0 && off && g_sn_n == 1);
    check("cut line: its own close is no cut", 0, err_lines(e, "link cut", 0));
    end();
    begin();
    port = peer_start(0, 0);
    node_make(&n, "127.0.0.1", port);
    snprintf(n.name, sizeof n.name, "N1");
    n.qp = "{\"disableChromeParrot\":true,\"maxIdleTimeout\":4}";
    err_open();
    r = ready_flow(1, &n, "10.0.0.1", 80, 0);
    li = last_link();
    fl_close(1);
    off = PUMP_UNTIL(watch_off(XC_MAX + li));
    pump_for(200);
    e = err_close();
    check("cut line: an idle link closes", 1, r == 0 && off && g_sn_n == 1);
    check("cut line: an idle close is no cut", 0, err_lines(e, "link cut", 0));
    end();
}

static void one_prepared_socket_per_link(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node a, b;
    node_make(&a, "127.0.0.1", port);
    for (int i = 1; i <= 3; i++) ready_flow(i, &a, "10.0.0.1", 80, 0);
    check("prepare: three flows, one link, one call", 1, g_prep);
    int fd;
    uint16_t sp = silent_bind("127.0.0.1", &fd);
    node_make(&b, "127.0.0.1", sp);
    fl_open(4, &b, "10.0.0.1", 80, 0);
    fl_open(5, &b, "10.0.0.1", 80, 0);
    check("prepare: two flows to a second node wait", 1, fl_attach(4, 0) == XA_WAIT && fl_attach(5, 0) == XA_WAIT);
    check("prepare: two links, two calls", 2, g_prep);
    end();
    close(fd);
}

static void a_hopping_link_charges_its_fds_until_freed(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    g_fdx = 0;
    check("fd charge: a plain link is ready", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    check("fd charge: a plain link charges nothing", 0, g_fdx);
    end();
    begin();
    port = peer_start(0, 0);
    node_make(&n, "127.0.0.1", port);
    snprintf(n.ports, sizeof n.ports, "%u", port);
    n.hop_mode = HY2_HOP_LOCAL | HY2_HOP_REMOTE;
    check("fd charge: a hopping link is ready", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    check("fd charge: a hopping link charges three", 3, g_fdx);
    unsigned li = last_link();
    qc_close(g_p[0].q, 0x100);
    qc_flush(g_p[0].q);
    check("fd charge: the link is freed", 1, PUMP_UNTIL(watch_off(XC_MAX + li)));
    check("fd charge: given back when it is freed", 0, g_fdx);
    end();
    check("fd charge: nothing left after the end", 0, g_fdx);
    begin();
    port = peer_start(0, 0);
    node_make(&n, "127.0.0.1", port);
    snprintf(n.ports, sizeof n.ports, "%u", port);
    n.hop_mode = HY2_HOP_REMOTE;
    check("fd charge: a remote mode with one port is ready", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    check("fd charge: a remote mode with one port has nothing to hop to", 0, g_fdx);
    end();
}

static void a_hopping_link_prepares_a_socket_per_hop(void) {
    uint32_t (*saved)(void) = g_hy2_rand;
    g_hy2_rand = script_rand;
    g_follow = 1;
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    snprintf(n.ports, sizeof n.ports, "%u", port);
    n.hop_mode = HY2_HOP_LOCAL | HY2_HOP_REMOTE;
    g_fdx = 0;
    g_script_n = 0;
    check("hop prepare: a hopping link is ready", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    check("hop prepare: one call for the first socket", 1, g_prep);
    check("hop prepare: three fds charged at the dial", 3, g_fdx);
    struct hy2c *c = hy2d_link_conn(last_link());
    if (c) hy2c_hop_now(c);
    check("hop prepare: a hop prepares its socket", 2, g_prep);
    struct qc_stats st;
    memset(&st, 0, sizeof st);
    if (c) hy2c_stats(c, &st);
    check("hop prepare: one hop made, none failed", 1, st.hops == 1 && st.hop_fails == 0);
    check("hop prepare: still three fds charged", 3, g_fdx);
    unsigned li = last_link();
    qc_close(g_p[0].q, 0x100);
    qc_flush(g_p[0].q);
    check("hop prepare: the link is freed", 1, PUMP_UNTIL(watch_off(XC_MAX + li)));
    check("hop prepare: the charge is given back", 0, g_fdx);
    end();

    begin();
    port = peer_start(0, 0);
    uint16_t other = peer_start(1, 0);
    node_make(&n, "127.0.0.1", port);
    snprintf(n.ports, sizeof n.ports, "%u,%u", port, other);
    n.hop_mode = HY2_HOP_REMOTE;
    g_fdx = 0;
    memset(g_script, 0, sizeof g_script);
    g_script[5] = 1;
    g_script_n = 0;
    check("hop prepare: a remote link is ready", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    check("hop prepare: a remote link charges three", 3, g_fdx);
    c = hy2d_link_conn(last_link());
    if (c) hy2c_hop_now(c);
    check("hop prepare: a hop onto the same port makes no socket", 1, g_prep);
    if (c) hy2c_hop_now(c);
    check("hop prepare: a hop onto another port prepares one", 2, g_prep);
    memset(&st, 0, sizeof st);
    if (c) hy2c_stats(c, &st);
    check("hop prepare: two hops, none failed", 1, st.hops == 2 && st.hop_fails == 0);
    end();
    g_follow = 0;
    g_hy2_rand = saved;
}

static void a_failed_hop_is_said_once(void) {
    uint32_t (*saved)(void) = g_hy2_rand;
    g_hy2_rand = script_rand;
    for (int k = 0; k < 16; k++) g_script[k] = 1;
    g_script[0] = 0;
    g_script_n = 0;
    g_follow = 1;
    begin();
    uint16_t port = peer_start(0, 0), other = peer_start(1, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    snprintf(n.name, sizeof n.name, "N3\ninjected");
    snprintf(n.ports, sizeof n.ports, "%u,%u", port, other);
    n.hop_mode = HY2_HOP_LOCAL | HY2_HOP_REMOTE;
    err_open();
    int r = ready_flow(1, &n, "10.0.0.1", 80, 0);
    struct hy2c *c = hy2d_link_conn(last_link());
    struct qc_stats st0, st;
    memset(&st0, 0, sizeof st0);
    memset(&st, 0, sizeof st);
    if (c) {
        hy2c_stats(c, &st0);
        hy2c_hop_now(c);
        pass();
        hy2c_stats(c, &st);
    }
    int moved = st0.port == port && st.port == other && st.hops == 1 && st.hop_fails == 0;
    g_prep_fail_at = g_prep + 1;
    if (c) {
        for (int k = 0; k < 3; k++) {
            hy2c_hop_now(c);
            pass();
            pass();
        }
        hy2c_stats(c, &st);
    }
    end();
    g_prep_fail_at = 0;
    begin();
    peer_start(0, port);
    peer_start(1, other);
    int r2 = ready_flow(2, &n, "10.0.0.2", 80, 0);
    g_prep_fail_at = g_prep + 1;
    c = hy2d_link_conn(last_link());
    uint64_t fails2 = 0;
    if (c) {
        hy2c_hop_now(c);
        pass();
        fails2 = hy2c_hop_fails(c);
    }
    pump_for(100);
    const char *e = err_close();
    char want[160];
    snprintf(want, sizeof want, "tunvless[warn]: hysteria2 N3 injected: port hop failed, staying on %u", other);
    check("failed hop: a hopping link is ready", 0, r);
    check("failed hop: the first hop moves from the first port to the other", 1, moved);
    check("failed hop: three hops failed and counted", 3, (long)st.hop_fails);
    check("failed hop: the node is redialled", 0, r2);
    check("failed hop: the redialled link's hop fails too", 1, (long)fails2);
    check("failed hop: the line names the node and the port it stays on, once per node", 1, err_lines(e, want, 1));
    check("failed hop: no other hop line", 1, err_lines(e, "port hop failed", 0));
    check("failed hop: the node's ready line is said once", 1, err_lines(e, "hysteria2 N3 injected: link ready", 0));
    end();
    g_follow = 0;
    g_hy2_rand = saved;
}

static void a_silent_node_wakes_its_waiters_by_the_budget(void) {
    begin();
    int fd;
    uint16_t port = silent_bind("127.0.0.1", &fd);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    uint64_t t0 = ms_now();
    hy2_mux.pass(t0, MUXP_EARLY);
    fl_open(1, &n, "10.0.0.1", 80, 0);
    check("silent: first waits", XA_WAIT, fl_attach(1, 0));
    hy2_mux.pass(t0 + 4000, MUXP_EARLY);
    fl_open(2, &n, "10.0.0.2", 80, 0);
    check("silent: second, 4000 ms later, waits on the same link", XA_WAIT, fl_attach(2, 0));
    check("silent: one link", 1, watch_adds());
    hy2_mux.pass(t0 + 7999, MUXP_LATE);
    check("silent: nobody woken at +7999", 0, wakes(1, XW_DONE) + wakes(2, XW_DONE));
    hy2_mux.pass(t0 + 8001, MUXP_LATE);
    check("silent: both woken at +8001", 1, wakes(1, XW_DONE) == 1 && wakes(2, XW_DONE) == 1);
    check("silent: with HY2_EDIAL", 1, wake_rc(1, XW_DONE) == HY2_EDIAL && wake_rc(2, XW_DONE) == HY2_EDIAL);
    check("silent: seen once with the dial's start", 1, g_sn_n == 1 && g_sn[0].rc == HY2_EDIAL && g_sn[0].started == t0);
    end();
    close(fd);

    begin();
    port = peer_start(0, 0);
    g_p[0].auth_mode = HP_AUTH_SILENT;
    node_make(&n, "127.0.0.1", port);
    fl_open(3, &n, "10.0.0.1", 80, 0);
    check("silent auth: waits", XA_WAIT, fl_attach(3, 0));
    check("silent auth: handshake done", 1, PUMP_UNTIL(g_p[0].hs));
    struct hy2c *c = hy2d_link_conn(last_link());
    check("silent auth: the session is handed out", 1, c != NULL);
    if (c) hy2c_clock_set(c, hy2c_opened_ns(c) + 7999000000ull);
    pump_for(300);
    check("silent auth: not woken at +7999 on the session clock", 0, wakes(3, XW_DONE));
    if (c) hy2c_clock_set(c, hy2c_opened_ns(c) + 8001000000ull);
    check("silent auth: woken at +8001", 1, PUMP_UNTIL(wakes(3, XW_DONE)));
    check("silent auth: with HY2_EDIAL", HY2_EDIAL, wake_rc(3, XW_DONE));
    check("silent auth: why says auth timed out", 1, why_has(3, HY2_EDIAL, "auth timed out"));
    end();
}

static void a_stale_link_takes_no_new_flows(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("stale: flow 1 ready", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    unsigned li = last_link();
    g_stale_below = 1;
    fl_open(2, &n, "10.0.0.2", 80, 0);
    unsigned adds = watch_adds();
    check("stale: a new attach does not join the stale link", XA_WAIT, fl_attach(2, 1));
    check("stale: it dials a second link", adds + 1, watch_adds());
    check("stale: on another slot", 1, last_link() != li);
    pump_for(100);
    check("stale: the old link lives while its flow does", 0, watch_off(XC_MAX + li));
    fl_close(1);
    check("stale: freed when its last flow closes", 1, PUMP_UNTIL(watch_off(XC_MAX + li)));
    end();
}

static void tcp_echo_through_send_read_deliver(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("echo: flow ready", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    g_sk[1].auto_rd = 1;
    check("echo: 100000 bytes sent within room", 0, send_all(1, g_pat, 100000));
    check("echo: the peer saw 10.0.0.1:80", 1, PUMP_UNTIL(peer_st(0, "10.0.0.1:80") != NULL));
    check("echo: 100000 bytes back", 1, PUMP_UNTIL(g_sk[1].n >= 100000));
    check("echo: exactly 100000", 100000, (long)g_sk[1].n);
    check("echo: equal to what was sent", 1, g_sk[1].n == 100000 && !memcmp(g_sk[1].b, g_pat, 100000));
    end();
}

static void a_silent_client_opens_the_stream_alone(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("silent client: flow ready", 0, ready_flow(1, &n, "10.0.0.5", 22, 0));
    check("silent client: a send of nothing is ok", SEND_OK, fl_send(1, NULL, 0));
    check("silent client: the peer got the request", 1, PUMP_UNTIL(peer_st(0, "10.0.0.5:22") != NULL));
    pump_for(100);
    struct hp_st *st = peer_st(0, "10.0.0.5:22");
    check("silent client: and no payload", 0, st ? (long)st->payload : -1);
    end();
}

static void a_slow_client_holds_the_stream_window(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    g_p[0].echo = 0;
    g_p[0].send_bytes = 4 * MIB;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("slow client: flow ready", 0, ready_flow(1, &n, "10.0.0.6", 80, 0));
    check("slow client: stream opens", SEND_OK, fl_send(1, NULL, 0));
    check("slow client: the window fills", 1, PUMP_UNTIL(hy2d_rx_held(&g_s[1]) >= HELD_FULL));
    pump_for(300);
    check("slow client: held = 2 MiB window less the 132-byte response", HELD_FULL, (long)hy2d_rx_held(&g_s[1]));
    check("slow client: the client takes 1 MiB", MIB, (long)rd(1, MIB));
    check("slow client: the window refills", 1, PUMP_UNTIL(hy2d_rx_held(&g_s[1]) >= 2097152));
    pump_for(300);
    check("slow client: and holds the whole window, the response's 132 now credited", 2097152,
          (long)hy2d_rx_held(&g_s[1]));
    g_sk[1].auto_rd = 1;
    check("slow client: reading delivers 4 MiB", 1, PUMP_UNTIL(g_sk[1].n >= 4 * MIB));
    check("slow client: exactly 4194304", 4194304, (long)g_sk[1].n);
    check("slow client: intact", 1, g_sk[1].n == 4 * MIB && !memcmp(g_sk[1].b, g_pat, 4 * MIB));
    end();
}

static void ends_map_to_the_stack(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    g_p[0].echo = 0;
    g_p[0].send_bytes = 1000;
    g_p[0].answer_after = 1;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("fin: flow ready", 0, ready_flow(1, &n, "10.0.0.7", 80, 0));
    check("fin: stream opens", SEND_OK, fl_send(1, NULL, 0));
    check("fin: the peer parsed it", 1, PUMP_UNTIL(peer_st(0, "10.0.0.7:80") != NULL));
    struct hp_st *st = peer_st(0, "10.0.0.7:80");
    NEED(st);
    hp_answer(&g_p[0], st);
    st->out.fin = 1;
    g_sk[1].auto_rd = 1;
    uint64_t e = ms_now() + 10000ull * g_tx;
    while (!g_sk[1].n && ms_now() < e) pass();
    check("fin: data and the end in the same pump", 1, g_sk[1].n == 1000 && g_sk[1].end == 1);
    check("fin: 1000 bytes intact", 1, g_sk[1].n == 1000 && !memcmp(g_sk[1].b, g_pat, 1000));
    check("fin: cut 0", 0, hy2_mux.cut(&g_s[1]));
    check("fin: has_data 0 afterwards", 0, hy2_dialer.has_data(&g_s[1]));
    unsigned w1 = wakes(1, XW_READ);
    qc_stream_stop(g_p[0].q, st->sid, 0);
    qc_flush(g_p[0].q);
    check("fin: the stream then closes cleanly at the peer", 1, PUMP_UNTIL(st->closed));
    pump_for(100);
    check("fin: the clean close wakes nobody", (long)w1, (long)wakes(1, XW_READ));
    check("fin: has_data still 0", 0, hy2_dialer.has_data(&g_s[1]));
    check("fin: cut still 0", 0, hy2_mux.cut(&g_s[1]));
    check("fin: an upload after the clean close is dropped, not fatal", SEND_OK, fl_send(1, g_pat, 100));
    check("fin: room 65536 after the clean close", 65536, fl_room(1));

    g_p[0].answer_after = 0;
    g_p[0].send_bytes = 65536;
    check("reset: flow ready", 0, ready_flow(2, &n, "10.0.0.8", 80, 0));
    check("reset: stream opens", SEND_OK, fl_send(2, NULL, 0));
    check("reset: 64 KiB queued", 1, PUMP_UNTIL(hy2d_rx_held(&g_s[2]) == 65536));
    struct hp_st *st2 = peer_st(0, "10.0.0.8:80");
    NEED(st2);
    unsigned w2 = wakes(2, XW_READ);
    qc_stream_reset(g_p[0].q, st2->sid, 0);
    qc_flush(g_p[0].q);
    check("reset: woken", 1, PUMP_UNTIL(wakes(2, XW_READ) > w2));
    unsigned char buf[TUNNEL_BUF];
    const unsigned char *d = buf;
    size_t got = 7;
    int rc = hy2_dialer.read(&g_s[2], buf, sizeof buf, &d, &got);
    check("reset: read ends at once", 1, rc != 0 && got == 0);
    check("reset: cut 2", 2, hy2_mux.cut(&g_s[2]));

    g_p[0].send_bytes = 0;
    check("link: flow 3 ready", 0, ready_flow(3, &n, "10.0.0.9", 80, 0));
    check("link: flow 4 ready", 0, ready_flow(4, &n, "10.0.0.10", 80, 0));
    check("link: udp flow 5 ready", 0, ready_flow(5, &n, "1.2.3.4", 53, 1));
    check("link: streams open and a datagram goes", 1,
          fl_send(3, NULL, 0) == SEND_OK && fl_send(4, NULL, 0) == SEND_OK && fl_dgram(5, g_pat, 10) == SEND_OK);
    check("link: the peer has them", 1,
          PUMP_UNTIL(peer_st(0, "10.0.0.9:80") && peer_st(0, "10.0.0.10:80") && g_p[0].dg_n >= 1));
    unsigned w3 = wakes(3, XW_READ), w4 = wakes(4, XW_READ), w5 = wakes(5, XW_READ);
    qc_close(g_p[0].q, 0x100);
    qc_flush(g_p[0].q);
    check("link: all three woken", 1,
          PUMP_UNTIL(wakes(3, XW_READ) > w3 && wakes(4, XW_READ) > w4 && wakes(5, XW_READ) > w5));
    got = 7;
    int r3 = hy2_dialer.read(&g_s[3], buf, sizeof buf, &d, &got);
    int r4 = hy2_dialer.read(&g_s[4], buf, sizeof buf, &d, &got);
    int r5 = hy2_dialer.read(&g_s[5], buf, sizeof buf, &d, &got);
    check("link: tcp reads end", 1, r3 != 0 && r4 != 0);
    check("link: the udp read is 1", 1, r5);
    check("link: cut 1 for each", 1, hy2_mux.cut(&g_s[3]) == 1 && hy2_mux.cut(&g_s[4]) == 1 && hy2_mux.cut(&g_s[5]) == 1);
    check("link: the finished flow keeps cut 0", 0, hy2_mux.cut(&g_s[1]));
    check("link: the reset flow keeps cut 2", 2, hy2_mux.cut(&g_s[2]));
    end();
}

static void a_stopped_upload_keeps_the_download(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    g_p[0].echo = 0;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("stop: flow ready", 0, ready_flow(1, &n, "10.0.0.11", 80, 0));
    check("stop: stream opens", SEND_OK, fl_send(1, NULL, 0));
    check("stop: the peer has it", 1, PUMP_UNTIL(peer_st(0, "10.0.0.11:80") != NULL));
    struct hp_st *st = peer_st(0, "10.0.0.11:80");
    NEED(st);
    size_t off = 0;
    uint64_t e = ms_now() + 10000ull * g_tx;
    while (st->payload < 65536 && ms_now() < e) {
        long r = fl_room(1);
        if (r >= (long)CHUNK && fl_send(1, g_pat + off, CHUNK) == SEND_OK) off += CHUNK;
        pass();
    }
    check("stop: 64 KiB reached the peer", 1, st->payload >= 65536);
    qc_stream_stop(g_p[0].q, st->sid, 0);
    hp_put(&st->out, g_pat, MIB);
    qc_flush(g_p[0].q);
    pump_for(200);
    check("stop: the stream still lives at the peer", 0, st->closed);
    check("stop: a later send is ok", SEND_OK, fl_send(1, g_pat + off, CHUNK));
    check("stop: and another", SEND_OK, fl_send(1, g_pat + off, CHUNK));
    check("stop: room 65536", 65536, fl_room(1));
    st->out.fin = 1;
    g_sk[1].auto_rd = 1;
    check("stop: the download ends", 1, PUMP_UNTIL(g_sk[1].end != 0));
    check("stop: 1 MiB tail intact", 1, g_sk[1].n == MIB && !memcmp(g_sk[1].b, g_pat, MIB));
    check("stop: read rc 1", 1, g_sk[1].end);
    check("stop: cut 0", 0, hy2_mux.cut(&g_s[1]));
    g_p[0].echo = 1;
    check("stop: a second flow on the link", 0, ready_flow(2, &n, "10.0.0.12", 80, 0));
    g_sk[2].auto_rd = 1;
    check("stop: it sends", 0, send_all(2, g_pat, 1000));
    check("stop: and its echo comes back", 1, PUMP_UNTIL(g_sk[2].n >= 1000));
    check("stop: intact", 1, g_sk[2].n == 1000 && !memcmp(g_sk[2].b, g_pat, 1000));
    end();
}

static void room_follows_the_stream(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    g_p[0].echo = 0;
    g_p[0].no_consume = 1;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("room: flow ready", 0, ready_flow(1, &n, "10.0.0.13", 80, 0));
    check("room: before the stream 65536", 65536, fl_room(1));
    check("room: stream opens", SEND_OK, fl_send(1, NULL, 0));
    size_t sent = 0;
    uint64_t e = ms_now() + 15000ull * g_tx;
    while (ms_now() < e) {
        if (fl_room(1) > (long)CHUNK + 1) {
            if (fl_send(1, g_pat + sent, CHUNK) == SEND_OK) sent += CHUNK;
            else pass();
            continue;
        }
        pump_for(200);
        if (fl_room(1) <= (long)CHUNK + 1) break;
    }
    long r0 = fl_room(1);
    check("room: the stream fills to a room above 0", 1, r0 > 0 && r0 <= (long)CHUNK + 1);
    check("room: room + 1 bytes with room above 0 are refused", SEND_AGAIN, fl_send(1, g_pat + sent, (size_t)r0 + 1));
    check("room: and nothing of them was taken", r0, fl_room(1));
    check("room: exactly room bytes go", SEND_OK, fl_send(1, g_pat + sent, (size_t)r0));
    sent += (size_t)r0;
    check("room: the stream is at room 0", 0, fl_room(1));
    check("room: room + 1 bytes are refused", SEND_AGAIN, fl_send(1, g_pat + sent, 1));
    unsigned w = wakes(1, XW_ROOM);
    g_p[0].no_consume = 0;
    hp_consume_all(&g_p[0]);
    qc_flush(g_p[0].q);
    check("room: the peer reads and the owner hears XW_ROOM", 1, PUMP_UNTIL(wakes(1, XW_ROOM) > w));
    struct hp_st *st = peer_st(0, "10.0.0.13:80");
    check("room: what was taken reaches the peer", 1, PUMP_UNTIL(st && st->payload >= sent));
    pump_for(200);
    check("room: the refused byte never did", (long)sent, st ? (long)st->payload : -1);
    end();
}

static int64_t peer_auth_closed(void) {
    struct hp_st *a = peer_sid(0, 0);
    return a && a->closed;
}

static void opens_wait_for_stream_credit(void) {
    begin();
    uint16_t port = peer_start_cfg(0, 0, 3);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("streams: link ready", 0, ready_flow(1, &n, "10.0.0.21", 80, 0));
    check("streams: the peer saw the auth stream end", 1, PUMP_UNTIL(peer_auth_closed()));
    pump_for(200);
    int free_n = 3 - 1 + (peer_auth_closed() ? 1 : 0);
    check("streams: so three are free", 3, free_n);
    int ok = 0;
    for (int i = 1; i <= free_n; i++) {
        char ip[32];
        snprintf(ip, sizeof ip, "10.0.0.%d", 20 + i);
        if (i > 1) ready_flow(i, &n, ip, 80, 0);
        ok += fl_send(i, NULL, 0) == SEND_OK;
    }
    check("streams: the free ones open", free_n, ok);
    int x = free_n + 1;
    check("streams: one more flow ready", 0, ready_flow(x, &n, "10.0.0.29", 80, 0));
    check("streams: its open waits", SEND_AGAIN, fl_send(x, NULL, 0));
    check("streams: room 0 while it waits", 0, fl_room(x));
    fl_close(1);
    check("streams: a close brings XW_ROOM", 1, PUMP_UNTIL(wakes((uint16_t)x, XW_ROOM)));
    check("streams: room is back", 1, fl_room(x) > 0);
    check("streams: the open goes", SEND_OK, fl_send(x, NULL, 0));
    check("streams: the peer has it", 1, PUMP_UNTIL(peer_st(0, "10.0.0.29:80") != NULL));
    end();
}

static void a_client_fin_ends_the_upload(void) {
    begin();
    uint16_t port = peer_start_cfg(0, 0, 2);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("client fin: the dialer takes a client FIN", 1, hy2_dialer.finish != NULL);
    NEED(hy2_dialer.finish);
    check("client fin: flow ready", 0, ready_flow(1, &n, "10.0.0.40", 80, 0));
    check("client fin: the peer saw the auth stream end", 1, PUMP_UNTIL(peer_auth_closed()));
    g_sk[1].auto_rd = 1;
    check("client fin: 1000 bytes go", SEND_OK, fl_send(1, g_pat, 1000));
    check("client fin: then the FIN", SEND_OK, hy2_dialer.finish(&n, &g_s[1]));
    check("client fin: the peer sees the FIN", 1,
          PUMP_UNTIL(peer_st(0, "10.0.0.40:80") && peer_st(0, "10.0.0.40:80")->fin));
    struct hp_st *st = peer_st(0, "10.0.0.40:80");
    check("client fin: after all 1000 bytes, intact", 1, st && st->payload == 1000 && !st->pbad);
    check("client fin: the download still comes", 1, PUMP_UNTIL(g_sk[1].n == 1000));
    check("client fin: and is the echo", 1, g_sk[1].n == 1000 && !memcmp(g_sk[1].b, g_pat, 1000) && !g_sk[1].end);
    check("client fin: a second flow ready", 0, ready_flow(2, &n, "10.0.0.41", 80, 0));
    check("client fin: it takes the last stream", SEND_OK, fl_send(2, NULL, 0));
    check("client fin: a third flow ready", 0, ready_flow(3, &n, "10.0.0.42", 80, 0));
    check("client fin: its FIN waits for stream credit", SEND_AGAIN, hy2_dialer.finish(&n, &g_s[3]));
    fl_close(2);
    check("client fin: the credit wakes it", 1, PUMP_UNTIL(wakes(3, XW_ROOM)));
    check("client fin: the FIN opens the stream", SEND_OK, hy2_dialer.finish(&n, &g_s[3]));
    check("client fin: the peer sees the request and the FIN", 1,
          PUMP_UNTIL(peer_st(0, "10.0.0.42:80") && peer_st(0, "10.0.0.42:80")->fin));
    st = peer_st(0, "10.0.0.42:80");
    check("client fin: and no payload", 0, st ? (long)st->payload : -1);
    end();
}

static void a_flow_waiting_for_a_stream_holds_its_first_bytes(void) {
    begin();
    uint16_t port = peer_start_cfg(0, 0, 2);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("held: flow ready", 0, ready_flow(1, &n, "10.0.0.43", 80, 0));
    check("held: the peer saw the auth stream end", 1, PUMP_UNTIL(peer_auth_closed()));
    pump_for(200);
    check("held: one flow takes a stream", SEND_OK, fl_send(1, NULL, 0));
    check("held: a second takes the last", 0, ready_flow(2, &n, "10.0.0.44", 80, 0));
    check("held: its open goes", SEND_OK, fl_send(2, NULL, 0));
    check("held: a third flow ready", 0, ready_flow(3, &n, "10.0.0.45", 80, 0));
    check("held: more than four chunks is refused", SEND_AGAIN, fl_send(3, g_pat, HELD_CAP + 1));
    check("held: its first bytes are taken without a stream", SEND_OK, fl_send(3, g_pat, 1000));
    check("held: more fits up to four chunks", SEND_OK, fl_send(3, g_pat + 1000, HELD_CAP - 1000));
    check("held: and not one byte past it", SEND_AGAIN, fl_send(3, g_pat + HELD_CAP, 1));
    check("held: the client gets no room", 0, fl_room(3));
    check("held: its FIN waits behind them", SEND_AGAIN, hy2_dialer.finish(&n, &g_s[3]));
    pump_for(200);
    check("held: nothing reaches the peer without credit", 1, peer_st(0, "10.0.0.45:80") == NULL);
    g_room_owner = 3;
    fl_close(2);
    check("held: the credit wakes it", 1, PUMP_UNTIL(wakes(3, XW_ROOM) > 0));
    check("held: no room at the wake, before the held bytes go", 0, g_room_at_wake);
    check("held: the credit sends them", 1,
          PUMP_UNTIL(peer_st(0, "10.0.0.45:80") && peer_st(0, "10.0.0.45:80")->payload == HELD_CAP));
    struct hp_st *st = peer_st(0, "10.0.0.45:80");
    check("held: intact and in order", 1, st && !st->pbad);
    check("held: then the client gets room", 1, fl_room(3) > 0);
    check("held: and its next bytes follow", SEND_OK, fl_send(3, g_pat + HELD_CAP, 1000));
    check("held: the FIN goes after them", SEND_OK, hy2_dialer.finish(&n, &g_s[3]));
    check("held: the peer has all and the FIN", 1, PUMP_UNTIL(st->fin && st->payload == HELD_CAP + 1000));
    check("held: still intact", 0, (long)st->pbad);
    check("held: a fourth flow ready", 0, ready_flow(4, &n, "10.0.0.46", 80, 0));
    check("held: it holds bytes too", SEND_OK, fl_send(4, g_pat, 500));
    fl_close(4);
    pump_for(200);
    check("held: a flow closed while holding sends nothing", 1, peer_st(0, "10.0.0.46:80") == NULL);
    end();
}

static void stream_credit_goes_to_the_first_to_wait(void) {
    begin();
    uint16_t port = peer_start_cfg(0, 0, 2);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("fifo: flow ready", 0, ready_flow(1, &n, "10.0.0.90", 80, 0));
    check("fifo: the peer saw the auth stream end", 1, PUMP_UNTIL(peer_auth_closed()));
    pump_for(200);
    check("fifo: one flow takes a stream", SEND_OK, fl_send(1, NULL, 0));
    check("fifo: a second takes the last", 0, ready_flow(2, &n, "10.0.0.91", 80, 0));
    check("fifo: its open goes", SEND_OK, fl_send(2, NULL, 0));
    int held = 0;
    for (int i = 3; i <= 5; i++) {
        char ip[32];
        snprintf(ip, sizeof ip, "10.0.0.%d", 89 + i);
        held += ready_flow(i, &n, ip, 80, 0) == 0 && fl_send(i, g_pat, 500) == SEND_OK;
    }
    check("fifo: three flows wait in order, holding bytes", 3, held);
    fl_close(2);
    check("fifo: one credit opens one stream", 1, PUMP_UNTIL(peer_st(0, "10.0.0.92:80") || peer_st(0, "10.0.0.93:80") ||
                                                             peer_st(0, "10.0.0.94:80")));
    pump_for(300);
    check("fifo: the first to wait got it", 1, peer_st(0, "10.0.0.92:80") != NULL);
    check("fifo: the later ones still wait", 1, !peer_st(0, "10.0.0.93:80") && !peer_st(0, "10.0.0.94:80"));
    end();
}

static void has_data_resumes_a_flow_stopped_by_the_client(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    g_p[0].echo = 0;
    g_p[0].send_bytes = 65536;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("client stop: flow ready", 0, ready_flow(1, &n, "10.0.0.14", 80, 0));
    check("client stop: stream opens", SEND_OK, fl_send(1, NULL, 0));
    check("client stop: 64 KiB queued", 1, PUMP_UNTIL(hy2d_rx_held(&g_s[1]) == 65536));
    check("client stop: the client takes 16 KiB", 16384, (long)rd(1, 16384));
    check("client stop: has_data 1", 1, hy2_dialer.has_data(&g_s[1]));
    unsigned w = wakes(1, XW_READ);
    pump_for(200);
    check("client stop: no wake comes for queued bytes", (long)w, (long)wakes(1, XW_READ));
    size_t more = 0;
    for (int k = 0; k < 64 && hy2_dialer.has_data(&g_s[1]); k++) more += rd(1, 65536);
    check("client stop: has_data brings the rest", 49152, (long)more);
    check("client stop: intact", 1, g_sk[1].n == 65536 && !memcmp(g_sk[1].b, g_pat, 65536));
    end();
}

static void one_full_stream_window_does_not_stop_another_flow(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("two flows: A ready", 0, ready_flow(1, &n, "10.0.0.30", 80, 0));
    check("two flows: A opens", SEND_OK, fl_send(1, NULL, 0));
    check("two flows: the peer answered A", 1, PUMP_UNTIL(peer_st(0, "10.0.0.30:80") && peer_st(0, "10.0.0.30:80")->responded));
    NEED(peer_st(0, "10.0.0.30:80"));
    hp_put(&peer_st(0, "10.0.0.30:80")->out, g_pat, 4 * MIB);
    check("two flows: A holds its window", 1, PUMP_UNTIL(hy2d_rx_held(&g_s[1]) >= HELD_FULL));
    check("two flows: B ready", 0, ready_flow(2, &n, "10.0.0.31", 80, 0));
    g_sk[2].auto_rd = 1;
    check("two flows: B sends 3 MiB, past its own window", 0, send_all(2, g_pat, 3 * MIB));
    check("two flows: B's echo comes back", 1, PUMP_UNTIL(g_sk[2].n >= 3 * MIB));
    check("two flows: intact", 1, g_sk[2].n == 3 * MIB && !memcmp(g_sk[2].b, g_pat, 3 * MIB));
    check("two flows: A still holds its window", HELD_FULL, (long)hy2d_rx_held(&g_s[1]));
    end();
}

static void four_stopped_readers_do_not_stop_a_fifth_flow(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    const char *ip[4] = { "10.0.0.32", "10.0.0.33", "10.0.0.34", "10.0.0.36" };
    for (int i = 0; i < 4; i++) {
        char a[32];
        snprintf(a, sizeof a, "%s:80", ip[i]);
        check("stopped readers: flow ready", 0, ready_flow(1 + i, &n, ip[i], 80, 0));
        check("stopped readers: it opens", SEND_OK, fl_send(1 + i, NULL, 0));
        check("stopped readers: the peer answered", 1, PUMP_UNTIL(peer_st(0, a) && peer_st(0, a)->responded));
        NEED(peer_st(0, a));
        hp_put(&peer_st(0, a)->out, g_pat, 4 * MIB);
    }
    check("stopped readers: each of four holds a full stream window", 1,
          PUMP_UNTIL(hy2d_rx_held(&g_s[1]) == HELD_FULL && hy2d_rx_held(&g_s[2]) == HELD_FULL &&
                     hy2d_rx_held(&g_s[3]) == HELD_FULL && hy2d_rx_held(&g_s[4]) == HELD_FULL));
    check("stopped readers: a fifth flow ready", 0, ready_flow(5, &n, "10.0.0.35", 80, 0));
    g_sk[5].auto_rd = 1;
    check("stopped readers: it sends 3 MiB", 0, send_all(5, g_pat, 3 * MIB));
    check("stopped readers: and gets them back", 1, PUMP_UNTIL(g_sk[5].n >= 3 * MIB));
    check("stopped readers: intact", 1, g_sk[5].n == 3 * MIB && !memcmp(g_sk[5].b, g_pat, 3 * MIB));
    end();
}

static struct hp_st *held_fin_setup(void) {
    g_peer_msd = 16384;
    uint16_t port = peer_start_cfg(0, 0, 10);
    g_peer_msd = 0;
    g_p[0].echo = 0;
    g_p[0].no_consume = 1;
    static struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("server fin: link ready", 0, ready_flow(1, &n, "10.0.0.70", 80, 0));
    check("server fin: the peer saw the auth stream end", 1, PUMP_UNTIL(peer_auth_closed()));
    pump_for(200);
    for (int i = 2; i <= 10; i++) {
        char ip[32];
        snprintf(ip, sizeof ip, "10.0.0.%d", 69 + i);
        check("server fin: a filler flow ready", 0, ready_flow(i, &n, ip, 80, 0));
    }
    int opened = 0;
    for (int i = 1; i <= 10; i++) opened += fl_send(i, NULL, 0) == SEND_OK;
    check("server fin: ten streams open", 10, opened);
    for (int i = 1; i <= 9; i++)
        for (int k = 0; k < 160 && fl_room(i) >= CHUNK && fl_send(i, g_pat, CHUNK) == SEND_OK; k++) pass();
    pump_for(300);
    check("server fin: the send budget is spent", 1, fl_room(1) < CHUNK);
    check("server fin: a held flow ready", 0, ready_flow(11, &n, "10.0.0.81", 80, 0));
    g_sk[11].auto_rd = 1;
    check("server fin: its bytes are held", SEND_OK, fl_send(11, g_pat, HELD_CAP));
    fl_close(10);
    check("server fin: credit opens its stream", 1, PUMP_UNTIL(peer_st(0, "10.0.0.81:80") != NULL));
    struct hp_st *st = peer_st(0, "10.0.0.81:80");
    if (!st) return NULL;
    pump_for(200);
    check("server fin: only part went", 1, st->payload < HELD_CAP);
    if (!st->responded) hp_answer(&g_p[0], st);
    st->out.fin = 1;
    check("server fin: the FIN reaches the flow", 1, PUMP_UNTIL(g_s[11].how != 0));
    pump_for(200);
    check("server fin: the end waits for the held bytes", 0, (long)g_sk[11].end);
    check("server fin: nothing to read while bytes are held", 0, hy2_dialer.has_data(&g_s[11]));
    {
        unsigned char b[64];
        const unsigned char *dp = b;
        size_t got = 1;
        check("server fin: a read does not end the flow while bytes are held", 0,
              hy2_dialer.read(&g_s[11], b, sizeof b, &dp, &got));
        check("server fin: and gives nothing", 0, (long)got);
    }
    return st;
}

static void a_server_fin_keeps_held_bytes_going(void) {
    begin();
    struct hp_st *st = held_fin_setup();
    NEED(st);
    g_p[0].no_consume = 0;
    hp_consume_all(&g_p[0]);
    check("server fin: the end comes once the held bytes are queued", 1, PUMP_UNTIL(g_sk[11].end == 1));
    long at_end = (long)st->payload;
    check("server fin: and is clean", 0, hy2_mux.cut(&g_s[11]));
    fl_close(11);
    check("server fin: the end came before the bytes all went", 1, at_end < (long)HELD_CAP);
    check("server fin: a close right after the end still delivers every byte", 1,
          PUMP_UNTIL(st->payload == HELD_CAP && st->fin));
    check("server fin: intact", 0, (long)st->pbad);
    check("server fin: and the peer sees no reset", 0, (long)st->pa_reset);
    end();
}

static void a_dead_link_ends_a_flow_still_holding_bytes(void) {
    begin();
    struct hp_st *st = held_fin_setup();
    NEED(st);
    qc_close(g_p[0].q, 0);
    qc_flush(g_p[0].q);
    check("held at link death: the flow ends", 1, PUMP_UNTIL(g_sk[11].end == 1));
    check("held at link death: as a link loss", 1, hy2_mux.cut(&g_s[11]));
    end();
}

static void a_close_while_bytes_are_held_after_a_server_fin_resets(void) {
    begin();
    struct hp_st *st = held_fin_setup();
    NEED(st);
    fl_close(11);
    g_p[0].no_consume = 0;
    hp_consume_all(&g_p[0]);
    check("held close: the stream ends at the peer", 1, PUMP_UNTIL(st->pa_reset || st->fin));
    pump_for(200);
    check("held close: by a reset, never a FIN on a cut upload", 1, st->pa_reset && !st->fin);
    check("held close: the peer got only part", 1, st->payload < HELD_CAP);
    end();
}

static void a_clean_close_then_link_death_in_one_batch_ends_the_flow(void) {
    begin();
    struct hp_st *st = held_fin_setup();
    NEED(st);
    qc_stream_stop(g_p[0].q, st->sid, 0);
    qc_flush(g_p[0].q);
    uint64_t e = ms_now() + 10000ull * g_tx;
    while (!g_s[11].up_stopped && ms_now() < e) pass_to(0);
    check("stop then close: the stream closes cleanly while bytes are held", 1, g_s[11].up_stopped && g_s[11].pre);
    qc_close(g_p[0].q, 0);
    qc_flush(g_p[0].q);
    e = ms_now() + 10000ull * g_tx;
    while (!hy2d_link_dead(&g_s[11]) && ms_now() < e) pass_to(0);
    check("stop then close: the link dies before a late pass", 1, hy2d_link_dead(&g_s[11]));
    uint64_t t0 = ms_now();
    check("stop then close: the flow ends", 1, PUMP_UNTIL(g_sk[11].end == 1));
    check("stop then close: at once", 1, ms_now() - t0 < 1000 * g_tx);
    check("stop then close: cleanly", 0, hy2_mux.cut(&g_s[11]));
    end();
}

static void an_inbound_name_goes_in_the_request(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    fl_open(1, &n, "10.0.0.40", 443, 0);
    check("name: set_host takes it", 0, hy2_dialer.set_host(&g_s[1], "example.com"));
    int a = fl_attach(1, 0);
    check("name: ready", 1, a == XA_WAIT && PUMP_UNTIL(wakes(1, XW_DONE)) && wake_rc(1, XW_DONE) == 0);
    check("name: opens", SEND_OK, fl_send(1, NULL, 0));
    check("name: the peer saw example.com:443", 1, PUMP_UNTIL(peer_st(0, "example.com:443") != NULL));
    end();
}

static void a_udp_flow_is_one_session(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    g_p[0].dg_echo = 1;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("udp: flow ready", 0, ready_flow(1, &n, "1.2.3.4", 53, 1));
    g_sk[1].auto_rd = 1;
    check("udp: a datagram goes", SEND_OK, fl_dgram(1, g_pat, 100));
    check("udp: the peer has it", 1, PUMP_UNTIL(g_p[0].dg_n >= 1));
    check("udp: session 1", 1, (long)g_p[0].dg[0].sid);
    check_str("udp: to 1.2.3.4:53", "1.2.3.4:53", g_p[0].dg[0].addr);
    check("udp: 100 bytes", 100, (long)g_p[0].dg[0].data_n);
    check("udp: the echo comes back", 1, PUMP_UNTIL(g_sk[1].dgrams >= 1));
    pump_for(100);
    check("udp: emitted once, whole", 1, g_sk[1].dgrams == 1 && g_sk[1].n == 100 && !memcmp(g_sk[1].b, g_pat, 100));
    check("udp: a second flow ready", 0, ready_flow(2, &n, "1.2.3.4", 53, 1));
    g_sk[2].auto_rd = 1;
    check("udp: it sends", SEND_OK, fl_dgram(2, g_pat, 50));
    check("udp: the peer has it", 1, PUMP_UNTIL(g_p[0].dg_n >= 2));
    check("udp: session 2", 2, (long)g_p[0].dg[1].sid);
    check("udp: a v6 flow ready", 0, ready_flow(3, &n, "2001:db8::1", 53, 1));
    g_sk[3].auto_rd = 1;
    check("udp: it sends", SEND_OK, fl_dgram(3, g_pat, 30));
    check("udp: the peer has it", 1, PUMP_UNTIL(g_p[0].dg_n >= 3));
    check_str("udp: to [2001:db8::1]:53", "[2001:db8::1]:53", g_p[0].dg[2].addr);
    check("udp: both echoes back", 1, PUMP_UNTIL(g_sk[2].dgrams >= 1 && g_sk[3].dgrams >= 1));
    struct qc_stats ps;
    qc_stats_get(g_p[0].q, &ps);
    uint64_t rx0 = ps.dg_rx;
    unsigned seen0 = g_p[0].dg_n;
    check("udp: an empty datagram is sent", SEND_OK, fl_dgram(2, g_pat, 0));
    check("udp: it reaches the peer as a datagram", 1, PUMP_UNTIL((qc_stats_get(g_p[0].q, &ps), ps.dg_rx > rx0)));
    check("udp: one datagram, empty, which the server's parser drops", 1, ps.dg_rx == rx0 + 1 && g_p[0].dg_n == seen0);
    check("udp: the flow lives on", SEND_OK, fl_dgram(2, g_pat, 40));
    check("udp: and its next reply comes back", 1, PUMP_UNTIL(g_sk[2].dgrams >= 2));
    check("udp: replies keep their flows' sizes", 1, g_sk[2].n == 90 && g_sk[3].n == 30);
    pump_for(100);
    unsigned long in = hy2d_udp_in();
    unsigned d2 = g_sk[2].dgrams, d3 = g_sk[3].dgrams;
    fl_close(1);
    uint8_t dg[256];
    size_t hl = hy2_udp_header(dg, sizeof dg, 1, 0, 0, 1, "1.2.3.4", 53);
    memcpy(dg + hl, g_pat, 20);
    check("udp: the peer sends to the ended session", 0, qc_datagram_send(g_p[0].q, dg, hl + 20));
    qc_flush(g_p[0].q);
    pump_for(200);
    check("udp: it never reaches the dialer", (long)in, (long)hy2d_udp_in());
    check("udp: nor another flow", 1, g_sk[2].dgrams == d2 && g_sk[3].dgrams == d3);
    end();
}

static int peer_udp(uint32_t sid, uint16_t pkt, const uint8_t *d, size_t n, size_t piece) {
    size_t count = n ? (n + piece - 1) / piece : 1;
    for (size_t f = 0; f < count; f++) {
        uint8_t dg[2048];
        size_t k = n - f * piece < piece ? n - f * piece : piece;
        size_t hl = hy2_udp_header(dg, sizeof dg, sid, count > 1 ? pkt : 0, (uint8_t)f, (uint8_t)count, "1.2.3.4", 53);
        if (!hl) return -1;
        if (k) memcpy(dg + hl, d + f * piece, k);
        if (qc_datagram_send(g_p[0].q, dg, hl + k) != 0) return -1;
    }
    qc_flush(g_p[0].q);
    return 0;
}

static void server_datagrams_are_bounded(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("dgram bound: flow ready", 0, ready_flow(1, &n, "1.2.3.4", 53, 1));
    uint32_t sid = g_s[1].usid;
    unsigned long in = hy2d_udp_in();
    check("dgram bound: the peer sends 4096 bytes in pieces", 0, peer_udp(sid, 7, g_pat, 4096, 900));
    check("dgram bound: then 4097", 0, peer_udp(sid, 8, g_pat, 4097, 900));
    check("dgram bound: then 10", 0, peer_udp(sid, 0, g_pat + 100, 10, 900));
    check("dgram bound: all three reach the dialer", 1, PUMP_UNTIL(hy2d_udp_in() == in + 3));
    check("dgram bound: two are queued", 2, (long)g_s[1].dg_n);
    check("dgram bound: 4096 and 10 with their lengths", 2 + 4096 + 2 + 10, (long)hy2d_rx_held(&g_s[1]));
    rd(1, (size_t)-1);
    check("dgram bound: two emitted", 2, (long)g_sk[1].dgrams);
    check("dgram bound: 4096 whole, then the 10", 1,
          g_sk[1].n == 4106 && !memcmp(g_sk[1].b, g_pat, 4096) && !memcmp(g_sk[1].b + 4096, g_pat + 100, 10));
    in = hy2d_udp_in();
    check("dgram bound: the peer sends 20000 bytes in 23 pieces", 0, peer_udp(sid, 9, g_pat, 20000, 900));
    check("dgram bound: then 10", 0, peer_udp(sid, 0, g_pat + 200, 10, 900));
    check("dgram bound: both reach the dialer", 1, PUMP_UNTIL(hy2d_udp_in() == in + 2));
    check("dgram bound: only the 10 is queued", 12, (long)hy2d_rx_held(&g_s[1]));
    rd(1, (size_t)-1);
    check("dgram bound: and emitted", 1, g_sk[1].dgrams == 3 && g_sk[1].last == 10 && g_sk[1].n == 4116);

    in = hy2d_udp_in();
    int sent = 0;
    for (int i = 0; i < 129; i++) {
        sent += peer_udp(sid, 0, g_pat + i, 10, 900) == 0;
        if (i % 32 == 31) pump_for(20);
    }
    check("queue bound: 129 replies sent", 129, sent);
    check("queue bound: all reach the dialer", 1, PUMP_UNTIL(hy2d_udp_in() == in + 129));
    check("queue bound: 128 are held", 128, (long)g_s[1].dg_n);
    check("queue bound: 128 x 12 bytes", 128 * 12, (long)hy2d_rx_held(&g_s[1]));
    rd(1, (size_t)-1);
    check("queue bound: 128 emitted", 3 + 128, (long)g_sk[1].dgrams);
    in = hy2d_udp_in();
    check("queue bound: one more", 0, peer_udp(sid, 0, g_pat, 10, 900));
    check("queue bound: it reaches the dialer", 1, PUMP_UNTIL(hy2d_udp_in() == in + 1));
    check("queue bound: and is held again", 1, (long)g_s[1].dg_n);
    rd(1, (size_t)-1);

    in = hy2d_udp_in();
    check("short read: the peer sends 100", 0, peer_udp(sid, 0, g_pat, 100, 900));
    check("short read: then 50", 0, peer_udp(sid, 0, g_pat + 300, 50, 900));
    check("short read: both reach the dialer", 1, PUMP_UNTIL(hy2d_udp_in() == in + 2));
    unsigned char buf[TUNNEL_BUF];
    const unsigned char *d = buf;
    size_t got = 7;
    check("short read: a 60-byte read of the 100 does not end", 0, hy2_dialer.read(&g_s[1], buf, 60, &d, &got));
    check("short read: and gives nothing", 0, (long)got);
    check("short read: the 100 is gone, the 50 stays", 1, g_s[1].dg_n == 1 && hy2d_rx_held(&g_s[1]) == 52);
    got = 0;
    check("short read: the next read", 0, hy2_dialer.read(&g_s[1], buf, 60, &d, &got));
    check("short read: gives the 50", 1, got == 50 && !memcmp(d, g_pat + 300, 50));
    end();
}

static void udp_limits_are_named(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("udp limit: first flow ready", 0, ready_flow(0, &n, "1.2.0.0", 53, 1));
    int ok = 1;
    for (int i = 1; i < 320; i++) {
        char ip[32];
        snprintf(ip, sizeof ip, "1.2.%d.%d", i / 250, i % 250);
        fl_open(i, &n, ip, 53, 1);
        ok += fl_attach(i, 0) == XA_READY;
    }
    check("udp limit: 320 flows hold a session each", 320, ok);
    fl_open(320, &n, "1.3.0.0", 53, 1);
    check("udp limit: the 321st is refused at attach", HY2_ENOUDP, fl_attach(320, 0));
    check("udp limit: why says full", 1, why_has(320, HY2_ENOUDP, "UDP sessions full"));
    fl_close(5);
    fl_open(320, &n, "1.3.0.0", 53, 1);
    check("udp limit: a freed session lets the next one in", XA_READY, fl_attach(320, 0));
    check("udp limit: and it sends", SEND_OK, fl_dgram(320, g_pat, 10));
    end();

    begin();
    g_dgmax = 0;
    port = peer_start(0, 0);
    g_dgmax = 1200;
    node_make(&n, "127.0.0.1", port);
    check("no datagrams: a tcp flow readies the link", 0, ready_flow(1, &n, "10.0.0.1", 80, 0));
    fl_open(2, &n, "1.2.3.4", 53, 1);
    check("no datagrams: a udp attach after ready is refused", HY2_ENOUDP, fl_attach(2, 0));
    check("no datagrams: why names it", 1, why_has(2, HY2_ENOUDP, "the node takes no UDP"));
    end();

    begin();
    port = peer_start(0, 0);
    g_p[0].auth_mode = HP_AUTH_NOUDP;
    node_make(&n, "127.0.0.1", port);
    fl_open(3, &n, "1.2.3.4", 53, 1);
    fl_open(4, &n, "10.0.0.4", 80, 0);
    check("no udp: both attach before ready", 1, fl_attach(3, 0) == XA_WAIT && fl_attach(4, 0) == XA_WAIT);
    check("no udp: both woken", 1, PUMP_UNTIL(wakes(3, XW_DONE) && wakes(4, XW_DONE)));
    check("no udp: the tcp flow is ready", 0, wake_rc(4, XW_DONE));
    check("no udp: the udp flow fails at the ready wake", HY2_ENOUDP, wake_rc(3, XW_DONE));
    check("no udp: why names it", 1, why_has(3, HY2_ENOUDP, "the node takes no UDP"));
    end();
}

static void peer_only(unsigned ms) {
    uint64_t e = ms_now() + (uint64_t)ms * g_tx;
    while (ms_now() < e) {
        int t = qc_timeout_ms(g_p[0].q);
        struct epoll_event ev;
        int k = epoll_wait(g_ep, &ev, 1, t < 0 || t > 5 ? 5 : t);
        (void)k;
        (void)qc_on_readable(g_p[0].q);
        if (qc_timeout_ms(g_p[0].q) == 0) (void)qc_on_timer(g_p[0].q);
        hp_drain(&g_p[0]);
        qc_flush(g_p[0].q);
    }
}

static void tail_until(int k, const char *addr) {
    struct hp_st *st = peer_st(k, addr);
    (void)PUMP_UNTIL(st && st->closed);
    pump_for(100);
}

static void a_closed_tail_returns_credit_as_it_is_read(void) {
    begin();
    uint16_t port = peer_start(0, 0);
    g_p[0].echo = 0;
    g_p[0].answer_after = 1;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    const char *a[2] = { "10.0.0.60:80", "10.0.0.61:80" };
    struct hp_st *st[2];
    for (int i = 0; i < 2; i++) {
        check("tail: flow ready", 0, ready_flow(1 + i, &n, i ? "10.0.0.61" : "10.0.0.60", 80, 0));
        check("tail: stream opens", SEND_OK, fl_send(1 + i, NULL, 0));
        check("tail: the peer parsed it", 1, PUMP_UNTIL(peer_st(0, a[i]) != NULL));
        st[i] = peer_st(0, a[i]);
        NEED(st[i]);
        hp_answer(&g_p[0], st[i]);
    }
    pump_for(300);
    uint64_t c0 = g_credit;
    for (int i = 0; i < 2; i++) {
        hp_put(&st[i]->out, g_pat, 100000);
        st[i]->out.fin = 1;
        qc_stream_stop(g_p[0].q, st[i]->sid, 0);
    }
    qc_flush(g_p[0].q);
    check("tail: both tails queued", 1, PUMP_UNTIL(hy2d_rx_held(&g_s[1]) == 100000 && hy2d_rx_held(&g_s[2]) == 100000));
    tail_until(0, a[0]);
    tail_until(0, a[1]);
    check("tail: both streams closed cleanly", 1, st[0]->closed && st[1]->closed && g_s[1].gone && g_s[2].gone);
    check("tail: nothing read, no credit back", 0, (long)(g_credit - c0));
    check("tail: 16384 bytes read", 16384, (long)rd(1, 16384));
    check("tail: exactly 16384 back", 16384, (long)(g_credit - c0));
    check("tail: the rest read", 100000 - 16384, (long)rd(1, (size_t)-1));
    check("tail: exactly 100000 back", 100000, (long)(g_credit - c0));
    check("tail: the other flow takes 16384", 16384, (long)rd(2, 16384));
    fl_close(2);
    check("tail: its close gives back the unread rest", 200000, (long)(g_credit - c0));

    for (int k = 4; k <= 5; k++) {
        const char *ip = k == 4 ? "10.0.0.63" : "10.0.0.64", *ad = k == 4 ? "10.0.0.63:80" : "10.0.0.64:80";
        const char *tag = k == 4 ? "reset after fin, read" : "reset after fin, closed unread";
        char b[128];
        snprintf(b, sizeof b, "%s: flow ready", tag);
        check(b, 0, ready_flow(k, &n, ip, 80, 0));
        snprintf(b, sizeof b, "%s: stream opens", tag);
        check(b, SEND_OK, fl_send(k, NULL, 0));
        snprintf(b, sizeof b, "%s: the peer parsed it", tag);
        check(b, 1, PUMP_UNTIL(peer_st(0, ad) != NULL));
        struct hp_st *sr = peer_st(0, ad);
        NEED(sr);
        hp_answer(&g_p[0], sr);
        pump_for(300);
        uint64_t c2 = g_credit;
        hp_put(&sr->out, g_pat, 4000);
        sr->out.fin = 1;
        peer_only(300);
        snprintf(b, sizeof b, "%s: the peer sent data and fin", tag);
        check(b, 1, sr->out.fin_done);
        snprintf(b, sizeof b, "%s: the peer resets before the fin is acked", tag);
        check(b, 0, qc_stream_reset_write(g_p[0].q, sr->sid, 0));
        qc_flush(g_p[0].q);
        snprintf(b, sizeof b, "%s: the reset reaches the flow", tag);
        check(b, 1, PUMP_UNTIL(g_s[k].gone));
        snprintf(b, sizeof b, "%s: by the reset path, not a clean close", tag);
        check(b, 1, g_s[k].gone);
        snprintf(b, sizeof b, "%s: the 4000-byte tail is still queued", tag);
        check(b, 4000, (long)hy2d_rx_held(&g_s[k]));
        if (k == 4) {
            snprintf(b, sizeof b, "%s: it is read whole", tag);
            check(b, 4000, (long)rd(k, (size_t)-1));
        }
        fl_close(k);
        snprintf(b, sizeof b, "%s: credit for 4000 bytes comes back once", tag);
        check(b, 4000, (long)(g_credit - c2));
    }

    g_p[0].answer_after = 0;
    g_p[0].send_bytes = 65536;
    check("queued close: flow ready", 0, ready_flow(3, &n, "10.0.0.62", 80, 0));
    check("queued close: stream opens", SEND_OK, fl_send(3, NULL, 0));
    check("queued close: 64 KiB queued", 1, PUMP_UNTIL(hy2d_rx_held(&g_s[3]) == 65536));
    pump_for(100);
    uint64_t c1 = g_credit;
    fl_close(3);
    check("queued close: closing gives back the 64 KiB at once", 65536, (long)(g_credit - c1));
    end();
}

static void the_loop_deadline_is_obeyed(void) {
    begin();
    check("deadline: no link waits for nothing", 0, hy2_mux.pass(ms_now(), MUXP_LATE));
    uint16_t port = peer_start(0, 0);
    g_p[0].echo = 0;
    struct vless_node n;
    node_make(&n, "127.0.0.1", port);
    check("deadline: flow ready", 0, ready_flow(1, &n, "10.0.0.50", 80, 0));
    pump_for(100);
    check("deadline: a send queues", SEND_OK, fl_send(1, g_pat, 1000));
    int d1 = hy2_mux.pass(ms_now(), MUXP_LATE);
    check("deadline: after the flushing pass more than 0", 1, d1 > 0);
    peer_only(300);
    struct hp_st *st = peer_st(0, "10.0.0.50:80");
    check("deadline: that pass flushed the send", 1000, st ? (long)st->payload : -1);
    struct hy2c *c = hy2d_link_conn(last_link());
    NEED(c);
    uint8_t junk[100];
    memset(junk, 0x55, sizeof junk);
    junk[0] = 0x43;
    int sent = 0;
    for (int i = 0; i < 200; i++) sent += send(qc_fd(g_p[0].q), junk, sizeof junk, 0) == (ssize_t)sizeof junk;
    check("deadline: 200 datagrams queued at the client", 200, sent);
    hy2_mux.event(last_link(), EPOLLIN);
    check("deadline: a pass stopped at its budget gives 1", 1, hy2_mux.pass(ms_now(), MUXP_LATE));
    fl_close(1);
    pump_for(300);
    int pos = 0;
    for (int i = 0; i < 20; i++) {
        pos += hy2_mux.pass(ms_now(), MUXP_LATE) > 0;
        usleep(1000);
    }
    check("deadline: an idle ready link never gives 0", 20, pos);
    check("deadline: the link lives", 1, hy2d_link_conn(last_link()) != NULL);
    end();
}

static int certs_make(void) {
    struct tcg_key *k1 = tcg_key_new(), *kl = tcg_key_new();
    int rc = -1;
    if (!k1 || !kl) goto out;
    if (tcg_issue(k1, "Test CA One", NULL, 1, NULL, NULL, 0, g_ca, sizeof g_ca, &g_ca_n) != 0) goto out;
    if (tcg_issue(kl, "node.test", NULL, 0, k1, g_ca, g_ca_n, g_leaf, sizeof g_leaf, &g_leaf_n) != 0) goto out;
    if (tcg_key_der(kl, g_key, sizeof g_key, &g_key_n) != 0) goto out;
    if (tcg_der_to_pem(g_ca, g_ca_n, g_ca_pem, sizeof g_ca_pem) != 0) goto out;
    snprintf(g_roots, sizeof g_roots, "%s", "/tmp/hy2dialmatch-roots-XXXXXX");
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

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *tx = getenv("QC_TEST_TIME_X");
    if (tx && atoi(tx) > 0) g_tx = (unsigned)atoi(tx);
    const char *nb = getenv("QC_TEST_NO_BATCH");
    g_nb = nb && !strcmp(nb, "1");
    hy2_no_batch = g_nb;
    g_pat = malloc(4 * MIB + 4096);
    if (!g_pat) return 1;
    for (size_t i = 0; i < 4 * MIB + 4096; i++) g_pat[i] = (uint8_t)((i * 31 + 7) % 251);
    check("certificates issued", 0, certs_make());
    tls_set_cert_roots(g_roots);
    attach_waits_and_ready_wakes_every_waiter();
    a_stop_closes_every_ready_link_and_no_dialling_one();
    a_failed_dial_wakes_waiters_with_the_reason();
    a_waiter_closed_before_ready_is_not_woken();
    links_per_loop_are_bounded();
    a_dead_link_is_freed_outside_callbacks_and_redialed();
    one_prepared_socket_per_link();
    a_hopping_link_charges_its_fds_until_freed();
    a_hopping_link_prepares_a_socket_per_hop();
    a_failed_hop_is_said_once();
    a_silence_cut_is_reported_as_a_failed_dial();
    a_ready_link_says_how_it_sends();
    a_cut_link_is_named_once();
    a_silent_node_wakes_its_waiters_by_the_budget();
    a_stale_link_takes_no_new_flows();
    tcp_echo_through_send_read_deliver();
    a_silent_client_opens_the_stream_alone();
    a_slow_client_holds_the_stream_window();
    ends_map_to_the_stack();
    a_stopped_upload_keeps_the_download();
    room_follows_the_stream();
    opens_wait_for_stream_credit();
    a_client_fin_ends_the_upload();
    a_flow_waiting_for_a_stream_holds_its_first_bytes();
    stream_credit_goes_to_the_first_to_wait();
    has_data_resumes_a_flow_stopped_by_the_client();
    one_full_stream_window_does_not_stop_another_flow();
    four_stopped_readers_do_not_stop_a_fifth_flow();
    a_server_fin_keeps_held_bytes_going();
    a_dead_link_ends_a_flow_still_holding_bytes();
    a_close_while_bytes_are_held_after_a_server_fin_resets();
    a_clean_close_then_link_death_in_one_batch_ends_the_flow();
    an_inbound_name_goes_in_the_request();
    a_udp_flow_is_one_session();
    server_datagrams_are_bounded();
    udp_limits_are_named();
    a_closed_tail_returns_credit_as_it_is_read();
    the_loop_deadline_is_obeyed();
    if (g_roots[0]) unlink(g_roots);
    free(g_pat);
    return unit_done("hy2dialmatch");
}
