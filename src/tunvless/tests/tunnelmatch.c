/* The VLESS tunnel's packet handling without a network: handle_packet and its neighbours over a
 * faked node connection.
 *
 * The tests/run-tunnel*.sh scripts run the whole tunnel but cannot reach some paths: a closed
 * HTTP/2 window (SEND_AGAIN) happens only with grpc and xhttp, while the scripts' fake server
 * speaks plain tcp, and a failure to create connector threads cannot be caused on demand. Here
 * such cases are set up by hand, and what is checked is what shows from outside: the packets
 * written to the device and whether the connection stays alive.
 *
 * HOW. The test includes the tunnel stack src/tunnel/stack.c whole (what it needs there is
 * static), uses the real VLESS dialer (src/proto/vless/vldial.c: header, Vision, response parsing)
 * and fakes the node connection under it: vless_connect and transport_* answer as each check
 * needs. The device is a socket pair: what the tunnel writes to "TUN" the test reads at the other
 * end and parses with the same ip_parse. The session descriptor is a pipe with an unread byte:
 * poll always sees it readable, and only the faked transport reads from it, that is, nobody.
 *
 * CONNECTOR THREAD FAILURE is made by the test: while g_refuse_threads is set, the overridden
 * pthread_attr_setstacksize asks for an impossible stack and pthread_create fails, on any libc.
 *
 * No network, privileges or crypto library: the library's types are not in the headers (they see
 * only src/lib/scrypto.h), so no header stubs are needed, and everything that needs TLS is faked.
 * So the test runs in `make unit-test`.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sched.h>

/* ---- connector thread stacks --------------------------------------------------- */

static int g_refuse_threads;

int pthread_attr_setstacksize(pthread_attr_t *a, size_t s) {
    static int (*real)(pthread_attr_t *, size_t);
    if (!real) real = (int (*)(pthread_attr_t *, size_t))dlsym(RTLD_NEXT,
                                                               "pthread_attr_setstacksize");
    /* Nearly all of size_t: larger than any address space, 32-bit included. The stack cannot be
     * mapped, so pthread_create fails without creating a thread. */
    if (g_refuse_threads) s = SIZE_MAX & ~(size_t)0xffff;
    return real(a, s);
}

/* ---- sleeps of connq_release --------------------------------------------------- */

/* connq_release waits for the connectors to report, sleeping 10 ms at a time for up to 15 s. The
 * check needs not the time but what is decided after the LAST sleep: with the hook on, sleeps
 * return at once, and on the given sleep the job behind g_sleep_c "reports". Otherwise a real
 * sleep. */
static int g_sleep_hook;
static int g_sleep_n;
static int g_sleep_report_at;
static int *g_sleep_c;             /* done field of the job that will "report" */

int nanosleep(const struct timespec *req, struct timespec *rem) {
    static int (*real)(const struct timespec *, struct timespec *);
    if (g_sleep_hook) {
        if (++g_sleep_n == g_sleep_report_at && g_sleep_c)
            __atomic_store_n(g_sleep_c, 1, __ATOMIC_RELEASE);
        return 0;
    }
    if (!real) real = (int (*)(const struct timespec *, struct timespec *))dlsym(RTLD_NEXT,
                                                                           "nanosleep");
    return real(req, rem);
}

#include "../src/tunnel/stack.c"
#include "vldial.h"
#include "trxmux.h"
#include "client.h"
#include "../src/tunnel/pool.c"

/* ---- faked node connection ----------------------------------------------------- */

static int g_sess_pipe[2] = { -1, -1 };
static int g_send_rc;                 /* what transport_write returns: 0 or H2_EWINDOW */
static int g_send_again_n;            /* return H2_EWINDOW this many times, then 0 */
static int g_send_calls;
static size_t g_send_last_n;          /* length of the last transport_write */
static size_t g_send_sz[64];
static int g_send_szn;
static int g_tx_direct_n;
static int g_send_dir[64];
static int g_send_ok_first;
static int g_whole;
static long g_grpc_win = -1;
/* The node's room (transport_room): -1 no limit. g_room_on_read, when not -2, becomes the room at
 * the next read, as a WINDOW_UPDATE read from the node would make it. */
static long g_room = -1;
static long g_room_on_read = -2;
static int g_recv_calls;
static int g_recv_rc;                 /* what transport_read_zc returns: 0 or -1 (end of stream) */
static unsigned char g_recv_buf[4096];
static size_t g_recv_n;               /* bytes returned once when g_recv_rc == 0 */
static int g_own_fd;
static int g_connect_ms;
static int g_connect_hold;
static int g_connect_in;
static int g_send_hold;
static int g_wire_on;
static unsigned char g_wire[256 * 1024];
static size_t g_wire_n;
static struct { const struct transport *t; size_t off, n; } g_wlog[8192];
static int g_wlog_n;
static int g_due_arm;
static int g_due_on_read;
static int g_due_rc;
static uint64_t g_due_at;
static uint64_t g_due_target;
static uint64_t g_due_sent;
static uint64_t g_due_calls[256];
static int g_due_n;
static long g_mask_room = -1;
static int g_idle;
static char g_fm_dummy;
static int g_due_block;

static uint64_t due_mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

int vless_connect(const struct vless_node *node, struct transport *conn, int timeout_s) {
    (void)node; (void)timeout_s;
    __atomic_add_fetch(&g_connect_in, 1, __ATOMIC_ACQ_REL);
    struct timespec tick = { 0, 1000000L };
    while (__atomic_load_n(&g_connect_hold, __ATOMIC_ACQUIRE)) nanosleep(&tick, NULL);
    int ms = __atomic_load_n(&g_connect_ms, __ATOMIC_ACQUIRE);
    struct timespec t0, t;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t);
        if ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000 >= ms) break;
        nanosleep(&tick, NULL);
    }
    memset(conn, 0, sizeof(*conn));
    conn->link.fd = __atomic_load_n(&g_own_fd, __ATOMIC_ACQUIRE) ? eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)
                                                                 : g_sess_pipe[0];
    conn->link.plain = 1;
    conn->link.tls.fm = (struct fm_link *)&g_fm_dummy;
    return 0;
}
int transport_write(struct transport *c, const unsigned char *d, size_t n) {
    g_send_calls++;
    g_send_last_n = n;
    if (g_send_szn < 64) {
        g_send_dir[g_send_szn] = g_tx_direct_n;
        g_send_sz[g_send_szn++] = n;
    }
    if (g_grpc_win >= 0) {
        long cost = (long)n + 6 + (n < 128 ? 1 : n < 16384 ? 2 : 3);
        if (cost > g_grpc_win) return H2_EWINDOW;
        g_grpc_win -= cost;
    }
    int rc;
    if (g_send_ok_first > 0) {
        g_send_ok_first--;
        rc = 0;
    } else {
        if (g_send_hold) return H2_EWINDOW;
        if (g_send_again_n > 0) { g_send_again_n--; return H2_EWINDOW; }
        rc = g_send_rc;
    }
    if (!rc && g_due_arm) {
        g_due_arm = 0;
        g_due_at = due_mono() + 30;
        g_due_target = g_due_at;
    }
    if (!rc && g_wire_on && g_wire_n + n <= sizeof g_wire && g_wlog_n < 8192) {
        g_wlog[g_wlog_n].t = c;
        g_wlog[g_wlog_n].off = g_wire_n;
        g_wlog[g_wlog_n++].n = n;
        memcpy(g_wire + g_wire_n, d, n);
        g_wire_n += n;
    }
    return rc;
}
int transport_whole_writes(const struct transport *t) { (void)t; return g_whole; }
const struct transport_ops tr_grpc = { .name = "grpc" };
int transport_read_zc(struct transport *c, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got) {
    (void)buf; (void)cap;
    g_recv_calls++;
    if (g_due_on_read) {
        uint64_t v;
        ssize_t rd = read(c->link.fd, &v, sizeof v);
        (void)rd;
        g_due_on_read = 0;
        g_due_at = due_mono() + 30;
        g_due_target = g_due_at;
    }
    if (g_room_on_read != -2) { g_room = g_room_on_read; g_room_on_read = -2; }
    *got = 0;
    if (g_recv_rc) return g_recv_rc;
    *data = g_recv_buf;
    *got = g_recv_n;
    g_recv_n = 0;
    return 0;
}
static int g_held_on;
int transport_has_data(const struct transport *c) { (void)c; return g_held_on && g_recv_n > 0; }
long transport_room(struct transport *c) {
    (void)c;
    if (g_grpc_win >= 0) return g_grpc_win > 9 ? g_grpc_win - 9 : 0;
    return g_room;
}
void transport_close(struct transport *c) {
    if (__atomic_load_n(&g_own_fd, __ATOMIC_ACQUIRE) && c->link.fd >= 0 && c->link.fd != g_sess_pipe[0])
        close(c->link.fd);
    c->link.fd = -1;
}
void transport_moved(struct transport *c) { (void)c; }
void transport_set_loop(struct transport *c) { (void)c; }
int transport_idle(const struct transport *c) { (void)c; return g_idle; }
int transport_due(struct transport *c, uint64_t now_ms, int *next_ms) {
    *next_ms = -1;
    if (g_due_n < 256) g_due_calls[g_due_n++] = now_ms;
    if (g_due_block) {
        struct pollfd p = { .fd = c->link.fd, .events = POLLOUT };
        if (poll(&p, 1, 0) == 1 && (p.revents & POLLOUT)) {
            g_due_block = 0;
            g_due_sent = now_ms;
            return 0;
        }
        *next_ms = 0;
        return 0;
    }
    if (!g_due_at) return 0;
    if (now_ms < g_due_at) {
        *next_ms = (int)(g_due_at - now_ms);
        return 0;
    }
    if (g_due_rc) return g_due_rc;
    g_due_at = 0;
    g_due_sent = now_ms;
    return 0;
}
long transport_mask_room(struct transport *c) { (void)c; return g_mask_room; }
void transport_direct(struct transport *c) { c->link.rx_direct = 1; }
static int g_can_direct = 1;
void transport_tx_direct(struct transport *c) { (void)c; g_tx_direct_n++; }
int transport_can_tx_direct(const struct transport *c) { (void)c; return g_can_direct; }
int tr_xmux_shares(const struct tr_node *n) { (void)n; return 0; }
int tr_xmux_attach(struct transport *t, const struct tr_node *n, const void *key, const void *dl_key,
                   uint16_t owner, const struct xc_ref *ref)
    { (void)t; (void)n; (void)key; (void)dl_key; (void)owner; (void)ref; return XA_NONE; }
void tr_xmux_host(const struct mux_host *h, int (*stale)(const struct xc_ref *r)) { (void)h; (void)stale; }
int tr_xmux_dial(void *link, int timeout_s) { (void)link; (void)timeout_s; return TR_ECONNECT; }
int tr_xmux_event(unsigned idx, uint32_t ev) { (void)idx; (void)ev; return 0; }
int tr_xmux_pass(uint64_t now_ms, int phase) { (void)now_ms; (void)phase; return 0; }
int tr_xmux_cut(const struct transport *t) { (void)t; return 0; }
int tr_xmux_busy(void) { return 0; }
void tr_xmux_dropped(void *link) { (void)link; }
const char *vless_strerror(int rc) { (void)rc; return "stub"; }
int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n) {
    (void)node; (void)timeout_s; (void)why; (void)why_n; return -1;
}
int vless_probe_timed(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms) {
    (void)node; (void)timeout_s; (void)why; (void)why_n; (void)handshake_ms; (void)ttfb_ms;
    return -1;
}

/* ---- device and client packets ------------------------------------------------- */

static struct tun_dev g_tun;
static int g_dev_peer = -1;           /* other end of "TUN": what the tunnel writes */
static struct vless_node g_node;
/* The stack's dialer: real VLESS to the test node. syn_bad swaps ctx for a node with a bad
 * UUID. */
static struct dialer g_dial = { .ops = &vless_dialer, .ctx = &g_node };

#define CLI_IP  0x0164330au           /* 10.51.100.1 in network order, as ip_parse reads it */
#define SRV_IP  0x0771cbcbu
#define CLI_PORT 40000
#define SRV_PORT 443

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-72s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) g_fail = 1;
}

/* One client packet in the middle of a TUN batch: gathered data stays gathered. */
static void cli_send_more(uint32_t seq, uint32_t ack, unsigned char flags, uint16_t win,
                          const unsigned char *d, size_t n) {
    unsigned char p[2048];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, seq, ack, flags,
                         d, n, win, 0, -1);
    handle_packet(&g_tun, p, l);
}

/* One client packet as a whole TUN batch: what the loop does after a batch, up_flush. */
static void cli_send(uint32_t seq, uint32_t ack, unsigned char flags, uint16_t win,
                     const unsigned char *d, size_t n) {
    cli_send_more(seq, ack, flags, win, d, n);
    up_flush(&g_tun);
}

/* Read everything the tunnel wrote to the device. Returns the number of packets; last gets the
 * key of the last one (it holds the ack number). */
static int dev_drain(struct flow_key *last) {
    unsigned char p[70000];
    int cnt = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) == 0) { if (last) *last = k; cnt++; }
    }
    return cnt;
}

static struct flow_key cli_key(void) {
    struct flow_key k;
    memset(&k, 0, sizeof(k));
    k.src.v4 = CLI_IP; k.dst.v4 = SRV_IP; k.sport = CLI_PORT; k.dport = SRV_PORT; k.proto = 6;
    return k;
}

/* What worker_loop does for a ready job: wait for the connector, up to a deadline, then
 * conn_ready. -1 — no report, or the flow did not open. */
static int wait_ready(struct conn *c, int ms) {
    for (int i = 0; i < ms; i++) {
        if (__atomic_load_n(&c->done, __ATOMIC_ACQUIRE)) return conn_ready(c, &g_tun) ? -1 : 0;
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    return -1;
}

/* Open a connection up to "flow ready, the server answered with the header and 1000 bytes, the
 * client has not acknowledged them yet". Client ISN 1000. */
static struct conn *open_conn_isn(uint16_t win, uint32_t isn) {
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    cli_send(isn, 0, TCP_SYN, win, NULL, 0);
    c = conn_find(&k);
    if (!c || !c->pending || wait_ready(c, 2000) != 0) return NULL;
    cli_send(isn + 1, 2, TCP_ACK, win, NULL, 0);
    g_recv_rc = 0;
    g_recv_buf[0] = 0; g_recv_buf[1] = 0;                 /* VLESS reply: version, addons length */
    memset(g_recv_buf + 2, 'r', 1000);
    g_recv_n = 1002;
    drain_conn(c, &g_tun);
    dev_drain(NULL);
    /* Check the setup itself, so a FAIL cannot mean a broken fixture. "VLESS response
     * consumed" is dialer state, kept in its session. */
    const struct vl_sess *vs = SESS(c);
    if (!vs->established || c->rtx.len != 1000 || c->srv_closed) return NULL;
    return c;
}

static struct conn *open_conn(uint16_t win) { return open_conn_isn(win, 1000); }

/* ---- checks -------------------------------------------------------------------- */

/* Not one connector thread could be created. The SYN must be refused: a queue taken as started
 * would answer SYN-ACK and leave the job pending forever, with neither RST nor retry. */
static void t_no_connectors(void) {
    g_refuse_threads = 1;
    struct flow_key k = cli_key();
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    struct conn *c = conn_find(&k);
    struct flow_key last;
    int synack = 0;
    int n = dev_drain(&last);
    if (n && (last.tcp_flags & TCP_SYN)) synack = 1;
    check(!c && !synack, "no connector threads: SYN refused, no SYN-ACK sent");
    if (c) conn_drop(c);

    /* Threads work again: the next SYN must get a connector, the failure does not stick. */
    g_refuse_threads = 0;
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    c = conn_find(&k);
    check(c && c->pending && wait_ready(c, 2000) == 0,
          "after the failure, connectors start on the next SYN");
    if (c) conn_drop(c);
    dev_drain(NULL);
}

/* The server speaks first (SSH, SMTP): the client sends nothing after the handshake. VLESS gives
 * the node the destination only in the request header, so the stack must send the header alone
 * after SERVER_FIRST_MS, once, and without a Vision frame (as Xray's client does). Before this
 * such a flow never opened: the node waited for the header, the client for the greeting. */
static void server_first(const char *flow, size_t header_n) {
    snprintf(g_node.flow, sizeof(g_node.flow), "%s", flow);
    struct flow_key k = cli_key();
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    struct conn *c = conn_find(&k);
    if (!c || wait_ready(c, 2000) != 0) {
        check(0, "server first: test connection did not open");
        if (c) conn_drop(c);
        g_node.flow[0] = 0;
        return;
    }
    char what[96];
    int calls = g_send_calls;
    /* The SYN-ACK was lost: the client has not acknowledged it and will repeat its SYN. Opening
     * the flow now would let the server's answer go out ahead of the handshake, after which the
     * repeated SYN can no longer be answered: nothing may go, however long it waits. */
    conn_deadlines(c, &g_tun, g_now_ns + 2000 * 1000000ull);
    snprintf(what, sizeof(what), "server first%s: nothing sent before the client's ACK",
             flow[0] ? ", Vision" : "");
    check(g_send_calls == calls && c->our_seq == 2, what);
    cli_send(1001, 2, TCP_ACK, 65535, NULL, 0);
    conn_deadlines(c, &g_tun, c->estab_ns + 499 * 1000000ull);
    snprintf(what, sizeof(what), "server first%s: nothing sent at 499 ms", flow[0] ? ", Vision" : "");
    check(g_send_calls == calls, what);
    conn_deadlines(c, &g_tun, c->estab_ns + 500 * 1000000ull);
    const struct vl_sess *vs = SESS(c);
    snprintf(what, sizeof(what), "server first%s: then at 500 ms the %zu-byte header alone",
             flow[0] ? ", Vision" : "", header_n);
    check(g_send_calls == calls + 1 && g_send_last_n == header_n && vs->header_sent, what);
    conn_deadlines(c, &g_tun, c->estab_ns + 600 * 1000000ull);
    snprintf(what, sizeof(what), "server first%s: and only once", flow[0] ? ", Vision" : "");
    check(g_send_calls == calls + 1, what);
    conn_drop(c);
    dev_drain(NULL);
    g_node.flow[0] = 0;
}

static void t_server_first(void) {
    server_first("", 26);                    /* version, UUID, no addons, cmd, port, IPv4 */
    server_first("xtls-rprx-vision", 44);    /* plus the flow addon: 0a 10 "xtls-rprx-vision" */
}

static struct conn *sf_pending(int connect_ms) {
    snprintf(g_node.flow, sizeof(g_node.flow), "xtls-rprx-vision");
    __atomic_store_n(&g_connect_ms, connect_ms, __ATOMIC_RELEASE);
    struct flow_key k = cli_key();
    g_now_ns = now_ns();
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    struct conn *c = conn_find(&k);
    return c && c->pending ? c : NULL;
}

static int sf_ready(struct conn *c) {
    uint64_t end = now_ns() + 10000 * 1000000ull;
    while (!__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) && now_ns() < end) {
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    __atomic_store_n(&g_connect_ms, 0, __ATOMIC_RELEASE);
    if (!__atomic_load_n(&c->done, __ATOMIC_ACQUIRE)) return -1;
    g_now_ns = now_ns();
    return conn_ready(c, &g_tun) ? -2 : 0;
}

static void sf_end(struct conn *c) {
    __atomic_store_n(&g_connect_ms, 0, __ATOMIC_RELEASE);
    if (c) conn_drop(c);
    dev_drain(NULL);
    g_node.flow[0] = 0;
}

/* catches: the wait counted from the client's handshake while the link was still dialing */
static void t_server_first_from_ready(void) {
    struct conn *c = sf_pending(301);
    if (!c) {
        check(0, "server first from ready: fixture pending connection");
        sf_end(NULL);
        return;
    }
    cli_send(1001, 2, TCP_ACK, 65535, NULL, 0);
    uint64_t t0 = c->estab_ns;
    int calls = g_send_calls;
    int r = sf_ready(c);
    if (r != 0) {
        check(0, r == -1 ? "server first from ready: fixture dial done" : "server first from ready: fixture flow ready");
        sf_end(NULL);
        return;
    }
    check(t0 && c->estab_ns >= t0 + 300 * 1000000ull,
          "server first from ready: the wait starts when the link is ready");
    conn_deadlines(c, &g_tun, t0 + 600 * 1000000ull);
    check(g_send_calls == calls, "server first from ready: nothing 600 ms after the client's handshake");
    conn_deadlines(c, &g_tun, c->estab_ns + 500 * 1000000ull);
    check(g_send_calls == calls + 1 && g_send_last_n == 44,
          "server first from ready: the header alone 500 ms after the link is ready");
    sf_end(c);
}

/* catches: the helper's condition without sent_any, which keeps a flow that spoke waiting and spins the loop */
static void t_server_first_early_twin(void) {
    struct conn *c = sf_pending(100);
    if (!c) {
        check(0, "server first early: fixture pending connection");
        sf_end(NULL);
        return;
    }
    unsigned char d[100];
    memset(d, 'e', sizeof d);
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof d);
    int held = c->early_n == 100;
    int calls = g_send_calls;
    g_send_szn = 0;
    if (!held || sf_ready(c) != 0) {
        check(0, "server first early: fixture early data and flow ready");
        sf_end(NULL);
        return;
    }
    check(g_send_calls == calls + 1 && g_send_last_n > 44 + 100 && !c->early,
          "server first early: the header and the data in one send at ready");
    int gone = conn_deadlines(c, &g_tun, c->estab_ns + 500 * 1000000ull);
    if (!gone) gone = conn_deadlines(c, &g_tun, c->estab_ns + 1000 * 1000000ull);
    int lone = 0;
    for (int i = 0; i < g_send_szn; i++) lone |= g_send_sz[i] == 44;
    check(!gone && g_send_calls == calls + 1 && !lone && first_wait_left(c, c->estab_ns + 1000 * 1000000ull) < 0,
          "server first early: no lone header after the data");
    sf_end(gone ? NULL : c);
}

/* catches: a flow the node already ended still waiting for its first payload */
static void t_server_first_srv_closed(void) {
    struct flow_key k = cli_key();
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    struct conn *c = conn_find(&k);
    if (!c || wait_ready(c, 2000) != 0) {
        check(0, "server first closed: fixture connection");
        if (c) conn_drop(c);
        return;
    }
    g_now_ns = now_ns();
    cli_send(1001, 2, TCP_ACK, 65535, NULL, 0);
    g_recv_rc = -1;
    g_recv_n = 0;
    drain_conn(c, &g_tun);
    g_recv_rc = 0;
    c = conn_find(&k);
    if (!c || !c->srv_closed || c->sent_any) {
        check(0, "server first closed: fixture stream ended by the node");
        if (c) conn_drop(c);
        dev_drain(NULL);
        return;
    }
    int calls = g_send_calls;
    int64_t left = first_wait_left(c, c->estab_ns + 600 * 1000000ull);
    int gone = conn_deadlines(c, &g_tun, c->estab_ns + 600 * 1000000ull);
    check(left < 0 && g_send_calls == calls, "server first closed: no header into a stream the node ended");
    if (!gone) conn_drop(c);
    dev_drain(NULL);
}

/* catches: the helper's condition without early, which sends a lone header ahead of refused early data */
static void t_server_first_early_refused(void) {
    struct conn *c = sf_pending(100);
    if (!c) {
        check(0, "server first early refused: fixture pending connection");
        sf_end(NULL);
        return;
    }
    unsigned char d[100];
    memset(d, 'e', sizeof d);
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof d);
    int held = c->early_n == 100;
    g_send_szn = 0;
    g_send_again_n = 2;
    if (!held || sf_ready(c) != 0 || !c->early) {
        g_send_again_n = 0;
        check(0, "server first early refused: fixture early data held at ready");
        sf_end(NULL);
        return;
    }
    int gone = conn_deadlines(c, &g_tun, c->estab_ns + 500 * 1000000ull);
    int lone = 0;
    for (int i = 0; i < g_send_szn; i++) lone |= g_send_sz[i] == 44;
    if (!gone) gone = conn_deadlines(c, &g_tun, c->estab_ns + 600 * 1000000ull);
    g_send_again_n = 0;
    check(!gone && !lone && !c->early && g_send_last_n > 44 + 100,
          "server first early refused: the data goes with the header, never a lone header first");
    sf_end(gone ? NULL : c);
}

/* The node's room caps the client's window (dialer_ops.room). Before, the client was granted the
 * full window whatever the node could take: against a 94 KB HTTP/2 window every refusal was a
 * "loss" and a retransmission timeout, uploads over grpc ran at 10-20 Mbit/s with stalls. */
static void t_room_window(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "room: test connection did not open"); return; }
    unsigned char d[100];
    memset(d, 'u', sizeof(d));
    struct flow_key last;
    uint32_t seq = 1001;
    cli_send(seq, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));        /* the header goes */
    seq += sizeof(d);
    flush_acks(&g_tun);
    dev_drain(&last);
    check(last.window == 65535, "room: no limit from the transport, the full window");

    g_room = 5000;
    cli_send(seq, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    seq += sizeof(d);
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    check(last.ack == seq && last.window == 5000, "room: the window is capped by the node's room");

    g_room = 0;
    cli_send(seq, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    seq += sizeof(d);
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    check(last.ack == seq && last.window == 0, "room: no room, zero window");

    /* The client's zero-window probe: one number below the expected, no data. */
    cli_send(seq - 1, 2, TCP_ACK, 65535, NULL, 0);
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(n == 1 && last.ack == seq && last.window == 0, "room: a zero-window probe is answered");

    /* A WINDOW_UPDATE from the node: the window update goes to the client without waiting for
     * a packet from it. */
    g_room_on_read = 60000;
    g_win_woke = 0;
    drain_conn(c, &g_tun);
    check(c->ack_due && g_win_woke, "room: grown by a read from the node, window update due");
    flush_acks(&g_tun);
    g_win_woke = 0;
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(n >= 1 && last.ack == seq && last.window == 60000, "room: the update carries the new window");

    /* Growth below WIN_UPDATE_MIN on an open window waits for the next ACK. */
    g_room_on_read = 60000 + WIN_UPDATE_MIN - 1;
    drain_conn(c, &g_tun);
    check(!c->ack_due && !g_win_woke, "room: small growth sends nothing by itself");

    g_room = -1;
    g_room_on_read = -2;

    /* The loop behind the device (a TUN batch hit TUN_DRAIN_MAX): a scaled client gets at most
     * RCV_WND_BACKLOG, so its unacknowledged data, which waits in the device queue ahead of the
     * ACKs of downloads, stays short; the full window again once the loop keeps up. */
    uint32_t save_wnd = g_rcv_wnd;
    uint8_t save_shift = g_rcv_shift;
    rcv_window_set(4u << 20);
    c->ws_on = 1;
    uint32_t full = (uint32_t)rcv_win_field(c) << g_rcv_shift;
    g_tun_backlog = 1;
    uint32_t held = (uint32_t)rcv_win_field(c) << g_rcv_shift;
    g_tun_backlog = 0;
    uint32_t back = (uint32_t)rcv_win_field(c) << g_rcv_shift;
    check(full >= (4u << 20) && held <= RCV_WND_BACKLOG && held > RCV_WND_BACKLOG / 2 && back == full,
          "backlog: the window drops to RCV_WND_BACKLOG while behind, and comes back");
    c->ws_on = 0;
    g_rcv_wnd = save_wnd;
    g_rcv_shift = save_shift;
    conn_drop(c);
    dev_drain(NULL);
}

/* Consecutive data segments of one flow in one TUN batch go to the node as ONE send (g_up in
 * stack.c): one TLS record and one write instead of one per 1.4 KB segment, which cost uploads
 * 80% of the loop. Acknowledged only once the node took them, as before. */
static void t_gather(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "gather: test connection did not open"); return; }
    unsigned char d[1000];
    memset(d, 'g', sizeof(d));
    struct flow_key last;
    int calls = g_send_calls;
    cli_send_more(1001, 2, TCP_ACK, 65535, d, sizeof(d));
    cli_send_more(2001, 2, TCP_ACK, 65535, d, sizeof(d));
    cli_send_more(3001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    check(g_send_calls == calls && c->client_seq == 1001,
          "gather: three segments in a batch, nothing sent or acknowledged yet");
    up_flush(&g_tun);
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    check(g_send_calls == calls + 1 && g_send_last_n == 26 + 3000 && c->client_seq == 4001 &&
          last.ack == 4001, "gather: end of batch, one send (header + 3000), one ACK of all");

    /* A FIN after gathered data: the data goes first, then the FIN's own segment. */
    calls = g_send_calls;
    cli_send_more(4001, 2, TCP_ACK, 65535, d, sizeof(d));
    cli_send_more(5001, 2, TCP_ACK | TCP_FIN, 65535, d, 10);
    check(g_send_calls == calls + 2 && c->client_seq == 5012 && c->client_fin,
          "gather: a FIN sends the gathered data first, in order");
    conn_drop(c);
    dev_drain(NULL);

    /* A gap: the gathered bytes go, the segment past the gap is not taken. */
    c = open_conn(65535);
    if (!c) { check(0, "gather: test connection did not open"); return; }
    calls = g_send_calls;
    cli_send_more(1001, 2, TCP_ACK, 65535, d, sizeof(d));
    cli_send_more(3001, 2, TCP_ACK, 65535, d, sizeof(d));
    up_flush(&g_tun);
    check(g_send_calls == calls + 1 && c->client_seq == 2001,
          "gather: a segment past a gap sends what was gathered, and is not taken");

    /* The node refuses the gathered send (window closed): nothing is acknowledged, and the
     * continuation in the same batch is not taken either: the client resends from 2001. */
    g_send_again_n = 1;
    g_recv_rc = -1;                     /* no WINDOW_UPDATE comes: the wait reads end of stream */
    cli_send_more(2001, 2, TCP_ACK, 65535, d, sizeof(d));
    up_flush(&g_tun);
    check(c->client_seq == 2001, "gather: send refused, nothing acknowledged");
    g_send_again_n = 0;
    g_recv_rc = 0;
    conn_drop(c);
    dev_drain(NULL);

    /* The buffer is full and the next segment forces a send, which the node refuses (window
     * closed, and still closed after the wait). That segment follows bytes that were NOT taken:
     * it must not start a new gathering, or the stream would skip them. */
    c = open_conn(65535);
    if (!c) { check(0, "gather: test connection did not open"); return; }
    uint32_t seq = 1001;
    while (seq - 1001 + sizeof(d) <= UP_MAX) {
        cli_send_more(seq, 2, TCP_ACK, 65535, d, sizeof(d));
        seq += sizeof(d);
    }
    g_send_again_n = 2;                 /* the send and its retry after the wait */
    g_recv_rc = 0;
    g_recv_n = 0;
    cli_send_more(seq, 2, TCP_ACK, 65535, d, sizeof(d));
    up_flush(&g_tun);
    check(c->client_seq == 1001 && g_ls->up.c == NULL,
          "gather: a refused send when full, the next segment is not taken either");
    g_send_again_n = 0;
    conn_drop(c);
    dev_drain(NULL);
}

static unsigned char g_up_stream[16400];

static void up_stream_fill(void) {
    for (size_t i = 0; i < sizeof g_up_stream; i++) g_up_stream[i] = (unsigned char)('a' + i / 1000);
}

static struct conn *up_open_isn(uint32_t isn) {
    struct conn *c = open_conn_isn(65535, isn);
    if (!c) return NULL;
    unsigned char d[100];
    memset(d, 'h', sizeof d);
    cli_send(isn + 1, 2, TCP_ACK, 65535, d, sizeof d);
    flush_acks(&g_tun);
    dev_drain(NULL);
    if (c->client_seq != isn + 101 || !((const struct vl_sess *)SESS(c))->header_sent) return NULL;
    g_send_szn = 0;
    g_wire_on = 1;
    g_wire_n = 0;
    g_wlog_n = 0;
    return c;
}

static struct conn *up_open(void) { return up_open_isn(1000); }

static void up_close(struct conn *c) {
    g_wire_on = 0;
    g_send_ok_first = 0;
    g_send_again_n = 0;
    g_send_rc = 0;
    g_whole = 0;
    g_room = -1;
    g_grpc_win = -1;
    g_recv_rc = 0;
    g_recv_n = 0;
    g_node.flow[0] = 0;
    if (c && c->used) conn_drop(c);
    dev_drain(NULL);
}

static void up_gather(uint32_t seq, int segs) {
    for (int i = 0; i < segs; i++)
        cli_send_more(seq + (uint32_t)i * 1000, 2, TCP_ACK, 65535, g_up_stream + i * 1000, 1000);
}

static void t_up_cut(void) {
    /* catches: the gather sent as one 16 KiB write */
    up_stream_fill();
    struct conn *c = up_open();
    if (!c) { check(0, "up cut: test connection did not open"); up_close(NULL); return; }
    uint32_t seq = c->client_seq;
    up_gather(seq, 16);
    up_flush(&g_tun);
    flush_acks(&g_tun);
    struct flow_key last;
    memset(&last, 0, sizeof last);
    int acks = dev_drain(&last);
    check(g_send_szn == 2 && g_send_sz[0] == 8192 && g_send_sz[1] == 7808 &&
              g_wire_n == 16000 && !memcmp(g_wire, g_up_stream, 16000),
          "up cut: a 16000-byte gather goes as 8192 + 7808, in order");
    check(c->client_seq == seq + 16000 && acks == 1 && last.ack == seq + 16000,
          "up cut: all 16000 acknowledged, with one ACK");
    up_close(c);
}

static void t_up_cut_partial(void) {
    /* catches: all or nothing acknowledged for a partly taken gather */
    up_stream_fill();
    struct conn *c = up_open();
    if (!c) { check(0, "up cut partial: test connection did not open"); up_close(NULL); return; }
    uint32_t seq = c->client_seq;
    g_send_ok_first = 1;
    g_send_again_n = 2;
    g_recv_rc = 0;
    g_recv_n = 0;
    up_gather(seq, 16);
    up_flush(&g_tun);
    check(g_send_szn == 3 && g_send_sz[0] == 8192 && g_send_sz[1] == 7808 && g_send_sz[2] == 7808 &&
              g_wire_n == 8192 && !memcmp(g_wire, g_up_stream, 8192),
          "up cut partial: the first piece taken, the second refused twice");
    flush_acks(&g_tun);
    struct flow_key last;
    memset(&last, 0, sizeof last);
    dev_drain(&last);
    check(c->client_seq == seq + 8192 && g_ls->up.c == NULL && c->used && !c->srv_closed &&
              last.ack == seq + 8192,
          "up cut partial: exactly the 8192 taken bytes acknowledged, nothing left gathered");
    g_send_szn = 0;
    cli_send(seq + 8192, 2, TCP_ACK, 65535, g_up_stream + 8192, 1000);
    check(g_send_szn == 1 && g_send_sz[0] == 1000 && c->client_seq == seq + 9192 &&
              g_wire_n == 9192 && !memcmp(g_wire, g_up_stream, 9192),
          "up cut partial: the client's resend at the new seq goes on, no byte lost or doubled");
    up_close(c);
}

static void t_up_cut_resend_whole(void) {
    /* catches: a resent segment that straddles the partial ACK dropped instead of trimmed to its tail */
    up_stream_fill();
    struct conn *c = up_open();
    if (!c) { check(0, "up cut resend: test connection did not open"); up_close(NULL); return; }
    uint32_t seq = c->client_seq;
    g_send_ok_first = 1;
    g_send_again_n = 2;
    g_recv_rc = 0;
    g_recv_n = 0;
    up_gather(seq, 16);
    up_flush(&g_tun);
    flush_acks(&g_tun);
    dev_drain(NULL);
    if (c->client_seq != seq + 8192) { check(0, "up cut resend: the first piece was not taken"); up_close(c); return; }
    g_send_szn = 0;
    c->ack_due = 0;
    cli_send(seq + 7000, 2, TCP_ACK, 65535, g_up_stream + 7000, 1000);
    check(g_send_szn == 0 && c->client_seq == seq + 8192 && c->ack_due && g_wire_n == 8192,
          "up cut resend: a segment wholly below the ACK is dropped and acknowledged again");
    c->ack_due = 0;
    cli_send(seq + 9000, 2, TCP_ACK, 65535, g_up_stream + 9000, 1000);
    check(g_send_szn == 0 && c->client_seq == seq + 8192 && c->ack_due && g_wire_n == 8192,
          "up cut resend: a segment past the ACK is dropped and acknowledged");
    cli_send(seq + 8000, 2, TCP_ACK, 65535, g_up_stream + 8000, 1000);
    check(g_send_szn == 1 && g_send_sz[0] == 808 && c->client_seq == seq + 9000 &&
              g_wire_n == 9000 && !memcmp(g_wire, g_up_stream, 9000),
          "up cut resend: the whole segment across the ACK sends its 808-byte tail only");
    cli_send(seq + 8000, 2, TCP_ACK | TCP_FIN, 65535, g_up_stream + 8000, 1001);
    check(g_send_szn == 2 && g_send_sz[1] == 1 && c->client_seq == seq + 9002 && c->client_fin &&
              g_wire_n == 9001 && !memcmp(g_wire, g_up_stream, 9001),
          "up cut resend: a FIN on a trimmed segment stays with its tail");
    up_close(c);
    c = up_open();
    if (!c) { check(0, "up cut resend: second test connection did not open"); up_close(NULL); return; }
    seq = c->client_seq;
    cli_send(seq, 2, TCP_ACK, 65535, g_up_stream, 1000);
    g_send_szn = 0;
    cli_send(seq, 2, TCP_ACK | TCP_FIN, 65535, g_up_stream, 1000);
    check(g_send_szn == 0 && c->client_seq == seq + 1001 && c->client_fin && g_wire_n == 1000,
          "up cut resend: taken data resent with a FIN gives the FIN alone");
    up_close(c);
}

static void t_up_cut_resend_wrap(void) {
    /* catches: the trim bounds compared unsigned, so a resent segment across 2^32 is dropped */
    up_stream_fill();
    struct conn *c = up_open_isn(0xFFFFFFFFu - 8200u);
    if (!c) { check(0, "up cut resend wrap: test connection did not open"); up_close(NULL); return; }
    uint32_t seq = c->client_seq;
    g_send_ok_first = 1;
    g_send_again_n = 2;
    g_recv_rc = 0;
    g_recv_n = 0;
    up_gather(seq, 16);
    up_flush(&g_tun);
    flush_acks(&g_tun);
    dev_drain(NULL);
    if (seq != 0xFFFFFFFFu - 8099u || c->client_seq != 92) {
        check(0, "up cut resend wrap: the partial ACK did not land past 2^32");
        up_close(c);
        return;
    }
    g_send_szn = 0;
    cli_send(seq + 8000, 2, TCP_ACK, 65535, g_up_stream + 8000, 1000);
    check(g_send_szn == 1 && g_send_sz[0] == 808 && c->client_seq == 900 &&
              g_wire_n == 9000 && !memcmp(g_wire, g_up_stream, 9000),
          "up cut resend wrap: the segment across 2^32 sends its 808-byte tail only");
    up_close(c);
}

static void t_up_cut_resend_early(void) {
    /* catches: a fully taken duplicate trimmed to nothing and held behind the early tail without an ACK */
    up_stream_fill();
    struct conn *c = up_open();
    if (!c) { check(0, "up cut resend early: test connection did not open"); up_close(NULL); return; }
    uint32_t seq = c->client_seq;
    c->early = malloc(EARLY_CAP);
    if (!c->early) { check(0, "up cut resend early: no memory"); up_close(c); return; }
    memset(c->early, 'e', 10);
    c->early_n = 10;
    c->early_off = 0;
    g_send_again_n = 1;
    c->ack_due = 0;
    unsigned char d[100];
    memset(d, 'h', sizeof d);
    cli_send(seq - 100, 2, TCP_ACK, 65535, d, sizeof d);
    check(c->ack_due && g_send_szn == 0 && c->client_seq == seq && c->early_n == 10 && c->early_off == 0,
          "up cut resend early: a taken duplicate is acknowledged again while the early tail waits");
    up_close(c);
}

static void t_up_cut_fatal(void) {
    /* catches: client_seq moved only after the whole gather, or the rest skipped */
    up_stream_fill();
    struct conn *c = up_open();
    if (!c) { check(0, "up cut fatal: test connection did not open"); up_close(NULL); return; }
    uint32_t seq = c->client_seq;
    struct flow_key k = cli_key();
    g_send_ok_first = 1;
    g_send_rc = -1;
    up_gather(seq, 16);
    up_flush(&g_tun);
    struct flow_key last;
    memset(&last, 0, sizeof last);
    dev_drain(&last);
    check(g_send_szn == 2 && g_send_sz[0] == 8192 && g_send_sz[1] == 7808 && conn_find(&k) == NULL,
          "up cut fatal: the second piece fails, the flow is reset");
    check((last.tcp_flags & TCP_RST) && last.ack == seq + 8192,
          "up cut fatal: the RST acknowledges the taken 8192 bytes");
    up_close(NULL);
}

static void t_up_whole_packet_up(void) {
    /* catches: private packet-up cut into two POSTs per gather */
    up_stream_fill();
    struct conn *c = up_open();
    if (!c) { check(0, "up whole: test connection did not open"); up_close(NULL); return; }
    uint32_t seq = c->client_seq;
    g_whole = 1;
    up_gather(seq, 16);
    up_flush(&g_tun);
    check(g_send_szn == 1 && g_send_sz[0] == 16000 && c->client_seq == seq + 16000 &&
              !memcmp(g_wire, g_up_stream, 16000),
          "up whole: packet-up keeps the 16000-byte gather as one write");
    up_close(c);
}

static struct conn *first_open(const char *flow) {
    snprintf(g_node.flow, sizeof(g_node.flow), "%s", flow);
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    c = conn_find(&k);
    if (!c || wait_ready(c, 2000) != 0) return NULL;
    cli_send(1001, 2, TCP_ACK, 65535, NULL, 0);
    dev_drain(NULL);
    if (((const struct vl_sess *)SESS(c))->header_sent) return NULL;
    g_send_szn = 0;
    g_wire_on = 1;
    g_wire_n = 0;
    g_wlog_n = 0;
    return c;
}

static const unsigned char g_hdr_uuid[16] = { 0x8f, 0x7d, 0x3b, 0x1a, 0x2c, 0x4e, 0x4f, 0x60,
                                              0x9a, 0x81, 0xb5, 0xd7, 0xe6, 0xc3, 0x01, 0x24 };

static size_t first_header(int vision, unsigned char *h) {
    size_t i = 0;
    h[i++] = 0;
    memcpy(h + i, g_hdr_uuid, 16);
    i += 16;
    if (vision) {
        h[i++] = 18;
        h[i++] = 0x0a;
        h[i++] = 16;
        memcpy(h + i, "xtls-rprx-vision", 16);
        i += 16;
    } else {
        h[i++] = 0;
    }
    h[i++] = 1;
    h[i++] = 0x01;
    h[i++] = 0xbb;
    h[i++] = 1;
    uint32_t a = SRV_IP;
    memcpy(h + i, &a, 4);
    i += 4;
    return i;
}

static void t_first_write_as_xray(void) {
    /* catches: header and data cut at the gather's own pieces (8192, 26, 808), not packed as Xray's BufferedWriter packs them, or the Vision gather's first piece cut at 8148 with 44 B sent unframed */
    up_stream_fill();
    unsigned char h[64];
    size_t hn = first_header(0, h);
    struct conn *c = first_open("");
    if (!c) { check(0, "first write: test connection did not open"); up_close(NULL); return; }
    up_gather(1001, 9);
    up_flush(&g_tun);
    check(hn == 26 && g_send_szn == 2 && g_send_sz[0] == 8192 && g_send_sz[1] == 834 &&
              g_wire_n == 26 + 9000 && !memcmp(g_wire, h, 26) &&
              !memcmp(g_wire + 26, g_up_stream, 9000) && c->client_seq == 10001,
          "first write: header + 9000 goes as 8192, 834, in order");
    up_close(c);

    hn = first_header(1, h);
    c = first_open("xtls-rprx-vision");
    if (!c) { check(0, "first write: Vision connection did not open"); up_close(NULL); return; }
    up_gather(1001, 9);
    up_flush(&g_tun);
    size_t vf[3][3] = {{0}};
    size_t at = 44 + 16, vfn = 0;
    int vok = g_wire_n >= at && !memcmp(g_wire, h, 44) && !memcmp(g_wire + 44, g_hdr_uuid, 16);
    while (vok && vfn < 3 && at + 5 <= g_wire_n) {
        const unsigned char *f = g_wire + at;
        vf[vfn][0] = f[0];
        vf[vfn][1] = ((size_t)f[1] << 8) | f[2];
        vf[vfn][2] = ((size_t)f[3] << 8) | f[4];
        at += 5 + vf[vfn][1] + vf[vfn][2];
        vfn++;
    }
    vok = vok && vfn == 3 && at == g_wire_n;
    size_t pa = vf[0][2], pb = vf[1][2], pc = vf[2][2];
    check(hn == 44 && vok && g_send_szn == 3 && g_send_sz[0] == 8192 &&
              g_send_sz[1] == 70 + pa + pb && g_send_sz[2] == 813 + pc &&
              pa < 256 && pb < 256 && pc < 256,
          "first write, Vision, as Xray: writes 8192, 70 + pads, 813 + pad");
    check(vok && vf[0][0] == VISION_CMD_CONTINUE && vf[1][0] == VISION_CMD_CONTINUE &&
              vf[2][0] == VISION_CMD_CONTINUE && vf[0][1] == 4096 && vf[1][1] == 4096 &&
              vf[2][1] == 808 && !memcmp(g_wire + 60 + 5, g_up_stream, 4096) &&
              !memcmp(g_wire + 60 + 5 + 4096 + pa + 5, g_up_stream + 4096, 4096) &&
              !memcmp(g_wire + 60 + 15 + 8192 + pa + pb, g_up_stream + 8192, 808) &&
              c->client_seq == 10001,
          "Vision, as Xray: header + 4096 + 4096, then 808");
    up_close(c);

    hn = first_header(0, h);
    c = first_open("");
    if (!c) { check(0, "first write: packet-up connection did not open"); up_close(NULL); return; }
    g_whole = 1;
    up_gather(1001, 9);
    up_flush(&g_tun);
    check(g_send_szn == 1 && g_send_sz[0] == 9026 && !memcmp(g_wire, h, 26) &&
              !memcmp(g_wire + 26, g_up_stream, 9000),
          "first write, packet-up: header + 9000 as one write of 9026");
    up_close(c);
}

static void t_first_write_cut_per_piece(void) {
    /* catches: the cut read once per flush, so every piece of a first gather is 8192 less the header */
    up_stream_fill();
    unsigned char h[64];
    first_header(0, h);
    struct conn *c = first_open("");
    if (!c) { check(0, "first write per piece: test connection did not open"); up_close(NULL); return; }
    up_gather(1001, 16);
    cli_send_more(1001 + 16000, 2, TCP_ACK, 65535, g_up_stream + 16000, 392);
    up_flush(&g_tun);
    check(g_send_szn == 3 && g_send_sz[0] == 8192 && g_send_sz[1] == 8192 && g_send_sz[2] == 34 &&
              g_wire_n == 26 + 16392 && !memcmp(g_wire, h, 26) &&
              !memcmp(g_wire + 26, g_up_stream, 16392) && c->client_seq == 1001 + 16392,
          "first write per piece: header + 16392 goes as 8192, 8192, 34");
    up_close(c);
}

static void t_up_write_size(void) {
    /* catches: the first piece sized without the header, or with the wrong header for the host, family or flow */
    static struct vl_sess s;
    struct flow_key k = cli_key();
    size_t v4, host, v6, vis, sent, whole;
    memset(&s, 0, offsetof(struct vl_sess, dg));
    s.t.link.fd = -1;
    vless_dialer.clear(&s);
    vless_dialer.flow_open(&g_node, &s, &k, 0);
    v4 = vless_dialer.up_write(&g_node, &s);
    vless_dialer.set_host(&s, "example.com");
    host = vless_dialer.up_write(&g_node, &s);
    s.header_sent = 1;
    sent = vless_dialer.up_write(&g_node, &s);
    g_whole = 1;
    whole = vless_dialer.up_write(&g_node, &s);
    g_whole = 0;
    k.v6 = 1;
    vless_dialer.clear(&s);
    vless_dialer.flow_open(&g_node, &s, &k, 0);
    v6 = vless_dialer.up_write(&g_node, &s);
    k.v6 = 0;
    snprintf(g_node.flow, sizeof g_node.flow, "xtls-rprx-vision");
    vless_dialer.clear(&s);
    vless_dialer.flow_open(&g_node, &s, &k, 0);
    vis = vless_dialer.up_write(&g_node, &s);
    g_node.flow[0] = 0;
    check(v4 == 8192 - 26 && host == 8192 - 34 && v6 == 8192 - 38 && vis == 8192 &&
              sent == 8192 && whole == 0,
          "up_write: 8192 less the unsent header (IPv4 26, host 34, IPv6 38), Vision 8192, then 8192");
}

static size_t sh(unsigned char *o, unsigned cipher, int sv) {
    size_t ext = sv ? 46 : 40, hl = 72 + ext, i = 0;
    o[i++] = 0x16; o[i++] = 0x03; o[i++] = 0x03;
    o[i++] = (unsigned char)((hl + 4) >> 8); o[i++] = (unsigned char)(hl + 4);
    o[i++] = 0x02; o[i++] = 0x00; o[i++] = (unsigned char)(hl >> 8); o[i++] = (unsigned char)hl;
    o[i++] = 0x03; o[i++] = 0x03;
    memset(o + i, 0x11, 32); i += 32;
    o[i++] = 0x20;
    memset(o + i, 0x22, 32); i += 32;
    o[i++] = (unsigned char)(cipher >> 8); o[i++] = (unsigned char)cipher;
    o[i++] = 0x00;
    o[i++] = (unsigned char)(ext >> 8); o[i++] = (unsigned char)ext;
    if (sv) {
        static const unsigned char v[6] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
        memcpy(o + i, v, 6); i += 6;
    }
    static const unsigned char ks[8] = {0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
    memcpy(o + i, ks, 8); i += 8;
    memset(o + i, 0x33, 32); i += 32;
    return i;
}

static size_t vframe(unsigned char *o, int cmd, const unsigned char *d, size_t n) {
    o[0] = (unsigned char)cmd;
    o[1] = (unsigned char)(n >> 8);
    o[2] = (unsigned char)n;
    o[3] = 0;
    o[4] = 0;
    memcpy(o + 5, d, n);
    return 5 + n;
}

static size_t down_head(unsigned char *o) {
    o[0] = 0;
    o[1] = 0;
    memcpy(o + 2, g_hdr_uuid, 16);
    return 18;
}

static int g_emit_n;
static int down_emit(void *arg, const unsigned char *p, size_t n) {
    (void)arg; (void)p; (void)n;
    g_emit_n++;
    return 0;
}

static size_t up_ch(unsigned char *b) {
    static const unsigned char h[6] = {0x16, 0x03, 0x01, 0x05, 0xc1, 0x01};
    memset(b, 0x42, 1478);
    memcpy(b, h, 6);
    return 1478;
}

static size_t up_fl(unsigned char *b) {
    static const unsigned char h[11] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x35};
    memcpy(b, h, 11);
    memset(b + 11, 0xaa, 53);
    return 64;
}

static size_t up_get(unsigned char *b) {
    static const unsigned char h[5] = {0x17, 0x03, 0x03, 0x00, 0x77};
    memcpy(b, h, 5);
    memset(b + 5, 0x47, 119);
    return 124;
}

static int wire_frame(size_t at, const unsigned char *d, size_t n) {
    if (at + 5 + n > g_wire_n || ((size_t)g_wire[at + 1] << 8 | g_wire[at + 2]) != n) return -1;
    if (memcmp(g_wire + at + 5, d, n)) return -1;
    return g_wire[at];
}

static void switch_up(int can, int again) {
    char what[112];
    const char *tag = again ? ", resent" : can ? "" : ", gate shut";
    static unsigned char d[2048];
    unsigned char r[256], hs[160];
    g_can_direct = can;
    g_tx_direct_n = 0;
    struct conn *c = first_open("xtls-rprx-vision");
    if (!c) {
        snprintf(what, sizeof what, "vision switch up%s: test connection did not open", tag);
        check(0, what);
        up_close(NULL);
        g_can_direct = 1;
        return;
    }
    struct vl_sess *vs = SESS(c);
    size_t n = up_ch(d);
    int s1 = upstream_send(c, d, n);
    int ch = g_wire_n > 60 && !memcmp(g_wire + 44, g_hdr_uuid, 16) ? wire_frame(60, d, n) : -1;
    size_t rn = down_head(r);
    rn += vframe(r + rn, 0, hs, sh(hs, 0x1301, 1));
    int dr = vless_dialer.deliver(&g_node, vs, 0, r, rn, down_emit, NULL);
    int xtls = vs->vis.enable_xtls;
    size_t at = g_wire_n;
    n = up_fl(d);
    int s2 = upstream_send(c, d, n);
    int fl = wire_frame(at, d, n);
    snprintf(what, sizeof what, "vision switch up%s: CH and Finished continue, the ServerHello enables", tag);
    check(s1 == SEND_OK && s2 == SEND_OK && dr == 0 && ch == VISION_CMD_CONTINUE && xtls == 1 &&
              fl == VISION_CMD_CONTINUE && g_tx_direct_n == 0, what);
    n = up_get(d);
    int refused = 0;
    if (again) {
        g_send_again_n = 1;
        int sa = upstream_send(c, d, n);
        refused = sa == SEND_AGAIN && g_tx_direct_n == 0 && vs->vis.is_padding == 1 && vs->vis.tx_switch == 0;
        snprintf(what, sizeof what, "vision switch up%s: a refused GET keeps padding and does not switch", tag);
        check(refused, what);
    }
    at = g_wire_n;
    int wi = g_send_szn;
    int s3 = upstream_send(c, d, n);
    int get = wire_frame(at, d, n);
    snprintf(what, sizeof what, "vision switch up%s: GET frame %s, switch %s", tag,
             can ? "direct" : "end", can ? "once, after its write" : "never");
    if (can)
        check(s3 == SEND_OK && get == VISION_CMD_DIRECT && g_tx_direct_n == 1 && wi < 64 &&
                  g_send_szn == wi + 1 && g_send_dir[wi] == 0, what);
    else
        check(s3 == SEND_OK && get == VISION_CMD_END && g_tx_direct_n == 0, what);
    unsigned char u[100];
    memset(u, 'u', sizeof u);
    int s4 = upstream_send(c, u, sizeof u);
    snprintf(what, sizeof what, "vision switch up%s: the next 100 B go as they are", tag);
    check(s4 == SEND_OK && g_send_last_n == 100 && g_wire_n >= 100 &&
              !memcmp(g_wire + g_wire_n - 100, u, 100) && g_tx_direct_n == (can ? 1 : 0), what);
    up_close(c);
    g_can_direct = 1;
}

/* catches: direct where the gate forbids it, the switch before the frame left, a retry that loses it */
static void t_vision_switch_up(void) {
    switch_up(1, 0);
    switch_up(0, 0);
    switch_up(1, 1);
}

/* catches: the uplink filter stopped with the padding, so a later upload is never filtered */
static void t_vision_filter_up_after_padding(void) {
    static unsigned char d[2048];
    struct conn *c = first_open("xtls-rprx-vision");
    if (!c) { check(0, "vision filter up: test connection did not open"); up_close(NULL); return; }
    struct vl_sess *vs = SESS(c);
    int s1 = upstream_send(c, d, up_ch(d));
    size_t at = g_wire_n;
    size_t n = up_get(d);
    int s2 = upstream_send(c, d, n);
    int get = wire_frame(at, d, n);
    int mid = vs->vis.filter_left, pad = vs->vis.is_padding;
    unsigned char u[100];
    memset(u, 'u', sizeof u);
    int s3 = upstream_send(c, u, sizeof u);
    check(s1 == SEND_OK && s2 == SEND_OK && s3 == SEND_OK && get == VISION_CMD_END && mid == 6 &&
              pad == 0 && vs->vis.filter_left == 5 && g_send_last_n == 100 &&
              !memcmp(g_wire + g_wire_n - 100, u, 100),
          "vision filter up: padding over, the next upload still filtered, 6 -> 5, sent as is");
    up_close(c);
}

/* catches: the XUDP uplink framed with the old first-frame end, or left out of the writer */
static void t_vision_xudp_up(void) {
    snprintf(g_node.flow, sizeof g_node.flow, "xtls-rprx-vision");
    struct conn *c = conn_new(&g_tun);
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->fd = -1;
    c->key = cli_key();
    c->key.proto = 17;
    c->key.sport = 30002;
    c->key.dport = 53;
    c->is_udp = 1;
    conn_link(c);
    struct vl_sess *s = SESS(c);
    memset(s, 0, offsetof(struct vl_sess, dg));
    s->t.link.fd = -1;
    vless_dialer.clear(s);
    int fo = vless_dialer.flow_open(&g_node, s, &c->key, 1);
    g_wire_on = 1;
    g_wire_n = 0;
    g_send_szn = 0;
    unsigned char d[102];
    int ok = fo == 0, cmd[9], plain[9];
    size_t at[10], pad[9];
    for (int i = 0; i < 9; i++) {
        d[0] = 0;
        d[1] = 100;
        memset(d + 2, 'a' + i, 100);
        at[i] = g_wire_n;
        ok = ok && upstream_send(c, d, sizeof d) == SEND_OK;
        at[i + 1] = g_wire_n;
    }
    static const unsigned char hd[37 - 17] = { 18, 0x0a, 16, 'x', 't', 'l', 's', '-', 'r', 'p', 'r', 'x',
                                               '-', 'v', 'i', 's', 'i', 'o', 'n', 3 };
    static const unsigned char m1[12] = { 0, 20, 0, 0, 1, 1, 2, 0, 53, 1, 0xcb, 0xcb };
    static const unsigned char mk[8] = { 0, 4, 0, 0, 2, 1, 0, 100 };
    ok = ok && g_wire_n > 58 && g_wire[0] == 0 && !memcmp(g_wire + 1, g_hdr_uuid, 16) &&
         !memcmp(g_wire + 17, hd, sizeof hd) && !memcmp(g_wire + 37, g_hdr_uuid, 16);
    for (int i = 0; ok && i < 9; i++) {
        size_t f = i ? at[i] : 53, len = i ? 108 : 124;
        const unsigned char *x = g_wire + f;
        plain[i] = at[i + 1] - at[i] == len;
        if (plain[i]) {
            cmd[i] = -1;
            pad[i] = 0;
            ok = !memcmp(x, mk, 6) && x[6] == 0 && x[7] == 100 && x[8] == 'a' + i;
            continue;
        }
        cmd[i] = x[0];
        pad[i] = ((size_t)x[3] << 8) | x[4];
        ok = (((size_t)x[1] << 8) | x[2]) == len && at[i + 1] == f + 5 + len + pad[i] &&
             !memcmp(x + 5, i ? mk : m1, i ? 6 : sizeof m1) && x[5 + len - 100] == 'a' + i &&
             x[5 + len - 1] == 'a' + i;
        for (size_t j = 0; ok && j < pad[i]; j++) ok = x[5 + len + j] == 0;
    }
    int framed = ok;
    for (int i = 0; ok && i < 9; i++) ok = i < 7 ? !plain[i] && pad[i] < 256 : plain[i];
    check(framed && ok && cmd[0] == VISION_CMD_CONTINUE && cmd[1] == VISION_CMD_CONTINUE &&
              cmd[5] == VISION_CMD_CONTINUE && cmd[6] == VISION_CMD_END && s->vis.filter_left == 0 &&
              s->vis.is_padding == 0,
          "vision XUDP up: six datagrams continue, the seventh ends, short pads, the rest unframed");
    g_wire_on = 0;
    g_node.flow[0] = 0;
    conn_drop(c);
    dev_drain(NULL);
}

static struct vl_sess *down_sess(int udp) {
    static struct vl_sess s;
    struct flow_key k = cli_key();
    if (udp) k.proto = 17;
    memset(&s, 0, offsetof(struct vl_sess, dg));
    s.t.link.fd = -1;
    vless_dialer.clear(&s);
    snprintf(g_node.flow, sizeof g_node.flow, "xtls-rprx-vision");
    vless_dialer.flow_open(&g_node, &s, &k, udp);
    return &s;
}

/* catches: the filter fed per Vision piece, cut other than 8 KiB after the response header, fed an empty slice, or after the server's direct */
static void t_vision_filter_down_slices(void) {
    static unsigned char r[9100], x[9000];
    unsigned char hs[160];
    memset(x, 'x', sizeof x);
    struct vl_sess *s = down_sess(0);
    size_t rn = down_head(r);
    rn += vframe(r + rn, 0, x, 9000);
    int before = s->vis.filter_left;
    int dr = vless_dialer.deliver(&g_node, s, 0, r, rn, down_emit, NULL);
    check(rn == 2 + 9021 && dr == 0 && before == 8 && s->vis.filter_left == 6,
          "vision filter down: 9021 B after the response header are two slices, 8 -> 6");

    s = down_sess(0);
    rn = down_head(r);
    rn += vframe(r + rn, 0, x, 10);
    rn += vframe(r + rn, 0, hs, sh(hs, 0x1301, 1));
    dr = vless_dialer.deliver(&g_node, s, 0, r, rn, down_emit, NULL);
    check(dr == 0 && s->vis.enable_xtls == 0 && s->vis.filter_left == 7,
          "vision filter down: two frames in one slice are one buffer starting with x");

    s = down_sess(0);
    rn = down_head(r);
    rn += vframe(r + rn, VISION_CMD_DIRECT, x, 5);
    dr = vless_dialer.deliver(&g_node, s, 0, r, rn, down_emit, NULL);
    int mid = s->vis.filter_left, direct = s->t.link.rx_direct;
    rn = sh(r, 0x1301, 1);
    int dr2 = vless_dialer.deliver(&g_node, s, 0, r, rn, down_emit, NULL);
    check(dr == 0 && dr2 == 0 && direct == 1 && mid == 7 && s->vis.filter_left == 7 &&
              s->vis.enable_xtls == 0,
          "vision filter down: nothing is filtered after the server's direct");

    s = down_sess(0);
    rn = down_head(r);
    rn += vframe(r + rn, 0, x, 8171);
    dr = vless_dialer.deliver(&g_node, s, 0, r, rn, down_emit, NULL);
    check(rn == 2 + 8192 && dr == 0 && s->vis.filter_left == 7,
          "vision filter down: 8192 B after the response header are one slice, 8 -> 7");

    s = down_sess(0);
    rn = down_head(r);
    rn += vframe(r + rn, 0, x, 8172);
    dr = vless_dialer.deliver(&g_node, s, 0, r, rn, down_emit, NULL);
    check(rn == 2 + 8193 && dr == 0 && s->vis.filter_left == 6,
          "vision filter down: 8193 B after the response header are two slices, 8 -> 6");

    s = down_sess(0);
    rn = down_head(r);
    rn += vframe(r + rn, VISION_CMD_DIRECT, x, 8171);
    rn += sh(r + rn, 0x1301, 1);
    dr = vless_dialer.deliver(&g_node, s, 0, r, rn, down_emit, NULL);
    check(dr == 0 && s->vis.filter_left == 7 && s->vis.enable_xtls == 0,
          "vision filter down: the slice after direct in the same delivery is not filtered");

    s = down_sess(0);
    rn = down_head(r);
    rn += vframe(r + rn, 0, x, 10) - 10;
    dr = vless_dialer.deliver(&g_node, s, 0, r, rn, down_emit, NULL);
    check(dr == 0 && s->vis.filter_left == 8, "vision filter down: a slice with no payload is not filtered");
    g_node.flow[0] = 0;
}

/* catches: the XUDP branch of vl_deliver left without the filter */
static void t_vision_filter_down_xudp(void) {
    static const unsigned char ka[6] = {0x00, 0x04, 0x00, 0x00, 0x04, 0x00};
    unsigned char r[64];
    struct vl_sess *s = down_sess(1);
    g_emit_n = 0;
    size_t rn = down_head(r);
    rn += vframe(r + rn, 0, ka, sizeof ka);
    int before = s->vis.filter_left;
    int dr = vless_dialer.deliver(&g_node, s, 1, r, rn, down_emit, NULL);
    int first = s->vis.filter_left;
    int ok = dr == 0;
    for (int i = 0; i < 7; i++) {
        rn = vframe(r, 0, ka, sizeof ka);
        ok = ok && vless_dialer.deliver(&g_node, s, 1, r, rn, down_emit, NULL) == 0;
    }
    check(ok && before == 8 && first == 7 && s->vis.filter_left == 0 && g_emit_n == 0,
          "vision filter down, XUDP: each KeepAlive delivery is one slice, 8 -> 7 -> 0");
    g_node.flow[0] = 0;
}

static void t_up_cut_grpc_room(void) {
    /* catches: a gather sized to the gRPC room refused in part once each piece is a message of its own */
    up_stream_fill();
    struct conn *c = up_open();
    if (!c) { check(0, "up cut gRPC: test connection did not open"); up_close(NULL); return; }
    struct vl_sess *vs = SESS(c);
    vs->t.fr = &tr_grpc;
    g_grpc_win = 16018;
    g_recv_rc = 0;
    g_recv_n = 0;
    long room = conn_room(c);
    uint32_t seq = c->client_seq;
    uint32_t got = 0;
    while (room > 0 && got + 1000 <= (uint32_t)room) {
        cli_send_more(seq + got, 2, TCP_ACK, 65535, g_up_stream + got, 1000);
        got += 1000;
    }
    if (room > 0 && got < (uint32_t)room) {
        cli_send_more(seq + got, 2, TCP_ACK, 65535, g_up_stream + got, (uint32_t)room - got);
        got = (uint32_t)room;
    }
    up_flush(&g_tun);
    check(room > 8192 && got == (uint32_t)room && g_send_szn == 2 && g_send_sz[0] == 8192 &&
              g_send_sz[1] == (size_t)room - 8192 && c->client_seq == seq + got &&
              !memcmp(g_wire, g_up_stream, got),
          "up cut gRPC: a gather of the whole room goes as two messages, all taken");
    vs->t.fr = NULL;
    up_close(c);
}

static void t_first_write_second_refused(void) {
    /* catches: a refused second part of the first write taken as a closed window */
    up_stream_fill();
    struct conn *c = first_open("");
    if (!c) { check(0, "first write refused: test connection did not open"); up_close(NULL); return; }
    g_send_ok_first = 1;
    g_send_again_n = 1;
    int sr = upstream_send(c, g_up_stream, 8192);
    check(sr == SEND_FATAL && g_send_szn == 2 && g_send_sz[0] == 8192 && g_send_sz[1] == 26,
          "first write: the second part refused, the send fails");
    up_close(c);
}

static void first_room(const char *flow) {
    up_stream_fill();
    unsigned char h[64];
    size_t hn = first_header(flow[0] != 0, h);
    struct conn *c = first_open(flow);
    char what[96];
    const char *tag = flow[0] ? ", Vision" : "";
    if (!c) {
        snprintf(what, sizeof what, "first write room%s: test connection did not open", tag);
        check(0, what);
        up_close(NULL);
        return;
    }
    struct vl_sess *vs = SESS(c);
    struct vision before = vs->vis;
    g_room = 8000;
    int sr = upstream_send(c, g_up_stream, 8192);
    snprintf(what, sizeof what, "first write room%s: refused before any write", tag);
    check(sr == SEND_AGAIN && g_send_szn == 0 && !vs->header_sent &&
              vs->vis.need_uuid == before.need_uuid && vs->vis.is_padding == before.is_padding &&
              vs->vis.filter_left == before.filter_left &&
              vs->vis.sent_frames == before.sent_frames, what);
    g_room = -1;
    sr = upstream_send(c, g_up_stream, 8192);
    size_t rest = hn;
    if (flow[0] && g_wire_n >= hn + 21) {
        size_t pa = ((size_t)g_wire[hn + 19] << 8) | g_wire[hn + 20];
        size_t nx = hn + 21 + 4096 + pa;
        rest = g_wire_n >= nx + 5 ? 70 + pa + (((size_t)g_wire[nx + 3] << 8) | g_wire[nx + 4]) : 0;
    } else if (flow[0]) {
        rest = 0;
    }
    snprintf(what, sizeof what, "first write room%s: the resend goes as 8192 + the rest", tag);
    check(sr == SEND_OK && g_send_szn == 2 && g_send_sz[0] == 8192 && g_send_sz[1] == rest && rest &&
              !memcmp(g_wire, h, hn) && vs->header_sent, what);
    up_close(c);
}

static void t_first_write_room(void) {
    /* catches: the first part written when the second cannot follow */
    first_room("");
    first_room("xtls-rprx-vision");
}

static void t_first_write_room_edge(void) {
    /* catches: the room compared with the first part, or refused when it equals the whole */
    up_stream_fill();
    struct conn *c = first_open("");
    if (!c) { check(0, "first write room edge: test connection did not open"); up_close(NULL); return; }
    struct vl_sess *vs = SESS(c);
    g_room = 26 + 8192 - 1;
    int sr = upstream_send(c, g_up_stream, 8192);
    check(sr == SEND_AGAIN && g_send_szn == 0 && !vs->header_sent,
          "first write room edge: room 8217 for 8218 refuses with no write");
    g_room = 26 + 8192;
    sr = upstream_send(c, g_up_stream, 8192);
    check(sr == SEND_OK && g_send_szn == 2 && g_send_sz[0] == 8192 && g_send_sz[1] == 26 && vs->header_sent,
          "first write room edge: room 8218 for 8218 gives 8192, 26");
    up_close(c);
}

static void t_first_write_room_grpc(void) {
    /* catches: the first write's room on gRPC checked without the second message's overhead, so half a request goes out */
    up_stream_fill();
    struct conn *c = first_open("");
    if (!c) { check(0, "first write room gRPC: test connection did not open"); up_close(NULL); return; }
    struct vl_sess *vs = SESS(c);
    vs->t.fr = &tr_grpc;
    g_grpc_win = 9 + 8218;
    int sr = upstream_send(c, g_up_stream, 8192);
    check(sr == SEND_AGAIN && g_send_szn == 0 && !vs->header_sent,
          "first write room gRPC: room 8218 for 8218 in two messages refuses with no write");
    g_grpc_win = 9 + 8218 + 8;
    sr = upstream_send(c, g_up_stream, 8192);
    check(sr == SEND_AGAIN && g_send_szn == 0 && !vs->header_sent,
          "first write room gRPC: room 8226 refuses with no write");
    g_grpc_win = 9 + 8218 + 9;
    sr = upstream_send(c, g_up_stream, 8192);
    check(sr == SEND_OK && g_send_szn == 2 && g_send_sz[0] == 8192 && g_send_sz[1] == 26 && vs->header_sent,
          "first write room gRPC: room 8227 gives 8192, 26");
    vs->t.fr = NULL;
    up_close(c);
}

/* SEND_AGAIN (the HTTP/2 window to the node is closed) while the client has no window either:
 * the server must not be read, and the client resends the packet. */
static void t_sendagain_window(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "SEND_AGAIN: test connection did not open"); return; }
    /* The client has not acknowledged the 1000 bytes and its window is exactly 1000: no room. */
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_rc = H2_EWINDOW;
    g_recv_rc = 0;
    memset(g_recv_buf, 'r', 1000);
    g_recv_n = 1000;
    int calls = g_recv_calls;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 1000, d, sizeof(d) - 1);
    check(g_recv_calls == calls, "SEND_AGAIN, client window closed: server not read");
    g_send_rc = 0;
    g_recv_n = 0;
    conn_drop(c);
    dev_drain(NULL);
}

/* The other side: the client's window is open, so the server is read (the WINDOW_UPDATE comes
 * from there), the retried send succeeds and the packet is taken. */
static void t_sendagain_retry(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "SEND_AGAIN: test connection did not open"); return; }
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_again_n = 1;
    g_recv_rc = 0;
    g_recv_n = 0;                                       /* a control frame: no data */
    int calls = g_recv_calls;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d) - 1);
    check(g_recv_calls > calls && c->used && c->client_seq == 1001 + sizeof(d) - 1,
          "SEND_AGAIN, client window open: server read, retried send succeeded");
    g_send_again_n = 0;
    conn_drop(c);
    dev_drain(NULL);
}

/* The server ends the stream on that same read. The connection must live until what was
 * already sent is acknowledged (srv_closed, as in drain_conn), not vanish with the ring. And the
 * packet is not sent again into the ended stream: the window would allow it now (only the first
 * send is refused), but it is neither sent nor acknowledged. */
static void t_sendagain_eof(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "SEND_AGAIN: test connection did not open"); return; }
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_again_n = 1;
    g_recv_rc = -1;
    int sends = g_send_calls;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d) - 1);
    struct flow_key k = cli_key();
    c = conn_find(&k);
    check(c && c->srv_closed && c->rtx.len == 1000,
          "SEND_AGAIN, end of stream: connection alive, 1000 bytes await ACK");
    check(c && g_send_calls == sends + 1 && c->client_seq == 1001 && !c->ack_due,
          "SEND_AGAIN, end of stream: the packet is not retried, not acknowledged");
    g_send_again_n = 0;
    g_recv_rc = 0;
    if (c) conn_drop(c);
    dev_drain(NULL);
}

/* An out-of-order segment is dropped (there is no reordering buffer), but it must be answered
 * with an ACK of the expected number: without duplicate ACKs the client's fast retransmit does
 * not fire, and the hole closes only on a timeout. A retransmit of data already taken needs the
 * same answer, or a lost ACK of ours is never recovered. */
static void t_out_of_order_dupack(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "dup ACK: test connection did not open"); return; }
    const unsigned char d[100] = { 0 };
    struct flow_key last;
    cli_send(1001 + 500, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(n == 1 && (last.tcp_flags & TCP_ACK) && last.ack == 1001 && c->client_seq == 1001,
          "segment past a hole: not taken, ACK of the expected number sent");

    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));      /* in order */
    flush_acks(&g_tun);
    dev_drain(NULL);
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));      /* the same again */
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(n == 1 && last.ack == 1101 && c->client_seq == 1101,
          "retransmit of taken data: not taken twice, ACK of the current number");
    conn_drop(c);
    dev_drain(NULL);
}

/* Receive window scaling (RFC 7323). A client with the scale option in its SYN gets our option in
 * the SYN-ACK and an unscaled window there (a SYN or SYN-ACK window is never scaled); in data and
 * ACKs the window field is the ceiling divided by our factor, so the real window can exceed 64 KB.
 * A client without the option does not get it back (the option in a SYN-ACK to a SYN without it
 * breaks RFC 7323, 2.2) and sees 65535 in every packet.
 *
 * Also checked: the shift itself (rcv_window_set), the smallest whose field holds the ceiling;
 * and the window field rounded up (rcv_win_field), so 65535 with shift 7 does not become 65408. */
static void syn_opts(uint32_t seq, int wscale) {
    unsigned char p[128];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, seq, 0, TCP_SYN, NULL, 0,
                         65535, 1460, wscale);
    handle_packet(&g_tun, p, l);
}

/* Send 100 bytes of client data; last gets the key of the last packet written to the device,
 * the return value is how many there were. */
static int ack_after_data(uint32_t seq, struct flow_key *last) {
    static const unsigned char d[100] = { 0 };
    cli_send(seq, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    flush_acks(&g_tun);
    memset(last, 0, sizeof(*last));
    return dev_drain(last);
}

static void t_window_scale(void) {
    uint32_t keep_wnd = g_rcv_wnd;
    uint8_t keep_shift = g_rcv_shift;

    rcv_window_set(100);
    check(g_rcv_wnd == 65535 && g_rcv_shift == 0, "window scale: below 65535 -> 65535, shift 0");
    rcv_window_set(65535);
    check(g_rcv_wnd == 65535 && g_rcv_shift == 0, "  exactly 65535: shift 0");
    rcv_window_set(65536);
    check(g_rcv_wnd == 65536 && g_rcv_shift == 1, "  65536: shift 1 (65535 << 0 too small)");
    rcv_window_set(1u << 20);
    check(g_rcv_wnd == (1u << 20) && g_rcv_shift == 5, "  1 MiB: shift 5 (65535 << 4 too small)");
    rcv_window_set(4u << 20);
    check(g_rcv_wnd == (4u << 20) && g_rcv_shift == 7, "  4 MiB: shift 7 (65535 << 6 too small)");
    rcv_window_set(0xFFFFFFFFu);
    check(g_rcv_shift == 14 && g_rcv_wnd == (65535u << 14), "  above max: shift 14, ceiling 65535 << 14");

    /* From here: ceiling 1 MiB, shift 5, window field 32768. */
    rcv_window_set(1u << 20);
    struct flow_key k = cli_key(), last;
    struct conn *c0 = conn_find(&k);
    if (c0) conn_drop(c0);
    dev_drain(NULL);

    syn_opts(1000, 7);                                    /* client: window scale 7 */
    struct conn *c = conn_find(&k);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(c && n == 1 && (last.tcp_flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && last.ws_seen &&
              last.wscale == 5,
          "SYN with window scale: SYN-ACK carries our option with shift 5");
    check(n == 1 && last.window == 65535, "  window in the SYN-ACK itself: 65535, unscaled");
    check(c && c->ws_on && c->client_wscale == 7, "  connection: scaling on, client shift 7 read");
    if (c && wait_ready(c, 2000) == 0) {
        cli_send(1001, 2, TCP_ACK, 65535, NULL, 0);
        n = ack_after_data(1001, &last);
        check(n == 1 && (last.tcp_flags & TCP_ACK) && last.ack == 1101 && last.window == 32768,
              "  data ACK: window field 32768, with shift 5 that is 1 MiB");
        check(((uint32_t)last.window << 5) == (1u << 20), "  field << 5 is the ceiling");
    } else {
        check(0, "  connector did not report");
    }
    if (c) conn_drop(c);
    dev_drain(NULL);

    /* Ceiling 65537, shift 1: the field is the ceiling divided by 2^shift, rounded up, so the
     * window is not below the ceiling: 32769, not 32768. The ceiling is odd: with an even one
     * both roundings give the same field. */
    rcv_window_set(65537);
    syn_opts(1500, 3);
    c = conn_find(&k);
    if (c && wait_ready(c, 2000) == 0) {
        cli_send(1501, 2, TCP_ACK, 65535, NULL, 0);
        dev_drain(NULL);
        n = ack_after_data(1501, &last);
        check(n == 1 && g_rcv_shift == 1 && last.window == 32769,
              "ceiling 65537, shift 1: field 32769, rounded up, window not below the ceiling");
    } else {
        check(0, "  connector did not report (rounding)");
    }
    if (c) conn_drop(c);
    dev_drain(NULL);
    rcv_window_set(1u << 20);

    /* Window scale with shift 0 is still the option: it must be answered, and the window scaled. */
    syn_opts(2000, 0);
    c = conn_find(&k);
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(c && c->ws_on && n == 1 && last.ws_seen && last.wscale == 5 && c->client_wscale == 0,
          "SYN with window scale 0: option seen (ws_seen), SYN-ACK with our shift");
    if (c) wait_ready(c, 2000);                           /* a job in progress cannot be dropped */
    if (c) conn_drop(c);
    dev_drain(NULL);

    /* SYN without window scale. */
    syn_opts(3000, -1);
    c = conn_find(&k);
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(c && !c->ws_on && n == 1 && !last.ws_seen && last.window == 65535,
          "SYN without window scale: SYN-ACK without it, window 65535");
    if (c && wait_ready(c, 2000) == 0) {
        cli_send(3001, 2, TCP_ACK, 65535, NULL, 0);
        n = ack_after_data(3001, &last);
        check(n == 1 && last.ack == 3101 && last.window == 65535,
              "  and the data ACK: window 65535, not scaled");
    } else {
        check(0, "  connector did not report");
    }
    if (c) conn_drop(c);
    dev_drain(NULL);

    rcv_window_set(keep_wnd);
    g_rcv_shift = keep_shift;
}

/* A connector reports during the LAST sleep of the wait. The report must be checked after that
 * sleep too; otherwise the verdict "did not report within 15 s" comes from the loop counter
 * alone, and the table is then deliberately not freed. */
static void t_release_last_sleep(void) {
    struct conn *c = &g_conns[MAX_CONNS - 1];
    struct conn save = *c;
    c->used = 1;
    c->pending = 1;
    __atomic_store_n(&c->done, 0, __ATOMIC_RELEASE);
    g_sleep_c = (int *)&c->done;
    g_sleep_n = 0;
    g_sleep_report_at = 1500;
    g_sleep_hook = 1;
    int save_err = dup(2), nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    int rc = connq_release(g_conns);
    fflush(stderr);
    dup2(save_err, 2); close(save_err); close(nul);
    g_sleep_hook = 0;
    check(rc == 0, "report during the last wait sleep accepted, table released");

    /* And the reverse: no report at all fails the wait. */
    __atomic_store_n(&c->done, 0, __ATOMIC_RELEASE);
    c->pending = 1;
    g_sleep_n = 0;
    g_sleep_report_at = 0;
    g_sleep_hook = 1;
    save_err = dup(2); nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    rc = connq_release(g_conns);
    fflush(stderr);
    dup2(save_err, 2); close(save_err); close(nul);
    g_sleep_hook = 0;
    check(rc == -1 && g_sleep_n == 1500, "no report within 15 s: wait fails after 1500 sleeps");
    g_sleep_c = NULL;
    *c = save;
}

/* Run f with stderr going to a file; return whether needle appears in what was written. */
static void stderr_of(void (*f)(void *), void *arg, char *buf, size_t cap) {
    char path[] = "/tmp/tunnelmatch-err.XXXXXX";
    buf[0] = 0;
    int fd = mkstemp(path);
    if (fd < 0) return;
    fflush(stderr);
    int save = dup(2);
    dup2(fd, 2);
    f(arg);
    fflush(stderr);
    dup2(save, 2); close(save);
    ssize_t r = pread(fd, buf, cap - 1, 0);
    close(fd); unlink(path);
    buf[r > 0 ? r : 0] = 0;
}

static int stderr_has(void (*f)(void *), void *arg, const char *needle) {
    char buf[4096];
    stderr_of(f, arg, buf, sizeof buf);
    return strstr(buf, needle) != NULL;
}

static void syn_bad(void *arg) {
    struct vless_node *bad = arg;
    unsigned char p[128];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, 1000, 0, TCP_SYN,
                         NULL, 0, 65535, 0, -1);
    g_dial.ctx = bad;
    handle_packet(&g_tun, p, l);
    g_dial.ctx = &g_node;
}

static int bad_probe(const void *node, int t, char *why, size_t n) {
    (void)node; (void)t; snprintf(why, n, "stub"); return -1;
}
static const char *bad_name(const void *node) { return ((const struct vless_node *)node)->name; }
static const struct pool_proto bad_proto = { .ops = &vless_dialer, .probe = bad_probe,
                                             .name = bad_name };

static int g_run_rc;
static const void *g_bad_node;
static const void *bad_at(int i) { (void)i; return g_bad_node; }
static void run_bad(void *arg) {
    /* A name longer than 15 characters: tun_open refuses it anyway, so no device appears even
     * without the UUID check; what differs is whether the reason is named. The pool gets a
     * protocol, so a run past the check reaches tun_open instead of crashing on the way. */
    struct tun_cfg tc = { .dev = "tunnelmatch-no-such-dev", .prefix = 32 };
    g_bad_node = arg;
    struct pool_cfg pc = { .proto = &bad_proto, .node = bad_at, .first = 0 };
    g_run_rc = vless_tunnel_run(&tc, &pc, NULL, NULL);
}

/* The node's UUID does not parse. The connection must not close silently, and vless_tunnel_run
 * must refuse before it brings up a device that would close every connection. */
static void t_bad_uuid(void) {
    struct vless_node bad = g_node;
    /* Shorter than 31 characters is a valid derived UUID (SHA-1 of the string, as in Xray);
     * longer than 36 never parses. */
    memset(bad.uuid, 0, sizeof(bad.uuid));
    memset(bad.uuid, 'x', 40);
    snprintf(bad.name, sizeof(bad.name), "test-node");
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    g_now_s += 10;                                   /* past the log line's rate limit */
    int said = stderr_has(syn_bad, &bad, "the UUID of node test-node does not parse");
    c = conn_find(&k);
    check(said && !c, "SYN to a node with a bad UUID: refused, reason logged");
    if (c) conn_drop(c);
    dev_drain(NULL);
    said = stderr_has(run_bad, &bad, "the UUID of node test-node does not parse");
    check(said && g_run_rc == 1, "startup names the bad UUID before the device comes up");
}

static void send_refused(void *arg) {
    (void)arg;
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_rc = H2_ESTATUS;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d) - 1);
    g_send_rc = 0;
}

/* The xhttp server refused an upload chunk (transport_write returned H2_ESTATUS). The connection
 * closes as on any send failure, but the reason must be logged: a silent RST makes the node look
 * alive. */
static void t_send_refused(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "send refused: test connection did not open"); return; }
    g_now_s += 10;
    int said = stderr_has(send_refused, NULL, "refused the data");
    struct flow_key k = cli_key();
    c = conn_find(&k);
    check(said && !c, "server refused the data: reason logged, connection closed");
    if (c) conn_drop(c);
    dev_drain(NULL);
}

/* UDP datagrams held until the flow is ready go to the dialer one at a time, one send call each,
 * not as one piece. A dialer may send each call as its own message, so joining them would merge
 * the client's three datagrams (1000, 2300 and 3000 bytes) into one, and a QUIC client's first
 * flight (two Initials, or an Initial with 0-RTT) would be lost. */
static size_t g_es_len[8];
static int g_es_n;
static size_t es_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > cap) return 0;
    memcpy(out, p, n);
    return n;
}
static int es_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *d, size_t n) {
    (void)ctx; (void)sess; (void)k; (void)udp; (void)d;
    if (g_es_n < 8) g_es_len[g_es_n] = n;
    g_es_n++;
    return SEND_OK;
}
static void t_udp_early_bounds(void) {
    static const struct dialer_ops es_ops = { .name = "bounds", .dgram_frame = es_frame,
                                              .send = es_send };
    static const struct dialer es_dl = { &es_ops, NULL, 0 };
    const struct dialer *save = g_dl;
    g_dl = &es_dl;
    struct conn *c = conn_new(&g_tun);
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->fd = -1;
    c->key = cli_key();
    c->key.proto = 17;
    c->key.sport = 30001;
    c->is_udp = 1;
    c->pending = 1;
    conn_link(c);
    static unsigned char d[3000];
    memset(d, 0x5a, sizeof d);
    g_es_n = 0;
    int ok = udp_send_dgram(c, d, 1000) == SEND_OK && udp_send_dgram(c, d, 2300) == SEND_OK &&
             udp_send_dgram(c, d, 3000) == SEND_OK;
    check(ok && g_es_n == 0, "UDP before the flow is ready: three datagrams held");
    c->pending = 0;
    int fr = early_flush(c);
    check(fr == 0 && g_es_n == 3 && g_es_len[0] == 1000 && g_es_len[1] == 2300 && g_es_len[2] == 3000,
          "UDP once ready: held datagrams sent one by one: 1000, 2300, 3000");
    if (fr != 0 || g_es_n != 3)
        fprintf(stderr, "  send calls %d: %zu %zu %zu\n", g_es_n, g_es_len[0], g_es_len[1], g_es_len[2]);
    g_dl = save;
    conn_drop(c);
    dev_drain(NULL);
}

/* Fill the whole table with fresh TCP connections plus one UDP flow with the given port and idle
 * time, then ask conn_new for a slot. Returns whether it gave that flow's slot. */
static int full_table_gives_udp(uint16_t dport, int idle_s) {
    struct conn *u = NULL;
    int n = 0;
    while (g_free_n) {
        struct conn *c = conn_new(&g_tun);
        memset(c, 0, sizeof(*c));
        c->used = 1;
        c->fd = -1;
        c->key = cli_key();
        c->key.sport = (uint16_t)(20000 + n++);
        c->last = g_now_s;
        if (!u) {
            u = c;
            c->is_udp = 1;
            c->key.proto = 17;
            c->key.dport = dport;
            c->last = g_now_s - idle_s;
        }
        conn_link(c);
    }
    int save = dup(2), nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    struct conn *got = conn_new(&g_tun);
    fflush(stderr);
    dup2(save, 2); close(save); close(nul);
    int gave = got && got == u;
    if (got) {                          /* link the slot given, so the cleanup frees it */
        memset(got, 0, sizeof(*got));
        got->used = 1;
        got->fd = -1;
        got->key = cli_key();
        got->key.sport = 19999;
        conn_link(got);
    }
    /* Cleanup: every live entry back to the free list. */
    while (g_live_n) conn_drop(&g_conns[g_live[g_live_n - 1]]);
    dev_drain(NULL);
    return gave;
}

/* The table is full. A DNS flow (UDP to port 53) silent for DNS_IDLE_S (10 s) is done, query and
 * answer, and must give up its slot: by the general 120 s threshold it would look active, and
 * conn_new would refuse new connections, plain TCP included. A live QUIC flow with a longer idle
 * time is left alone, and so is a DNS flow whose answer may still come (a second less). */
static void t_dns_evict(void) {
    /* The fixture itself: a flow idle longer than IDLE_EVICT_S is evicted whatever its port. */
    check(full_table_gives_udp(443, IDLE_EVICT_S + 10), "full table: flow idle over 120 s evicted");
    check(full_table_gives_udp(53, DNS_IDLE_S),
          "full table: DNS flow idle DNS_IDLE_S gives up its slot");
    check(!full_table_gives_udp(443, 15), "full table: non-DNS UDP flow idle 15 s is kept");
    check(!full_table_gives_udp(53, DNS_IDLE_S - 1), "full table: DNS flow idle 1 s less is kept");
}

/* Spare pool: a ready session is handed to a connection, and its slot is empty afterwards. The
 * move is the dialer's take, checked in tests/takematch.c on the real transport; the pool slot is
 * the stack's job, checked here. */
static void t_spare_slot(void) {
    static struct vl_sess spare;
    memset(&spare, 0, sizeof(spare));
    spare.t.link.fd = -1;
    struct spare *sp = &g_spares[0];
    struct spare save = *sp;
    sp->sess = &spare;
    sp->state = SPARE_READY;
    sp->born_ns = now_ns();
    static struct vl_sess out;
    memset(&out, 0, sizeof(out));
    check(spare_checkout(&out) == 0, "spare pool: ready session taken");
    check(sp->state == SPARE_EMPTY, "spare pool: slot freed");
    *sp = save;
}


/* ==== NODE LINK CUT AND CONNECTION RESETS ==================================================
 *
 * WHAT IS CHECKED. The link to the node is CUT (RST from the node, kernel timeout): the client
 * gets RST, not FIN, and the dialer is told lost. The node closes the link cleanly (FIN): the
 * client gets FIN. A send to the node fails: RST, not a silent close. Data for a connection not in
 * the table (the client restarted): RST. The silence threshold is set on the link socket
 * (TCP_USER_TIMEOUT, keepalive).
 *
 * HOW. The protocol is a fake dialer whose link is real TCP over loopback to the test's listener,
 * so the node's RST and FIN are real, and the stack asks the kernel for the socket state
 * (TCP_INFO), not the fake. The device is the same socket pair. */

/* ---- fake protocol: node and link ----------------------------------------------------------- */

struct fnode { char name[16]; char host[16]; int alive; };
#define FN_N 24
static struct fnode g_fn[FN_N];

struct fsess { int fd; const struct fnode *node; int flow_opens; int udp; char host[256]; };

static int g_lfd = -1;
static uint16_t g_lport;
static pthread_mutex_t g_srv_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_srv[256];
static const struct fnode *g_srv_node[256];
static int g_srv_n;

static const char *f_peer(const void *ctx) { return ((const struct fnode *)ctx)->host; }
static void f_describe(const void *ctx, char *out, size_t n) {
    snprintf(out, n, "%s", ((const struct fnode *)ctx)->name);
}
static const char *f_strerror(int rc) { (void)rc; return "fake"; }
static int f_connect(const void *ctx, void *sess, int t) {
    (void)t;
    const struct fnode *n = ctx;
    struct fsess *s = sess;
    if (!n->alive) return TR_ECONNECT;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(g_lport) };
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) return TR_ECONNECT;
    int a = accept(g_lfd, NULL, NULL);
    pthread_mutex_lock(&g_srv_mu);
    g_srv_node[g_srv_n] = n;
    g_srv[g_srv_n++] = a;
    pthread_mutex_unlock(&g_srv_mu);
    s->fd = fd;
    return 0;
}
static void f_take(void *dst, void *src) {
    struct fsess *d = dst, *s = src;
    d->fd = s->fd;
    s->fd = -1;
}
static void f_close(void *sess) {
    struct fsess *s = sess;
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
}
static void f_clear(void *sess) {
    struct fsess *s = sess;
    s->fd = -1;
    s->node = NULL;
    s->flow_opens = 0;
}
static int f_fd(const void *sess) { return ((const struct fsess *)sess)->fd; }
static int g_f_buffered;
static int f_has_data(const void *sess) {
    int fd = ((const struct fsess *)sess)->fd, n = 0;
    return g_f_buffered && fd >= 0 && ioctl(fd, FIONREAD, &n) == 0 && n > 0;
}
static int g_fopen_fail;
static struct flow_key g_fopen_key;
static int f_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    g_fopen_key = *k;
    if (g_fopen_fail) return -1;
    struct fsess *s = sess;
    s->node = ctx;
    s->udp = udp;
    s->flow_opens++;
    s->host[0] = 0;
    return 0;
}
static int f_set_host(void *sess, const char *host) {
    snprintf(((struct fsess *)sess)->host, sizeof ((struct fsess *)sess)->host, "%s", host);
    return 0;
}
static int f_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                  const unsigned char *d, size_t n) {
    (void)ctx; (void)k; (void)udp;
    struct fsess *s = sess;
    return n == 0 || send(s->fd, d, n, MSG_NOSIGNAL) == (ssize_t)n ? SEND_OK : SEND_FATAL;
}
static size_t f_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n + 2 > cap) return 0;
    out[0] = (unsigned char)(n >> 8);
    out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return n + 2;
}
static int f_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    struct fsess *s = sess;
    *got = 0;
    ssize_t r = recv(s->fd, buf, cap, MSG_DONTWAIT);
    if (r > 0) { *data = buf; *got = (size_t)r; return 0; }
    return -1;
}
static int f_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                     dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess; (void)udp;
    return emit(arg, d, n);
}
static int g_lost;
static void f_lost(const void *ctx, const void *sess) { (void)ctx; (void)sess; g_lost++; }

static const struct dialer_ops f_ops = {
    .name = "fake", .caps = DC_PRECONNECT, .sess_size = sizeof(struct fsess),
    .peer = f_peer, .describe = f_describe, .strerror = f_strerror, .connect = f_connect,
    .take = f_take, .close = f_close, .clear = f_clear, .fd = f_fd, .has_data = f_has_data,
    .flow_open = f_flow_open, .send = f_send, .dgram_frame = f_dgram_frame, .read = f_read,
    .deliver = f_deliver, .lost = f_lost, .set_host = f_set_host,
};

/* A fresh stack with the fake dialer to one node and a 20 s silence threshold. */
static void fake_new(void) {
    static struct dialer d = { .ops = &f_ops, .ctx = &g_fn[0], .silence_s = 20 };
    while (g_conns && g_live_n) conn_drop(&g_conns[g_live[0]]);
    g_spare_want = 0;
    stack_setup(&d);
}

static void pm_send(uint16_t sport, uint32_t dst, uint32_t seq, uint32_t ack, unsigned char flags,
                     const unsigned char *d, size_t n) {
    unsigned char p[2048];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, dst, sport, 443, seq, ack, flags, d, n, 65535, 0, -1);
    handle_packet(&g_tun, p, l);
    up_flush(&g_tun);                       /* a packet is a whole batch here, as in cli_send */
}

/* Packets the stack wrote to the device: how many, the flags of all ORed, the seq of the last. */
static int pm_drain(unsigned *flags, uint32_t *seq) {
    unsigned char p[70000];
    int cnt = 0;
    if (flags) *flags = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) == 0) {
            if (flags) *flags |= k.tcp_flags;
            if (seq) *seq = k.seq;
            cnt++;
        }
    }
    return cnt;
}

static struct flow_key pm_key(uint16_t sport, uint32_t dst) {
    struct flow_key k;
    memset(&k, 0, sizeof(k));
    k.src.v4 = CLI_IP; k.dst.v4 = dst; k.sport = sport; k.dport = 443; k.proto = 6;
    return k;
}

/* A connection up to "flow ready": SYN, connector, conn_ready, the client's ACK. */
static struct conn *pm_open(uint16_t sport, uint32_t dst) {
    struct flow_key k = pm_key(sport, dst);
    pm_send(sport, dst, 1000, 0, TCP_SYN, NULL, 0);
    struct conn *c = conn_find(&k);
    if (!c || !c->pending) return NULL;
    for (int i = 0; i < 3000 && !__atomic_load_n(&c->done, __ATOMIC_ACQUIRE); i++) {
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    if (!__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) || conn_ready(c, &g_tun)) return NULL;
    pm_send(sport, dst, 1001, 2, TCP_ACK, NULL, 0);
    pm_drain(NULL, NULL);
    return conn_find(&k);
}

static int pm_srv_of(const struct conn *c) {
    /* The server end of the connection's link, found by port: the client's local port is the
     * server's peer port. */
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    if (getsockname(c->fd, (struct sockaddr *)&a, &al) != 0) return -1;
    pthread_mutex_lock(&g_srv_mu);
    int found = -1;
    for (int i = 0; i < g_srv_n; i++) {
        struct sockaddr_in b;
        socklen_t bl = sizeof b;
        if (g_srv[i] >= 0 && getpeername(g_srv[i], (struct sockaddr *)&b, &bl) == 0 &&
            b.sin_port == a.sin_port) found = g_srv[i];
    }
    pthread_mutex_unlock(&g_srv_mu);
    return found;
}

static void pm_srv_rst(int fd) {
    struct linger lg = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(fd);
    struct timespec ts = { 0, 50000000 };
    nanosleep(&ts, NULL);
}

static void pm_sweep(void) {
    g_now_ns = now_ns();
    g_now_s = (time_t)(g_now_ns / 1000000000ull);
    static unsigned seen;
    nodes_sweep(&seen, g_now_ns);
    for (int li = 0; li < g_live_n; ) {
        struct conn *c = &g_conns[g_live[li]];
        if (c->pending || !conn_deadlines(c, &g_tun, g_now_ns)) li++;
    }
}


/* ==== NODE POOL (src/tunnel/pool.c) ========================================================
 *
 * The pool runs over the fake dialer above, whose nodes answer a probe while `alive` is set.
 * Checks (pl_check) are called by hand instead of from the health thread, so every step of a
 * failover is deterministic. */

static int g_probes[FN_N];              /* probes per node */
static int g_hook_node = -1;
static const int *g_hook_sel;
static size_t g_hook_n;
static int g_hook_wake_node = -1;
static int g_hook_wake_idx[1];
static int f_probe(const void *node, int t, char *why, size_t n) {
    (void)t;
    g_probes[(const struct fnode *)node - g_fn]++;
    if ((const struct fnode *)node - g_fn == g_hook_node) {
        g_hook_node = -1;
        pool_select(g_hook_sel, g_hook_n);
    }
    if ((const struct fnode *)node - g_fn == g_hook_wake_node) {
        g_hook_wake_node = -1;
        pool_wake(g_hook_wake_idx, 1);
    }
    if (((const struct fnode *)node)->alive) return 0;
    snprintf(why, n, "test node is silent");
    return -1;
}
static const char *f_name(const void *node) { return ((const struct fnode *)node)->name; }
static const struct pool_proto f_proto = { .ops = &f_ops, .probe = f_probe, .name = f_name };
static const struct pool_proto *g_pproto = &f_proto;

static int g_cand[FN_N] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 };
static const void *f_at(int i) { return &g_fn[i]; }

/* A fresh pool: `active` slots, candidates 0..ncand-1, node 0 chosen at startup. */
static void pool_build(int active, int by, int ncand, int checked) {
    while (g_conns && g_live_n) conn_drop(&g_conns[g_live[0]]);
    free(g_pl.slot);
    memset(&g_pl.cf, 0, sizeof g_pl.cf);
    g_pl.sig[0] = '\0';
    g_pl.said_up = 0;
    g_pl.pub = 0;
    g_pl.why[0] = '\0';
    g_pl.any_v6 = 0;
    g_pl.sig6 = 0;
    struct pool_cfg pc = {
        .proto = g_pproto, .node = f_at, .sel = g_cand,
        .sel_n = (size_t)ncand, .first = 0, .checked = checked, .active = active, .by = by,
        .interval_s = 60, .silence_s = 20,
    };
    const struct dialer *d = pool_setup(&pc);
    g_spare_want = 0;
    stack_setup(d);
}
static void pool_new_ex(int active, int by, int ncand, int checked) {
    free(g_pl.cand);
    g_pl.cand = NULL;
    g_pl.cand_n = 0;
    g_pl_clock_ms = 0;
    pool_build(active, by, ncand, checked);
}
static void pool_new_keep(int active, int by, int ncand) { pool_build(active, by, ncand, 1); }
static void pool_new(int active, int by, int ncand) { pool_new_ex(active, by, ncand, 1); }

static void all_alive(void) { for (int i = 0; i < 5; i++) g_fn[i].alive = 1; }

static void t_pool_setup(void) {
    check(pool_by_parse("connection") == POOL_BY_CONNECTION && pool_by_parse("site") == POOL_BY_SITE &&
          pool_by_parse("site-client") == POOL_BY_SITE_CLIENT &&
          pool_by_parse("site_client") == POOL_BY_SITE_CLIENT && pool_by_parse("node") == -1,
          "--by: connection, site, site-client (and site_client) parse; anything else is refused");
    check(!strcmp(pool_by_name(POOL_BY_SITE_CLIENT), "site-client") &&
          !strcmp(pool_by_name(POOL_BY_SITE), "site") &&
          !strcmp(pool_by_name(POOL_BY_CONNECTION), "connection"),
          "pool_by_name names each mode as --by takes it");
    all_alive();
    pool_new(4, POOL_BY_CONNECTION, 2);
    check(g_pl.n == 2, "more active nodes asked than candidates — one slot per candidate");
    pool_new(2, POOL_BY_CONNECTION, 3);
    uint64_t now = pl_now_ms();
    check(g_pl.slot[0].node == 0 && g_pl.slot[0].up && g_pl.slot[0].due > now + 50000 &&
          g_pl.slot[0].due <= now + 60000 && g_pl.slot[1].node == -1 && g_pl.slot[1].due <= now,
          "startup: slot 0 holds the probed node, next check in a period; the empty slot searches now");
    pool_new_ex(1, POOL_BY_CONNECTION, 3, 0);
    check(g_pl.slot[0].node == 0 && g_pl.slot[0].due <= pl_now_ms(),
          "a node not probed at startup (named) is checked at once");
}

/* The node of a connection stops being active: its connections are reset, the others stay. */
static void t_pool_stale(void) {
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 4);
    pl_check(1);
    check(g_pl.slot[1].node == 1 && g_pl.slot[1].up, "an empty slot takes the first free candidate (1)");
    struct conn *a = NULL, *b = NULL;
    for (uint16_t p = 51000; p < 51100 && (!a || !b); p++) {
        struct conn *c = pm_open(p, 0x0b0b0b0bu);
        if (!c) break;                      /* broken: do not wait 3 s a hundred times */
        const struct pl_sess *ps = SESS(c);
        if (ps->slot == 0 && !a) a = c;
        else if (ps->slot == 1 && !b) b = c;
        else conn_reset(c, &g_tun);
    }
    pm_drain(NULL, NULL);
    check(a && b, "by connection: connections land on both active nodes");
    if (!a || !b) return;
    struct flow_key ka = a->key, kb = b->key;
    unsigned ep0 = __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE);
    g_fn[0].alive = 0;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0 &&
              __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE) == ep0 &&
              g_pl.slot[0].due == g_pl.slot[0].checked_at + 3000,
          "one failed check — the node is still active (confirmed 3 s later)");
    g_fn[0].alive = 1;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].due == g_pl.slot[0].checked_at + 60000,
          "the confirmation passes — the next check a period (60 s) later");
    g_fn[0].alive = 0;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0,
          "  a failure after it is the first again, not the second in a row");
    memset(g_probes, 0, sizeof g_probes);
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 2,
          "two failed checks in a row — replaced by the next free candidate (1 is taken, 2 is used)");
    check(g_probes[0] == 1 && g_probes[1] == 0 && g_probes[2] == 1,
          "  the search probes free candidates only: not the failed node again, not a taken one");
    /* Death and replacement both tell it; each one alone is checked in t_pool_refill. */
    check(__atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE) != ep0,
          "a dead node replaced — the stack is told the node set changed");
    pm_sweep();
    unsigned fl;
    pm_drain(&fl, NULL);
    check(!conn_find(&ka) && (fl & TCP_RST), "a connection of the dead node — RST to the client, no restart");
    check(conn_find(&kb) != NULL, "a connection of a live node — left alone");
    struct conn *cb = conn_find(&kb);
    if (cb) conn_reset(cb, &g_tun);
    pm_drain(NULL, NULL);
}

static void t_pool_pick(void) {
    all_alive();
    pool_new(3, POOL_BY_SITE, 5);
    pl_check(1);
    pl_check(2);
    check(g_pl.slot[1].node == 1 && g_pl.slot[2].node == 2, "three slots — nodes 0, 1, 2 in candidate order");
    int at[200], per[3] = { 0, 0, 0 }, same = 1;
    struct flow_key k = pm_key(1, 0);
    for (int i = 0; i < 200; i++) {
        k.dst.v4 = htonl(0x5db80000u + (uint32_t)i * 7919u);
        k.sport = (uint16_t)(1000 + i);
        at[i] = pl_pick(&k);
        k.sport = (uint16_t)(2000 + i);
        k.src.v4 = htonl(0x0a000099u);
        if (pl_pick(&k) != at[i]) same = 0;
        k.src.v4 = CLI_IP;
        per[at[i]]++;
    }
    check(same, "by site: a site stays on one node whatever the port and the client");
    check(per[0] > 30 && per[1] > 30 && per[2] > 30, "by site: sites spread over all three nodes");
    g_pl.slot[1].up = 0;
    int kept = 1, moved = 1;
    for (int i = 0; i < 200; i++) {
        k.dst.v4 = htonl(0x5db80000u + (uint32_t)i * 7919u);
        int now = pl_pick(&k);
        if (at[i] != 1 && now != at[i]) kept = 0;
        if (at[i] == 1 && now == 1) moved = 0;
    }
    check(kept, "a node goes down — the sites of live nodes stay where they are");
    check(moved, "a node goes down — its sites move to live nodes");
    g_pl.slot[1].up = 1;

    pool_new(3, POOL_BY_SITE_CLIENT, 5);
    pl_check(1);
    pl_check(2);
    k.dst.v4 = htonl(0x5db80001u);
    int seen[3] = { 0, 0, 0 }, stable = 1;
    for (uint32_t c = 0; c < 60; c++) {
        k.src.v4 = htonl(0x0a000002u + c);
        int s1 = pl_pick(&k);
        k.sport = (uint16_t)(k.sport + 1);
        if (pl_pick(&k) != s1) stable = 0;
        seen[s1] = 1;
    }
    check(seen[0] + seen[1] + seen[2] >= 2, "by site-client: one site, different clients — different nodes");
    check(stable, "by site-client: one client and site stay on one node whatever the port");

    pool_new(3, POOL_BY_CONNECTION, 5);
    pl_check(1);
    pl_check(2);
    int cnt[3] = { 0, 0, 0 };
    for (int i = 0; i < 3000; i++) cnt[pl_pick(&k)]++;
    check(cnt[0] > 800 && cnt[1] > 800 && cnt[2] > 800, "by connection: new connections spread evenly");
    for (int i = 0; i < 3; i++) g_pl.slot[i].up = 0;
    check(pl_pick(&k) == 0, "no live node — a slot that has one, so the connection fails fast");
    for (int i = 0; i < 3; i++) g_pl.slot[i].node = -1;
    check(pl_pick(&k) == -1, "no slot has a node — none");
}

/* Catches: a connection bound to a slot the pool marked dead dialled anyway, so each SYN waits out the connect timeout. */
static void t_pool_dead_slot_refuses(void) {
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 1);
    _Alignas(max_align_t) unsigned char buf[PL_HDR + sizeof(struct fsess)];
    memset(buf, 0, sizeof buf);
    struct pl_sess *s = (struct pl_sess *)buf;
    ((struct fsess *)INNER(s))->fd = -1;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, 0);
    pthread_mutex_unlock(&g_pl.mu);
    g_pl.slot[0].up = 0;
    check(pl_connect(NULL, s, 1) == TR_ENONODE, "a slot the pool marked dead: refused without dialling");
    g_pl.slot[0].up = 1;
    int rc = pl_connect(NULL, s, 1);
    check(rc == 0, "the same slot live again: dialled");
    if (rc == 0) close(((struct fsess *)INNER(s))->fd);
}

static const void *g_upw_ctx;
static const void *g_upw_sess;
static size_t f_up_write(const void *ctx, void *sess) {
    g_upw_ctx = ctx;
    g_upw_sess = sess;
    return 4321;
}

static void t_pool_up_write(void) {
    /* catches: the pool handing the inner dialer its own session, or no piece size at all */
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 1);
    check(g_pl_ops.up_write == NULL, "pool: no piece size when the inner dialer has none");
    static struct dialer_ops up_ops;
    static struct pool_proto up_proto;
    up_ops = f_ops;
    up_ops.up_write = f_up_write;
    up_proto = f_proto;
    up_proto.ops = &up_ops;
    g_pproto = &up_proto;
    pool_new(1, POOL_BY_CONNECTION, 1);
    _Alignas(max_align_t) unsigned char buf[PL_HDR + sizeof(struct fsess)];
    memset(buf, 0, sizeof buf);
    struct pl_sess *s = (struct pl_sess *)buf;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, 0);
    pthread_mutex_unlock(&g_pl.mu);
    g_upw_ctx = g_upw_sess = NULL;
    size_t w = g_pl_ops.up_write ? g_pl_ops.up_write(&g_pl, s) : 0;
    check(w == 4321 && s->node && g_upw_ctx == s->node && g_upw_sess == INNER(s),
          "pool: the piece size is the inner dialer's, asked for the inner session");
    g_pproto = &f_proto;
    pool_new(1, POOL_BY_CONNECTION, 1);
}

/* Catches: a full connector queue blamed on the CPU while the handshakes wait for a silent node, or the other way round. */
static void t_connq_full_cause(void) {
    char b[96];
    check(strstr(connq_full_cause(0, b, sizeof b), "the CPU cannot keep up") != NULL, "no handshake running: the CPU");
    check(strstr(connq_full_cause(2999, b, sizeof b), "the CPU cannot keep up") != NULL, "a handshake under 3 s: the CPU");
    check(strcmp(connq_full_cause(3000, b, sizeof b), "the node does not answer (a handshake waits 3 s)") == 0,
          "a handshake at 3 s: the node, with its age");
    check(strcmp(connq_full_cause(7999, b, sizeof b), "the node does not answer (a handshake waits 7 s)") == 0,
          "the age in whole seconds");
    memset(g_conn_busy_ms, 0, sizeof g_conn_busy_ms);
    check(connq_busy_ms() == 0, "no connector busy: no age");
    g_conn_busy_ms[1] = mono_ms() - 1000;
    g_conn_busy_ms[3] = mono_ms() - 5000;
    uint32_t got = connq_busy_ms();
    check(got >= 5000 && got < 6000, "the oldest running handshake counts, not the first or the newest");
    memset(g_conn_busy_ms, 0, sizeof g_conn_busy_ms);
}

static void t_pool_refill(void) {
    all_alive();
    g_fn[1].alive = 0;
    pool_new(3, POOL_BY_CONNECTION, 5);
    pl_check(1);
    pl_check(2);
    check(g_pl.slot[1].node == 2 && g_pl.slot[2].node == 3,
          "empty slots fill in candidate order, a silent candidate skipped");
    /* Connections, as the pool's session header: on slot 0's node, and (bound below) on it once
     * dead, where pl_pick sends new ones when no slot is live. */
    struct pl_sess on_live, on_dead;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(&on_live, 0);
    pthread_mutex_unlock(&g_pl.mu);
    for (int i = 0; i < 5; i++) g_fn[i].alive = 0;
    unsigned ep = __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE);
    pl_check(0);
    uint64_t t0 = pl_now_ms();
    pl_check(0);
    uint64_t t1 = pl_now_ms();
    check(!g_pl.slot[0].up && g_pl.slot[0].node == 0 && g_pl.slot[0].due >= t0 + 300000 &&
              g_pl.slot[0].due <= t1 + 300000 && g_pl.slot[0].retry == 30,
          "no replacement answers while other slots live — the slot waits 5 min for the next round, the pause doubles");
    check(__atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE) != ep,
          "a dead node without a replacement still tells the stack the node set changed");
    check(pl_stale(&g_pl, &on_live),
          "  and its connections are stale at once, not on a replacement");
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(&on_dead, 0);
    pthread_mutex_unlock(&g_pl.mu);
    check(g_pl.said_up == 1, "other slots are alive — the pool is still up");
    for (int s = 1; s < 3; s++) { pl_check(s); pl_check(s); }
    check(g_pl.said_up == 0, "no live slot left — the pool says so");
    g_fn[3].alive = 1;
    pl_check(0);
    check(!g_pl.slot[0].up, "a round: the node a dead slot waits for is not given to another slot");
    pl_check(2);
    check(g_pl.slot[2].up && g_pl.slot[2].node == 3 && g_pl.said_up == 1 && g_pl.cand_n > 3 &&
              g_pl.cand[3].fails == 0,
          "a round: the slot's own node answers again — the slot lives on it, the pool is up again");
    g_fn[4].alive = 1;
    ep = __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE);
    g_pl_clock_ms = pl_now_ms() + 600000;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 4 &&
              __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE) != ep,
          "a round: a free candidate answers — the slot takes it, the stack is told");
    check(pl_stale(&g_pl, &on_dead), "  connections bound to the slot's dead node are stale then");
    g_pl_clock_ms = 0;
    int dup = 0;
    for (int i = 0; i < 3; i++)
        for (int j = i + 1; j < 3; j++)
            if (g_pl.slot[i].up && g_pl.slot[j].up && g_pl.slot[i].node == g_pl.slot[j].node) dup = 1;
    check(!dup, "two live slots never share a node");
}

static void t_pool_spares(void) {
    all_alive();
    pool_new(2, POOL_BY_SITE, 3);
    pl_check(1);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)], src[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *d = (struct pl_sess *)dst, *s = (struct pl_sess *)src;
    pl_clear(dst);
    pl_clear(src);
    struct flow_key k = pm_key(1, htonl(0x5db80001u));
    pl_flow_open(&g_pl, dst, &k, 0);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, 1 - d->slot);
    pthread_mutex_unlock(&g_pl.mu);
    check(pl_match(&g_pl, dst, src) == 0, "by site: a spare to another node does not suit the site's connection");
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, d->slot);
    pthread_mutex_unlock(&g_pl.mu);
    check(pl_match(&g_pl, dst, src) == 1, "by site: a spare to its own node suits");
    g_pl.slot[d->slot].gen++;
    check(pl_match(&g_pl, dst, src) == -1, "a spare to a node no longer active — dropped");

    pool_new(2, POOL_BY_CONNECTION, 3);
    pl_check(1);
    pl_clear(dst);
    pl_clear(src);
    pl_flow_open(&g_pl, dst, &k, 0);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, 1 - d->slot);
    pthread_mutex_unlock(&g_pl.mu);
    const void *want = s->node;
    int want_slot = s->slot;
    unsigned want_gen = s->gen;
    check(pl_match(&g_pl, dst, src) == 1, "by connection: a spare to any live node suits");
    ((struct fsess *)INNER(src))->fd = -1;
    pl_take(dst, src);
    const struct fsess *fd = INNER(dst);
    /* The slot and generation move too: they decide when the connection is stale. */
    check(d->node == want && d->slot == want_slot && d->gen == want_gen && fd->node == want &&
              fd->flow_opens == 2,
          "a spare to another node — the connection moves to it, its flow set up again for that node");

    /* Spares go to the live slots in turn. */
    int slots[2] = { -1, -1 };
    for (int i = 0; i < 2; i++) {
        pl_clear(src);
        if (pl_connect(&g_pl, src, 1) == 0) slots[i] = s->slot;
        pl_close(src);
    }
    check(slots[0] >= 0 && slots[1] >= 0 && slots[0] != slots[1], "spares are opened to the live nodes in turn");
    g_pl.slot[0].up = g_pl.slot[1].up = 0;
    pl_clear(src);
    check(pl_connect(&g_pl, src, 1) == TR_ENONODE && s->slot == -1, "no live node — no spare is opened");
    g_pl.slot[0].up = g_pl.slot[1].up = 1;

    /* A streak of failed connects brings the check forward. */
    g_pl.slot[0].kick = 0;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    pl_seen_at(d, -1, pl_now_ms());
    pl_seen_at(d, -1, pl_now_ms());
    check(!g_pl.slot[0].kick, "two failed connects — no early check yet");
    pl_seen_at(d, 0, pl_now_ms());
    pl_seen_at(d, -1, pl_now_ms());
    pl_seen_at(d, -1, pl_now_ms());
    check(!g_pl.slot[0].kick, "a successful connect breaks the streak");
    pl_seen_at(d, -1, pl_now_ms());
    check(g_pl.slot[0].kick == 1, "three failed connects in a row — check the node now");
    g_pl.slot[0].kick = 0;
    pl_seen_at(d, 0, pl_now_ms());
    struct pl_sess former = *d;                 /* a connection to the slot's previous node */
    former.gen--;
    for (int i = 0; i < 3; i++) pl_seen_at(&former, -1, pl_now_ms());
    check(!g_pl.slot[0].kick,
          "failed connects to the slot's previous node do not count against it");
    g_pl.slot[0].checked_at = pl_now_ms();
    pl_lost(&g_pl, d);
    check(!g_pl.slot[0].kick, "a cut right after a check does not call another (cuts come in bursts)");

    /* After a stall the node is dead on the first failed check. */
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 3);
    pl_check(1);
    g_pl.slot[0].checked_at = 0;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    pl_lost(&g_pl, d);
    check(g_pl.slot[0].kick == 1 && g_pl.slot[0].lost == 1, "a cut connection — check its node now");
    g_fn[0].alive = 0;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 2,
          "a stall and one failed check — replaced without the 3 s confirmation");
    g_fn[0].alive = 1;

    /* A stall whose check passes is forgotten: a later failure waits for its confirmation. */
    pool_new(2, POOL_BY_CONNECTION, 3);
    pl_check(1);
    g_pl.slot[0].checked_at = 0;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    pl_lost(&g_pl, d);
    pl_check(0);
    g_fn[0].alive = 0;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0,
          "a stall whose check passed — the next failure is confirmed again");
    g_fn[0].alive = 1;
}

static void t_pool_kick_once(void) {
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 1);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *d = (struct pl_sess *)dst;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    for (int i = 0; i < 3; i++) pl_seen_at(d, -1, pl_now_ms());
    check(g_pl.slot[0].kick == 1, "kick once: three failed connects ask for a check");
    g_pl.slot[0].kick = 0;
    pl_seen_at(d, -1, pl_now_ms());
    check(!g_pl.slot[0].kick, "kick once: the next failure after a taken kick does not ask again");
    pl_seen_at(d, -1, pl_now_ms());
    check(!g_pl.slot[0].kick, "kick once: two new failures do not ask yet");
    pl_seen_at(d, -1, pl_now_ms());
    check(g_pl.slot[0].kick == 1, "kick once: three new failures ask again");
}

static void t_pool_retry_cap(void) {
    for (int i = 0; i < 5; i++) g_fn[i].alive = 0;
    pool_new(1, POOL_BY_CONNECTION, 2);
    pl_check(0);
    pl_check(0);
    for (int k = 0; k < 8; k++) pl_check(0);
    uint64_t t0 = pl_now_ms();
    pl_check(0);
    uint64_t t1 = pl_now_ms();
    check(!g_pl.slot[0].up && g_pl.slot[0].retry == 30 && g_pl.slot[0].due >= t0 + 30000 &&
              g_pl.slot[0].due <= t1 + 30000,
          "retry cap: after many empty rounds a dead slot searches again every 30 s");
    g_fn[1].alive = 1;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 1 && g_pl.slot[0].retry == 15,
          "retry cap: a node found again, the round pause starts at 15 s");
    all_alive();
}

static void publish(void *arg) { (void)arg; pl_publish(); }
static void check_slot0(void *arg) { (void)arg; pl_check(0); pl_check(0); }

static void t_pool_log(void) {
    all_alive();
    pool_new(3, POOL_BY_SITE, 5);
    pl_check(1);
    pl_check(2);
    g_pl.sig[0] = '\0';
    check(stderr_has(publish, NULL, "active: n0 (#0), n1 (#1), n2 (#2)"),
          "the log names the active nodes with their numbers");
    check(!stderr_has(publish, NULL, "active:"), "the same active set is not logged again");
    g_fn[0].alive = 0;
    check(stderr_has(check_slot0, NULL, "node n0 does not answer — n3 takes its place"),
          "a replacement is logged with both names");
    for (int i = 0; i < 5; i++) g_fn[i].alive = 0;
    pool_new(1, POOL_BY_CONNECTION, 1);
    pl_publish();
    check(stderr_has(check_slot0, NULL, "no active node answers (test node is silent)"),
          "the last node dies — the log says no node answers, with the reason");
    g_fn[0].alive = 1;
    check(stderr_has(check_slot0, NULL, "node n0 answers again"), "it comes back — the log says so");
    all_alive();
}


static int stdout_has(void (*f)(void *), void *arg, const char *needle) {
    int p[2];
    if (pipe(p) != 0) return 0;
    int save = dup(1);
    dup2(p[1], 1);
    ctl_init(1);
    f(arg);
    ctl_init(0);
    dup2(save, 1);
    close(save);
    close(p[1]);
    char buf[4096];
    ssize_t r = read(p[0], buf, sizeof buf - 1);
    close(p[0]);
    buf[r > 0 ? r : 0] = 0;
    return strstr(buf, needle) != NULL;
}

static struct pl_sess *g_up_sess;
static void unproven_streak(void *arg) {
    (void)arg;
    for (int i = 0; i < 3; i++) pl_seen_at(g_up_sess, -1, pl_now_ms());
    pl_check(0);
}

static void t_pool_unproven(void) {
    all_alive();
    g_fn[1].alive = 0;
    pool_new(1, POOL_BY_CONNECTION, 2);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *d = (struct pl_sess *)dst;
    g_up_sess = d;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    pl_check(0);
    pl_check(0);
    check(g_pl.slot[0].up, "unproven: scheduled checks that pass never count against the node");
    for (int i = 0; i < 2; i++) {
        g_pl.slot[0].checked_at = 0;
        pl_lost(&g_pl, d);
        pl_check(0);
    }
    check(g_pl.slot[0].up, "unproven: checks a cut connection asked for and that pass never count");
    unproven_streak(NULL);
    check(g_pl.slot[0].up, "unproven: a check passing after the first streak keeps the node");
    pl_seen_at(d, 0, pl_now_ms());
    unproven_streak(NULL);
    check(g_pl.slot[0].up, "unproven: a successful connect between streaks starts the count again");
    check(stdout_has(unproven_streak, NULL,
                     "{\"type\":\"node_down\",\"node\":\"n0\",\"index\":0,\"why\":\"the check passes but "
                     "connections do not open (6 failed connects in a row)\"}"),
          "unproven: a second streak whose check passes drops the node with that reason");
    check(!g_pl.slot[0].up && g_pl.said_up == 0, "unproven: the slot is dead and the pool says so");
    uint64_t retry = g_pl.slot[0].retry;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0, "unproven: a round finds the node answering again");
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    for (int i = 0; i < 3; i++) pl_seen_at(d, -1, pl_now_ms());
    uint64_t t0 = pl_now_ms();
    pl_check(0);
    check(!g_pl.slot[0].up && g_pl.slot[0].due >= t0 + retry * 1000,
          "unproven: revived without a connect, the first streak drops it and the round pause holds");
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    pl_check(0);
    pl_seen_at(d, 0, pl_now_ms());
    unproven_streak(NULL);
    check(g_pl.slot[0].up, "unproven: a successful connect after reviving clears the verdict");
    g_fn[1].alive = 1;

    pool_new(1, POOL_BY_CONNECTION, 2);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    unproven_streak(NULL);
    unproven_streak(NULL);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 1, "unproven: a dropped node is replaced by a free candidate");
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    unproven_streak(NULL);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 1,
          "unproven: the replacement starts its own count, one streak does not drop it");
}

static void t_pool_unproven_alone(void) {
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 1);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *d = (struct pl_sess *)dst;
    g_up_sess = d;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    unproven_streak(NULL);
    unsigned gen = g_pl.slot[0].gen;
    unproven_streak(NULL);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0,
          "unproven alone: with no free candidate the only node limps on");
    check(g_pl.slot[0].gen == gen, "unproven alone: its connections are not reset");
    pool_new(2, POOL_BY_CONNECTION, 2);
    pl_check(1);
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    unproven_streak(NULL);
    unproven_streak(NULL);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0 && g_pl.slot[1].up,
          "unproven alone: every candidate in a slot, the node limps on");
}

static void t_pool_streak_after_check(void) {
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 2);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *d = (struct pl_sess *)dst;
    g_up_sess = d;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    uint64_t before = pl_now_ms() - 1000;
    unproven_streak(NULL);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0, "restart burst: the first streak's check passes");
    for (int i = 0; i < 3; i++) pl_seen_at(d, -1, before);
    check(!g_pl.slot[0].kick && g_pl.slot[0].streak == 0,
          "restart burst: failures of connects started before the check do not count");
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0, "restart burst: the node is not dropped for them");
    pl_seen_at(d, -1, g_pl.slot[0].checked_at);
    check(g_pl.slot[0].streak == 1, "restart burst: a connect started at the check counts");
    pl_seen_at(d, 0, before);
    check(g_pl.slot[0].streak == 0 && g_pl.slot[0].unproven == 0,
          "restart burst: a success counts whenever it started");
}

static const int g_sel_13[] = { 1, 3 };
static const int g_sel_012[] = { 0, 1, 2 };
static const int g_sel_02[] = { 0, 2 };
static const int g_sel_12[] = { 1, 2 };
static const int g_sel_3[] = { 3 };
static const int g_sel_134[] = { 1, 3, 4 };

static void t_pool_swap(void) {
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 3);
    pl_check(1);
    struct conn *a = NULL;
    for (uint16_t p = 52000; p < 52100 && !a; p++) {
        struct conn *c = pm_open(p, 0x0b0b0b0cu);
        if (!c) break;
        if (((const struct pl_sess *)SESS(c))->slot == 0) a = c;
        else conn_reset(c, &g_tun);
    }
    pm_drain(NULL, NULL);
    check(a != NULL, "swap fixture: a connection on node 0");
    if (!a) return;
    struct flow_key ka = a->key;
    static unsigned char spare[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *sp = (struct pl_sess *)spare;
    pl_clear(spare);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(sp, 0);
    pthread_mutex_unlock(&g_pl.mu);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)];
    pl_clear(dst);
    unsigned gen1 = g_pl.slot[1].gen;
    unsigned ep = __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE);
    pool_select(g_sel_13, 2);
    /* catches: a swap resetting a node that stays in the list */
    check(g_pl.slot[1].node == 1 && g_pl.slot[1].up && g_pl.slot[1].gen == gen1,
          "swap: a node kept in the list keeps its slot and generation");
    /* catches: a removed node still taking new connections */
    check(g_pl.slot[0].node == -1 && __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE) != ep &&
              g_pl.slot[0].due <= pl_now_ms(),
          "swap: a removed node leaves its slot, the slot searches at once");
    /* catches: a spare to a removed node handed to a new connection */
    check(pl_match(&g_pl, dst, spare) == -1, "swap: a spare to a removed node is dropped");
    pl_check(0);
    /* catches: an added node never used */
    check(g_pl.slot[0].node == 3 && g_pl.slot[0].up, "swap: the slot refills from the new list (3)");
    pm_sweep();
    struct conn *c = conn_find(&ka);
    /* catches: a drained node's connections reset like a dead node's */
    check(c != NULL, "swap: a connection of a removed node is not reset");
    if (!c) return;
    const struct pl_sess *ps = SESS(c);
    /* catches: a drained session left bound to the slot's new node */
    check(ps->slot == -1 && ps->node == &g_fn[0], "swap: it keeps its node and leaves the slot");
    struct pl_sess on3;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(&on3, 0);
    pthread_mutex_unlock(&g_pl.mu);
    g_fn[3].alive = 0;
    pl_check(0);
    pl_check(0);
    /* catches: every generation change treated as a drain */
    check(pl_stale(&g_pl, &on3), "swap: a node of the new list that dies still resets its connections");
    g_fn[3].alive = 1;
    conn_reset(c, &g_tun);
    pm_drain(NULL, NULL);
}

static void t_pool_swap_grow(void) {
    all_alive();
    pool_new(3, POOL_BY_CONNECTION, 1);
    check(g_pl.n == 1, "grow fixture: one candidate, one slot");
    pool_select(g_sel_012, 3);
    pl_check(1);
    pl_check(2);
    /* catches: slots fixed at startup by the first list's length */
    check(g_pl.n == 3 && g_pl.slot[1].node == 1 && g_pl.slot[2].node == 2,
          "swap: a longer list fills the active slots it lacked");

    pool_new(2, POOL_BY_CONNECTION, 2);
    g_fn[1].alive = 0;
    pl_check(1);
    check(g_pl.slot[1].node == -1 && g_pl.slot[1].due > pl_now_ms() + 10000,
          "backoff fixture: the empty slot waits for its next round");
    g_fn[1].alive = 1;
    pool_select(g_sel_012, 3);
    /* catches: a waiting empty slot ignoring the new list until its pause ends */
    check(g_pl.slot[1].due <= pl_now_ms() && g_pl.slot[1].retry == 15,
          "swap: an empty slot searches the new list at once");
}

static void check0(void *arg) { (void)arg; pl_check(0); }

static void t_pool_swap_races(void) {
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 3);
    g_hook_node = 1;
    g_hook_sel = g_sel_02;
    g_hook_n = 2;
    pl_check(1);
    /* catches: refill taking a candidate removed while it was probed */
    check(g_pl.slot[1].node == 2, "swap during a probe: the removed candidate is not taken");

    pool_new(2, POOL_BY_CONNECTION, 2);
    g_fn[1].alive = 0;
    g_hook_node = 1;
    g_hook_sel = g_sel_012;
    g_hook_n = 3;
    pl_check(1);
    /* catches: a round over the old list putting off the new one */
    check(g_pl.slot[1].node == -1 && g_pl.slot[1].due <= pl_now_ms(),
          "swap during a failed round: the slot searches the new list at once");
    all_alive();

    pool_new(1, POOL_BY_CONNECTION, 3);
    pl_check(0);
    g_fn[0].alive = 0;
    g_fn[1].alive = 0;
    pl_check(0);
    memset(g_probes, 0, sizeof g_probes);
    g_hook_node = 1;
    g_hook_sel = g_sel_12;
    g_hook_n = 2;
    pl_check(0);
    /* catches: a round going on over a slot drained under it */
    check(g_probes[1] == 1 && g_probes[2] == 0, "swap during a round: the round stops at once");
    all_alive();

    pool_new(1, POOL_BY_CONNECTION, 3);
    g_pl.slot[0].lost = 1;
    g_fn[0].alive = 0;
    g_hook_node = 0;
    g_hook_sel = g_sel_12;
    g_hook_n = 2;
    /* catches: a check finishing on a slot drained under it */
    check(!stderr_has(check0, NULL, "node n0 does not answer"),
          "swap during a check: the removed node is not declared dead");
    all_alive();

    pool_new(2, POOL_BY_CONNECTION, 3);
    pl_check(1);
    g_fn[0].alive = 0;
    g_fn[2].alive = 0;
    pl_check(0);
    pl_check(0);
    check(!g_pl.slot[0].up && g_pl.slot[0].node == 0, "revive fixture: slot 0 waits for its dead node");
    g_fn[0].alive = 1;
    g_hook_node = 0;
    g_hook_sel = g_sel_12;
    g_hook_n = 2;
    pl_check(0);
    /* catches: a dead slot revived on its own node after the node was removed */
    check(g_pl.slot[0].node == -1 && !g_pl.slot[0].up, "swap during a revive: the removed node does not come back");
    g_hook_node = -1;
    all_alive();
}

static void t_pool_swap_events(void) {
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 3);
    pl_check(1);
    pool_select(g_sel_13, 2);
    pl_check(0);
    g_pl.sig[0] = '\0';
    /* catches: events without the node's index in the store */
    check(stdout_has(publish, NULL, "{\"type\":\"active\",\"nodes\":[\"n3\",\"n1\"],\"index\":[3,1],\"v6\":[false,false]}"),
          "the active event carries each node's index");
    g_fn[3].alive = 0;
    g_pl.slot[0].lost = 1;
    check(stdout_has(check0, NULL, "{\"type\":\"node_down\",\"node\":\"n3\",\"index\":3,"),
          "node_down carries the node's index");
    g_fn[3].alive = 1;

    pool_new(1, POOL_BY_CONNECTION, 3);
    pl_publish();
    g_fn[3].alive = 0;
    pool_select(g_sel_3, 1);
    pthread_mutex_lock(&g_pl.mu);
    int next = pl_next();
    pthread_mutex_unlock(&g_pl.mu);
    /* catches: a drain the pool thread does not publish */
    check(next == -1, "a drain asks the pool thread to publish the active set");
    /* catches: a removed node still named active when nothing replaces it */
    check(stdout_has(check0, NULL, "{\"type\":\"active\",\"nodes\":[],\"index\":[],\"v6\":[]}"),
          "nothing active after a swap: the active event says so");
    g_fn[3].alive = 1;
}

static volatile int g_thr_stop;
static void *thr_select(void *arg) {
    (void)arg;
    for (unsigned k = 0; !__atomic_load_n(&g_thr_stop, __ATOMIC_ACQUIRE); k++) {
        pool_select(k & 1 ? g_sel_012 : g_sel_134, 3);
        nanosleep(&(struct timespec){ 0, 200000 }, NULL);
    }
    return NULL;
}
static void *thr_conn(void *arg) {
    (void)arg;
    static unsigned char d[PL_HDR + sizeof(struct fsess)], sp[PL_HDR + sizeof(struct fsess)];
    struct flow_key k = pm_key(1, htonl(0x5db80001u));
    while (!__atomic_load_n(&g_thr_stop, __ATOMIC_ACQUIRE)) {
        pl_clear(d);
        pl_clear(sp);
        pl_flow_open(&g_pl, d, &k, 0);
        pthread_mutex_lock(&g_pl.mu);
        int s = pl_pick(&k);
        if (s >= 0) pl_bind((struct pl_sess *)sp, s);
        pthread_mutex_unlock(&g_pl.mu);
        pl_match(&g_pl, d, sp);
        pl_stale(&g_pl, d);
        pl_stale(&g_pl, sp);
        pl_lost(&g_pl, d);
        pl_peer_of(&g_pl, d);
    }
    return NULL;
}
static void *thr_check(void *arg) {
    (void)arg;
    for (unsigned k = 0; !__atomic_load_n(&g_thr_stop, __ATOMIC_ACQUIRE); k++) {
        pthread_mutex_lock(&g_pl.mu);
        int n = g_pl.n;
        pthread_mutex_unlock(&g_pl.mu);
        pl_check((int)(k % (unsigned)n));
    }
    return NULL;
}

static void quiet(void *arg) {
    pthread_t a, b, c;
    __atomic_store_n(&g_thr_stop, 0, __ATOMIC_RELEASE);
    pthread_create(&a, NULL, thr_select, NULL);
    pthread_create(&b, NULL, thr_conn, NULL);
    pthread_create(&c, NULL, thr_check, NULL);
    nanosleep(&(struct timespec){ 1, 0 }, NULL);
    __atomic_store_n(&g_thr_stop, 1, __ATOMIC_RELEASE);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    pthread_join(c, NULL);
    *(int *)arg = 1;
}

static void t_pool_threads(void) {
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 3);
    int done = 0;
    stderr_has(quiet, &done, "-");
    int dup = 0;
    pthread_mutex_lock(&g_pl.mu);
    if (g_pl.slot[0].node >= 0 && g_pl.slot[0].node == g_pl.slot[1].node) dup = 1;
    pthread_mutex_unlock(&g_pl.mu);
    /* catches: swaps, checks and connections racing into a broken slot set (run under TSan) */
    check(done && !dup, "swaps, checks and connections on three threads keep the slots sound");
}

static _Alignas(64) unsigned char g_pin[PL_HDR + sizeof(struct fsess)];

static const struct fnode *pin_dial(void) {
    int n0 = g_srv_n;
    if (g_pl_ops.connect(&g_pl, g_pin, 1) != 0 || g_srv_n != n0 + 1) return NULL;
    pthread_mutex_lock(&g_srv_mu);
    const struct fnode *n = g_srv_node[--g_srv_n];
    close(g_srv[g_srv_n]);
    pthread_mutex_unlock(&g_srv_mu);
    g_pl_ops.close(g_pin);
    return n;
}

/* Catches a pinned session that picks a slot instead of dialling the node it was given. */
static void t_pin_dials_the_named_node(void) {
    all_alive();
    pool_new(3, POOL_BY_CONNECTION, 3);
    pl_check(1);
    pl_check(2);
    struct flow_key k = pm_key(52000, 0x0b0b0b0bu);
    int hits = 0;
    for (int i = 0; i < 20; i++) {
        g_pl_ops.clear(g_pin);
        if (pool_flow_open_on(g_pin, 2, &k, 0, NULL) == 0 && pin_dial() == &g_fn[2]) hits++;
        k.sport++;
    }
    check(hits == 20, "a pinned session dials its node, 20 times out of 20");
    g_pl_ops.clear(g_pin);
}

/* Catches a pinned session refused or moved because its node holds no live slot. */
static void t_pin_survives_a_dead_slot(void) {
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 3);
    pl_check(1);
    struct flow_key k = pm_key(52100, 0x0b0b0b0bu);
    g_pl_ops.clear(g_pin);
    check(g_pl.slot[0].node == 0 && g_pl.slot[1].node == 1 && pool_flow_open_on(g_pin, 2, &k, 0, NULL) == 0 &&
              pin_dial() == &g_fn[2],
          "a pinned node outside the active slots is still dialled");
    g_pl.slot[1].up = 0;
    g_pl_ops.clear(g_pin);
    check(pool_flow_open_on(g_pin, 1, &k, 0, NULL) == 0 && pin_dial() == &g_fn[1],
          "a pinned node whose slot is down is still dialled");
    g_pl.slot[1].up = 1;
    g_pl_ops.clear(g_pin);
}

/* Catches a spare handed to a pinned session, which would move it off its node. */
static void t_pin_never_takes_a_spare(void) {
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 3);
    static _Alignas(64) unsigned char spare[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *ps = (struct pl_sess *)spare;
    struct spare *sp = &g_spares[0];
    struct spare save = *sp;
    struct flow_key k = pm_key(52200, 0x0b0b0b0bu);
    int took[2];
    const void *pinned_node = NULL;
    for (int pin = 1; pin >= 0; pin--) {
        g_pl_ops.clear(spare);
        pl_bind(ps, 0);
        sp->sess = spare;
        sp->state = SPARE_READY;
        sp->born_ns = now_ns();
        g_pl_ops.clear(g_pin);
        if (pin) pool_flow_open_on(g_pin, 2, &k, 0, NULL);
        else g_pl_ops.flow_open(&g_pl, g_pin, &k, 0);
        took[pin] = spare_checkout(g_pin);
        if (pin) pinned_node = ((struct pl_sess *)g_pin)->node;
    }
    check(took[1] == -1 && pinned_node == &g_fn[2], "a pinned session never takes a spare and keeps its node");
    check(took[0] == 0, "a session cleared after a pin takes a spare again");
    *sp = save;
    g_pl_ops.clear(g_pin);
}

static int g_v6ok[5];
static int g_probes6[5];
static int g_v6cb_n, g_v6cb_last = -1;
static int g_hook6_node = -1;
static int g_pick6_in_probe = -2;
static int g_v6_in_probe = -1;
static int f_probe6(const void *node, int t, char *why, size_t n) {
    (void)t;
    int i = (int)((const struct fnode *)node - g_fn);
    g_probes6[i]++;
    if (i == g_hook6_node) {
        g_hook6_node = -1;
        pool_select(g_hook_sel, g_hook_n);
    }
    if (g_pick6_in_probe == -1) {
        struct flow_key k = pm_key(1, 0);
        k.v6 = 1;
        pthread_mutex_lock(&g_pl.mu);
        g_pick6_in_probe = pl_pick(&k);
        g_v6_in_probe = g_pl.slot[0].v6;
        pthread_mutex_unlock(&g_pl.mu);
    }
    if (g_v6ok[i]) return 0;
    snprintf(why, n, "no IPv6");
    return -1;
}
static const struct pool_proto f6_proto = { .ops = &f_ops, .probe = f_probe, .probe6 = f_probe6,
                                            .name = f_name };
static int g_v6cb_rc;
static int f_v6cb(int on) { g_v6cb_n++; g_v6cb_last = on; return g_v6cb_rc; }

static void pool_new6(int active, int by, int ncand, int checked) {
    pool_new_ex(active, by, ncand, checked);
    g_pl.cf.proto = &f6_proto;
    g_pl.cf.v6_changed = f_v6cb;
    memset(g_probes6, 0, sizeof g_probes6);
    g_v6cb_n = 0;
    g_v6cb_last = -1;
    g_v6cb_rc = 0;
}

static struct flow_key pkey6(uint16_t sport, unsigned char last) {
    struct flow_key k = pm_key(sport, 0);
    static const unsigned char cli[16] = { 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    static const unsigned char srv[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    memcpy(k.src.b, cli, 16);
    memcpy(k.dst.b, srv, 16);
    k.dst.b[15] = last;
    k.v6 = 1;
    return k;
}

static void t_pool_v6_flows_only_to_a_v6_node(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[0] = 1;
    for (int by = POOL_BY_CONNECTION; by <= POOL_BY_SITE_CLIENT; by++) {
        pool_new6(2, by, 3, 1);
        pl_check(1);
        pl_check(0);
        int only0 = 1, v4[2] = { 0, 0 };
        for (int i = 0; i < 300; i++) {
            struct flow_key k = pkey6((uint16_t)(1000 + i), (unsigned char)i);
            k.src.b[14] = (unsigned char)i;
            if (pl_pick(&k) != 0) only0 = 0;
            struct flow_key k4 = pm_key((uint16_t)(1000 + i), htonl(0x5db80000u + (uint32_t)i * 7919u));
            k4.src.v4 = htonl(0x0a000002u + (uint32_t)i);
            int s = pl_pick(&k4);
            if (s == 0 || s == 1) v4[s]++;
        }
        check(only0, "v6: every v6 flow goes to the one v6-capable node, whatever the spread");
        check(v4[0] > 30 && v4[1] > 30, "v6: v4 flows still spread over both nodes");
    }
}

static void t_pool_v6_none_refuses_v6_only(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    pl_check(0);
    static unsigned char s6[PL_HDR + sizeof(struct fsess)], s4[PL_HDR + sizeof(struct fsess)];
    pl_clear(s6);
    pl_clear(s4);
    struct flow_key k6 = pkey6(2000, 1), k4 = pm_key(2000, htonl(0x5db80001u));
    check(pl_flow_open(&g_pl, s6, &k6, 0) == -1, "v6: no v6-capable node — a v6 flow does not open");
    check(pl_flow_open(&g_pl, s4, &k4, 0) == 0, "v6: no v6-capable node — a v4 flow opens");
    g_v6ok[0] = 1;
    pl_check(0);
    g_pl.slot[0].up = 0;
    check(pl_pick(&k6) == -1 && pl_pick(&k4) == 0,
          "v6: a dead v6 node is no fallback for a v6 flow, as it is for a v4 one");
    g_pl.slot[0].up = 1;
}

static void t_pool_v6_changed_once_per_flip(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[0] = 1;
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    pl_check(0);
    check(g_v6cb_n == 1 && g_v6cb_last == 1 && g_probes6[0] == 1,
          "v6: the first passing v6 check turns IPv6 on once");
    pl_check(0);
    check(g_v6cb_n == 1 && g_probes6[0] == 2, "v6: the next passing check does not call it again");
    g_fn[0].alive = 0;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].v6 && g_v6cb_n == 1 && g_probes6[0] == 2,
          "v6: one failed v4 check keeping the node up leaves IPv6 on and skips the v6 check");
    pl_check(0);
    check(!g_pl.slot[0].up && g_v6cb_n == 2 && g_v6cb_last == 0 && g_probes6[0] == 2,
          "v6: the node dies — IPv6 off once, no v6 check of a dead node");
    pl_check(0);
    check(g_v6cb_n == 2 && g_probes6[0] == 2, "v6: a failed search round neither checks v6 nor calls again");
    g_fn[0].alive = 1;
    pl_check(0);
    check(g_pl.slot[0].up && g_v6cb_n == 3 && g_v6cb_last == 1 && g_probes6[0] == 3,
          "v6: the node answers again — IPv6 on once");
    g_v6ok[0] = 0;
    pl_check(0);
    check(g_pl.slot[0].up && !g_pl.slot[0].v6 && g_v6cb_n == 4 && g_v6cb_last == 0,
          "v6: one failed v6 check turns IPv6 off");
    g_v6ok[0] = 1;
}

static void t_pool_v6_failed_apply_retried_while_on(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[0] = 1;
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    g_v6cb_rc = -1;
    pl_check(0);
    check(g_v6cb_n == 1 && g_v6cb_last == 1, "v6: the first apply is tried");
    pl_check(0);
    check(g_v6cb_n == 2 && g_v6cb_last == 1, "v6: a failed apply is tried again at the next check");
    g_v6cb_rc = 0;
    pl_check(0);
    check(g_v6cb_n == 3, "v6: a failed apply is tried until it succeeds");
    pl_check(0);
    check(g_v6cb_n == 3, "v6: an applied flag is not called again");
    g_v6cb_rc = -1;
    g_v6ok[0] = 0;
    pl_check(0);
    check(g_v6cb_n == 4 && g_v6cb_last == 0, "v6: IPv6 off is called once");
    pl_check(0);
    check(g_v6cb_n == 4, "v6: a failed removal is not retried");
    g_v6ok[0] = 1;
}

static void t_pool_v6_replacement_starts_v4_only(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[0] = 1;
    pool_new6(1, POOL_BY_CONNECTION, 2, 1);
    pl_check(0);
    g_fn[0].alive = 0;
    pl_check(0);
    g_pick6_in_probe = -1;
    g_v6_in_probe = -1;
    pl_check(0);
    int pick = g_pick6_in_probe;
    g_pick6_in_probe = -2;
    check(g_pl.slot[0].up && g_pl.slot[0].node == 1 && g_probes6[1] == 1,
          "v6 replacement fixture: node 1 replaces node 0 and gets its v6 check");
    check(pick == -1 && g_v6_in_probe == 0,
          "v6: a replacement node carries no v6 flow before its own v6 check passes");
    check(g_v6cb_n == 2 && g_v6cb_last == 0, "v6: a v4-only replacement turns IPv6 off");
    g_fn[0].alive = 1;
}

static void t_pool_v6_stale_result_dropped(void) {
    all_alive();
    for (int i = 0; i < 5; i++) g_v6ok[i] = 1;
    pool_new6(1, POOL_BY_CONNECTION, 3, 1);
    pl_check(0);
    static const int sel_1[] = { 1 };
    g_hook_sel = sel_1;
    g_hook_n = 1;
    g_hook6_node = 0;
    pl_check(0);
    check(g_v6cb_n == 1 && g_pl.slot[0].node == -1 && !g_pl.slot[0].v6,
          "v6: a v6 check result for a node that left meanwhile is dropped, its flag cleared");
    g_hook6_node = -1;
    pl_publish();
    check(g_v6cb_n == 2 && g_v6cb_last == 0, "v6: the node left — IPv6 off");
}

static void t_pool_v6_spare_on_v4_node_kept(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[0] = 1;
    pool_new6(2, POOL_BY_CONNECTION, 3, 1);
    pl_check(1);
    pl_check(0);
    static _Alignas(64) unsigned char spare[PL_HDR + sizeof(struct fsess)];
    static _Alignas(64) unsigned char sess[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *ps = (struct pl_sess *)spare;
    struct spare *sp = &g_spares[0];
    struct spare save = *sp;
    g_pl_ops.clear(spare);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(ps, 1);
    pthread_mutex_unlock(&g_pl.mu);
    sp->sess = spare;
    sp->state = SPARE_READY;
    sp->born_ns = now_ns();
    g_pl_ops.clear(sess);
    struct flow_key k6 = pkey6(3000, 3);
    int opened = g_pl_ops.flow_open(&g_pl, sess, &k6, 0);
    int took = spare_checkout(sess);
    check(opened == 0 && took == -1 && sp->state == SPARE_READY && ((struct pl_sess *)sess)->slot == 0,
          "v6: a v6 flow does not take a spare on a v4-only node, and the spare stays");
    g_pl_ops.clear(sess);
    struct flow_key k4 = pm_key(3001, htonl(0x5db80003u));
    g_pl_ops.flow_open(&g_pl, sess, &k4, 0);
    check(spare_checkout(sess) == 0, "v6: the same spare goes to a v4 flow");
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(ps, 0);
    pthread_mutex_unlock(&g_pl.mu);
    g_pl_ops.clear(sess);
    g_pl_ops.flow_open(&g_pl, sess, &k6, 0);
    check(pl_match(&g_pl, sess, spare) == 1, "v6: a spare on the v6 node suits a v6 flow");
    *sp = save;
    g_pl_ops.clear(sess);
}

static void t_pool_v6_null_hooks(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[0] = 1;
    pool_new(1, POOL_BY_CONNECTION, 1);
    pl_check(0);
    struct flow_key k6 = pkey6(4000, 4);
    check(g_pl.slot[0].up && !g_pl.slot[0].v6 && pl_pick(&k6) == -1,
          "v6: a protocol without a v6 check — every node is v4-only");
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    g_pl.cf.v6_changed = NULL;
    pl_check(0);
    check(g_pl.slot[0].v6 && pl_pick(&k6) == 0, "v6: no v6_changed hook — the flag still works");
}

static void t_pool_v6_checked_first_node(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[0] = 1;
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    pl_start6();
    check(g_probes6[0] == 1 && g_pl.slot[0].v6 && g_v6cb_n == 1 && g_v6cb_last == 1,
          "v6: a node probed at startup gets its v6 check when the checks start");
    pool_new6(1, POOL_BY_CONNECTION, 1, 0);
    pl_start6();
    check(g_probes6[0] == 0, "v6: a node not probed at startup waits for its own first check");
}

static void checks0(int n) { for (int k = 0; k < n; k++) pl_check(0); }

/* catches: a v4-only node dialled for v6 on every check, or the gap not restarting after a failure */
static void t_pool_v6_gap_on_v4_only_node(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    pl_check(0);
    check(g_pl.slot[0].up && !g_pl.slot[0].v6 && g_probes6[0] == 1, "v6 gap: the first check dials v6 once");
    checks0(9);
    check(g_pl.slot[0].up && g_probes6[0] == 1, "v6 gap: the next nine checks of a v4-only node dial no v6");
    pl_check(0);
    check(g_probes6[0] == 2, "v6 gap: the tenth check dials v6 again");
    checks0(9);
    check(g_probes6[0] == 2, "v6 gap: a failure at the tenth check starts the gap again");
    pl_check(0);
    check(g_probes6[0] == 3, "v6 gap: and the next tenth dials it");
}

/* catches: the gap applied while IPv6 is on, so a node losing v6 keeps it for ten checks */
static void t_pool_v6_on_checked_every_time(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[0] = 1;
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    checks0(12);
    check(g_pl.slot[0].v6 && g_probes6[0] == 12, "v6 gap: with IPv6 on every check dials v6");
    g_v6ok[0] = 0;
    pl_check(0);
    check(!g_pl.slot[0].v6 && g_probes6[0] == 13 && g_v6cb_last == 0,
          "v6 gap: a node losing v6 turns IPv6 off at the next check");
}

/* catches: the gap gating the v6 check of a node new to the slot */
static void t_pool_v6_gap_reset_by_node_change(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    g_v6ok[1] = 1;
    pool_new6(1, POOL_BY_CONNECTION, 2, 1);
    pl_check(0);
    g_fn[0].alive = 0;
    checks0(2);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 1 && g_probes6[0] == 1 && g_probes6[1] == 1,
          "v6 gap: the replacement node is dialled for v6 at once");
    check(g_pl.slot[0].v6 && g_v6cb_last == 1, "v6 gap: a v6 replacement turns IPv6 on");
    pl_check(0);
    check(g_probes6[1] == 2, "v6 gap: and its next check dials v6 too");
    g_fn[0].alive = 1;
}

/* catches: a v6 check passing after the gap that does not turn IPv6 on */
static void t_pool_v6_gap_then_pass(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    pl_check(0);
    checks0(9);
    g_v6ok[0] = 1;
    check(!g_pl.slot[0].v6 && g_probes6[0] == 1, "v6 gap: the node gained v6, not yet dialled");
    pl_check(0);
    check(g_pl.slot[0].v6 && g_probes6[0] == 2 && g_v6cb_n == 1 && g_v6cb_last == 1,
          "v6 gap: the tenth check passes v6 and turns IPv6 on");
    pl_check(0);
    check(g_probes6[0] == 3, "v6 gap: IPv6 on again means a v6 check every time");
}

static void check_slot0_once(void *arg) { (void)arg; pl_check(0); }

static void t_pool_v6_flag_publishes(void) {
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    pool_new6(1, POOL_BY_CONNECTION, 1, 1);
    pl_publish();
    g_v6ok[0] = 1;
    check(stdout_has(check_slot0_once, NULL, "{\"type\":\"active\",\"nodes\":[\"n0\"],\"index\":[0],\"v6\":[true]}\n"),
          "v6: the same node turning v6-capable publishes the active set again");
}

static void t_addr6_of(void) {
    static const unsigned char want[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc6, 0x33, 0x64, 0x02 };
    unsigned char got[16];
    struct in_addr a;
    inet_pton(AF_INET, "198.51.100.2", &a);
    ifcfg_addr6_of(a.s_addr, got);
    check(!memcmp(got, want, 16), "v6: the device address is 2001:db8:: and the IPv4 address in network order");
}

static void pool_v6_part(void) {
    t_pool_v6_flows_only_to_a_v6_node();
    t_pool_v6_none_refuses_v6_only();
    t_pool_v6_changed_once_per_flip();
    t_pool_v6_failed_apply_retried_while_on();
    t_pool_v6_replacement_starts_v4_only();
    t_pool_v6_stale_result_dropped();
    t_pool_v6_spare_on_v4_node_kept();
    t_pool_v6_null_hooks();
    t_pool_v6_checked_first_node();
    t_pool_v6_flag_publishes();
    t_pool_v6_gap_on_v4_only_node();
    t_pool_v6_on_checked_every_time();
    t_pool_v6_gap_reset_by_node_change();
    t_pool_v6_gap_then_pass();
    t_addr6_of();
}

#define CT 1000000ull

static int ints_are(const int *got, size_t n, const int *want, size_t wn) {
    return n == wn && !memcmp(got, want, n * sizeof *got);
}

static void cand_pool(void) {
    pool_new(2, POOL_BY_CONNECTION, 5);
    g_pl.slot[0].node = g_pl.slot[1].node = -1;
}

static void t_pool_cand_backoff(void) {
    /* catches: a schedule that does not start at 300 s, does not double, has no 30-min cap, overflows on a long run, or a pass that leaves the backoff */
    pool_new(2, POOL_BY_CONNECTION, 5);
    static const uint64_t back[5] = { 300000, 600000, 1200000, 1800000, 1800000 };
    int ok = 1;
    for (int j = 0; j < 5; j++) {
        pl_note(3, 0, CT + (uint64_t)j);
        ok = ok && g_pl.cand_n > 3 && g_pl.cand[3].fails == (uint32_t)j + 1 &&
             g_pl.cand[3].last == CT + (uint64_t)j && g_pl.cand[3].next == CT + (uint64_t)j + back[j];
    }
    check(ok, "a candidate failing in a row backs off 300, 600, 1200, 1800, 1800 s from its last failure");
    pl_note(3, 1, CT + 5);
    check(g_pl.cand_n > 3 && g_pl.cand[3].fails == 0 && g_pl.cand[3].next == 0 && g_pl.cand[3].last == 0,
          "a passing probe clears the record");
    for (int j = 0; j < 40; j++) pl_note(3, 0, CT + 10 + (uint64_t)j);
    check(g_pl.cand_n > 3 && g_pl.cand[3].fails == 40 && g_pl.cand[3].last == CT + 49 &&
              g_pl.cand[3].next == CT + 49 + 1800000,
          "forty failures in a row stay at the 30-min cap");
    pl_note(4096, 0, CT);
    check(g_pl.cand_n > 4096 && g_pl.cand[4096].fails == 1 && g_pl.cand[4096].next == CT + 300000,
          "a record far past the others is grown on demand");
    pl_note(4097, 0, CT);
    check(g_pl.cand_n == 8194, "the records grow to twice their size, not one at a time");
    size_t n = g_pl.cand_n;
    pl_note(-1, 0, CT);
    check(g_pl.cand_n == n && pl_rec(-1) == NULL, "a negative index has no record and is not noted");
}

static void t_pool_cand_order_clean_is_fircd_order(void) {
    /* catches: candidates sorted by index instead of fircd's order, or the slot's previous node or another slot's node offered */
    cand_pool();
    static const int sel[5] = { 4, 2, 0, 3, 1 };
    static const int all[5] = { 4, 2, 0, 3, 1 }, no2[4] = { 4, 0, 3, 1 }, no0[4] = { 4, 2, 3, 1 };
    int out[8];
    int ok = 1;
    for (int down = 0; down < 2; down++) {
        ok = ok && ints_are(out, pl_order(sel, 5, -1, -1, down, CT, out, 8), all, 5);
        ok = ok && ints_are(out, pl_order(sel, 5, -1, 2, down, CT, out, 8), no2, 4);
    }
    check(ok, "no records: both orders are fircd's, without the slot's previous node");
    g_pl.slot[1].node = 0;
    ok = 1;
    for (int down = 0; down < 2; down++) {
        ok = ok && ints_are(out, pl_order(sel, 5, 0, -1, down, CT, out, 8), no0, 4);
        ok = ok && ints_are(out, pl_order(sel, 5, 1, -1, down, CT, out, 8), all, 5);
    }
    check(ok, "another slot's node is left out; the asking slot's own is not another's");
}

static void t_pool_cand_order_extra_waits(void) {
    /* catches: backoff ignored in extra mode, an expiry compared with > instead of >=, or an expired candidate kept behind clean ones */
    cand_pool();
    static const int sel[5] = { 0, 1, 2, 3, 4 }, wait[4] = { 0, 2, 3, 4 };
    int out[8];
    pl_note(1, 0, CT);
    check(ints_are(out, pl_order(sel, 5, -1, -1, 0, CT + 299999, out, 8), wait, 4),
          "extra mode: a candidate in backoff is left out");
    check(ints_are(out, pl_order(sel, 5, -1, -1, 0, CT + 300000, out, 8), sel, 5),
          "extra mode: an expired backoff is clean again, in fircd's order");
}

static void t_pool_cand_order_extra_heals(void) {
    /* catches: extra mode ordered by last failure, so a healed pool never returns to fircd's order */
    cand_pool();
    static const int sel[5] = { 0, 1, 2, 3, 4 };
    int out[8];
    for (int c = 4; c >= 0; c--) pl_note(c, 0, CT + (uint64_t)(4 - c));
    check(ints_are(out, pl_order(sel, 5, -1, -1, 0, CT + 400000, out, 8), sel, 5),
          "extra mode: a healed pool is back in fircd's order, not in the order of failures");
}

static void t_pool_cand_order_down_rotates(void) {
    /* catches: down mode leaving out candidates in backoff (the tunnel stays down), not oldest-first, ordered by next, or a cleared candidate not first */
    cand_pool();
    static const int sel[5] = { 0, 1, 2, 3, 4 }, three[3] = { 3, 1, 4 }, five[5] = { 3, 1, 4, 2, 0 };
    static const int tie[5] = { 0, 1, 2, 3, 4 }, two[5] = { 2, 0, 1, 3, 4 };
    int out[16];
    pl_note(0, 0, CT + 4);
    pl_note(1, 0, CT + 1);
    pl_note(2, 0, CT + 3);
    pl_note(4, 0, CT + 2);
    pl_note(3, 0, CT - 1000);
    pl_note(3, 0, CT);
    check(ints_are(out, pl_order(sel, 5, -1, -1, 1, CT + 5, out, 3), three, 3),
          "down mode: all in backoff, the oldest failures first, capped");
    check(ints_are(out, pl_order(sel, 5, -1, -1, 1, CT + 5, out, 16), five, 5),
          "down mode: nobody is left out");
    for (int c = 0; c < 5; c++) pl_note(c, 0, CT);
    check(ints_are(out, pl_order(sel, 5, -1, -1, 1, CT + 5, out, 16), tie, 5),
          "down mode: failures at one moment fall back to fircd's order");
    pl_note(2, 1, CT + 6);
    check(ints_are(out, pl_order(sel, 5, -1, -1, 1, CT + 6, out, 16), two, 5),
          "down mode: a clean candidate comes before the failed ones");
}

static void t_pool_order_start(void) {
    /* catches: the start's later rounds probing the same first sixteen, or never coming back to the ones that failed */
    cand_pool();
    int sel[20], want[16], out[16];
    for (int c = 0; c < 20; c++) sel[c] = c;
    check(ints_are(out, pool_order(sel, 20, out, 16), sel, 16), "the start's order: fircd's first sixteen");
    g_pl_clock_ms = CT;
    for (int c = 0; c < 16; c++) pool_note(c, 0);
    for (int c = 0; c < 16; c++) want[c] = c < 4 ? 16 + c : c - 4;
    check(ints_are(out, pool_order(sel, 20, out, 16), want, 16) && g_pl.cand_n > 15 &&
              g_pl.cand[15].last == CT && g_pl.cand[15].next == CT + 300000,
          "after sixteen failures the untried four come first, then the failed ones");
    g_pl_clock_ms = 0;
}

static void tick(void) { g_pl_clock_ms += 31000; }

static void fn_alive(int a, int b, int alive) {
    for (int i = a; i <= b; i++) g_fn[i].alive = alive;
}

static int probes_are(int a, int b, int n) {
    for (int i = a; i <= b; i++)
        if (g_probes[i] != n) return 0;
    return 1;
}

static void t_pool_walk_extra_capped(void) {
    /* catches: an uncapped walk, the same eight every round, backoff ignored in extra mode, the extra slot searching after 15 s, or a 5-min pause after a round that probed nothing */
    all_alive();
    fn_alive(1, 20, 0);
    pool_new(2, POOL_BY_CONNECTION, 21);
    memset(g_probes, 0, sizeof g_probes);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(1);
    check(probes_are(1, 8, 1) && probes_are(9, 20, 0) && g_probes[0] == 0 && g_pl.slot[1].node == -1 &&
              g_pl.slot[1].due == b + 300000,
          "extra mode: a round probes the first eight free candidates, then waits 5 min");
    tick();
    pl_check(1);
    check(probes_are(1, 16, 1) && probes_are(17, 20, 0), "extra mode: the next round takes the next eight");
    tick();
    pl_check(1);
    check(probes_are(1, 20, 1) && g_probes[0] == 0, "extra mode: the third round takes the last four");
    tick();
    pl_check(1);
    check(probes_are(1, 20, 1) && g_pl.slot[1].due == b + 93000 + 30000,
          "extra mode: every candidate in backoff, no probe, and the round pause is 30 s, not 5 min");
    g_pl_clock_ms = b + 300000;
    pl_check(1);
    check(probes_are(1, 8, 2) && probes_are(9, 20, 1) && g_probes[0] == 0,
          "extra mode: the expired backoffs come back in fircd's order");
    g_pl_clock_ms = 0;
    fn_alive(0, FN_N - 1, 1);
}

static void t_pool_extra_own_node_cadence(void) {
    /* catches: a dead slot whose free candidates are in backoff re-probing its own node only every 5 min */
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 3);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(1);
    check(g_pl.slot[1].up && g_pl.slot[1].node == 1, "own node cadence: the empty slot takes node 1");
    pl_note(2, 0, b);
    g_fn[1].alive = 0;
    memset(g_probes, 0, sizeof g_probes);
    pl_check(1);
    pl_check(1);
    check(!g_pl.slot[1].up && g_pl.slot[1].due == b + 15000 && g_pl.slot[1].retry == 30 && g_probes[2] == 0,
          "own node cadence: dead, no free candidate to probe, the next round in 15 s");
    check(g_pl.cand_n > 1 && g_pl.cand[1].fails == 1 && g_pl.cand[1].next == b + 300000,
          "own node cadence: the death backs the node off");
    tick();
    pl_check(1);
    check(g_probes[1] == 3 && g_probes[2] == 0 && g_pl.slot[1].due == b + 31000 + 30000,
          "own node cadence: the own node probed again, the next round in 30 s");
    check(g_pl.cand[1].fails == 2 && g_pl.cand[1].last == b + 31000 && g_pl.cand[1].next == b + 31000 + 600000,
          "own node cadence: the own node's failed probe is noted at the round's time");
    g_pl_clock_ms = 0;
    all_alive();
}

static void t_pool_walk_down_rotates(void) {
    /* catches: down mode honouring backoff (no probe and the tunnel stays down), a quota other than 16, the pause doubling before a full rotation (retry 30 after round 1), no rotation, or the own node skipped */
    fn_alive(0, 20, 0);
    pool_new(1, POOL_BY_CONNECTION, 21);
    memset(g_probes, 0, sizeof g_probes);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(0);
    pl_check(0);
    check(!g_pl.slot[0].up && probes_are(1, 16, 1) && probes_are(17, 20, 0) && g_pl.slot[0].due == b + 15000 &&
              g_pl.slot[0].retry == 15,
          "down mode: the death's round probes sixteen, the pause stays 15 s before a full rotation");
    tick();
    pl_check(0);
    check(g_probes[0] == 3 && probes_are(17, 20, 1) && probes_are(1, 12, 2) && probes_are(13, 16, 1) &&
              g_pl.slot[0].due == b + 31000 + 15000 && g_pl.slot[0].retry == 30,
          "down mode: own node, the untried four, then the oldest failures; the rotation done, the pause doubles");
    g_fn[14].alive = 1;
    tick();
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 14 && g_probes[13] == 2 && g_probes[14] == 2 &&
              g_probes[15] == 1 && g_probes[16] == 1 && g_pl.cand[14].fails == 0,
          "down mode: the oldest failures first, the round stops at the node that answers");
    g_pl_clock_ms = 0;
    fn_alive(0, FN_N - 1, 1);
}

static void t_pool_walk_one_leader(void) {
    /* catches: every dead slot walking the free candidates, or the last death leaving the leader on its 5-min extra pause */
    all_alive();
    pool_new(3, POOL_BY_CONNECTION, 6);
    pl_check(1);
    pl_check(2);
    check(g_pl.slot[1].node == 1 && g_pl.slot[2].node == 2, "one leader: slots 1 and 2 take nodes 1 and 2");
    fn_alive(0, 5, 0);
    memset(g_probes, 0, sizeof g_probes);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(0);
    pl_check(0);
    check(probes_are(3, 5, 1) && g_pl.slot[0].due == b + 300000,
          "one leader: slot 0 dies while others live, probes the free three, waits 5 min");
    pl_check(1);
    pl_check(1);
    check(probes_are(3, 5, 1), "one leader: slot 1 dies, the free three are in backoff");
    unsigned w0 = g_pl.slot[0].woke, w1 = g_pl.slot[1].woke;
    pl_check(2);
    pl_check(2);
    check(g_pl.slot[0].due <= b && g_pl.slot[0].retry == 15 && g_pl.slot[1].retry == 15 &&
              g_pl.slot[0].woke != w0 && g_pl.slot[1].woke != w1,
          "one leader: the last death re-arms the other slots at once");
    check(probes_are(3, 5, 1), "one leader: the last dying slot is not the leader and probes no free candidate");
    memset(g_probes, 0, sizeof g_probes);
    pl_check(1);
    check(g_probes[1] == 1 && probes_are(3, 5, 0), "one leader: a slot that is not the leader probes its own node only");
    pl_check(0);
    check(g_probes[0] == 1 && probes_are(3, 5, 1), "one leader: the leader probes its own node and the free ones");
    g_pl_clock_ms = 0;
    fn_alive(0, FN_N - 1, 1);
}

static void t_pool_start_records_carry(void) {
    /* catches: pool_setup wiping the start's records, so the first spare-slot round probes again what the start just saw fail */
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 5);
    g_pl_clock_ms = CT;
    for (int c = 1; c <= 3; c++) pool_note(c, 0);
    pool_new_keep(2, POOL_BY_CONNECTION, 5);
    memset(g_probes, 0, sizeof g_probes);
    pl_check(1);
    check(g_pl.slot[1].up && g_pl.slot[1].node == 4 && probes_are(1, 3, 0),
          "the start's failures carry into the pool: the spare slot skips them");
    g_pl_clock_ms = 0;
}

static void t_pool_select_clears_new_only(void) {
    /* catches: a node list resetting every record (a refresh of one node makes all N probed again), or a new node inheriting a stale record */
    all_alive();
    g_fn[1].alive = g_fn[2].alive = 0;
    pool_new(2, POOL_BY_CONNECTION, 3);
    memset(g_probes, 0, sizeof g_probes);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(1);
    pl_note(3, 0, b);
    unsigned w = g_pl.slot[1].woke;
    static const int sel[4] = { 0, 1, 2, 3 };
    pool_select(sel, 4);
    check(g_pl.cand_n > 3 && g_pl.cand[3].fails == 0 && g_pl.cand[3].next == 0 && g_pl.cand[1].fails == 1 &&
              g_pl.cand[2].fails == 1,
          "a node list: a node new to the selection starts clean, kept ones keep their records");
    check(g_pl.slot[1].due <= b && g_pl.slot[1].woke != w, "a node list re-arms the empty slot");
    g_fn[3].alive = 0;
    tick();
    pl_check(1);
    check(g_probes[3] == 1 && g_probes[1] == 1 && g_probes[2] == 1,
          "a node list: the new node is probed, the kept ones stay in backoff");
    g_pl_clock_ms = 0;
    all_alive();
}

static void t_pool_check_pass_clears(void) {
    /* catches: a live node that passes its check keeping an old backoff, so it is skipped as a spare once its slot moves */
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 2);
    g_pl_clock_ms = CT;
    pl_note(0, 0, CT);
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.cand_n > 0 && g_pl.cand[0].fails == 0 && g_pl.cand[0].next == 0,
          "a passing check clears the node's record");
    g_pl_clock_ms = 0;
}

static void t_pool_walk_down_old_records(void) {
    /* catches: a rotation that does not start at the death, the re-arm or a node list, so failures from earlier extra rounds count and the pause doubles before every candidate was tried */
    all_alive();
    fn_alive(1, 20, 0);
    pool_new(2, POOL_BY_CONNECTION, 21);
    memset(g_probes, 0, sizeof g_probes);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(1);
    tick();
    pl_check(1);
    tick();
    pl_check(1);
    check(probes_are(1, 20, 1) && g_pl.slot[1].node == -1, "old records: the extra rounds tried all twenty");
    tick();
    g_fn[0].alive = 0;
    memset(g_probes, 0, sizeof g_probes);
    pl_check(0);
    pl_check(0);
    check(!g_pl.slot[0].up && probes_are(1, 16, 1) && probes_are(17, 20, 0) && g_pl.slot[0].retry == 15,
          "old records: the death's round probes sixteen, and failures before the death do not finish the rotation");
    pl_check(1);
    check(g_pl.slot[1].retry == 15, "old records: the re-armed slot's rotation starts at the death too");
    tick();
    pl_check(0);
    check(g_pl.slot[0].retry == 30, "old records: every candidate tried since the death, the pause doubles");
    tick();
    pool_select(g_cand, 21);
    pl_check(1);
    check(g_pl.slot[1].retry == 15, "old records: a node list starts a new rotation");
    g_pl_clock_ms = 0;
    fn_alive(0, FN_N - 1, 1);
}

static char g_reach_ok[FN_N];
static int g_reach_calls;
static size_t g_reach_n;
static int g_reach_at[FN_N];
static int f_reach(const void *const *nodes, size_t n, int t, char *ok, int *err) {
    (void)t;
    g_reach_calls++;
    g_reach_n = n;
    for (size_t k = 0; k < n; k++) {
        int i = (int)((const struct fnode *)nodes[k] - g_fn);
        if (k < FN_N) g_reach_at[k] = i;
        ok[k] = g_reach_ok[i];
        err[k] = ok[k] ? 0 : TR_ECONNREFUSED;
    }
    return 0;
}
static const struct pool_proto fr_proto = { .ops = &f_ops, .probe = f_probe, .reach = f_reach, .name = f_name };

static int reach_at_are(const int *want, size_t n) {
    if (g_reach_n != n) return 0;
    for (size_t k = 0; k < n; k++)
        if (g_reach_at[k] != want[k]) return 0;
    return 1;
}

static int fails_are(int a, int b, uint32_t n, uint64_t last) {
    if (g_pl.cand_n <= (size_t)b) return 0;
    for (int i = a; i <= b; i++)
        if (g_pl.cand[i].fails != n || g_pl.cand[i].last != last) return 0;
    return 1;
}

static void t_pool_prepass(void) {
    /* catches: unreachable candidates handshaked, a pre-pass per candidate, or a pre-pass failure not noted (it would lead every round) */
    fn_alive(0, 20, 0);
    memset(g_reach_ok, 0, sizeof g_reach_ok);
    memset(g_reach_ok + 11, 1, 10);
    g_pproto = &fr_proto;
    pool_new(1, POOL_BY_CONNECTION, 21);
    memset(g_probes, 0, sizeof g_probes);
    g_reach_calls = 0;
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(0);
    check(g_reach_calls == 0, "pre-pass: a live slot's check runs no pre-pass");
    pl_check(0);
    static const int r1[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    check(g_reach_calls == 1 && reach_at_are(r1, 16),
          "pre-pass: the death's round runs one pre-pass over its sixteen candidates in order");
    check(probes_are(1, 10, 0) && probes_are(11, 16, 1) && probes_are(17, 20, 0),
          "pre-pass: only the candidates that connected are probed");
    check(fails_are(1, 10, 1, b) && fails_are(11, 16, 1, b), "pre-pass: a candidate that did not connect is noted failed");
    tick();
    g_reach_calls = 0;
    pl_check(0);
    static const int r2[16] = { 17, 18, 19, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    check(g_reach_calls == 1 && reach_at_are(r2, 16),
          "pre-pass: the next round's pre-pass takes the untried four, then the oldest failures");
    check(probes_are(1, 10, 0) && probes_are(11, 12, 2) && probes_are(13, 20, 1),
          "pre-pass: the next round probes only the candidates that connected");
    g_pl_clock_ms = 0;
    g_pproto = &f_proto;
    fn_alive(0, FN_N - 1, 1);
}

static void t_pool_prepass_none_reached(void) {
    /* catches: a round with only pre-pass failures read as one that probed nothing, or their reason lost */
    fn_alive(0, 20, 0);
    memset(g_reach_ok, 0, sizeof g_reach_ok);
    g_pproto = &fr_proto;
    pool_new(1, POOL_BY_CONNECTION, 21);
    memset(g_probes, 0, sizeof g_probes);
    g_reach_calls = 0;
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(0);
    pl_check(0);
    check(g_reach_calls == 1 && g_reach_n == 16 && probes_are(1, 20, 0) && fails_are(1, 16, 1, b) &&
              g_pl.slot[0].due == b + 15000 && g_pl.slot[0].retry == 15,
          "pre-pass, none connects, down mode: nothing probed, sixteen noted, the pause is the retry");
    fn_alive(0, 0, 1);
    pool_new(2, POOL_BY_CONNECTION, 21);
    memset(g_probes, 0, sizeof g_probes);
    g_reach_calls = 0;
    g_pl_clock_ms = b;
    pl_check(1);
    check(g_reach_calls == 1 && g_reach_n == 8 && probes_are(1, 20, 0) && fails_are(1, 8, 1, b) &&
              g_pl.slot[1].due == b + 300000,
          "pre-pass, none connects, extra mode: the round counts eight probed and waits 5 min");
    check(!strcmp(g_pl.why, "node refused the TCP connection (nothing listens on that port)"),
          "pre-pass, none connects: the reason is the connect's own");
    g_pl_clock_ms = 0;
    g_pproto = &f_proto;
    fn_alive(0, FN_N - 1, 1);
}

static void t_pool_wake_extra(void) {
    /* catches: wake not reaching the backoff (node 3 waits 5-30 min), wake clearing every record, or wake touching a live slot */
    all_alive();
    fn_alive(1, 4, 0);
    pool_new(2, POOL_BY_CONNECTION, 5);
    memset(g_probes, 0, sizeof g_probes);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(1);
    check(probes_are(1, 4, 1) && g_pl.slot[1].node == -1 && g_pl.slot[1].due == b + 300000,
          "wake, extra mode: the round fails 1..4 and waits 5 min");
    g_fn[3].alive = 1;
    uint64_t due0 = g_pl.slot[0].due;
    unsigned gen0 = g_pl.slot[0].gen;
    static const int w[1] = { 3 };
    check(pool_wake(w, 1) == 0, "wake returns 0");
    check(g_pl.slot[1].due <= b && g_pl.slot[1].retry == 15, "wake: the empty slot searches at once, retry 15 s");
    check(g_pl.cand[3].fails == 0 && g_pl.cand[1].fails == 1 && g_pl.cand[2].fails == 1 && g_pl.cand[4].fails == 1,
          "wake: only the woken node's record is cleared");
    check(g_pl.slot[0].due == due0 && g_pl.slot[0].gen == gen0, "wake: the live slot is untouched");
    memset(g_probes, 0, sizeof g_probes);
    pl_check(1);
    check(g_pl.slot[1].up && g_pl.slot[1].node == 3 && g_probes[1] == 0 && g_probes[2] == 0 && g_probes[4] == 0,
          "wake, extra mode: the next round takes the woken node, the others stay in backoff");
    g_pl_clock_ms = 0;
    fn_alive(0, FN_N - 1, 1);
}

static void t_pool_wake_down_first(void) {
    /* catches: a woken node left behind the oldest-first queue */
    fn_alive(0, 20, 0);
    pool_new(1, POOL_BY_CONNECTION, 21);
    memset(g_probes, 0, sizeof g_probes);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    pl_check(0);
    pl_check(0);
    tick();
    pl_check(0);
    check(!g_pl.slot[0].up && probes_are(17, 20, 1) && probes_are(1, 12, 2) && probes_are(13, 16, 1),
          "wake, down mode: two rounds probe every candidate");
    g_fn[20].alive = 1;
    static const int w[1] = { 20 };
    pool_wake(w, 1);
    memset(g_probes, 0, sizeof g_probes);
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 20 && g_probes[0] == 1 && probes_are(1, 19, 0),
          "wake, down mode: the woken node is probed first, right after the own node");
    g_pl_clock_ms = 0;
    fn_alive(0, FN_N - 1, 1);
}

static void t_pool_wake_mid_round(void) {
    /* catches: the end of a round overwriting a wake fired while it ran */
    all_alive();
    fn_alive(1, 4, 0);
    pool_new(2, POOL_BY_CONNECTION, 5);
    memset(g_probes, 0, sizeof g_probes);
    uint64_t b = pl_now_ms();
    g_pl_clock_ms = b;
    g_hook_wake_node = 2;
    g_hook_wake_idx[0] = 4;
    pl_check(1);
    check(g_hook_wake_node == -1 && probes_are(1, 4, 1), "wake mid-round: fired while node 2 was probed");
    check(g_pl.slot[1].node == -1 && g_pl.slot[1].due <= b && g_pl.slot[1].retry == 15,
          "wake mid-round: the round's end keeps the wake, not its 5-min pause");
    g_hook_wake_node = -1;
    g_pl_clock_ms = 0;
    fn_alive(0, FN_N - 1, 1);
}

static int g_next_got = -2;
static void *next_thread(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_pl.mu);
    int i = pl_next();
    pthread_mutex_unlock(&g_pl.mu);
    __atomic_store_n(&g_next_got, i, __ATOMIC_RELEASE);
    return NULL;
}

static void t_pool_wake_signals(void) {
    /* catches: a wake that never signals the health thread, so the slot waits out its old due */
    all_alive();
    pool_new(2, POOL_BY_CONNECTION, 3);
    uint64_t far = pl_now_ms() + 600000;
    g_pl.slot[0].due = g_pl.slot[1].due = far;
    g_next_got = -2;
    pthread_t t;
    pthread_create(&t, NULL, next_thread, NULL);
    struct timespec ts = { 0, 100000000 };
    nanosleep(&ts, NULL);
    pool_wake(NULL, 0);
    uint64_t t0 = pl_now_ms();
    while (__atomic_load_n(&g_next_got, __ATOMIC_ACQUIRE) == -2 && pl_now_ms() - t0 < 1000) {
        struct timespec s = { 0, 5000000 };
        nanosleep(&s, NULL);
    }
    uint64_t took = pl_now_ms() - t0;
    int got = __atomic_load_n(&g_next_got, __ATOMIC_ACQUIRE);
    if (got == -2) {
        pthread_mutex_lock(&g_pl.mu);
        g_pl.slot[1].due = 0;
        pthread_cond_signal(&g_pl.cv);
        pthread_mutex_unlock(&g_pl.mu);
    }
    pthread_join(t, NULL);
    check(got == 1 && took < 100, "wake: the health thread takes the woken slot at once");
}

static void pool_part(void) {
    t_pool_setup();
    t_pool_cand_backoff();
    t_pool_cand_order_clean_is_fircd_order();
    t_pool_cand_order_extra_waits();
    t_pool_cand_order_extra_heals();
    t_pool_cand_order_down_rotates();
    t_pool_order_start();
    t_pool_stale();
    t_pool_pick();
    t_pool_refill();
    t_pool_walk_extra_capped();
    t_pool_extra_own_node_cadence();
    t_pool_walk_down_rotates();
    t_pool_walk_one_leader();
    t_pool_start_records_carry();
    t_pool_select_clears_new_only();
    t_pool_check_pass_clears();
    t_pool_walk_down_old_records();
    t_pool_prepass();
    t_pool_prepass_none_reached();
    t_pool_wake_extra();
    t_pool_wake_down_first();
    t_pool_wake_mid_round();
    t_pool_wake_signals();
    t_pool_dead_slot_refuses();
    t_pool_up_write();
    t_connq_full_cause();
    t_pool_spares();
    t_pool_kick_once();
    t_pool_unproven();
    t_pool_streak_after_check();
    t_pool_unproven_alone();
    t_pool_retry_cap();
    t_pool_log();
    t_pool_swap();
    t_pool_swap_grow();
    t_pool_swap_races();
    t_pool_swap_events();
    t_pool_threads();
    t_pin_dials_the_named_node();
    t_pin_survives_a_dead_slot();
    t_pin_never_takes_a_spare();
    pool_v6_part();
}

static struct conn *side_conn(uint16_t sport, int udp, int sock) {
    struct conn *c = conn_new(&g_tun);
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->fd = -1;
    c->cfd = -1;
    c->key = cli_key();
    c->key.sport = sport;
    c->key.proto = udp ? 17 : 6;
    c->is_udp = (uint8_t)udp;
    c->sock = (uint8_t)sock;
    c->our_seq = 5000;
    c->client_ack = 4000;
    c->client_seq = 6000;
    conn_link(c);
    return c;
}

static int stop_rsts(uint16_t dport, uint32_t *seq, uint32_t *ack, int cap, int *wrong) {
    unsigned char p[70000];
    int n = 0;
    *wrong = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) != 0) continue;
        if (k.src.v4 != SRV_IP || k.dst.v4 != CLI_IP || k.sport != SRV_PORT || k.dport != dport ||
            k.tcp_flags != (TCP_RST | TCP_ACK)) {
            (*wrong)++;
            continue;
        }
        if (n < cap) {
            seq[n] = k.seq;
            ack[n] = k.ack;
        }
        n++;
    }
    return n;
}

/* Catches: an orderly stop leaving open TUN connections hanging, an RST the client refuses (tuple or numbers), or one sent for a socket or UDP connection. */
static void t_stop_resets(void) {
    struct conn *c = open_conn(65535);
    if (!c) {
        check(0, "fixture: an open TUN connection with data in flight");
        return;
    }
    uint32_t a = c->client_ack, o = c->our_seq, q = c->client_seq;
    side_conn(40001, 0, 1);
    side_conn(40002, 1, 0);
    dev_drain(NULL);
    stop_reset(&g_tun, 0);
    uint32_t seq[4], ack[4];
    int wrong;
    int n = stop_rsts(CLI_PORT, seq, ack, 4, &wrong);
    check(a != o && n == 2 && wrong == 0 && seq[0] == a && seq[1] == o && ack[0] == q && ack[1] == q,
          "stop: RST|ACK to the TUN client at client_ack then our_seq, nothing for a socket or UDP");
    while (g_live_n) conn_drop(&g_conns[g_live[0]]);
    int before = __atomic_load_n(&g_stop_loops, __ATOMIC_ACQUIRE), mid = -1;
    struct loop L;
    if (loop_open(&L, &g_tun, 0) == 0) {
        mid = __atomic_load_n(&g_stop_loops, __ATOMIC_ACQUIRE);
        loop_close(&L);
    }
    check(mid == before + 1 && __atomic_load_n(&g_stop_loops, __ATOMIC_ACQUIRE) == before,
          "stop: an open loop is counted, a closed one no longer is");
}

static int g_stop_ms = -1;
static struct loop g_L_due;
static void *stop_thread(void *arg) {
    (void)arg;
    uint64_t t0 = now_ns();
    stack_stop(2000);
    __atomic_store_n(&g_stop_ms, (int)((now_ns() - t0) / 1000000ull), __ATOMIC_RELEASE);
    return NULL;
}

/* Catches: a stop that never wakes an idle loop, so it waits out its deadline and the RSTs never leave. */
static void t_stop_wakes_the_loop(void) {
    struct loop L;
    if (loop_open(&L, &g_tun, 0) != 0) {
        check(0, "fixture: a loop");
        return;
    }
    struct conn *c = open_conn(65535);
    if (!c) {
        check(0, "fixture: an open TUN connection with data in flight");
        loop_close(&L);
        return;
    }
    uint32_t a = c->client_ack, o = c->our_seq;
    dev_drain(NULL);
    pthread_t t;
    if (pthread_create(&t, NULL, stop_thread, NULL) != 0) {
        check(0, "fixture: a thread");
        loop_close(&L);
        return;
    }
    for (int i = 0; i < 50 && __atomic_load_n(&g_stop_ms, __ATOMIC_ACQUIRE) < 0; i++) loop_turn(&L, 100);
    pthread_join(t, NULL);
    uint64_t v;
    ssize_t rd = read(g_stop_efd, &v, sizeof v);
    (void)rd;
    uint32_t seq[4], ack[4];
    int wrong;
    int n = stop_rsts(CLI_PORT, seq, ack, 4, &wrong);
    check(g_stop_ms >= 0 && g_stop_ms < 1000 && n == 2 && seq[0] == a && seq[1] == o,
          "stop: the loop is woken, resets its TUN connection, and the stop returns at once");
    while (g_live_n) conn_drop(&g_conns[g_live[0]]);
    loop_close(&L);
}

static struct conn *due_open(struct loop *L) {
    if (loop_open(L, &g_tun, 0) != 0) return NULL;
    __atomic_store_n(&g_own_fd, 1, __ATOMIC_RELEASE);
    struct conn *c = open_conn(65535);
    __atomic_store_n(&g_own_fd, 0, __ATOMIC_RELEASE);
    if (!c) {
        loop_close(L);
        return NULL;
    }
    cli_send(1001, 1002, TCP_ACK, 65535, NULL, 0);
    flush_acks(&g_tun);
    loop_turn(L, 0);
    dev_drain(NULL);
    g_due_at = g_due_sent = 0;
    g_due_n = 0;
    g_due_rc = 0;
    return c;
}

static void due_close(struct loop *L) {
    __atomic_store_n(&g_own_fd, 1, __ATOMIC_RELEASE);
    while (g_live_n) conn_drop(&g_conns[g_live[0]]);
    __atomic_store_n(&g_own_fd, 0, __ATOMIC_RELEASE);
    loop_close(L);
    dev_drain(NULL);
    g_due_at = g_due_sent = 0;
    g_due_arm = g_due_on_read = g_due_rc = g_due_block = 0;
    g_due_n = 0;
}

static int due_calls(void) {
    int k = 0;
    for (int i = 0; i < g_due_n; i++) k += g_due_calls[i] <= g_due_sent;
    return k;
}

static void due_run(uint64_t t0, int ms) {
    while (!g_due_sent && due_mono() < t0 + (uint64_t)ms && g_live_n) loop_turn(&g_L_due, 1000);
}

/* catches: the loop sleeping its full max_ms past a mask delay, or polling due on every connection */
static void t_due_wakes_loop(void) {
    struct conn *c = due_open(&g_L_due);
    if (!c) {
        check(0, "due: fixture connection");
        return;
    }
    unsigned char d[100];
    memset(d, 'u', sizeof d);
    g_due_arm = 1;
    uint64_t t0 = due_mono();
    cli_send(1001, 1002, TCP_ACK | TCP_PSH, 65535, d, sizeof d);
    flush_acks(&g_tun);
    dev_drain(NULL);
    check(g_due_at != 0 && c->fm_wait, "due: a send that leaves a piece behind a gap flags the connection");
    due_run(t0, 300);
    check(g_due_sent && g_due_sent < t0 + 300, "due: the loop asks due again within 300 ms");
    check(g_due_sent >= g_due_target, "due: and never before the piece is due");
    check(due_calls() <= 8, "due: no polling on every turn meanwhile");
    check(!c->fm_wait, "due: the flag clears once nothing waits");
    int n = g_due_n;
    loop_turn(&g_L_due, 30);
    loop_turn(&g_L_due, 30);
    check(g_due_n == n, "due: not asked again once cleared");
    due_close(&g_L_due);
}

/* catches: an unmasked connection asking the dialer for a deadline after every send */
static void t_due_idle_latched(void) {
    g_idle = 1;
    struct conn *c = due_open(&g_L_due);
    if (!c) {
        g_idle = 0;
        check(0, "due idle: fixture connection");
        return;
    }
    unsigned char d[100];
    memset(d, 'u', sizeof d);
    g_due_n = 0;
    for (int i = 0; i < 4; i++) {
        cli_send(1001 + (uint32_t)i * 100, 1002, TCP_ACK | TCP_PSH, 65535, d, sizeof d);
        flush_acks(&g_tun);
        dev_drain(NULL);
    }
    check(c->no_due, "due idle: a session that can never be due is latched");
    check(g_due_n == 0, "due idle: and never asked");
    due_close(&g_L_due);
    g_idle = 0;
}

/* catches: the delay flag set only after sends, so a read-path write behind a gap never leaves */
static void t_due_after_read(void) {
    struct conn *c = due_open(&g_L_due);
    if (!c) {
        check(0, "due read: fixture connection");
        return;
    }
    g_recv_n = 0;
    g_due_on_read = 1;
    uint64_t one = 1;
    uint64_t t0 = due_mono();
    ssize_t w = write(c->fd, &one, sizeof one);
    check(w == (ssize_t)sizeof one, "due read: the node's socket made readable");
    due_run(t0, 300);
    check(!g_due_on_read, "due read: the read ran");
    check(g_due_sent && g_due_sent < t0 + 300 && g_due_sent >= g_due_target,
          "due read: the pong leaves within 300 ms, not before its due time");
    check(due_calls() <= 8, "due read: no polling on every turn meanwhile");
    memset(g_recv_buf, 'd', 10);
    g_recv_n = 10;
    g_due_sent = 0;
    g_due_n = 0;
    g_due_on_read = 1;
    t0 = due_mono();
    w = write(c->fd, &one, sizeof one);
    due_run(t0, 300);
    check(g_due_sent && g_due_sent < t0 + 300 && g_due_sent >= g_due_target,
          "due read: also after a read that carried data");
    check(due_calls() <= 8, "due read: and no polling then either");
    due_close(&g_L_due);
}

/* catches: a link blocked on a full socket polled with a zero wait, or never woken when it drains */
static void t_due_writable(void) {
    struct conn *c = due_open(&g_L_due);
    int sp[2];
    if (!c || socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) != 0) {
        check(0, "due writable: fixture connection");
        if (c) due_close(&g_L_due);
        return;
    }
    unsigned char fill[4096];
    memset(fill, 'f', sizeof fill);
    while (send(sp[0], fill, sizeof fill, MSG_DONTWAIT) > 0) {}
    struct vl_sess *vs = SESS(c);
    close(c->fd);
    c->fd = vs->t.link.fd = sp[0];
    c->armed = 0;
    unsigned char d[100];
    memset(d, 'u', sizeof d);
    g_due_block = 1;
    cli_send(1001, 1002, TCP_ACK | TCP_PSH, 65535, d, sizeof d);
    flush_acks(&g_tun);
    dev_drain(NULL);
    check(c->fm_wait == 2, "due writable: a link held by a full socket waits for writability");
    uint64_t t1 = due_mono();
    loop_turn(&g_L_due, 200);
    check(due_mono() - t1 >= 150, "due writable: the loop sleeps while the socket is full");
    check(!g_due_sent && (c->armed & ARM_OUT), "due writable: not kicked while full, writability watched");
    unsigned char b[65536];
    while (recv(sp[1], b, sizeof b, MSG_DONTWAIT) > 0) {}
    uint64_t drained = due_mono();
    struct epoll_event ev[8];
    int n = epoll_wait(g_L_due.ep, ev, 8, 0), out = 0;
    for (int i = 0; i < n; i++)
        if (ev[i].data.u32 == (uint32_t)(c - g_conns) && (ev[i].events & EPOLLOUT)) out = 1;
    check(out, "due writable: the drained socket wakes the loop");
    while (!g_due_sent && due_mono() < drained + 5000 && g_live_n) loop_turn(&g_L_due, 100);
    check(g_due_sent && g_due_sent >= drained, "due writable: kicked once the socket drains, not before");
    due_close(&g_L_due);
    close(sp[1]);
}

/* catches: a failed delayed write ignored */
static void t_due_fatal(void) {
    struct conn *c = due_open(&g_L_due);
    if (!c) {
        check(0, "due fatal: fixture connection");
        return;
    }
    unsigned char d[100];
    memset(d, 'u', sizeof d);
    g_due_arm = 1;
    g_due_rc = TR_EIO;
    uint64_t t0 = due_mono();
    cli_send(1001, 1002, TCP_ACK | TCP_PSH, 65535, d, sizeof d);
    flush_acks(&g_tun);
    dev_drain(NULL);
    while (g_live_n && due_mono() < t0 + 300) loop_turn(&g_L_due, 1000);
    struct flow_key k = cli_key();
    uint32_t seq[4], ack[4];
    int wrong;
    int r = stop_rsts(CLI_PORT, seq, ack, 4, &wrong);
    check(!conn_find(&k) && r >= 1, "due fatal: the flow ends with RST to the client");
    due_close(&g_L_due);
}

/* catches: the deadline checked only when the loop wakes, or a busy loop */
static void t_server_first_wakes_loop(void) {
    snprintf(g_node.flow, sizeof(g_node.flow), "xtls-rprx-vision");
    g_now_ns = now_ns();
    struct conn *c = due_open(&g_L_due);
    if (!c || c->sent_any || c->rtx.len || !c->estab_ns) {
        check(0, "server first loop: fixture silent connection");
        if (c) due_close(&g_L_due);
        g_node.flow[0] = 0;
        return;
    }
    uint64_t est = c->estab_ns;
    int calls = g_send_calls, turns = 0;
    while (g_send_calls == calls && now_ns() < est + 2000 * 1000000ull && g_live_n) {
        loop_turn(&g_L_due, 1000);
        turns++;
    }
    uint64_t at = now_ns();
    check(g_send_calls == calls + 1 && g_send_last_n == 44, "server first loop: the header alone leaves");
    check(at >= est + 500 * 1000000ull && at < est + 900 * 1000000ull,
          "server first loop: at 500 ms, not at the loop's next wake");
    check(turns <= 4, "server first loop: without spinning");
    due_close(&g_L_due);
    g_node.flow[0] = 0;
}

/* catches: a flow already due when the loop computes its sleep, left to the loop's next wake */
static void t_server_first_due_at_sleep(void) {
    snprintf(g_node.flow, sizeof(g_node.flow), "xtls-rprx-vision");
    g_now_ns = now_ns();
    struct conn *c = due_open(&g_L_due);
    if (!c || c->sent_any || c->rtx.len || !c->estab_ns) {
        check(0, "server first due: fixture silent connection");
        if (c) due_close(&g_L_due);
        g_node.flow[0] = 0;
        return;
    }
    c->estab_ns = now_ns() - 600 * 1000000ull;
    int calls = g_send_calls;
    uint64_t t = now_ns();
    loop_turn(&g_L_due, 1000);
    uint64_t took = now_ns() - t;
    check(g_send_calls == calls + 1 && g_send_last_n == 44 && took < 300 * 1000000ull,
          "server first due: a flow past its deadline sends on a turn that does not sleep");
    due_close(&g_L_due);
    g_node.flow[0] = 0;
}

/* catches: a refused deadline send that keeps the wait at 0 and spins the loop */
static void t_server_first_again_no_spin(void) {
    snprintf(g_node.flow, sizeof(g_node.flow), "xtls-rprx-vision");
    g_now_ns = now_ns();
    struct conn *c = due_open(&g_L_due);
    if (!c || c->sent_any || c->rtx.len || !c->estab_ns) {
        check(0, "server first again: fixture silent connection");
        if (c) due_close(&g_L_due);
        g_node.flow[0] = 0;
        return;
    }
    g_send_hold = 1;
    uint64_t est = c->estab_ns;
    int calls = g_send_calls;
    while (g_send_calls == calls && now_ns() < est + 2000 * 1000000ull && g_live_n) loop_turn(&g_L_due, 1000);
    check(g_send_calls > calls && !c->sent_any && c->fw_again,
          "server first again: the refused header send backs off");
    int slow = 1, flagged = 1;
    for (int i = 0; i < 5; i++) {
        uint64_t t = now_ns();
        loop_turn(&g_L_due, 200);
        if (now_ns() - t < 150 * 1000000ull) slow = 0;
        if (!c->fw_again) flagged = 0;
    }
    check(slow && flagged, "server first again: the loop sleeps while the window stays closed");
    g_send_hold = 0;
    calls = g_send_calls;
    loop_turn(&g_L_due, 200);
    int sent = g_send_calls == calls + 1 && g_send_last_n == 44 && c->sent_any && !c->fw_again;
    loop_turn(&g_L_due, 50);
    check(sent && g_send_calls == calls + 1, "server first again: the header leaves once on the next turn");
    due_close(&g_L_due);
    g_node.flow[0] = 0;
}

/* catches: room ignoring the queue, so a delayed flow buffers without limit */
static void t_room_held(void) {
    struct conn *c = open_conn(65535);
    if (!c) {
        check(0, "room held: fixture connection");
        return;
    }
    unsigned char d[100];
    memset(d, 'u', sizeof d);
    g_mask_room = 65536 - 60000;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof d);
    flush_acks(&g_tun);
    struct flow_key last;
    memset(&last, 0, sizeof last);
    dev_drain(&last);
    check(last.ack == 1101 && last.window <= 5536, "room held: 60000 queued, the window is at most 5536");
    g_mask_room = -1;
    conn_drop(c);
    dev_drain(NULL);
}

/* ---- stack --------------------------------------------------------------------------------- */

/* Catches counting moved into upstream_send or the dialer's emit path, so TUN bytes count as redirected and the card counts them twice. */
static void t_bytes_tun(void) {
    uint64_t rx0 = g_kb.rx, tx0 = g_kb.tx;
    struct conn *c = pm_open(50021, 0x0a0a0a0cu);
    if (!c) { check(0, "fixture: TUN connection did not open"); return; }
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    pm_send(50021, 0x0a0a0a0cu, 1001, c->our_seq, TCP_ACK | TCP_PSH, d, sizeof d - 1);
    int s = pm_srv_of(c);
    if (send(s, "abcdef", 6, 0) != 6) check(0, "fixture: server send failed");
    struct timespec ts = { 0, 30000000 };
    nanosleep(&ts, NULL);
    drain_conn(c, &g_tun);
    pm_drain(NULL, NULL);
    check(g_kb.rx == rx0 && g_kb.tx == tx0, "TUN traffic does not move the redirected byte counters");
}

static void t_stack_abort(void) {
    fake_new();
    unsigned fl;
    uint32_t sq;

    /* Data for a connection that does not exist. */
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    pm_send(50001, 0x0a0a0a0au, 5000, 777, TCP_ACK | TCP_PSH, d, sizeof d - 1);
    int n = pm_drain(&fl, &sq);
    check(n == 1 && (fl & TCP_RST) && sq == 777,
          "data without a connection (client restarted): RST with seq = its ack");
    pm_send(50001, 0x0a0a0a0au, 5000, 778, TCP_ACK, NULL, 0);
    n = pm_drain(&fl, &sq);
    check(n == 1 && (fl & TCP_RST) && sq == 778,
          "ACK without a connection (challenge ACK to our RST): RST with seq = its ack");
    /* With ACK, as clients usually send it: a bare RST would be left unanswered for lacking one. */
    pm_send(50001, 0x0a0a0a0au, 5000, 779, TCP_RST | TCP_ACK, NULL, 0);
    check(pm_drain(NULL, NULL) == 0, "RST without a connection: no answer");

    /* Silence threshold on the link socket. */
    struct conn *c = pm_open(50002, 0x0a0a0a0bu);
    check(c != NULL, "fixture: connection opened");
    if (!c) return;
    unsigned uto = 0;
    int ka = 0, idle = 0;
    socklen_t l = sizeof uto;
    getsockopt(c->fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &uto, &l);
    l = sizeof ka;
    getsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, &ka, &l);
    l = sizeof idle;
    getsockopt(c->fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, &l);
    check(uto == 20000 && ka == 1 && idle == 20,
          "silence 20 s: link socket has TCP_USER_TIMEOUT 20000 ms, keepalive idle 20 s");

    /* The node resets the link in the middle of a response. */
    g_lost = 0;
    int s = pm_srv_of(c);
    if (send(s, "abc", 3, 0) != 3) check(0, "fixture: server send failed");
    struct timespec ts = { 0, 30000000 };
    nanosleep(&ts, NULL);
    drain_conn(c, &g_tun);
    pm_drain(NULL, NULL);
    pm_send(50002, 0x0a0a0a0bu, 1001, c->our_seq, TCP_ACK, NULL, 0);
    pm_srv_rst(s);
    drain_conn(c, &g_tun);
    check(c->srv_closed && c->aborted, "RST from the node: link aborted, not closed");
    check(g_lost == 1, "link cut: dialer told lost");
    pm_sweep();
    n = pm_drain(&fl, NULL);
    struct flow_key k = pm_key(50002, 0x0a0a0a0bu);
    check(n == 1 && (fl & TCP_RST) && !(fl & TCP_FIN) && !conn_find(&k),
          "cut link: client gets RST, not FIN (a truncated response must not look whole)");

    /* A cut while the client has not acknowledged all it got: the seq it expects is unknown, so RST
     * with both. */
    c = pm_open(50005, 0x0a0a0a0bu);
    if (!c) { check(0, "fixture: connection for the two-RST case did not open"); return; }
    s = pm_srv_of(c);
    if (send(s, "abcdef", 6, 0) != 6) check(0, "fixture: server send failed");
    nanosleep(&ts, NULL);
    drain_conn(c, &g_tun);
    pm_drain(NULL, NULL);
    uint32_t ca = c->client_ack, os = c->our_seq;
    pm_srv_rst(s);
    drain_conn(c, &g_tun);
    pm_sweep();
    {
        unsigned char p[2048];
        uint32_t seqs[4];
        int m = 0;
        ssize_t r;
        while (m < 4 && (r = recv(g_dev_peer, p, sizeof p, MSG_DONTWAIT)) > 0) {
            struct flow_key kk;
            size_t off;
            if (ip_parse(p, (size_t)r, &kk, &off) == 0 && (kk.tcp_flags & TCP_RST)) seqs[m++] = kk.seq;
        }
        check(os == ca + 6 && m == 2 && seqs[0] == ca && seqs[1] == os,
              "cut with unacked data: RST at both the acked and the sent seq (RFC 5961)");
    }

    /* The node closes the link cleanly. */
    c = pm_open(50003, 0x0a0a0a0bu);
    if (!c) { check(0, "fixture: second connection did not open"); return; }
    s = pm_srv_of(c);
    shutdown(s, SHUT_WR);
    nanosleep(&ts, NULL);
    drain_conn(c, &g_tun);
    check(c->srv_closed && !c->aborted, "FIN from the node: closed, not aborted");
    pm_sweep();
    uint32_t fin_seq = 0;
    n = pm_drain(&fl, &fin_seq);
    check(n == 1 && (fl & TCP_FIN) && !(fl & TCP_RST), "link closed by the node: client gets FIN");
    close(s);

    /* After FIN the slot is free, but the ACK of our FIN and the client's FIN are not strangers'
     * segments (fin_recent_take): the first is taken silently, the second gets an ACK, not RST. */
    pm_send(50003, 0x0a0a0a0bu, 1001, fin_seq + 1, TCP_ACK, NULL, 0);
    check(pm_drain(NULL, NULL) == 0, "ACK of our FIN after the close: no RST");
    /* Data after our FIN cannot be delivered: RST, as the closed server would answer. Taken
     * silently, an uploading client blocked until its own timeout (sigpipe.sh). */
    pm_send(50003, 0x0a0a0a0bu, 1001, fin_seq + 1, TCP_ACK | TCP_PSH, (const unsigned char *)"more", 4);
    n = pm_drain(&fl, NULL);
    check(n == 1 && (fl & TCP_RST), "data after our FIN: RST, not silence");
    pm_send(50003, 0x0a0a0a0bu, 1001, fin_seq + 1, TCP_FIN | TCP_ACK, NULL, 0);
    {
        unsigned char p[2048];
        ssize_t r = recv(g_dev_peer, p, sizeof p, MSG_DONTWAIT);
        struct flow_key kk;
        size_t off;
        int got = r > 0 && ip_parse(p, (size_t)r, &kk, &off) == 0;
        check(got && kk.tcp_flags == TCP_ACK && kk.ack == 1002 && kk.seq == fin_seq + 1 &&
              pm_drain(NULL, NULL) == 0,
              "client's FIN after ours: ACK of its seq + 1, not RST");
    }
    pm_send(50003, 0x0a0a0a0bu, 1002, fin_seq + 1, TCP_ACK, NULL, 0);
    n = pm_drain(&fl, NULL);
    check(n == 1 && (fl & TCP_RST), "both halves closed: RST again, as to a stranger");

    /* A send to the node fails. */
    c = pm_open(50004, 0x0a0a0a0bu);
    if (!c) { check(0, "fixture: third connection did not open"); return; }
    pm_srv_rst(pm_srv_of(c));
    pm_send(50004, 0x0a0a0a0bu, 1001, 2, TCP_ACK | TCP_PSH, d, sizeof d - 1);
    n = pm_drain(&fl, NULL);
    k = pm_key(50004, 0x0a0a0a0bu);
    check((fl & TCP_RST) && !conn_find(&k), "failed send to node: client gets RST, not silence");
}

/* A fake dialer with a bounded queue (DC_ACK_PACED): the link is a SOCK_SEQPACKET pair, and its
 * other end g_hpeer is the "multiplexer", which the test drains by hand. The queue is small (16 KiB
 * send buffer, writable while at most a quarter full) so a few packets fill it. The test checks
 * what shows from outside: the ACK to the client is held while the queue is above the low mark
 * and goes out once it drains. Waiting for writability in epoll (ARM_OUT) is worker_loop's job
 * and is not covered here. */
struct hsess { int fd; };
static int g_hpeer = -1;

static const char *h_peer(const void *ctx) { (void)ctx; return "queue"; }
static void h_describe(const void *ctx, char *out, size_t n) { (void)ctx; snprintf(out, n, "queue"); }
static const char *h_strerror(int rc) { (void)rc; return "fake"; }
static int h_connect(const void *ctx, void *sess, int t) {
    (void)ctx; (void)t;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, sv) != 0) return -1;
    int sz = 16 * 1024;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    g_hpeer = sv[1];
    ((struct hsess *)sess)->fd = sv[0];
    return 0;
}
static void h_take(void *dst, void *src) { (void)dst; (void)src; }
static void h_close(void *sess) {
    struct hsess *s = sess;
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
}
static void h_clear(void *sess) { ((struct hsess *)sess)->fd = -1; }
static int h_fd(const void *sess) { return ((const struct hsess *)sess)->fd; }
static int h_has_data(const void *sess) { (void)sess; return 0; }
static int h_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)ctx; (void)sess; (void)k; (void)udp;
    return 0;
}
static int h_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                  const unsigned char *d, size_t n) {
    (void)ctx; (void)k; (void)udp;
    ssize_t w = send(((struct hsess *)sess)->fd, d, n, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (w == (ssize_t)n) return SEND_OK;
    return w < 0 && errno == EAGAIN ? SEND_AGAIN : SEND_FATAL;
}
static int h_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    ssize_t r = recv(((struct hsess *)sess)->fd, buf, cap, MSG_DONTWAIT);
    *data = buf;
    *got = r > 0 ? (size_t)r : 0;
    return 0;
}
static int h_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                     dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess; (void)udp;
    return emit(arg, d, n);
}

static const struct dialer_ops h_ops = {
    .name = "queue", .caps = DC_ACK_PACED, .rcv_wnd_max = 100000, .sess_size = sizeof(struct hsess),
    .peer = h_peer, .describe = h_describe, .strerror = h_strerror, .connect = h_connect,
    .take = h_take, .close = h_close, .clear = h_clear, .fd = h_fd, .has_data = h_has_data,
    .flow_open = h_flow_open, .send = h_send, .dgram_frame = f_dgram_frame, .read = h_read,
    .deliver = h_deliver,
};

struct csess { int fd; };
static int g_cd_rc;
static int g_cd_spare;
static int g_cd_busy;

static int cd_connect(const void *ctx, void *sess, int t) {
    (void)ctx; (void)t;
    __atomic_add_fetch(&g_cd_busy, 1, __ATOMIC_SEQ_CST);
    for (int i = 0; i < SPARE_MAX; i++)
        if (g_spares[i].sess == sess) __atomic_add_fetch(&g_cd_spare, 1, __ATOMIC_SEQ_CST);
    int rc = g_cd_rc;
    ((struct csess *)sess)->fd = rc == 0 ? 99 : -1;
    __atomic_sub_fetch(&g_cd_busy, 1, __ATOMIC_SEQ_CST);
    return rc;
}
static void cd_take(void *dst, void *src) { (void)dst; (void)src; }
static void cd_close(void *sess) { ((struct csess *)sess)->fd = -1; }
static void cd_clear(void *sess) { ((struct csess *)sess)->fd = -1; }
static int cd_fd(const void *sess) { (void)sess; return -1; }
static int cd_has_data(const void *sess) { (void)sess; return 0; }
static const struct dialer_ops cd_ops = {
    .name = "count", .caps = DC_PRECONNECT, .rcv_wnd_max = 100000, .sess_size = sizeof(struct csess),
    .peer = h_peer, .describe = h_describe, .strerror = h_strerror, .connect = cd_connect,
    .take = cd_take, .close = cd_close, .clear = cd_clear, .fd = cd_fd, .has_data = cd_has_data,
    .flow_open = h_flow_open, .send = h_send, .dgram_frame = f_dgram_frame, .read = h_read,
    .deliver = h_deliver,
};

static void cd_settle(void) {
    for (int i = 0; i < 400; i++) {
        pthread_mutex_lock(&g_cq.mu);
        int n = (int)g_cq.n;
        pthread_mutex_unlock(&g_cq.mu);
        if (!n && !__atomic_load_n(&g_cd_busy, __ATOMIC_SEQ_CST)) { usleep(20000); return; }
        usleep(5000);
    }
}

static void cd_at(uint64_t t_ms) { g_spare_clock_ns = t_ms * 1000000ull + 1000000000000ull; }

static void cd_syn(uint64_t t_ms) {
    cd_at(t_ms);
    static struct csess out;
    spare_sweep();
    if (spare_checkout(&out) == 0) cd_close(&out);
    spare_refill();
    cd_settle();
}

static void cd_reset(int rc) {
    cd_settle();
    for (int i = 0; i < SPARE_MAX; i++) g_spares[i].state = SPARE_EMPTY;
    g_spare_fail_ns = 0;
    g_spare_fail_n = 0;
    g_spare_syn_ns = 0;
    g_cd_rc = rc;
    g_cd_spare = 0;
}

static void t_spare_churn(void) {
    static struct dialer cd = { .ops = &cd_ops, .ctx = NULL };
    const struct dialer *save_dl = g_dl;
    int save_want = g_spare_want;
    g_spare_want = 4;
    stack_setup(&cd);

    cd_reset(0);
    for (int k = 0; k < 6; k++) cd_syn((uint64_t)k * 10000);
    check(g_cd_spare == 0, "spares: lone connections 10 s apart open no spare");

    g_cd_spare = 0;
    for (int k = 0; k < 5; k++) cd_syn(100000 + (uint64_t)k * 100);
    check(g_cd_spare == 7, "spares: a flow of connections fills the pool (4) and tops it up (1 per taken)");

    g_cd_spare = 0;
    cd_at(400000);
    spare_sweep();
    cd_settle();
    check(g_cd_spare == 0, "spares: no connections, no attempt to the node");

    cd_reset(-1);
    for (int k = 0; k < 120; k++) cd_syn(1000000 + (uint64_t)k * 1000);
    check(g_cd_spare == 12,
          "spares: a refusing node and a connection a second for 120 s cost 12 spare attempts (pause 40 s, then 60 s)");

    g_cd_rc = 0;
    g_cd_spare = 0;
    for (int k = 0; k < 4; k++) cd_syn(2000000 + (uint64_t)k * 100);
    check(g_cd_spare == 6, "spares: the node answers again, the pool fills");

    g_cd_rc = -1;
    for (int i = 0; i < SPARE_MAX; i++) g_spares[i].state = SPARE_EMPTY;
    g_cd_spare = 0;
    cd_syn(3000000);
    cd_syn(3000100);
    cd_syn(3045000);
    cd_syn(3045100);
    check(g_cd_spare == 8, "spares: a success clears the failures, so the next pause is 40 s again, not 60 s");

    cd_reset(-1);
    static struct conn live;
    static struct csess live_sess;
    memset(&live, 0, sizeof live);
    struct connjob j = { .c = &live, .sess = &live_sess, .sp = NULL, .efd = -1 };
    cd_at(4000000);
    check(connq_push(&j) == 0, "spares: a live connect is queued");
    cd_settle();
    cd_syn(4001000);
    cd_syn(4001100);
    check(g_cd_spare == 0, "spares: a failed live connect pauses the refill too");
    cd_syn(4006000);
    cd_syn(4006100);
    check(g_cd_spare == 4, "spares: 5 s after one failure the refill runs again");

    cd_reset(-1);
    cd_at(5000000);
    for (int i = 0; i < 5; i++) {
        connq_push(&j);
        cd_settle();
    }
    cd_syn(5061000);
    cd_syn(5061100);
    check(g_cd_spare == 4, "spares: five failures in a row pause the refill for 60 s, not longer");

    cd_reset(-1);
    cd_at(6000000);
    connq_push(&j);
    cd_settle();
    g_cd_rc = 0;
    cd_at(6001000);
    connq_push(&j);
    cd_settle();
    cd_syn(6002000);
    cd_syn(6002100);
    check(g_cd_spare == 4, "spares: a success right after a failure lifts the pause at once");

    cd_reset(0);
    g_spare_clock_ns = 0;
    g_spare_want = save_want;
    stack_setup(save_dl);
}

/* ACKs written to the device: how many, and the ack number of the last. */
static int h_acks(uint32_t *ack) {
    unsigned char p[70000];
    int cnt = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) == 0 && (k.tcp_flags & TCP_ACK)) {
            if (ack) *ack = k.ack;
            cnt++;
        }
    }
    return cnt;
}

static int h_writable(int fd) {
    struct pollfd pf = { .fd = fd, .events = POLLOUT };
    return poll(&pf, 1, 0) > 0 && (pf.revents & POLLOUT);
}

static void t_ack_paced(void) {
    static const struct dialer hd = { .ops = &h_ops, .ctx = NULL };
    while (g_conns && g_live_n) conn_drop(&g_conns[g_live[0]]);
    g_spare_want = 0;
    stack_setup(&hd);
    pm_drain(NULL, NULL);
    struct conn *c = pm_open(41000, SRV_IP);
    int ty = 0;
    socklen_t tl = sizeof ty;
    check(c && getsockopt(c->fd, SOL_SOCKET, SO_TYPE, &ty, &tl) == 0 && ty == SOCK_SEQPACKET,
          "queue: connection opened, its fd is the SEQPACKET pair");
    if (!c) return;

    /* The client's window. The stack's ceiling is megabytes (rcv_window_set), more than the
     * pair's queue holds, so the dialer names its own limit: a client with window scaling is
     * offered that, not the ceiling; without scaling, 65535 as with any dialer. */
    uint32_t save_wnd = g_rcv_wnd;
    uint8_t save_shift = g_rcv_shift;
    rcv_window_set(4u << 20);
    c->ws_on = 1;
    uint32_t seen = (uint32_t)rcv_win_field(c) << g_rcv_shift;
    check(seen >= h_ops.rcv_wnd_max && seen < h_ops.rcv_wnd_max + (1u << g_rcv_shift),
          "scaled client window: the dialer's rcv_wnd_max, not the stack's 4 MiB ceiling");
    c->ws_on = 0;
    check(rcv_win_field(c) == 65535, "  unscaled: 65535, as with any dialer");
    g_rcv_wnd = save_wnd;
    g_rcv_shift = save_shift;

    unsigned char d[1000];
    memset(d, 'x', sizeof d);
    uint32_t seq = 1001, ack = 0;

    /* Queue empty: the ACK goes at once, as with any dialer. */
    pm_send(41000, SRV_IP, seq, 2, TCP_ACK | TCP_PSH, d, sizeof d);
    seq += sizeof d;
    flush_acks(&g_tun);
    check(h_acks(&ack) == 1 && ack == seq && !c->ack_hold && !c->ack_due,
          "queue empty: data taken and acknowledged at once");

    /* Fill until the queue is above the low mark. Every packet is taken (the multiplexer drains
     * nothing), and no ACKs go between them: flush_acks sends them, and the loop calls it after a
     * batch of packets, not after each. */
    int sent = 0;
    while (h_writable(c->fd) && sent < 200) {
        pm_send(41000, SRV_IP, seq, 2, TCP_ACK | TCP_PSH, d, sizeof d);
        seq += sizeof d;
        sent++;
    }
    check(sent > 1 && sent < 200 && !h_writable(c->fd),
          "queue: not writable after a few packets (above the low mark)");
    check(c->client_seq == seq, "queue: all packets taken and passed on (client_seq moved)");

    /* Not writable: the ACK is held until the fd is writable. */
    h_acks(NULL);
    flush_acks(&g_tun);
    check(h_acks(NULL) == 0 && c->ack_hold && c->ack_due,
          "queue above the low mark: ACK held until writable");

    /* More data while the ACK is held: still no ACK (the client is bound by its window). */
    pm_send(41000, SRV_IP, seq, 2, TCP_ACK | TCP_PSH, d, sizeof d);
    seq += sizeof d;
    flush_acks(&g_tun);
    check(h_acks(NULL) == 0 && c->ack_hold, "  still held until the multiplexer drains the queue");

    /* The multiplexer drains the queue: writable, and the ACK goes out covering all data taken. */
    unsigned char sink[4096];
    while (recv(g_hpeer, sink, sizeof sink, MSG_DONTWAIT) > 0) {}
    check(h_writable(c->fd), "queue drained: writable");
    flush_acks(&g_tun);
    check(h_acks(&ack) == 1 && ack == seq && !c->ack_hold && !c->ack_due,
          "writable: ACK sent covering all data taken, no longer held");

    conn_drop(c);
    close(g_hpeer);
    g_hpeer = -1;
    pm_drain(NULL, NULL);
}

/* Link cuts, the bounded queue and the pool come after the packet checks: they set up their own
 * dialers, and the connection table lives with them from here on. */
static const unsigned char CLI6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const unsigned char SRV6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5 };

static uint32_t sum6(const unsigned char *p, size_t n) {
    size_t plen = ((size_t)p[4] << 8) | p[5];
    uint32_t s = 0;
    for (size_t i = 8; i < 40; i += 2) s += (uint32_t)(p[i] << 8 | p[i + 1]);
    s += (uint32_t)plen + p[6];
    for (size_t i = 0; i < plen && 40 + i < n; i++) s += (i & 1) ? p[40 + i] : (uint32_t)p[40 + i] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return s;
}

static int sum6_ok(const unsigned char *p, size_t n) {
    return n >= 40 && 40 + (((size_t)p[4] << 8) | p[5]) == n && sum6(p, n) == 0xffff;
}

static void p6_send(const unsigned char *src, const unsigned char *dst, uint16_t sport, uint32_t seq,
                    uint32_t ack, unsigned char flags, const unsigned char *opt, size_t opt_n,
                    const unsigned char *d, size_t n) {
    unsigned char p[2048];
    size_t l = tcp6_build(p, sizeof p, src, dst, sport, 443, seq, ack, flags, 65535, opt, opt_n, d, n);
    handle_packet(&g_tun, p, l);
    up_flush(&g_tun);
    flush_acks(&g_tun);
}

static void u6_send(const unsigned char *src, uint16_t sport, uint16_t dport, const char *d) {
    unsigned char p[256];
    size_t n = strlen(d), ul = 8 + n;
    memset(p, 0, 48);
    p[0] = 0x60;
    p[4] = (unsigned char)(ul >> 8); p[5] = (unsigned char)ul;
    p[6] = 17; p[7] = 64;
    memcpy(p + 8, src, 16);
    memcpy(p + 24, SRV6, 16);
    p[40] = (unsigned char)(sport >> 8); p[41] = (unsigned char)sport;
    p[42] = (unsigned char)(dport >> 8); p[43] = (unsigned char)dport;
    p[44] = (unsigned char)(ul >> 8); p[45] = (unsigned char)ul;
    memcpy(p + 48, d, n);
    uint16_t cs = (uint16_t)~sum6(p, 48 + n);
    p[46] = (unsigned char)(cs >> 8); p[47] = (unsigned char)cs;
    handle_packet(&g_tun, p, 48 + n);
}

static unsigned char g_pk[16][2048];
static size_t g_pk_n[16];
static struct flow_key g_pk_k[16];
static size_t g_pk_off[16];

static int dev_take(void) {
    int m = 0;
    unsigned char sink[70000];
    for (;;) {
        unsigned char *b = m < 16 ? g_pk[m] : sink;
        ssize_t r = recv(g_dev_peer, b, m < 16 ? sizeof g_pk[0] : sizeof sink, MSG_DONTWAIT);
        if (r <= 0) break;
        if (m < 16) {
            g_pk_n[m] = (size_t)r;
            if (ip_parse(b, (size_t)r, &g_pk_k[m], &g_pk_off[m]) != 0) g_pk_k[m].proto = 0;
        }
        m++;
    }
    return m;
}

static int from6(int i, const unsigned char *src, const unsigned char *dst, uint16_t cport) {
    const struct flow_key *k = &g_pk_k[i];
    return (g_pk[i][0] >> 4) == 6 && k->v6 && k->proto && !memcmp(k->src.b, src, 16) &&
           !memcmp(k->dst.b, dst, 16) && k->sport == 443 && k->dport == cport &&
           sum6_ok(g_pk[i], g_pk_n[i]);
}

static struct flow_key key6(const unsigned char *src, const unsigned char *dst, uint16_t sport) {
    struct flow_key k;
    memset(&k, 0, sizeof k);
    memcpy(k.src.b, src, 16);
    memcpy(k.dst.b, dst, 16);
    k.v6 = 1;
    k.sport = sport;
    k.dport = 443;
    k.proto = 6;
    return k;
}

static struct conn *p6_syn(const unsigned char *src, const unsigned char *dst, uint16_t sport,
                           const unsigned char *opt, size_t opt_n) {
    struct flow_key k = key6(src, dst, sport);
    p6_send(src, dst, sport, 1000, 0, TCP_SYN, opt, opt_n, NULL, 0);
    struct conn *c = conn_find(&k);
    return c && c->pending ? c : NULL;
}

static struct conn *p6_ready(struct conn *c, const unsigned char *src, const unsigned char *dst,
                             uint16_t sport) {
    struct flow_key k = key6(src, dst, sport);
    if (!c) return NULL;
    for (int i = 0; i < 3000 && !__atomic_load_n(&c->done, __ATOMIC_ACQUIRE); i++) {
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    if (!__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) || conn_ready(c, &g_tun)) return NULL;
    p6_send(src, dst, sport, 1001, 2, TCP_ACK, NULL, 0, NULL, 0);
    dev_take();
    return conn_find(&k);
}

static struct conn *p6_open(const unsigned char *src, const unsigned char *dst, uint16_t sport) {
    return p6_ready(p6_syn(src, dst, sport, NULL, 0), src, dst, sport);
}

static void settle(void) {
    struct timespec ts = { 0, 30000000 };
    nanosleep(&ts, NULL);
}

static ssize_t srv_got(int s, unsigned char *b, size_t cap) {
    settle();
    return recv(s, b, cap, MSG_DONTWAIT);
}

static void t6_end(void) {
    while (g_live_n) conn_drop(&g_conns[g_live[0]]);
    dev_take();
}

static void t6_tcp_flow(void) {
    fake_new();
    dev_take();
    struct conn *c = p6_syn(CLI6, SRV6, 51000, NULL, 0);
    int n = dev_take();
    const unsigned char *p = g_pk[0];
    static const unsigned char mss[4] = { 2, 4, 0x05, 0xa0 };
    check(n == 1 && from6(0, SRV6, CLI6, 51000) && g_pk_n[0] == 64 && p[52] == 0x60 &&
              g_pk_k[0].tcp_flags == (TCP_SYN | TCP_ACK) && g_pk_k[0].seq == 1 &&
              g_pk_k[0].ack == 1001 && !memcmp(p + 60, mss, 4),
          "v6 SYN: one v6 SYN-ACK, seq 1, ack 1001, MSS 1440 only");

    static const unsigned char ws[4] = { 1, 3, 3, 7 };
    p6_ready(c, CLI6, SRV6, 51000);
    c = p6_syn(CLI6, SRV6, 51001, ws, 4);
    n = dev_take();
    const unsigned char want[8] = { 2, 4, 0x05, 0xa0, 1, 3, 3, g_rcv_shift };
    check(n == 1 && from6(0, SRV6, CLI6, 51001) && g_pk_n[0] == 68 && p[52] == 0x70 &&
              !memcmp(p + 60, want, 8),
          "v6 SYN with window scale: SYN-ACK carries MSS 1440, NOP, our shift");
    p6_ready(c, CLI6, SRV6, 51001);

    c = p6_open(CLI6, SRV6, 51002);
    check(c != NULL, "fixture: v6 connection opened");
    if (!c) return;
    int s = pm_srv_of(c);
    static unsigned char big[3000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (unsigned char)(i * 7 + 3);
    if (send(s, big, sizeof big, 0) != (ssize_t)sizeof big) check(0, "fixture: server send failed");
    settle();
    drain_conn(c, &g_tun);
    n = dev_take();
    int ok = n > 0 && n <= 16;
    size_t at = 0, most = 0;
    for (int i = 0; ok && i < n; i++) {
        size_t dn = g_pk_n[i] - g_pk_off[i];
        ok = from6(i, SRV6, CLI6, 51002) && g_pk_k[i].proto == 6 &&
             g_pk_k[i].tcp_flags == (TCP_ACK | TCP_PSH) && g_pk_k[i].seq == 2 + at &&
             g_pk_k[i].ack == 1001 && dn <= 1440 && at + dn <= sizeof big &&
             !memcmp(g_pk[i] + g_pk_off[i], big + at, dn);
        at += dn;
        if (dn > most) most = dn;
    }
    check(ok && at == sizeof big && most == 1440,
          "v6 data from the node: v6 segments of at most 1440 bytes, seq from 2, in order");

    p6_send(CLI6, SRV6, 51002, 1001, 3002, TCP_ACK | TCP_PSH | TCP_FIN, NULL, 0,
            (const unsigned char *)"hi", 2);
    n = dev_take();
    check(n == 1 && from6(0, SRV6, CLI6, 51002) && g_pk_k[0].tcp_flags == TCP_ACK &&
              g_pk_k[0].seq == 3002 && g_pk_k[0].ack == 1004,
          "v6 data with FIN from the client: v6 ACK of both");
    unsigned char got[16];
    check(srv_got(s, got, sizeof got) == 2 && !memcmp(got, "hi", 2),
          "v6 client data before its FIN reaches the node");

    shutdown(s, SHUT_WR);
    settle();
    drain_conn(c, &g_tun);
    pm_sweep();
    n = dev_take();
    check(n == 1 && from6(0, SRV6, CLI6, 51002) && g_pk_k[0].tcp_flags == (TCP_FIN | TCP_ACK) &&
              g_pk_k[0].seq == 3002 && g_pk_k[0].ack == 1004,
          "node closes a v6 flow: v6 FIN|ACK to the client");
    close(s);
}

static void t6_trailing_bytes_not_forwarded(void) {
    fake_new();
    dev_take();
    struct conn *c = p6_open(CLI6, SRV6, 51020);
    check(c != NULL, "fixture: v6 connection for trailing bytes opened");
    if (!c) return;
    unsigned char p[2048];
    size_t l = tcp6_build(p, sizeof p, CLI6, SRV6, 51020, 443, 1001, 2, TCP_ACK | TCP_PSH, 65535, NULL, 0,
                          (const unsigned char *)"data", 4);
    memcpy(p + l, "JUNK", 4);
    handle_packet(&g_tun, p, l + 4);
    up_flush(&g_tun);
    flush_acks(&g_tun);
    int n = dev_take();
    check(n == 1 && from6(0, SRV6, CLI6, 51020) && g_pk_k[0].ack == 1005,
          "v6 bytes past the payload length: not acknowledged");
    int s = pm_srv_of(c);
    unsigned char got[16];
    check(srv_got(s, got, sizeof got) == 4 && !memcmp(got, "data", 4),
          "v6 bytes past the payload length: only the payload reaches the node");
    close(s);
}

static void t6_fin_recent(void) {
    fake_new();
    dev_take();
    struct conn *c = p6_open(CLI6, SRV6, 51010);
    check(c != NULL, "fixture: v6 connection for fin_recent opened");
    if (!c) return;
    const unsigned char d[] = "data";
    p6_send(CLI6, SRV6, 51010, 1001, 2, TCP_ACK | TCP_PSH, NULL, 0, d, 4);
    int n = dev_take();
    check(n == 1 && from6(0, SRV6, CLI6, 51010) && g_pk_k[0].tcp_flags == TCP_ACK &&
              g_pk_k[0].ack == 1005,
          "v6 client data: v6 ACK of it");
    int s = pm_srv_of(c);
    unsigned char got[16];
    check(srv_got(s, got, sizeof got) == 4 && !memcmp(got, "data", 4),
          "v6 client data reaches the node");
    shutdown(s, SHUT_WR);
    settle();
    drain_conn(c, &g_tun);
    pm_sweep();
    n = dev_take();
    uint32_t fin_seq = g_pk_k[0].seq;
    check(n == 1 && from6(0, SRV6, CLI6, 51010) && (g_pk_k[0].tcp_flags & TCP_FIN) && fin_seq == 2,
          "v6 FIN to the client after the node closed");
    close(s);

    p6_send(CLI6, SRV6, 51010, 1005, fin_seq + 1, TCP_ACK, NULL, 0, NULL, 0);
    check(dev_take() == 0, "late v6 ACK of our FIN: taken silently");
    p6_send(CLI6, SRV6, 51010, 1005, fin_seq + 1, TCP_FIN | TCP_ACK, NULL, 0, NULL, 0);
    n = dev_take();
    check(n == 1 && from6(0, SRV6, CLI6, 51010) && g_pk_n[0] == 60 &&
              g_pk_k[0].tcp_flags == TCP_ACK && g_pk_k[0].seq == fin_seq + 1 &&
              g_pk_k[0].ack == 1006,
          "v6 FIN after ours: the fin_recent ACK is v6, ack of its seq + 1");

    p6_send(CLI6, SRV6, 51999, 5000, 777, TCP_ACK, NULL, 0, NULL, 0);
    n = dev_take();
    check(n == 1 && from6(0, SRV6, CLI6, 51999) && g_pk_n[0] == 60 &&
              g_pk_k[0].tcp_flags == TCP_RST && g_pk_k[0].seq == 777,
          "stray v6 ACK: v6 RST with seq = its ack");
}

static void t6_cut_resets(void) {
    fake_new();
    dev_take();
    struct conn *c = p6_open(CLI6, SRV6, 51020);
    check(c != NULL, "fixture: v6 connection for the cut opened");
    if (!c) return;
    pm_srv_rst(pm_srv_of(c));
    drain_conn(c, &g_tun);
    pm_sweep();
    int n = dev_take();
    int ok = n >= 1 && n <= 2;
    for (int i = 0; ok && i < n; i++)
        ok = from6(i, SRV6, CLI6, 51020) && g_pk_k[i].tcp_flags == (TCP_RST | TCP_ACK) &&
             g_pk_k[i].ack == 1001;
    struct flow_key k = key6(CLI6, SRV6, 51020);
    check(ok && !conn_find(&k), "v6 link cut: the client gets a v6 RST");
}

static void t6_udp(void) {
    fake_new();
    dev_take();
    memset(&g_fopen_key, 0, sizeof g_fopen_key);
    u6_send(CLI6, 52001, 53, "ping");
    struct flow_key k = key6(CLI6, SRV6, 52001);
    k.dport = 53;
    k.proto = 17;
    struct conn *c = conn_find(&k);
    check(c && c->is_udp && g_fopen_key.v6 == 1 && g_fopen_key.proto == 17 &&
              !memcmp(g_fopen_key.dst.b, SRV6, 16) && !memcmp(g_fopen_key.src.b, CLI6, 16) &&
              g_fopen_key.dport == 53,
          "v6 datagram: the dialer opens a UDP flow with the 16-byte destination");
    if (!c) return;
    for (int i = 0; i < 3000 && !__atomic_load_n(&c->done, __ATOMIC_ACQUIRE); i++) {
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    if (!__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) || conn_ready(c, &g_tun)) {
        check(0, "fixture: v6 UDP flow did not become ready");
        return;
    }
    int s = pm_srv_of(c);
    unsigned char got[16];
    static const unsigned char framed[6] = { 0, 4, 'p', 'i', 'n', 'g' };
    check(srv_got(s, got, sizeof got) == 6 && !memcmp(got, framed, 6),
          "v6 datagram reaches the node");

    if (send(s, "pong", 4, 0) != 4) check(0, "fixture: server send failed");
    settle();
    drain_conn(c, &g_tun);
    int n = dev_take();
    const unsigned char *p = g_pk[0];
    check(n == 1 && (p[0] >> 4) == 6 && g_pk_k[0].v6 && g_pk_k[0].proto == 17 && g_pk_n[0] == 52 &&
              !memcmp(p + 8, SRV6, 16) && !memcmp(p + 24, CLI6, 16) && g_pk_k[0].sport == 53 &&
              g_pk_k[0].dport == 52001 && !memcmp(p + 48, "pong", 4) && sum6_ok(p, g_pk_n[0]),
          "reply on a v6 flow: v6 datagram to the client");

    static unsigned char big[1500];
    memset(big, 'z', sizeof big);
    if (send(s, big, sizeof big, 0) != (ssize_t)sizeof big) check(0, "fixture: server send failed");
    settle();
    drain_conn(c, &g_tun);
    check(dev_take() == 0, "1500-byte reply on a v6 flow: dropped, nothing written");
    if (send(s, "pong", 4, 0) != 4) check(0, "fixture: server send failed");
    settle();
    drain_conn(c, &g_tun);
    n = dev_take();
    check(n == 1 && g_pk_k[0].v6 && g_pk_k[0].proto == 17 && !memcmp(g_pk[0] + 48, "pong", 4) &&
              !c->srv_closed,
          "after a dropped 1500-byte reply the v6 flow still carries the next one");
    if (send(s, big, 1452, 0) != 1452) check(0, "fixture: server send failed");
    settle();
    drain_conn(c, &g_tun);
    n = dev_take();
    check(n == 1 && g_pk_n[0] == 1500 && g_pk_k[0].v6 && sum6_ok(g_pk[0], g_pk_n[0]),
          "1452-byte reply on a v6 flow: one full 1500-byte v6 packet");

    static const unsigned char odd[16] = { 0x20, 0x11, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    memset(&g_fopen_key, 0, sizeof g_fopen_key);
    u6_send(odd, 52002, 53, "ping");
    check(g_fopen_key.v6 == 1 && !memcmp(g_fopen_key.src.b, odd, 16) && g_fopen_key.sport == 52002,
          "v6 datagram whose bytes look like a v4 fragment is not taken for one");
    struct flow_key ko = key6(odd, SRV6, 52002);
    ko.dport = 53;
    ko.proto = 17;
    struct conn *co = conn_find(&ko);
    for (int i = 0; co && i < 3000 && !__atomic_load_n(&co->done, __ATOMIC_ACQUIRE); i++) {
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    if (co && conn_ready(co, &g_tun)) check(0, "fixture: the second v6 UDP flow did not open");
}

static void t6_refused_syn(void) {
    fake_new();
    dev_take();
    g_fopen_fail = 1;
    p6_send(CLI6, SRV6, 53001, 1000, 0, TCP_SYN, NULL, 0, NULL, 0);
    int n = dev_take();
    static const unsigned char want[60] = {
        0x60, 0, 0, 0, 0x00, 0x14, 0x06, 0x40,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x01, 0xbb, 0xcf, 0x09, 0, 0, 0, 0, 0x00, 0x00, 0x03, 0xe9,
        0x50, 0x14, 0x00, 0x00, 0x7f, 0xab, 0x00, 0x00,
    };
    struct flow_key k = key6(CLI6, SRV6, 53001);
    check(n == 1 && g_pk_n[0] == 60 && !memcmp(g_pk[0], want, 60) && !conn_find(&k),
          "v6 SYN the dialer refuses: one v6 RST|ACK, seq 0, ack 1001, window 0");

    pm_send(53002, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    struct flow_key k4 = pm_key(53002, SRV_IP);
    check(dev_take() == 0 && !conn_find(&k4), "v4 SYN the dialer refuses: nothing written");

    u6_send(CLI6, 53003, 53, "ping");
    check(dev_take() == 0, "v6 datagram the dialer refuses: nothing written");
    g_fopen_fail = 0;
}

static void t6_same_low_bytes(void) {
    fake_new();
    dev_take();
    unsigned char c6[16] = { 0 }, s6[16] = { 0 };
    uint32_t ci = CLI_IP, si = SRV_IP;
    memcpy(c6, &ci, 4);
    memcpy(s6, &si, 4);
    uint16_t sp = 0;
    for (uint32_t t = 1024; t < 65536 && !sp; t++) {
        struct flow_key k4 = pm_key((uint16_t)t, SRV_IP), k6 = key6(c6, s6, (uint16_t)t);
        if (flow_hash(&k4) == flow_hash(&k6)) sp = (uint16_t)t;
    }
    check(sp != 0, "fixture: a port where the v4 and the v6 key share a bucket");
    struct conn *a = pm_open(sp, SRV_IP);
    struct conn *b = p6_open(c6, s6, sp);
    check(a && b && a != b && !a->key.v6 && b->key.v6,
          "v4 and v6 SYN with the same address bytes: two connections");
    if (!a || !b) return;
    int sa = pm_srv_of(a), sb = pm_srv_of(b);
    pm_send(sp, SRV_IP, 1001, 2, TCP_ACK | TCP_PSH, (const unsigned char *)"four", 4);
    p6_send(c6, s6, sp, 1001, 2, TCP_ACK | TCP_PSH, NULL, 0, (const unsigned char *)"six!", 4);
    unsigned char ga[16], gb[16];
    ssize_t na = srv_got(sa, ga, sizeof ga), nb = recv(sb, gb, sizeof gb, MSG_DONTWAIT);
    check(na == 4 && !memcmp(ga, "four", 4) && nb == 4 && !memcmp(gb, "six!", 4),
          "same address bytes: client data goes to its own flow's node");
    dev_take();
    if (send(sa, "AAAA", 4, 0) != 4 || send(sb, "BBBB", 4, 0) != 4) check(0, "fixture: send failed");
    settle();
    drain_conn(a, &g_tun);
    drain_conn(b, &g_tun);
    int n = dev_take(), v4 = 0, v6 = 0;
    for (int i = 0; i < n && i < 16; i++) {
        const unsigned char *d = g_pk[i] + g_pk_off[i];
        size_t dn = g_pk_n[i] - g_pk_off[i];
        if ((g_pk[i][0] >> 4) == 4 && !g_pk_k[i].v6 && dn == 4 && !memcmp(d, "AAAA", 4)) v4++;
        if (from6(i, s6, c6, sp) && dn == 4 && !memcmp(d, "BBBB", 4)) v6++;
    }
    check(n == 2 && v4 == 1 && v6 == 1, "same address bytes: node data goes to its own family");

    pm_send(sp, SRV_IP, 1005, a->our_seq, TCP_ACK, NULL, 0);
    p6_send(c6, s6, sp, 1005, b->our_seq, TCP_ACK, NULL, 0, NULL, 0);
    dev_take();
    shutdown(sa, SHUT_WR);
    settle();
    drain_conn(a, &g_tun);
    pm_sweep();
    n = dev_take();
    uint32_t fin4 = g_pk_k[0].seq;
    check(n == 1 && !g_pk_k[0].v6 && (g_pk_k[0].tcp_flags & TCP_FIN),
          "same address bytes: the v4 flow closes with a v4 FIN");
    conn_drop(b);
    p6_send(c6, s6, sp, 1005, fin4 + 1, TCP_ACK, NULL, 0, NULL, 0);
    n = dev_take();
    check(n == 1 && from6(0, s6, c6, sp) && g_pk_k[0].tcp_flags == TCP_RST &&
              g_pk_k[0].seq == fin4 + 1,
          "same address bytes: a v6 ACK of the v4 FIN is a stranger's, RST");
}

static int stack_part(void) {
    signal(SIGPIPE, SIG_IGN);
    for (int i = 0; i < FN_N; i++) {
        snprintf(g_fn[i].name, sizeof g_fn[i].name, "n%d", i);
        snprintf(g_fn[i].host, sizeof g_fn[i].host, "h%d", i);
        g_fn[i].alive = 1;
    }
    g_lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET };
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof sa;
    if (g_lfd < 0 || bind(g_lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(g_lfd, 64) != 0 ||
        getsockname(g_lfd, (struct sockaddr *)&sa, &sl) != 0) return 2;
    g_lport = ntohs(sa.sin_port);
    dev_drain(NULL);
    t_stack_abort();
    t_bytes_tun();
    t_ack_paced();
    t6_tcp_flow();
    t6_end();
    t6_trailing_bytes_not_forwarded();
    t6_fin_recent();
    t6_end();
    t6_cut_resets();
    t6_end();
    t6_udp();
    t6_end();
    t6_refused_syn();
    t6_end();
    t6_same_low_bytes();
    t6_end();
    pool_part();
    return 0;
}

struct odent { uint16_t cport; uint32_t a; uint16_t p; };
static struct odent g_od[1024];
static int g_od_n;
static struct loop g_L;
static int g_kport;

int getsockopt(int fd, int level, int opt, void *val, socklen_t *len) {
    static int (*real)(int, int, int, void *, socklen_t *);
    if (!real) real = (int (*)(int, int, int, void *, socklen_t *))dlsym(RTLD_NEXT, "getsockopt");
    if (level != SOL_IP || opt != SO_ORIGINAL_DST) return real(fd, level, opt, val, len);
    struct sockaddr_in p;
    socklen_t pl = sizeof p;
    if (getpeername(fd, (struct sockaddr *)&p, &pl) == 0 && *len >= sizeof(struct sockaddr_in))
        for (int i = g_od_n - 1; i >= 0; i--) {
            if (g_od[i].cport != ntohs(p.sin_port)) continue;
            struct sockaddr_in o = { .sin_family = AF_INET, .sin_port = htons(g_od[i].p) };
            o.sin_addr.s_addr = g_od[i].a;
            memcpy(val, &o, sizeof o);
            *len = sizeof o;
            return 0;
        }
    errno = ENOENT;
    return -1;
}

static uint32_t ip4(int a, int b, int c, int d) {
    return htonl((uint32_t)a << 24 | (uint32_t)b << 16 | (uint32_t)c << 8 | (uint32_t)d);
}

static int k_sock(uint32_t a, uint16_t p, int reg) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in me = { .sin_family = AF_INET };
    me.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t ml = sizeof me;
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&me, sizeof me) != 0 ||
        getsockname(fd, (struct sockaddr *)&me, &ml) != 0) {
        close(fd);
        return -1;
    }
    if (reg && g_od_n < 1024) g_od[g_od_n++] = (struct odent){ ntohs(me.sin_port), a, p };
    return fd;
}

static int k_connect(int fd) {
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons((uint16_t)g_kport) };
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&to, sizeof to) != 0) return -1;
    return fd;
}

static int k_dial(uint32_t a, uint16_t p, int reg) {
    int fd = k_sock(a, p, reg);
    if (fd >= 0 && k_connect(fd) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void spin(int n) {
    for (int i = 0; i < n; i++) loop_turn(&g_L, 10);
}

static int k_seen(int fd) {
    char b;
    ssize_t r = recv(fd, &b, 1, MSG_DONTWAIT | MSG_PEEK);
    if (r > 0) return 'D';
    if (r == 0) return 'F';
    if (errno == ECONNRESET) return 'R';
    return errno == EAGAIN || errno == EWOULDBLOCK ? 'W' : 'E';
}

static int k_wait(int fd, int turns) {
    for (int i = 0; i < turns; i++) {
        loop_turn(&g_L, 10);
        int s = k_seen(fd);
        if (s != 'W') return s;
    }
    return 'W';
}

static struct conn *k_conn_of(int fd) {
    struct sockaddr_in me;
    socklen_t ml = sizeof me;
    if (fd < 0 || getsockname(fd, (struct sockaddr *)&me, &ml) != 0) return NULL;
    for (int li = 0; li < g_live_n; li++) {
        struct conn *c = &g_conns[g_live[li]];
        if (c->sock && c->key.sport == ntohs(me.sin_port)) return c;
    }
    return NULL;
}

static struct conn *k_ready(int fd, int turns) {
    for (int i = 0; i < turns; i++) {
        loop_turn(&g_L, 10);
        struct conn *c = k_conn_of(fd);
        if (c && !c->pending && c->fd >= 0) return c;
    }
    return NULL;
}

static void k_reset(void) {
    for (int i = 0; i < 300; i++) {
        int p = 0;
        for (int li = 0; li < g_live_n; li++) p += g_conns[g_live[li]].pending;
        if (!p) break;
        loop_turn(&g_L, 10);
    }
    while (g_park_n) sock_rst(park_take(g_park_n - 1).fd);
    while (g_live_n) conn_drop(&g_conns[g_live[0]]);
    g_od_n = 0;
    loop_turn(&g_L, 0);
}

static void k_cmd(const char *body, int close_cmd) {
    FILE *f = fmemopen((void *)body, strlen(body), "r");
    char *line = NULL;
    size_t cap = 0;
    if (!f) return;
    if (close_cmd) ctlmap_read_close(f, &line, &cap);
    else ctlmap_read_cmd(f, &line, &cap, 0);
    free(line);
    fclose(f);
}

static int g_out_save = -1, g_out_pipe[2];
static void out_start(void) {
    fflush(stdout);
    if (pipe(g_out_pipe) != 0) return;
    g_out_save = dup(1);
    dup2(g_out_pipe[1], 1);
    ctl_init(1);
}
static void out_end(char *buf, size_t cap) {
    ctl_init(0);
    dup2(g_out_save, 1);
    close(g_out_save);
    close(g_out_pipe[1]);
    ssize_t r = read(g_out_pipe[0], buf, cap - 1);
    close(g_out_pipe[0]);
    buf[r > 0 ? r : 0] = 0;
}

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

static const unsigned char g_uuid_b[16] = { 0x8f, 0x7d, 0x3b, 0x1a, 0x2c, 0x4e, 0x4f, 0x60,
                                            0x9a, 0x81, 0xb5, 0xd7, 0xe6, 0xc3, 0x01, 0x24 };

static size_t host_header(struct vl_sess *s, const char *host, int reopen, unsigned char *w, size_t cap) {
    char flow[sizeof g_node.flow];
    memcpy(flow, g_node.flow, sizeof flow);
    g_node.flow[0] = 0;
    struct flow_key k = cli_key();
    k.dst.v4 = ip4(93, 184, 216, 34);
    k.dport = 8443;
    memset(s, 0, offsetof(struct vl_sess, dg));
    s->t.link.fd = -1;
    vless_dialer.clear(s);
    vless_dialer.flow_open(&g_node, s, &k, 0);
    vless_dialer.set_host(s, host);
    if (reopen) {
        vless_dialer.clear(s);
        vless_dialer.flow_open(&g_node, s, &k, 0);
    }
    g_send_rc = 0;
    g_send_hold = 0;
    g_send_again_n = 0;
    g_wire_on = 1;
    g_wire_n = 0;
    g_wlog_n = 0;
    size_t n = 0;
    if (vless_dialer.send(&g_node, s, &k, 0, NULL, 0) == SEND_OK)
        for (int i = 0; i < g_wlog_n; i++)
            if (g_wlog[i].t == &s->t && n + g_wlog[i].n <= cap) {
                memcpy(w + n, g_wire + g_wlog[i].off, g_wlog[i].n);
                n += g_wlog[i].n;
            }
    g_wire_on = 0;
    memcpy(g_node.flow, flow, sizeof flow);
    return n;
}

/* Catches a host dropped from the request or sent with the wrong address type, length or port. */
static void t_host_is_atyp_domain(void) {
    static struct vl_sess s;
    unsigned char w[512], want[34] = { 0 };
    memcpy(want + 1, g_uuid_b, 16);
    want[17] = 0;
    want[18] = 1;
    want[19] = 0x20;
    want[20] = 0xfb;
    want[21] = 2;
    want[22] = 11;
    memcpy(want + 23, "example.com", 11);
    size_t n = host_header(&s, "example.com", 0, w, sizeof w);
    check(n == sizeof want && !memcmp(w, want, sizeof want),
          "a host goes as ATYP 2: length 11, example.com, port 8443");
}

static int ipv4_header(const unsigned char *w, size_t n) {
    static const unsigned char tail[9] = { 0, 1, 0x20, 0xfb, 1, 93, 184, 216, 34 };
    return n == 26 && w[0] == 0 && !memcmp(w + 1, g_uuid_b, 16) && !memcmp(w + 17, tail, 9);
}

/* Catches a NULL host taken as a name instead of keeping the IPv4 destination. */
static void t_no_host_stays_ipv4(void) {
    static struct vl_sess s;
    unsigned char w[512];
    size_t n = host_header(&s, NULL, 0, w, sizeof w);
    check(ipv4_header(w, n), "no host: the request carries the IPv4 93.184.216.34:8443 (ATYP 1)");
}

/* Catches a host left from a session's previous flow leaking into the next one. */
static void t_host_is_cleared_on_reuse(void) {
    static struct vl_sess s;
    unsigned char w[512];
    size_t n = host_header(&s, "example.com", 1, w, sizeof w);
    check(ipv4_header(w, n), "a reused session without a host dials the IPv4 again (ATYP 1)");
}

static const void *vl_at(int i) { return i == 3 ? &g_node : NULL; }

/* Catches the pool dropping the host, or setting it before flow_open clears it. */
static void t_pin_carries_the_host(void) {
    static const struct pool_proto vp = { .ops = &vless_dialer, .probe = f_probe, .name = f_name };
    struct pool_cfg pc = { .proto = &vp, .node = vl_at, .sel = g_cand, .sel_n = 1, .first = 3, .checked = 1,
                           .active = 1, .by = POOL_BY_CONNECTION, .interval_s = 60 };
    free(g_pl.slot);
    g_pl.slot = NULL;
    const struct dialer *d = pool_setup(&pc);
    static _Alignas(64) unsigned char buf[PL_HDR + sizeof(struct vl_sess)];
    struct vl_sess *s = (struct vl_sess *)(buf + PL_HDR);
    char flow[sizeof g_node.flow];
    memcpy(flow, g_node.flow, sizeof flow);
    g_node.flow[0] = 0;
    memset(buf, 0, sizeof buf);
    s->t.link.fd = -1;
    d->ops->clear(buf);
    struct flow_key k = cli_key();
    k.dport = 8443;
    g_send_rc = 0;
    g_send_hold = 0;
    g_send_again_n = 0;
    g_wire_on = 1;
    g_wire_n = 0;
    g_wlog_n = 0;
    int rc = pool_flow_open_on(buf, 3, &k, 0, "example.com");
    int sent = rc == 0 && d->ops->send(d->ctx, buf, &k, 0, NULL, 0) == SEND_OK;
    g_wire_on = 0;
    memcpy(g_node.flow, flow, sizeof flow);
    check(sent && g_wlog_n == 1 && g_wlog[0].t == &s->t && g_wlog[0].n == 34 && g_wire[21] == 2 &&
              g_wire[22] == 11 && !memcmp(g_wire + 23, "example.com", 11) && g_wire[19] == 0x20 &&
              g_wire[20] == 0xfb,
          "pool_flow_open_on: the pinned session's request carries the host (ATYP 2)");
    d->ops->clear(buf);
}

static void long_host(char *h, size_t n) {
    memset(h, 'a', n);
    h[n] = 0;
}

static int room_send(int vision, long *bare) {
    static struct vl_sess s;
    static unsigned char d[TUNNEL_BUF];
    char host[256], flow[sizeof g_node.flow];
    long_host(host, 255);
    memcpy(flow, g_node.flow, sizeof flow);
    if (!vision) g_node.flow[0] = 0;
    else snprintf(g_node.flow, sizeof g_node.flow, "xtls-rprx-vision");
    struct flow_key k = cli_key();
    memset(&s, 0, offsetof(struct vl_sess, dg));
    s.t.link.fd = -1;
    vless_dialer.clear(&s);
    vless_dialer.flow_open(&g_node, &s, &k, 0);
    g_room = TUNNEL_BUF;
    if (bare) *bare = vless_dialer.room(&g_node, &s);
    vless_dialer.set_host(&s, host);
    long r = vless_dialer.room(&g_node, &s);
    g_send_rc = 0;
    g_send_hold = 0;
    g_send_again_n = 0;
    g_wire_on = 0;
    int sr = r > 0 ? vless_dialer.send(&g_node, &s, &k, 0, d, (size_t)r) : SEND_FATAL;
    g_room = -1;
    memcpy(g_node.flow, flow, sizeof flow);
    return sr;
}

static void t_room_vision_reserve(void) {
    /* catches: the Vision reserve kept after padding ends, or dropped while Vision pads */
    static struct vl_sess s;
    struct flow_key k = cli_key();
    snprintf(g_node.flow, sizeof g_node.flow, "xtls-rprx-vision");
    memset(&s, 0, offsetof(struct vl_sess, dg));
    s.t.link.fd = -1;
    vless_dialer.clear(&s);
    vless_dialer.flow_open(&g_node, &s, &k, 0);
    g_room = TUNNEL_BUF;
    long padding = vless_dialer.room(&g_node, &s);
    s.vis.is_padding = 0;
    long over = vless_dialer.room(&g_node, &s);
    g_room = -1;
    g_node.flow[0] = 0;
    check(padding == TUNNEL_BUF - 64 - 2048 && over == TUNNEL_BUF - 64,
          "room, Vision: 2048 reserved while padding, none after");
}

/* Catches a room that reserves 64 bytes for a request header that carries a 255-byte host. */
static void t_room_covers_a_long_host(void) {
    long bare = 0;
    check(room_send(0, &bare) == SEND_OK && bare == TUNNEL_BUF - 64,
          "a first write of the whole room with a 255-byte host is sent; no host keeps 64");
    check(room_send(1, &bare) == SEND_OK && bare == TUNNEL_BUF - 64 - 2048,
          "  and with Vision too, 2048 more kept");
}

/* Catches a host over 255 bytes cut to fit instead of refused, at the dialer and the pool. */
static void t_long_host_refused(void) {
    static struct vl_sess s;
    char h255[256], h256[257];
    long_host(h255, 255);
    long_host(h256, 256);
    memset(&s, 0, offsetof(struct vl_sess, dg));
    s.t.link.fd = -1;
    vless_dialer.clear(&s);
    check(vless_dialer.set_host(&s, h256) == -1 && vless_dialer.set_host(&s, h255) == 0 &&
              strlen(s.host) == 255,
          "set_host: 256 bytes refused, 255 kept whole");
    static const struct pool_proto vp = { .ops = &vless_dialer, .probe = f_probe, .name = f_name };
    struct pool_cfg pc = { .proto = &vp, .node = vl_at, .sel = g_cand, .sel_n = 1, .first = 3, .checked = 1,
                           .active = 1, .by = POOL_BY_CONNECTION, .interval_s = 60 };
    free(g_pl.slot);
    g_pl.slot = NULL;
    const struct dialer *d = pool_setup(&pc);
    static _Alignas(64) unsigned char buf[PL_HDR + sizeof(struct vl_sess)];
    memset(buf, 0, sizeof buf);
    ((struct vl_sess *)(buf + PL_HDR))->t.link.fd = -1;
    d->ops->clear(buf);
    struct flow_key k = cli_key();
    int over = pool_flow_open_on(buf, 3, &k, 0, h256);
    d->ops->clear(buf);
    int fits = pool_flow_open_on(buf, 3, &k, 0, h255);
    d->ops->clear(buf);
    check(over == -1 && fits == 0, "pool_flow_open_on: a 256-byte host fails the open, 255 opens");
}

/* Catches a host dropped in silence when the inner dialer cannot carry one. */
static void t_host_needs_set_host(void) {
    static struct dialer_ops bare;
    bare = f_ops;
    bare.set_host = NULL;
    static const struct pool_proto bp = { .ops = &bare, .probe = f_probe, .name = f_name };
    struct pool_cfg pc = { .proto = &bp, .node = f_at, .sel = g_cand, .sel_n = 3, .first = 0, .checked = 1,
                           .active = 1, .by = POOL_BY_CONNECTION, .interval_s = 60 };
    free(g_pl.slot);
    g_pl.slot = NULL;
    const struct dialer *d = pool_setup(&pc);
    static _Alignas(64) unsigned char buf[PL_HDR + sizeof(struct fsess)];
    struct flow_key k = cli_key();
    d->ops->clear(buf);
    int named = pool_flow_open_on(buf, 1, &k, 0, "example.com");
    d->ops->clear(buf);
    int none = pool_flow_open_on(buf, 1, &k, 0, NULL);
    d->ops->clear(buf);
    int empty = pool_flow_open_on(buf, 1, &k, 0, "");
    d->ops->clear(buf);
    check(named == -1 && none == 0 && empty == 0,
          "a dialer without set_host: a named open fails, an address-only open goes");
}

static size_t wire_of(const struct conn *c, unsigned char *out, size_t cap) {
    const struct transport *t = &((const struct vl_sess *)SESS(c))->t;
    size_t n = 0;
    for (int i = 0; i < g_wlog_n; i++) {
        if (g_wlog[i].t != t || n + g_wlog[i].n > cap) continue;
        memcpy(out + n, g_wire + g_wlog[i].off, g_wlog[i].n);
        n += g_wlog[i].n;
    }
    return n;
}

static int header_is(const unsigned char *w, size_t n, uint32_t a, uint16_t p) {
    const unsigned char *q = (const unsigned char *)&a;
    return n >= 26 && w[0] == 0 && w[17] == 0 && w[18] == 1 && w[19] == (p >> 8) && w[20] == (p & 255) &&
           w[21] == 1 && !memcmp(w + 22, q, 4);
}

static void k_vless(void) {
    k_reset();
    g_miss.since = now_ns();
    __atomic_store_n(&g_own_fd, 1, __ATOMIC_RELEASE);
    g_spare_want = 0;
    stack_setup(&g_dial);
    g_recv_rc = 0;
    g_recv_n = 0;
    g_room = -1;
    g_send_rc = 0;
    g_send_again_n = 0;
    g_send_hold = 0;
    g_wire_on = 1;
    g_wire_n = 0;
    g_wlog_n = 0;
}

static void k_fake(void) {
    k_reset();
    fake_new();
    all_alive();
}

static unsigned char pat(size_t i) { return (unsigned char)(i * 7 + i / 251); }

#define FAKE(x) ip4(198, 18, 0, x)

/* Catches serving the open port: a connection with no original destination must be reset. */
static void t_k_direct(void) {
    k_vless();
    int fd = k_dial(0, 0, 0);
    check(fd >= 0 && k_wait(fd, 50) == 'R' && g_live_n == 0 && g_park_n == 0,
          "a direct connection is reset (no original destination)");
    if (fd >= 0) close(fd);
}

/* Catches a loop through the listener: its own address and port as the destination is reset. */
static void t_k_listener_itself(void) {
    k_vless();
    int fd = k_dial(htonl(INADDR_LOOPBACK), (uint16_t)g_kport, 1);
    check(fd >= 0 && k_wait(fd, 50) == 'R' && g_live_n == 0 && g_park_n == 0,
          "the listener itself as the destination is reset");
    if (fd >= 0) close(fd);
}

/* Catches dialling the fake address: the node must be asked for the mapped real one. */
static void t_k_mapped(void) {
    k_vless();
    k_cmd("198.18.0.10 10.1.2.3\n\n", 0);
    unsigned miss0 = g_miss.miss;
    int fd = k_dial(FAKE(10), 443, 1);
    struct conn *c = k_ready(fd, 200);
    if (fd >= 0 && send(fd, "hello", 5, 0) != 5) check(0, "fixture: client send failed");
    static unsigned char w[4096];
    size_t n = 0;
    for (int i = 0; c && i < 100 && n < 31; i++) {
        spin(1);
        n = wire_of(c, w, sizeof w);
    }
    check(c && c->odst == FAKE(10) && c->key.dst.v4 == ip4(10, 1, 2, 3) && n == 31 && g_miss.miss == miss0 &&
              header_is(w, n, ip4(10, 1, 2, 3), 443) && !memcmp(w + 26, "hello", 5),
          "a mapped fake dials the real address (VLESS header carries 10.1.2.3:443)");
    if (fd >= 0) close(fd);
}

/* Catches a destination outside the pool being parked or rewritten instead of dialled as is. */
static void t_k_real(void) {
    k_vless();
    int fd = k_dial(ip4(93, 184, 216, 34), 80, 1);
    struct conn *c = k_ready(fd, 200);
    static unsigned char w[4096];
    int nd = 0;
    socklen_t nl = sizeof nd;
    if (c) getsockopt(c->cfd, IPPROTO_TCP, TCP_NODELAY, &nd, &nl);
    check(c && nd == 1, "an accepted socket has TCP_NODELAY");
    uint64_t t0 = now_ns();
    while (c && (now_ns() - t0) / 1000000 < SERVER_FIRST_MS + 50) spin(1);
    size_t n = c ? wire_of(c, w, sizeof w) : 0;
    check(n == 26 && header_is(w, n, ip4(93, 184, 216, 34), 80),
          "a silent client: the header goes alone after 100 ms (server speaks first)");
    if (fd >= 0 && send(fd, "GET", 3, 0) != 3) check(0, "fixture: client send failed");
    for (int i = 0; c && i < 100 && n < 29; i++) {
        spin(1);
        n = wire_of(c, w, sizeof w);
    }
    check(c && n == 29 && header_is(w, n, ip4(93, 184, 216, 34), 80) && !memcmp(w + 26, "GET", 3),
          "a real destination dials as is (93.184.216.34:80)");
    if (fd >= 0) close(fd);
}

/* Catches a client read past the node's room, and a socket connection woken by room_watch onto the TUN. */
static void t_k_room(void) {
    k_vless();
    int fd = k_dial(ip4(93, 184, 216, 41), 443, 1);
    struct conn *c = k_ready(fd, 200);
    g_room = 64;
    static unsigned char d[100];
    memset(d, 'r', sizeof d);
    if (fd >= 0 && send(fd, d, sizeof d, 0) != (ssize_t)sizeof d) check(0, "fixture: client send failed");
    uint64_t t0 = now_ns();
    loop_turn(&g_L, 50);
    uint64_t ms = (now_ns() - t0) / 1000000;
    int none = g_wlog_n == 0 && ms >= 40;
    g_room = 74;
    spin(3);
    int first = g_wlog_n >= 1 ? (int)g_wlog[0].n : -1;
    dev_drain(NULL);
    g_room = 1 << 20;
    spin(5);
    unsigned char w[256];
    size_t n = c ? wire_of(c, w, sizeof w) : 0;
    check(none && first == 36 && n == 126 && dev_drain(NULL) == 0,
          "the node's room bounds the client read (0: none, 10: 10 bytes), nothing on the TUN");
    g_room = -1;
    if (fd >= 0) close(fd);
}

/* catches: data a transport took off the socket outside a read left waiting for a socket event */
static void t_k_held_data(void) {
    k_vless();
    int fd = k_dial(ip4(93, 184, 216, 42), 443, 1);
    struct conn *c = k_ready(fd, 200);
    if (fd >= 0 && send(fd, "GET", 3, 0) != 3) check(0, "fixture: client send failed");
    unsigned char w[64];
    size_t n = 0;
    for (int i = 0; c && i < 100 && n < 29; i++) {
        spin(1);
        n = wire_of(c, w, sizeof w);
    }
    g_recv_buf[0] = 0;
    g_recv_buf[1] = 0;
    memcpy(g_recv_buf + 2, "pong", 4);
    g_recv_n = 6;
    g_held_on = 1;
    char b[8] = { 0 };
    int seen = k_wait(fd, 20);
    ssize_t r = seen == 'D' ? recv(fd, b, sizeof b, MSG_DONTWAIT) : -1;
    g_held_on = 0;
    check(c && n == 29 && r == 4 && !memcmp(b, "pong", 4),
          "data the transport holds goes to the client without a socket event");
    if (fd >= 0) close(fd);
}

/* Catches an evicted socket connection reset on the TUN instead of on its socket. */
static void t_k_evict(void) {
    k_vless();
    int a = k_dial(ip4(93, 184, 216, 42), 443, 1);
    struct conn *ca = k_ready(a, 200);
    if (ca) ca->last = g_now_s - IDLE_EVICT_S - 5;
    dev_drain(NULL);
    int n0 = g_free_n;
    uint16_t f0 = g_freelist[0];
    g_free_n = 0;
    int b = k_dial(ip4(93, 184, 216, 43), 443, 1);
    for (int i = 0; i < 20 && !k_conn_of(b); i++) loop_turn(&g_L, 10);
    struct conn *cb = k_conn_of(b);
    g_freelist[0] = f0;
    g_free_n = n0;
    check(ca && cb && cb == ca && k_wait(a, 5) == 'R' && dev_drain(NULL) == 0,
          "an evicted socket connection is reset on its socket, nothing on the TUN");
    if (a >= 0) close(a);
    if (b >= 0) close(b);
}

/* Catches the client's first bytes left unread when the connector reports, so the header goes alone. */
static void t_k_spoke_early(void) {
    k_vless();
    __atomic_store_n(&g_connect_ms, 150, __ATOMIC_RELEASE);
    int fd = k_dial(ip4(93, 184, 216, 39), 443, 1);
    if (fd >= 0 && send(fd, "hi", 2, 0) != 2) check(0, "fixture: client send failed");
    struct conn *c = k_ready(fd, 200);
    __atomic_store_n(&g_connect_ms, 0, __ATOMIC_RELEASE);
    spin(2);
    const struct transport *t = c ? &((const struct vl_sess *)SESS(c))->t : NULL;
    int first = -1;
    for (int i = 0; t && i < g_wlog_n && first < 0; i++)
        if (g_wlog[i].t == t) first = i;
    check(first >= 0 && g_wlog[first].n == 28 && !memcmp(g_wire + g_wlog[first].off + 26, "hi", 2),
          "bytes sent during the handshake go with the header");
    if (fd >= 0) close(fd);
}

/* Catches a half-closed client left armed: its end of stream would wake the loop every turn. */
static void t_k_half_close(void) {
    k_vless();
    int fd = k_dial(ip4(93, 184, 216, 40), 443, 1);
    struct conn *c = k_ready(fd, 200);
    if (fd >= 0) shutdown(fd, SHUT_WR);
    spin(3);
    uint64_t t0 = now_ns();
    loop_turn(&g_L, 50);
    uint64_t ms = (now_ns() - t0) / 1000000;
    check(c && k_conn_of(fd) == c && c->client_fin && !(c->carmed & ARM_IN) && ms >= 40,
          "a client half-close stops reading it, the connection stays");
    if (fd >= 0) close(fd);
}

/* Catches the prototype's handshake per flow (+110 ms): a ready spare is taken at accept. */
static void t_k_spare(void) {
    k_vless();
    void *old = g_spares[0].sess;
    g_spare_want = 1;
    stack_setup(&g_dial);
    free(old);
    g_spare_syn_ns = 0;
    spare_refill();
    spare_refill();
    int ready = 0;
    for (int i = 0; i < 500 && !ready; i++) {
        pthread_mutex_lock(&g_spare_mu);
        ready = g_spares[0].state == SPARE_READY;
        pthread_mutex_unlock(&g_spare_mu);
        if (!ready) usleep(2000);
    }
    check(ready, "fixture: one spare session is ready");
    int fd = k_dial(ip4(93, 184, 216, 35), 443, 1);
    struct conn *c = NULL;
    for (int i = 0; i < 50 && !c; i++) {
        loop_turn(&g_L, 10);
        c = k_conn_of(fd);
    }
    check(c && !c->pending && c->fd >= 0, "a new connection takes a spare (no connector job)");
    if (fd >= 0) close(fd);
    k_reset();
    for (int i = 0, filling = 1; i < 500 && filling; i++) {
        filling = 0;
        pthread_mutex_lock(&g_spare_mu);
        for (int j = 0; j < SPARE_MAX; j++) filling |= g_spares[j].state == SPARE_FILLING;
        pthread_mutex_unlock(&g_spare_mu);
        if (filling) usleep(2000);
    }
    g_spare_want = 0;
    stack_setup(&g_dial);
}

/* Catches a miss emitted per socket instead of once per fake. */
static void t_k_ask_once(int *a, int *b) {
    k_vless();
    char out[4096];
    out_start();
    *a = k_dial(FAKE(20), 443, 1);
    *b = k_dial(FAKE(20), 443, 1);
    spin(5);
    out_end(out, sizeof out);
    check(*a >= 0 && *b >= 0 && g_park_n == 2 && count_of(out, "\"miss\"") == 1 &&
              strstr(out, "{\"type\":\"miss\",\"fake\":\"198.18.0.20\"}") != NULL,
          "two accepts to one unmapped fake: both parked, one miss asked");
}

/* Catches fail-open and an ask let go while a parked socket still waits for it. */
static void t_k_answer(int a, int b) {
    k_cmd("198.18.0.20 10.9.9.9\n\n", 0);
    for (int i = 0; i < 10 && g_park_n; i++) spin(1);
    struct conn *ca = k_conn_of(a), *cb = k_conn_of(b);
    struct cm_real r;
    check(!g_park_n && ca && cb && ca->key.dst.v4 == ip4(10, 9, 9, 9) && cb->key.dst.v4 == ip4(10, 9, 9, 9) &&
              ca->odst == FAKE(20) && k_seen(a) == 'W' && k_seen(b) == 'W' &&
              ctlmap_answer(FAKE(20), &r) == CM_NONE,
          "an answer opens both parked connections and the ask is let go after the last");
    if (a >= 0) close(a);
    if (b >= 0) close(b);
}

/* Catches a dash read as "no answer yet": the parked socket must go at once, not at the deadline. */
static void t_k_dash(void) {
    k_vless();
    int fd = k_dial(FAKE(21), 443, 1);
    for (int i = 0; i < 10 && !g_park_n; i++) spin(1);
    if (g_park_n) g_park[0].at -= 50000000ull;
    unsigned ans = g_miss.answered, tmo = g_miss.timed_out;
    uint64_t t0 = now_ns();
    k_cmd("198.18.0.21 -\n\n", 0);
    int s = k_wait(fd, 40);
    uint64_t ms = (now_ns() - t0) / 1000000;
    check(g_park_n == 0 && s == 'R' && ms < 150, "a dash resets the parked connection at once");
    check(g_miss.answered == ans + 1 && g_miss.timed_out == tmo && g_miss.max_ms >= 50,
          "  counted as answered, its wait in the max");
    if (fd >= 0) close(fd);
}

/* Catches a miss that never times out, or a loop that sleeps through the 300 ms deadline. */
static void t_k_deadline(void) {
    k_vless();
    uint64_t t0 = now_ns();
    int fd = k_dial(FAKE(22), 443, 1);
    for (int i = 0; i < 10 && !g_park_n; i++) spin(1);
    unsigned ans = g_miss.answered, tmo = g_miss.timed_out;
    while ((now_ns() - t0) / 1000000 < 250) spin(1);
    int early = k_seen(fd) == 'W' && g_park_n == 1;
    uint64_t t1 = now_ns();
    for (int i = 0; i < 3 && g_park_n; i++) loop_turn(&g_L, 1000);
    uint64_t ms = (now_ns() - t1) / 1000000;
    check(early && g_park_n == 0 && k_wait(fd, 3) == 'R' && ms < 400,
          "300 ms without an answer resets it (not before, and the loop wakes for it)");
    check(g_miss.timed_out == tmo + 1 && g_miss.answered == ans, "  counted as timed out");
    if (fd >= 0) close(fd);
}

/* Catches an unbounded parked set: past 256 the socket is reset at once. */
static void t_k_park_cap(void) {
    k_vless();
    static int fds[PARK_MAX + 1];
    int ok = 1;
    for (int i = 0; i < PARK_MAX; i++) {
        fds[i] = k_dial(FAKE(23), 443, 1);
        if (fds[i] < 0) ok = 0;
        if (i % 32 == 31) {
            spin(1);
            for (int j = 0; j < g_park_n; j++) g_park[j].at = now_ns();
        }
    }
    for (int i = 0; i < 20 && g_park_n < PARK_MAX; i++) {
        spin(1);
        for (int j = 0; j < g_park_n; j++) g_park[j].at = now_ns();
    }
    check(ok && g_park_n == PARK_MAX, "fixture: 256 connections parked");
    fds[PARK_MAX] = k_dial(FAKE(23), 443, 1);
    int s = k_wait(fds[PARK_MAX], 10);
    check(s == 'R' && g_park_n == PARK_MAX && k_seen(fds[0]) == 'W' && k_seen(fds[PARK_MAX - 1]) == 'W',
          "the 257th parked is reset at once, the 256 stay parked");
    k_cmd("198.18.0.23 -\n\n", 0);
    spin(3);
    for (int i = 0; i <= PARK_MAX; i++)
        if (fds[i] >= 0) close(fds[i]);
}

/* Catches a read past EARLY_CAP - early_n (bytes lost) and a read while early holds a byte (bytes swapped). */
static void t_k_send_again(void) {
    static unsigned char buf[40960], w[64 * 1024];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = pat(i);
    k_vless();
    int fd = k_dial(ip4(93, 184, 216, 36), 443, 1);
    struct conn *c = k_ready(fd, 200);
    g_send_hold = 1;
    if (fd >= 0 && send(fd, buf, sizeof buf, 0) != (ssize_t)sizeof buf) check(0, "fixture: client send failed");
    spin(20);
    int unread = -1;
    if (c) ioctl(c->cfd, FIONREAD, &unread);
    check(c && c->used && c->sock && !c->aborted && c->early_n == EARLY_CAP && unread == 40960 - EARLY_CAP,
          "SEND_AGAIN: one read of 8192 held, the client is not read further");
    g_send_hold = 0;
    size_t n = 0;
    for (int i = 0; c && i < 300 && n < 26 + sizeof buf; i++) {
        spin(1);
        n = wire_of(c, w, sizeof w);
    }
    check(n == 26 + sizeof buf && !memcmp(w + 26, buf, sizeof buf),
          "SEND_AGAIN released: the node received all 40 KB in order");
    if (fd >= 0) close(fd);

    k_vless();
    fd = k_dial(ip4(93, 184, 216, 37), 443, 1);
    c = k_ready(fd, 200);
    g_send_hold = 1;
    if (fd >= 0 && send(fd, buf, 3000, 0) != 3000) check(0, "fixture: client send failed");
    spin(10);
    int held = c && c->early_n == 3000;
    if (fd >= 0 && send(fd, buf + 3000, sizeof buf - 3000, 0) != (ssize_t)(sizeof buf - 3000))
        check(0, "fixture: client send failed");
    spin(5);
    unread = -1;
    if (c) ioctl(c->cfd, FIONREAD, &unread);
    uint64_t t0 = now_ns();
    loop_turn(&g_L, 50);
    uint64_t ms = (now_ns() - t0) / 1000000;
    check(held && unread == (int)sizeof buf - 3000 && ms >= 40,
          "SEND_AGAIN: no read while early holds a byte, and no wake for the waiting bytes");
    g_send_hold = 0;
    n = 0;
    for (int i = 0; c && i < 300 && n < 26 + sizeof buf; i++) {
        spin(1);
        n = wire_of(c, w, sizeof w);
    }
    check(n == 26 + sizeof buf && !memcmp(w + 26, buf, sizeof buf),
          "SEND_AGAIN released: the held 3000 bytes go before the rest");
    if (fd >= 0) close(fd);
}

/* Catches a listener left disarmed past the next turn, or never disarmed (a spinning loop). */
static void t_k_fd_table(void) {
    k_vless();
    struct rlimit save, rl;
    getrlimit(RLIMIT_NOFILE, &save);
    rl = save;
    rl.rlim_cur = 908;
    setrlimit(RLIMIT_NOFILE, &rl);
    park_cap_init();
    int cap100 = g_park_cap;
    rl.rlim_cur = 808;
    setrlimit(RLIMIT_NOFILE, &rl);
    park_cap_init();
    int cap0 = g_park_cap;
    setrlimit(RLIMIT_NOFILE, &save);
    park_cap_init();
    check(cap100 == 100 && cap0 == 0 && g_park_cap == PARK_MAX, "the parked cap follows the fd limit");

    int fd = k_sock(ip4(93, 184, 216, 38), 443, 1);
    int top = open("/dev/null", O_RDONLY);
    static int fill[256];
    int nf = 0;
    rl = save;
    rl.rlim_cur = (rlim_t)top + 8;
    setrlimit(RLIMIT_NOFILE, &rl);
    int x;
    while (nf < 256 && (x = open("/dev/null", O_RDONLY)) >= 0) fill[nf++] = x;
    k_connect(fd);
    for (int i = 0; i < 3; i++) loop_turn(&g_L, 0);
    int off = g_L.lst_off;
    uint64_t t0 = now_ns();
    loop_turn(&g_L, 1000);
    uint64_t ms = (now_ns() - t0) / 1000000;
    check(off && g_L.lst_off && ms >= 5 && !k_conn_of(fd), "EMFILE disarms the listener, the loop does not spin");
    for (int i = 0; i < 4 && nf; i++) close(fill[--nf]);
    t0 = now_ns();
    loop_turn(&g_L, 1000);
    ms = (now_ns() - t0) / 1000000;
    check(k_conn_of(fd) != NULL && !g_L.lst_off && ms < 100,
          "a full fd table does not stop accepting: an idle loop accepts within 100 ms");
    setrlimit(RLIMIT_NOFILE, &save);
    while (nf) close(fill[--nf]);
    close(top);
    if (fd >= 0) close(fd);
}

/* Catches unbounded buffering: a client that does not read must stop the reads from the node. */
static void t_k_full_client(void) {
    static unsigned char big[1 << 20], got[1 << 20];
    for (size_t i = 0; i < sizeof big; i++) big[i] = pat(i);
    k_fake();
    int fd = k_sock(ip4(10, 0, 0, 9), 443, 1);
    int small = 4096;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    k_connect(fd);
    struct conn *c = k_ready(fd, 300);
    if (!c) { check(0, "fixture: full-client connection did not open"); close(fd); return; }
    setsockopt(c->cfd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    int s = pm_srv_of(c);
    fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
    size_t off = 0;
    uint64_t rx0 = g_rx_total;
    for (int i = 0; i < 300; i++) {
        ssize_t w = send(s, big + off, sizeof big - off, MSG_DONTWAIT);
        if (w > 0) off += (size_t)w;
        loop_turn(&g_L, 2);
    }
    int left = 0;
    ioctl(c->fd, FIONREAD, &left);
    check(k_conn_of(fd) == c && !c->aborted && c->rtx.len > 0 && c->rtx.len <= RTX_CAP &&
              !(c->armed & ARM_IN) && left > 0 && g_rx_total - rx0 < 128 * 1024,
          "a full client socket stops reading the node (tail held, node not armed)");
    size_t rx = 0;
    for (int i = 0; i < 20000 && rx < sizeof big; i++) {
        if (off < sizeof big) {
            ssize_t w = send(s, big + off, sizeof big - off, MSG_DONTWAIT);
            if (w > 0) off += (size_t)w;
        }
        loop_turn(&g_L, 1);
        ssize_t r = recv(fd, got + rx, sizeof got - rx, MSG_DONTWAIT);
        if (r > 0) rx += (size_t)r;
    }
    check(rx == sizeof big && !memcmp(got, big, sizeof big), "  then the client gets all of it, in order");
    close(fd);
}

/* Catches a close that resets outside its prefixes, skips parked sockets or miscounts. */
static void t_k_close(void) {
    k_vless();
    k_cmd("198.18.4.1 10.4.4.1\n198.18.5.1 10.5.5.1\n\n", 0);
    int a = k_dial(ip4(198, 18, 4, 1), 443, 1);
    int b = k_dial(ip4(198, 18, 5, 1), 443, 1);
    int d = k_dial(ip4(10, 0, 0, 7), 443, 1);
    int p = k_dial(ip4(198, 18, 4, 9), 443, 1);
    struct conn *ca = k_ready(a, 200), *cb = k_ready(b, 200), *cd = k_ready(d, 200);
    check(ca && cb && cd && g_park_n == 1, "fixture: three open, one parked");
    char out[4096];
    out_start();
    for (int j = 0; j < g_park_n; j++) g_park[j].at = now_ns();
    k_cmd("198.18.4.0/24\n10.0.0.0/8\n\n", 1);
    spin(3);
    out_end(out, sizeof out);
    check(strstr(out, "{\"type\":\"close\",\"count\":3}") != NULL && k_wait(a, 5) == 'R' &&
              k_wait(d, 5) == 'R' && k_wait(p, 5) == 'R' && k_seen(b) == 'W' && k_conn_of(b) == cb &&
              g_park_n == 0 && ctlmap_answer(ip4(198, 18, 4, 9), &(struct cm_real){ { 0 }, 0 }) == CM_NONE,
          "close resets only inside the prefixes and counts them (3)");
    close(a); close(b); close(d); close(p);
}

/* Catches: two close commands drained in one pass acked once, so fircd waits out the second's deadline. */
static void t_k_close_two_cmds(void) {
    k_vless();
    k_cmd("198.18.6.1 10.6.6.1\n198.18.7.1 10.7.7.1\n198.18.7.2 10.7.7.2\n\n", 0);
    int a = k_dial(ip4(198, 18, 6, 1), 443, 1);
    int b = k_dial(ip4(198, 18, 7, 1), 443, 1);
    int c = k_dial(ip4(198, 18, 7, 2), 443, 1);
    check(k_ready(a, 200) && k_ready(b, 200) && k_ready(c, 200), "fixture: three open");
    char out[4096];
    out_start();
    k_cmd("198.18.6.0/24\n\n", 1);
    k_cmd("198.18.7.0/24\n\n", 1);
    k_cmd("\n", 1);
    spin(3);
    out_end(out, sizeof out);
    const char *one = strstr(out, "{\"type\":\"close\",\"count\":1}");
    const char *two = one ? strstr(one, "{\"type\":\"close\",\"count\":2}") : NULL;
    const char *empty = two ? strstr(two, "{\"type\":\"close\",\"count\":0}") : NULL;
    check(count_of(out, "\"type\":\"close\"") == 3 && one && two && empty,
          "three close commands in one pass: three acks, in order, each with its own count (1, 2, 0)");
    close(a); close(b); close(c);
}

static void kb_sum(const char *out, uint64_t *rx, uint64_t *tx, int *n) {
    *rx = 0; *tx = 0; *n = 0;
    for (const char *p = out; (p = strstr(p, "{\"type\":\"bytes\",\"rx\":")) != NULL; p++) {
        unsigned long long a = 0, b = 0;
        if (sscanf(p, "{\"type\":\"bytes\",\"rx\":%llu,\"tx\":%llu}", &a, &b) == 2) { *rx += a; *tx += b; (*n)++; }
    }
}

/* Catches a redirected download not counted (direct or queued write), counted as upload, or a bytes event sent while nothing moved. */
static void t_k_bytes(void) {
    static unsigned char big[100000], got[100000];
    static char out[8192];
    for (size_t i = 0; i < sizeof big; i++) big[i] = pat(i);
    k_fake();
    int fd = k_sock(ip4(10, 0, 0, 11), 443, 1);
    int small = 4096;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    k_connect(fd);
    struct conn *c = k_ready(fd, 300);
    if (!c) { check(0, "fixture: bytes connection did not open"); if (fd >= 0) close(fd); return; }
    setsockopt(c->cfd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    int s = pm_srv_of(c);
    fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
    g_kb.sent_rx = g_kb.rx;
    g_kb.sent_tx = g_kb.tx;
    out_start();
    if (send(fd, "hello", 5, 0) != 5) check(0, "fixture: client send failed");
    size_t off = 0, rx = 0;
    for (int i = 0; i < 20000 && rx < sizeof big; i++) {
        if (off < sizeof big) {
            ssize_t w = send(s, big + off, sizeof big - off, MSG_DONTWAIT);
            if (w > 0) off += (size_t)w;
        }
        loop_turn(&g_L, 1);
        if (i < 100) continue;
        ssize_t r = recv(fd, got + rx, sizeof got - rx, MSG_DONTWAIT);
        if (r > 0) rx += (size_t)r;
    }
    g_kb.at = g_now_ns - KB_PERIOD_NS - 1;
    loop_turn(&g_L, 0);
    out_end(out, sizeof out);
    uint64_t srx, stx;
    int n;
    kb_sum(out, &srx, &stx, &n);
    check(rx == sizeof big && n >= 1 && srx == 100000 && stx == 5,
          "a redirected download counts 100000 down and 5 up in bytes events");
    g_kb.at = g_now_ns - KB_PERIOD_NS - 1;
    out_start();
    loop_turn(&g_L, 0);
    out_end(out, sizeof out);
    check(strstr(out, "\"bytes\"") == NULL, "  and no bytes event once nothing moves");
    g_kb.rx = g_kb.sent_rx + KB_EARLY;
    g_kb.at = g_now_ns;
    out_start();
    loop_turn(&g_L, 0);
    out_end(out, sizeof out);
    check(strstr(out, "{\"type\":\"bytes\",\"rx\":2147483648,\"tx\":0}") != NULL,
          "  2^31 bytes are sent at once, before the second, so a delta never wraps");
    close(fd);
}

/* Catches freeing a pending record under its connector (use after free). */
static void t_k_close_pending(void) {
    k_vless();
    int in0 = __atomic_load_n(&g_connect_in, __ATOMIC_ACQUIRE);
    __atomic_store_n(&g_connect_hold, 1, __ATOMIC_RELEASE);
    int fd = k_dial(ip4(10, 0, 0, 8), 443, 1);
    for (int i = 0; i < 500 && __atomic_load_n(&g_connect_in, __ATOMIC_ACQUIRE) == in0; i++) spin(1);
    struct conn *c = k_conn_of(fd);
    int pend = c && c->pending;
    if (!pend)
        fprintf(stderr, "close during a connector job: fd %d conn %s pending %d done %d connects %d seen %c\n", fd,
                c ? "found" : "gone", c ? c->pending : -1, c ? __atomic_load_n(&c->done, __ATOMIC_ACQUIRE) : -1,
                __atomic_load_n(&g_connect_in, __ATOMIC_ACQUIRE) - in0, k_seen(fd));
    char out[4096];
    out_start();
    k_cmd("10.0.0.0/8\n\n", 1);
    spin(2);
    out_end(out, sizeof out);
    int marked = k_conn_of(fd) == c && c && c->pending && c->client_gone && k_seen(fd) == 'W';
    __atomic_store_n(&g_connect_hold, 0, __ATOMIC_RELEASE);
    int s = k_wait(fd, 100);
    check(fd >= 0 && pend, "close during a connector job: fixture: the connection is with its connector");
    check(marked && strstr(out, "{\"type\":\"close\",\"count\":1}") != NULL,
          "  the close marks it and counts it, without touching it");
    check(s == 'R' && !k_conn_of(fd), "  reset after the connector reports");
    close(fd);
}

/* Catches a cut node link passed on as a clean end. */
static void t_k_aborted(void) {
    k_fake();
    int fd = k_dial(ip4(10, 0, 0, 10), 443, 1);
    struct conn *c = k_ready(fd, 300);
    int s = c ? pm_srv_of(c) : -1;
    if (s < 0 || send(s, "abc", 3, 0) != 3) { check(0, "fixture: node send failed"); close(fd); return; }
    char b[8];
    int st = k_wait(fd, 50);
    ssize_t r = recv(fd, b, sizeof b, MSG_DONTWAIT);
    pm_srv_rst(s);
    check(st == 'D' && r == 3 && k_wait(fd, 50) == 'R', "an aborted node resets the client");
    close(fd);
}

/* Catches a truncated download looking whole: FIN only after the held tail is written. */
static void t_k_fin(void) {
    static unsigned char big[200000], got[200000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = pat(i + 3);
    k_fake();
    int fd = k_sock(ip4(10, 0, 0, 11), 443, 1);
    int small = 4096;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    k_connect(fd);
    struct conn *c = k_ready(fd, 300);
    if (!c) { check(0, "fixture: FIN connection did not open"); close(fd); return; }
    setsockopt(c->cfd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    int s = pm_srv_of(c);
    fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
    size_t off = 0, rx = 0;
    int shut = 0, end = 'W';
    for (int i = 0; i < 40000 && end == 'W'; i++) {
        if (off < sizeof big) {
            ssize_t w = send(s, big + off, sizeof big - off, MSG_DONTWAIT);
            if (w > 0) off += (size_t)w;
        } else if (!shut) {
            shutdown(s, SHUT_WR);
            shut = 1;
        }
        loop_turn(&g_L, 1);
        if (i % 4) continue;
        ssize_t r = recv(fd, got + rx, sizeof got - rx > 1000 ? 1000 : sizeof got - rx, MSG_DONTWAIT);
        if (r > 0) rx += (size_t)r;
        else if (r == 0) end = 'F';
        else if (errno == ECONNRESET) end = 'R';
    }
    check(end == 'F' && rx == sizeof big && !memcmp(got, big, sizeof big),
          "a closed node ends with FIN after the whole tail");
    close(fd);
    close(s);
}

/* Catches: an accepted socket closed with a FIN when the process dies, so an unfinished download reads as complete. */
static void t_k_killed_resets(void) {
    k_vless();
    k_cmd("198.18.0.15 10.1.2.7\n\n", 0);
    int fd = k_dial(FAKE(15), 443, 1);
    struct conn *c = k_ready(fd, 200);
    if (!c || c->cfd < 0) {
        check(0, "fixture: an open socket connection");
        if (fd >= 0) close(fd);
        return;
    }
    pid_t kid = fork();
    if (kid == 0) {
        for (;;) pause();
    }
    close(c->cfd);
    c->cfd = -1;
    kill(kid, SIGKILL);
    waitpid(kid, NULL, 0);
    check(k_seen(fd) == 'R', "a killed process holding an unfinished redirected download resets it");
    close(fd);
}

/* Catches a second loop opening the same parked socket: only the listener's loop owns the park list. */
static int g_w1_stop, g_w1_turns, g_w1_most = -1;
static void *w1_loop(void *arg) {
    (void)arg;
    static struct loop l1;
    struct tun_dev t;
    memset(&t, 0, sizeof t);
    t.fd = -1;
    if (conn_table_init() != 0 || loop_open(&l1, &t, 0) != 0) return NULL;
    int most = 0;
    while (!__atomic_load_n(&g_w1_stop, __ATOMIC_ACQUIRE)) {
        loop_turn(&l1, 5);
        if (g_live_n > most) most = g_live_n;
        __atomic_add_fetch(&g_w1_turns, 1, __ATOMIC_RELEASE);
    }
    while (g_live_n) conn_drop(&g_conns[g_live[0]]);
    loop_close(&l1);
    conn_table_free();
    __atomic_store_n(&g_w1_most, most, __ATOMIC_RELEASE);
    return NULL;
}

static void t_k_two_loops(void) {
    k_vless();
    pthread_t t;
    if (pthread_create(&t, NULL, w1_loop, NULL) != 0) { check(0, "fixture: second loop thread"); return; }
    while (__atomic_load_n(&g_w1_turns, __ATOMIC_ACQUIRE) < 3) usleep(1000);
    int fd = k_dial(FAKE(24), 443, 1);
    for (int i = 0; i < 10 && !g_park_n; i++) spin(1);
    int parked = g_park_n;
    k_cmd("198.18.0.24 10.2.4.6\n\n", 0);
    usleep(60000);
    int kept = g_park_n;
    for (int i = 0; i < 10 && !k_conn_of(fd); i++) spin(1);
    struct conn *c = k_conn_of(fd);
    __atomic_store_n(&g_w1_stop, 1, __ATOMIC_RELEASE);
    pthread_join(t, NULL);
    check(parked == 1 && kept == 1 && c && c->key.dst.v4 == ip4(10, 2, 4, 6) && k_seen(fd) == 'W' &&
              __atomic_load_n(&g_w1_most, __ATOMIC_ACQUIRE) == 0,
          "two loops: only the listener's loop opens a parked socket, once");
    if (fd >= 0) close(fd);
}

/* Catches a client error during the ring flush left to idle eviction instead of a reset. */
static void t_k_flush_error(void) {
    static unsigned char big[1 << 19];
    for (size_t i = 0; i < sizeof big; i++) big[i] = pat(i);
    k_fake();
    int fd = k_sock(ip4(10, 0, 0, 13), 443, 1);
    int small = 4096;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    k_connect(fd);
    struct conn *c = k_ready(fd, 300);
    if (!c) { check(0, "fixture: flush-error connection did not open"); close(fd); return; }
    setsockopt(c->cfd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    int s = pm_srv_of(c);
    fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
    size_t off = 0;
    for (int i = 0; i < 100 && !c->rtx.len; i++) {
        ssize_t w = send(s, big + off, sizeof big - off, MSG_DONTWAIT);
        if (w > 0) off += (size_t)w;
        loop_turn(&g_L, 2);
    }
    int held = c->rtx.len > 0;
    sock_rst(fd);
    int gone = 0;
    for (int i = 0; i < 20 && !gone; i++) {
        loop_turn(&g_L, 10);
        gone = !c->used || !c->sock;
    }
    check(held && gone, "a client error while the tail is held resets the connection");
}

/* Catches a prefix match that drops the length guard (/0) or ignores the mask (/32, /24). */
static void t_k_prefixes(void) {
    uint32_t b[3] = { 0, ip4(10, 0, 0, 7), ip4(192, 168, 1, 0) };
    uint8_t l[3] = { 0, 32, 24 };
    check(in_prefixes(ip4(203, 0, 113, 9), b, l, 1) && in_prefixes(ip4(10, 0, 0, 7), b + 1, l + 1, 1) &&
              !in_prefixes(ip4(10, 0, 0, 6), b + 1, l + 1, 1) && in_prefixes(ip4(192, 168, 1, 255), b + 2, l + 2, 1) &&
              !in_prefixes(ip4(192, 168, 2, 0), b + 2, l + 2, 1),
          "close prefixes: /0 takes all, /32 one address, /24 its block only");
}

/* Catches a failed connect left open instead of reset. */
static void t_k_no_node(void) {
    k_fake();
    g_fn[0].alive = 0;
    int fd = k_dial(ip4(10, 0, 0, 12), 443, 1);
    int s = k_wait(fd, 100);
    g_fn[0].alive = 1;
    check(s == 'R' && !k_conn_of(fd), "no active node: the connection is reset when the connector reports");
    close(fd);
}

static void miss_set(void) {
    g_miss.since = 1;
    g_miss.miss = 3;
    g_miss.answered = 2;
    g_miss.timed_out = 1;
    g_miss.max_ms = 17;
}

static void miss_early(void *arg) {
    (void)arg;
    miss_set();
    miss_report(60000000000ull);
}

static void miss_line(void *arg) {
    (void)arg;
    miss_set();
    miss_report(60000000001ull);
}

static void quiet_minute(void *arg) {
    (void)arg;
    memset(&g_miss, 0, sizeof g_miss);
    g_miss.since = 1;
    miss_report(60000000001ull);
}

static void lst_busy(void *arg) { lst_open(*(int *)arg); }

/* Catches: a socket connection in slot 0 taken for the stop token, which resets every TUN connection and spends the stop. */
static void t_k_slot0_not_stop(void) {
    k_vless();
    k_cmd("198.18.0.11 10.1.2.3\n\n", 0);
    for (int i = 0; i < g_free_n; i++) {
        if (g_freelist[i] != 0) continue;
        g_freelist[i] = g_freelist[g_free_n - 1];
        g_freelist[g_free_n - 1] = 0;
        break;
    }
    int fd = k_dial(FAKE(11), 443, 1);
    struct conn *s = k_ready(fd, 200);
    struct conn *t = s && s - g_conns == 0 ? open_conn(65535) : NULL;
    if (!t || g_L.stop_in != 1) {
        check(0, "fixture: a socket connection in slot 0, a TUN connection, the loop armed for stop");
        if (fd >= 0) close(fd);
        return;
    }
    uint32_t a = t->client_ack, o = t->our_seq;
    dev_drain(NULL);
    if (send(fd, "hello", 5, 0) != 5) check(0, "fixture: client send failed");
    static unsigned char w[4096];
    size_t n = 0;
    for (int i = 0; i < 100 && n < 31; i++) {
        spin(1);
        n = wire_of(s, w, sizeof w);
    }
    uint32_t seq[4], ack[4];
    int wrong;
    int rst = stop_rsts(CLI_PORT, seq, ack, 4, &wrong);
    check(n == 31 && !memcmp(w + 26, "hello", 5) && rst == 0 && g_L.stop_in == 1,
          "socket slot 0 readable: its data is pumped, no TUN connection is reset, the stop stays armed");
    uint64_t one = 1;
    if (write(g_stop_efd, &one, sizeof one) != (ssize_t)sizeof one) check(0, "fixture: stop write");
    spin(2);
    rst = stop_rsts(CLI_PORT, seq, ack, 4, &wrong);
    check(rst == 2 && seq[0] == a && seq[1] == o && g_L.stop_in == 0, "  and the stop itself still resets the TUN connection");
    uint64_t t0 = now_ns();
    loop_turn(&g_L, 40);
    check(now_ns() - t0 >= 30 * 1000000ull, "  a loop that answered the stop no longer wakes on it");
    uint64_t v;
    ssize_t rd = read(g_stop_efd, &v, sizeof v);
    (void)rd;
    close(fd);
    if (lst_open(0) != 0) check(0, "fixture: listener reopened");
    g_kport = stack_tcp_port();
    lst_arm(&g_L);
}

/* Catches: a stop that lets exit close redirected sockets with a FIN, so a cut download without a length looks complete. */
static void t_k_stop_resets_sockets(void) {
    k_vless();
    k_cmd("198.18.0.12 10.1.2.4\n\n", 0);
    k_cmd("198.18.0.13 10.1.2.5\n198.18.0.14 10.1.2.6\n\n", 0);
    int fd = k_dial(FAKE(12), 443, 1);
    struct conn *s = k_ready(fd, 200);
    int dfd = k_dial(FAKE(13), 443, 1);
    struct conn *d = k_ready(dfd, 200);
    int tfd = k_dial(FAKE(14), 443, 1);
    struct conn *t = k_ready(tfd, 200);
    int pfd = k_dial(FAKE(23), 443, 1);
    for (int i = 0; i < 10 && !g_park_n; i++) spin(1);
    if (!s || s->cfd < 0 || !d || d->cfd < 0 || !t || t->cfd < 0 || g_park_n != 1) {
        check(0, "fixture: three open socket connections and one parked");
        if (fd >= 0) close(fd);
        if (dfd >= 0) close(dfd);
        if (tfd >= 0) close(tfd);
        if (pfd >= 0) close(pfd);
        return;
    }
    d->srv_closed = 1;
    t->srv_closed = 1;
    t->rtx.len = 10;
    stop_reset(&g_L.tun, 1);
    t->rtx.len = 0;
    close(s->cfd);
    s->cfd = -1;
    close(d->cfd);
    d->cfd = -1;
    close(t->cfd);
    t->cfd = -1;
    close(g_park[0].fd);
    g_park_n = 0;
    check(k_seen(fd) == 'R' && k_seen(pfd) == 'R',
          "stop: an open and a parked redirected socket are reset when the process closes them");
    /* catches: a finished node's tail still in rtx taken as done, so the client reads a short body as complete */
    check(k_seen(tfd) == 'R', "  a finished node whose tail is still held is reset");
    close(tfd);
    /* catches: a connection already finishing at the stop cut by linger 0, losing its unsent tail */
    check(k_seen(dfd) == 'F', "  a connection the node already finished ends with a FIN");
    int late = k_sock(FAKE(12), 443, 1);
    /* catches: the listener left armed, so a connection accepted in the exit window ends with a FIN */
    check(g_lst_fd < 0 && k_connect(late) < 0, "  and the listener is closed, so nothing is accepted after the stop");
    if (late >= 0) close(late);
    close(fd);
    close(dfd);
    close(pfd);
}

#define IB_UUID "b831381d-6324-4d53-ad4f-8cda48b30811"
#define IB_L0 "vless://" IB_UUID "@ha:443?security=none&type=tcp#n0"
#define IB_L1 "vless://" IB_UUID "@hb:443?security=none&type=tcp#n1"
#define LO htonl(INADDR_LOOPBACK)

static void ib_nodes(void) {
    const char *l[2] = { IB_L0, IB_L1 };
    nodes_init(sizeof(struct vless_node));
    sl_set_interner(nodes_intern);
    for (int i = 0; i < 2; i++) {
        struct vless_node nd;
        memset(&nd, 0, sizeof nd);
        if (vless_parse_url(l[i], &nd) != 0 || nodes_add(&nd, l[i]) != i) check(0, "fixture: node store");
    }
    sl_set_interner(NULL);
}

static void ib_cmd(const char *body) {
    FILE *f = fmemopen((void *)body, strlen(body), "r");
    char *line = NULL;
    size_t cap = 0;
    if (!f) return;
    sl_set_interner(nodes_intern);
    ctlinb_read_cmd(f, &line, &cap);
    sl_set_interner(NULL);
    free(line);
    fclose(f);
}

static void ib_cmd_spin(void *arg) {
    ib_cmd(arg);
    spin(2);
}

static void ib_events(const char *body, char *out, size_t cap) {
    out_start();
    ib_cmd_spin((void *)body);
    out_end(out, cap);
}

static void srv_reset(void) {
    pthread_mutex_lock(&g_srv_mu);
    for (int i = 0; i < g_srv_n; i++)
        if (g_srv[i] >= 0) close(g_srv[i]);
    g_srv_n = 0;
    pthread_mutex_unlock(&g_srv_mu);
}

static int srv_count(void) {
    pthread_mutex_lock(&g_srv_mu);
    int n = g_srv_n;
    pthread_mutex_unlock(&g_srv_mu);
    return n;
}

static void ib_fixture(void) {
    k_reset();
    ib_cmd_spin("\n");
    srv_reset();
    all_alive();
    pool_new(1, POOL_BY_CONNECTION, 3);
}

static uint16_t free_port(uint32_t addr) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET };
    a.sin_addr.s_addr = addr;
    socklen_t l = sizeof a;
    uint16_t p = 0;
    if (fd >= 0 && bind(fd, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(fd, (struct sockaddr *)&a, &l) == 0)
        p = ntohs(a.sin_port);
    if (fd >= 0) close(fd);
    return p;
}

static int ib_dial(uint32_t addr, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    a.sin_addr.s_addr = addr;
    if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int ib_send_all(int fd, const void *p, size_t n) {
    return fd >= 0 && send(fd, p, n, MSG_NOSIGNAL) == (ssize_t)n ? 0 : -1;
}

static int ib_socks_at(uint32_t addr, uint16_t port, uint32_t dst, uint16_t dport) {
    int fd = ib_dial(addr, port);
    unsigned char m[13] = { 5, 1, 0, 5, 1, 0, 1 };
    memcpy(m + 7, &dst, 4);
    m[11] = (unsigned char)(dport >> 8);
    m[12] = (unsigned char)dport;
    if (fd >= 0 && ib_send_all(fd, m, sizeof m) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int ib_socks(uint16_t port, uint32_t dst) { return ib_socks_at(LO, port, dst, 443); }

static size_t ib_read(int fd, unsigned char *b, size_t want, int turns) {
    size_t got = 0;
    for (int i = 0; fd >= 0 && i < turns && got < want; i++) {
        loop_turn(&g_L, 10);
        ssize_t r = recv(fd, b + got, want - got, MSG_DONTWAIT);
        if (r > 0) got += (size_t)r;
        else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) break;
    }
    return got;
}

static const unsigned char IB_OK[12] = { 5, 0, 5, 0, 0, 1 };

static int ib_reply_is(int fd, unsigned char rep) {
    unsigned char r[12], want[12] = { 5, 0, 5, rep, 0, 1 };
    return ib_read(fd, r, sizeof r, 300) == sizeof r && !memcmp(r, want, sizeof r);
}

static int ib_reply_is_rest(int fd, unsigned char rep) {
    unsigned char r[10], want[10] = { 5, rep, 0, 1 };
    return ib_read(fd, r, sizeof r, 300) == sizeof r && !memcmp(r, want, sizeof r);
}

static int ib_open(uint16_t port, uint32_t dst, struct conn **cc, int *srv) {
    int fd = ib_socks(port, dst);
    int ok = ib_reply_is(fd, 0);
    struct conn *c = ok ? k_conn_of(fd) : NULL;
    *cc = c;
    *srv = c ? pm_srv_of(c) : -1;
    return fd;
}

static int ib_echo(int fd, int srv) {
    unsigned char b[4];
    if (srv < 0 || ib_send_all(fd, "ping", 4) != 0) return 0;
    size_t got = 0;
    for (int i = 0; i < 300 && got < 4; i++) {
        loop_turn(&g_L, 10);
        ssize_t r = recv(srv, b + got, 4 - got, MSG_DONTWAIT);
        if (r > 0) got += (size_t)r;
    }
    if (got != 4 || memcmp(b, "ping", 4) || ib_send_all(srv, "pong", 4) != 0) return 0;
    return ib_read(fd, b, 4, 300) == 4 && !memcmp(b, "pong", 4);
}

static void ib_line(char *cmd, size_t cap, uint32_t addr, uint16_t port, const char *creds, const char *link) {
    char a[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, a, sizeof a);
    snprintf(cmd, cap, "%s:%u %s %s\n\n", a, port, creds, link);
}

static int ib_event(const char *out, uint16_t port, const char *state, const char *why_part) {
    char k[96];
    snprintf(k, sizeof k, "{\"type\":\"inbound\",\"port\":%u,\"state\":\"%s\",\"why\":\"", port, state);
    const char *p = strstr(out, k);
    if (!p) return 0;
    const char *e = strchr(p, '\n');
    const char *w = strstr(p + strlen(k), why_part);
    return *why_part ? w && (!e || w < e) : p[strlen(k)] == '"';
}

/* Catches an inbound that dials the pool's pick, or replies after the node's bytes instead of first. */
static void t_ib_listens_on_its_address(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512], out[4096];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_events(cmd, out, sizeof out);
    check(ib_event(out, p, "up", ""), "an inbound line: its port listens, the event says up");
    int n0 = srv_count();
    int fd = ib_socks(p, ip4(10, 9, 8, 7));
    for (int i = 0; i < 300 && srv_count() == n0; i++) spin(1);
    int s = srv_count() > n0 ? g_srv[n0] : -1;
    if (s >= 0) ib_send_all(s, "pong", 4);
    unsigned char r[16], want[16];
    memcpy(want, IB_OK, 12);
    memcpy(want + 12, "pong", 4);
    size_t n = ib_read(fd, r, sizeof r, 300);
    struct conn *c = k_conn_of(fd);
    check(srv_count() == n0 + 1 && g_srv_node[n0] == &g_fn[1] && n == 16 && !memcmp(r, want, 16) && c &&
              c->key.dst.v4 == ip4(10, 9, 8, 7) && c->key.dport == 443 && c->ib == 1,
          "a SOCKS CONNECT dials node 1; the client reads 05 00, the success reply, then the node's bytes");
    unsigned char b[4];
    size_t got = 0;
    if (fd >= 0 && ib_send_all(fd, "ping", 4) == 0)
        for (int i = 0; s >= 0 && i < 300 && got < 4; i++) {
            loop_turn(&g_L, 10);
            ssize_t k = recv(s, b + got, 4 - got, MSG_DONTWAIT);
            if (k > 0) got += (size_t)k;
        }
    check(got == 4 && !memcmp(b, "ping", 4), "  and the client's bytes reach the node");
    if (fd >= 0) close(fd);
}

/* Catches a gone node (a dash, or an index past the node store) dialled instead of refused with 03. */
static void t_ib_gone_replies_03(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512], out[4096];
    ib_line(cmd, sizeof cmd, LO, p, "- -", "-");
    ib_events(cmd, out, sizeof out);
    int n0 = srv_count();
    int fd = ib_socks(p, ip4(10, 9, 8, 7));
    int rep = ib_reply_is(fd, 3);
    check(ib_event(out, p, "no-node", "") && rep && k_wait(fd, 50) == 'F' && srv_count() == n0 && g_live_n == 0,
          "a dash: the port listens, a CONNECT reads 03 then EOF, no dial");
    if (fd >= 0) close(fd);
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    nodes_init(sizeof(struct vless_node));
    fd = ib_socks(p, ip4(10, 9, 8, 7));
    rep = ib_reply_is(fd, 3);
    ib_nodes();
    check(rep && srv_count() == n0 && g_live_n == 0, "a node index past the store: 03, no dial");
    if (fd >= 0) close(fd);
}

/* Catches a failed dial answered with a reset instead of 04 and a clean close. */
static void t_ib_dial_fail_replies_04(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    g_fn[1].alive = 0;
    int fd = ib_socks(p, ip4(10, 9, 8, 7));
    int rep = ib_reply_is(fd, 4);
    int end = k_wait(fd, 50);
    g_fn[1].alive = 1;
    check(rep && end == 'F' && g_live_n == 0, "node 1 refuses: the client reads 04, then EOF, not a reset");
    if (fd >= 0) close(fd);
}

static int ib_http(uint16_t port, const char *want) {
    int fd = ib_dial(LO, port);
    const char *req = "CONNECT 10.9.8.7:443 HTTP/1.1\r\nHost: 10.9.8.7:443\r\n\r\n";
    char r[128];
    size_t n = strlen(want);
    int ok = ib_send_all(fd, req, strlen(req)) == 0 && ib_read(fd, (unsigned char *)r, n, 300) == n &&
             !memcmp(r, want, n);
    if (fd >= 0) close(fd);
    return ok;
}

/* Catches an HTTP client answered in SOCKS bytes, after a dial or a gone node. */
static void t_ib_http_replies(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    int ok = ib_http(p, "HTTP/1.1 200 Connection established\r\n\r\n");
    g_fn[1].alive = 0;
    int bad = ib_http(p, "HTTP/1.1 502 Bad Gateway\r\n\r\n");
    g_fn[1].alive = 1;
    ib_line(cmd, sizeof cmd, LO, p, "- -", "-");
    ib_cmd_spin(cmd);
    int gone = ib_http(p, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
    check(ok && bad && gone, "HTTP CONNECT: 200 dialled, 502 dial failed, 503 node gone");
}

/* Catches the line's credentials not reaching the handshake. */
static void t_ib_auth_from_the_line(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "alice pw", IB_L1);
    ib_cmd_spin(cmd);
    int fd = ib_dial(LO, p);
    unsigned char m[] = { 5, 1, 2, 1, 5, 'a', 'l', 'i', 'c', 'e', 2, 'p', 'w', 5, 1, 0, 1, 10, 9, 8, 7, 1, 187 };
    unsigned char r[14], want[14] = { 5, 2, 1, 0, 5, 0, 0, 1 };
    int ok = ib_send_all(fd, m, sizeof m) == 0 && ib_read(fd, r, sizeof r, 300) == sizeof r && !memcmp(r, want, 14);
    if (fd >= 0) close(fd);
    fd = ib_dial(LO, p);
    unsigned char g[3] = { 5, 1, 0 }, ff[2];
    int refused = ib_send_all(fd, g, 3) == 0 && ib_read(fd, ff, 2, 300) == 2 && ff[0] == 5 && ff[1] == 0xff;
    check(ok && refused, "user and password from the line: 02 with them succeeds, a client without them gets FF");
    if (fd >= 0) close(fd);
}

/* Catches a handshake begun without auth finishing a CONNECT after the line gained credentials, or one cut by a command that kept them. */
static void t_ib_creds_change_ends_handshakes(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    unsigned char g[3] = { 5, 1, 0 }, ok2[2], req[10] = { 5, 1, 0, 1, 10, 9, 8, 7, 1, 187 };
    int a = ib_dial(LO, p);
    int greeted = ib_send_all(a, g, 3) == 0 && ib_read(a, ok2, 2, 300) == 2 && ok2[0] == 5 && ok2[1] == 0;
    ib_cmd_spin(cmd);
    int kept = ib_send_all(a, req, sizeof req) == 0 && ib_reply_is_rest(a, 0);
    int n0 = srv_count(), live0 = g_live_n;
    int b = ib_dial(LO, p);
    int greeted_b = ib_send_all(b, g, 3) == 0 && ib_read(b, ok2, 2, 300) == 2 && ok2[0] == 5 && ok2[1] == 0;
    ib_line(cmd, sizeof cmd, LO, p, "alice pw", IB_L1);
    ib_cmd_spin(cmd);
    int ended = k_wait(b, 50) == 'F';
    ib_send_all(b, req, sizeof req);
    spin(5);
    check(greeted && kept && greeted_b && ended && srv_count() == n0 && g_live_n == live0,
          "a line gains a password: a handshake begun without it is closed and never dials; the same line keeps one");
    if (a >= 0) close(a);
    if (b >= 0) close(b);
}

/* Catches a domain resolved, dropped, or put into the destination address instead of carried as the host. */
static void t_ib_domain_is_the_host(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    int fd = ib_dial(LO, p);
    unsigned char m[] = { 5, 1, 0, 5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187 };
    int ok = ib_send_all(fd, m, sizeof m) == 0 && ib_reply_is(fd, 0);
    struct conn *c = ok ? k_conn_of(fd) : NULL;
    const struct fsess *fs = c ? CINNER(SESS(c)) : NULL;
    check(fs && !strcmp(fs->host, "example.com") && c->key.dst.v4 == 0 && c->key.dport == 443,
          "a SOCKS domain goes to the dialer as the host, the address left 0");
    if (fd >= 0) close(fd);
}

/* Catches early bytes past the handshake buffer failing a good request, or reaching the node out of order. */
static void t_ib_early_data(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    static unsigned char m[13 + 900], got[900];
    unsigned char h[13] = { 5, 1, 0, 5, 1, 0, 1, 10, 9, 8, 7, 1, 187 };
    memcpy(m, h, 13);
    for (size_t i = 0; i < 900; i++) m[13 + i] = pat(i);
    int n0 = srv_count();
    int fd = ib_dial(LO, p);
    int ok = ib_send_all(fd, m, sizeof m) == 0 && ib_reply_is(fd, 0);
    int s = srv_count() > n0 ? g_srv[n0] : -1;
    size_t n = 0;
    for (int i = 0; s >= 0 && i < 300 && n < sizeof got; i++) {
        loop_turn(&g_L, 10);
        ssize_t r = recv(s, got + n, sizeof got - n, MSG_DONTWAIT);
        if (r > 0) n += (size_t)r;
    }
    check(ok && n == sizeof got && !memcmp(got, m + 13, sizeof got),
          "900 bytes pipelined after the request: success, and the node gets all of them in order");
    if (fd >= 0) close(fd);
}

/* Catches one busy port taking down the other inbound, a busy port without its reason, a password logged, or every retry logged. */
static void t_ib_busy_one_of_two(void) {
    ib_fixture();
    int hold = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ha = { .sin_family = AF_INET };
    ha.sin_addr.s_addr = LO;
    socklen_t hl = sizeof ha;
    uint16_t a = 0, b = free_port(LO);
    if (hold >= 0 && bind(hold, (struct sockaddr *)&ha, sizeof ha) == 0 && listen(hold, 1) == 0 &&
        getsockname(hold, (struct sockaddr *)&ha, &hl) == 0)
        a = ntohs(ha.sin_port);
    char cmd[1024], out[4096], said[96];
    snprintf(cmd, sizeof cmd, "127.0.0.1:%u alice s3cret " IB_L1 "\n127.0.0.1:%u - - " IB_L1 "\n\n", a, b);
    snprintf(said, sizeof said, "tunvless[error] tunnel: inbound :%u cannot listen: ", a);
    char err1[4096], err2[4096];
    out_start();
    stderr_of(ib_cmd_spin, cmd, err1, sizeof err1);
    int leaked = strstr(err1, "s3cret") || strstr(err1, "alice");
    out_end(out, sizeof out);
    check(a && ib_event(out, a, "busy", "in use") && strstr(err1, said) && !leaked,
          "a taken port: event busy with the kernel's reason, one error line, no credentials in it");
    out_start();
    stderr_of(ib_cmd_spin, cmd, err2, sizeof err2);
    out_end(out, sizeof out);
    check(ib_event(out, a, "busy", "in use") && !strstr(err2, said),
          "  the same command again: busy again, the same error not logged twice");
    struct conn *c;
    int s;
    int fd = ib_open(b, ip4(10, 9, 8, 7), &c, &s);
    check(ib_event(out, b, "up", "") && c && ib_echo(fd, s), "  the other inbound is up and serves");
    if (fd >= 0) close(fd);
    if (hold >= 0) close(hold);
}

/* Catches a port that came up and was lost again staying silent in the log. */
static void t_ib_busy_again_after_up(void) {
    ib_fixture();
    uint32_t two = htonl(0x7f000002);
    int hold = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ha = { .sin_family = AF_INET };
    ha.sin_addr.s_addr = two;
    socklen_t hl = sizeof ha;
    uint16_t a = 0;
    if (hold >= 0 && bind(hold, (struct sockaddr *)&ha, sizeof ha) == 0 && listen(hold, 1) == 0 &&
        getsockname(hold, (struct sockaddr *)&ha, &hl) == 0)
        a = ntohs(ha.sin_port);
    char on2[256], on1[256], out[4096], said[96], e1[4096], e2[4096], e3[4096];
    snprintf(on2, sizeof on2, "127.0.0.2:%u - - " IB_L1 "\n\n", a);
    snprintf(on1, sizeof on1, "127.0.0.1:%u - - " IB_L1 "\n\n", a);
    snprintf(said, sizeof said, "tunvless[error] tunnel: inbound :%u cannot listen: ", a);
    out_start();
    stderr_of(ib_cmd_spin, on2, e1, sizeof e1);
    stderr_of(ib_cmd_spin, on1, e2, sizeof e2);
    stderr_of(ib_cmd_spin, on2, e3, sizeof e3);
    out_end(out, sizeof out);
    check(a && strstr(e1, said) && !strstr(e2, said) && ib_event(out, a, "up", "") && strstr(e3, said),
          "busy, up on another address, busy again: the error is logged both times");
    if (hold >= 0) close(hold);
}

static uint32_t kb_of(const char *out, uint16_t port, const char *field) {
    char k[64];
    snprintf(k, sizeof k, "{\"type\":\"ibytes\",\"port\":%u,", port);
    const char *p = strstr(out, k);
    const char *f = p ? strstr(p, field) : NULL;
    return f ? (uint32_t)strtoul(f + strlen(field), NULL, 10) : UINT32_MAX;
}

static void ib_flush_counts(char *out, size_t cap) {
    g_kb.at = 0;
    for (int i = 0; i < IB_MAX; i++) g_ib[i].kb.at = 0;
    out_start();
    loop_turn(&g_L, 0);
    out_end(out, cap);
}

/* Catches a rebind that cuts live flows, a closed listener left open, or an old flow counted to a new port. */
static void t_ib_rebind_keeps_live_conns(void) {
    ib_fixture();
    uint32_t two = ip4(127, 0, 0, 2);
    uint16_t p = free_port(LO), q = free_port(LO);
    char cmd[512], out[4096];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    struct conn *c;
    int s;
    int fd = ib_open(p, ip4(10, 9, 8, 7), &c, &s);
    ib_line(cmd, sizeof cmd, two, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    int old = ib_dial(LO, p);
    int fresh = ib_socks_at(two, p, ip4(10, 9, 8, 6), 443);
    check(c && old < 0 && ib_reply_is(fresh, 0) && ib_echo(fd, s),
          "a new address: the old one refuses, the new one serves, the live flow still echoes");
    if (fresh >= 0) close(fresh);
    ib_line(cmd, sizeof cmd, LO, q, "- -", IB_L1);
    ib_cmd_spin(cmd);
    ib_flush_counts(out, sizeof out);
    int gone = ib_dial(two, p);
    check(gone < 0 && ib_echo(fd, s), "another port: the old port refuses, the live flow still echoes");
    ib_flush_counts(out, sizeof out);
    check(c->ib == IB_ORPHAN && kb_of(out, q, "\"rx\":") == UINT32_MAX && !strstr(out, "\"bytes\""),
          "  and its bytes are counted to neither the new port nor the kernel");
    if (gone >= 0) close(gone);
    if (old >= 0) close(old);
    if (fd >= 0) close(fd);
}

/* Catches an empty command that leaves the old listeners open. */
static void t_ib_cleared_closes_listeners(void) {
    ib_fixture();
    uint16_t p = free_port(LO), q = free_port(LO);
    char cmd[1024];
    snprintf(cmd, sizeof cmd, "127.0.0.1:%u - - " IB_L1 "\n127.0.0.1:%u - - -\n\n", p, q);
    ib_cmd_spin(cmd);
    int before = ib_dial(LO, p);
    ib_cmd_spin("\n");
    int a = ib_dial(LO, p), b = ib_dial(LO, q);
    check(before >= 0 && a < 0 && b < 0, "an empty command: both ports refuse connections");
    if (before >= 0) close(before);
    if (a >= 0) close(a);
    if (b >= 0) close(b);
}

/* Catches an inbound flow that takes a spare session instead of dialling its node. */
static void t_ib_no_spare(void) {
    ib_fixture();
    void *old = g_spares[0].sess;
    g_spare_want = 1;
    stack_setup(g_dl);
    free(old);
    g_spare_syn_ns = 0;
    spare_refill();
    spare_refill();
    int ready = 0;
    for (int i = 0; i < 500 && !ready; i++) {
        pthread_mutex_lock(&g_spare_mu);
        ready = g_spares[0].state == SPARE_READY;
        pthread_mutex_unlock(&g_spare_mu);
        if (!ready) usleep(2000);
    }
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    int n0 = srv_count();
    struct conn *c;
    int s;
    int fd = ib_open(p, ip4(10, 9, 8, 7), &c, &s);
    pthread_mutex_lock(&g_spare_mu);
    int kept = g_spares[0].state == SPARE_READY;
    pthread_mutex_unlock(&g_spare_mu);
    check(ready && c && kept && srv_count() == n0 + 1 && g_srv_node[n0] == &g_fn[1] && ib_echo(fd, s),
          "a ready spare: the inbound flow dials node 1 itself and the spare stays");
    if (fd >= 0) close(fd);
    k_reset();
    pthread_mutex_lock(&g_spare_mu);
    for (int j = 0; j < SPARE_MAX; j++)
        if (g_spares[j].state == SPARE_READY) {
            g_dl->ops->close(g_spares[j].sess);
            g_spares[j].state = SPARE_EMPTY;
        }
    pthread_mutex_unlock(&g_spare_mu);
    g_spare_want = 0;
}

/* Catches inbound bytes counted into the kernel bytes event, the handshake counted, or ibytes missing its port. */
static void t_ib_not_in_kernel_bytes(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512], out[4096];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    struct conn *c;
    int s;
    int fd = ib_open(p, ip4(10, 9, 8, 7), &c, &s);
    ib_flush_counts(out, sizeof out);
    int quiet = kb_of(out, p, "\"rx\":") == UINT32_MAX;
    int moved = ib_echo(fd, s) && ib_echo(fd, s);
    ib_flush_counts(out, sizeof out);
    check(quiet && moved && kb_of(out, p, "\"rx\":") == 8 && kb_of(out, p, "\"tx\":") == 8 && !strstr(out, "\"bytes\""),
          "inbound traffic: ibytes with its port, 8 down and 8 up, and no bytes event");
    if (fd >= 0) close(fd);
}

/* Catches a close prefix that resets an inbound flow (its odst is 0, inside 0.0.0.0/0). */
static void t_ib_close_prefix_skips(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512], out[4096];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    struct conn *c;
    int s;
    int fd = ib_open(p, ip4(10, 9, 8, 7), &c, &s);
    out_start();
    k_cmd("0.0.0.0/0\n\n", 1);
    spin(3);
    out_end(out, sizeof out);
    check(c && strstr(out, "{\"type\":\"close\",\"count\":0}") && k_seen(fd) == 'W' && ib_echo(fd, s),
          "close 0.0.0.0/0: the inbound flow is not counted and still echoes");
    if (fd >= 0) close(fd);
}

static struct conn *ib_fake(uint8_t ib) {
    struct conn *c = &g_conns[g_freelist[--g_free_n]];
    memset(c, 0, sizeof(*c));
    g_dl->ops->clear(SESS(c));
    c->used = 1;
    c->pending = 1;
    c->ib = ib;
    c->fd = c->cfd = -1;
    c->hnext = -1;
    c->livepos = (int16_t)g_live_n;
    g_live[g_live_n++] = (uint16_t)(c - g_conns);
    return c;
}

/* Catches an inbound cap off by one, or a refusal that takes a slot first. */
static void t_ib_conn_cap(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    struct conn *c;
    int s;
    int fd = ib_open(p, ip4(10, 9, 8, 7), &c, &s);
    static struct conn *fk[IB_CONNS_MAX];
    for (int i = 0; i < IB_CONNS_MAX - 1; i++) fk[i] = ib_fake(1);
    int free0 = g_free_n;
    int n0 = srv_count();
    int over = ib_socks(p, ip4(10, 9, 8, 6));
    int refused = ib_reply_is(over, 1) && g_free_n == free0 && srv_count() == n0;
    fk[IB_CONNS_MAX - 2]->pending = 0;
    conn_drop(fk[IB_CONNS_MAX - 2]);
    int under = ib_socks(p, ip4(10, 9, 8, 5));
    int taken = ib_reply_is(under, 0);
    check(c && refused && taken && ib_echo(fd, s),
          "128 inbound flows: the 129th reads 01 with no slot taken; at 127 the next one opens");
    for (int i = 0; i < IB_CONNS_MAX - 2; i++) {
        fk[i]->pending = 0;
        conn_drop(fk[i]);
    }
    if (over >= 0) close(over);
    if (under >= 0) close(under);
    if (fd >= 0) close(fd);
}

/* Catches an inbound that evicts a connection or eats the last free slots the TUN needs. */
static void t_ib_reserve(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    struct conn *dns = ib_fake(0);
    dns->pending = 0;
    dns->is_udp = 1;
    dns->key.proto = 17;
    dns->key.dport = 53;
    dns->last = g_now_s - DNS_IDLE_S - 1;
    int n0 = g_free_n;
    g_free_n = 0;
    int a = ib_socks(p, ip4(10, 9, 8, 6));
    int none = ib_reply_is(a, 1) && dns->used && dns->is_udp && dns->key.dport == 53 && g_live_n == 1;
    g_free_n = IB_RESERVE - 1;
    int b = ib_socks(p, ip4(10, 9, 8, 5));
    int short_ = ib_reply_is(b, 1) && g_free_n == IB_RESERVE - 1;
    g_free_n = IB_RESERVE;
    int d = ib_socks(p, ip4(10, 9, 8, 4));
    int at = ib_reply_is(d, 0) && g_free_n == IB_RESERVE - 1;
    g_freelist[IB_RESERVE - 1] = g_freelist[n0 - 1];
    g_free_n = n0 - 1;
    check(none && short_ && at,
          "free slots: 0 refuses with 01 and keeps an evictable DNS flow; 63 refuses; 64 opens");
    conn_drop(dns);
    if (a >= 0) close(a);
    if (b >= 0) close(b);
    if (d >= 0) close(d);
}

/* Catches a handshake that never ends, or one cut before its 5000 ms. */
static void t_ib_handshake_deadline(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    int fd = ib_dial(LO, p);
    ib_send_all(fd, "\x05", 1);
    int j = -1;
    for (int i = 0; i < 50 && j < 0; i++) {
        spin(1);
        for (int k = 0; k < IB_HS_MAX; k++)
            if (g_hs[k].ib) j = k;
    }
    uint64_t at = j >= 0 ? g_hs[j].at : 0;
    if (j >= 0) ib_deadlines(at + 4999ull * 1000000ull);
    int early = j >= 0 && g_hs[j].ib && k_seen(fd) == 'W';
    if (j >= 0) ib_deadlines(at + 5001ull * 1000000ull);
    check(early && !g_hs[j].ib && k_seen(fd) != 'W',
          "a client silent after 05: open at 4999 ms, closed at 5001 ms");
    if (fd >= 0) close(fd);
}

/* Catches a stop that leaves inbound listeners, handshakes or flows to end with a FIN. */
static void t_ib_stop_resets(void) {
    ib_fixture();
    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    struct conn *c;
    int s;
    int fd = ib_open(p, ip4(10, 9, 8, 7), &c, &s);
    int hs = ib_dial(LO, p);
    ib_send_all(hs, "\x05", 1);
    int j = -1;
    for (int i = 0; i < 50 && j < 0; i++) {
        spin(1);
        for (int k = 0; k < IB_HS_MAX; k++)
            if (g_hs[k].ib) j = k;
    }
    if (!c || c->cfd < 0 || j < 0) {
        check(0, "fixture: an inbound flow and a handshake");
        return;
    }
    stop_reset(&g_L.tun, 1);
    close(c->cfd);
    c->cfd = -1;
    int late = ib_dial(LO, p);
    check(k_seen(fd) == 'R' && k_seen(hs) == 'R' && late < 0,
          "stop: the inbound flow and the handshake are reset, the port refuses");
    if (late >= 0) close(late);
    close(hs);
    close(fd);
}

static int ib_assoc_open(uint16_t port, uint16_t *relay) {
    int fd = ib_dial(LO, port);
    unsigned char m[13] = { 5, 1, 0, 5, 3, 0, 1 }, r[12], want[10] = { 5, 0, 5, 0, 0, 1, 127, 0, 0, 1 };
    *relay = 0;
    if (ib_send_all(fd, m, sizeof m) == 0 && ib_read(fd, r, sizeof r, 300) == sizeof r && !memcmp(r, want, 10))
        *relay = (uint16_t)(r[10] << 8 | r[11]);
    return fd;
}

static int ib_ucli(uint32_t addr) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in a = { .sin_family = AF_INET };
    a.sin_addr.s_addr = addr;
    if (fd >= 0 && bind(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void ib_dgram(int u, uint16_t relay, const unsigned char *h, size_t hn, const char *d) {
    unsigned char b[512];
    size_t n = strlen(d);
    memcpy(b, h, hn);
    memcpy(b + hn, d, n);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(relay) };
    a.sin_addr.s_addr = LO;
    if (u >= 0) sendto(u, b, hn + n, 0, (struct sockaddr *)&a, sizeof a);
}

static void ib_to(int u, uint16_t relay, uint32_t dst, uint16_t dport, const char *d) {
    unsigned char h[10] = { 0, 0, 0, 1 };
    memcpy(h + 4, &dst, 4);
    h[8] = (unsigned char)(dport >> 8);
    h[9] = (unsigned char)dport;
    ib_dgram(u, relay, h, sizeof h, d);
}

static struct conn *ib_ucon(uint32_t dst, uint16_t dport) {
    for (int li = 0; li < g_live_n; li++) {
        struct conn *c = &g_conns[g_live[li]];
        if (c->ib_udp && c->key.dst.v4 == dst && c->key.dport == dport) return c;
    }
    return NULL;
}

static int ib_ucount(void) {
    int n = 0;
    for (int li = 0; li < g_live_n; li++) n += g_conns[g_live[li]].ib_udp != 0;
    return n;
}

static int ib_slots_used(void) {
    int n = 0;
    for (int a = 0; a < IB_ASSOC_MAX; a++)
        for (int k = 0; g_assoc[a].ib && k < IB_UDP_DST; k++) n += g_assoc[a].dst_conn[k] >= 0;
    return n;
}

static struct conn *ib_uready(uint32_t dst, uint16_t dport) {
    for (int i = 0; i < 300; i++) {
        struct conn *c = ib_ucon(dst, dport);
        if (c && !c->pending && c->fd >= 0) return c;
        loop_turn(&g_L, 10);
    }
    return NULL;
}

static int ib_srv_got(int srv, const void *want, size_t n) {
    unsigned char b[512];
    size_t got = 0;
    for (int i = 0; srv >= 0 && i < 300 && got < n; i++) {
        loop_turn(&g_L, 10);
        ssize_t r = recv(srv, b + got, sizeof b - got, MSG_DONTWAIT);
        if (r > 0) got += (size_t)r;
    }
    return got == n && !memcmp(b, want, n);
}

static int ib_cli_got(int u, uint16_t relay, const void *want, size_t n) {
    unsigned char b[512];
    for (int i = 0; u >= 0 && i < 300; i++) {
        loop_turn(&g_L, 10);
        struct sockaddr_in a;
        socklen_t al = sizeof a;
        ssize_t r = recvfrom(u, b, sizeof b, MSG_DONTWAIT, (struct sockaddr *)&a, &al);
        if (r >= 0)
            return (size_t)r == n && !memcmp(b, want, n) && a.sin_addr.s_addr == LO && ntohs(a.sin_port) == relay;
    }
    return 0;
}

static uint16_t ib_udp_fixture(char *cmd, size_t cap, int *tcp, uint16_t *relay, int *u) {
    ib_fixture();
    uint16_t p = free_port(LO);
    ib_line(cmd, cap, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    *tcp = ib_assoc_open(p, relay);
    *u = ib_ucli(LO);
    return p;
}

static void ib_udp_done(int tcp, int u) {
    if (tcp >= 0) close(tcp);
    if (u >= 0) close(u);
    spin(2);
}

/* Catches a relay that dials the pool's pick, drops the destination, or answers without the SOCKS header. */
static void t_ib_udp_relay(void) {
    char cmd[512], out[4096];
    int tcp, u;
    uint16_t relay;
    uint16_t p = ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    int n0 = srv_count();
    ib_to(u, relay, ip4(10, 9, 8, 7), 443, "ping");
    struct conn *c = ib_uready(ip4(10, 9, 8, 7), 443);
    int s = c ? pm_srv_of(c) : -1;
    static const unsigned char framed[6] = { 0, 4, 'p', 'i', 'n', 'g' };
    const struct fsess *fs = c ? CINNER(SESS(c)) : NULL;
    check(relay && c && fs && fs->udp == 1 && c->is_udp && c->key.proto == 17 && c->cfd == -1 && c->ib == 1 &&
              srv_count() == n0 + 1 &&
              g_srv_node[n0] == &g_fn[1] && ib_srv_got(s, framed, sizeof framed),
          "UDP ASSOCIATE: 05 00 with the listen address and a relay port; a datagram opens a UDP flow on node 1");
    static const unsigned char back[14] = { 0, 0, 0, 1, 10, 9, 8, 7, 1, 187, 'p', 'o', 'n', 'g' };
    ib_send_all(s, "pong", 4);
    check(ib_cli_got(u, relay, back, sizeof back), "  the answer reaches the client from the relay port behind 00 00 00 01 10.9.8.7:443");
    ib_flush_counts(out, sizeof out);
    /* catches: UDP payloads counted into the kernel bytes event, or not counted to the inbound */
    check(kb_of(out, p, "\"rx\":") == 4 && kb_of(out, p, "\"tx\":") == 4 && !strstr(out, "\"bytes\""),
          "  ibytes counts the payloads: 4 down, 4 up, no bytes event");
    ib_udp_done(tcp, u);
}

/* Catches one session shared by two destinations, a session per datagram, or an answer framed with another session's address. */
static void t_ib_udp_two_destinations(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    int n0 = srv_count();
    ib_to(u, relay, ip4(10, 9, 8, 7), 443, "a1");
    ib_to(u, relay, ip4(10, 9, 8, 6), 53, "b1");
    struct conn *a = ib_uready(ip4(10, 9, 8, 7), 443), *b = ib_uready(ip4(10, 9, 8, 6), 53);
    int sa = a ? pm_srv_of(a) : -1, sb = b ? pm_srv_of(b) : -1;
    ib_to(u, relay, ip4(10, 9, 8, 7), 443, "a2");
    static const unsigned char wa[8] = { 0, 2, 'a', '1', 0, 2, 'a', '2' }, wb[4] = { 0, 2, 'b', '1' };
    int got = ib_srv_got(sa, wa, sizeof wa) && ib_srv_got(sb, wb, sizeof wb);
    check(a && b && a != b && ib_ucount() == 2 && srv_count() == n0 + 2 && g_srv_node[n0] == &g_fn[1] &&
              g_srv_node[n0 + 1] == &g_fn[1] && got,
          "two destinations: two UDP sessions on node 1, each gets its own datagrams");
    static const unsigned char back[12] = { 0, 0, 0, 1, 10, 9, 8, 6, 0, 53, 'o', 'k' };
    ib_send_all(sb, "ok", 2);
    check(ib_cli_got(u, relay, back, sizeof back), "  the answer of the second carries 10.9.8.6:53");
    ib_udp_done(tcp, u);
}

/* Catches a relay that takes datagrams from any source instead of the control connection's address. */
static void t_ib_udp_foreign_source_dropped(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    int f = ib_ucli(ip4(127, 0, 0, 2));
    ib_to(f, relay, ip4(10, 9, 8, 7), 443, "x");
    ib_to(u, relay, ip4(10, 9, 8, 6), 443, "y");
    struct conn *b = ib_uready(ip4(10, 9, 8, 6), 443);
    spin(5);
    check(f >= 0 && b && ib_ucount() == 1 && !ib_ucon(ip4(10, 9, 8, 7), 443),
          "a datagram from 127.0.0.2: no flow; the client's own opens one");
    if (f >= 0) close(f);
    ib_udp_done(tcp, u);
}

/* Catches a fragment sent on as a whole datagram. */
static void t_ib_udp_frag_dropped(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    static const unsigned char h[10] = { 0, 0, 1, 1, 10, 9, 8, 7, 1, 187 };
    ib_dgram(u, relay, h, sizeof h, "x");
    ib_to(u, relay, ip4(10, 9, 8, 6), 443, "y");
    struct conn *b = ib_uready(ip4(10, 9, 8, 6), 443);
    spin(5);
    check(b && ib_ucount() == 1 && !ib_ucon(ip4(10, 9, 8, 7), 443), "FRAG 1: dropped; a whole datagram opens a flow");
    ib_udp_done(tcp, u);
}

/* Catches a datagram to a domain opened as a session (stage 1 carries IPv4 only). */
static void t_ib_udp_domain_dropped(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    int n0 = srv_count();
    static const unsigned char h[19] = { 0, 0, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187 };
    ib_dgram(u, relay, h, 18, "x");
    ib_to(u, relay, ip4(10, 9, 8, 6), 443, "y");
    struct conn *b = ib_uready(ip4(10, 9, 8, 6), 443);
    spin(5);
    check(b && ib_ucount() == 1 && srv_count() == n0 + 1, "ATYP 3: dropped, no session; an IPv4 datagram opens one");
    ib_udp_done(tcp, u);
}

/* Catches a destination drop that closes the relay socket or leaves its slot taken. */
static void t_ib_udp_drop_keeps_relay(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    int n0 = srv_count();
    ib_to(u, relay, ip4(10, 9, 8, 7), 443, "a1");
    struct conn *a = ib_uready(ip4(10, 9, 8, 7), 443);
    int cfd = a ? a->cfd : 0;
    int sa = a ? pm_srv_of(a) : -1;
    if (sa >= 0) close(sa);
    for (int i = 0; i < 300 && ib_ucon(ip4(10, 9, 8, 7), 443); i++) loop_turn(&g_L, 10);
    int gone = !ib_ucon(ip4(10, 9, 8, 7), 443);
    ib_to(u, relay, ip4(10, 9, 8, 7), 443, "a2");
    struct conn *b = ib_uready(ip4(10, 9, 8, 7), 443);
    int sb = b ? pm_srv_of(b) : -1;
    static const unsigned char w[4] = { 0, 2, 'a', '2' };
    check(a && cfd == -1 && gone && b && srv_count() == n0 + 2 && ib_srv_got(sb, w, sizeof w) && k_seen(tcp) == 'W' &&
              ib_slots_used() == 1,
          "the node ends a destination: the relay stays, the next datagram opens a new session");
    ib_udp_done(tcp, u);
}

/* Catches a relay that follows the client to whichever port of its address sends next. */
static void t_ib_udp_client_port_pinned(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    int v = ib_ucli(LO);
    ib_to(u, relay, ip4(10, 9, 8, 6), 443, "y");
    struct conn *b = ib_uready(ip4(10, 9, 8, 6), 443);
    ib_to(v, relay, ip4(10, 9, 8, 7), 443, "x");
    spin(5);
    check(v >= 0 && b && ib_ucount() == 1 && !ib_ucon(ip4(10, 9, 8, 7), 443),
          "a second port of the client's address after the first: dropped, no flow");
    if (v >= 0) close(v);
    ib_udp_done(tcp, u);
}

/* Catches a listen-address change that leaves associations bound to the old address. */
static void t_ib_udp_ends_on_address_change(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    uint16_t p = ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    ib_to(u, relay, ip4(10, 9, 8, 7), 443, "a1");
    struct conn *a = ib_uready(ip4(10, 9, 8, 7), 443);
    int before = a && ib_ucount() == 1;
    ib_line(cmd, sizeof cmd, ip4(127, 0, 0, 2), p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    spin(5);
    unsigned char b;
    int live = 0;
    for (int i = 0; i < IB_ASSOC_MAX; i++) live += g_assoc[i].ib != 0;
    check(before && live == 0 && ib_ucount() == 0 && recv(tcp, &b, 1, MSG_DONTWAIT) <= 0,
          "the listen address changes: the association and its UDP session end");
    ib_udp_done(tcp, u);
}

/* Catches an association that outlives its TCP connection. */
static void t_ib_udp_ends_with_tcp(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    ib_to(u, relay, ip4(10, 9, 8, 7), 443, "a1");
    struct conn *a = ib_uready(ip4(10, 9, 8, 7), 443);
    int sa = a ? pm_srv_of(a) : -1;
    static const unsigned char w[4] = { 0, 2, 'a', '1' };
    int sent = ib_srv_got(sa, w, sizeof w);
    close(tcp);
    spin(10);
    unsigned char b;
    ssize_t eof = sa >= 0 ? recv(sa, &b, 1, MSG_DONTWAIT) : -1;
    int again = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ra = { .sin_family = AF_INET, .sin_port = htons(relay) };
    ra.sin_addr.s_addr = LO;
    int bound = again >= 0 && bind(again, (struct sockaddr *)&ra, sizeof ra) == 0;
    check(relay && sent && ib_ucount() == 0 && eof == 0 && bound,
          "the TCP connection closes: the relay port is free again and the session to the node is closed");
    if (again >= 0) close(again);
    ib_udp_done(-1, u);
}

static uint64_t *ib_last_of(uint32_t dst) {
    for (int a = 0; a < IB_ASSOC_MAX; a++)
        for (int k = 0; g_assoc[a].ib && k < IB_UDP_DST; k++) {
            int i = g_assoc[a].dst_conn[k];
            if (i >= 0 && g_conns[i].used && g_conns[i].key.dst.v4 == dst) return &g_assoc[a].last_ms[k];
        }
    return NULL;
}

/* Catches a 17th destination that grows the association, evicts a busy session, or evicts not the oldest idle one. */
static void t_ib_udp_17th_destination(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    int n0 = srv_count();
    for (int i = 1; i <= 16; i++) ib_to(u, relay, ip4(10, 9, 8, i), 443, "x");
    int ready = 1;
    for (int i = 1; i <= 16; i++) ready &= ib_uready(ip4(10, 9, 8, i), 443) != NULL;
    uint64_t *l3 = ib_last_of(ip4(10, 9, 8, 3)), *l7 = ib_last_of(ip4(10, 9, 8, 7));
    if (!ready || !l3 || !l7 || srv_count() != n0 + 16) {
        check(0, "fixture: sixteen ready destinations");
        ib_udp_done(tcp, u);
        return;
    }
    *l3 = g_now_ns / 1000000 - 59500;
    ib_to(u, relay, ip4(10, 9, 8, 17), 443, "x");
    spin(10);
    int dropped = ib_ucount() == 16 && !ib_ucon(ip4(10, 9, 8, 17), 443) && srv_count() == n0 + 16;
    l3 = ib_last_of(ip4(10, 9, 8, 3));
    l7 = ib_last_of(ip4(10, 9, 8, 7));
    if (l3) *l3 = g_now_ns / 1000000 - 60300;
    if (l7) *l7 = g_now_ns / 1000000 - 60600;
    ib_to(u, relay, ip4(10, 9, 8, 17), 443, "x");
    struct conn *n = ib_uready(ip4(10, 9, 8, 17), 443);
    check(dropped && n && ib_ucount() == 16 && !ib_ucon(ip4(10, 9, 8, 7), 443) && ib_ucon(ip4(10, 9, 8, 3), 443),
          "a 17th destination: dropped while none is idle 60 s, else the oldest idle one makes room");
    ib_udp_done(tcp, u);
}

/* Catches UDP destination sessions left out of the inbound cap and the reserve. */
static void t_ib_udp_counts_in_cap(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    static struct conn *fk[IB_CONNS_MAX];
    for (int i = 0; i < IB_CONNS_MAX - 1; i++) fk[i] = ib_fake(1);
    ib_to(u, relay, ip4(10, 9, 8, 1), 443, "x");
    struct conn *a = ib_uready(ip4(10, 9, 8, 1), 443);
    ib_to(u, relay, ip4(10, 9, 8, 2), 443, "x");
    spin(5);
    int capped = a && !ib_ucon(ip4(10, 9, 8, 2), 443);
    fk[0]->pending = 0;
    conn_drop(fk[0]);
    int free0 = g_free_n;
    g_free_n = IB_RESERVE - 1;
    ib_to(u, relay, ip4(10, 9, 8, 3), 443, "x");
    spin(5);
    int reserved = !ib_ucon(ip4(10, 9, 8, 3), 443) && g_free_n == IB_RESERVE - 1;
    g_free_n = free0;
    ib_to(u, relay, ip4(10, 9, 8, 4), 443, "x");
    struct conn *d = ib_uready(ip4(10, 9, 8, 4), 443);
    check(capped && reserved && d, "UDP sessions count: the 129th inbound conn and a short reserve drop the datagram; 127 opens");
    for (int i = 1; i < IB_CONNS_MAX - 1; i++) {
        fk[i]->pending = 0;
        conn_drop(fk[i]);
    }
    ib_udp_done(tcp, u);
}

/* Catches a 33rd association taken past the table, or a gone node given a relay. */
static void t_ib_udp_assoc_limits(void) {
    ib_fixture();
    uint16_t p = free_port(LO), relay;
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    static int t[IB_ASSOC_MAX];
    int all = 1;
    for (int i = 0; i < IB_ASSOC_MAX; i++) {
        t[i] = ib_assoc_open(p, &relay);
        all &= relay != 0;
    }
    int fd = ib_dial(LO, p);
    unsigned char m[13] = { 5, 1, 0, 5, 3, 0, 1 }, r[12], full[12] = { 5, 0, 5, 1, 0, 1 };
    int refused = ib_send_all(fd, m, sizeof m) == 0 && ib_read(fd, r, sizeof r, 300) == sizeof r && !memcmp(r, full, 12);
    if (fd >= 0) close(fd);
    close(t[0]);
    spin(3);
    t[0] = ib_assoc_open(p, &relay);
    check(all && refused && relay, "32 associations: the 33rd reads 01; one closes and the next gets a relay");
    for (int i = 0; i < IB_ASSOC_MAX; i++)
        if (t[i] >= 0) close(t[i]);
    spin(3);
    ib_line(cmd, sizeof cmd, LO, p, "- -", "-");
    ib_cmd_spin(cmd);
    fd = ib_dial(LO, p);
    unsigned char gone[12] = { 5, 0, 5, 3, 0, 1 };
    int g = ib_send_all(fd, m, sizeof m) == 0 && ib_read(fd, r, sizeof r, 300) == sizeof r && !memcmp(r, gone, 12);
    check(g && k_wait(fd, 50) == 'F', "a dash: UDP ASSOCIATE reads 03, then EOF");
    if (fd >= 0) close(fd);
}

/* Catches an association left open after its inbound is removed, or ended with a FIN at a stop. */
static void t_ib_udp_removed_and_stop(void) {
    char cmd[512];
    int tcp, u;
    uint16_t relay;
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    ib_cmd_spin("\n");
    int end = k_wait(tcp, 50);
    int again = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ra = { .sin_family = AF_INET, .sin_port = htons(relay) };
    ra.sin_addr.s_addr = LO;
    int bound = again >= 0 && bind(again, (struct sockaddr *)&ra, sizeof ra) == 0;
    if (again >= 0) close(again);
    check(relay && end == 'F' && bound, "an inbound removed: its association ends, the relay port is free");
    ib_udp_done(tcp, u);
    ib_udp_fixture(cmd, sizeof cmd, &tcp, &relay, &u);
    stop_reset(&g_L.tun, 1);
    check(relay && k_seen(tcp) == 'R', "stop: the association's TCP connection is reset");
    ib_udp_done(tcp, u);
}

static void ib_part(void) {
    ib_nodes();
    t_ib_listens_on_its_address();
    t_ib_gone_replies_03();
    t_ib_dial_fail_replies_04();
    t_ib_http_replies();
    t_ib_auth_from_the_line();
    t_ib_creds_change_ends_handshakes();
    t_ib_domain_is_the_host();
    t_ib_early_data();
    t_ib_busy_one_of_two();
    t_ib_busy_again_after_up();
    t_ib_rebind_keeps_live_conns();
    t_ib_cleared_closes_listeners();
    t_ib_no_spare();
    t_ib_not_in_kernel_bytes();
    t_ib_close_prefix_skips();
    t_ib_conn_cap();
    t_ib_reserve();
    t_ib_handshake_deadline();
    t_ib_stop_resets();
    t_ib_udp_relay();
    t_ib_udp_two_destinations();
    t_ib_udp_foreign_source_dropped();
    t_ib_udp_frag_dropped();
    t_ib_udp_domain_dropped();
    t_ib_udp_drop_keeps_relay();
    t_ib_udp_client_port_pinned();
    t_ib_udp_ends_on_address_change();
    t_ib_udp_ends_with_tcp();
    t_ib_udp_17th_destination();
    t_ib_udp_counts_in_cap();
    t_ib_udp_assoc_limits();
    t_ib_udp_removed_and_stop();
    ib_fixture();
}

struct msess { const struct fnode *node; int udp; };

static const struct mux_host *g_mh;
static int g_m_attach_rc, g_m_attach_n, g_m_connect_n, g_m_lost, g_m_cut, g_m_read_rc, g_m_send_rc;
static int g_m_send_n, g_m_dial_n, g_m_dial_in, g_m_release, g_m_dropped_n;
static uint16_t g_m_owner;
static struct xc_ref g_m_ref;
static unsigned char g_m_sent[4096];
static size_t g_m_sent_n, g_m_rn, g_m_wake_rn;
static long g_m_room, g_m_wake_room;
static unsigned g_m_wake_what;
static int g_m_wake_rc;
static struct xconn g_m_link[CONNECTORS + 1];
static uint16_t g_m_link_owner[CONNECTORS + 1];
static int g_m_link_gone[CONNECTORS + 1];
static int g_m_link_n;
static char g_m_log[64];
static size_t g_m_log_n;
static int g_m_sp[2] = { -1, -1 };
static int g_m_watch_on, g_m_watch_rc, g_m_dial_rc;
static unsigned g_m_watch_ev;
static int g_m_ev_n;
static unsigned g_m_ev_idx, g_m_ev_last;

static void m_log(char ch) {
    if (g_m_log_n + 1 < sizeof g_m_log) g_m_log[g_m_log_n++] = ch;
    g_m_log[g_m_log_n] = 0;
}

static int m_connect(const void *ctx, void *sess, int t) {
    (void)ctx; (void)sess; (void)t;
    __atomic_add_fetch(&g_m_connect_n, 1, __ATOMIC_SEQ_CST);
    return TR_ECONNECT;
}
static void m_take(void *dst, void *src) { (void)dst; (void)src; }
static void m_close(void *sess) { (void)sess; }
static void m_clear(void *sess) { memset(sess, 0, sizeof(struct msess)); }
static int m_fd(const void *sess) { (void)sess; return -1; }
static int m_has_data(const void *sess) { (void)sess; return g_m_rn > 0; }
static int m_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)k;
    struct msess *s = sess;
    s->node = ctx;
    s->udp = udp;
    return 0;
}
static int m_set_host(void *sess, const char *host) { (void)sess; (void)host; return 0; }
static int m_send(const void *ctx, void *sess, const struct flow_key *k, int udp, const unsigned char *d, size_t n) {
    (void)ctx; (void)sess; (void)k; (void)udp;
    g_m_send_n++;
    if (g_m_send_rc != SEND_OK) return g_m_send_rc;
    if (g_m_sent_n + n > sizeof g_m_sent) return SEND_FATAL;
    if (n) {
        memcpy(g_m_sent + g_m_sent_n, d, n);
        m_log('S');
    }
    g_m_sent_n += n;
    return SEND_OK;
}
static long m_room(const void *ctx, void *sess) { (void)ctx; (void)sess; return g_m_room; }
static int m_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    (void)sess;
    *got = 0;
    if (g_m_read_rc) return g_m_read_rc;
    size_t n = g_m_rn < cap ? g_m_rn : cap;
    memset(buf, 'r', n);
    if (n) m_log('R');
    *data = buf;
    *got = n;
    g_m_rn -= n;
    return 0;
}
static void m_lost(const void *ctx, const void *sess) { (void)ctx; (void)sess; g_m_lost++; }

static void m_host(const struct mux_host *h) { g_mh = h; }
static int m_attach(const void *ctx, void *sess, uint16_t owner, const struct xc_ref *ref) {
    (void)ctx; (void)sess;
    g_m_attach_n++;
    g_m_owner = owner;
    if (ref) g_m_ref = *ref;
    return g_m_attach_rc;
}
static int m_dial(const void *ctx, void *link, int t) {
    (void)ctx; (void)link; (void)t;
    __atomic_add_fetch(&g_m_dial_n, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&g_m_dial_in, 1, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&g_m_release, __ATOMIC_ACQUIRE)) sched_yield();
    return g_m_dial_rc;
}
static int m_event(unsigned idx, uint32_t ev) {
    g_m_ev_n++;
    g_m_ev_idx = idx;
    g_m_ev_last = ev;
    return 0;
}
static int g_m_due;
static int m_pass(uint64_t now, int phase) {
    (void)now;
    m_log(phase == MUXP_EARLY ? 'E' : 'L');
    if (phase == MUXP_LATE) return g_m_due;
    if (phase == MUXP_EARLY && g_m_watch_on) {
        g_m_watch_on = 0;
        g_m_watch_rc = g_mh->watch(0, g_m_sp[0], g_m_watch_ev);
    }
    if (phase != MUXP_EARLY || !g_m_wake_what) return 0;
    if (g_m_wake_rn) g_m_rn = g_m_wake_rn;
    if (g_m_wake_room != -2) g_m_room = g_m_wake_room;
    unsigned what = g_m_wake_what;
    g_m_wake_what = 0;
    g_m_wake_rn = 0;
    g_m_wake_room = -2;
    g_mh->wake(g_mh->arg, g_m_owner, what, g_m_wake_rc);
    return 0;
}
static int m_cut(const void *sess) { (void)sess; return g_m_cut; }
static int m_busy(void) {
    int n = 0;
    for (int i = 0; i < g_m_link_n; i++)
        n += !g_m_link_gone[i] && !__atomic_load_n(&g_m_link[i].done, __ATOMIC_ACQUIRE);
    return n;
}
static void m_dropped(void *link) {
    int i = (int)((struct xconn *)link - g_m_link);
    g_m_dropped_n++;
    g_m_link_gone[i] = 1;
    if (g_m_link_owner[i] != UINT16_MAX) g_mh->wake(g_mh->arg, g_m_link_owner[i], XW_DONE, TR_ECLOSED);
}

static const struct dialer_mux m_mux = {
    .host = m_host, .attach = m_attach, .dial = m_dial, .event = m_event, .pass = m_pass, .cut = m_cut,
    .busy = m_busy, .dropped = m_dropped,
};
static const struct dialer_ops m_ops = {
    .name = "mux", .sess_size = sizeof(struct msess), .peer = f_peer, .describe = f_describe,
    .strerror = tr_dial_strerror, .connect = m_connect, .take = m_take, .close = m_close, .clear = m_clear,
    .fd = m_fd, .has_data = m_has_data, .flow_open = m_flow_open, .send = m_send, .room = m_room,
    .dgram_frame = f_dgram_frame, .read = m_read, .deliver = f_deliver, .lost = m_lost, .set_host = m_set_host,
    .mux = &m_mux,
};
static const struct pool_proto m_proto = { .ops = &m_ops, .probe = f_probe, .name = f_name };

static void m_zero(void) {
    g_m_attach_rc = XA_READY;
    g_m_attach_n = g_m_lost = g_m_cut = g_m_read_rc = g_m_send_n = g_m_dial_n = g_m_dial_in = 0;
    g_m_dropped_n = g_m_link_n = 0;
    g_m_watch_on = g_m_watch_rc = g_m_dial_rc = g_m_ev_n = 0;
    g_m_log_n = 0;
    g_m_log[0] = 0;
    g_m_send_rc = SEND_OK;
    __atomic_store_n(&g_m_connect_n, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_m_release, 0, __ATOMIC_SEQ_CST);
    g_m_sent_n = g_m_rn = g_m_wake_rn = 0;
    g_m_room = -1;
    g_m_wake_room = -2;
    g_m_wake_what = 0;
    g_m_wake_rc = 0;
    g_m_due = 0;
    memset(&g_m_ref, 0, sizeof g_m_ref);
    memset(g_m_link_gone, 0, sizeof g_m_link_gone);
    memset(g_m_link, 0, sizeof g_m_link);
    pm_drain(NULL, NULL);
}

static void m_new(void) {
    static struct dialer d = { .ops = &m_ops, .ctx = &g_fn[0], .silence_s = 20 };
    k_reset();
    g_spare_want = 0;
    stack_setup(&d);
    loop_mux(&g_L);
    m_zero();
}

static void m_pool(void) {
    k_reset();
    ib_nodes();
    ib_cmd_spin("\n");
    srv_reset();
    all_alive();
    g_pproto = &m_proto;
    pool_new(1, POOL_BY_CONNECTION, 3);
    g_pproto = &f_proto;
    loop_mux(&g_L);
    m_zero();
}

static int m_queued(void) {
    pthread_mutex_lock(&g_cq.mu);
    int n = (int)g_cq.n;
    pthread_mutex_unlock(&g_cq.mu);
    return n;
}

static int m_drain(unsigned *flags, uint16_t *win) {
    unsigned char p[70000];
    int cnt = 0;
    *flags = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) == 0) {
            *flags |= k.tcp_flags;
            if (win) *win = k.window;
            cnt++;
        }
    }
    return cnt;
}

static struct conn *m_flow(uint16_t sport) {
    g_m_attach_rc = XA_READY;
    pm_send(sport, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    pm_send(sport, SRV_IP, 1001, 2, TCP_ACK, NULL, 0);
    pm_drain(NULL, NULL);
    struct flow_key k = pm_key(sport, SRV_IP);
    struct conn *c = conn_find(&k);
    return c && c->mux && !c->pending && c->fd == -1 ? c : NULL;
}

static uint64_t m_turn_ms(int max_ms) {
    uint64_t t0 = now_ns();
    loop_turn(&g_L, max_ms);
    return (now_ns() - t0) / 1000000;
}

static void m_turn(void *arg) { (void)arg; loop_turn(&g_L, 0); }

/* catches: a shared flow queued for a connector */
static void t_mux_ready_no_connector(void) {
    m_new();
    pm_send(41100, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    struct flow_key k = pm_key(41100, SRV_IP);
    struct conn *c = conn_find(&k);
    unsigned fl;
    int n = m_drain(&fl, NULL);
    check(c && c->mux && !c->pending && c->fd == -1 && g_m_attach_n == 1 && g_m_owner == c - g_conns &&
              n == 1 && fl == (TCP_SYN | TCP_ACK) && m_queued() == 0 && g_m_connect_n == 0,
          "mux READY: SYN-ACK at once, owner is the slot, no connector job");
    pm_send(41100, SRV_IP, 1001, 2, TCP_ACK | TCP_PSH, (const unsigned char *)"hello", 5);
    check(g_m_sent_n == 5 && !memcmp(g_m_sent, "hello", 5), "  the client's first data goes to the shared stream at once");
}

/* catches: waiters never released, or early data reordered */
static void t_mux_wait_then_done(void) {
    m_new();
    g_m_attach_rc = XA_WAIT;
    pm_send(41110, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    struct flow_key k = pm_key(41110, SRV_IP);
    struct conn *c = conn_find(&k);
    unsigned fl;
    int n = m_drain(&fl, NULL);
    unsigned char e[300], l[100];
    memset(e, 'e', sizeof e);
    memset(l, 'l', sizeof l);
    pm_send(41110, SRV_IP, 1001, 2, TCP_ACK | TCP_PSH, e, sizeof e);
    check(c && c->mux && c->pending && !c->done && n == 1 && fl == (TCP_SYN | TCP_ACK) && g_m_sent_n == 0 &&
              m_queued() == 0,
          "mux WAIT: SYN-ACK at once, the flow pends, early data held");
    g_m_wake_what = XW_DONE;
    loop_turn(&g_L, 0);
    int same_turn = g_m_sent_n == 300 && !memcmp(g_m_sent, e, 300) && !c->pending;
    pm_send(41110, SRV_IP, 1301, 2, TCP_ACK | TCP_PSH, l, sizeof l);
    check(same_turn && g_m_sent_n == 400 && !memcmp(g_m_sent + 300, l, 100),
          "mux WAIT then XW_DONE: the 300 early bytes go in that turn, before the next segment");
}

/* catches: a waiter resolved between turns left until the next second's wake */
static void t_mux_done_between_turns(void) {
    m_new();
    g_m_attach_rc = XA_WAIT;
    pm_send(41115, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    pm_drain(NULL, NULL);
    struct flow_key k = pm_key(41115, SRV_IP);
    struct conn *c = conn_find(&k);
    if (c) g_mh->wake(g_mh->arg, (uint16_t)(c - g_conns), XW_DONE, 0);
    uint64_t ms = m_turn_ms(300);
    check(c && !c->pending && ms < 100, "mux WAIT resolved outside a pass: the next turn does not wait");
}

/* catches: a failed attach taken as ready or queued for a connector */
static void t_mux_attach_fails(void) {
    m_new();
    g_m_attach_rc = TR_ECONNREFUSED;
    pm_send(41125, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    struct flow_key k = pm_key(41125, SRV_IP);
    struct conn *c = conn_find(&k);
    int pend = c && c->mux && c->pending && c->done && m_queued() == 0;
    memset(&g_said_open, 0, sizeof g_said_open);
    char buf[4096];
    stderr_of(m_turn, NULL, buf, sizeof buf);
    unsigned fl;
    m_drain(&fl, NULL);
    check(pend && (fl & TCP_SYN) && (fl & TCP_RST) && !conn_find(&k) && g_m_connect_n == 0 &&
              strstr(buf, "refused the TCP connection"),
          "mux attach < 0: SYN-ACK, then RST in the next turn, no connector");
}

/* catches: link tokens never dispatched, or watch unable to add, change or remove a link */
static void t_mux_link_events(void) {
    m_new();
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_m_sp) != 0) {
        check(0, "fixture: link socketpair");
        return;
    }
    if (send(g_m_sp[1], "x", 1, 0) != 1) check(0, "fixture: link byte");
    g_m_watch_ev = EPOLLIN;
    g_m_watch_on = 1;
    loop_turn(&g_L, 0);
    int add_rc = g_m_watch_rc;
    loop_turn(&g_L, 0);
    check(add_rc == 0 && g_m_ev_n == 1 && g_m_ev_idx == 0 && g_m_ev_last == EPOLLIN,
          "mux watch: a new link fd is added, its readiness reaches event(0) next turn");
    g_m_watch_ev = EPOLLIN | EPOLLOUT;
    g_m_watch_on = 1;
    loop_turn(&g_L, 0);
    int mod_rc = g_m_watch_rc;
    loop_turn(&g_L, 0);
    check(mod_rc == 0 && (g_m_ev_last & EPOLLOUT) && (g_m_ev_last & EPOLLIN), "  re-watched with EPOLLOUT: the next event carries it");
    g_m_watch_ev = 0;
    g_m_watch_on = 1;
    loop_turn(&g_L, 0);
    int del_rc = g_m_watch_rc, before = g_m_ev_n;
    close(g_m_sp[1]);
    loop_turn(&g_L, 0);
    check(del_rc == 0 && g_m_ev_n == before, "  watched with 0: the fd is gone, not even a hang-up reaches event");
    close(g_m_sp[0]);
    g_m_sp[0] = g_m_sp[1] = -1;
}

/* catches: queued frames left unflushed after the TUN batch, the forced read or the deadlines */
static void t_mux_phase_order(void) {
    m_new();
    struct conn *c = m_flow(41135);
    unsigned char p[2048];
    size_t l = tcp_build(p, sizeof p, CLI_IP, SRV_IP, 41135, 443, 1001, 2, TCP_ACK | TCP_PSH,
                         (const unsigned char *)"data", 4, 65535, 0, -1);
    g_m_log_n = 0;
    if (send(g_dev_peer, p, l, 0) != (ssize_t)l) check(0, "fixture: device write");
    loop_turn(&g_L, 0);
    check(c && !strcmp(g_m_log, "ESLLL"), "mux phases: a TUN segment gives EARLY, the send, then LATE thrice");
    g_m_log_n = 0;
    g_m_wake_what = XW_READ;
    g_m_wake_rn = 100;
    loop_turn(&g_L, 0);
    check(c && !strcmp(g_m_log, "ERLL"), "  a woken read gives EARLY, the read, then LATE after it and the deadlines");
}

/* catches: a mux deadline (packet-up's POST interval) left out of the loop's wait */
static void t_mux_deadline_wakes_loop(void) {
    m_new();
    g_m_due = 40;
    loop_turn(&g_L, 0);
    uint64_t ms = m_turn_ms(2000);
    check(ms >= 30 && ms < 500, "mux deadline: a quiet loop waits the 40 ms the mux asked for, not 2 s");
    g_m_due = 0;
    loop_turn(&g_L, 0);
    ms = m_turn_ms(150);
    check(ms >= 120, "  no deadline: the loop waits its own time");
}

static void *m_efd_later(void *arg) {
    struct timespec ts = { 0, 80 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    __atomic_store_n((int *)arg, -1, __ATOMIC_RELEASE);
    return NULL;
}

/* catches: a loop closing its eventfd while a connector is about to write it */
static void t_mux_release_waits_efd(void) {
    m_new();
    int i = CONNECTORS - 1;
    __atomic_store_n(&g_cq_efd[i], g_conn_efd, __ATOMIC_RELEASE);
    pthread_t t;
    int made = g_conn_efd >= 0 && pthread_create(&t, NULL, m_efd_later, &g_cq_efd[i]) == 0;
    int rc = made ? connq_release(g_conns) : -2;
    int held = __atomic_load_n(&g_cq_efd[i], __ATOMIC_ACQUIRE) == g_conn_efd;
    if (made) pthread_join(t, NULL);
    check(rc == 0 && !held, "connq_release waits while a connector holds the loop's eventfd");
}

/* catches: a failed dial leaving the flow hanging */
static void t_mux_wait_fail(void) {
    m_new();
    g_m_attach_rc = XA_WAIT;
    pm_send(41120, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    pm_drain(NULL, NULL);
    g_m_wake_what = XW_DONE;
    g_m_wake_rc = TR_ECONNREFUSED;
    memset(&g_said_open, 0, sizeof g_said_open);
    char buf[4096];
    stderr_of(m_turn, NULL, buf, sizeof buf);
    unsigned fl;
    m_drain(&fl, NULL);
    struct flow_key k = pm_key(41120, SRV_IP);
    check((fl & TCP_RST) && !conn_find(&k) && strstr(buf, "flow to h0 did not open") &&
              strstr(buf, "refused the TCP connection"),
          "mux WAIT, the link fails: RST to the client, the log names the node and the refusal");
}

/* catches: a shared flow read only on a socket event it never gets */
static void t_mux_read_wake(void) {
    m_new();
    struct conn *c = m_flow(41130);
    g_m_wake_what = XW_READ;
    g_m_wake_rn = 1000;
    loop_turn(&g_L, 0);
    unsigned fl;
    int n = m_drain(&fl, NULL);
    check(c && c->our_seq == 1002 && n >= 1 && g_m_rn == 0, "mux XW_READ: the 1000 bytes reach the client in that turn");
    pm_send(41130, SRV_IP, 1001, 1002, TCP_ACK, NULL, 0);
    uint64_t idle = m_turn_ms(300);
    g_m_rn = 500;
    uint64_t busy = m_turn_ms(300);
    check(c && idle >= 200 && busy < 100 && c->our_seq == 1502,
          "  the next wait is 0 only while the stream has data");
}

static void m_window(uint16_t sport, uint16_t win) {
    unsigned char p[128];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, sport, 443, 1001, 2, TCP_ACK, NULL, 0, win, 0, -1);
    handle_packet(&g_tun, p, l);
    up_flush(&g_tun);
}

/* catches: ready flows that cannot take spending the late pass, so a later ready flow is never read */
static void t_mux_ready_tail_drained(void) {
    m_new();
    struct conn *a = m_flow(41135), *b = m_flow(41136), *c = m_flow(41137);
    m_window(41135, 0);
    m_window(41136, 0);
    pm_drain(NULL, NULL);
    g_m_wake_what = 0;
    g_mh->wake(g_mh->arg, (uint16_t)(a - g_conns), XW_READ, 0);
    g_mh->wake(g_mh->arg, (uint16_t)(b - g_conns), XW_READ, 0);
    loop_turn(&g_L, 0);
    check(a && b && c && a->rx_ready && b->rx_ready && !c->rx_ready && c->our_seq == 2,
          "mux: two flows ready with a closed client window, a third one idle");
    g_m_rn = 1000;
    for (int i = 0; i < 3; i++) loop_turn(&g_L, 0);
    check(c && c->our_seq == 1002 && g_m_rn == 0 && a->our_seq == 2 && b->our_seq == 2,
          "  the third flow's data is read in the next turns");
}

/* catches: a ready flow whose client window is closed cutting the wait to zero */
static void t_mux_blocked_ready_waits(void) {
    m_new();
    struct conn *a = m_flow(41140), *b = m_flow(41141);
    m_window(41140, 0);
    m_window(41141, 0);
    pm_drain(NULL, NULL);
    g_m_wake_what = 0;
    g_m_rn = 1000;
    g_mh->wake(g_mh->arg, (uint16_t)(a - g_conns), XW_READ, 0);
    g_mh->wake(g_mh->arg, (uint16_t)(b - g_conns), XW_READ, 0);
    loop_turn(&g_L, 0);
    uint64_t w = m_turn_ms(300);
    check(a && b && a->rx_ready && b->rx_ready && a->our_seq == 2 && b->our_seq == 2 && g_m_rn == 1000 && w >= 200,
          "mux: flows ready behind a closed client window do not make the loop poll");
}

/* catches: the late pass reading a direct flow whose client window is closed */
static void t_late_direct_closed_window(void) {
    fake_new();
    pm_drain(NULL, NULL);
    struct conn *a = pm_open(41150, SRV_IP), *b = pm_open(41151, SRV_IP);
    int sa = a ? pm_srv_of(a) : -1, sb = b ? pm_srv_of(b) : -1;
    static unsigned char big[200000];
    memset(big, 'd', sizeof big);
    check(sa >= 0 && sb >= 0 && send(sa, big, sizeof big, MSG_DONTWAIT) == (ssize_t)sizeof big,
          "fixture: two direct flows, 200000 B waiting for the first");
    settle();
    g_f_buffered = 1;
    loop_turn(&g_L, 0);
    pm_drain(NULL, NULL);
    uint32_t s1 = a ? a->our_seq : 0;
    int full = a && !conn_can_take(a) && a->rx_ready && !a->srv_closed;
    if (sb >= 0 && send(sb, big, 1000, 0) != 1000) check(0, "fixture: server send");
    settle();
    for (int i = 0; i < 3; i++) loop_turn(&g_L, 0);
    pm_drain(NULL, NULL);
    check(full && a->our_seq == s1 && !a->srv_closed && b->our_seq == 1002,
          "late pass: a direct flow with a closed client window reads nothing past it");
    g_f_buffered = 0;
    while (g_live_n) conn_drop(&g_conns[g_live[0]]);
    pm_drain(NULL, NULL);
}

static void m_ack(uint16_t sport, uint32_t ack, uint16_t win) {
    unsigned char p[128];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, sport, 443, 1001, ack, TCP_ACK, NULL, 0, win, 0, -1);
    handle_packet(&g_tun, p, l);
    up_flush(&g_tun);
}

/* catches: a flow reopened by the TUN batch spending the late pass, so a ready flow counted before the wait is never read */
static void t_mux_reopened_head_spares_tail(void) {
    m_new();
    struct conn *a = m_flow(41138), *c = m_flow(41139);
    m_window(41138, 0);
    m_window(41139, 0);
    pm_drain(NULL, NULL);
    g_m_wake_what = 0;
    g_mh->wake(g_mh->arg, (uint16_t)(a - g_conns), XW_READ, 0);
    g_m_rn = (size_t)1 << 30;
    for (int i = 0; i < 2; i++) loop_turn(&g_L, 0);
    int closed = a && c && a->our_seq == 2 && c->our_seq == 2;
    m_ack(41139, 2, 65535);
    for (int i = 0; i < 50 && a && c; i++) {
        unsigned char p[128];
        size_t l = tcp_build(p, sizeof p, CLI_IP, SRV_IP, 41138, 443, 1001, a->our_seq, TCP_ACK, NULL, 0, 65535, 0, -1);
        if (send(g_dev_peer, p, l, 0) != (ssize_t)l) check(0, "fixture: device write");
        loop_turn(&g_L, 0);
        pm_drain(NULL, NULL);
    }
    check(closed && a->our_seq - 2 > 65536 && c->our_seq - 2 >= 16384,
          "mux: a flow reopened in every TUN batch does not starve a ready flow behind it");
    g_m_rn = 0;
    if (a && c) {
        m_ack(41138, a->our_seq, 65535);
        m_ack(41139, c->our_seq, 65535);
    }
    for (int i = 0; i < 3; i++) loop_turn(&g_L, 0);
    pm_drain(NULL, NULL);
    check(m_turn_ms(300) >= 200, "  with nothing left to read the loop waits again");
}

/* catches: a grown room announced twice */
static void t_mux_room_wake(void) {
    m_new();
    g_m_room = 0;
    struct conn *c = m_flow(41140);
    loop_turn(&g_L, 0);
    pm_drain(NULL, NULL);
    int seen0 = c && c->room_seen == 0;
    g_m_wake_what = XW_ROOM;
    g_m_wake_room = 65536;
    loop_turn(&g_L, 0);
    unsigned fl;
    uint16_t win = 0;
    int n = m_drain(&fl, &win);
    loop_turn(&g_L, 0);
    unsigned fl2;
    int again = m_drain(&fl2, NULL);
    check(seen0 && n == 1 && fl == TCP_ACK && win > 0 && again == 0,
          "mux XW_ROOM: one window update to the client, no second one");
}

/* catches: a cut shared link reported as a clean end */
static void t_mux_cut_rst(void) {
    m_new();
    struct conn *c = m_flow(41150);
    g_m_read_rc = -1;
    g_m_cut = 1;
    g_m_wake_what = XW_READ;
    loop_turn(&g_L, 0);
    unsigned fl;
    m_drain(&fl, NULL);
    struct flow_key k = pm_key(41150, SRV_IP);
    check(c && (fl & TCP_RST) && !(fl & TCP_FIN) && !conn_find(&k) && g_m_lost == 1,
          "mux link cut: RST to the client, lost told once");
    g_m_read_rc = 0;
    c = m_flow(41151);
    g_m_read_rc = -1;
    g_m_cut = 0;
    g_m_wake_what = XW_READ;
    loop_turn(&g_L, 0);
    m_drain(&fl, NULL);
    check(c && (fl & TCP_FIN) && !(fl & TCP_RST) && g_m_lost == 1, "  a stream that ended, not cut: FIN, no lost");
    /* catches: a stream the server refused (GOAWAY) reported to the pool as a dead node */
    g_m_read_rc = 0;
    c = m_flow(41152);
    g_m_read_rc = -1;
    g_m_cut = 2;
    g_m_wake_what = XW_READ;
    loop_turn(&g_L, 0);
    m_drain(&fl, NULL);
    k = pm_key(41152, SRV_IP);
    check(c && (fl & TCP_RST) && !(fl & TCP_FIN) && !conn_find(&k) && g_m_lost == 1,
          "  a refused stream: RST to the client, no lost");
}

/* catches: poll(-1, 5 ms) per refused send */
static void t_mux_send_does_not_poll(void) {
    m_new();
    struct conn *c = m_flow(41160);
    g_m_send_rc = SEND_AGAIN;
    unsigned char d[100];
    memset(d, 'd', sizeof d);
    uint64_t best = UINT64_MAX;
    int sr = SEND_OK;
    for (int i = 0; c && i < 3; i++) {
        uint64_t t0 = now_ns();
        sr = send_or_wait(c, &g_tun, d, sizeof d);
        uint64_t dt = now_ns() - t0;
        if (dt < best) best = dt;
    }
    check(c && sr == SEND_AGAIN && best < 1000000, "mux SEND_AGAIN: send_or_wait returns in under 1 ms");
}

/* catches: an entry point left on the per-flow path */
static void t_mux_five_sites(void) {
    m_pool();
    g_pl.slot[0].gen = 7;
    pm_send(41170, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    struct flow_key tk = pm_key(41170, SRV_IP);
    struct conn *t = conn_find(&tk);
    check(t && t->mux && !t->pending && g_m_attach_n == 1 && g_m_ref.node == &g_fn[0] && g_m_ref.slot == 0 &&
              g_m_ref.gen == 7,
          "mux sites: a TUN SYN attaches, the pool passes its node, slot and generation");

    struct flow_key uk = pm_key(41171, SRV_IP);
    uk.proto = 17;
    udp_packet(&g_tun, NULL, &uk, (const unsigned char *)"abcd", 4, 0);
    struct conn *u = conn_find(&uk);
    check(u && u->mux && !u->pending && g_m_attach_n == 2 && g_m_sent_n == 6 && !memcmp(g_m_sent + 2, "abcd", 4),
          "  a TUN datagram attaches and goes out");

    int kfd = k_dial(ip4(93, 184, 216, 50), 80, 1);
    struct conn *kc = NULL;
    for (int i = 0; i < 200 && !(kc = k_conn_of(kfd)); i++) spin(1);
    check(kc && kc->mux && !kc->pending && g_m_attach_n == 3, "  a redirected socket attaches");

    uint16_t p = free_port(LO);
    char cmd[512];
    ib_line(cmd, sizeof cmd, LO, p, "- -", IB_L1);
    ib_cmd_spin(cmd);
    int ifd = ib_socks(p, ip4(10, 9, 8, 7));
    int replied = ib_reply_is(ifd, 0);
    struct conn *ic = k_conn_of(ifd);
    check(replied && ic && ic->mux && !ic->pending && g_m_attach_n == 4 && g_m_ref.node == &g_fn[1] &&
              g_m_ref.slot == -1,
          "  an inbound CONNECT attaches pinned to its node and gets 05 00 at once");

    uint16_t relay;
    int tcp = ib_assoc_open(p, &relay);
    int uc = ib_ucli(LO);
    ib_to(uc, relay, ip4(10, 9, 8, 8), 443, "ping");
    struct conn *iu = NULL;
    for (int i = 0; i < 200 && !(iu = ib_ucon(ip4(10, 9, 8, 8), 443)); i++) spin(1);
    check(iu && iu->mux && !iu->pending && g_m_attach_n == 5, "  an inbound datagram attaches");
    check(g_m_connect_n == 0 && m_queued() == 0, "  and none of the five went to a connector");
    if (kfd >= 0) close(kfd);
    if (ifd >= 0) close(ifd);
    if (tcp >= 0) close(tcp);
    if (uc >= 0) close(uc);
    spin(2);
    ib_cmd_spin("\n");
    g_pl.slot[0].gen = 0;
}

static void *m_release_later(void *arg) {
    (void)arg;
    struct timespec ts = { 0, 80 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    __atomic_store_n(&g_m_release, 1, __ATOMIC_RELEASE);
    return NULL;
}

static int g_m_rel_rc;
static int g_m_rel_done;
static void m_release(void *arg) {
    (void)arg;
    pthread_t t;
    if (pthread_create(&t, NULL, m_release_later, NULL) != 0) return;
    g_m_rel_rc = connq_release(g_conns);
    g_m_rel_done = 1;
    for (int i = 0; i < CONNECTORS; i++) g_m_rel_done &= __atomic_load_n(&g_m_link[i].done, __ATOMIC_ACQUIRE) == 1;
    pthread_join(t, NULL);
}

/* catches: a link freed under a working connector, or waiters of a dropped job left pending */
static void t_mux_release_waits(void) {
    m_new();
    g_m_attach_rc = XA_WAIT;
    pm_send(41180, SRV_IP, 1000, 0, TCP_SYN, NULL, 0);
    pm_drain(NULL, NULL);
    struct flow_key k = pm_key(41180, SRV_IP);
    struct conn *c = conn_find(&k);
    uint16_t owner = c ? (uint16_t)(c - g_conns) : UINT16_MAX;
    int pushed = 1;
    for (int i = 0; i < CONNECTORS; i++) {
        g_m_link_owner[i] = UINT16_MAX;
        g_m_link_n = i + 1;
        pushed &= g_mh->submit(&g_m_link[i], &g_m_link[i].done) == 0;
    }
    for (int i = 0; i < 2000 && __atomic_load_n(&g_m_dial_in, __ATOMIC_SEQ_CST) < CONNECTORS; i++) usleep(1000);
    g_m_link_owner[CONNECTORS] = owner;
    g_m_link_n = CONNECTORS + 1;
    pushed &= g_mh->submit(&g_m_link[CONNECTORS], &g_m_link[CONNECTORS].done) == 0;
    int queued = m_queued();
    check(c && pushed && __atomic_load_n(&g_m_dial_in, __ATOMIC_SEQ_CST) == CONNECTORS && queued == 1,
          "mux release: every connector busy on a link, one link job queued");
    memset(&g_said_open, 0, sizeof g_said_open);
    char buf[4096];
    stderr_of(m_release, NULL, buf, sizeof buf);
    int all_done = 1;
    for (int i = 0; i < CONNECTORS; i++) all_done &= __atomic_load_n(&g_m_link[i].done, __ATOMIC_ACQUIRE) == 1;
    check(g_m_rel_rc == 0 && g_m_rel_done && all_done && g_m_dial_n == CONNECTORS,
          "  connq_release returns only after the taken link jobs are done");
    unsigned fl;
    m_drain(&fl, NULL);
    check(g_m_dropped_n == 1 && g_m_link[CONNECTORS].done == 0 && m_queued() == 0 && (fl & TCP_RST) && !conn_find(&k),
          "  the queued job is dropped and its waiting flow gets RST");
}

/* catches: a dial to a slot gone down, or a stale ref read as live */
static void t_pool_ref_dead_slot(void) {
    k_reset();
    all_alive();
    g_pproto = &m_proto;
    pool_new(1, POOL_BY_CONNECTION, 3);
    g_pproto = &f_proto;
    m_zero();
    __atomic_store_n(&g_m_release, 1, __ATOMIC_SEQ_CST);
    static struct xconn x;
    x.ref = (struct xc_ref){ &g_fn[0], 0, g_pl.slot[0].gen };
    int live = g_pl_ops.mux->dial(&g_pl, &x, 1);
    int fresh = pool_ref_stale(&x.ref);
    g_pl.slot[0].up = 0;
    int dead = g_pl_ops.mux->dial(&g_pl, &x, 1);
    g_pl.slot[0].up = 1;
    g_pl.slot[0].gen++;
    int stale = pool_ref_stale(&x.ref);
    g_pl.slot[0].drained[0] = x.ref.gen + 1;
    int drained = pool_ref_stale(&x.ref);
    g_pl.slot[0].drained[0] = 0;
    g_pl.slot[0].gen--;
    g_pl.slot[0].streak = 0;
    g_m_dial_rc = TR_ECONNREFUSED;
    int failed = g_pl_ops.mux->dial(&g_pl, &x, 1);
    int streak = g_pl.slot[0].streak;
    g_m_dial_rc = 0;
    check(live == 0 && dead == TR_ENONODE && g_m_dial_n == 2, "pool mux dial: a dead slot is refused without dialling");
    check(fresh == 0 && stale == 1, "  pool_ref_stale: the slot's generation moved on");
    check(drained == 0, "  pool_ref_stale: a drained generation is not stale");
    check(failed == TR_ECONNREFUSED && streak == 1, "  a failed shared dial counts in the slot's streak");
}

static int sh_shares(const void *ctx) { return ctx == &g_fn[0]; }
static const struct dialer_mux sh_mux = {
    .host = m_host, .attach = m_attach, .dial = m_dial, .event = m_event, .pass = m_pass, .cut = m_cut,
    .busy = m_busy, .dropped = m_dropped, .shares = sh_shares,
};
static const struct dialer_ops sh_ops = {
    .name = "shares", .caps = DC_PRECONNECT, .sess_size = sizeof(struct fsess),
    .peer = f_peer, .describe = f_describe, .strerror = f_strerror, .connect = f_connect,
    .take = f_take, .close = f_close, .clear = f_clear, .fd = f_fd, .has_data = f_has_data,
    .flow_open = f_flow_open, .send = f_send, .dgram_frame = f_dgram_frame, .read = f_read,
    .deliver = f_deliver, .lost = f_lost, .set_host = f_set_host, .mux = &sh_mux,
};
static const struct pool_proto sh_proto = { .ops = &sh_ops, .probe = f_probe, .name = f_name };

static void sh_settle(void) {
    for (int i = 0; i < 400; i++) {
        pthread_mutex_lock(&g_cq.mu);
        int n = (int)g_cq.n;
        pthread_mutex_unlock(&g_cq.mu);
        int filling = 0;
        pthread_mutex_lock(&g_spare_mu);
        for (int k = 0; k < SPARE_MAX; k++) filling += g_spares[k].state == SPARE_FILLING;
        pthread_mutex_unlock(&g_spare_mu);
        if (!n && !filling) return;
        usleep(5000);
    }
}

static void sh_round(int *ready, int *on_shared) {
    for (int i = 0; i < SPARE_MAX; i++) g_spares[i].state = SPARE_EMPTY;
    g_spare_fail_ns = 0;
    g_spare_fail_n = 0;
    g_spare_syn_ns = 0;
    g_spare_clock_ns = 7000000000000ull;
    spare_refill();
    g_spare_clock_ns += 100000000ull;
    spare_refill();
    sh_settle();
    *ready = *on_shared = 0;
    for (int i = 0; i < SPARE_MAX; i++) {
        if (g_spares[i].state != SPARE_READY) continue;
        (*ready)++;
        if (((const struct pl_sess *)g_spares[i].sess)->node == &g_fn[0]) (*on_shared)++;
        g_dl->ops->close(g_spares[i].sess);
        g_spares[i].state = SPARE_EMPTY;
    }
}

static void sh_spares(int want) {
    free(g_spares[0].sess);
    for (int i = 0; i < SPARE_MAX; i++) g_spares[i].sess = NULL;
    g_spare_want = want;
    if (want) stack_setup(g_dl);
}

/* catches: spares dialled for flows that never take them */
static void t_spares_skip_shared_nodes(void) {
    k_reset();
    all_alive();
    srv_reset();
    g_pproto = &sh_proto;
    pool_new(1, POOL_BY_CONNECTION, 1);
    g_pproto = &f_proto;
    sh_spares(4);
    int ready, shared;
    sh_round(&ready, &shared);
    check(ready == 0 && g_spare_fail_n == 0, "spares: a node whose flows share gets no spare, and that is no failure");
    g_pproto = &sh_proto;
    pool_new(2, POOL_BY_CONNECTION, 2);
    g_pproto = &f_proto;
    pl_check(1);
    sh_spares(4);
    sh_round(&ready, &shared);
    check(ready == 4 && shared == 0 && g_spare_fail_n == 0, "  with a tcp node beside it the spares go to the tcp node only");
    g_spare_clock_ns = 0;
    sh_spares(0);
    srv_reset();
}

static void mux_part(void) {
    t_mux_ready_no_connector();
    t_mux_wait_then_done();
    t_mux_done_between_turns();
    t_mux_wait_fail();
    t_mux_attach_fails();
    t_mux_link_events();
    t_mux_phase_order();
    t_mux_deadline_wakes_loop();
    t_mux_read_wake();
    t_mux_ready_tail_drained();
    t_mux_blocked_ready_waits();
    t_mux_reopened_head_spares_tail();
    t_late_direct_closed_window();
    t_mux_room_wake();
    t_mux_cut_rst();
    t_mux_send_does_not_poll();
    t_mux_five_sites();
    t_mux_release_waits();
    t_mux_release_waits_efd();
    t_pool_ref_dead_slot();
    t_spares_skip_shared_nodes();
}

static const unsigned char g_k6_real[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40 };

static int k6_pool(int v6_node) {
    k_reset();
    srv_reset();
    all_alive();
    memset(g_v6ok, 0, sizeof g_v6ok);
    if (v6_node >= 0) g_v6ok[v6_node] = 1;
    pool_new6(2, POOL_BY_CONNECTION, 2, 1);
    conn_table_init();
    pl_check(0);
    pl_check(1);
    int six = -1, n6 = 0;
    for (int i = 0; i < g_pl.n; i++)
        if (g_pl.slot[i].node >= 0 && g_pl.slot[i].up && g_pl.slot[i].v6) {
            six = i;
            n6++;
        }
    return n6 == 1 ? six : n6 == 0 ? -1 : -2;
}

static int k6_on(const struct conn *c, int slot) {
    return c && c->key.v6 == 1 && !memcmp(c->key.dst.b, g_k6_real, 16) && c->key.dport == 443 &&
           ((const struct pl_sess *)SESS(c))->slot == slot;
}

/* Catches: a v6 real dialled with a v4 key, on a node without IPv6, or not at all after a miss */
static void t_ktcp_v6_real_dials_a_v6_node(void) {
    int six = k6_pool(1);
    check(six >= 0 && g_pl.slot[1 - six].up && !g_pl.slot[1 - six].v6, "fixture: two live slots, one carries IPv6");
    k_cmd("198.18.0.40 2001:db8::40\n\n", 0);
    int all = 1;
    for (int i = 0; i < 8; i++) {
        int fd = k_dial(FAKE(40), 443, 1);
        struct conn *c = k_ready(fd, 200);
        if (!k6_on(c, six) || c->odst != FAKE(40)) all = 0;
        if (fd >= 0) close(fd);
        k_reset();
    }
    check(all, "a fake mapped to a v6 real dials it with a v6 key, always on the v6 node");
    int fd = k_dial(FAKE(41), 443, 1);
    for (int i = 0; i < 10 && !g_park_n; i++) spin(1);
    int parked = g_park_n == 1;
    k_cmd("198.18.0.41 2001:db8::40\n\n", 0);
    struct conn *c = k_ready(fd, 200);
    check(parked && !g_park_n && k6_on(c, six) && c->odst == FAKE(41),
          "a miss answered with a v6 real opens the parked socket with the v6 key");
    if (fd >= 0) close(fd);
    k_vless();
    k_cmd("198.18.0.42 2001:db8::40\n\n", 0);
    fd = k_dial(FAKE(42), 8443, 1);
    c = k_ready(fd, 200);
    static unsigned char w[4096];
    uint64_t t0 = now_ns();
    while (c && (now_ns() - t0) / 1000000 < SERVER_FIRST_MS + 50) spin(1);
    size_t n = c ? wire_of(c, w, sizeof w) : 0;
    check(n == 38 && w[0] == 0 && w[17] == 0 && w[18] == 1 && w[19] == 0x20 && w[20] == 0xfb && w[21] == 3 &&
              !memcmp(w + 22, g_k6_real, 16),
          "the request names the v6 real: address type 3 and its 16 bytes");
    if (fd >= 0) close(fd);
    k_reset();
}

/* Catches: a v6 real dialled at a v4-only node, or the socket left open when no node carries IPv6 */
static void t_ktcp_v6_real_without_v6_node_is_refused(void) {
    int six = k6_pool(-1);
    check(six == -1 && g_pl.slot[0].up && g_pl.slot[1].up, "fixture: two live slots, none carries IPv6");
    k_cmd("198.18.0.43 2001:db8::40\n\n", 0);
    int dials = srv_count();
    unsigned miss0 = g_miss.miss;
    int fd = k_dial(FAKE(43), 443, 1);
    int st = k_wait(fd, 10);
    check(st == 'R' && !k_conn_of(fd) && srv_count() == dials && g_park_n == 0 && g_miss.miss == miss0,
          "no v6 node: the socket is reset and nothing is dialled");
    if (fd >= 0) close(fd);
    k_reset();
}

/* Catches: a v4 real given a v6 key or stray address bytes, or kept off the v4-only node */
static void t_ktcp_v4_real_unchanged(void) {
    int six = k6_pool(1);
    k_cmd("198.18.0.44 10.4.4.4\n\n", 0);
    int all = 1, on[2] = { 0, 0 };
    static const unsigned char zero[12];
    for (int i = 0; i < 24; i++) {
        int fd = k_dial(FAKE(44), 443, 1);
        struct conn *c = k_ready(fd, 200);
        if (!c || c->key.v6 || c->key.dst.v4 != ip4(10, 4, 4, 4) || memcmp(c->key.dst.b + 4, zero, 12)) all = 0;
        else on[((const struct pl_sess *)SESS(c))->slot & 1]++;
        if (fd >= 0) close(fd);
        k_reset();
    }
    check(six >= 0 && all && on[0] && on[1], "a v4 real dials with a v4 key, on either node");
    k_reset();
}

static void sock_part(void) {
    int fl = fcntl(g_tun.fd, F_GETFL, 0);
    fcntl(g_tun.fd, F_SETFL, fl | O_NONBLOCK);
    signal(SIGPIPE, SIG_IGN);
    check(sizeof(struct conn) <= 224, "the hot record stays within 224 bytes");

    int busy = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in ba = { .sin_family = AF_INET };
    socklen_t bl = sizeof ba;
    int bport = -1;
    if (busy >= 0 && bind(busy, (struct sockaddr *)&ba, sizeof ba) == 0 && listen(busy, 1) == 0 &&
        getsockname(busy, (struct sockaddr *)&ba, &bl) == 0)
        bport = ntohs(ba.sin_port);
    char want[96];
    snprintf(want, sizeof want, "tunvless[warn] tunnel: cannot listen on port %d: ", bport);
    check(bport > 0 && stderr_has(lst_busy, &bport, want) && stack_tcp_port() == 0 && g_lst_fd < 0,
          "a taken port: tcpPort 0 and one warn line");
    if (busy >= 0) close(busy);

    check(!stderr_has(miss_early, NULL, "misses"), "misses: nothing before the minute is over");
    check(stderr_has(miss_line, NULL,
                     "tunvless[warn] tunnel: 3 misses in the last minute, 2 answered (max 17 ms), 1 timed out\n") &&
              g_miss.miss == 0,
          "misses: one line a minute with answered, max and timed out");
    check(!stderr_has(quiet_minute, NULL, "misses"), "  and none for a minute without misses");

    ctlmap_init(ip4(198, 18, 0, 0), 15);
    if (ctlinb_init() != 0 || lst_open(0) != 0 || loop_open(&g_L, &g_tun, 1) != 0) {
        check(0, "fixture: listener and loop");
        return;
    }
    g_kport = stack_tcp_port();
    park_cap_init();
    check(g_kport > 0 && g_L.ctl >= 0 && g_L.ibw >= 0, "fixture: the listener, the map and the inbounds wakes are in the loop");

    int a = -1, b = -1;
    t_k_direct();
    t_k_listener_itself();
    t_k_mapped();
    t_k_real();
    t_k_spare();
    t_k_spoke_early();
    t_k_room();
    t_k_held_data();
    t_k_evict();
    t_k_half_close();
    t_k_ask_once(&a, &b);
    t_k_answer(a, b);
    t_k_dash();
    t_k_deadline();
    t_k_park_cap();
    t_k_send_again();
    t_k_fd_table();
    t_k_close();
    t_k_close_two_cmds();
    t_k_bytes();
    t_k_close_pending();
    t_k_full_client();
    t_k_aborted();
    t_k_fin();
    t_k_killed_resets();
    t_k_no_node();
    t_ktcp_v6_real_dials_a_v6_node();
    t_ktcp_v6_real_without_v6_node_is_refused();
    t_ktcp_v4_real_unchanged();
    t_k_two_loops();
    t_k_flush_error();
    t_k_prefixes();
    mux_part();
    t_k_slot0_not_stop();
    t_k_stop_resets_sockets();
    ib_part();
    k_reset();
}

static struct conn *key_link(const struct flow_key *k) {
    struct conn *c = conn_new(&g_tun);
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->fd = -1;
    c->key = *k;
    conn_link(c);
    return c;
}

static void t_v4_and_v6_keys_differ(void) {
    struct flow_key a = cli_key(), b = cli_key();
    memset(&a.src, 0, sizeof a.src);
    memset(&a.dst, 0, sizeof a.dst);
    memset(&b.src, 0, sizeof b.src);
    memset(&b.dst, 0, sizeof b.dst);
    a.src.v4 = 0x0a000001u;
    memcpy(b.src.b + 12, &a.src.v4, 4);
    b.v6 = 1;
    struct conn *ca = key_link(&a);
    check(conn_find(&a) == ca && conn_find(&b) == NULL,
          "a v4 key and a v6 key with the same four bytes are different flows");

    struct flow_key c6 = b, d6 = b;
    c6.dst.b[0] = 0x20;
    d6.dst.b[0] = 0x30;
    struct conn *cc = key_link(&c6);
    struct conn *cd = key_link(&d6);
    check(cc != cd && conn_find(&c6) == cc && conn_find(&d6) == cd && conn_find(&b) == NULL,
          "two v6 keys differing in one leading address byte are found separately");
    struct flow_key l1 = b, l2 = b;
    l1.dst.b[15] = 1;
    l2.dst.b[15] = 2;
    struct conn *cl = key_link(&l1);
    check(!fk_same_addr(&l1.dst, &l2.dst) && flow_hash(&l1) != flow_hash(&l2) &&
              conn_find(&l1) == cl && conn_find(&l2) == NULL,
          "two v6 keys differing only in the last address byte are separate flows");
    struct flow_key e = a;
    e.v6 = 1;
    check(conn_find(&e) == NULL, "identical address bytes with the v6 byte set are another flow");
    while (g_live_n) conn_drop(&g_conns[g_live[g_live_n - 1]]);
    dev_drain(NULL);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);       /* a crash or a hang keeps the checks printed so far */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0 || pipe(g_sess_pipe) != 0) return 2;
    if (write(g_sess_pipe[1], "x", 1) != 1) return 2;
    memset(&g_tun, 0, sizeof(g_tun));
    g_tun.fd = sp[0];
    g_dev_peer = sp[1];
    snprintf(g_node.uuid, sizeof(g_node.uuid), "8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124");
    snprintf(g_node.host, sizeof(g_node.host), "stand");
    /* What stack_run does before the threads: the dialer and the session stride. The spare pool
     * is off, so stack_setup allocates nothing for it. */
    g_spare_want = 0;
    stack_setup(&g_dial);
    if (conn_table_init() != 0) return 2;
    g_now_ns = now_ns();
    g_now_s = (time_t)(g_now_ns / 1000000000ull);

    t_no_connectors();
    t_v4_and_v6_keys_differ();
    t_sendagain_window();
    t_sendagain_retry();
    t_sendagain_eof();
    t_out_of_order_dupack();
    t_window_scale();
    t_release_last_sleep();
    t_bad_uuid();
    t_send_refused();
    t_dns_evict();
    t_spare_slot();
    t_spare_churn();
    t_host_is_atyp_domain();
    t_no_host_stays_ipv4();
    t_host_is_cleared_on_reuse();
    t_pin_carries_the_host();
    t_room_covers_a_long_host();
    t_room_vision_reserve();
    t_long_host_refused();
    t_host_needs_set_host();
    t_udp_early_bounds();
    t_server_first();
    t_server_first_from_ready();
    t_server_first_early_twin();
    t_server_first_early_refused();
    t_server_first_srv_closed();
    t_room_window();
    t_gather();
    t_up_cut();
    t_up_cut_partial();
    t_up_cut_resend_whole();
    t_up_cut_resend_wrap();
    t_up_cut_resend_early();
    t_up_cut_fatal();
    t_up_whole_packet_up();
    t_first_write_as_xray();
    t_first_write_cut_per_piece();
    t_first_write_room();
    t_first_write_second_refused();
    t_first_write_room_edge();
    t_first_write_room_grpc();
    t_up_write_size();
    t_vision_switch_up();
    t_vision_filter_up_after_padding();
    t_vision_filter_down_slices();
    t_vision_filter_down_xudp();
    t_vision_xudp_up();
    t_up_cut_grpc_room();
    t_stop_resets();
    t_stop_wakes_the_loop();
    t_due_wakes_loop();
    t_due_after_read();
    t_due_idle_latched();
    t_due_writable();
    t_due_fatal();
    t_server_first_wakes_loop();
    t_server_first_due_at_sleep();
    t_server_first_again_no_spin();
    t_room_held();
    if (stack_part() != 0) check(0, "fixture: loopback listener failed");
    sock_part();

    printf(g_fail ? "\ntunnelmatch: FAIL\n" : "\nall checks passed\n");
    return g_fail;
}
