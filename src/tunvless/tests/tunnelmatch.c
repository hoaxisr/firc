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
#include "client.h"
#include "../src/tunnel/pool.c"

/* ---- faked node connection ----------------------------------------------------- */

static int g_sess_pipe[2] = { -1, -1 };
static int g_send_rc;                 /* what transport_write returns: 0 or H2_EWINDOW */
static int g_send_again_n;            /* return H2_EWINDOW this many times, then 0 */
static int g_send_calls;
static size_t g_send_last_n;          /* length of the last transport_write */
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
    return 0;
}
int transport_write(struct transport *c, const unsigned char *d, size_t n) {
    g_send_calls++;
    g_send_last_n = n;
    if (g_send_hold) return H2_EWINDOW;
    if (g_send_again_n > 0) { g_send_again_n--; return H2_EWINDOW; }
    if (!g_send_rc && g_wire_on && g_wire_n + n <= sizeof g_wire && g_wlog_n < 8192) {
        g_wlog[g_wlog_n].t = c;
        g_wlog[g_wlog_n].off = g_wire_n;
        g_wlog[g_wlog_n++].n = n;
        memcpy(g_wire + g_wire_n, d, n);
        g_wire_n += n;
    }
    return g_send_rc;
}
int transport_read_zc(struct transport *c, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got) {
    (void)c; (void)buf; (void)cap;
    g_recv_calls++;
    if (g_room_on_read != -2) { g_room = g_room_on_read; g_room_on_read = -2; }
    *got = 0;
    if (g_recv_rc) return g_recv_rc;
    *data = g_recv_buf;
    *got = g_recv_n;
    g_recv_n = 0;
    return 0;
}
int transport_has_data(const struct transport *c) { (void)c; return 0; }
long transport_room(struct transport *c) { (void)c; return g_room; }
void transport_close(struct transport *c) {
    if (__atomic_load_n(&g_own_fd, __ATOMIC_ACQUIRE) && c->link.fd >= 0 && c->link.fd != g_sess_pipe[0])
        close(c->link.fd);
    c->link.fd = -1;
}
void transport_moved(struct transport *c) { (void)c; }
void transport_direct(struct transport *c) { c->link.rx_direct = 1; }
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
static struct conn *open_conn(uint16_t win) {
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    cli_send(1000, 0, TCP_SYN, win, NULL, 0);
    c = conn_find(&k);
    if (!c || !c->pending || wait_ready(c, 2000) != 0) return NULL;
    cli_send(1001, 2, TCP_ACK, win, NULL, 0);
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
    conn_deadlines(c, &g_tun, c->estab_ns + (SERVER_FIRST_MS / 2) * 1000000ull);
    snprintf(what, sizeof(what), "server first%s: nothing sent before %d ms", flow[0] ? ", Vision" : "",
             SERVER_FIRST_MS);
    check(g_send_calls == calls, what);
    conn_deadlines(c, &g_tun, c->estab_ns + (SERVER_FIRST_MS + 50) * 1000000ull);
    const struct vl_sess *vs = SESS(c);
    snprintf(what, sizeof(what), "server first%s: then the %zu-byte header alone",
             flow[0] ? ", Vision" : "", header_n);
    check(g_send_calls == calls + 1 && g_send_last_n == header_n && vs->header_sent, what);
    conn_deadlines(c, &g_tun, c->estab_ns + (SERVER_FIRST_MS + 100) * 1000000ull);
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
    check(c->client_seq == 1001 && g_up.c == NULL,
          "gather: a refused send when full, the next segment is not taken either");
    g_send_again_n = 0;
    conn_drop(c);
    dev_drain(NULL);
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
 * self-pointers are fixed by the transport (xhttp_moved, through the dialer's take) and checked in
 * tests/takematch.c on the real transport; the pool slot is the stack's job, checked here. */
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
static struct fnode g_fn[5];

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
static int f_has_data(const void *sess) { (void)sess; return 0; }
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

static int g_probes[5];                 /* probes per node */
static int g_hook_node = -1;
static const int *g_hook_sel;
static size_t g_hook_n;
static int f_probe(const void *node, int t, char *why, size_t n) {
    (void)t;
    g_probes[(const struct fnode *)node - g_fn]++;
    if ((const struct fnode *)node - g_fn == g_hook_node) {
        g_hook_node = -1;
        pool_select(g_hook_sel, g_hook_n);
    }
    if (((const struct fnode *)node)->alive) return 0;
    snprintf(why, n, "test node is silent");
    return -1;
}
static const char *f_name(const void *node) { return ((const struct fnode *)node)->name; }
static const struct pool_proto f_proto = { .ops = &f_ops, .probe = f_probe, .name = f_name };

static int g_cand[5] = { 0, 1, 2, 3, 4 };
static const void *f_at(int i) { return &g_fn[i]; }

/* A fresh pool: `active` slots, candidates 0..ncand-1, node 0 chosen at startup. */
static void pool_new_ex(int active, int by, int ncand, int checked) {
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
        .proto = &f_proto, .node = f_at, .sel = g_cand,
        .sel_n = (size_t)ncand, .first = 0, .checked = checked, .active = active, .by = by,
        .interval_s = 60, .silence_s = 20,
    };
    const struct dialer *d = pool_setup(&pc);
    g_spare_want = 0;
    stack_setup(d);
}
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
    check(!g_pl.slot[0].up && g_pl.slot[0].node == 0 && g_pl.slot[0].due >= t0 + 15000 &&
              g_pl.slot[0].due <= t1 + 15000 && g_pl.slot[0].retry == 30,
          "no replacement answers — the slot waits 15 s for the next round, the pause doubles");
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
    check(g_pl.slot[2].up && g_pl.slot[2].node == 3 && g_pl.said_up == 1,
          "a round: the slot's own node answers again — the slot lives on it, the pool is up again");
    g_fn[4].alive = 1;
    ep = __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE);
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 4 &&
              __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE) != ep,
          "a round: a free candidate answers — the slot takes it, the stack is told");
    check(pl_stale(&g_pl, &on_dead), "  connections bound to the slot's dead node are stale then");
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
    t_addr6_of();
}

static void pool_part(void) {
    t_pool_setup();
    t_pool_stale();
    t_pool_pick();
    t_pool_refill();
    t_pool_dead_slot_refuses();
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
    for (int i = 0; i < 5; i++) {
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

/* Catches a room that reserves 64 bytes for a request header that carries a 255-byte host. */
static void t_room_covers_a_long_host(void) {
    long bare = 0;
    check(room_send(0, &bare) == SEND_OK && bare == TUNNEL_BUF - 64,
          "a first write of the whole room with a 255-byte host is sent; no host keeps 64");
    check(room_send(1, NULL) == SEND_OK, "  and with Vision too");
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
    uint32_t r = 0;
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
    rl.rlim_cur = 780;
    setrlimit(RLIMIT_NOFILE, &rl);
    park_cap_init();
    int cap100 = g_park_cap;
    rl.rlim_cur = 680;
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
              g_park_n == 0 && ctlmap_answer(ip4(198, 18, 4, 9), &(uint32_t){ 0 }) == CM_NONE,
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
    t_k_two_loops();
    t_k_flush_error();
    t_k_prefixes();
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
    t_long_host_refused();
    t_host_needs_set_host();
    t_udp_early_bounds();
    t_server_first();
    t_room_window();
    t_gather();
    t_stop_resets();
    t_stop_wakes_the_loop();
    if (stack_part() != 0) check(0, "fixture: loopback listener failed");
    sock_part();

    printf(g_fail ? "\ntunnelmatch: FAIL\n" : "\nall checks passed\n");
    return g_fail;
}
