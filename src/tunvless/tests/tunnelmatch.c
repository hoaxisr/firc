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
#include <sys/stat.h>
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

int vless_connect(const struct vless_node *node, struct transport *conn, int timeout_s) {
    (void)node; (void)timeout_s;
    memset(conn, 0, sizeof(*conn));
    conn->link.fd = g_sess_pipe[0];
    conn->link.plain = 1;
    return 0;
}
int transport_write(struct transport *c, const unsigned char *d, size_t n) {
    (void)c; (void)d;
    g_send_calls++;
    g_send_last_n = n;
    if (g_send_again_n > 0) { g_send_again_n--; return H2_EWINDOW; }
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
void transport_close(struct transport *c) { c->link.fd = -1; }   /* shared pipe: keep it open */
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
    k.src = CLI_IP; k.dst = SRV_IP; k.sport = CLI_PORT; k.dport = SRV_PORT; k.proto = 6;
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
static int stderr_has(void (*f)(void *), void *arg, const char *needle) {
    char path[] = "/tmp/tunnelmatch-err.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    fflush(stderr);
    int save = dup(2);
    dup2(fd, 2);
    f(arg);
    fflush(stderr);
    dup2(save, 2); close(save);
    char buf[4096];
    ssize_t r = pread(fd, buf, sizeof(buf) - 1, 0);
    close(fd); unlink(path);
    buf[r > 0 ? r : 0] = 0;
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

struct fsess { int fd; const struct fnode *node; int flow_opens; };

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
static int f_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)k; (void)udp;
    struct fsess *s = sess;
    s->node = ctx;
    s->flow_opens++;
    return 0;
}
static int f_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                  const unsigned char *d, size_t n) {
    (void)ctx; (void)k; (void)udp;
    struct fsess *s = sess;
    return send(s->fd, d, n, MSG_NOSIGNAL) == (ssize_t)n ? SEND_OK : SEND_FATAL;
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
    .deliver = f_deliver, .lost = f_lost,
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
    k.src = CLI_IP; k.dst = dst; k.sport = sport; k.dport = 443; k.proto = 6;
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
        k.dst = htonl(0x5db80000u + (uint32_t)i * 7919u);
        k.sport = (uint16_t)(1000 + i);
        at[i] = pl_pick(&k);
        k.sport = (uint16_t)(2000 + i);
        k.src = htonl(0x0a000099u);
        if (pl_pick(&k) != at[i]) same = 0;
        k.src = CLI_IP;
        per[at[i]]++;
    }
    check(same, "by site: a site stays on one node whatever the port and the client");
    check(per[0] > 30 && per[1] > 30 && per[2] > 30, "by site: sites spread over all three nodes");
    g_pl.slot[1].up = 0;
    int kept = 1, moved = 1;
    for (int i = 0; i < 200; i++) {
        k.dst = htonl(0x5db80000u + (uint32_t)i * 7919u);
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
    k.dst = htonl(0x5db80001u);
    int seen[3] = { 0, 0, 0 }, stable = 1;
    for (uint32_t c = 0; c < 60; c++) {
        k.src = htonl(0x0a000002u + c);
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
    check(pl_connect(&g_pl, src, 1) == TR_ECONNECT && s->slot == -1, "no live node — no spare is opened");
    g_pl.slot[0].up = g_pl.slot[1].up = 1;

    /* A streak of failed connects brings the check forward. */
    g_pl.slot[0].kick = 0;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    pl_seen(d, -1);
    pl_seen(d, -1);
    check(!g_pl.slot[0].kick, "two failed connects — no early check yet");
    pl_seen(d, 0);
    pl_seen(d, -1);
    pl_seen(d, -1);
    check(!g_pl.slot[0].kick, "a successful connect breaks the streak");
    pl_seen(d, -1);
    check(g_pl.slot[0].kick == 1, "three failed connects in a row — check the node now");
    g_pl.slot[0].kick = 0;
    pl_seen(d, 0);
    struct pl_sess former = *d;                 /* a connection to the slot's previous node */
    former.gen--;
    for (int i = 0; i < 3; i++) pl_seen(&former, -1);
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
    check(stdout_has(publish, NULL, "{\"type\":\"active\",\"nodes\":[\"n3\",\"n1\"],\"index\":[3,1]}"),
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
    check(stdout_has(check0, NULL, "{\"type\":\"active\",\"nodes\":[],\"index\":[]}"),
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

static void pool_part(void) {
    t_pool_setup();
    t_pool_stale();
    t_pool_pick();
    t_pool_refill();
    t_pool_spares();
    t_pool_log();
    t_pool_swap();
    t_pool_swap_grow();
    t_pool_swap_races();
    t_pool_swap_events();
    t_pool_threads();
}

/* ---- stack --------------------------------------------------------------------------------- */

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
    t_ack_paced();
    pool_part();
    return 0;
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
    t_udp_early_bounds();
    t_server_first();
    t_room_window();
    t_gather();
    if (stack_part() != 0) check(0, "fixture: loopback listener failed");

    printf(g_fail ? "\ntunnelmatch: FAIL\n" : "\nall checks passed\n");
    return g_fail;
}
