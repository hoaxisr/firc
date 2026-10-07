/* xudpprobe <vless:// link> <address> <port> [N]: send UDP datagrams through the VLESS dialer
 * (vldial.c) to a real server and print the answers; exit code 0 — every answer arrived.
 *
 * The dialer is driven directly (connect, flow_open, dgram_frame, send, read, deliver), without TUN
 * or the stack: on the wire this is what the stack does, with no device to bring up (impossible
 * without root anyway). It checks exactly what the client sends and parses: a node with
 * flow=xtls-rprx-vision carries UDP as the Mux command with XUDP frames (vldial.c, the XUDP
 * part), a node without flow as command 2.
 *
 * N datagrams one at a time, each waiting for its echo. BURST=1 instead sends three datagrams in
 * ONE send call (as the stack's early_hold joins them during the handshake) and then a 1400-byte
 * datagram: frames of several datagrams in one write, and a frame that does not fit into one TLS
 * record with a small MTU.
 *
 * The stack is replaced by stubs below: vldial.c calls two of its functions, and the stack is
 * not linked in. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include "vless.h"
#include "vldial.h"
#include "dialer.h"
#include "stack.h"

time_t stack_now_s(void) { return time(NULL); }
int stack_run(const struct tun_cfg *tc, const struct dialer *d, stack_ready_fn ready, void *arg) {
    (void)tc; (void)d; (void)ready; (void)arg;
    return 1;
}

static int g_got;
static int emit(void *arg, const unsigned char *p, size_t n) {
    (void)arg;
    g_got++;
    printf("  answer %d: %zu bytes: %.*s\n", g_got, n, (int)(n > 40 ? 40 : n), p);
    return 0;
}

/* Read and parse whatever arrives within ~100 ms. -11 from read means "no data yet", not a
 * failure. */
static int pump(const struct dialer_ops *ops, const struct vless_node *n, void *sess) {
    static unsigned char rx[65536];
    struct pollfd p = { .fd = ops->fd(sess), .events = POLLIN };
    if (poll(&p, 1, 100) <= 0 && !ops->has_data(sess)) return 0;
    const unsigned char *data = NULL;
    size_t got = 0;
    int rr = ops->read(sess, rx, sizeof rx, &data, &got);
    if (rr != 0 && rr != -11) { printf("read: rc=%d\n", rr); return -1; }
    if (got && ops->deliver(n, sess, 1, data, got, emit, NULL) != 0) { printf("deliver: end of stream\n"); return -1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "xudpprobe <link> <address> <port> [N]\n"); return 2; }
    struct vless_node n;
    int rc = vless_parse_url(argv[1], &n);
    if (rc) { printf("node unusable: rc=%d %s\n", rc, n.skip_reason); return 2; }
    struct flow_key k;
    memset(&k, 0, sizeof k);
    inet_pton(AF_INET, "10.99.1.9", &k.src);
    inet_pton(AF_INET, argv[2], &k.dst);
    k.sport = 40000;
    k.dport = (uint16_t)atoi(argv[3]);
    int cnt = argc > 4 ? atoi(argv[4]) : 3;
    const struct dialer_ops *ops = &vless_dialer;
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    if (ops->connect(&n, sess, 10) != 0) { printf("connect: failed\n"); return 3; }
    if (ops->flow_open(&n, sess, &k, 1) != 0) { printf("flow_open: failed\n"); return 3; }

    if (getenv("BURST")) {
        unsigned char fr[4000];
        size_t fn = 0;
        for (int i = 0; i < 3; i++) {
            char msg[32];
            int ml = snprintf(msg, sizeof msg, "burst-%d", i);
            fn += ops->dgram_frame((unsigned char *)msg, (size_t)ml, fr + fn, sizeof fr - fn);
        }
        printf("burst send: rc=%d\n", ops->send(&n, sess, &k, 1, fr, fn));
        unsigned char big[1400];
        memset(big, 'B', sizeof big);
        fn = ops->dgram_frame(big, sizeof big, fr, sizeof fr);
        printf("big send: rc=%d\n", ops->send(&n, sess, &k, 1, fr, fn));
        for (int t = 0; t < 60 && g_got < 4; t++)
            if (pump(ops, &n, sess) != 0) return 4;
        printf(g_got == 4 ? "ok burst\n" : "FAIL burst: %d answers\n", g_got);
        ops->close(sess);
        return g_got == 4 ? 0 : 6;
    }
    for (int i = 0; i < cnt; i++) {
        char msg[64];
        int ml = snprintf(msg, sizeof msg, "xudp-ping-%d", i);
        unsigned char fr[200];
        size_t fn = ops->dgram_frame((unsigned char *)msg, (size_t)ml, fr, sizeof fr);
        printf("send %d: rc=%d\n", i, ops->send(&n, sess, &k, 1, fr, fn));
        int before = g_got;
        for (int t = 0; t < 30 && g_got == before; t++)
            if (pump(ops, &n, sess) != 0) return 4;
        if (g_got == before) { printf("no answer to %d\n", i); return 6; }
    }
    printf("ok: %d answers\n", g_got);
    ops->close(sess);
    return 0;
}
