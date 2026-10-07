/* The grpc transport (src/proto/transport/trgrpc.c).
 *
 * Framing: what grpc_wrap writes grpc_unwrap reads back, in chunks of any size, and a malformed
 * stream is refused rather than misread. The file is included for these static functions.
 *
 * The end of a stream: Xray (grpc-go) ends a stream whose target has closed by flushing the last
 * data, the closing HEADERS with END_STREAM and RST_STREAM(NO_ERROR) in ONE TLS record. The data
 * must be returned, not dropped with the reset (h2match tests that at the frame level), and once
 * the end is known it must be visible through transport_has_data: the socket stays silent after
 * the server has sent everything, and without it the client got no FIN until idle cleanup.
 *
 * The transport and h2.c are real; the link is plain (security=none) over a socket pair whose
 * other end the test writes HTTP/2 frames to by hand, in one write so that h2_read sees one
 * record. TLS and Reality are stubbed out: they are never reached. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "../src/proto/transport/trgrpc.c"
#include "reality.h"

/* ---- TLS and Reality stubs: the test link is plain ---------------------------------- */

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)out; (void)out_n; *out_len = 0; return -1; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)car; (void)out; (void)out_n; *out_len = 0; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth)
    { (void)t; (void)fd; (void)ch; (void)n; (void)ss; (void)auth; return -1; }
const char *tls13_verify_reason(void) { return ""; }
int xc_b64url_decode(const char *in, unsigned char *out, size_t out_n)
    { (void)in; (void)out; (void)out_n; return -1; }
int tls13_has_record(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_buffered(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap)
    { (void)t; (void)out; (void)cap; return 0; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n)
    { (void)t; (void)d; (void)n; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t cap, size_t *got)
    { (void)t; (void)o; (void)cap; *got = 0; return -1; }
int tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *bn)
    { (void)t; *b = NULL; *bn = 0; return -1; }
void tls13_free(struct tls13 *t) { (void)t; }

static int fails;

static void check(int ok, const char *what) {
    printf("%-84s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

/* ---- framing ------------------------------------------------------------------------- */

/* Feed in to a fresh decoder in pieces of step bytes; the decoded bytes go to out. */
static int unwrap_steps(const unsigned char *in, size_t n, size_t step, unsigned char *out,
                        size_t cap, size_t *out_n) {
    struct grpc_de de;
    memset(&de, 0, sizeof(de));
    *out_n = 0;
    for (size_t i = 0; i < n; i += step) {
        size_t k = n - i < step ? n - i : step, got = 0;
        int rc = grpc_unwrap(&de, in + i, k, out + *out_n, cap - *out_n, &got);
        if (rc) return rc;
        *out_n += got;
    }
    return 0;
}

/* A message whose field length is written as a varint of exactly len_bytes bytes (padded with
 * continuation bytes, as protobuf allows for a non-minimal encoding). */
static size_t msg_with_varint(unsigned char *out, const char *data, int len_bytes) {
    size_t dn = strlen(data), o = 5;
    out[o++] = 0x0A;
    uint32_t v = (uint32_t)dn;
    for (int b = 0; b < len_bytes; b++) {
        unsigned char c = (unsigned char)(v & 0x7F);
        v >>= 7;
        if (b < len_bytes - 1) c |= 0x80;
        out[o++] = c;
    }
    memcpy(out + o, data, dn);
    o += dn;
    size_t msg = o - 5;
    out[0] = 0;
    out[1] = (unsigned char)(msg >> 24); out[2] = (unsigned char)(msg >> 16);
    out[3] = (unsigned char)(msg >> 8);  out[4] = (unsigned char)msg;
    return o;
}

static void t_framing(void) {
    unsigned char wire[4096], back[4096], data[1000];
    size_t got = 0;
    for (size_t i = 0; i < sizeof(data); i++) data[i] = (unsigned char)(i * 7 + 3);

    size_t wn = grpc_wrap(data, sizeof(data), wire, sizeof(wire));
    check(wn == 5 + 1 + 2 + sizeof(data), "wrap: header, tag, 2-byte length, data");
    int bad = 0;
    for (size_t step = 1; step <= wn; step += (step < 16 ? 1 : 97)) {
        if (unwrap_steps(wire, wn, step, back, sizeof(back), &got) != 0 || got != sizeof(data) ||
            memcmp(back, data, sizeof(data)) != 0)
            bad = 1;
    }
    check(!bad, "unwrap: the data back, in pieces of any size");

    size_t mn = msg_with_varint(wire, "hello", 5);
    check(unwrap_steps(wire, mn, mn, back, sizeof(back), &got) == 0 && got == 5 &&
          !memcmp(back, "hello", 5), "a 5-byte length varint is read");
    mn = msg_with_varint(wire, "hello", 6);
    check(unwrap_steps(wire, mn, mn, back, sizeof(back), &got) == TR_EGRPC,
          "a 6-byte length varint is refused, not shifted past 32 bits");
    mn = msg_with_varint(wire, "hello", 7);
    check(unwrap_steps(wire, mn, 1, back, sizeof(back), &got) == TR_EGRPC,
          "a 7-byte varint is refused, byte by byte too");

    mn = msg_with_varint(wire, "hello", 1);
    wire[5] = 0x12;                                        /* field 2 */
    check(unwrap_steps(wire, mn, mn, back, sizeof(back), &got) == TR_EGRPC,
          "a field other than 1 is refused");
    mn = msg_with_varint(wire, "hello", 1);
    wire[0] = 1;                                           /* compressed */
    check(unwrap_steps(wire, mn, mn, back, sizeof(back), &got) == TR_EGRPC,
          "a compressed message is refused");

}

/* ---- the end of a stream over the real transport -------------------------------------- */

static int g_srv = -1;                /* the "server" end of the socket pair */

static void srv_drain(void) {
    unsigned char b[8192];
    while (recv(g_srv, b, sizeof(b), MSG_DONTWAIT) > 0) {}
}

static void s_put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

static size_t frame(unsigned char *out, unsigned char type, unsigned char flags, uint32_t sid,
                    const unsigned char *body, size_t n) {
    out[0] = (unsigned char)(n >> 16); out[1] = (unsigned char)(n >> 8); out[2] = (unsigned char)n;
    out[3] = type; out[4] = flags;
    s_put32(out + 5, sid);
    if (n) memcpy(out + 9, body, n);
    return 9 + n;
}

/* A gRPC message holding Hunk { data = d }: [0][length u32][0x0A][varint length][data]. */
static size_t grpc_msg(unsigned char *out, const char *d) {
    size_t n = strlen(d);
    out[0] = 0;
    s_put32(out + 1, (uint32_t)(2 + n));      /* short data: the tag and a one-byte length */
    out[5] = 0x0A;
    out[6] = (unsigned char)n;
    memcpy(out + 7, d, n);
    return 7 + n;
}

#define FRH 0x01
#define FRD 0x00
#define FRR 0x03
#define FEND_HEADERS 0x04
#define FEND_STREAM  0x01

static int open_stream(struct transport *c) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    if (g_srv >= 0) close(g_srv);
    g_srv = sp[1];
    /* A read deadline: with the bug, a read nothing wakes would hang instead of failing. */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sp[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    memset(c, 0, sizeof(*c));
    c->fr = &tr_grpc;
    c->link.fd = sp[0];
    c->link.plain = 1;
    struct tr_node n;
    memset(&n, 0, sizeof(n));
    n.host = "stand.example"; n.sni = "stand.example"; n.service = "svc"; n.mode = "gun";
    int rc = tr_grpc.open(c, &n, 5);
    srv_drain();
    return rc;
}

static void t_end_in_one_record(int with_rst, int with_end_stream, const char *what) {
    struct transport c;
    check(open_stream(&c) == 0, "stream opened");
    unsigned char w[512];
    size_t n = 0;
    static const unsigned char ok[1] = { 0x88 };
    n += frame(w + n, FRH, FEND_HEADERS, 1, ok, 1);                       /* :status 200 */
    unsigned char m[64];
    size_t mn = grpc_msg(m, "hello");
    n += frame(w + n, FRD, 0, 1, m, mn);
    if (with_end_stream) n += frame(w + n, FRH, FEND_HEADERS | FEND_STREAM, 1, ok, 1);
    if (with_rst) { unsigned char z[4] = { 0, 0, 0, 0 }; n += frame(w + n, FRR, 0, 1, z, 4); }
    if (write(g_srv, w, n) != (ssize_t)n) { perror("write"); exit(2); }

    unsigned char buf[TRANSPORT_MIN_READ_CAP];
    size_t got = 0;
    int rc = transport_read(&c, buf, sizeof(buf), &got);
    char line[200];
    snprintf(line, sizeof(line), "%s: 'hello' is returned, not lost", what);
    check(rc == 0 && got == 5 && !memcmp(buf, "hello", 5), line);
    if (with_rst || with_end_stream) {
        snprintf(line, sizeof(line), "%s: the end is visible without a socket event", what);
        check(transport_has_data(&c) == 1, line);
        rc = transport_read(&c, buf, sizeof(buf), &got);
        snprintf(line, sizeof(line), "%s: the next read is the end of the stream", what);
        check(rc == H2_ERESET, line);
    } else {
        snprintf(line, sizeof(line), "%s: no end, has_data says nothing", what);
        check(transport_has_data(&c) == 0, line);
    }
    transport_close(&c);
}

/* A response of closing HEADERS only (the server refused the method): no data, stream over. */
static void t_trailers_only(const char *what) {
    struct transport c;
    check(open_stream(&c) == 0, "stream opened");
    unsigned char w[64];
    static const unsigned char ok[1] = { 0x88 };
    size_t n = frame(w, FRH, FEND_HEADERS | FEND_STREAM, 1, ok, 1);
    if (write(g_srv, w, n) != (ssize_t)n) { perror("write"); exit(2); }
    unsigned char buf[TRANSPORT_MIN_READ_CAP];
    size_t got = 0;
    int rc = transport_read(&c, buf, sizeof(buf), &got);
    int pend = transport_has_data(&c);
    int rc2 = transport_read(&c, buf, sizeof(buf), &got);
    char line[160];
    snprintf(line, sizeof(line), "%s: first read, no error and no data", what);
    check(rc == 0 && got == 0, line);
    snprintf(line, sizeof(line), "%s: the end is announced through has_data", what);
    check(pend == 1, line);
    snprintf(line, sizeof(line), "%s: the next read is the end of the stream", what);
    check(rc2 == H2_ERESET, line);
    transport_close(&c);
}

int main(void) {
    t_framing();
    t_end_in_one_record(1, 1, "data + END_STREAM + RST_STREAM in one record");
    t_end_in_one_record(0, 1, "data + END_STREAM without RST_STREAM");
    t_end_in_one_record(1, 0, "data + RST_STREAM without END_STREAM");
    t_end_in_one_record(0, 0, "data only");
    t_trailers_only("closing HEADERS only");
    if (fails) printf("\ngrpcmatch: %d FAILED\n", fails);
    else printf("\ngrpcmatch: all checks passed\n");
    return fails ? 1 : 0;
}
