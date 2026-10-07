/* A server's answer to an xhttp upload (stream-up and packet-up): a refusal must reach the sender.
 *
 * In stream-up and packet-up the upload goes over its own link, and its answers are read only by
 * up_drain, which runs as part of a write. The xhttp server answers 400 to a chunk with bad
 * padding; if up_drain drops that answer, the write reports success, and the node looks alive
 * while no data flows. packet-up is harder: the answer to a chunk arrives when the next chunk is
 * already open, so h2.c must not throw it away as a frame of another stream. The
 * tests/run-tunnel*.sh stands do not reach this: their fake server speaks bare TCP, not xhttp.
 *
 * The file includes the xhttp transport whole (src/proto/transport/trxhttp.c: up_drain and
 * up_request are static) and links the real h2.c and the other transport layers as separate
 * objects. The upload link is plain (as with security=none) on a socket pair: what the client
 * writes, the test reads (and looks for the request paths in), and the "server" writes HTTP/2
 * frames to the other end by hand. TLS and Reality are not needed and are stubbed out. No
 * header stubs are needed: tls13.h includes only src/lib/scrypto.h, which has no crypto library
 * types. No network and no privileges, so the test runs in `make test`. */
#include "../src/proto/transport/trxhttp.c"

#include <stdlib.h>
#include <sys/socket.h>
#include "reality.h"

/* ---- TLS and Reality stubs: the test link is plain, they are never reached --------- */

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)out; (void)out_n; *out_len = 0; return -1; }
/* trsec.c also calls the carrier variant (ALPN http/1.1 for ws and httpupgrade); not reached
 * here either. */
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)car; (void)out; (void)out_n; *out_len = 0; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth)
    { (void)t; (void)fd; (void)ch; (void)n; (void)ss; (void)auth; return -1; }
const char *tls13_verify_reason(void) { return ""; }
/* trsec.c parses the pqv key with it (reality.c); not reached here. */
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

/* ---- test -------------------------------------------------------------------------- */

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-74s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) g_fail = 1;
}

static int g_srv = -1;                /* the "server" end of the socket pair */

/* What the client has written since the pair was made: preface, HEADERS, DATA. Kept to look for
 * the request paths: HPACK sends them as plain literals (put_headers in h2.c). */
static unsigned char g_seen[65536];
static size_t g_seen_n;

static void srv_drain(void) {
    ssize_t r;
    while ((r = recv(g_srv, g_seen + g_seen_n, sizeof(g_seen) - g_seen_n, MSG_DONTWAIT)) > 0)
        g_seen_n += (size_t)r;
}

static int seen(const char *s) {
    return memmem(g_seen, g_seen_n, s, strlen(s)) != NULL;
}

/* Whether the client left unread bytes on its end: an answer up_drain never took. */
static int unread(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    return poll(&p, 1, 0) > 0;
}

/* HEADERS from the server on stream sid with one HPACK byte, a static index of :status:
 * 0x88 is 200, 0x8C is 400 (RFC 7541, Appendix A). */
static void srv_headers(uint32_t sid, unsigned char hpack, int end_stream) {
    unsigned char f[10] = { 0, 0, 1, 0x01, (unsigned char)(0x04 | (end_stream ? 0x01 : 0)),
                            (unsigned char)(sid >> 24), (unsigned char)(sid >> 16),
                            (unsigned char)(sid >> 8), (unsigned char)sid, hpack };
    if (write(g_srv, f, sizeof(f)) != (ssize_t)sizeof(f)) { perror("write"); exit(2); }
}

/* RST_STREAM(NO_ERROR) from the server on stream sid. */
static void srv_rst(uint32_t sid) {
    unsigned char f[13] = { 0, 0, 4, 0x03, 0, (unsigned char)(sid >> 24),
                            (unsigned char)(sid >> 16), (unsigned char)(sid >> 8),
                            (unsigned char)sid, 0, 0, 0, 0 };
    if (write(g_srv, f, sizeof(f)) != (ssize_t)sizeof(f)) { perror("write"); exit(2); }
}

static void conn_init(struct transport *c, enum xhttp_mode xh, int fd) {
    memset(c, 0, sizeof(*c));
    c->link.fd = -1;
    c->fr = &tr_xhttp;
    c->xh.mode = xh;
    c->xh.up.link.fd = fd;
    c->xh.up.link.plain = 1;
    snprintf(c->xh.authority, sizeof(c->xh.authority), "stand.example");
    snprintf(c->xh.up_path, sizeof(c->xh.up_path), "/xh/0f1e2d3c");
}

static int new_pair(int *cli) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    if (g_srv >= 0) close(g_srv);
    g_srv = sp[1];
    g_seen_n = 0;
    *cli = sp[0];
    return 0;
}

static const unsigned char piece[] = "upload chunk";

/* packet-up: the answer to chunk 0 arrives when chunk 1 is already open. */
static void t_packet_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0, stream 1 */
    srv_drain();
    srv_headers(1, hpack, 1);                                /* answer to chunk 0 */
    int rc1 = transport_write(&c, piece, sizeof(piece));     /* chunk 1, stream 3 */
    srv_drain();
    if (want_refused)
        check(rc0 == 0 && rc1 == H2_ESTATUS &&
              strstr(transport_strerror(rc1), "400") != NULL, what);
    else
        check(rc0 == 0 && rc1 == 0 && !unread(fd), what);
    if (!want_refused)
        check(seen("/xh/0f1e2d3c/0") && seen("/xh/0f1e2d3c/1") && !seen("/xh/0f1e2d3c/2"),
              "packet-up: the two chunks go as requests numbered 0 and 1");
    close(fd);
}

/* packet-up: the answer to a chunk already in the socket when the chunk is written, ended by
 * RST_STREAM(NO_ERROR) as a Go server ends a finished handler's stream. up_drain then sees the
 * reset on the current stream: the normal end of an answer, not a failure of the write. */
static void t_packet_up_rst(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    srv_headers(1, 0x88, 1);
    srv_rst(1);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0 reads its own answer */
    srv_drain();
    int rc1 = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    check(rc0 == 0 && rc1 == 0 && !unread(fd),
          "packet-up: a chunk's 200 ended by RST_STREAM(NO_ERROR) is read, not a refusal");
    close(fd);
}

/* packet-up with the connection window too small for a chunk: the write is refused before its
 * request opens, so the retry opens chunk 1 once, not a second stream for it. */
static void t_packet_up_window(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0, stream 1 */
    srv_drain();
    srv_headers(1, 0x88, 1);
    int32_t win = c.xh.up.h2.send_win_conn;
    c.xh.up.h2.send_win_conn = (int32_t)sizeof(piece) - 1;
    int rc1 = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    int opened = seen("/xh/0f1e2d3c/1");
    c.xh.up.h2.send_win_conn = win;
    int rc2 = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    check(rc0 == 0 && rc1 == H2_EWINDOW && !opened,
          "packet-up: a chunk the window cannot take opens no request");
    check(rc2 == 0 && seen("/xh/0f1e2d3c/1") && !seen("/xh/0f1e2d3c/2"),
          "packet-up: the retry sends it as chunk 1");
    close(fd);
}

/* stream-up: one long POST, and the refusal comes on that same stream. */
static void t_stream_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_STREAM_UP, fd);
    int ro = up_request(&c, -1);                        /* as up_open does: the POST opens at once */
    srv_drain();
    srv_headers(1, hpack, 0);
    int rc = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    if (want_refused)
        check(ro == 0 && rc == H2_ESTATUS && strstr(transport_strerror(rc), "400") != NULL, what);
    else
        check(ro == 0 && rc == 0 && !unread(fd), what);
    close(fd);
}

/* packet-up: the server answers chunks in any order. Here the CURRENT chunk (stream 3) is
 * answered first, and the older one (stream 1) in a later read. up_drain used to stop once the
 * current stream was done, so the older answer stayed unread: the chunk counted as unanswered for
 * good, the window over seq filled, and the upload stalled with no chunk left to send. */
static void t_packet_up_order(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0, stream 1 */
    int rc1 = transport_write(&c, piece, sizeof(piece));     /* chunk 1, stream 3 */
    srv_drain();
    srv_headers(3, 0x88, 1);                                 /* the newer chunk first */
    long r1 = transport_room(&c);
    srv_headers(1, 0x88, 1);                                 /* then the older one */
    long r2 = transport_room(&c);
    check(rc0 == 0 && rc1 == 0 && r1 >= 0 && r2 > 0 && h2_open_streams(&c.xh.up.h2) == 0 &&
          !unread(fd), "packet-up: an older chunk's 200 after the current one's is read");
    close(fd);
}

int main(void) {
    t_packet_up_order();
    t_packet_up(0x8C, 1, "packet-up: 400 to the previous chunk fails the next write, naming 400");
    t_packet_up(0x88, 0, "packet-up: 200 to the previous chunk is read and is not a refusal");
    t_packet_up_window();
    t_packet_up_rst();
    t_stream_up(0x8C, 1, "stream-up: 400 to the upload fails the write, naming 400");
    t_stream_up(0x88, 0, "stream-up: 200 to the upload is read and is not a refusal");
    printf(g_fail ? "\nxhupmatch: FAILED\n" : "\nall checks passed\n");
    return g_fail;
}
