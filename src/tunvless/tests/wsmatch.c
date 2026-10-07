/* The ws and httpupgrade transports: path, Upgrade request, 101 response, frames.
 *
 * Both kinds of error possible here look the same from outside: "the node does not work". With a
 * wrong path or request the Xray server answers 404 or silently drops the connection; with a
 * wrong frame gorilla on the other side closes the stream, and the only sign is lost traffic. So
 * the check is not "does it look like WebSocket" but a byte-exact match with a reference:
 *
 *   - the path (trpath.c) and the Upgrade request (trupgrade.c): against what Go itself prints.
 *     The values below come from a program on Go 1.22 net/url and net/http that repeats Xray's
 *     code (infra/conf Build, websocket/dialer.go with gorilla client.go, httpupgrade/dialer.go)
 *     with our Chrome version. The header order and the `%3F` of httpupgrade were also checked
 *     against a capture of real Xray 26.3.27 (in docker);
 *   - Sec-WebSocket-Accept: against the RFC 6455 example (1.3);
 *   - the client frame: against the RFC 6455 example (5.7, "Hello" with mask 37 fa 21 3d);
 *   - parsing server frames: fragments, a control frame inside a message, lengths 125/126/65536,
 *     feeding byte by byte, parsing in place, and every RFC violation on which gorilla drops the
 *     connection;
 *   - the 101 response and refusals: not 101 (the code in the error text), no Upgrade, a wrong
 *     Accept, timeout, server closed. Bytes after the response in the same read, for ws (the
 *     first frame) and for httpupgrade (the start of the stream), are not lost and show as
 *     readiness without the socket (transport_has_data);
 *   - ping -> pong with the same body and a mask, close -> a close in reply and end of stream.
 *
 * All transport layers are real and linked as separate objects. The link is security=none on a
 * real 127.0.0.1 socket: a server thread listens on a port, and transport_open dials it with the
 * usual tr_dial. TLS and Reality are not needed and are stubbed out; vlessmatch (make
 * crypto-test) checks ws and httpupgrade over tls and reality with the real library. No network
 * namespaces, privileges or docker: the test runs in `make test`. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <dirent.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "transport.h"
#include "trpath.h"
#include "reality.h"
#include "vless.h"

/* ---- TLS and Reality stubs: the test link is plain, they are never reached --------- */

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

static int g_fail, g_pass;
static void check(int ok, const char *what) {
    if (ok) { g_pass++; return; }
    printf("%-74s FAIL\n", what);
    g_fail = 1;
}
static void check_str(const char *what, const char *want, const char *got) {
    int ok = got && !strcmp(want, got);
    if (!ok) printf("  expected \"%s\"\n  got      \"%s\"\n", want, got ? got : "(NULL)");
    check(ok, what);
}

static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    int n = 0;
    if (!d) return -1;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

/* ---- 1. path ----------------------------------------------------------------------- */

/* Ed is Xray's uint32(strconv.Atoi(ed)): out of int64 range it is 0, never a wrapped value. */
static void test_ed(void) {
    static const struct { const char *path; uint32_t ed; } V[] = {
        { "/p?ed=2048", 2048 },
        { "/p?ed=9223372036854775807", 0xFFFFFFFFu },
        { "/p?ed=9223372036854775808", 0 },
        { "/p?ed=18446744073709551617", 0 },   /* 2^64 + 1: a wrapping parser gives 1 */
        { "/p?ed=184467440737095516160", 0 },
    };
    for (size_t i = 0; i < sizeof(V) / sizeof(*V); i++) {
        char out[256], what[128];
        uint32_t ed = 12345;
        int rc = tr_upgrade_target_ed(V[i].path, 1, out, sizeof(out), NULL, &ed);
        snprintf(what, sizeof(what), "Ed of '%s' is %u", V[i].path, V[i].ed);
        check(rc == 0 && ed == V[i].ed, what);
    }
}

static void test_path(void) {
    /* Node path, request target for ws, for httpupgrade. NULL: refused (url.Parse fails in Go). */
    static const struct { const char *path, *ws, *hu; } V[] = {
        { "", "/", "/" },
        { "/", "/", "/" },
        { "ws", "/ws", "/ws" },
        { "/p/q?x=1&ed=2048", "/p/q?x=1", "/p/q%3Fx=1" },
        { "/p?ed=2048", "/p", "/p" },
        { "/p?ed=", "/p?ed=", "/p%3Fed=" },
        { "/p?ed=abc&b=2&a=1&a=0", "/p?a=1&a=0&b=2", "/p%3Fa=1&a=0&b=2" },
        { "/a b?ed=1", "/a%20b", "/a%2520b" },
        { "/a%41?ed=1", "/a%41", "/a%2541" },
        { "/a%41", "/a%41", "/a%2541" },
        { "/a b", "/a%20b", "/a%20b" },
        { "/p?", "/p?", "/p%3F" },
        { "/p?x=a+b&ed=1", "/p?x=a+b", "/p%3Fx=a+b" },
        { "/p?x=%zz&ed=1&y=/", "/p?y=%2F", "/p%3Fy=%252F" },
        { "/\xd0\xb6?ed=9", "/%D0%B6", "/%25D0%25B6" },
        { "/a%zz", NULL, "/a%25zz" },
        { "/a%zz?ed=1", NULL, "/a%25zz%3Fed=1" },
        { "/p?q=1;2&ed=1&r", "/p?r=", "/p%3Fr=" },
        { "/(x)*!", "/(x)*!", "/%28x%29%2A%21" },
        { "/p?ed=1&ed=2&e=3", "/p?e=3", "/p%3Fe=3" },
        { "/a%4a?ed=1", "/a%4a", "/a%254a" },
        { "/p?x=a~b&ed=1", "/p?x=a~b", "/p%3Fx=a~b" },
    };
    for (size_t i = 0; i < sizeof(V) / sizeof(*V); i++) {
        char out[1024], what[160];
        for (int ws = 1; ws >= 0; ws--) {
            const char *want = ws ? V[i].ws : V[i].hu;
            int rc = tr_upgrade_target(V[i].path, ws, out, sizeof(out), NULL);
            snprintf(what, sizeof(what), "path '%s' for %s as Xray", V[i].path, ws ? "ws" : "httpupgrade");
            if (!want) check(rc != 0, what);
            else if (rc != 0) check(0, what);
            else check_str(what, want, out);
        }
    }
    /* Every refusal with its reason. The reason becomes the node's skip_reason (upg_node_bad in
     * sublink.c), so it must name what is wrong and fit there whole. The first four are paths
     * Xray would parse ambiguously; they are not in the Go table. "path too long" has three
     * causes: the path over the 1 KB buffers, a query of more pairs than strip_ed holds, and an
     * out buffer too small for the result. */
    static char huge[1100], pairs[160];
    memset(huge, 'a', sizeof(huge) - 1);
    huge[0] = '/';
    strcpy(pairs, "/p?");
    for (int i = 0; i < 65; i++) strcat(pairs, "a&");
    strcat(pairs, "ed=1");
    const struct { const char *path; int ws; size_t cap; const char *why, *note; } bad[] = {
        { "/a\nb", 1, 64, "control character in path", "" },
        { "/a#b", 1, 64, "# in path", "" },
        { "//h/p", 1, 64, "path starts with //", "" },
        { "a:b/c", 1, 64, "path has : before its first /", "" },
        { "/a%zz", 1, 64, "bad %XX in path", "" },
        { huge, 0, 2048, "path too long", " (over 1 KB)" },
        { pairs, 1, 2048, "path too long", " (65 query pairs)" },
        { "/long/path", 1, 4, "path too long", " (out too small)" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        char out[2048], what[96];
        const char *why = NULL;
        int rc = tr_upgrade_target(bad[i].path, bad[i].ws, out, bad[i].cap, &why);
        snprintf(what, sizeof(what), "refused, reason \"%s\"%s", bad[i].why, bad[i].note);
        check_str(what, bad[i].why, rc != 0 && why ? why : "(not refused)");
        snprintf(what, sizeof(what), "the reason \"%s\"%s fits skip_reason whole", bad[i].why,
                 bad[i].note);
        check(why && strlen(why) < sizeof(((struct vless_node *)0)->skip_reason), what);
    }

    /* Ed as Xray's Build computes it: uint32(strconv.Atoi(the first ed value)) when ed is
     * stripped. */
    static const struct { const char *path; uint32_t ed; } E[] = {
        { "/w?ed=2048", 2048 }, { "/w?x=1&ed=16", 16 }, { "/w?ed=", 0 }, { "/w?ed=abc", 0 },
        { "/w?ed=+5", 0 } /* query '+' is a space */, { "/w?ed=%2B5", 5 }, { "/w?ed=-1", 4294967295u }, { "/w?ed=4294967296", 0 }, { "/w", 0 },
        { "/a%zz?ed=9", 0 }, { "/w?ed=7&ed=9", 7 }, { "/w?ed=12x", 0 },
        { "/w?ed=-9223372036854775809", 0 },
    };
    for (size_t i = 0; i < sizeof(E) / sizeof(*E); i++) {
        char out[256], what[96];
        uint32_t ed = 7;
        tr_upgrade_target_ed(E[i].path, 0, out, sizeof(out), NULL, &ed);
        snprintf(what, sizeof(what), "Ed of path '%s' is %u, as in Xray", E[i].path, E[i].ed);
        check(ed == E[i].ed, what);
    }
}

/* ---- 2. Upgrade request ------------------------------------------------------------ */

#define UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
#define CH "\"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\""

static void node0(struct tr_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    n->host = "127.0.0.1"; n->port = 1; n->type = type; n->security = "none";
    n->sni = ""; n->fp = ""; n->pbk = ""; n->sid = ""; n->path = "/w"; n->service = ""; n->mode = "";
}

static void test_request(void) {
    struct tr_node n;
    char out[4096];
    const char *key = "dGhlIHNhbXBsZSBub25jZQ==";

    node0(&n, "ws");
    n.path = "/w?ed=2048";
    n.http_host = "cdn.example.com";
    n.headers = "x-custom: v1\naccept: text/x\n";
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check_str("ws: request as Xray's (own headers canonicalized, the node's Accept wins)",
        "GET /w HTTP/1.1\r\n"
        "Host: cdn.example.com\r\n"
        "User-Agent: " UA "\r\n"
        "Accept: text/x\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: Upgrade\r\n"
        "DNT: 1\r\n"
        "Pragma: no-cache\r\n"
        "Sec-CH-UA: " CH "\r\n"
        "Sec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\n"
        "Sec-Fetch-Dest: empty\r\n"
        "Sec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Upgrade: websocket\r\n"
        "X-Custom: v1\r\n"
        "\r\n", out);

    node0(&n, "httpupgrade");
    n.path = "/w?ed=2048";
    n.http_host = "cdn.example.com";
    n.headers = "x-custom: v1\nPragma: p\n";
    tr_h1_request(&n, 0, NULL, NULL, out, sizeof(out));
    check_str("httpupgrade: request as Xray's (own key as written, the node's Pragma wins)",
        "GET /w HTTP/1.1\r\n"
        "Host: cdn.example.com\r\n"
        "User-Agent: " UA "\r\n"
        "Accept: */*\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: Upgrade\r\n"
        "DNT: 1\r\n"
        "Pragma: p\r\n"
        "Sec-CH-UA: " CH "\r\n"
        "Sec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\n"
        "Sec-Fetch-Dest: empty\r\n"
        "Sec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\n"
        "Upgrade: websocket\r\n"
        "x-custom: v1\r\n"
        "\r\n", out);

    node0(&n, "ws");
    n.http_host = "h";
    n.headers = "User-Agent: MyUA/1\n";
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check_str("ws: own User-Agent, no browser look",
        "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: MyUA/1\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Upgrade: websocket\r\n\r\n", out);

    node0(&n, "httpupgrade");
    n.http_host = "h";
    n.headers = "user-agent: MyUA/1\n";
    tr_h1_request(&n, 0, NULL, NULL, out, sizeof(out));
    check(strstr(out, "\r\nUser-Agent: " UA "\r\n") && strstr(out, "\r\nuser-agent: MyUA/1\r\n"),
          "httpupgrade: lowercase user-agent not recognized (as in Go), browser look kept");

    /* Host: host, else sni, else the node address. */
    node0(&n, "ws");
    n.sni = "mask.example";
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check(strstr(out, "\r\nHost: mask.example\r\n") != NULL, "Host without host: sni");
    node0(&n, "ws");
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check(strstr(out, "\r\nHost: 127.0.0.1\r\n") != NULL, "Host without host or sni: node address");
    node0(&n, "ws");
    n.host = "2001:db8::1";
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check(strstr(out, "\r\nHost: [2001:db8::1]\r\n") != NULL, "Host of an IPv6 node in brackets");

    char small[64];
    node0(&n, "ws");
    check(tr_h1_request(&n, 1, key, NULL, small, sizeof(small)) == 0, "request too long: 0, not cut");

    /* Early data, and the looks picked by a word in User-Agent: against the same Go program
     * (net/http, Xray's browser.go and dialer.go with our built-in versions). */
    node0(&n, "ws");
    n.http_host = "h";
    tr_h1_request(&n, 1, key, "aGVsbG8sIGVhcmx5IGRhdGEA_w", out, sizeof(out));
    check_str("ws: early data in Sec-WebSocket-Protocol, between Key and Version, as Xray",
        "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: " UA "\r\nAccept: */*\r\n"
        "Accept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\n"
        "DNT: 1\r\nPragma: no-cache\r\nSec-CH-UA: " CH "\r\nSec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Protocol: aGVsbG8sIGVhcmx5IGRhdGEA_w\r\nSec-WebSocket-Version: 13\r\n"
        "Upgrade: websocket\r\n\r\n", out);
    static const struct { const char *word, *want; } B[] = {
        { "firefox",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) "
          "Gecko/20100101 Firefox/153.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\n"
          "Cache-Control: no-cache\r\nConnection: Upgrade\r\nDNT: 1\r\nPragma: no-cache\r\n"
          "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
        { "safari",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Safari/605.1.15\r\nAccept: */*\r\n"
          "Accept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\n"
          "Pragma: no-cache\r\nSec-Fetch-Dest: websocket\r\nSec-Fetch-Mode: websocket\r\n"
          "Sec-Fetch-Site: same-origin\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
          "Sec-WebSocket-Version: 13\r\nUpgrade: websocket\r\n\r\n" },
        { "edge",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: " UA "Edg/149.0.0.0\r\nAccept: */*\r\n"
          "Accept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\n"
          "DNT: 1\r\nPragma: no-cache\r\nSec-CH-UA: \"Microsoft Edge\";v=\"149\", \"Chromium\";v=\"149\", "
          "\"Not)A;Brand\";v=\"24\"\r\nSec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\n"
          "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
        { "curl",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8.20.0\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
        { "golang",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: Go-http-client/1.1\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
        /* Not one of the words (Xray's switch on the value is exact): it goes as written. */
        { "Firefox",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: Firefox\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
    };
    for (size_t i = 0; i < sizeof(B) / sizeof(*B); i++) {
        char hv[64], what[96];
        snprintf(hv, sizeof(hv), "User-Agent: %s\n", B[i].word);
        node0(&n, "ws");
        n.http_host = "h";
        n.headers = hv;
        tr_h1_request(&n, 1, key, NULL, out, sizeof(out));
        snprintf(what, sizeof(what), "ws: User-Agent \"%s\" gives Xray's look", B[i].word);
        check_str(what, B[i].want, out);
    }
    node0(&n, "httpupgrade");
    n.http_host = "h";
    n.headers = "connection: keep-alive\nUpgrade: h2c\n";
    tr_h1_request(&n, 0, NULL, NULL, out, sizeof(out));
    check_str("httpupgrade: own Connection and Upgrade as Xray (Set overrides only the exact key)",
        "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: " UA "\r\nAccept: */*\r\n"
        "Accept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\n"
        "DNT: 1\r\nPragma: no-cache\r\nSec-CH-UA: " CH "\r\nSec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\nUpgrade: websocket\r\nconnection: keep-alive\r\n\r\n", out);
}

/* ---- 3. Accept and the client frame ------------------------------------------------ */

static void test_frames_out(void) {
    char acc[29];
    tr_ws_accept("dGhlIHNhbXBsZSBub25jZQ==", acc);
    check_str("Sec-WebSocket-Accept: RFC 6455 example, 1.3", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", acc);

    unsigned char f[80000];
    const unsigned char key[4] = { 0x37, 0xfa, 0x21, 0x3d };
    size_t n = tr_ws_frame(f, sizeof(f), 1, 1, key, (const unsigned char *)"Hello", 5);
    static const unsigned char rfc[] = { 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    check(n == sizeof(rfc) && !memcmp(f, rfc, n), "masked \"Hello\" frame: RFC 6455 example, 5.7");

    static unsigned char d[70000];
    for (size_t i = 0; i < sizeof(d); i++) d[i] = (unsigned char)(i * 7);
    static const struct { size_t len, hdr; unsigned char b1; } L[] = {
        { 0, 2, 0x80 }, { 125, 2, 0x80 | 125 }, { 126, 4, 0x80 | 126 }, { 65535, 4, 0x80 | 126 },
        { 65536, 10, 0x80 | 127 },
    };
    for (size_t i = 0; i < sizeof(L) / sizeof(*L); i++) {
        n = tr_ws_frame(f, sizeof(f), 2, 0, key, d, L[i].len);
        int ok = n == L[i].hdr + 4 + L[i].len && f[0] == 0x02 && f[1] == L[i].b1 &&
                 !memcmp(f + L[i].hdr, key, 4);
        for (size_t k = 0; ok && k < L[i].len; k++)
            if ((f[L[i].hdr + 4 + k] ^ key[k & 3]) != d[k]) ok = 0;
        char what[160];
        snprintf(what, sizeof(what), "%zu-byte frame: %zu-byte header, every byte masked", L[i].len, L[i].hdr);
        check(ok, what);
    }
    check(tr_ws_frame(f, 10, 2, 1, key, d, 125) == 0, "frame does not fit: 0");
}

/* ---- 4. parsing server frames ------------------------------------------------------ */

static size_t srv_frame(unsigned char *out, int op, int fin, const void *d, size_t n) {
    size_t h = 0;
    out[h++] = (unsigned char)((fin ? 0x80 : 0) | op);
    if (n > 65535) {
        out[h++] = 127;
        for (int i = 0; i < 8; i++) out[h++] = (unsigned char)((uint64_t)n >> (56 - 8 * i));
    } else if (n > 125) {
        out[h++] = 126; out[h++] = (unsigned char)(n >> 8); out[h++] = (unsigned char)n;
    } else {
        out[h++] = (unsigned char)n;
    }
    memcpy(out + h, d, n);
    return h + n;
}

static int parse_all(const unsigned char *in, size_t n, unsigned char *out, size_t cap, size_t *on,
                     struct ws_rx *r) {
    memset(r, 0, sizeof(*r));
    return tr_ws_parse(r, in, n, out, cap, on);
}

static void test_frames_in(void) {
    static unsigned char in[200000], out[200000];
    struct ws_rx r;
    size_t n = 0, on = 0;

    n = srv_frame(in, 2, 1, "Hello", 5);
    check(parse_all(in, n, out, sizeof(out), &on, &r) == 0 && on == 5 && !memcmp(out, "Hello", 5),
          "binary \"Hello\" in one frame");

    /* Fragments and a ping inside a message (RFC 6455, 5.4 and 5.5). */
    n = srv_frame(in, 1, 0, "Hel", 3);
    n += srv_frame(in + n, 9, 1, "pp", 2);
    n += srv_frame(in + n, 0, 1, "lo", 2);
    check(parse_all(in, n, out, sizeof(out), &on, &r) == 0 && on == 5 && !memcmp(out, "Hello", 5),
          "fragments with a ping in between: whole \"Hello\"");
    check(r.pong_due && r.pong_n == 2 && !memcmp(r.pong, "pp", 2), "ping: pong due, same body");
    /* The last fragment ends the message: a new one may follow. */
    size_t n2 = n + srv_frame(in + n, 2, 1, "!", 1);
    check(parse_all(in, n2, out, sizeof(out), &on, &r) == 0 && on == 6 && !memcmp(out, "Hello!", 6),
          "after the last fragment: a new message is legal");

    /* Fed byte by byte, the same result: record and frame boundaries do not coincide. */
    memset(&r, 0, sizeof(r));
    size_t tot = 0;
    int rc = 0;
    for (size_t i = 0; i < n && !rc; i++) {
        size_t o1 = 0;
        rc = tr_ws_parse(&r, in + i, 1, out + tot, sizeof(out) - tot, &o1);
        tot += o1;
    }
    check(!rc && tot == 5 && !memcmp(out, "Hello", 5), "fed one byte at a time: whole \"Hello\"");

    /* Lengths 125, 126 and 65536+, and parsing in place (out == in). */
    static const size_t lens[] = { 125, 126, 65535, 65536, 70000 };
    static unsigned char d[70000];
    for (size_t i = 0; i < sizeof(d); i++) d[i] = (unsigned char)(i * 13 + 1);
    for (size_t k = 0; k < sizeof(lens) / sizeof(*lens); k++) {
        n = srv_frame(in, 2, 1, d, lens[k]);
        n += srv_frame(in + n, 2, 1, "z", 1);
        rc = parse_all(in, n, in, sizeof(in), &on, &r);
        char what[96];
        snprintf(what, sizeof(what), "%zu-byte frame, then another: parsed in place", lens[k]);
        check(!rc && on == lens[k] + 1 && !memcmp(in, d, lens[k]) && in[lens[k]] == 'z', what);
    }

    /* close: data before it is returned, then the end. */
    n = srv_frame(in, 2, 1, "ab", 2);
    n += srv_frame(in + n, 8, 1, "\x03\xe8", 2);
    n += srv_frame(in + n, 2, 1, "zz", 2);
    rc = parse_all(in, n, out, sizeof(out), &on, &r);
    check(!rc && on == 2 && r.closed && r.close_code == 1000, "close 1000: data before it returned, none after");
    n = srv_frame(in, 8, 1, "", 0);
    rc = parse_all(in, n, out, sizeof(out), &on, &r);
    check(!rc && r.closed && r.close_code == 1005, "close without a code: 1005");
    n = srv_frame(in, 2, 1, "", 0);
    rc = parse_all(in, n, out, sizeof(out), &on, &r);
    check(!rc && on == 0 && !r.in_payload, "empty data frame: legal");

    /* RFC violations: refused, as gorilla does. */
    struct { const char *what; unsigned char b[16]; size_t n; } bad[] = {
        { "masked server frame", { 0x82, 0x81, 1, 2, 3, 4, 'x' }, 7 },
        { "RSV1 without extensions", { 0xC2, 0x01, 'x' }, 3 },
        { "control frame longer than 125", { 0x89, 126, 0, 126 }, 4 },
        { "control frame without FIN", { 0x09, 0x01, 'x' }, 3 },
        { "continuation outside a message", { 0x80, 0x01, 'x' }, 3 },
        { "new message inside a fragmented one", { 0x02, 0x01, 'x', 0x82, 0x01, 'y' }, 6 },
        { "opcode 3", { 0x83, 0x01, 'x' }, 3 },
        { "opcode 11", { 0x8B, 0x00 }, 2 },
        { "top bit of a 64-bit length", { 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0 }, 10 },
        { "one-byte close", { 0x88, 0x01, 0x03 }, 3 },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        char what[96];
        snprintf(what, sizeof(what), "refused: %s", bad[i].what);
        check(parse_all(bad[i].b, bad[i].n, out, sizeof(out), &on, &r) == TR_EWSFRAME, what);
    }
    n = srv_frame(in, 2, 1, "abcdef", 6);
    check(parse_all(in, n, out, 3, &on, &r) == H2_ETOOBIG, "out too small: refused, not truncated");
}

/* ---- 5. 101 response --------------------------------------------------------------- */

static void test_resp(void) {
    char acc[29];
    tr_ws_accept("dGhlIHNhbXBsZSBub25jZQ==", acc);
    char ok[256];
    snprintf(ok, sizeof(ok), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
             "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\nTAIL", acc);
    struct h1_resp r;
    size_t used;

    memset(&r, 0, sizeof(r));
    tr_h1_resp_feed(&r, 1, acc, (const unsigned char *)ok, strlen(ok), &used);
    check(r.done && tr_h1_resp_verdict(&r, 1) == 0 && used == strlen(ok) - 4,
          "101 with the right Accept: accepted, bytes after the headers not consumed");

    memset(&r, 0, sizeof(r));
    size_t tot = 0;
    for (size_t i = 0; i < strlen(ok) && !r.done; i++) {
        tr_h1_resp_feed(&r, 1, acc, (const unsigned char *)ok + i, 1, &used);
        tot += used;
    }
    check(r.done && tr_h1_resp_verdict(&r, 1) == 0 && tot == strlen(ok) - 4, "response byte by byte: same");

    static const struct { const char *what, *resp; int ws, want; } V[] = {
        { "ws: 404", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 1, TR_EUPSTATUS },
        { "httpupgrade: 200", "HTTP/1.1 200 OK\r\n\r\n", 0, TR_EUPSTATUS },
        { "101, no Upgrade", "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n", 0, TR_ENOUPGRADE },
        { "101, no Connection", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", 0, TR_ENOUPGRADE },
        { "101, wrong Accept", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
          "Connection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n", 1, TR_EWSACCEPT },
        { "101, no Accept", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
          "Connection: Upgrade\r\n\r\n", 1, TR_EWSACCEPT },
        { "httpupgrade: 101, no Accept: legal", "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\n"
          "connection: upgrade\r\n\r\n", 0, 0 },
        { "ws: Connection list: token found (gorilla)", "HTTP/1.1 101 x\r\nUpgrade: websocket\r\n"
          "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", 1, 0 },
        { "httpupgrade: Connection list: refused (Xray compares the whole value)",
          "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\r\n", 0, TR_ENOUPGRADE },
        { "not HTTP", "SSH-2.0-OpenSSH\r\n\r\n", 1, TR_EUPTOOBIG },
        { "not HTTP, then a 101: refused at the first line", "SSH-2.0-OpenSSH\r\n"
          "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", 0, TR_EUPTOOBIG },
        { "status code of four digits: not HTTP",
          "HTTP/1.1 1010 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", 0, TR_EUPTOOBIG },
        { "101, Accept cut short", "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZ\r\n\r\n", 1, TR_EWSACCEPT },
        { "ws: Upgrade list: token found (gorilla)", "HTTP/1.1 101 x\r\nUpgrade: h2c, websocket\r\n"
          "Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
          1, 0 },
        { "bare \\n lines: legal", "HTTP/1.1 101 x\nUpgrade: websocket\nConnection: Upgrade\n\n", 0, 0 },
    };
    for (size_t i = 0; i < sizeof(V) / sizeof(*V); i++) {
        memset(&r, 0, sizeof(r));
        tr_h1_resp_feed(&r, V[i].ws, acc, (const unsigned char *)V[i].resp, strlen(V[i].resp), &used);
        check(tr_h1_resp_verdict(&r, V[i].ws) == V[i].want, V[i].what);
    }
    /* A long line from a middlebox is not refused; an endless response is. */
    static char big[20000];
    int k = snprintf(big, sizeof(big), "HTTP/1.1 101 x\r\nSet-Cookie: ");
    memset(big + k, 'c', 1000);
    snprintf(big + k + 1000, sizeof(big) - (size_t)k - 1000, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    memset(&r, 0, sizeof(r));
    tr_h1_resp_feed(&r, 0, NULL, (const unsigned char *)big, strlen(big), &used);
    check(tr_h1_resp_verdict(&r, 0) == 0, "a 1000-byte line in the middle: accepted");
    memset(big, 'x', sizeof(big));
    memcpy(big, "HTTP/1.1 101 x\r\nX: ", 19);
    memset(&r, 0, sizeof(r));
    tr_h1_resp_feed(&r, 0, NULL, (const unsigned char *)big, sizeof(big), &used);
    check(r.bad && tr_h1_resp_verdict(&r, 0) == TR_EUPTOOBIG, "headers longer than 16 KB: refused");
}

/* ---- 6. on a socket: the test server ----------------------------------------------- */

enum plan { P_WS_OK, P_HU_OK, P_404, P_NOUP, P_BADACC, P_SILENT, P_HANGUP,
            /* early data (Ed > 0): srv_ed */
            P_WS_ED, P_WS_EDBIG, P_HU_ED };

struct srv {
    int lfd, port;
    enum plan plan;
    char req[4096];                /* what the client sent */
    int rc;
    /* P_WS_OK: what came in client frames */
    unsigned char got[9000 + 8192];
    size_t got_n;
    int frames, masked_all, pong_ok, close_ok, ops_ok;
    unsigned char keys[3][4];      /* mask keys of the first three frames */
    /* early data: what Sec-WebSocket-Protocol held, whether anything came before the response,
     * whether a close 1000 came when the client closed */
    char proto[128];
    int early_before_101, close1000;
    /* ws early data: the client says on go right before its first write and waits for ack;
     * req_at_open — the request was already readable then, i.e. open sent it */
    int go[2], ack[2], req_at_open;
};

static int rd_until(int fd, char *buf, size_t cap, const char *end) {
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t k = read(fd, buf + n, 1);
        if (k <= 0) return -1;
        n++;
        buf[n] = '\0';
        if (strstr(buf, end)) return (int)n;
    }
    return -1;
}

static int rd_all(int fd, unsigned char *b, size_t n) {
    size_t g = 0;
    while (g < n) {
        ssize_t k = read(fd, b + g, n - g);
        if (k <= 0) return -1;
        g += (size_t)k;
    }
    return 0;
}

static unsigned char g_last_key[4];   /* mask key of the last frame rd_cframe read */

/* Read a client frame, which must be masked. The body is returned unmasked. */
static int rd_cframe(int fd, int *op, int *fin, int *masked, unsigned char *body, size_t cap, size_t *bn) {
    unsigned char h[2];
    if (rd_all(fd, h, 2)) return -1;
    *op = h[0] & 15; *fin = h[0] >> 7; *masked = h[1] >> 7;
    uint64_t len = h[1] & 0x7f;
    if (len == 126) { unsigned char e[2]; if (rd_all(fd, e, 2)) return -1; len = (e[0] << 8) | e[1]; }
    else if (len == 127) { unsigned char e[8]; if (rd_all(fd, e, 8)) return -1; len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | e[i]; }
    unsigned char key[4] = { 0 };
    if (*masked && rd_all(fd, key, 4)) return -1;
    memcpy(g_last_key, key, 4);
    if (len > cap) return -1;
    if (rd_all(fd, body, (size_t)len)) return -1;
    for (size_t i = 0; i < len; i++) body[i] ^= key[i & 3];
    *bn = (size_t)len;
    return 0;
}

/* Early data. P_WS_ED: the client's first write, "hello" (not longer than Ed), must arrive in
 * the request's Sec-WebSocket-Protocol, and the second write (9000 bytes, made BEFORE the
 * response) as frames strictly after the 101 response. P_WS_EDBIG: the first write, 9000 bytes,
 * is longer than Ed: the request goes without early data, the write as frames after the 101.
 * P_HU_ED: the request goes at open; over security=none the client still holds its data until
 * the 101 (see below). In all three the client closes on its own at the end; for ws a close 1000
 * must arrive. */
static void *srv_ed(struct srv *s, int fd) {
    const char *p = strstr(s->req, "\r\nSec-WebSocket-Protocol: ");
    if (p) sscanf(p + 26, "%127[^\r]", s->proto);
    unsigned char resp[512];
    int n;
    if (s->plan == P_HU_ED) {
        /* security=none: the client waits for the response even with Ed > 0 (trupgrade.c: the
         * Xray server loses data that arrives in one segment with the request). Silence before the
         * response, "echo" after it. */
        struct pollfd pf0 = { .fd = fd, .events = POLLIN, .revents = 0 };
        s->early_before_101 = poll(&pf0, 1, 200) > 0;
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\n\r\nRAW-START");
        if (write(fd, resp, (size_t)n) != n) { close(fd); return NULL; }
        char b[8];
        s->got_n = rd_all(fd, (unsigned char *)b, 4) == 0 && !memcmp(b, "echo", 4);
        s->rc = 0;
        close(fd);
        return NULL;
    }
    /* Before the response NOTHING but the request may come from the client (gorilla drops such
     * a connection). */
    struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
    s->early_before_101 = poll(&pf, 1, 200) > 0;
    char acc[29] = "";
    const char *k = strstr(s->req, "\r\nSec-WebSocket-Key: ");
    if (k) { char key[32]; sscanf(k + 21, "%31[^\r]", key); tr_ws_accept(key, acc); }
    n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
    n += (int)srv_frame(resp + n, 2, 1, "FIRST", 5);
    if (write(fd, resp, (size_t)n) != n) { close(fd); return NULL; }
    int op, fin, masked;
    size_t bn;
    unsigned char body[8192];
    s->masked_all = 1;
    while (s->got_n < 9000) {
        if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn)) { close(fd); return NULL; }
        if (!masked) s->masked_all = 0;
        memcpy(s->got + s->got_n, body, bn);
        s->got_n += bn;
        s->frames++;
    }
    if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn) == 0)
        s->close1000 = op == 8 && masked && bn == 2 && body[0] == 0x03 && body[1] == 0xe8;
    s->rc = 0;
    close(fd);
    return NULL;
}

static void *srv_main(void *arg) {
    struct srv *s = arg;
    int fd = accept(s->lfd, NULL, NULL);
    s->rc = -1;
    if (fd < 0) return NULL;
    if (s->plan == P_WS_ED || s->plan == P_WS_EDBIG) {
        char c;
        struct pollfd pg = { .fd = s->go[0], .events = POLLIN, .revents = 0 };
        if (poll(&pg, 1, 5000) <= 0 || read(s->go[0], &c, 1) != 1) { close(fd); return NULL; }
        struct pollfd pc = { .fd = fd, .events = POLLIN, .revents = 0 };
        s->req_at_open = poll(&pc, 1, 0) > 0;
        if (write(s->ack[1], "k", 1) != 1) { close(fd); return NULL; }
    }
    /* Close without answering AFTER the request is read: closing a socket with an unread
     * request makes the kernel send a reset (RST), and the client would see an end of stream or
     * a reset depending on whether the request arrived before close (on a loaded machine the test
     * failed every other run). */
    if (rd_until(fd, s->req, sizeof(s->req), "\r\n\r\n") < 0) { close(fd); return NULL; }
    if (s->plan == P_HANGUP) { close(fd); s->rc = 0; return NULL; }
    if (s->plan == P_SILENT) { sleep(2); close(fd); s->rc = 0; return NULL; }
    if (s->plan >= P_WS_ED) return srv_ed(s, fd);

    char acc[29] = "";
    const char *k = strstr(s->req, "\r\nSec-WebSocket-Key: ");
    if (k) {
        char key[32];
        sscanf(k + 21, "%31[^\r]", key);
        tr_ws_accept(key, acc);
    }
    unsigned char resp[1024];
    int n = 0;
    switch (s->plan) {
    case P_404:
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        break;
    case P_NOUP:
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\n"
                     "Sec-WebSocket-Accept: %s\r\n\r\n", acc);
        break;
    case P_BADACC:
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n");
        break;
    case P_HU_OK:
        /* The response and the start of the stream in ONE socket write: the rest must come
         * through. */
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\n\r\nRAW-START");
        break;
    default:
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
        /* And the first frame in the same write. */
        n += (int)srv_frame(resp + n, 2, 1, "FIRST", 5);
    }
    if (write(fd, resp, (size_t)n) != n) { close(fd); return NULL; }
    if (s->plan != P_WS_OK && s->plan != P_HU_OK) { usleep(200000); close(fd); s->rc = 0; return NULL; }

    if (s->plan == P_HU_OK) {
        /* A raw stream: echo what came in. */
        char b[64];
        ssize_t r = read(fd, b, sizeof(b));
        if (r > 0 && write(fd, b, (size_t)r) != r) r = -1;
        s->got_n = r > 0 ? (size_t)r : 0;
        memcpy(s->got, b, s->got_n);
        s->rc = 0;
        close(fd);
        return NULL;
    }

    /* ws: 9000 bytes in one client write are three frames, cut as Xray does (4096, 4096, 808). */
    s->masked_all = 1;
    s->ops_ok = 1;
    int op, fin, masked;
    size_t bn;
    unsigned char body[8192];
    while (s->got_n < 9000) {
        if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn)) { close(fd); return NULL; }
        int want_op = s->frames == 0 ? 2 : 0;
        int want_fin = s->got_n + bn == 9000;
        size_t want_n = 9000 - s->got_n > 4096 ? 4096 : 9000 - s->got_n;
        if (op != want_op || fin != want_fin || bn != want_n) s->ops_ok = 0;
        if (!masked) s->masked_all = 0;
        if (s->frames < 3) memcpy(s->keys[s->frames], g_last_key, 4);
        memcpy(s->got + s->got_n, body, bn);
        s->got_n += bn;
        s->frames++;
    }
    /* ping: expect a pong with the same body. */
    unsigned char f[64];
    size_t fl = srv_frame(f, 9, 1, "hb", 2);
    if (write(fd, f, fl) != (ssize_t)fl) { close(fd); return NULL; }
    if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn) == 0)
        s->pong_ok = op == 10 && fin && masked && bn == 2 && !memcmp(body, "hb", 2);
    /* close 1001: expect a close in reply with the same code. */
    fl = srv_frame(f, 8, 1, "\x03\xe9", 2);
    if (write(fd, f, fl) != (ssize_t)fl) { close(fd); return NULL; }
    if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn) == 0)
        s->close_ok = op == 8 && masked && bn == 2 && body[0] == 0x03 && body[1] == 0xe9;
    s->rc = 0;
    close(fd);
    return NULL;
}

static int srv_start(struct srv *s, enum plan p, pthread_t *th) {
    memset(s, 0, sizeof(*s));
    s->plan = p;
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof(a);
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof(a)) || listen(s->lfd, 1) ||
        getsockname(s->lfd, (struct sockaddr *)&a, &al))
        return -1;
    s->port = ntohs(a.sin_port);
    if (pipe(s->go) || pipe(s->ack)) return -1;
    return pthread_create(th, NULL, srv_main, s);
}

static void srv_stop(struct srv *s, pthread_t th) {
    pthread_join(th, NULL);
    close(s->lfd);
    close(s->go[0]); close(s->go[1]); close(s->ack[0]); close(s->ack[1]);
}

/* ws early data: tell the server the first write comes next, and wait until it has looked. */
static void srv_go(struct srv *s) {
    char c;
    struct pollfd p = { .fd = s->ack[0], .events = POLLIN, .revents = 0 };
    if (write(s->go[1], "w", 1) == 1 && poll(&p, 1, 5000) > 0) (void)!read(s->ack[0], &c, 1);
}

/* Wait as the tunnel loop does: for the transport's own unread data or a readable socket. A
 * plain socket is read with a blocking read, and reading without readiness would wait for the
 * socket timeout. */
static int ready(struct transport *t) {
    if (transport_has_data(t)) return 1;
    struct pollfd p = { .fd = transport_fd(t), .events = POLLIN, .revents = 0 };
    return poll(&p, 1, 3000) > 0;
}

/* Read through the transport until something comes or time runs out. */
static int tread(struct transport *t, unsigned char *b, size_t cap, size_t *got) {
    for (int i = 0; i < 20; i++) {
        *got = 0;
        if (!ready(t)) return 0;
        int rc = transport_read(t, b, cap, got);
        if (rc || *got) return rc;
    }
    return 0;
}

static void test_socket(void) {
    struct srv s;
    pthread_t th;
    struct transport t;
    struct tr_node n;
    static unsigned char buf[TRANSPORT_MIN_READ_CAP];
    size_t got;
    int fd0 = fd_count();

    /* ws: upgrade, the first frame in the same read, upload in 4096-byte frames, ping, close. */
    if (srv_start(&s, P_WS_OK, &th)) { check(0, "test server started"); return; }
    node0(&n, "ws");
    n.port = (uint16_t)s.port;
    n.path = "/w?ed=0";                        /* ed is stripped, Ed = 0: upgrade at once */
    n.http_host = "cdn.example.com";
    int rc = transport_open(&t, &n, 3);
    check(rc == 0, "ws: upgrade on a socket succeeds");
    if (!rc) {
        check(transport_has_data(&t), "ws: first frame after 101 ready without the socket");
        rc = tread(&t, buf, sizeof(buf), &got);
        check(!rc && got == 5 && !memcmp(buf, "FIRST", 5), "ws: first frame after 101 not lost");
        static unsigned char up[9000];
        for (size_t i = 0; i < sizeof(up); i++) up[i] = (unsigned char)(i * 31);
        check(transport_write(&t, up, sizeof(up)) == 0, "ws: 9000-byte write");
        /* Then the server sends a ping (zero data bytes, not a failure) and a close (end of
         * stream). */
        size_t data = 0;
        rc = 0;
        for (int i = 0; i < 20 && !rc && ready(&t); i++) {
            rc = transport_read(&t, buf, sizeof(buf), &got);
            data += got;
        }
        if (rc != TR_ECLOSED || data) printf("  code %d (%s), data %zu\n", rc, transport_strerror(rc), data);
        check(rc == TR_ECLOSED && data == 0, "ws: ping yields no data, close ends the stream");
        transport_close(&t);
    }
    srv_stop(&s, th);
    check(!strncmp(s.req, "GET /w HTTP/1.1\r\nHost: cdn.example.com\r\n", 40), "ws: request line and Host");
    check(strstr(s.req, "Sec-WebSocket-Protocol") == NULL, "ws: no early data (ed stripped from path)");
    check(s.frames == 3 && s.ops_ok, "ws: 9000 bytes as 4096+4096+808 frames, binary then continuation, FIN last");
    /* A mask is only a mask with an unpredictable key (RFC 6455, 5.3): three frames from kernel
     * randomness share a key or get a zero one with odds of about 2^-30. */
    int keys_ok = s.frames == 3;
    for (int i = 0; keys_ok && i < 3; i++) {
        if (!memcmp(s.keys[i], "\0\0\0\0", 4)) keys_ok = 0;
        for (int j = 0; j < i; j++) if (!memcmp(s.keys[i], s.keys[j], 4)) keys_ok = 0;
    }
    check(s.masked_all && keys_ok, "ws: every client frame masked, each with its own nonzero key");
    int same = s.got_n == 9000;
    for (size_t i = 0; same && i < 9000; i++) if (s.got[i] != (unsigned char)(i * 31)) same = 0;
    check(same, "ws: the server got exactly what was written");
    check(s.pong_ok, "ws: ping answered by a pong with the same body");
    check(s.close_ok, "ws: close answered by a close with the same code");

    /* httpupgrade: the bytes after the response, and an echo. */
    if (srv_start(&s, P_HU_OK, &th)) { check(0, "test server started"); return; }
    node0(&n, "httpupgrade");
    n.port = (uint16_t)s.port;
    rc = transport_open(&t, &n, 3);
    check(rc == 0, "httpupgrade: upgrade on a socket succeeds");
    if (!rc) {
        check(transport_has_data(&t), "httpupgrade: bytes after 101 ready without the socket");
        const unsigned char *data = NULL;
        rc = transport_read_zc(&t, buf, sizeof(buf), &data, &got);
        check(!rc && got == 9 && !memcmp(data, "RAW-START", 9), "httpupgrade: stream start after 101 not lost");
        check(!transport_has_data(&t), "httpupgrade: once taken, not ready without the socket");
        check(transport_write(&t, (const unsigned char *)"echo", 4) == 0, "httpupgrade: raw write");
        rc = tread(&t, buf, sizeof(buf), &got);
        check(!rc && got == 4 && !memcmp(buf, "echo", 4), "httpupgrade: unframed stream both ways");
        transport_close(&t);
    }
    srv_stop(&s, th);
    check(strstr(s.req, "Sec-WebSocket-Key") == NULL && strstr(s.req, "\r\nUpgrade: websocket\r\n"),
          "httpupgrade: Upgrade without a WebSocket key");

    /* Early data as in Xray: ws holds the request back until the first write. */
    static unsigned char big[9000];
    for (size_t i = 0; i < sizeof(big); i++) big[i] = (unsigned char)(i * 31);
    for (int v = 0; v < 2; v++) {
        const int small = v == 0;
        if (srv_start(&s, small ? P_WS_ED : P_WS_EDBIG, &th)) { check(0, "test server started"); return; }
        node0(&n, "ws");
        n.port = (uint16_t)s.port;
        n.path = small ? "/w?ed=2048" : "/w?ed=16";
        rc = transport_open(&t, &n, 3);
        const int opened = rc == 0;
        const char *tag = small ? "ws ed=2048, first write 5 bytes" : "ws ed=16, first write 9000 bytes";
        char what[160];
        snprintf(what, sizeof(what), "%s: open succeeds", tag);
        check(rc == 0, what);
        if (!rc) {
            srv_go(&s);
            if (small) check(transport_write(&t, (const unsigned char *)"hello", 5) == 0, "ws ed: early data written");
            snprintf(what, sizeof(what), "%s: 9000-byte write before the 101 is queued", tag);
            check(transport_write(&t, big, sizeof(big)) == 0, what);
            rc = tread(&t, buf, sizeof(buf), &got);
            snprintf(what, sizeof(what), "%s: 101 accepted, the first frame after it read", tag);
            check(!rc && got == 5 && !memcmp(buf, "FIRST", 5), what);
            transport_close(&t);
        }
        srv_stop(&s, th);
        snprintf(what, sizeof(what), "%s: open sends no request, the first write does", tag);
        check(opened && !s.req_at_open && s.req[0], what);
        snprintf(what, sizeof(what), "%s: Sec-WebSocket-Protocol", tag);
        check_str(what, small ? "aGVsbG8" : "", s.proto);
        snprintf(what, sizeof(what), "%s: no frames before the 101", tag);
        check(!s.early_before_101, what);
        same = s.got_n == 9000 && s.masked_all;
        for (size_t i = 0; same && i < 9000; i++) if (s.got[i] != big[i]) same = 0;
        snprintf(what, sizeof(what), "%s: 9000 bytes in masked frames after the 101", tag);
        check(same, what);
        snprintf(what, sizeof(what), "%s: close 1000 on closing", tag);
        check(s.close1000, what);
    }

    /* httpupgrade with ed over security=none: the response is awaited (why: trupgrade.c,
     * tr_h1_upgrade). Lazy parsing of the response over TLS and REALITY is checked by vlessmatch
     * (make crypto-test). */
    if (srv_start(&s, P_HU_ED, &th)) { check(0, "test server started"); return; }
    node0(&n, "httpupgrade");
    n.port = (uint16_t)s.port;
    n.path = "/u?ed=1";
    rc = transport_open(&t, &n, 3);
    /* Read in open, the 101 leaves the bytes that came with it held: ready without the socket. */
    check(rc == 0 && transport_has_data(&t), "httpupgrade ed, no TLS: open reads the 101");
    if (!rc) {
        check(transport_write(&t, (const unsigned char *)"echo", 4) == 0, "httpupgrade ed: write after 101");
        const unsigned char *data = NULL;
        size_t tot = 0;
        char acc[32] = "";
        for (int i = 0; i < 20 && tot < 9 && ready(&t); i++) {
            rc = transport_read_zc(&t, buf, sizeof(buf), &data, &got);
            if (rc) break;
            if (tot + got < sizeof(acc)) memcpy(acc + tot, data, got);
            tot += got;
        }
        check(!rc && tot == 9 && !memcmp(acc, "RAW-START", 9), "httpupgrade ed: bytes after 101 intact");
        transport_close(&t);
    }
    srv_stop(&s, th);
    check(!s.early_before_101 && s.got_n == 1, "httpupgrade ed, no TLS: data only after the 101");
    check(!strncmp(s.req, "GET /u HTTP/1.1\r\n", 17), "httpupgrade ed: ed stripped from the path");

    /* Refusals. */
    static const struct { enum plan p; const char *type; int want; const char *what; } F[] = {
        { P_404, "ws", TR_EUPSTATUS, "ws: 404 response refused" },
        { P_404, "httpupgrade", TR_EUPSTATUS, "httpupgrade: 404 response refused" },
        { P_NOUP, "ws", TR_ENOUPGRADE, "ws: 101 without Upgrade refused" },
        { P_BADACC, "ws", TR_EWSACCEPT, "ws: wrong Accept refused" },
        { P_SILENT, "ws", TR_EUPTIMEOUT, "ws: silent server times out" },
        { P_HANGUP, "httpupgrade", TR_ECLOSED, "httpupgrade: server closed, refused" },
    };
    for (size_t i = 0; i < sizeof(F) / sizeof(*F); i++) {
        if (srv_start(&s, F[i].p, &th)) { check(0, "test server started"); return; }
        node0(&n, F[i].type);
        n.port = (uint16_t)s.port;
        rc = transport_open(&t, &n, 1);
        if (rc != F[i].want) printf("  %s: code %d (%s)\n", F[i].what, rc, transport_strerror(rc));
        check(rc == F[i].want, F[i].what);
        if (F[i].p == P_404)
            check(strstr(transport_strerror(rc), "404") != NULL, "error text names code 404");
        if (!rc) transport_close(&t);
        srv_stop(&s, th);
    }
    check(fd_count() == fd0, "descriptor count back to where it started");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wsmatch: path\n");
    test_path();
    test_ed();
    printf("wsmatch: Upgrade request\n");
    test_request();
    printf("wsmatch: client frames\n");
    test_frames_out();
    printf("wsmatch: server frames\n");
    test_frames_in();
    printf("wsmatch: 101 response\n");
    test_resp();
    printf("wsmatch: on a socket\n");
    test_socket();
    printf("wsmatch: %d checks, %s\n", g_pass + g_fail, g_fail ? "SOME FAILED" : "all passed");
    return g_fail ? 1 : 0;
}
