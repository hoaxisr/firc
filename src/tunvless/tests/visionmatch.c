/* Parsing a Vision stream on fixtures: no network, no server, no root.
 *
 * vision_unwrap reads the stream FROM THE SERVER, that is untrusted bytes, and it parses as a
 * stream: state carries over between calls. So what matters is less the content than the
 * SLICING: where exactly a TLS record boundary falls. The live stand (tests/run-tunnel.sh) cannot
 * choose the slicing and does not reach these cases; it runs the good path end to end and needs
 * root with ip netns.
 *
 * Checked: a stream start that arrives in pieces (bytes before the UUID is recognized must not be
 * lost, or the parser loses sync and hands frame header bytes to the client as data); the frames
 * after it at every slicing (payload kept, padding dropped, `end` and `direct` switching to the
 * plain stream); a UUID that is not ours (the stream passes as is); and an invalid command (it
 * must fail every time, never leave the parser consuming zero bytes forever).
 *
 * The module is linked with the test, not included: the state checked here is the fields of
 * struct vision, declared in vision.h, and nothing static in vision.c is needed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "../src/proto/vless/vision.h"

static int fails;

static void check(const char *what, long want, long got) {
    if (want == got) { printf("%-58s ok\n", what); return; }
    printf("%-58s FAIL: expected %ld, got %ld\n", what, want, got);
    fails++;
}

static const unsigned char UUID[16] = {
    0x96, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* One frame: command, payload length, padding length, the payload and the padding. The same
 * shape vision_wrap builds on the other side. Padding bytes are 0xEE: any of them reaching the
 * client makes the output longer than the payloads. */
static size_t put_frame(unsigned char *out, unsigned char cmd, const void *data, size_t data_n,
                        size_t pad_n) {
    size_t i = 0;
    out[i++] = cmd;
    out[i++] = (unsigned char)(data_n >> 8);
    out[i++] = (unsigned char)(data_n & 0xFF);
    out[i++] = (unsigned char)(pad_n >> 8);
    out[i++] = (unsigned char)(pad_n & 0xFF);
    memcpy(out + i, data, data_n); i += data_n;
    memset(out + i, 0xEE, pad_n); i += pad_n;
    return i;
}

/* A server stream: UUID and one frame without padding. */
static size_t make_stream(unsigned char *out, unsigned char cmd,
                          const char *data, size_t data_n) {
    memcpy(out, UUID, 16);
    return 16 + put_frame(out + 16, cmd, data, data_n, 0);
}

static void vinit(struct vision *v) {
    memset(v, 0, sizeof(*v));
    memcpy(v->uuid, UUID, 16);
}

/* Feed the whole stream to the parser in chunks of step bytes and collect the output. */
static size_t drain(struct vision *v, const unsigned char *in, size_t n, size_t step,
                    char *out, size_t out_cap, int *rc_out) {
    size_t got = 0, pos = 0;
    *rc_out = 0;
    while (pos < n) {
        size_t chunk = n - pos < step ? n - pos : step;
        size_t off = 0;
        /* Loop within a chunk while the parser consumes or returns something, as
         * downstream_pump in stack.c does. */
        for (;;) {
            size_t used = 0, pl_n = 0;
            const unsigned char *pl = NULL;
            int rc = vision_unwrap(v, in + pos + off, chunk - off, &used, &pl, &pl_n);
            if (rc != 0) { *rc_out = rc; return got; }
            if (pl_n) {
                if (got + pl_n > out_cap) return got;
                memcpy(out + got, pl, pl_n);
                got += pl_n;
            }
            off += used;
            if (!used && !pl_n) break;
            if (off >= chunk) break;
        }
        pos += chunk;
    }
    return got;
}

/* Every chunk size from 1 byte to the whole stream, a fresh parser each time. Returns the first
 * size whose output is not want (or that fails), -1 if every size gives want. */
static int every_step(const unsigned char *in, size_t n, const unsigned char *want, size_t want_n) {
    for (size_t step = 1; step <= n; step++) {
        struct vision v;
        vinit(&v);
        static char out[2048];
        int rc = 0;
        size_t got = drain(&v, in, n, step, out, sizeof(out), &rc);
        if (rc != 0 || got != want_n || memcmp(out, want, want_n) != 0) return (int)step;
    }
    return -1;
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

static void finit(struct vision *v) {
    vision_init(v, UUID);
}

/* catches: the builder drifting from the offsets every filter case relies on */
static void t_filter_builder(void) {
    unsigned char b[160];
    check("sh with sv: 127 B", 127, (long)sh(b, 0x1301, 1));
    check("sh with sv: LL 122", 122, (b[3] << 8) | b[4]);
    check("sh with sv: HL 118", 118, b[8]);
    check("sh with sv: 20 at 43", 0x20, b[43]);
    check("sh with sv: suite at 76-77", 0x1301, (b[76] << 8) | b[77]);
    check("sh with sv: extension at 81", 0x2b, b[82]);
    check("sh without sv: 121 B", 121, (long)sh(b, 0x1301, 0));
    check("sh without sv: LL 116", 116, (b[3] << 8) | b[4]);
}

/* catches: the ClientHello test reading the wrong byte, or the ServerHello test ignoring 03 03 */
static void t_filter_client_hello(void) {
    unsigned char b[206];
    memset(b, 0, sizeof b);
    b[0] = 0x16; b[1] = 0x03; b[2] = 0x01; b[3] = 0x00; b[4] = 0xc8; b[5] = 0x01;
    struct vision v;
    finit(&v);
    int r = vision_filter(&v, b, sizeof b);
    check("client hello: return 0", 0, r);
    check("client hello: is_tls 1", 1, v.is_tls);
    check("client hello: tls12_or_above 0", 0, v.tls12_or_above);
    check("client hello: enable_xtls 0", 0, v.enable_xtls);
    check("client hello: filter_left 7", 7, v.filter_left);
    check("client hello: sh_left -1", -1, v.sh_left);
    b[5] = 0x02;
    finit(&v);
    r = vision_filter(&v, b, sizeof b);
    check("16 03 01 with type 2: return 0", 0, r);
    check("16 03 01 with type 2: is_tls 0", 0, v.is_tls);
    check("16 03 01 with type 2: tls12_or_above 0", 0, v.tls12_or_above);
    check("16 03 01 with type 2: sh_left -1", -1, v.sh_left);
    b[2] = 0x03; b[5] = 0x01;
    finit(&v);
    r = vision_filter(&v, b, sizeof b);
    check("16 03 03 with type 1: return 0", 0, r);
    check("16 03 03 with type 1: is_tls 1", 1, v.is_tls);
    check("16 03 03 with type 1: tls12_or_above 0", 0, v.tls12_or_above);
    check("16 03 03 with type 1: sh_left -1", -1, v.sh_left);
}

/* catches: CCM_8 allowed, CCM refused, or an unknown suite taken as TLS 1.3 */
static void t_filter_tls13_suites(void) {
    unsigned char b[160];
    struct vision v;
    finit(&v);
    size_t n = sh(b, 0x1301, 1);
    int r = vision_filter(&v, b, n);
    check("tls13 1301: return 1", 1, r);
    check("tls13 1301: is_tls 1", 1, v.is_tls);
    check("tls13 1301: tls12_or_above 1", 1, v.tls12_or_above);
    check("tls13 1301: cipher", 0x1301, v.cipher);
    check("tls13 1301: enable_xtls 1", 1, v.enable_xtls);
    check("tls13 1301: filter_left 0", 0, v.filter_left);
    check("tls13 1301: sh_left 0", 0, v.sh_left);
    static const unsigned suites[5] = {0x1302, 0x1303, 0x1304, 0x1305, 0x00ff};
    static const int want[5] = {1, 1, 1, 0, 0};
    for (int k = 0; k < 5; k++) {
        char what[64];
        finit(&v);
        n = sh(b, suites[k], 1);
        r = vision_filter(&v, b, n);
        snprintf(what, sizeof what, "tls13 %04x: return 1", suites[k]);
        check(what, 1, r);
        snprintf(what, sizeof what, "tls13 %04x: enable_xtls", suites[k]);
        check(what, want[k], v.enable_xtls);
        snprintf(what, sizeof what, "tls13 %04x: filter_left 0", suites[k]);
        check(what, 0, v.filter_left);
    }
}

/* catches: a ServerHello without supported_versions taken as TLS 1.3 */
static void t_filter_tls12(void) {
    unsigned char b[160];
    struct vision v;
    finit(&v);
    size_t n = sh(b, 0x1301, 0);
    int r = vision_filter(&v, b, n);
    check("tls12: return 1", 1, r);
    check("tls12: tls12_or_above 1", 1, v.tls12_or_above);
    check("tls12: enable_xtls 0", 0, v.enable_xtls);
    check("tls12: filter_left 0", 0, v.filter_left);
}

/* catches: a search across buffers (Xray's bytes.Contains sees one buffer) */
static void t_filter_split_in_two(void) {
    unsigned char b[160];
    struct vision v;
    finit(&v);
    sh(b, 0x1301, 1);
    int r = vision_filter(&v, b, 84);
    check("split 84: return 0", 0, r);
    check("split 84: cipher", 0x1301, v.cipher);
    check("split 84: sh_left 43", 43, v.sh_left);
    check("split 84: filter_left 7", 7, v.filter_left);
    check("split 84: enable_xtls 0", 0, v.enable_xtls);
    r = vision_filter(&v, b + 84, 43);
    check("split 43: return 1", 1, r);
    check("split 43: enable_xtls 0", 0, v.enable_xtls);
    check("split 43: filter_left 0", 0, v.filter_left);
}

/* catches: the suite read from a buffer under 79 B */
static void t_filter_short_buffer(void) {
    unsigned char b[160];
    struct vision v;
    finit(&v);
    sh(b, 0x1301, 1);
    int r = vision_filter(&v, b, 70);
    check("short 70: return 0", 0, r);
    check("short 70: cipher 0", 0, v.cipher);
    check("short 70: sh_left 57", 57, v.sh_left);
    r = vision_filter(&v, b + 70, 57);
    check("short 57: return 1", 1, r);
    check("short 57: enable_xtls 0", 0, v.enable_xtls);
    check("short 57: filter_left 0", 0, v.filter_left);
}

/* catches: a counter not decremented per buffer */
static void t_filter_plain(void) {
    static const char get[] = "GET / HTTP/1.1\r\n";
    struct vision v;
    finit(&v);
    check("plain: filter_left 8 before", 8, v.filter_left);
    int rets = 0;
    for (int k = 0; k < 8; k++) rets |= vision_filter(&v, (const unsigned char *)get, sizeof get - 1);
    check("plain: every return 0", 0, rets);
    check("plain: filter_left 0", 0, v.filter_left);
    check("plain: is_tls 0", 0, v.is_tls);
    check("plain: tls12_or_above 0", 0, v.tls12_or_above);
    check("plain: enable_xtls 0", 0, v.enable_xtls);
    check("plain: cipher 0", 0, v.cipher);
    check("plain: sh_left -1", -1, v.sh_left);
}

/* catches: > 79 for >= 79 */
static void t_filter_79(void) {
    unsigned char b[160];
    struct vision v;
    finit(&v);
    sh(b, 0x1301, 1);
    int r = vision_filter(&v, b, 79);
    check("79: return 0", 0, r);
    check("79: cipher", 0x1301, v.cipher);
    r = vision_filter(&v, b + 79, 48);
    check("79 then 48: return 1", 1, r);
    check("79 then 48: enable_xtls 1", 1, v.enable_xtls);
}

/* catches: the search run over the whole buffer instead of the ServerHello's bytes */
static void t_filter_search_bound(void) {
    unsigned char b[160];
    static const unsigned char sv[6] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    size_t n = sh(b, 0x1301, 0);
    memcpy(b + n, sv, 6);
    n += 6;
    struct vision v;
    finit(&v);
    int r = vision_filter(&v, b, n);
    check("search bound: 127 B", 127, (long)n);
    check("search bound: return 1", 1, r);
    check("search bound: sh_left -6", -6, v.sh_left);
    check("search bound: tls12_or_above 1", 1, v.tls12_or_above);
    check("search bound: enable_xtls 0", 0, v.enable_xtls);
    check("search bound: filter_left 0", 0, v.filter_left);
}

/* catches: a session-id length pointing the suite read past the buffer */
static void t_filter_sid_past_buffer(void) {
    unsigned char b[160];
    size_t n = sh(b, 0x1301, 1);
    b[43] = 0xff;
    struct vision v;
    finit(&v);
    unsigned char *h = malloc(n);
    if (!h) { check("sid past buffer: malloc", 1, 0); return; }
    memcpy(h, b, n);
    int r = vision_filter(&v, h, n);
    free(h);
    check("sid past buffer: cipher 0", 0, v.cipher);
    check("sid past buffer: return 1", 1, r);
    check("sid past buffer: enable_xtls 0", 0, v.enable_xtls);
}

/* catches: > 79 for >= 79 on the ServerHello's record length */
static void t_filter_record_79(void) {
    unsigned char b[160];
    size_t n = sh(b, 0x1301, 1);
    b[3] = 0x00; b[4] = 0x4a;
    struct vision v;
    finit(&v);
    int r = vision_filter(&v, b, n);
    check("record 79: cipher", 0x1301, v.cipher);
    check("record 79: sh_left -48", -48, v.sh_left);
    check("record 79: return 1", 1, r);
    check("record 79: enable_xtls 0", 0, v.enable_xtls);
}

/* catches: the search missing supported_versions in the last bytes of the ServerHello */
static void t_filter_version_at_end(void) {
    unsigned char b[160];
    static const unsigned char sv[6] = {0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    size_t n = sh(b, 0x1301, 0);
    memcpy(b + n, sv, 6);
    n += 6;
    b[3] = 0x00; b[4] = 0x7a;
    struct vision v;
    finit(&v);
    int r = vision_filter(&v, b, n);
    check("version at end: sh_left 0", 0, v.sh_left);
    check("version at end: return 1", 1, r);
    check("version at end: enable_xtls 1", 1, v.enable_xtls);
}

/* catches: the suite bound off by one, reading a byte past the buffer or refusing the last two */
static void t_filter_suite_at_edge(void) {
    unsigned char b[160];
    size_t n = sh(b, 0x1301, 1);
    static const unsigned char sid[2] = {81, 82};
    static const long want[2] = {0x3333, 0};
    for (int k = 0; k < 2; k++) {
        char what[64];
        b[43] = sid[k];
        unsigned char *h = malloc(n);
        if (!h) { check("suite at edge: malloc", 1, 0); return; }
        memcpy(h, b, n);
        struct vision v;
        finit(&v);
        int r = vision_filter(&v, h, n);
        free(h);
        snprintf(what, sizeof what, "suite at edge, sid %u: cipher", sid[k]);
        check(what, want[k], v.cipher);
        snprintf(what, sizeof what, "suite at edge, sid %u: return 1", sid[k]);
        check(what, 1, r);
        snprintf(what, sizeof what, "suite at edge, sid %u: enable_xtls 0", sid[k]);
        check(what, 0, v.enable_xtls);
    }
}

static unsigned char g_rb;

ssize_t __wrap_os_getrandom(void *buf, size_t n, unsigned int flags);
ssize_t __wrap_os_getrandom(void *buf, size_t n, unsigned int flags) {
    (void)flags;
    memset(buf, g_rb, n);
    return (ssize_t)n;
}

struct wf {
    int cmd;
    size_t len, pad, at;
};

static size_t g_raw_at;

static int wparse(const unsigned char *o, size_t n, int uuid, struct wf *f, int max) {
    size_t i = 0;
    int k = 0;
    g_raw_at = n;
    if (uuid) {
        if (n < 16 || memcmp(o, UUID, 16) != 0) return -1;
        i = 16;
    }
    while (i < n && k < max) {
        if (n - i < 5) return -1;
        f[k].cmd = o[i];
        f[k].len = ((size_t)o[i + 1] << 8) | o[i + 2];
        f[k].pad = ((size_t)o[i + 3] << 8) | o[i + 4];
        f[k].at = i + 5;
        i += 5 + f[k].len;
        if (i + f[k].pad > n) return -1;
        for (size_t z = 0; z < f[k].pad; z++)
            if (o[i + z]) return -1;
        i += f[k].pad;
        if (f[k++].cmd != VISION_CMD_CONTINUE) { g_raw_at = i; return k; }
    }
    g_raw_at = i;
    return k;
}

static unsigned char g_wout[20000];

static size_t mk_ch(unsigned char *b) {
    static const unsigned char h[6] = {0x16, 0x03, 0x01, 0x05, 0xc1, 0x01};
    memset(b, 0x42, 1478);
    memcpy(b, h, 6);
    return 1478;
}

static size_t mk_fl(unsigned char *b) {
    static const unsigned char h[11] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
                                        0x17, 0x03, 0x03, 0x00, 0x35};
    memcpy(b, h, 11);
    memset(b + 11, 0xaa, 53);
    return 64;
}

static size_t mk_get(unsigned char *b) {
    static const unsigned char h[5] = {0x17, 0x03, 0x03, 0x00, 0x77};
    memcpy(b, h, 5);
    memset(b + 5, 0x47, 119);
    return 124;
}

static size_t mk_rec(unsigned char *b, unsigned claim, size_t body) {
    b[0] = 0x17; b[1] = 0x03; b[2] = 0x03;
    b[3] = (unsigned char)(claim >> 8); b[4] = (unsigned char)claim;
    memset(b + 5, 0, body);
    return 5 + body;
}

static void tls13_seq(unsigned char rb, int may, int sv, const long pads[3], int want_cmd) {
    char what[96];
    const char *tag = sv ? (may ? "tls13" : "tls13 may 0") : "tls12";
    static unsigned char d[2048];
    unsigned char hs[160];
    struct vision v;
    struct wf f[4];
    size_t on = 0;
    g_rb = rb;
    finit(&v);
    size_t n = mk_ch(d);
    int r = vision_wrap(&v, d, n, may, g_wout, sizeof g_wout, &on);
    int k = wparse(g_wout, on, 1, f, 4);
    snprintf(what, sizeof what, "wrap %s %02x: CH frame", tag, rb);
    check(what, 1, r == 0 && k == 1 && on == 1478 + 21 + (size_t)pads[0] && f[0].cmd == 0 &&
                   f[0].len == 1478 && f[0].pad == (size_t)pads[0] && !memcmp(g_wout + 21, d, n));
    vision_filter(&v, hs, sh(hs, 0x1301, sv));
    n = mk_fl(d);
    r = vision_wrap(&v, d, n, may, g_wout, sizeof g_wout, &on);
    k = wparse(g_wout, on, 0, f, 4);
    snprintf(what, sizeof what, "wrap %s %02x: Finished frame", tag, rb);
    check(what, 1, r == 0 && k == 1 && on == 5 + 64 + (size_t)pads[1] && f[0].cmd == 0 &&
                   f[0].len == 64 && f[0].pad == (size_t)pads[1] && !memcmp(g_wout + 5, d, n));
    n = mk_get(d);
    r = vision_wrap(&v, d, n, may, g_wout, sizeof g_wout, &on);
    k = wparse(g_wout, on, 0, f, 4);
    snprintf(what, sizeof what, "wrap %s %02x: GET frame command", tag, rb);
    check(what, want_cmd, r == 0 && k == 1 ? f[0].cmd : -1);
    snprintf(what, sizeof what, "wrap %s %02x: GET frame", tag, rb);
    check(what, 1, on == 5 + 124 + (size_t)pads[2] && f[0].len == 124 &&
                   f[0].pad == (size_t)pads[2] && !memcmp(g_wout + 5, d, n));
    snprintf(what, sizeof what, "wrap %s %02x: switch and padding", tag, rb);
    check(what, want_cmd == VISION_CMD_DIRECT ? 11 : 10, v.tx_switch + 10 * !v.is_padding);
    memset(d, 'u', 100);
    r = vision_wrap(&v, d, 100, may, g_wout, sizeof g_wout, &on);
    snprintf(what, sizeof what, "wrap %s %02x: plain after", tag, rb);
    check(what, VISION_PLAIN, r);
}

/* catches: end on the first frame, direct without the ServerHello, long padding missing on the handshake */
static void t_wrap_tls13_sequence(void) {
    static const long p0[3] = {0, 836, 776}, pf[3] = {255, 871, 811};
    tls13_seq(0x00, 1, 1, p0, VISION_CMD_DIRECT);
    tls13_seq(0xff, 1, 1, pf, VISION_CMD_DIRECT);
    tls13_seq(0x00, 0, 1, p0, VISION_CMD_END);
}

/* catches: direct for inner TLS 1.2 */
static void t_wrap_tls12_end(void) {
    static const long p0[3] = {0, 836, 776};
    tls13_seq(0x00, 1, 0, p0, VISION_CMD_END);
}

static void plain_counter(int dl, const char *want) {
    char what[96], got[16];
    unsigned char d[100], ten[10];
    struct vision v;
    struct wf f[2];
    size_t on = 0;
    int bad = 0;
    g_rb = 0;
    finit(&v);
    memset(d, 'u', sizeof d);
    memset(ten, 'u', sizeof ten);
    size_t w = strlen(want);
    for (size_t i = 0; i < w; i++) {
        if (dl && i == 2) vision_filter(&v, ten, sizeof ten);
        int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
        int k = wparse(g_wout, on, i == 0, f, 2);
        if (r != 0 || k != 1 || f[0].pad != 0 || f[0].len != 100 || on != (i ? 105u : 121u) ||
            g_raw_at != on)
            bad = 1;
        got[i] = r == 0 && k == 1 ? (char)('0' + f[0].cmd) : '?';
    }
    got[w] = 0;
    snprintf(what, sizeof what, "wrap plain counter%s: commands %s", dl ? " with downlink" : "", want);
    check(what, 0, strcmp(got, want));
    snprintf(what, sizeof what, "wrap plain counter%s: pad 0, 121 then 105", dl ? " with downlink" : "");
    check(what, 0, bad);
    snprintf(what, sizeof what, "wrap plain counter%s: plain after", dl ? " with downlink" : "");
    check(what, VISION_PLAIN, vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on));
}

/* catches: a counter not shared with the downlink, or end one write early or late */
static void t_wrap_plain_counter(void) {
    plain_counter(0, "0000001");
    plain_counter(1, "000001");
}

/* catches: long padding for a plain first frame (tunvless's old rule) */
static void t_wrap_long_by_is_tls(void) {
    static unsigned char ch[1478];
    unsigned char d[100];
    struct vision v;
    struct wf f[2];
    size_t on = 0;
    g_rb = 0;
    memset(d, 'u', sizeof d);
    finit(&v);
    int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
    int k = wparse(g_wout, on, 1, f, 2);
    check("wrap long by is_tls: plain first frame pad 0", 0, r == 0 && k == 1 ? (long)f[0].pad : -1);
    finit(&v);
    vision_filter(&v, ch, mk_ch(ch));
    r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
    k = wparse(g_wout, on, 1, f, 2);
    check("wrap long by is_tls: after a ClientHello pad 800", 800,
          r == 0 && k == 1 ? (long)f[0].pad : -1);
}

static int two_frames(const unsigned char *d, size_t n, int uuid, struct wf *f, size_t on,
                      size_t c0, size_t c1) {
    int k = wparse(g_wout, on, uuid, f, 4);
    return k == 2 && g_raw_at == on && f[0].len == c0 && f[1].len == c1 && c0 + c1 == n &&
           !memcmp(g_wout + f[0].at, d, c0) && !memcmp(g_wout + f[1].at, d + c0, c1);
}

/* catches: no reshape (one frame over 8192) */
static void t_wrap_reshape_plain(void) {
    static unsigned char d[8192];
    struct vision v;
    struct wf f[4];
    size_t on = 0;
    memset(d, 'u', sizeof d);
    for (int s = 0; s < 2; s++) {
        size_t pad = s ? 0 : 255;
        g_rb = s ? 0x00 : 0xff;
        finit(&v);
        int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
        int ok = r == 0 && two_frames(d, sizeof d, 1, f, on, 4096, 4096) && f[0].cmd == 0 &&
                 f[1].cmd == 0 && f[0].pad == pad && f[1].pad == pad &&
                 f[1].at - 5 == 16 + 5 + 4096 + pad && on == 2 * 4096 + 26 + 2 * pad;
        check(s ? "wrap reshape plain 00: 4117 + 4101" : "wrap reshape plain ff: 4372 + 4356", 1, ok);
    }
}

/* catches: the cut at 4096 when a record start is in range, or direct on a non-last buffer */
static void t_wrap_reshape_at_record(void) {
    static unsigned char d[8192];
    unsigned char hs[160], ch[1478];
    struct vision v;
    struct wf f[4];
    size_t on = 0;
    g_rb = 0xff;
    finit(&v);
    vision_filter(&v, ch, mk_ch(ch));
    vision_filter(&v, hs, sh(hs, 0x1301, 1));
    size_t n = mk_rec(d, 0x0bb3, 2995);
    n += mk_rec(d + n, 0x1443, 5187);
    int r = vision_wrap(&v, d, n, 1, g_wout, sizeof g_wout, &on);
    check("wrap reshape at record: 8192 B written", 8192, (long)n);
    check("wrap reshape at record: 3000 + 5192, continue then direct, pad 255", 1,
          r == 0 && two_frames(d, n, 1, f, on, 3000, 5192) && f[0].cmd == 0 &&
              f[1].cmd == VISION_CMD_DIRECT && f[0].pad == 255 && f[1].pad == 255);
    check("wrap reshape at record: switch", 1, v.tx_switch);
}

static void cut_case(size_t n, long at, size_t c0, size_t c1) {
    static unsigned char d[8192];
    char what[96];
    struct vision v;
    struct wf f[4];
    size_t on = 0;
    g_rb = 0;
    memset(d, 'u', sizeof d);
    if (at >= 0) { d[at] = 0x17; d[at + 1] = 0x03; d[at + 2] = 0x03; }
    finit(&v);
    int r = vision_wrap(&v, d, n, 1, g_wout, sizeof g_wout, &on);
    snprintf(what, sizeof what, "wrap cut: %zu B, record at %ld -> %zu, %zu", n, at, c0, c1);
    check(what, 1, r == 0 && two_frames(d, n, 1, f, on, c0, c1));
}

/* catches: off-by-one at either bound of the cut, the threshold, or the cap */
static void t_wrap_cut_bounds(void) {
    static unsigned char d[8192];
    struct vision v;
    struct wf f[2];
    size_t on = 0;
    cut_case(8192, 20, 4096, 4096);
    cut_case(8192, 21, 21, 8171);
    cut_case(8192, 8171, 8171, 21);
    cut_case(8192, 8172, 4096, 4096);
    cut_case(8171, -1, 4096, 4075);
    g_rb = 0xff;
    memset(d, 'u', sizeof d);
    finit(&v);
    int r = vision_wrap(&v, d, 8170, 1, g_wout, sizeof g_wout, &on);
    int k = wparse(g_wout, on, 1, f, 2);
    check("wrap cut: 8170 B one frame, pad 1, 8192 B", 1,
          r == 0 && k == 1 && f[0].len == 8170 && f[0].pad == 1 && on == 8192 &&
              !memcmp(g_wout + 21, d, 8170));
}

/* catches: the remaining buffers framed after the non-TLS end */
static void t_wrap_end_break(void) {
    static unsigned char d[8292];
    unsigned char ten[10];
    struct vision v;
    struct wf f[4];
    size_t on = 0;
    g_rb = 0;
    memset(d, 'u', sizeof d);
    memset(ten, 'u', sizeof ten);
    finit(&v);
    for (int i = 0; i < 5; i++) vision_filter(&v, ten, sizeof ten);
    int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
    int k = wparse(g_wout, on, 1, f, 4);
    check("wrap end break: end frame of 4096, pad 0", 1,
          r == 0 && k == 1 && f[0].cmd == VISION_CMD_END && f[0].len == 4096 && f[0].pad == 0);
    check("wrap end break: 4196 B unframed after, 8313 in all", 1,
          on == 8313 && g_raw_at == 16 + 5 + 4096 && !memcmp(g_wout + 21, d, 8292));
    check("wrap end break: padding over", 0, v.is_padding);
}

/* catches: completeness judged per buffer after the cut (R2 alone would switch) */
static void t_wrap_complete_before_cut(void) {
    static unsigned char d[8192];
    unsigned char hs[160], ch[1478];
    struct vision v;
    struct wf f[4];
    size_t on = 0;
    g_rb = 0;
    finit(&v);
    vision_filter(&v, ch, mk_ch(ch));
    vision_filter(&v, hs, sh(hs, 0x1301, 1));
    size_t n = mk_rec(d, 0x0bb3, 2979);
    n += mk_rec(d + n, 0x1443, 5187);
    int r = vision_wrap(&v, d, n, 1, g_wout, sizeof g_wout, &on);
    check("wrap complete before cut: 2984 + 5192, continue twice", 1,
          n == 8176 && r == 0 && two_frames(d, n, 1, f, on, 2984, 5192) && f[0].cmd == 0 &&
              f[1].cmd == 0);
    check("wrap complete before cut: no switch, still padding", 1, !v.tx_switch && v.is_padding);
}

/* catches: long padding kept for the buffers after the switching one */
static void t_wrap_long_reset(void) {
    static unsigned char d[8300];
    unsigned char hs[160], ch[1478];
    struct vision v;
    struct wf f[4];
    size_t on = 0;
    g_rb = 0;
    finit(&v);
    vision_filter(&v, ch, mk_ch(ch));
    vision_filter(&v, hs, sh(hs, 0x1301, 1));
    size_t n = mk_rec(d, 0x2003, 8195);
    n += mk_rec(d + n, 0x5f, 95);
    int r = vision_wrap(&v, d, n, 1, g_wout, sizeof g_wout, &on);
    int k = wparse(g_wout, on, 1, f, 4);
    check("wrap long reset: 4096, 4096, 108", 1,
          n == 8300 && r == 0 && k == 3 && f[0].len == 4096 && f[1].len == 4096 &&
              f[2].len == 108 && g_raw_at == on && !memcmp(g_wout + f[0].at, d, 4096) &&
              !memcmp(g_wout + f[1].at, d + 4096, 4096) && !memcmp(g_wout + f[2].at, d + 8192, 108));
    check("wrap long reset: continue, continue, direct", 1,
          k == 3 && f[0].cmd == 0 && f[1].cmd == 0 && f[2].cmd == VISION_CMD_DIRECT);
    check("wrap long reset: every pad 0", 1, k == 3 && !f[0].pad && !f[1].pad && !f[2].pad);
}

/* catches: the non-TLS exit always padded short */
static void t_wrap_end_long(void) {
    unsigned char ch[1478], ten[10], d[100];
    struct vision v;
    struct wf f[2];
    size_t on = 0;
    g_rb = 0;
    memset(ten, 'u', sizeof ten);
    memset(d, 'u', sizeof d);
    finit(&v);
    vision_filter(&v, ch, mk_ch(ch));
    for (int i = 0; i < 5; i++) vision_filter(&v, ten, sizeof ten);
    int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
    int k = wparse(g_wout, on, 1, f, 2);
    check("wrap end long: end, pad 800, 921 B", 1,
          r == 0 && k == 1 && f[0].cmd == VISION_CMD_END && f[0].len == 100 && f[0].pad == 800 &&
              on == 921);
}

/* catches: a state advanced by a frame that did not fit */
static void t_wrap_efit(void) {
    unsigned char d[100];
    struct vision v, before;
    size_t on = 0;
    g_rb = 0;
    memset(d, 'u', sizeof d);
    finit(&v);
    memcpy(&before, &v, sizeof v);
    int r = vision_wrap(&v, d, sizeof d, 1, g_wout, 120, &on);
    check("wrap efit: VISION_EFIT", VISION_EFIT, r);
    check("wrap efit: state unchanged", 0, memcmp(&before, &v, sizeof v));
}

/* catches: the filter run on the slices after the one that decided */
static void t_wrap_filter_stops(void) {
    static unsigned char d[8292];
    struct vision v;
    size_t on = 0;
    g_rb = 0;
    memset(d, 'u', sizeof d);
    sh(d, 0x1301, 1);
    finit(&v);
    int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
    check("wrap filter stops: decided in the first slice, counter 0", 1,
          r == 0 && v.filter_left == 0 && v.enable_xtls);
}

/* catches: an empty record taken as complete */
static void t_wrap_empty_record(void) {
    static const unsigned char d[11] = {0x17, 0x03, 0x03, 0x00, 0x00,
                                        0x17, 0x03, 0x03, 0x00, 0x01, 0x41};
    unsigned char hs[160];
    struct vision v;
    struct wf f[2];
    size_t on = 0;
    g_rb = 0;
    finit(&v);
    vision_filter(&v, hs, sh(hs, 0x1301, 1));
    int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
    int k = wparse(g_wout, on, 1, f, 2);
    check("wrap empty record: continue, no switch", 1,
          r == 0 && k == 1 && f[0].cmd == VISION_CMD_CONTINUE && !v.tx_switch && v.is_padding);
}

/* catches: the last record start searched short of the piece's last three bytes */
static void t_wrap_cut_tail(void) {
    static unsigned char d[8192];
    struct vision v;
    struct wf f[4];
    size_t on = 0;
    g_rb = 0;
    memset(d, 'u', sizeof d);
    d[100] = 0x17; d[101] = 0x03; d[102] = 0x03;
    d[8189] = 0x17; d[8190] = 0x03; d[8191] = 0x03;
    finit(&v);
    int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
    check("wrap cut: records at 100 and 8189 -> 4096, 4096", 1,
          r == 0 && two_frames(d, sizeof d, 1, f, on, 4096, 4096));
}

/* catches: long padding for a frame of exactly 900 B */
static void t_wrap_long_at_900(void) {
    static unsigned char d[900];
    unsigned char ch[1478];
    struct vision v;
    struct wf f[2];
    size_t on = 0;
    g_rb = 0xff;
    memset(d, 'u', sizeof d);
    finit(&v);
    vision_filter(&v, ch, mk_ch(ch));
    int r = vision_wrap(&v, d, sizeof d, 1, g_wout, sizeof g_wout, &on);
    int k = wparse(g_wout, on, 1, f, 2);
    check("wrap long at 900: short pad 255, 1176 B", 1,
          r == 0 && k == 1 && f[0].len == 900 && f[0].pad == 255 && on == 1176);
}

static void efit_late(const char *what, size_t n, int filters, size_t cap) {
    unsigned char *d = malloc(n), *o = malloc(cap), ten[10];
    struct vision v, before;
    size_t on = 0;
    if (!d || !o) { free(d); free(o); check(what, 1, 0); return; }
    g_rb = 0;
    memset(d, 'u', n);
    memset(ten, 'u', sizeof ten);
    finit(&v);
    for (int i = 0; i < filters; i++) vision_filter(&v, ten, sizeof ten);
    memcpy(&before, &v, sizeof v);
    int r = vision_wrap(&v, d, n, 1, o, cap, &on);
    check(what, 1, r == VISION_EFIT && on == 0 && !memcmp(&before, &v, sizeof v));
    free(d);
    free(o);
}

/* catches: a later frame or the unframed rest written past cap */
static void t_wrap_efit_late(void) {
    efit_late("wrap efit: second frame one byte short (8217 of 8218)", 8192, 0, 8217);
    efit_late("wrap efit: end rest one byte short (8312 of 8313)", 8292, 5, 8312);
}

int main(void) {
    t_filter_builder();
    t_filter_client_hello();
    t_filter_tls13_suites();
    t_filter_tls12();
    t_filter_split_in_two();
    t_filter_short_buffer();
    t_filter_plain();
    t_filter_79();
    t_filter_search_bound();
    t_filter_sid_past_buffer();
    t_filter_record_79();
    t_filter_version_at_end();
    t_filter_suite_at_edge();
    t_wrap_tls13_sequence();
    t_wrap_tls12_end();
    t_wrap_plain_counter();
    t_wrap_long_by_is_tls();
    t_wrap_reshape_plain();
    t_wrap_reshape_at_record();
    t_wrap_cut_bounds();
    t_wrap_end_break();
    t_wrap_complete_before_cut();
    t_wrap_long_reset();
    t_wrap_end_long();
    t_wrap_efit();
    t_wrap_filter_stops();
    t_wrap_empty_record();
    t_wrap_cut_tail();
    t_wrap_long_at_900();
    t_wrap_efit_late();

    unsigned char stream[256];
    const char *msg = "the payload of one Vision frame";
    size_t msg_n = strlen(msg);
    size_t n = make_stream(stream, VISION_CMD_CONTINUE, msg, msg_n);

    /* The whole stream in one chunk: the base case. */
    {
        struct vision v;
        vinit(&v);
        char out[256];
        int rc = 0;
        size_t got = drain(&v, stream, n, n, out, sizeof(out), &rc);
        check("stream in one chunk: no error", 0, rc);
        check("stream in one chunk: payload length", (long)msg_n, (long)got);
        check("stream in one chunk: payload content", 0, memcmp(out, msg, msg_n));
    }

    /* Every chunk size, down to 1 byte. A chunk shorter than the 21-byte start (UUID and
     * first frame header) must be kept, not dropped: otherwise the UUID is compared at a
     * shifted offset, does not match, and the parser slips. */
    check("any chunk size down to 1 byte gives the same payload", -1,
          every_step(stream, n, (const unsigned char *)msg, msg_n));

    /* The frames after the start, at every chunk size: a record boundary may fall inside a
     * header, a payload or the padding. A payload and a padding longer than 255 bytes (both
     * length bytes count), then a frame with `end`, then the plain stream. The client gets the
     * payloads and the plain tail, not one byte of padding or header. */
    {
        static unsigned char s[1024], want[1024];
        unsigned char p1[300];
        for (size_t i = 0; i < sizeof(p1); i++) p1[i] = (unsigned char)(i * 7 + 1);
        const char *p2 = "the second frame, with end";
        const char *tail = "the plain stream after end";
        size_t sn = 0, wn = 0;
        memcpy(s, UUID, 16);
        sn = 16;
        sn += put_frame(s + sn, VISION_CMD_CONTINUE, p1, sizeof(p1), 300);
        sn += put_frame(s + sn, VISION_CMD_END, p2, strlen(p2), 7);
        memcpy(s + sn, tail, strlen(tail));
        sn += strlen(tail);
        memcpy(want, p1, sizeof(p1));
        wn = sizeof(p1);
        memcpy(want + wn, p2, strlen(p2));
        wn += strlen(p2);
        memcpy(want + wn, tail, strlen(tail));
        wn += strlen(tail);
        check("padded frames, end, plain tail: any chunk size", -1, every_step(s, sn, want, wn));

        /* An end frame with neither payload nor padding: the server ends padding this way. */
        const char *p3 = "one frame";
        memcpy(s, UUID, 16);
        sn = 16;
        sn += put_frame(s + sn, VISION_CMD_CONTINUE, p3, strlen(p3), 3);
        sn += put_frame(s + sn, VISION_CMD_END, "", 0, 0);
        memcpy(s + sn, tail, strlen(tail));
        sn += strlen(tail);
        memcpy(want, p3, strlen(p3));
        memcpy(want + strlen(p3), tail, strlen(tail));
        check("empty end frame, plain tail: any chunk size", -1,
              every_step(s, sn, want, strlen(p3) + strlen(tail)));
    }

    /* `direct` ends the padding as `end` does, and the reader must also be told: the server then
     * writes the stream without its TLS records, and reading it as records breaks mid-transfer.
     * `end` must not tell the reader that. */
    for (int direct = 0; direct <= 1; direct++) {
        unsigned char s[128];
        const char *p = "the last frame";
        const char *tail = "+raw tail";
        memcpy(s, UUID, 16);
        size_t sn = 16 + put_frame(s + 16, direct ? VISION_CMD_DIRECT : VISION_CMD_END,
                                   p, strlen(p), 5);
        memcpy(s + sn, tail, strlen(tail));
        sn += strlen(tail);
        struct vision v;
        vinit(&v);
        char out[128];
        int rc = 0;
        size_t got = drain(&v, s, sn, sn, out, sizeof(out), &rc);
        int same = rc == 0 && got == strlen(p) + strlen(tail) &&
                   memcmp(out, p, strlen(p)) == 0 &&
                   memcmp(out + strlen(p), tail, strlen(tail)) == 0;
        if (direct) {
            check("direct: the payload, then the stream as is", 1, same);
            check("direct: the reader is told to bypass TLS", 1, v.recv_direct);
        } else {
            check("end: the payload, then the stream as is", 1, same);
            check("end: the reader is not told to bypass TLS", 0, v.recv_direct);
        }
    }

    /* Another UUID: the stream is not wrapped and passes as is. The start collected while
     * looking for the UUID must reach the client whole, not stay in the parser's buffer. */
    {
        unsigned char plain[64];
        memset(plain, 0, sizeof(plain));
        memcpy(plain, "not a Vision stream: plain data, byte by byte.", 46);
        struct vision v;
        vinit(&v);                           /* the stream does not carry this UUID */
        char out[128];
        int rc = 0;
        size_t got = drain(&v, plain, 46, 7, out, sizeof(out), &rc);
        check("another UUID: no error", 0, rc);
        check("another UUID: the whole stream comes through", 46, (long)got);
        check("another UUID: content unchanged", 0, memcmp(out, plain, 46));
    }

    /* A UUID that differs from ours in ONE byte, the first or the last included, is another
     * UUID: a compare that skips a byte would take the stream as wrapped and strip 21 bytes. */
    {
        int bad_k = -1;
        for (int k = 0; k < 16 && bad_k < 0; k++) {
            unsigned char s[64];
            size_t sn = make_stream(s, VISION_CMD_CONTINUE, msg, msg_n);
            s[k] ^= 0x01;
            struct vision v;
            vinit(&v);
            char out[128];
            int rc = 0;
            size_t got = drain(&v, s, sn, sn, out, sizeof(out), &rc);
            if (rc != 0 || got != sn || memcmp(out, s, sn) != 0) bad_k = k;
        }
        check("UUID off in any one byte: the stream passes as is", -1, bad_k);
    }

    /* An invalid command: an error, not endless re-reading of one frame. */
    {
        unsigned char bad[64];
        size_t bn = make_stream(bad, 0x7F, "xx", 2);   /* there is no command 0x7F */
        struct vision v;
        vinit(&v);
        char out[64];
        int rc = 0;
        drain(&v, bad, bn, bn, out, sizeof(out), &rc);
        check("invalid command: parser returns VISION_EPROTO", VISION_EPROTO, rc);
    }

    /* The broken frame stays: the next call must give EPROTO again, even on bytes that form a
     * valid frame. Parsing them would read the rest of a broken stream as frames, and a success
     * that consumes nothing would leave a live connection re-reading the frame forever. */
    {
        unsigned char bad[64];
        size_t bn = make_stream(bad, 0x7F, "xx", 2);
        struct vision v;
        vinit(&v);
        size_t used = 0, pl_n = 0;
        const unsigned char *pl = NULL;
        int rc1 = vision_unwrap(&v, bad, bn, &used, &pl, &pl_n);
        check("broken frame: error on the first call", VISION_EPROTO, rc1);
        unsigned char good[16];
        size_t gn = put_frame(good, VISION_CMD_CONTINUE, "ok", 2, 0);
        int rc2 = vision_unwrap(&v, good, gn, &used, &pl, &pl_n);
        check("broken frame: error again on the next call, even on a valid frame",
              VISION_EPROTO, rc2);
    }

    /* catches: a direct frame split across outer records bypassing decryption before its last byte */
    {
        static unsigned char s[8192];
        static unsigned char want[4096];
        size_t sn = 0, wn = 0;
        memcpy(s, UUID, 16);
        sn = 16;
        unsigned char hello[200];
        memset(hello, 0x16, sizeof hello);
        sn += put_frame(s + sn, VISION_CMD_CONTINUE, hello, sizeof hello, 50);
        memcpy(want, hello, sizeof hello);
        wn = sizeof hello;
        unsigned char app[3000];
        for (size_t k = 0; k < sizeof app; k++) app[k] = (unsigned char)(k * 7 + 1);
        app[0] = 0x17; app[1] = 0x03; app[2] = 0x03;
        sn += put_frame(s + sn, VISION_CMD_DIRECT, app, sizeof app, 30);
        memcpy(want + wn, app, sizeof app);
        wn += sizeof app;
        const size_t rec[3] = {1185, 2370, 0};
        struct vision v;
        vinit(&v);
        static char out[4096];
        size_t got = 0, pos = 0;
        int early = 0, rc = 0;
        for (int r = 0; r < 3 && pos < sn; r++) {
            size_t len = rec[r] && rec[r] < sn - pos ? rec[r] : sn - pos;
            got += drain(&v, s + pos, len, len, out + got, sizeof(out) - got, &rc);
            pos += len;
            if (pos < sn && v.recv_direct) early = 1;
        }
        check("direct frame across records: no bypass before its last byte", 0, early);
        check("direct frame across records: bypass after its last byte", 1, v.recv_direct);
        check("direct frame across records: payloads whole", 1,
              rc == 0 && got == wn && memcmp(out, want, wn) == 0);
    }

    /* catches: an empty direct frame leaving the stream parsed instead of passed through */
    {
        static unsigned char s[256];
        size_t sn = 16;
        memcpy(s, UUID, 16);
        sn += put_frame(s + sn, VISION_CMD_DIRECT, "", 0, 0);
        const char tail[] = "\x17\x03\x03raw tail";
        memcpy(s + sn, tail, sizeof tail - 1);
        sn += sizeof tail - 1;
        struct vision v;
        vinit(&v);
        char out[64];
        int rc = 0;
        size_t got = drain(&v, s, sn, sn, out, sizeof out, &rc);
        check("empty direct frame: bypass set", 1, v.recv_direct);
        check("empty direct frame: tail passes through", 1,
              rc == 0 && got == sizeof tail - 1 && memcmp(out, tail, got) == 0);
    }

    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed");
    return fails ? 1 : 0;
}
