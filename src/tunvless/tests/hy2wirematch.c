#include <stdlib.h>
#include <string.h>

#include "unit.h"
#include "hy2wire.h"
#include "hpack.h"
#include "hy2-frozen.h"

static uint8_t *mdup(const void *p, size_t n) {
    uint8_t *m = malloc(n ? n : 1);
    if (n) memcpy(m, p, n);
    return m;
}

static size_t put_len(uint8_t *o, size_t v) {
    if (v < 64) { o[0] = (uint8_t)v; return 1; }
    o[0] = (uint8_t)(0x40 | (v >> 8));
    o[1] = (uint8_t)v;
    return 2;
}

static size_t frame(uint8_t *o, uint8_t type, const uint8_t *p, size_t n) {
    o[0] = type;
    size_t k = 1 + put_len(o + 1, n);
    if (n) memcpy(o + k, p, n);
    return k + n;
}

static int resp_of(const uint8_t *sec, size_t sn, struct hy2_auth_resp *r) {
    uint8_t *buf = malloc(sn + 8);
    size_t n = frame(buf, 0x01, sec, sn);
    uint8_t *m = mdup(buf, n);
    free(buf);
    r->status = -7;
    r->rx_bps = 99;
    r->udp = -7;
    int rc = hy2_auth_response(m, n, r);
    free(m);
    return rc;
}

static void t_varints(void) {
    uint8_t b[8];
    uint64_t v;
    static const struct { uint64_t v; const char *hex; } c[] = {
        { 37, "25" }, { 64, "4040" }, { 15293, "7bbd" }, { 494878333u, "9d7f3e7d" },
        { 151288809941952652ull, "c2197c5eff14e88c" },
    };
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        size_t n = hy2_varint_put(b, sizeof b, c[i].v);
        check_hex("varint put", c[i].hex, b, n);
        uint8_t *m = mdup(b, n);
        check("varint get length", (long)n, (long)hy2_varint_get(m, n, &v));
        check("varint get value", (long)c[i].v, (long)v);
        free(m);
    }
    uint8_t *m = mdup("\x7b", 1);
    check("varint get short 2-byte form", 0, (long)hy2_varint_get(m, 1, &v));
    free(m);
    check("varint get empty", 0, (long)hy2_varint_get(b, 0, &v));
    check("varint put too big", 0, (long)hy2_varint_put(b, sizeof b, 1ull << 62));
    check("varint put small cap", 0, (long)hy2_varint_put(b, 1, 64));
}

static void t_control(void) {
    uint8_t b[16];
    size_t n = hy2_h3_control(b, sizeof b);
    check_hex("control stream is Xray's", "0004050680a00000", b, n);
    check("control stream needs 8 bytes", 0, (long)hy2_h3_control(b, 7));
}

static void t_auth_request(void) {
    uint8_t pad[256], out[1024], want[1024];
    memset(pad, 'a', sizeof pad);
    size_t n = hy2_auth_request(out, sizeof out, "pw", 0, (const char *)pad, sizeof pad);
    want[0] = 0x01;
    size_t k = 1 + put_len(want + 1, sizeof hy2_frozen_auth);
    memcpy(want + k, hy2_frozen_auth, sizeof hy2_frozen_auth);
    check("auth request length", (long)(k + sizeof hy2_frozen_auth), (long)n);
    check_mem("auth request bytes", want, out, k + sizeof hy2_frozen_auth);
    check("auth request into a small buffer", 0, (long)hy2_auth_request(out, k + sizeof hy2_frozen_auth - 1, "pw", 0, (const char *)pad, sizeof pad));
}

static void t_qpack_fields(void) {
    struct hy2_field f;
    const uint8_t *p = hy2_frozen_auth, *end = hy2_frozen_auth + sizeof hy2_frozen_auth;
    check("qpack start", 0, hy2_qpack_start(&p, end));
    static const char *const names[10] = { ":authority", ":method", ":path", ":scheme", "hysteria-auth",
        "hysteria-cc-rx", "hysteria-padding", "content-length", "accept-encoding", "user-agent" };
    static const char *const vals[10] = { "hysteria", "POST", "/auth", "https", "pw", "0", NULL, "0", "gzip", "quic-go HTTP/3" };
    char padv[257];
    memset(padv, 'a', 256);
    padv[256] = 0;
    for (int i = 0; i < 10; i++) {
        check("qpack next yields a field", 1, hy2_qpack_next(&p, end, &f));
        check_str("qpack name", names[i], f.name);
        check_str("qpack value", vals[i] ? vals[i] : padv, f.value);
    }
    check("qpack next at the end", 0, hy2_qpack_next(&p, end, &f));

    p = hy2_frozen_404;
    end = hy2_frozen_404 + sizeof hy2_frozen_404;
    check("qpack start 404", 0, hy2_qpack_start(&p, end));
    check("qpack 404 first", 1, hy2_qpack_next(&p, end, &f));
    check_str("qpack 404 name", ":status", f.name);
    check_str("qpack 404 value", "404", f.value);
    check("qpack 404 second", 1, hy2_qpack_next(&p, end, &f));
    check_str("qpack 404 name 2", "content-type", f.name);
    check_str("qpack 404 value 2", "text/plain; charset=utf-8", f.value);

    uint8_t *m = mdup(hy2_frozen_auth, sizeof hy2_frozen_auth);
    for (size_t k = 0; k < sizeof hy2_frozen_auth; k++) {
        uint8_t *t = mdup(m, k);
        const uint8_t *q = t, *qe = t + k;
        int rc = hy2_qpack_start(&q, qe);
        if (rc == 0) do rc = hy2_qpack_next(&q, qe, &f); while (rc == 1);
        check("a truncated section ends in 0 or -1", 1, rc == 0 || rc == -1);
        free(t);
    }
    free(m);
}

static uint8_t *lit_path(size_t vlen, size_t *total) {
    uint8_t *s = malloc(vlen + 16);
    size_t k = 0;
    s[k++] = 0; s[k++] = 0; s[k++] = 0x51; s[k++] = 0x7f;
    size_t v = vlen - 127;
    while (v >= 128) { s[k++] = (uint8_t)(0x80 | (v & 0x7f)); v >>= 7; }
    s[k++] = (uint8_t)v;
    memset(s + k, 'x', vlen);
    uint8_t *m = mdup(s, k + vlen);
    *total = k + vlen;
    free(s);
    return m;
}

static void t_value_limits(void) {
    struct hy2_field f;
    size_t n;
    uint8_t *m = lit_path(2303, &n);
    const uint8_t *p = m, *end = m + n;
    check("value of 2303 start", 0, hy2_qpack_start(&p, end));
    check("value of 2303 accepted", 1, hy2_qpack_next(&p, end, &f));
    check("value of 2303 length", 2303, (long)strlen(f.value));
    free(m);
    m = lit_path(2304, &n);
    p = m; end = m + n;
    hy2_qpack_start(&p, end);
    check("value of 2304 refused", -1, hy2_qpack_next(&p, end, &f));
    free(m);

    uint8_t nm[3 + 64 + 3];
    nm[0] = 0; nm[1] = 0; nm[2] = 0x27; nm[3] = 64 - 7;
    memset(nm + 4, 'n', 64);
    nm[68] = 0x01; nm[69] = 'v';
    m = mdup(nm, 70);
    p = m; end = m + 70;
    hy2_qpack_start(&p, end);
    check("name of 64 refused", -1, hy2_qpack_next(&p, end, &f));
    free(m);
    nm[3] = 63 - 7;
    nm[67] = 0x01; nm[68] = 'v';
    m = mdup(nm, 69);
    p = m; end = m + 69;
    hy2_qpack_start(&p, end);
    check("name of 63 accepted", 1, hy2_qpack_next(&p, end, &f));
    check("name of 63 length", 63, (long)strlen(f.name));
    free(m);
}

static void t_auth_response(void) {
    struct hy2_auth_resp r;
    check("response ok done", 1, resp_of(hy2_frozen_ok, sizeof hy2_frozen_ok, &r));
    check("response ok status", 233, r.status);
    check("response ok rate", 13107200, (long)r.rx_bps);
    check("response ok with hysteria-udp true: udp 1", 1, r.udp);
    check("response with hysteria-udp false done", 1, resp_of(hy2_frozen_ok_noudp, sizeof hy2_frozen_ok_noudp, &r));
    check("response with hysteria-udp false: status", 233, r.status);
    check("response with hysteria-udp false: rate", 13107200, (long)r.rx_bps);
    check("response with hysteria-udp false: udp 0", 0, r.udp);

    uint8_t buf[700];
    size_t n = frame(buf, 0x21, (const uint8_t *)"abc", 3);
    n += frame(buf + n, 0x01, hy2_frozen_ok, sizeof hy2_frozen_ok);
    uint8_t *m = mdup(buf, n);
    r.status = 0; r.rx_bps = 0;
    check("response after an unknown frame", 1, hy2_auth_response(m, n, &r));
    check("response after unknown status", 233, r.status);
    check("response after unknown rate", 13107200, (long)r.rx_bps);
    free(m);

    size_t half = n / 2;
    m = mdup(buf, half);
    check("response first half needs more", 0, hy2_auth_response(m, half, &r));
    free(m);
    m = mdup(buf, n);
    check("response both halves", 1, hy2_auth_response(m, n, &r));
    free(m);

    check("response 404 done", 1, resp_of(hy2_frozen_404, sizeof hy2_frozen_404, &r));
    check("response 404 status", 404, r.status);
    check("response 404 rate", 0, (long)r.rx_bps);

    static const uint8_t autorx[] = { 0x00, 0x00, 0x5f, 0x09, 0x03, '2', '3', '3', 0x27, 0x07,
        'h', 'y', 's', 't', 'e', 'r', 'i', 'a', '-', 'c', 'c', '-', 'r', 'x', 0x04, 'a', 'u', 't', 'o' };
    check("response with auto done", 1, resp_of(autorx, sizeof autorx, &r));
    check("response with auto status", 233, r.status);
    check("response with auto rate", 0, (long)r.rx_bps);
    check("response without hysteria-udp: udp 1", 1, r.udp);

    for (size_t k = 0; k < n; k++) {
        m = mdup(buf, k);
        check("every proper prefix needs more", 0, hy2_auth_response(m, k, &r));
        free(m);
    }
}

static int fields_end(const uint8_t *sec, size_t n) {
    uint8_t *m = mdup(sec, n);
    const uint8_t *p = m, *end = m + n;
    struct hy2_field *f = malloc(sizeof *f);
    int rc = hy2_qpack_start(&p, end);
    if (rc == 0) do rc = hy2_qpack_next(&p, end, f); while (rc == 1);
    free(f);
    free(m);
    return rc;
}

static void t_hostile(void) {
    static const struct { const char *what; const char *sec; size_t n; } c[] = {
        { "insert count 1", "\x01\x00\xd9", 3 },
        { "base not zero", "\x00\x01\xd9", 3 },
        { "dynamic indexed field", "\x00\x00\xd9\x80", 4 },
        { "dynamic indexed field, long form", "\x00\x00\xd9\xbf\x00", 5 },
        { "dynamic name reference", "\x00\x00\xd9\x41\x80", 5 },
        { "post-base index", "\x00\x00\xd9\x10", 4 },
        { "post-base name reference", "\x00\x00\xd9\x00\x00", 5 },
        { "huffman literal runs past the frame", "\x00\x00\xd9\x51\x8a\xaa", 6 },
        { "plain literal runs past the frame", "\x00\x00\xd9\x51\x05" "ab", 7 },
        { "varint cut at the end", "\x00\x00\xd9\x5f", 4 },
        { "varint cut after a continuation", "\x00\x00\xd9\x5f\x80", 5 },
        { "static index out of range", "\x00\x00\xd9\xff\x24", 5 },
        { "literal name runs past the frame", "\x00\x00\xd9\x27\x61", 5 },
        { "literal name with a NUL", "\x00\x00\xd9\x22" "a\0\x01" "v", 8 },
        { "value with a NUL", "\x00\x00\xd9\x51\x03" "a\0" "b", 8 },
    };
    struct hy2_auth_resp r;
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        uint8_t *s = mdup(c[i].sec, c[i].n);
        check(c[i].what, -1, resp_of(s, c[i].n, &r));
        free(s);
        check(c[i].what, -1, fields_end((const uint8_t *)c[i].sec, c[i].n));
    }
    static const struct { const char *what; const char *sec; size_t n; } nost[] = {
        { "no :status", "\x00\x00\xc4", 3 },
        { "empty section", "", 0 },
    };
    for (size_t i = 0; i < sizeof nost / sizeof nost[0]; i++) {
        uint8_t *s = mdup(nost[i].sec, nost[i].n);
        check(nost[i].what, -1, resp_of(s, nost[i].n, &r));
        free(s);
    }
    static const uint8_t pre[4][2] = { { 1, 0 }, { 0, 1 }, { 0, 0x81 }, { 0x80, 0 } };
    for (int i = 0; i < 4; i++) {
        uint8_t sec[sizeof hy2_frozen_404];
        memcpy(sec, hy2_frozen_404, sizeof sec);
        sec[0] = pre[i][0];
        sec[1] = pre[i][1];
        uint8_t *s = mdup(sec, sizeof sec);
        check("a prefix other than 00 00 on a good section", -1, resp_of(s, sizeof sec, &r));
        free(s);
    }
    uint8_t *one = mdup("\x00", 1);
    const uint8_t *p = one, *end = one + 1;
    check("start with one byte", -1, hy2_qpack_start(&p, end));
    free(one);

    uint8_t *huge = calloc(1, 3 + 16382);
    huge[0] = 0x21;
    huge[1] = 0x40 | (16382 >> 8);
    huge[2] = (uint8_t)16382;
    uint8_t *m = mdup(huge, 3 + 16382);
    check("16385 bytes of unknown frames", -1, hy2_auth_response(m, 3 + 16382, &r));
    free(m);
    huge[1] = 0x40 | (16381 >> 8);
    huge[2] = (uint8_t)16381;
    m = mdup(huge, 3 + 16381);
    check("16384 bytes of unknown frames still wait", 0, hy2_auth_response(m, 3 + 16381, &r));
    free(m);
    free(huge);
}

static size_t pint(uint8_t *o, unsigned bits, uint8_t flags, size_t v) {
    size_t k = ((size_t)1 << bits) - 1, n = 0;
    if (v < k) { o[0] = (uint8_t)(flags | v); return 1; }
    o[n++] = (uint8_t)(flags | k);
    v -= k;
    for (; v >= 128; v >>= 7) o[n++] = (uint8_t)(0x80 | (v & 0x7f));
    o[n++] = (uint8_t)v;
    return n;
}

static uint8_t *huff_section(const char *name, size_t name_n, const char *val, size_t val_n, size_t *total) {
    uint8_t *b = malloc(16 + name_n * 4 + val_n * 4);
    size_t k = 0, h;
    b[k++] = 0;
    b[k++] = 0;
    if (name) {
        h = hpe_huff_len(name, name_n);
        k += pint(b + k, 3, 0x28, h);
        k += hpe_huff(b + k, name, name_n);
    } else {
        b[k++] = 0x51;
    }
    h = hpe_huff_len(val, val_n);
    k += pint(b + k, 7, 0x80, h);
    k += hpe_huff(b + k, val, val_n);
    uint8_t *m = mdup(b, k);
    free(b);
    *total = k;
    return m;
}

static int huff_next(const char *name, size_t name_n, const char *val, size_t val_n, struct hy2_field *f) {
    size_t n;
    uint8_t *m = huff_section(name, name_n, val, val_n, &n);
    const uint8_t *p = m, *end = m + n;
    int rc = hy2_qpack_start(&p, end);
    if (rc == 0) rc = hy2_qpack_next(&p, end, f);
    free(m);
    return rc;
}

static void t_huffman_limits(void) {
    char *a = malloc(2400);
    memset(a, 'a', 2400);
    struct hy2_field *f = malloc(sizeof *f);
    check("huffman name of 63 accepted", 1, huff_next(a, 63, "v", 1, f));
    check("huffman name of 63 length", 63, (long)strlen(f->name));
    check_mem("huffman name of 63 bytes", a, f->name, 63);
    check_str("huffman name of 63 value", "v", f->value);
    free(f);
    f = malloc(sizeof *f);
    check("huffman name of 64 refused", -1, huff_next(a, 64, "v", 1, f));
    free(f);
    f = malloc(sizeof *f);
    check("huffman value of 2303 accepted", 1, huff_next(NULL, 0, a, 2303, f));
    check("huffman value of 2303 length", 2303, (long)strlen(f->value));
    check_mem("huffman value of 2303 bytes", a, f->value, 2303);
    free(f);
    f = malloc(sizeof *f);
    check("huffman value of 2304 refused", -1, huff_next(NULL, 0, a, 2304, f));
    free(f);
    f = malloc(sizeof *f);
    check("huffman value with a NUL refused", -1, huff_next(NULL, 0, "a\0b", 3, f));
    free(f);
    f = malloc(sizeof *f);
    check("huffman name with a NUL refused", -1, huff_next("a\0b", 3, "v", 1, f));
    free(f);
    free(a);
}

static uint8_t *status_rate(const char *st, const char *rx, size_t *total) {
    uint8_t b[128];
    size_t k = 0, sl = strlen(st), rl = strlen(rx);
    b[k++] = 0; b[k++] = 0;
    b[k++] = 0x5f; b[k++] = 0x09;
    b[k++] = (uint8_t)sl;
    memcpy(b + k, st, sl); k += sl;
    b[k++] = 0x27; b[k++] = 0x07;
    memcpy(b + k, "hysteria-cc-rx", 14); k += 14;
    b[k++] = (uint8_t)rl;
    memcpy(b + k, rx, rl); k += rl;
    *total = k;
    return mdup(b, k);
}

static int sr(const char *st, const char *rx, struct hy2_auth_resp *r) {
    size_t n;
    uint8_t *m = status_rate(st, rx, &n);
    int rc = resp_of(m, n, r);
    free(m);
    return rc;
}

static void t_status_and_rate(void) {
    struct hy2_auth_resp r;
    check("status with a leading zero", 1, sr("0233", "1", &r));
    check("status with a leading zero value", 233, r.status);
    check("status of five digits", 1, sr("12345", "1", &r));
    check("status of five digits value", 12345, r.status);
    check("status above 999", 1, sr("1000", "1", &r));
    check("status above 999 value", 1000, r.status);
    check("status with a plus", 1, sr("+233", "1", &r));
    check("status with a plus value", 233, r.status);
    check("status with a minus", 1, sr("-233", "1", &r));
    check("status with a minus value", -233, r.status);
    check("status of thirteen digits with leading zeros", 1, sr("0000000000233", "1", &r));
    check("status of thirteen digits with leading zeros value", 233, r.status);
    check("status of a plus alone", -1, sr("+", "1", &r));
    check("status of a minus alone", -1, sr("-", "1", &r));
    check("status with a leading space", -1, sr(" 233", "1", &r));
    check("status with a trailing space", -1, sr("233 ", "1", &r));
    check("status with an underscore", -1, sr("2_33", "1", &r));
    check("status over the int range", -1, sr("2147483648", "1", &r));
    check("status at the int limit", 1, sr("2147483647", "1", &r));
    check("status at the int limit value", 2147483647, r.status);
    check("status not digits", -1, sr("2x3", "1", &r));
    check("empty status", -1, sr("", "1", &r));
    check("rate at the 64-bit limit", 1, sr("233", "18446744073709551615", &r));
    check("rate at the 64-bit limit value", 1, r.rx_bps == UINT64_MAX);
    check("rate over the 64-bit limit", 1, sr("233", "18446744073709551616", &r));
    check("rate over the limit saturates", 1, r.rx_bps == UINT64_MAX);
    check("rate far over the limit", 1, sr("233", "99999999999999999999", &r));
    check("rate far over the limit saturates", 1, r.rx_bps == UINT64_MAX);
    check("rate over the limit before junk", 1, sr("233", "99999999999999999999x", &r));
    check("rate over the limit before junk saturates", 1, r.rx_bps == UINT64_MAX);
    check("rate with junk before the overflow", 0, sr("233", "1x9999999999999999999999", &r) == 1 ? (long)r.rx_bps : -1);
    check("rate with a sign", 0, sr("233", "-5", &r) == 1 ? (long)r.rx_bps : -1);
    check("rate of auto", 0, sr("233", "auto", &r) == 1 ? (long)r.rx_bps : -1);
    check("rate with trailing junk", 0, sr("233", "12abc", &r) == 1 ? (long)r.rx_bps : -1);
}

static int fields(const char *const *kv, size_t n, struct hy2_auth_resp *r) {
    uint8_t b[256];
    size_t k = 0;
    b[k++] = 0; b[k++] = 0;
    for (size_t i = 0; i < n; i++) {
        size_t nl = strlen(kv[2 * i]), vl = strlen(kv[2 * i + 1]);
        if (!strcmp(kv[2 * i], ":status")) {
            b[k++] = 0x5f; b[k++] = 0x09;
        } else {
            b[k++] = 0x27; b[k++] = (uint8_t)(nl - 7);
            memcpy(b + k, kv[2 * i], nl); k += nl;
        }
        b[k++] = (uint8_t)vl;
        memcpy(b + k, kv[2 * i + 1], vl); k += vl;
    }
    uint8_t *m = mdup(b, k);
    int rc = resp_of(m, k, r);
    free(m);
    return rc;
}

static void t_repeated_fields(void) {
    struct hy2_auth_resp r;
    static const char *const auto_first[] = { ":status", "233", "hysteria-cc-rx", "auto", "hysteria-cc-rx", "6553600" };
    check("two rates, auto first", 1, fields(auto_first, 3, &r));
    check("two rates, auto first: the first wins", 0, (long)r.rx_bps);
    static const char *const rate_first[] = { ":status", "233", "hysteria-cc-rx", "6553600", "hysteria-cc-rx", "auto" };
    check("two rates, a rate first", 1, fields(rate_first, 3, &r));
    check("two rates, a rate first: the first wins", 6553600, (long)r.rx_bps);
    static const char *const udp_off_first[] = { ":status", "233", "hysteria-udp", "false", "hysteria-udp", "true" };
    check("two udp fields, false first", 1, fields(udp_off_first, 3, &r));
    check("two udp fields, false first: the first wins", 0, r.udp);
    static const char *const udp_on_first[] = { ":status", "233", "hysteria-udp", "true", "hysteria-udp", "false" };
    check("two udp fields, true first", 1, fields(udp_on_first, 3, &r));
    check("two udp fields, true first: the first wins", 1, r.udp);
    static const char *const two_status[] = { ":status", "404", ":status", "233" };
    check("two statuses are refused", -1, fields(two_status, 2, &r));
    static const char *const empty_first[] = { ":status", "", ":status", "233" };
    check("an empty status then a status", 1, fields(empty_first, 2, &r));
    check("an empty status then a status: the status", 233, r.status);
    static const char *const empty_twice[] = { ":status", "", ":status", "" };
    check("two empty statuses are refused", -1, fields(empty_twice, 2, &r));
    static const char *const junk_first[] = { ":status", "abc", ":status", "233" };
    check("a junk status then a status is refused", -1, fields(junk_first, 2, &r));
    static const char *const udp_cased[] = { ":status", "233", "hysteria-udp", "False" };
    check("udp False", 1, fields(udp_cased, 2, &r));
    check("udp False keeps udp on", 1, r.udp);
    static const char *const udp_zero[] = { ":status", "233", "hysteria-udp", "0" };
    check("udp 0", 1, fields(udp_zero, 2, &r));
    check("udp 0 keeps udp on", 1, r.udp);
}

static void t_frames_before_headers(void) {
    static const uint8_t types[] = { 0x00, 0x02, 0x04, 0x06, 0x07, 0x08, 0x09 };
    static const uint8_t skipped[] = { 0x03, 0x05, 0x0d, 0x21 };
    struct hy2_auth_resp r;
    uint8_t buf[700];
    for (size_t i = 0; i < sizeof types; i++) {
        size_t n = frame(buf, types[i], (const uint8_t *)"abc", 3);
        n += frame(buf + n, 0x01, hy2_frozen_ok, sizeof hy2_frozen_ok);
        uint8_t *m = mdup(buf, n);
        check("frame type refused before HEADERS", -1, hy2_auth_response(m, n, &r));
        free(m);
        n = frame(buf, types[i], (const uint8_t *)"abc", 3);
        m = mdup(buf, n);
        check("frame type refused alone", -1, hy2_auth_response(m, n, &r));
        free(m);
    }
    for (size_t i = 0; i < sizeof skipped; i++) {
        size_t n = frame(buf, skipped[i], (const uint8_t *)"abc", 3);
        n += frame(buf + n, 0x01, hy2_frozen_ok, sizeof hy2_frozen_ok);
        uint8_t *m = mdup(buf, n);
        check("frame type skipped before HEADERS", 1, hy2_auth_response(m, n, &r));
        free(m);
    }
}

static void t_prefix_and_long_ints(void) {
    struct hy2_auth_resp r;
    uint8_t sec[sizeof hy2_frozen_404];
    memcpy(sec, hy2_frozen_404, sizeof sec);
    sec[1] = 0x80;
    uint8_t *m = mdup(sec, sizeof sec);
    check("sign bit with a zero delta is base 0", 1, resp_of(m, sizeof sec, &r));
    free(m);
    static const uint8_t longint[] = { 0x00, 0x00, 0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };
    m = mdup(longint, sizeof longint);
    check("overlong index done", 1, resp_of(m, sizeof longint, &r));
    check("overlong index is :status 100", 100, r.status);
    free(m);
    static const uint8_t huge[] = { 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
    m = mdup(huge, sizeof huge);
    check("index beyond 32 bits", -1, fields_end(m, sizeof huge));
    free(m);
}

static void t_tcp_request(void) {
    uint8_t out[256], want[256];
    char pad[64];
    memset(pad, 'x', sizeof pad);
    size_t n = hy2_tcp_request(out, sizeof out, "example.com", 443, pad, sizeof pad);
    memcpy(want, "\x44\x01\x0f" "example.com:443" "\x40\x40", 20);
    memset(want + 20, 'x', 64);
    check("tcp request length", 84, (long)n);
    check_mem("tcp request bytes", want, out, 84);

    char addr[64];
    size_t used = 0;
    uint8_t *m = mdup(out + 2, n - 2);
    check("tcp request parses", 1, hy2_tcp_request_parse(m, n - 2, addr, sizeof addr, &used));
    check_str("tcp request address", "example.com:443", addr);
    check("tcp request used", 82, (long)used);
    free(m);
    for (size_t k = 0; k < n - 2; k++) {
        m = mdup(out + 2, k);
        check("tcp request prefix needs more", 0, hy2_tcp_request_parse(m, k, addr, sizeof addr, &used));
        free(m);
    }

    n = hy2_tcp_request(out, sizeof out, "2001:db8::1", 443, pad, 0);
    check("tcp request v6 length byte", 0x11, out[2]);
    check_mem("tcp request v6 address", "[2001:db8::1]:443", out + 3, 17);
    n = hy2_tcp_request(out, sizeof out, "[2001:db8::1]", 443, pad, 0);
    check_mem("tcp request bracketed v6 stays", "[2001:db8::1]:443", out + 3, 17);
    check("tcp request without padding", 2 + 1 + 17 + 1, (long)n);

    m = mdup("\x00", 1);
    check("address length 0", -1, hy2_tcp_request_parse(m, 1, addr, sizeof addr, &used));
    free(m);
    char *wide = malloc(4096);
    m = mdup("\x48\x01", 2);
    check("address length 2049", -1, hy2_tcp_request_parse(m, 2, wide, 4096, &used));
    free(m);
    uint8_t *full = calloc(1, 2 + 2048 + 1);
    full[0] = 0x48; full[1] = 0x00;
    memset(full + 2, 'a', 2048);
    m = mdup(full, 2 + 2048 + 1);
    check("address length 2048", 1, hy2_tcp_request_parse(m, 2 + 2048 + 1, wide, 4096, &used));
    check("address length 2048 used", 2 + 2048 + 1, (long)used);
    free(m);
    free(full);
    free(wide);
    m = mdup("\x03" "abc" "\x50\x01", 6);
    check("padding length 4097", -1, hy2_tcp_request_parse(m, 6, addr, sizeof addr, &used));
    free(m);
    m = mdup("\x05" "abcde" "\x00", 7);
    check("address larger than the buffer", -1, hy2_tcp_request_parse(m, 7, addr, 5, &used));
    check("address that just fits", 1, hy2_tcp_request_parse(m, 7, addr, 6, &used));
    free(m);
    check("one-letter host written", 1, hy2_tcp_request(out, sizeof out, "h", 1, pad, 0) > 0);
    check("empty host refused", 0, (long)hy2_tcp_request(out, sizeof out, "", 1, pad, 0));
    check("padding over 4096 not written", 0, (long)hy2_tcp_request(out, sizeof out, "h", 1, pad, 4097));
    check("small buffer not written", 0, (long)hy2_tcp_request(out, 5, "example.com", 443, pad, 0));
}

static void t_tcp_response(void) {
    struct hy2_tcp_resp r;
    uint8_t *m = mdup("\x00\x00\x00", 3);
    check("response ok", 1, hy2_tcp_response(m, 3, &r));
    check("response ok flag", 1, r.ok);
    check("response ok used", 3, (long)r.used);
    free(m);

    m = mdup("\x01\x04nope\x02pp", 9);
    check("response refused", 1, hy2_tcp_response(m, 9, &r));
    check("response refused flag", 0, r.ok);
    check_str("response refused message", "nope", r.msg);
    check("response refused used", 9, (long)r.used);
    free(m);

    m = mdup("\x02\x00\x00", 3);
    check("status 2 done", 1, hy2_tcp_response(m, 3, &r));
    check("status 2 is not ok", 0, r.ok);
    free(m);
    m = mdup("\xff\x00\x00", 3);
    check("status 255 is not ok", 1, hy2_tcp_response(m, 3, &r) == 1 && r.ok == 0);
    free(m);
    m = mdup("\x00\x40", 2);
    check("response cut inside a varint", 0, hy2_tcp_response(m, 2, &r));
    free(m);
    m = mdup("\x01\x48\x01", 3);
    check("message length 2049", -1, hy2_tcp_response(m, 3, &r));
    free(m);
    m = mdup("\x00\x00\x50\x01", 4);
    check("padding length 4097", -1, hy2_tcp_response(m, 4, &r));
    free(m);

    uint8_t big[200 + 8], out[400];
    big[0] = 0x01; big[1] = 0x40; big[2] = 200;
    memset(big + 3, 'm', 200);
    big[203] = 0;
    m = mdup(big, 204);
    check("long message done", 1, hy2_tcp_response(m, 204, &r));
    check("long message cut", 127, (long)strlen(r.msg));
    check("long message used", 204, (long)r.used);
    free(m);

    size_t n = hy2_tcp_response_put(out, sizeof out, 1, "", 128);
    check("response put length", 132, (long)n);
    check_hex("response put head", "00004080", out, 4);
    m = mdup(out, n);
    check("response put parses", 1, hy2_tcp_response(m, n, &r));
    check("response put used", 132, (long)r.used);
    free(m);
    n = hy2_tcp_response_put(out, sizeof out, 0, "no", 0);
    check_hex("response put refusal", "01026e6f00", out, n);
    check("response put small buffer", 0, (long)hy2_tcp_response_put(out, 131, 1, "", 128));
    check("response put big padding", 0, (long)hy2_tcp_response_put(out, sizeof out, 1, "", 4097));
}

static void t_udp(void) {
    uint8_t out[64];
    size_t n = hy2_udp_header(out, sizeof out, 0x01020304, 0, 0, 1, "1.2.3.4", 53);
    check_hex("udp header", "010203040000000" "10a" "312e322e332e343a3533", out, n);
    check("udp header length", 19, (long)n);
    out[n] = 'h'; out[n + 1] = 'i';
    uint8_t *m = mdup(out, n + 2);
    struct hy2_udp_msg u;
    check("udp parse", 0, hy2_udp_parse(m, n + 2, &u));
    check("udp sid", 0x01020304, (long)u.sid);
    check("udp pkt", 0, u.pkt);
    check("udp frag", 0, u.frag);
    check("udp count", 1, u.count);
    check("udp addr_n", 10, (long)u.addr_n);
    check_mem("udp addr", "1.2.3.4:53", u.addr, 10);
    check("udp data_n", 2, (long)u.data_n);
    check_mem("udp data", "hi", u.data, 2);
    free(m);
    m = mdup(out, n);
    check("udp no data", -1, hy2_udp_parse(m, n, &u));
    free(m);
    m = mdup(out, 8);
    check("udp shorter than 9", -1, hy2_udp_parse(m, 8, &u));
    free(m);
    m = mdup(out, 9);
    check("udp nine bytes", -1, hy2_udp_parse(m, 9, &u));
    free(m);
    out[8] = 0x30;
    m = mdup(out, n + 2);
    check("udp address runs past", -1, hy2_udp_parse(m, n + 2, &u));
    free(m);
    out[8] = 0;
    m = mdup(out, n + 2);
    check("udp address length 0", -1, hy2_udp_parse(m, n + 2, &u));
    free(m);
    n = hy2_udp_header(out, sizeof out, 0xa1b2c3d4, 0x0102, 3, 7, "::1", 9);
    check_hex("udp v6 header", "a1b2c3d401020307" "07" "5b3a3a315d3a39", out, n);
    check("udp empty host refused", 0, (long)hy2_udp_header(out, sizeof out, 1, 0, 0, 1, "", 53));
    check("udp header small buffer", 0, (long)hy2_udp_header(out, 18, 1, 0, 0, 1, "1.2.3.4", 53));
}

static void t_frags(void) {
    check("3000 bytes", 3, (long)hy2_udp_frags(3000, 19, 1197));
    check("1178 bytes", 1, (long)hy2_udp_frags(1178, 19, 1197));
    check("1179 bytes", 2, (long)hy2_udp_frags(1179, 19, 1197));
    check("limit equals header", 0, (long)hy2_udp_frags(10, 19, 19));
    check("limit under header", 0, (long)hy2_udp_frags(10, 19, 5));
    check("40000 bytes", 0, (long)hy2_udp_frags(40000, 19, 1197));
    check("exactly 32 fragments", 32, (long)hy2_udp_frags(32 * 1178, 19, 1197));
    check("33 fragments", 0, (long)hy2_udp_frags(32 * 1178 + 1, 19, 1197));
}

static struct hy2_udp_msg mk(uint16_t pkt, uint8_t frag, uint8_t count, const uint8_t *d, size_t n) {
    struct hy2_udp_msg m;
    memset(&m, 0, sizeof m);
    m.pkt = pkt; m.frag = frag; m.count = count; m.data = d; m.data_n = n;
    return m;
}

static void t_rasm(void) {
    uint8_t data[3000];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 7 + 3);
    struct hy2_rasm r;
    memset(&r, 0, sizeof r);
    size_t n = 0;
    struct hy2_udp_msg m;
    m = mk(7, 2, 3, data + 2000, 1000);
    check("fragment 2 first", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(7, 0, 3, data, 1000);
    check("fragment 0", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(7, 0, 3, data + 500, 1000);
    check("duplicate", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(7, 1, 3, data + 1000, 1000);
    const uint8_t *w = hy2_rasm_feed(&r, &m, &n);
    check("whole message returned", 1, w != NULL);
    check("whole message length", 3000, (long)n);
    if (w) check_mem("whole message bytes", data, w, 3000);

    m = mk(7, 0, 3, data, 1000);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(7, 1, 3, data + 1000, 1000);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(8, 0, 3, data, 1000);
    check("other packet replaces", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(7, 2, 3, data + 2000, 1000);
    check("replaced packet does not finish", 1, hy2_rasm_feed(&r, &m, &n) == NULL);

    m = mk(9, 0, 2, data, 10);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(9, 1, 3, data, 10);
    check("other count replaces", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(9, 2, 3, data, 10);
    check("replaced count keeps one piece", 1, hy2_rasm_feed(&r, &m, &n) == NULL);

    m = mk(10, 3, 3, data, 10);
    check("frag 3 of 3 ignored", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(10, 0, 3, data, 500);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(10, 5, 3, data, 10);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(10, 1, 3, data + 500, 500);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(10, 2, 3, data + 1000, 5);
    w = hy2_rasm_feed(&r, &m, &n);
    check("out of range frag left the rest alone", 1005, (long)n);
    if (w) check_mem("pieces of unequal size joined", data, w, 1005);

    uint8_t one[5] = { 1, 2, 3, 4, 5 };
    m = mk(11, 0, 3, data, 10);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(0, 0, 0, one, 5);
    w = hy2_rasm_feed(&r, &m, &n);
    check("count 0 returned at once", 1, w == one);
    check("count 0 length", 5, (long)n);
    m = mk(0, 0, 1, one, 5);
    w = hy2_rasm_feed(&r, &m, &n);
    check("count 1 returned at once", 1, w == one);
    m = mk(11, 1, 3, data + 10, 10);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(11, 2, 3, data + 20, 10);
    w = hy2_rasm_feed(&r, &m, &n);
    check("single frames left the partial alone", 30, (long)n);
    if (w) check_mem("partial finished", data, w, 30);

    m = mk(12, 0, 3, data, 10);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(12, 1, 33, data, 10);
    check("count 33 refused", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(12, 1, 3, data + 10, 10);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(12, 2, 3, data + 20, 10);
    check("count 33 dropped the partial", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(13, 0, 255, data, 10);
    check("count 255 refused", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    for (uint8_t f = 0; f < 3; f++) {
        m = mk(14, f, 3, data + f * 100, 100);
        w = hy2_rasm_feed(&r, &m, &n);
    }
    check("a following packet still assembles", 300, (long)n);
    if (w) check_mem("following packet bytes", data, w, 300);

    uint8_t *big = calloc(1, 2049);
    m = mk(15, 0, 2, data, 10);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(15, 1, 2, big, 2049);
    check("2049 bytes dropped", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(15, 0, 2, data, 10);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(15, 1, 2, big, 2048);
    w = hy2_rasm_feed(&r, &m, &n);
    check("2048 bytes accepted", 2058, (long)n);
    free(big);

    m = mk(16, 0, 32, data, 1);
    hy2_rasm_feed(&r, &m, &n);
    hy2_rasm_free(&r);
    check("free clears the buffer", 1, r.buf == NULL);
    hy2_rasm_free(&r);
    m = mk(17, 0, 32, data, 1);
    hy2_rasm_feed(&r, &m, &n);
    for (uint8_t f = 1; f < 32; f++) {
        m = mk(17, f, 32, data + f, 1);
        w = hy2_rasm_feed(&r, &m, &n);
    }
    check("32 fragments assemble", 32, (long)n);
    if (w) check_mem("32 fragments bytes", data, w, 32);
    hy2_rasm_free(&r);

    m = mk(7, 0, 3, data, 1000);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(7, 1, 3, data + 1000, 1000);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(8, 5, 3, data, 10);
    check("out of range fragment of another packet", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(7, 2, 3, data + 2000, 1000);
    w = hy2_rasm_feed(&r, &m, &n);
    check("the partial packet survived", 3000, (long)n);
    if (w) check_mem("the partial packet bytes", data, w, 3000);
    hy2_rasm_free(&r);

    m = mk(7, 0, 3, data, 1000);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(7, 1, 40, data, 10);
    check("count beyond max with a high fragment", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    m = mk(7, 1, 3, data + 1000, 1000);
    hy2_rasm_feed(&r, &m, &n);
    m = mk(7, 2, 3, data + 2000, 1000);
    check("count beyond max dropped the partial", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    hy2_rasm_free(&r);

    for (uint8_t f = 0; f < 3; f++) {
        m = mk(21, f, 3, data + f * 100, 100);
        w = hy2_rasm_feed(&r, &m, &n);
    }
    check("a packet delivered once", 300, (long)n);
    for (uint8_t f = 0; f < 3; f++) {
        m = mk(21, f, 3, data + f * 100, 100);
        check("a fragment of a delivered packet is ignored", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    }
    m = mk(21, 0, 4, data, 10);
    check("same packet with another count starts over", 1, hy2_rasm_feed(&r, &m, &n) == NULL);
    for (uint8_t f = 1; f < 4; f++) {
        m = mk(21, f, 4, data + f * 10, 10);
        w = hy2_rasm_feed(&r, &m, &n);
    }
    check("and then delivers", 40, (long)n);
    for (uint8_t f = 0; f < 2; f++) {
        m = mk(22, f, 2, data + f * 5, 5);
        w = hy2_rasm_feed(&r, &m, &n);
    }
    check("another packet after a delivered one", 10, (long)n);
    if (w) check_mem("another packet bytes", data, w, 10);
    hy2_rasm_free(&r);
}

static void t_pad(void) {
    check("pad len low", 256, (long)hy2_pad_len(0, 256, 2048));
    check("pad len high", 2047, (long)hy2_pad_len(1791, 256, 2048));
    check("pad len wraps", 256, (long)hy2_pad_len(1792, 256, 2048));
    static const uint8_t rnd[7] = { 0, 25, 26, 51, 52, 61, 62 };
    char out[8];
    hy2_pad_fill(out, 7, rnd);
    out[7] = 0;
    check_str("pad alphabet", "azAZ09a", out);
}

static void t_salamander(void) {
    static const uint8_t key[32] = { 0xd4, 0x62, 0x1a, 0x0b, 0xf0, 0x98, 0x94, 0xdc, 0xf7, 0x8a, 0x77, 0x7b,
        0xa0, 0x36, 0xd1, 0x1d, 0xd2, 0xc1, 0x40, 0x84, 0x87, 0x85, 0xb0, 0x63, 0x87, 0x72, 0x59, 0xb3,
        0x2f, 0x48, 0xce, 0x4a };
    static const uint8_t salt[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t pay[40], want[48], out[48], back[48];
    for (int i = 0; i < 40; i++) pay[i] = (uint8_t)i;
    memcpy(want, salt, 8);
    for (int i = 0; i < 40; i++) want[8 + i] = pay[i] ^ key[i % 32];
    struct hy2_salamander s;
    check("salamander init", 0, hy2_salamander_init(&s, "test"));
    check("salamander wrap length", 48, (long)hy2_salamander_wrap(&s, salt, out, pay, 40));
    check_mem("salamander wrap bytes", want, out, 48);
    uint8_t *m = mdup(out, 48);
    check("salamander unwrap length", 40, (long)hy2_salamander_unwrap(&s, back, m, 48));
    check_mem("salamander unwrap bytes", pay, back, 40);
    free(m);
    m = mdup(out, 8);
    check("salamander unwrap of 8", 0, (long)hy2_salamander_unwrap(&s, back, m, 8));
    free(m);
    m = mdup(out, 7);
    check("salamander unwrap of 7", 0, (long)hy2_salamander_unwrap(&s, back, m, 7));
    free(m);
    uint8_t *io = malloc(48);
    memcpy(io, pay, 40);
    check("salamander wrap in place length", 48, (long)hy2_salamander_wrap(&s, salt, io, io, 40));
    check_mem("salamander wrap in place bytes", want, io, 48);
    free(io);
    io = malloc(48);
    memcpy(io + 8, pay, 40);
    check("salamander wrap shifted in place length", 48, (long)hy2_salamander_wrap(&s, salt, io, io + 8, 40));
    check_mem("salamander wrap shifted in place bytes", want, io, 48);
    free(io);
    check("salamander password of 3", -1, hy2_salamander_init(&s, "abc"));
    char pw[300];
    memset(pw, 'k', sizeof pw);
    pw[256] = 0;
    check("salamander password of 256", 0, hy2_salamander_init(&s, pw));
    pw[256] = 'k';
    pw[257] = 0;
    check("salamander password of 257", -1, hy2_salamander_init(&s, pw));
    hy2_salamander_init(&s, "test");
    memcpy(back, out, 48);
    check("salamander unwrap in place", 40, (long)hy2_salamander_unwrap(&s, back, back, 48));
    check_mem("salamander unwrap in place bytes", pay, back, 40);
}

int main(void) {
    t_varints();
    t_control();
    t_auth_request();
    t_qpack_fields();
    t_value_limits();
    t_auth_response();
    t_hostile();
    t_huffman_limits();
    t_status_and_rate();
    t_repeated_fields();
    t_frames_before_headers();
    t_prefix_and_long_ints();
    t_tcp_request();
    t_tcp_response();
    t_udp();
    t_frags();
    t_rasm();
    t_pad();
    t_salamander();
    return unit_done("hy2wirematch");
}
