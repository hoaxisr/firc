#ifndef TUNVLESS_TESTS_HPACKREAD_H
#define TUNVLESS_TESTS_HPACKREAD_H
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define HR_MAX 256

struct hr_field {
    int kind;
    unsigned index;
    int hname, hvalue;
    char name[64];
    char value[20480];
};

struct hr_block {
    size_t n;
    size_t nupd;
    uint32_t upd[2];
    struct hr_field f[HR_MAX];
};

#define HR_DYN 256

struct hr_ent {
    size_t nl, vl;
    char name[64];
    char value[4100];
};

struct hr_ctx {
    uint32_t settings, max;
    size_t size, n, head;
    struct hr_ent e[HR_DYN];
};

static const struct { uint32_t code; uint8_t len; } hr_huff[257] = {
    { 0x1ff8, 13 }, { 0x7fffd8, 23 }, { 0xfffffe2, 28 }, { 0xfffffe3, 28 }, { 0xfffffe4, 28 }, { 0xfffffe5, 28 },
    { 0xfffffe6, 28 }, { 0xfffffe7, 28 }, { 0xfffffe8, 28 }, { 0xffffea, 24 }, { 0x3ffffffc, 30 }, { 0xfffffe9, 28 },
    { 0xfffffea, 28 }, { 0x3ffffffd, 30 }, { 0xfffffeb, 28 }, { 0xfffffec, 28 }, { 0xfffffed, 28 }, { 0xfffffee, 28 },
    { 0xfffffef, 28 }, { 0xffffff0, 28 }, { 0xffffff1, 28 }, { 0xffffff2, 28 }, { 0x3ffffffe, 30 }, { 0xffffff3, 28 },
    { 0xffffff4, 28 }, { 0xffffff5, 28 }, { 0xffffff6, 28 }, { 0xffffff7, 28 }, { 0xffffff8, 28 }, { 0xffffff9, 28 },
    { 0xffffffa, 28 }, { 0xffffffb, 28 }, { 0x14, 6 }, { 0x3f8, 10 }, { 0x3f9, 10 }, { 0xffa, 12 },
    { 0x1ff9, 13 }, { 0x15, 6 }, { 0xf8, 8 }, { 0x7fa, 11 }, { 0x3fa, 10 }, { 0x3fb, 10 },
    { 0xf9, 8 }, { 0x7fb, 11 }, { 0xfa, 8 }, { 0x16, 6 }, { 0x17, 6 }, { 0x18, 6 },
    { 0x0, 5 }, { 0x1, 5 }, { 0x2, 5 }, { 0x19, 6 }, { 0x1a, 6 }, { 0x1b, 6 },
    { 0x1c, 6 }, { 0x1d, 6 }, { 0x1e, 6 }, { 0x1f, 6 }, { 0x5c, 7 }, { 0xfb, 8 },
    { 0x7ffc, 15 }, { 0x20, 6 }, { 0xffb, 12 }, { 0x3fc, 10 }, { 0x1ffa, 13 }, { 0x21, 6 },
    { 0x5d, 7 }, { 0x5e, 7 }, { 0x5f, 7 }, { 0x60, 7 }, { 0x61, 7 }, { 0x62, 7 },
    { 0x63, 7 }, { 0x64, 7 }, { 0x65, 7 }, { 0x66, 7 }, { 0x67, 7 }, { 0x68, 7 },
    { 0x69, 7 }, { 0x6a, 7 }, { 0x6b, 7 }, { 0x6c, 7 }, { 0x6d, 7 }, { 0x6e, 7 },
    { 0x6f, 7 }, { 0x70, 7 }, { 0x71, 7 }, { 0x72, 7 }, { 0xfc, 8 }, { 0x73, 7 },
    { 0xfd, 8 }, { 0x1ffb, 13 }, { 0x7fff0, 19 }, { 0x1ffc, 13 }, { 0x3ffc, 14 }, { 0x22, 6 },
    { 0x7ffd, 15 }, { 0x3, 5 }, { 0x23, 6 }, { 0x4, 5 }, { 0x24, 6 }, { 0x5, 5 },
    { 0x25, 6 }, { 0x26, 6 }, { 0x27, 6 }, { 0x6, 5 }, { 0x74, 7 }, { 0x75, 7 },
    { 0x28, 6 }, { 0x29, 6 }, { 0x2a, 6 }, { 0x7, 5 }, { 0x2b, 6 }, { 0x76, 7 },
    { 0x2c, 6 }, { 0x8, 5 }, { 0x9, 5 }, { 0x2d, 6 }, { 0x77, 7 }, { 0x78, 7 },
    { 0x79, 7 }, { 0x7a, 7 }, { 0x7b, 7 }, { 0x7ffe, 15 }, { 0x7fc, 11 }, { 0x3ffd, 14 },
    { 0x1ffd, 13 }, { 0xffffffc, 28 }, { 0xfffe6, 20 }, { 0x3fffd2, 22 }, { 0xfffe7, 20 }, { 0xfffe8, 20 },
    { 0x3fffd3, 22 }, { 0x3fffd4, 22 }, { 0x3fffd5, 22 }, { 0x7fffd9, 23 }, { 0x3fffd6, 22 }, { 0x7fffda, 23 },
    { 0x7fffdb, 23 }, { 0x7fffdc, 23 }, { 0x7fffdd, 23 }, { 0x7fffde, 23 }, { 0xffffeb, 24 }, { 0x7fffdf, 23 },
    { 0xffffec, 24 }, { 0xffffed, 24 }, { 0x3fffd7, 22 }, { 0x7fffe0, 23 }, { 0xffffee, 24 }, { 0x7fffe1, 23 },
    { 0x7fffe2, 23 }, { 0x7fffe3, 23 }, { 0x7fffe4, 23 }, { 0x1fffdc, 21 }, { 0x3fffd8, 22 }, { 0x7fffe5, 23 },
    { 0x3fffd9, 22 }, { 0x7fffe6, 23 }, { 0x7fffe7, 23 }, { 0xffffef, 24 }, { 0x3fffda, 22 }, { 0x1fffdd, 21 },
    { 0xfffe9, 20 }, { 0x3fffdb, 22 }, { 0x3fffdc, 22 }, { 0x7fffe8, 23 }, { 0x7fffe9, 23 }, { 0x1fffde, 21 },
    { 0x7fffea, 23 }, { 0x3fffdd, 22 }, { 0x3fffde, 22 }, { 0xfffff0, 24 }, { 0x1fffdf, 21 }, { 0x3fffdf, 22 },
    { 0x7fffeb, 23 }, { 0x7fffec, 23 }, { 0x1fffe0, 21 }, { 0x1fffe1, 21 }, { 0x3fffe0, 22 }, { 0x1fffe2, 21 },
    { 0x7fffed, 23 }, { 0x3fffe1, 22 }, { 0x7fffee, 23 }, { 0x7fffef, 23 }, { 0xfffea, 20 }, { 0x3fffe2, 22 },
    { 0x3fffe3, 22 }, { 0x3fffe4, 22 }, { 0x7ffff0, 23 }, { 0x3fffe5, 22 }, { 0x3fffe6, 22 }, { 0x7ffff1, 23 },
    { 0x3ffffe0, 26 }, { 0x3ffffe1, 26 }, { 0xfffeb, 20 }, { 0x7fff1, 19 }, { 0x3fffe7, 22 }, { 0x7ffff2, 23 },
    { 0x3fffe8, 22 }, { 0x1ffffec, 25 }, { 0x3ffffe2, 26 }, { 0x3ffffe3, 26 }, { 0x3ffffe4, 26 }, { 0x7ffffde, 27 },
    { 0x7ffffdf, 27 }, { 0x3ffffe5, 26 }, { 0xfffff1, 24 }, { 0x1ffffed, 25 }, { 0x7fff2, 19 }, { 0x1fffe3, 21 },
    { 0x3ffffe6, 26 }, { 0x7ffffe0, 27 }, { 0x7ffffe1, 27 }, { 0x3ffffe7, 26 }, { 0x7ffffe2, 27 }, { 0xfffff2, 24 },
    { 0x1fffe4, 21 }, { 0x1fffe5, 21 }, { 0x3ffffe8, 26 }, { 0x3ffffe9, 26 }, { 0xffffffd, 28 }, { 0x7ffffe3, 27 },
    { 0x7ffffe4, 27 }, { 0x7ffffe5, 27 }, { 0xfffec, 20 }, { 0xfffff3, 24 }, { 0xfffed, 20 }, { 0x1fffe6, 21 },
    { 0x3fffe9, 22 }, { 0x1fffe7, 21 }, { 0x1fffe8, 21 }, { 0x7ffff3, 23 }, { 0x3fffea, 22 }, { 0x3fffeb, 22 },
    { 0x1ffffee, 25 }, { 0x1ffffef, 25 }, { 0xfffff4, 24 }, { 0xfffff5, 24 }, { 0x3ffffea, 26 }, { 0x7ffff4, 23 },
    { 0x3ffffeb, 26 }, { 0x7ffffe6, 27 }, { 0x3ffffec, 26 }, { 0x3ffffed, 26 }, { 0x7ffffe7, 27 }, { 0x7ffffe8, 27 },
    { 0x7ffffe9, 27 }, { 0x7ffffea, 27 }, { 0x7ffffeb, 27 }, { 0xffffffe, 28 }, { 0x7ffffec, 27 }, { 0x7ffffed, 27 },
    { 0x7ffffee, 27 }, { 0x7ffffef, 27 }, { 0x7fffff0, 27 }, { 0x3ffffee, 26 }, { 0x3fffffff, 30 },
};

static const char *const hr_static[62][2] = {
    { NULL, NULL },
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" },
};

static void hr_ctx_init(struct hr_ctx *c, uint32_t settings_max) {
    c->settings = settings_max;
    c->max = settings_max;
    c->size = 0;
    c->n = 0;
    c->head = 0;
}

static struct hr_ent *hr_dyn(struct hr_ctx *c, size_t k) {
    return &c->e[(c->head + c->n - 1 - k) % HR_DYN];
}

static void hr_evict(struct hr_ctx *c, size_t limit) {
    while (c->n && c->size > limit) {
        struct hr_ent *o = &c->e[c->head];
        c->size -= o->nl + o->vl + 32;
        c->head = (c->head + 1) % HR_DYN;
        c->n--;
    }
}

static int hr_add(struct hr_ctx *c, const char *name, const char *value) {
    size_t nl = strlen(name), vl = strlen(value), sz = nl + vl + 32;
    if (sz > c->max) { c->n = 0; c->size = 0; c->head = 0; return 0; }
    hr_evict(c, c->max - sz);
    if (c->n >= HR_DYN || nl >= sizeof c->e[0].name || vl >= sizeof c->e[0].value) return -1;
    struct hr_ent *x = &c->e[(c->head + c->n) % HR_DYN];
    memcpy(x->name, name, nl + 1);
    memcpy(x->value, value, vl + 1);
    x->nl = nl;
    x->vl = vl;
    c->n++;
    c->size += sz;
    return 0;
}

static int hr_lookup(struct hr_ctx *c, uint32_t idx, const char **name, const char **value) {
    if (idx == 0) return -1;
    if (idx <= 61) { *name = hr_static[idx][0]; *value = hr_static[idx][1]; return 0; }
    if (idx - 62 >= c->n) return -1;
    struct hr_ent *x = hr_dyn(c, idx - 62);
    *name = x->name;
    *value = x->value;
    return 0;
}

static int hr_int(const unsigned char *d, size_t n, size_t *p, unsigned bits, uint32_t *out) {
    if (*p >= n) return -1;
    uint32_t max = (1u << bits) - 1;
    uint32_t v = d[(*p)++] & max;
    if (v < max) { *out = v; return 0; }
    unsigned shift = 0;
    for (;;) {
        if (*p >= n || shift > 28) return -1;
        unsigned char c = d[(*p)++];
        v += (uint32_t)(c & 0x7F) << shift;
        shift += 7;
        if (!(c & 0x80)) break;
    }
    *out = v;
    return 0;
}

static int hr_unhuff(const unsigned char *d, size_t len, char *out, size_t cap) {
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < len * 8; i++) {
        acc = (acc << 1) | ((d[i / 8] >> (7 - i % 8)) & 1);
        bits++;
        if (bits > 30) return -1;
        for (int s = 0; s < 257; s++) {
            if (hr_huff[s].len != bits || hr_huff[s].code != acc) continue;
            if (s == 256 || o + 1 >= cap) return -1;
            out[o++] = (char)s;
            acc = 0;
            bits = 0;
            break;
        }
    }
    if (bits > 7 || acc != (1u << bits) - 1) return -1;
    out[o] = '\0';
    return 0;
}

static int hr_str(const unsigned char *d, size_t n, size_t *p, char *out, size_t cap, int *huff) {
    if (*p >= n) return -1;
    int h = (d[*p] & 0x80) != 0;
    uint32_t len;
    if (hr_int(d, n, p, 7, &len)) return -1;
    if (*p + len > n) return -1;
    if (h) {
        if (hr_unhuff(d + *p, len, out, cap)) return -1;
    } else {
        if (len >= cap) return -1;
        memcpy(out, d + *p, len);
        out[len] = '\0';
    }
    *p += len;
    if (huff) *huff = h;
    return 0;
}

static int hr_decode_ctx(struct hr_ctx *c, const unsigned char *d, size_t n, struct hr_block *b) {
    size_t p = 0;
    b->n = 0;
    b->nupd = 0;
    while (p < n) {
        uint32_t idx;
        if ((d[p] & 0xE0) == 0x20) {
            if (b->n || b->nupd >= 2) return -1;
            if (hr_int(d, n, &p, 5, &idx) || idx > c->settings) return -1;
            b->upd[b->nupd++] = idx;
            c->max = idx;
            hr_evict(c, idx);
            continue;
        }
        if (b->n >= HR_MAX) return -1;
        struct hr_field *f = &b->f[b->n];
        const char *nm, *vl;
        f->hname = 0;
        f->hvalue = 0;
        if (d[p] & 0x80) {
            if (hr_int(d, n, &p, 7, &idx) || hr_lookup(c, idx, &nm, &vl)) return -1;
            f->kind = 'i';
            f->index = idx;
            snprintf(f->name, sizeof f->name, "%s", nm);
            snprintf(f->value, sizeof f->value, "%s", vl);
            b->n++;
            continue;
        }
        unsigned bits;
        if (d[p] & 0x40) { f->kind = 'a'; bits = 6; }
        else if (d[p] & 0x10) { f->kind = 'v'; bits = 4; }
        else { f->kind = 'l'; bits = 4; }
        if (hr_int(d, n, &p, bits, &idx)) return -1;
        f->index = idx;
        if (idx) {
            if (hr_lookup(c, idx, &nm, &vl)) return -1;
            snprintf(f->name, sizeof f->name, "%s", nm);
        } else {
            if (f->kind == 'l') f->kind = 'n';
            if (hr_str(d, n, &p, f->name, sizeof f->name, &f->hname)) return -1;
        }
        if (hr_str(d, n, &p, f->value, sizeof f->value, &f->hvalue)) return -1;
        if (f->kind == 'a' && hr_add(c, f->name, f->value)) return -1;
        b->n++;
    }
    return 0;
}

static int hr_decode(const unsigned char *d, size_t n, struct hr_block *b) {
    static struct hr_ctx c;
    hr_ctx_init(&c, 4096);
    return hr_decode_ctx(&c, d, n, b);
}

static int hr_nth_headers(const unsigned char *d, size_t n, int k, struct hr_block *b) {
    static struct hr_ctx c;
    static unsigned char blk[1 << 17];
    size_t p = 0, bn = 0;
    int in = 0;
    hr_ctx_init(&c, 4096);
    if (n >= 24 && memcmp(d, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) p = 24;
    while (p + 9 <= n) {
        uint32_t len = ((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2];
        if (p + 9 + len > n) return -1;
        unsigned char t = d[p + 3];
        if (t == 0x01 || (t == 0x09 && in)) {
            if (t == 0x01) bn = 0;
            if (bn + len > sizeof blk) return -1;
            memcpy(blk + bn, d + p + 9, len);
            bn += len;
            in = !(d[p + 4] & 0x04);
            if (!in && hr_decode_ctx(&c, blk, bn, b)) return -1;
            if (!in && k-- == 0) return 0;
        }
        p += 9 + len;
    }
    return -1;
}

static int hr_first_headers(const unsigned char *d, size_t n, struct hr_block *b) {
    return hr_nth_headers(d, n, 0, b);
}

static int hr_nth_headers_flags(const unsigned char *d, size_t n, int k) {
    size_t p = 0;
    if (n >= 24 && memcmp(d, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) p = 24;
    while (p + 9 <= n) {
        uint32_t len = ((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2];
        if (p + 9 + len > n) return -1;
        if (d[p + 3] == 0x01 && k-- == 0) return d[p + 4];
        p += 9 + len;
    }
    return -1;
}

static int hr_count_frames(const unsigned char *d, size_t n, unsigned char type) {
    size_t p = 0;
    int k = 0;
    if (n >= 24 && memcmp(d, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) p = 24;
    while (p + 9 <= n) {
        uint32_t len = ((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2];
        if (p + 9 + len > n) return -1;
        k += d[p + 3] == type;
        p += 9 + len;
    }
    return k;
}

static size_t hr_list_size(const struct hr_block *b) {
    size_t s = 0;
    for (size_t i = 0; i < b->n; i++) s += strlen(b->f[i].name) + strlen(b->f[i].value) + 32;
    return s;
}

static int hr_find_from(const struct hr_block *b, const char *name, int from) {
    for (size_t i = (size_t)from; i < b->n; i++)
        if (strcmp(b->f[i].name, name) == 0) return (int)i;
    return -1;
}

static int hr_find(const struct hr_block *b, const char *name) {
    for (size_t i = 0; i < b->n; i++)
        if (strcmp(b->f[i].name, name) == 0) return (int)i;
    return -1;
}

#endif
