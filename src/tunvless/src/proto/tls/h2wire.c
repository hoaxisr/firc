#include <string.h>
#include <strings.h>

#include "h2wire.h"

/* ---- HPACK on send ----------------------------------------------------------
 *
 * :method and :scheme go as indexed fields; everything else as "literal without indexing":
 * the name by its static table index (or as a string when the table lacks it), the value as a
 * plain string. There is no dynamic table at all, which is legal: HPACK allows indexing
 * nothing. No Huffman either: it would save tens of bytes per connection and need the code
 * table.
 *
 * Static table indices (RFC 7541, appendix A) are plain numbers: the table is part of the
 * protocol and never changes. */
#define HP_AUTHORITY   1
#define HP_METHOD_GET  2
#define HP_METHOD_POST 3
#define HP_PATH        4
#define HP_SCHEME_HTTPS 7
#define HP_CONTENT_TYPE 31
#define HP_REFERER     51
#define HP_USER_AGENT  58
#define HP_ACCEPT      19
#define HP_ACCEPT_LANG 17
#define HP_CACHE_CTRL  24

/* ---- browser look for xhttp ---------------------------------------------------------
 *
 * xhttp is a plain HTTP request to an ordinary-looking path, and it should come from what the
 * ClientHello already claims to be: a browser. gRPC headers (`te: trailers`,
 * `user-agent: grpc-go/1.60.0`) give xhttp away: nodes with CDN-cache-like paths
 * (`/static/v1/cache/<hash>`) answered them with RST/GOAWAY even though Reality accepted us;
 * something in front of the server cut them.
 *
 * The set is Xray's (transport/internet/splithttp/config.go: GetRequestHeader →
 * TryDefaultHeadersWith(header, "fetch") → applyMasqueradedHeaders(chrome, fetch)), repeated
 * name by name. Xray derives the Chrome version from the date (144 on 2026-01-13, plus one per
 * 35 days, minus a CPU-seeded lag; see h2.h); 149 is its highest value for early September
 * 2026. sec-ch-ua follows its rule: three brands, one fake, shuffled by the version number
 * (seed 149 gives exactly this order).
 *
 * The strings (UA_CHROME, UA_CH_CHROME) are in h2.h: the Upgrade requests of ws and
 * httpupgrade (proto/transport/trupgrade.c) use the same look, and two transports of one node
 * must not disagree on the browser version. */

struct wbuf { unsigned char *p; size_t n, cap; };

static void wb(struct wbuf *b, const void *d, size_t n) {
    if (b->n + n <= b->cap) memcpy(b->p + b->n, d, n);
    b->n += n;
}
static void wb8(struct wbuf *b, unsigned v) {
    unsigned char c = (unsigned char)v;
    wb(b, &c, 1);
}

/* An HPACK integer with an N-bit prefix, for indices and string lengths: the xhttp Referer with
 * its padding runs to a thousand bytes and more, while seven bits hold only 126. */
static void hp_int(struct wbuf *b, unsigned prefix, unsigned bits, uint32_t v) {
    uint32_t max = (1u << bits) - 1;
    if (v < max) { wb8(b, prefix | v); return; }
    wb8(b, prefix | max);
    v -= max;
    while (v >= 128) { wb8(b, (v & 0x7F) | 0x80); v >>= 7; }
    wb8(b, v);
}

static void hp_str(struct wbuf *b, const char *s, size_t n) {
    hp_int(b, 0x00, 7, (uint32_t)n);     /* no Huffman: high bit clear */
    wb(b, s, n);
}

/* A field with a name from the static table and our own value. */
static void hp_field(struct wbuf *b, unsigned name_index, const char *value) {
    hp_int(b, 0x00, 4, name_index);      /* 0000 — literal without indexing */
    hp_str(b, value, strlen(value));
}

/* A field whose name is not in the table. */
static void hp_new(struct wbuf *b, const char *name, const char *value) {
    wb8(b, 0x00);
    hp_str(b, name, strlen(name));
    hp_str(b, value, strlen(value));
}

/* An indexed field: name AND value from the static table. */
static void hp_indexed(struct wbuf *b, unsigned index) {
    hp_int(b, 0x80, 7, index);
}

struct hf { unsigned idx; const char *name, *value; int soft; };

static const struct hf br_head[] = {
    { 0, "sec-ch-ua", UA_CH_CHROME, 0 },
    { 0, "sec-ch-ua-mobile", "?0", 0 },
    { 0, "sec-ch-ua-platform", "\"Windows\"", 0 },
    { 0, "dnt", "1", 0 },
    { HP_USER_AGENT, "user-agent", UA_CHROME, 0 },
    { HP_ACCEPT, "accept", "*/*", 1 },
    { 0, "sec-fetch-site", "same-origin", 0 },
    { 0, "sec-fetch-mode", "cors", 0 },
    { 0, "sec-fetch-dest", "empty", 0 },
};
static const struct hf br_tail[] = {
    { HP_ACCEPT_LANG, "accept-language", "en-US,en;q=0.9", 0 },
    { 0, "priority", "u=1, i", 1 },
    { HP_CACHE_CTRL, "cache-control", "no-cache", 1 },
    { 0, "pragma", "no-cache", 1 },
};
static const struct hf grpc_tail[] = {
    { 0, "te", "trailers", 0 },
    { HP_USER_AGENT, "user-agent", "grpc-go/1.60.0", 0 },
};

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

static int hf_taken(const struct h2_req *r, const char *name) {
    for (size_t i = 0; r && i < r->fields_n; i++)
        if (strcasecmp(r->fields[i].name, name) == 0) return 1;
    return 0;
}

static int hf_forced(const struct hf *l, size_t n, const char *name) {
    for (size_t i = 0; i < n; i++)
        if (!l[i].soft && strcasecmp(l[i].name, name) == 0) return 1;
    return 0;
}

static int look_forced(const char *name) {
    return hf_forced(br_head, NELEM(br_head), name) || hf_forced(br_tail, NELEM(br_tail), name);
}

static void hp_list(struct wbuf *b, const struct hf *l, size_t n, const struct h2_req *r) {
    for (size_t i = 0; i < n; i++) {
        if (l[i].soft && hf_taken(r, l[i].name)) continue;
        if (l[i].idx) hp_field(b, l[i].idx, l[i].value);
        else hp_new(b, l[i].name, l[i].value);
    }
}

static size_t hf_size(const struct hf *l, size_t n, const struct h2_req *r) {
    size_t s = 0;
    for (size_t i = 0; i < n; i++)
        if (!l[i].soft || !hf_taken(r, l[i].name)) s += strlen(l[i].name) + strlen(l[i].value) + 32;
    return s;
}

static void hp_user(struct wbuf *b, const struct h2_field *f) {
    size_t n = strlen(f->name);
    if (n == 7 && strncasecmp(f->name, "referer", 7) == 0) {
        hp_field(b, HP_REFERER, f->value);
        return;
    }
    wb8(b, 0x00);
    hp_int(b, 0x00, 7, (uint32_t)n);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)f->name[i];
        wb8(b, c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    hp_str(b, f->value, strlen(f->value));
}

size_t h2w_list_size(const struct h2_req *r, int browser) {
    size_t s = strlen(":method") + strlen(r->method) + 32;
    s += strlen(":scheme") + strlen("https") + 32;
    s += strlen(":path") + strlen(r->path) + 32;
    s += strlen(":authority") + strlen(r->authority) + 32;
    if (r->content_type) s += strlen("content-type") + strlen(r->content_type) + 32;
    int look = browser && !r->no_look;
    for (size_t i = 0; i < r->fields_n; i++)
        if (!look || !look_forced(r->fields[i].name))
            s += strlen(r->fields[i].name) + strlen(r->fields[i].value) + 32;
    if (look)
        s += hf_size(br_head, NELEM(br_head), r) + hf_size(br_tail, NELEM(br_tail), r);
    else if (!browser) s += hf_size(grpc_tail, NELEM(grpc_tail), NULL);
    return s;
}

size_t h2w_headers(unsigned char *out, size_t cap, const struct h2_req *r, int browser) {
    struct wbuf hp = { out, 0, cap };
    if (strcmp(r->method, "GET") == 0) hp_indexed(&hp, HP_METHOD_GET);
    else if (strcmp(r->method, "POST") == 0) hp_indexed(&hp, HP_METHOD_POST);
    else hp_field(&hp, HP_METHOD_GET, r->method);
    hp_indexed(&hp, HP_SCHEME_HTTPS);
    hp_field(&hp, HP_PATH, r->path);
    hp_field(&hp, HP_AUTHORITY, r->authority);
    if (r->content_type) hp_field(&hp, HP_CONTENT_TYPE, r->content_type);
    if (browser && r->no_look) {
        for (size_t i = 0; i < r->fields_n; i++) hp_user(&hp, &r->fields[i]);
    } else if (browser) {
        /* Chrome's order: client hints, then who it is, then what it wants and where it came
         * from. Referer carries the xhttp padding and stands where a browser puts it. */
        size_t lead = r->lead_n < r->fields_n ? r->lead_n : r->fields_n;
        for (size_t i = 0; i < lead; i++)
            if (!look_forced(r->fields[i].name)) hp_user(&hp, &r->fields[i]);
        hp_list(&hp, br_head, NELEM(br_head), r);
        for (size_t i = lead; i < r->fields_n; i++)
            if (!look_forced(r->fields[i].name)) hp_user(&hp, &r->fields[i]);
        hp_list(&hp, br_tail, NELEM(br_tail), r);
    } else {
        for (size_t i = 0; i < r->fields_n; i++) hp_user(&hp, &r->fields[i]);
        /* te: trailers is the one connection-specific header HTTP/2 explicitly allows, and
         * gRPC requires it. */
        hp_list(&hp, grpc_tail, NELEM(grpc_tail), NULL);
    }
    return hp.n > hp.cap ? 0 : hp.n;
}

/* The response status from the first bytes of HEADERS, without the dynamic table. In practice
 * the server sends ":status 200" as index 8, the single byte 0x88. Anything unknown gives -1,
 * NOT an error: a guessed status is worse than none, and the read shows whether data came. */
int h2w_status(const unsigned char *p, size_t n) {
    size_t i = 0;
    /* A dynamic table size update (001xxxxx) comes first, if at all. Its value is an integer
     * with a 5-bit prefix: with 0x1F in the low bits it continues in the next bytes, high bit
     * set. */
    while (i < n && (p[i] & 0xE0) == 0x20) {
        int cont = (p[i] & 0x1F) == 0x1F;
        i++;
        if (!cont) continue;
        while (i < n && (p[i] & 0x80)) i++;
        if (i < n) i++;
    }
    if (i >= n) return 0;
    switch (p[i]) {
        case 0x88: return 200;
        case 0x89: return 204;
        case 0x8A: return 206;
        case 0x8B: return 304;
        case 0x8C: return 400;
        case 0x8D: return 404;
        case 0x8E: return 500;
        default: {
            /* A literal with a :status name (indices 8 to 14): the value as three digits. */
            unsigned idx = (p[i] & 0xC0) == 0x40 ? p[i] & 0x3Fu : (p[i] & 0xE0) == 0 ? p[i] & 0x0Fu : 0;
            if (idx >= 8 && idx <= 14 && i + 2 < n) {
                size_t len = p[i + 1] & 0x7F;
                if (!(p[i + 1] & 0x80) && len == 3 && i + 4 < n) {
                    const unsigned char *v = p + i + 2;
                    if (v[0] < '0' || v[0] > '9' || v[1] < '0' || v[1] > '9' || v[2] < '0' || v[2] > '9')
                        return -1;
                    return (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
                }
                /* The same value in Huffman code: three digits take 15 to 18 bits. */
                if ((p[i + 1] & 0x80) && len >= 2 && len <= 3 && i + 1 + len < n) {
                    int v = status_huff(p + i + 2, len);
                    if (v >= 100) return v;
                }
            }
            return -1;
        }
    }
}

size_t h2w_preface(unsigned char *out, size_t cap, int conn_update) {
    struct wbuf b = { out, 0, cap };

    /* The preface, byte for byte from RFC 7540 §3.5: the server compares it literally. */
    wb(&b, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);

    /* SETTINGS: disable push (not needed, it would only complicate parsing) and announce our
     * stream window. */
    {
        unsigned char s[12];
        s[0] = 0; s[1] = 0x02; put32(s + 2, 0);              /* ENABLE_PUSH = 0 */
        s[6] = 0; s[7] = 0x04; put32(s + 8, OUR_WINDOW);     /* INITIAL_WINDOW_SIZE */
        unsigned char hdr[9] = { 0, 0, 12, FR_SETTINGS, 0, 0, 0, 0, 0 };
        wb(&b, hdr, 9);
        wb(&b, s, 12);
    }

    /* The CONNECTION window is not set by SETTINGS, only by WINDOW_UPDATE on stream 0. Without
     * this frame it stays at 65535 and caps the 1 MB stream window, the very limit OUR_WINDOW
     * is there to lift. */
    if (conn_update) {
        unsigned char wu[4];
        put32(wu, OUR_WINDOW - 65535);
        unsigned char hdr[9] = { 0, 0, 4, FR_WINDOW_UPDATE, 0, 0, 0, 0, 0 };
        wb(&b, hdr, 9);
        wb(&b, wu, 4);
    }
    return b.n > b.cap ? 0 : b.n;
}
