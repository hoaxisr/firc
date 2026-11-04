#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unit.h"
#include "hpackread.h"
#include "hpack.h"

static unsigned char g_out[8192];
static unsigned char g_want[8192];
static struct hr_block g_blk;
static struct hr_ctx g_ctx;
static struct hpe g_e, g_e2;

static size_t unhex(const char *s, unsigned char *out) {
    size_t n = 0;
    while (*s) {
        if (*s == ' ') { s++; continue; }
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

static void check_bytes(const char *what, const char *hex, const unsigned char *got, size_t got_n) {
    size_t n = unhex(hex, g_want);
    check(what, (long)n, (long)got_n);
    if (n == got_n) check_mem(what, g_want, got, n);
}

static void check_prefix(const char *what, const char *hex, const unsigned char *got, size_t got_n) {
    size_t n = unhex(hex, g_want);
    if (got_n < n) { check(what, (long)n, (long)got_n); return; }
    check_mem(what, g_want, got, n);
}

static size_t enc(struct hpe *e, const struct h2_field *f, size_t n) {
    return hpe_block(e, f, n, g_out, sizeof g_out);
}

static int decoded_as(struct hr_ctx *c, const unsigned char *d, size_t len, const struct h2_field *f, size_t n) {
    if (hr_decode_ctx(c, d, len, &g_blk)) return 0;
    if (g_blk.n != n) return 0;
    for (size_t i = 0; i < n; i++)
        if (strcmp(g_blk.f[i].name, f[i].name) || strcmp(g_blk.f[i].value, f[i].value)) return 0;
    return 1;
}

static const struct h2_field c41[] = {
    { ":method", "GET" }, { ":scheme", "http" }, { ":path", "/" }, { ":authority", "www.example.com" },
};
static const struct h2_field c42[] = {
    { ":method", "GET" }, { ":scheme", "http" }, { ":path", "/" }, { ":authority", "www.example.com" },
    { "cache-control", "no-cache" },
};
static const struct h2_field c43[] = {
    { ":method", "GET" }, { ":scheme", "https" }, { ":path", "/index.html" },
    { ":authority", "www.example.com" }, { "custom-key", "custom-value" },
};

static void t_rfc_c4(void) {
    /* catches: a wrong static index, a dynamic index counted from the oldest, or Huffman not applied */
    hpe_init(&g_e);
    hr_ctx_init(&g_ctx, 4096);
    size_t n = enc(&g_e, c41, 4);
    check_bytes("c4: C.4.1", "82 86 84 41 8c f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff", g_out, n);
    check("c4: C.4.1 decodes", 1, decoded_as(&g_ctx, g_out, n, c41, 4));
    n = enc(&g_e, c42, 5);
    check_bytes("c4: C.4.2", "82 86 84 be 58 86 a8 eb 10 64 9c bf", g_out, n);
    check("c4: C.4.2 decodes", 1, decoded_as(&g_ctx, g_out, n, c42, 5));
    n = enc(&g_e, c43, 5);
    check_bytes("c4: C.4.3",
                "82 87 85 bf 40 88 25 a8 49 e9 5b a9 7d 7f 89 25 a8 49 e9 5b b8 e8 b4 bf", g_out, n);
    check("c4: C.4.3 decodes", 1, decoded_as(&g_ctx, g_out, n, c43, 5));
    check("c4: decoder table 164", 164, (long)g_ctx.size);
}

static void huff_case(const char *s, size_t want_len, const char *hex) {
    char what[80];
    snprintf(what, sizeof what, "huffman: \"%s\" length", s);
    check(what, (long)want_len, (long)hpe_huff_len(s, strlen(s)));
    if (!hex) return;
    memset(g_out, 0, sizeof g_out);
    size_t n = hpe_huff(g_out, s, strlen(s));
    snprintf(what, sizeof what, "huffman: \"%s\" bytes", s);
    check_bytes(what, hex, g_out, n);
}

static void t_huffman(void) {
    /* catches: wrong code table, padding with zeros, or Huffman when merely equal */
    huff_case("gzip", 3, "9b d9 ab");
    huff_case("a.example", 7, "1a e5 f2 3a 6b a0 bf");
    huff_case("/xp/abc", 6, "63 cd 6c 0e 32 7f");
    huff_case("PUT", 3, NULL);
    huff_case("XXXX", 4, NULL);
    huff_case("1000000", 5, "08 00 00 00 1f");
    static const struct h2_field put[] = { { "x-a", "PUT" } };
    hpe_init(&g_e);
    size_t n = enc(&g_e, put, 1);
    check_bytes("huffman: equal length goes raw", "40 03 78 2d 61 03 50 55 54", g_out, n);
}

static void t_newest_static_name(void) {
    /* catches: the first static index of a name used instead of the newest, or Huffman when not shorter */
    static const struct h2_field m[] = { { ":method", "PUT" } };
    static const struct h2_field cl[] = { { "content-length", "0" } };
    static const struct h2_field pa[] = { { ":path", "/x" } };
    static const struct h2_field sc[] = { { ":scheme", "ftp" } };
    hpe_init(&g_e);
    hr_ctx_init(&g_ctx, 4096);
    size_t n = enc(&g_e, m, 1);
    check_bytes("static name: :method PUT", "43 03 50 55 54", g_out, n);
    check("static name: :method PUT decodes", 1, decoded_as(&g_ctx, g_out, n, m, 1));
    n = enc(&g_e, cl, 1);
    check_bytes("static name: content-length 0", "5c 01 30", g_out, n);
    n = enc(&g_e, pa, 1);
    check_prefix("static name: :path by 5", "45", g_out, n);
    n = enc(&g_e, sc, 1);
    check_prefix("static name: :scheme by 7", "47", g_out, n);
    static const struct h2_field mp[] = { { ":method", "PATCH" } };
    n = enc(&g_e, mp, 1);
    check_bytes("static name: over a dynamic one", "43 05 50 41 54 43 48", g_out, n);
    static const struct h2_field xb[] = { { "x-a", "b" } }, xc[] = { { "x-a", "c" } }, xd[] = { { "x-a", "d" } };
    hpe_init(&g_e);
    hr_ctx_init(&g_ctx, 4096);
    n = enc(&g_e, xb, 1);
    check_bytes("dynamic name: first", "40 03 78 2d 61 01 62", g_out, n);
    check("dynamic name: first decodes", 1, decoded_as(&g_ctx, g_out, n, xb, 1));
    n = enc(&g_e, xc, 1);
    check_bytes("dynamic name: second", "7e 01 63", g_out, n);
    check("dynamic name: second decodes", 1, decoded_as(&g_ctx, g_out, n, xc, 1));
    n = enc(&g_e, xd, 1);
    check_bytes("dynamic name: the newest", "7e 01 64", g_out, n);
    check("dynamic name: the newest decodes", 1, decoded_as(&g_ctx, g_out, n, xd, 1));
}

static char g_ref[5000];
static const struct h2_field b1[] = {
    { ":authority", "a.example" }, { ":method", "GET" }, { "user-agent", "ua1" },
};

static void t_eviction_go(void) {
    /* catches: eviction of the newest, size counted without 32, or a full table not exactly filled */
    memset(g_ref, 'X', 3961);
    g_ref[3961] = '\0';
    const struct h2_field b2[] = { { "referer", g_ref } };
    static const struct h2_field b3[] = { { "x-a", "b" } };
    hpe_init(&g_e);
    hr_ctx_init(&g_ctx, 4096);
    size_t n = enc(&g_e, b1, 3);
    check_bytes("evict: block 1", "41 87 1a e5 f2 3a 6b a0 bf 82 7a 82 b4 61", g_out, n);
    check("evict: block 1 decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    n = enc(&g_e, b2, 1);
    check("evict: block 2 length", 3965, (long)n);
    check_prefix("evict: block 2 starts", "73 7f fa 1d", g_out, n);
    check("evict: block 2 decodes", 1, decoded_as(&g_ctx, g_out, n, b2, 1));
    check("evict: decoder table full", 4096, (long)g_ctx.size);
    static const struct h2_field au[] = { { ":authority", "a.example" } };
    n = enc(&g_e, au, 1);
    check_bytes("evict: a full table keeps the oldest", "c0", g_out, n);
    n = enc(&g_e, b3, 1);
    check_bytes("evict: block 3", "40 03 78 2d 61 01 62", g_out, n);
    check("evict: block 3 decodes", 1, decoded_as(&g_ctx, g_out, n, b3, 1));
    n = enc(&g_e, b1, 3);
    check_bytes("evict: block 4", "41 87 1a e5 f2 3a 6b a0 bf 82 7a 82 b4 61", g_out, n);
    check("evict: block 4 decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    n = enc(&g_e, b1, 3);
    check_bytes("evict: block 5", "bf 82 be", g_out, n);
    check("evict: block 5 decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    check("evict: decoder table 132", 132, (long)g_ctx.size);
    memset(g_ref, 'X', 2000);
    g_ref[2000] = '\0';
    const struct h2_field ca[] = { { "x-a", g_ref } }, cb[] = { { "x-b", g_ref } }, cc[] = { { "x-c", g_ref } };
    hpe_init(&g_e);
    hr_ctx_init(&g_ctx, 4096);
    n = enc(&g_e, ca, 1);
    check("churn: a length", 2008, (long)n);
    check_prefix("churn: a", "40 03 78 2d 61 7f d1 0e 58", g_out, n);
    check("churn: a decodes", 1, decoded_as(&g_ctx, g_out, n, ca, 1));
    n = enc(&g_e, cb, 1);
    check("churn: b decodes", 1, decoded_as(&g_ctx, g_out, n, cb, 1));
    n = enc(&g_e, cc, 1);
    check("churn: c length", 2008, (long)n);
    check("churn: c decodes", 1, decoded_as(&g_ctx, g_out, n, cc, 1));
    n = enc(&g_e, cb, 1);
    check_bytes("churn: b indexed", "bf", g_out, n);
    n = enc(&g_e, ca, 1);
    check("churn: a again length", 2008, (long)n);
    check("churn: a again decodes", 1, decoded_as(&g_ctx, g_out, n, ca, 1));
    n = enc(&g_e, cc, 1);
    check_bytes("churn: c indexed", "bf", g_out, n);
    n = enc(&g_e, ca, 1);
    check_bytes("churn: a indexed", "be", g_out, n);
}

static void t_too_big_not_indexed(void) {
    /* catches: an entry larger than the table added, or the table cleared by it */
    memset(g_ref, 'X', 4132);
    g_ref[4132] = '\0';
    const struct h2_field big[] = { { "referer", g_ref } };
    hpe_init(&g_e);
    hr_ctx_init(&g_ctx, 4096);
    size_t n = enc(&g_e, b1, 3);
    check("too big: block 1 decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    memset(g_ref, 'X', 4057);
    g_ref[4057] = '\0';
    const struct h2_field full[] = { { "referer", g_ref } };
    hpe_init(&g_e2);
    n = hpe_block(&g_e2, full, 1, g_out, sizeof g_out);
    check("too big: exactly 4096 length", 4061, (long)n);
    check_prefix("too big: exactly 4096 indexed", "73 7f da 1e", g_out, n);
    n = hpe_block(&g_e2, full, 1, g_out, sizeof g_out);
    check_bytes("too big: exactly 4096 then by index", "be", g_out, n);
    memset(g_ref, 'X', 4132);
    g_ref[4132] = '\0';
    n = enc(&g_e, big, 1);
    check("too big: length", 4137, (long)n);
    check_prefix("too big: starts", "0f 24 7f a5 1f", g_out, n);
    check("too big: decodes", 1, decoded_as(&g_ctx, g_out, n, big, 1));
    n = enc(&g_e, b1, 3);
    check_bytes("too big: block 1 again", "bf 82 be", g_out, n);
    check("too big: block 1 again decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
}

static void t_size_update_go(void) {
    /* catches: the minimum dropped, the update repeated or placed after a field, or no clamp */
    hpe_init(&g_e);
    hr_ctx_init(&g_ctx, 4096);
    size_t n = enc(&g_e, b1, 3);
    decoded_as(&g_ctx, g_out, n, b1, 3);
    hpe_set_max(&g_e, 0);
    hpe_set_max(&g_e, 4096);
    n = enc(&g_e, b1, 3);
    check_bytes("update: min then max",
                "20 3f e1 1f 41 87 1a e5 f2 3a 6b a0 bf 82 7a 82 b4 61", g_out, n);
    check("update: min then max decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    check("update: two updates seen", 2, (long)g_blk.nupd);
    n = enc(&g_e, b1, 3);
    check_bytes("update: none after", "bf 82 be", g_out, n);
    hpe_set_max(&g_e, 4096);
    hpe_set_max(&g_e, 4096);
    n = enc(&g_e, b1, 3);
    check_bytes("update: equal sent once", "3f e1 1f bf 82 be", g_out, n);
    check("update: equal decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    n = enc(&g_e, b1, 3);
    check_bytes("update: none after equal", "bf 82 be", g_out, n);
    hpe_set_max(&g_e, 8192);
    n = enc(&g_e, b1, 3);
    check_bytes("update: clamped to 4096", "3f e1 1f bf 82 be", g_out, n);
    check("update: clamped decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    n = enc(&g_e, b1, 3);
    check_bytes("update: none after clamp", "bf 82 be", g_out, n);
    hpe_set_max(&g_e, 100);
    n = enc(&g_e, b1, 3);
    check_bytes("update: shrink to 100", "3f 45 bf 82 be", g_out, n);
    check("update: shrink decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    n = enc(&g_e, b1, 3);
    check_bytes("update: none after shrink", "bf 82 be", g_out, n);
    hpe_set_max(&g_e, 50);
    n = enc(&g_e, b1, 3);
    check_bytes("update: shrink to 50 evicts",
                "3f 13 01 87 1a e5 f2 3a 6b a0 bf 82 be", g_out, n);
    check("update: shrink to 50 decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
    hpe_set_max(&g_e, 31);
    n = enc(&g_e, b1, 3);
    check_bytes("update: 31 on two bytes", "3f 00 01 87 1a e5 f2 3a 6b a0 bf 82 0f 2b 82 b4 61", g_out, n);
    check("update: 31 decodes", 1, decoded_as(&g_ctx, g_out, n, b1, 3));
}

static void t_bound_refuses_untouched(void) {
    /* catches: a refused block that still changed the table */
    static const struct h2_field f[] = { { "x-a", "b" }, { ":authority", "a.example" } };
    check("bound: by hand", 61, (long)hpe_bound(f, 2));
    hpe_init(&g_e);
    hpe_init(&g_e2);
    enc(&g_e, b1, 3);
    enc(&g_e2, b1, 3);
    hpe_set_max(&g_e, 100);
    hpe_set_max(&g_e2, 100);
    check("bound: one short refused", 0, (long)hpe_block(&g_e, f, 2, g_out, hpe_bound(f, 2) - 1));
    size_t n = enc(&g_e, f, 2);
    unsigned char a[64];
    memcpy(a, g_out, n);
    size_t m = enc(&g_e2, f, 2);
    check("bound: same length as fresh", (long)m, (long)n);
    check_mem("bound: same bytes as fresh", g_out, a, m < n ? m : n);
    check_bytes("bound: update kept", "3f 45 40 03 78 2d 61 01 62 41 87 1a e5 f2 3a 6b a0 bf", a, n);
    n = enc(&g_e, b1, 3);
    m = hpe_block(&g_e2, b1, 3, g_out + 4096, 4096);
    check_bytes("bound: next block", "be 82 7a 82 b4 61", g_out, n);
    check("bound: next block same length", (long)m, (long)n);
    check_mem("bound: next block same bytes", g_out + 4096, g_out, m < n ? m : n);
    check("bound: exact cap accepted", 1, hpe_block(&g_e, b1, 3, g_out, hpe_bound(b1, 3)) > 0);
}

static void t_decoder_rfc(void) {
    /* catches: a test decoder that would agree with a broken encoder */
    static const struct h2_field c31[] = {
        { ":method", "GET" }, { ":scheme", "http" }, { ":path", "/" }, { ":authority", "www.example.com" },
    };
    unsigned char d[256];
    size_t n;
    hr_ctx_init(&g_ctx, 4096);
    n = unhex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d", d);
    check("decoder: C.3.1", 1, decoded_as(&g_ctx, d, n, c31, 4));
    check("decoder: C.3.1 kind", 'a', g_blk.f[3].kind);
    check("decoder: C.3.1 size", 57, (long)g_ctx.size);
    n = unhex("8286 84be 5808 6e6f 2d63 6163 6865", d);
    check("decoder: C.3.2", 1, decoded_as(&g_ctx, d, n, c42, 5));
    check("decoder: C.3.2 size", 110, (long)g_ctx.size);
    n = unhex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65", d);
    check("decoder: C.3.3", 1, decoded_as(&g_ctx, d, n, c43, 5));
    check("decoder: C.3.3 size", 164, (long)g_ctx.size);
    check("decoder: C.3.3 entries", 3, (long)g_ctx.n);
    n = unhex("20 3f e1 1f 82", d);
    check("decoder: update to 0", 0, hr_decode_ctx(&g_ctx, d, n, &g_blk));
    check("decoder: update to 0 empties", 0, (long)g_ctx.size);

    static const struct h2_field c61[] = {
        { ":status", "302" }, { "cache-control", "private" },
        { "date", "Mon, 21 Oct 2013 20:13:21 GMT" }, { "location", "https://www.example.com" },
    };
    static const struct h2_field c62[] = {
        { ":status", "307" }, { "cache-control", "private" },
        { "date", "Mon, 21 Oct 2013 20:13:21 GMT" }, { "location", "https://www.example.com" },
    };
    static const struct h2_field c63[] = {
        { ":status", "200" }, { "cache-control", "private" },
        { "date", "Mon, 21 Oct 2013 20:13:22 GMT" }, { "location", "https://www.example.com" },
        { "content-encoding", "gzip" },
        { "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
    };
    hr_ctx_init(&g_ctx, 256);
    n = unhex("4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6"
              "2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3", d);
    check("decoder: C.6.1", 1, decoded_as(&g_ctx, d, n, c61, 4));
    check("decoder: C.6.1 huffman value", 1, g_blk.f[1].hvalue);
    check("decoder: C.6.1 size", 222, (long)g_ctx.size);
    n = unhex("4883 640e ffc1 c0bf", d);
    check("decoder: C.6.2", 1, decoded_as(&g_ctx, d, n, c62, 4));
    check("decoder: C.6.2 size", 222, (long)g_ctx.size);
    n = unhex("88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab"
              "77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f"
              "9587 3160 65c0 03ed 4ee5 b106 3d50 07", d);
    check("decoder: C.6.3", 1, decoded_as(&g_ctx, d, n, c63, 6));
    check("decoder: C.6.3 size", 215, (long)g_ctx.size);
    check("decoder: C.6.3 entries", 3, (long)g_ctx.n);

    hr_ctx_init(&g_ctx, 4096);
    n = unhex("00 01 61 81 1f", d);
    check("decoder: 3 bits of padding", 0, hr_decode_ctx(&g_ctx, d, n, &g_blk));
    check_str("decoder: padded value", "a", g_blk.f[0].value);
    n = unhex("00 01 61 82 1f ff", d);
    check("decoder: 11 bits of padding refused", -1, hr_decode_ctx(&g_ctx, d, n, &g_blk));
    n = unhex("00 01 61 81 18", d);
    check("decoder: zero padding refused", -1, hr_decode_ctx(&g_ctx, d, n, &g_blk));
    n = unhex("3f e1 1f 82", d);
    check("decoder: update first", 0, hr_decode_ctx(&g_ctx, d, n, &g_blk));
    check("decoder: update counted", 1, (long)g_blk.nupd);
    check("decoder: update value", 4096, (long)g_blk.upd[0]);
    n = unhex("82 3f e1 1f", d);
    check("decoder: update after a field refused", -1, hr_decode_ctx(&g_ctx, d, n, &g_blk));
    hr_ctx_init(&g_ctx, 256);
    n = unhex("3f e1 1f 82", d);
    check("decoder: update above settings refused", -1, hr_decode_ctx(&g_ctx, d, n, &g_blk));
    n = unhex("1001 6101 62", d);
    check("decoder: never indexed", 0, hr_decode_ctx(&g_ctx, d, n, &g_blk));
    check("decoder: never indexed kind", 'v', g_blk.f[0].kind);
    check("decoder: never indexed not added", 0, (long)g_ctx.n);
}

static void t_empty_refused(void) {
    /* catches: an empty field list encoded, or its refusal consuming the pending size update */
    hpe_init(&g_e);
    hpe_set_max(&g_e, 100);
    check("empty: refused with -1", -1, (long)hpe_block(&g_e, b1, 0, g_out, sizeof g_out));
    check_prefix("empty: the update still leads the next block", "3f 45", g_out, enc(&g_e, b1, 3));
}

int main(void) {
    t_rfc_c4();
    t_huffman();
    t_newest_static_name();
    t_eviction_go();
    t_too_big_not_indexed();
    t_size_update_go();
    t_bound_refuses_untouched();
    t_decoder_rfc();
    t_empty_refused();
    return unit_done("hpackmatch");
}
