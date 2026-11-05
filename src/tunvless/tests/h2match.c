/* HTTP/2 in h2.c: flow control windows and frame parsing (Huffman :status, RST_STREAM, PADDED,
 * PRIORITY); the request headers h2wire.c builds, in both looks.
 *
 * The server's send window (send_win, send_win_conn) is int32_t, and a negative value is legal:
 * a SETTINGS with INITIAL_WINDOW_SIZE below 65535 subtracts the difference from the window
 * already granted (RFC 7540 §6.9.2). Compared through size_t, a negative window becomes
 * 1.8e19, the check in h2_write never fires, the frame goes past the window, and the server
 * answers RST_STREAM with FLOW_CONTROL_ERROR. From outside a grpc/xhttp node "sometimes drops",
 * while h2_write returned success and the error came later from elsewhere. Gaps like this, between
 * "returned 0" and "actually broke the stream", are what this test is for.
 *
 * The SOURCE of h2.c is included: send_win is state that cannot be set from outside, and a
 * command in the engine just for the test would change the engine for the test. I/O is replaced
 * through struct h2_io, the abstraction made for that, so there is no network or TLS here. h2.c
 * takes only the constant TLS13_MAX_PLAIN from tls13.h and calls nothing, and tls13.h includes
 * only src/lib/scrypto.h, with no crypto library types, so no header stubs are needed. */
#include <stdio.h>
#include <string.h>

#include "../src/proto/tls/h2.c"
#include "hpackread.h"

static int fails;

static void check(const char *what, int want, int got) {
    printf("%-58s %s\n", what, want == got ? "ok" : "FAIL");
    if (want != got) fails++;
}

/* The network below: writes pile up in a buffer, reads return bytes prepared in advance.
 * That is enough: h2.c knows nothing of what is below it but these two functions. */
struct fake_io {
    unsigned char sent[65536];
    size_t sent_n;
    const unsigned char *feed;
    size_t feed_n, feed_pos;
};

static int fake_write(void *ctx, const unsigned char *d, size_t n) {
    struct fake_io *io = ctx;
    if (io->sent_n + n > sizeof(io->sent)) return H2_EIO;
    memcpy(io->sent + io->sent_n, d, n);
    io->sent_n += n;
    return 0;
}

static int fake_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    struct fake_io *io = ctx;
    size_t left = io->feed_n - io->feed_pos;
    size_t take = left < cap ? left : cap;
    memcpy(d, io->feed + io->feed_pos, take);
    io->feed_pos += take;
    *got = take;
    return 0;
}

static void h2_open(struct h2 *h, struct fake_io *io) {
    memset(io, 0, sizeof(*io));
    struct h2_io ops = { io, fake_write, fake_read };
    h2_start(h, &ops, "example.org", "/x", "application/grpc", NULL);
    io->sent_n = 0;                      /* the preface and HEADERS do not matter below */
}

/* A DATA frame on stream sid with a body of len bytes. Returns the full frame length. */
static size_t put_data(unsigned char *out, uint32_t sid, size_t len) {
    out[0] = (unsigned char)(len >> 16); out[1] = (unsigned char)(len >> 8);
    out[2] = (unsigned char)len;
    out[3] = FR_DATA; out[4] = 0;
    put32(out + 5, sid);
    memset(out + 9, 'q', len);
    return 9 + len;
}

/* The sum of increments in all WINDOW_UPDATE frames sent on stream sid. Counted from what
 * actually went to the network: the state fields say how much we INTEND to return, while the
 * server sees only frames. */
static uint32_t wu_sum(const struct fake_io *io, uint32_t sid) {
    uint32_t sum = 0;
    size_t p = 0;
    while (p + 9 <= io->sent_n) {
        uint32_t len = ((uint32_t)io->sent[p] << 16) | ((uint32_t)io->sent[p + 1] << 8) |
                       io->sent[p + 2];
        unsigned char type = io->sent[p + 3];
        uint32_t fsid = get32(io->sent + p + 5) & 0x7FFFFFFF;
        if (type == FR_WINDOW_UPDATE && fsid == sid && len == 4)
            sum += get32(io->sent + p + 9) & 0x7FFFFFFF;
        p += 9 + len;
    }
    return sum;
}

/* A frame of any type with the given body. Returns the full frame length. */
static size_t put_frame(unsigned char *out, unsigned char type, unsigned char flags,
                        uint32_t sid, const unsigned char *body, size_t len) {
    out[0] = (unsigned char)(len >> 16); out[1] = (unsigned char)(len >> 8);
    out[2] = (unsigned char)len;
    out[3] = type; out[4] = flags;
    put32(out + 5, sid);
    if (len) memcpy(out + 9, body, len);
    return 9 + len;
}

/* A SETTINGS frame with one setting. */
static size_t settings_frame(unsigned char *out, uint16_t id, uint32_t v) {
    out[0] = 0; out[1] = 0; out[2] = 6;
    out[3] = FR_SETTINGS; out[4] = 0;
    put32(out + 5, 0);
    out[9] = (unsigned char)(id >> 8); out[10] = (unsigned char)id;
    put32(out + 11, v);
    return 15;
}

static struct hr_block g_blk;

static void grpc_req(struct fake_io *io, const struct h2_req *r) {
    memset(io, 0, sizeof *io);
    io->sent_n = h2w_preface(io->sent, sizeof io->sent, 1);
    size_t n = h2w_headers(io->sent + io->sent_n + 9, DEFAULT_MAX_FRAME, r);
    unsigned char flags = (unsigned char)(FLAG_END_HEADERS | (r->end_stream ? FLAG_END_STREAM : 0));
    h2w_frame_hdr(io->sent + io->sent_n, (uint32_t)n, FR_HEADERS, flags, 1);
    io->sent_n += 9 + n;
}

static struct h2w_list g_gl;

static void go_req(const struct h2_req *r) {
    uint64_t rng = 7;
    if (h2w_go_fields(r, &rng, &g_gl)) g_gl.n = 0;
    g_blk.n = 0;
    for (size_t i = 0; i < g_gl.n && i < HR_MAX; i++) {
        snprintf(g_blk.f[i].name, sizeof g_blk.f[i].name, "%s", g_gl.f[i].name);
        snprintf(g_blk.f[i].value, sizeof g_blk.f[i].value, "%s", g_gl.f[i].value);
        g_blk.n++;
    }
}

static void t_req_put_method_not_collapsed_to_post(void) {
    struct h2 h;
    struct fake_io io;
    memset(&io, 0, sizeof io);
    struct h2_io ops = { &io, fake_write, fake_read };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "PUT" };
    check("PUT request: started", 0, h2_start_req(&h, &ops, &r));
    check("PUT request: HEADERS decode", 0, hr_first_headers(io.sent, io.sent_n, &g_blk));
    check("PUT request: :method first", 0, hr_find(&g_blk, ":method"));
    check("PUT request: :method a literal with name index 2", 1,
          g_blk.f[0].kind == 'l' && g_blk.f[0].index == 2);
    check("PUT request: :method value PUT", 0, strcmp(g_blk.f[0].value, "PUT"));

    struct h2_req g = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1 };
    grpc_req(&io, &g);
    hr_first_headers(io.sent, io.sent_n, &g_blk);
    check("GET request: :method indexed 2", 1, g_blk.f[0].kind == 'i' && g_blk.f[0].index == 2);
    check("GET request: END_STREAM on HEADERS", 1, (io.sent[24 + 21 + 13 + 4] & 0x01) != 0);
}

static void t_req_fields_lowercase(void) {
    const struct h2_field fl[] = { { "X-A", "1" }, { "cookie", "s=2" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "POST",
                        .fields = fl, .fields_n = 2 };
    go_req(&r);
    check("browser request with fields: listed", 1, g_blk.n > 0);
    check("sec-fetch-dest present", 1, hr_find(&g_blk, "sec-fetch-dest") > 0);
    check("first field lowercased", 0, strcmp(g_blk.f[hr_find(&g_blk, "x-a")].value, "1"));
    check("second field value", 0, strcmp(g_blk.f[hr_find(&g_blk, "cookie")].value, "s=2"));
    check("accept-language present", 1, hr_find(&g_blk, "accept-language") > 0);
    check("no upper-case X-A", -1, hr_find(&g_blk, "X-A"));
    check("no referer unless given", -1, hr_find(&g_blk, "referer"));
}

static void t_list_size_counts_32_per_field(void) {
    struct h2 h;
    struct fake_io io;
    memset(&io, 0, sizeof io);
    struct h2_io ops = { &io, fake_write, fake_read };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "POST" };
    h2_start_req(&h, &ops, &r);
    check("list size of a gRPC-look request", 267, (int)h2w_list_size(&r, 0));
}

static void t_list_size_browser_matches_decoded_block(void) {
    const struct h2_field fl[] = { { "X-Pad", "abc" }, { "referer", "https://a/p" } };
    struct h2_req r = { .authority = "a", .path = "/p", .content_type = "application/grpc",
                        .method = "PATCH", .fields = fl, .fields_n = 2 };
    go_req(&r);
    size_t want = 0;
    for (size_t i = 0; i < g_blk.n; i++)
        want += strlen(g_blk.f[i].name) + strlen(g_blk.f[i].value) + 32;
    check("browser list size: 22 fields listed", 22, (int)g_blk.n);
    check("browser list size equals the listed fields", (int)want, (int)h2w_list_size(&r, 1));
}

static void t_block_too_big_writes_nothing(void) {
    static char big[16401];
    memset(big, 'v', 16400); big[16400] = '\0';
    struct h2 h;
    struct fake_io io;
    memset(&io, 0, sizeof io);
    struct h2_io ops = { &io, fake_write, fake_read };
    const struct h2_field fl[] = { { "x-big", big } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "POST",
                        .fields = fl, .fields_n = 1 };
    check("16400-byte field: H2_ETOOBIG", H2_ETOOBIG, h2_start_req(&h, &ops, &r));
    check("16400-byte field: nothing written", 0, (int)io.sent_n);
}

static void t_block_at_16384_fits_16385_refused(void) {
    static char v[16341];
    struct h2 h;
    struct fake_io io;
    struct h2_io ops = { &io, fake_write, fake_read };
    const struct h2_field fl[] = { { "x", v } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "POST",
                        .fields = fl, .fields_n = 1 };
    memset(v, 'v', 16339); v[16339] = '\0';
    memset(&io, 0, sizeof io);
    check("block of exactly 16384: sent", 0, h2_start_req(&h, &ops, &r));
    check("block of exactly 16384: frame length", 16384,
          (int)(((uint32_t)io.sent[58] << 16) | ((uint32_t)io.sent[59] << 8) | io.sent[60]));
    memset(v, 'v', 16340); v[16340] = '\0';
    memset(&io, 0, sizeof io);
    check("block of 16385: H2_ETOOBIG", H2_ETOOBIG, h2_start_req(&h, &ops, &r));
}

static int count_named(const struct hr_block *b, const char *name) {
    int k = 0;
    for (size_t i = 0; i < b->n; i++) k += strcmp(b->f[i].name, name) == 0;
    return k;
}

static size_t decoded_size(const struct hr_block *b) {
    size_t s = 0;
    for (size_t i = 0; i < b->n; i++) s += strlen(b->f[i].name) + strlen(b->f[i].value) + 32;
    return s;
}

static void t_user_fields_join_the_look(void) {
    const struct h2_field fl[] = { { "X-A", "1" }, { "referer", "https://a/p" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 2 };
    go_req(&r);
    check("user fields: x-a present", 1, hr_find(&g_blk, "x-a") >= 4);
    check("user fields: the look present", 1, hr_find(&g_blk, "sec-ch-ua") >= 4);
    check("user fields: referer present", 1, hr_find(&g_blk, "referer") >= 4);
    check("user fields: list size equals the listed fields", (int)decoded_size(&g_blk),
          (int)h2w_list_size(&r, 1));
}

static void t_field_named_like_a_look_field_replaces_it(void) {
    const struct h2_field fl[] = { { "Accept", "text/html" }, { "Pragma", "p" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 2 };
    go_req(&r);
    check("replace: one accept", 1, count_named(&g_blk, "accept"));
    check("replace: accept is ours", 0,
          strcmp(g_blk.f[hr_find(&g_blk, "accept")].value, "text/html"));
    check("replace: one pragma (a tail field)", 1, count_named(&g_blk, "pragma"));
    check("replace: pragma is ours", 0, strcmp(g_blk.f[hr_find(&g_blk, "pragma")].value, "p"));
    check("replace: the rest of the look stays", 1, hr_find(&g_blk, "sec-fetch-dest") > 0);
    check("replace: list size equals the listed fields", (int)decoded_size(&g_blk),
          (int)h2w_list_size(&r, 1));
}

static int has_value(const char *name, const char *value) {
    for (size_t i = 0; i < g_blk.n; i++)
        if (!strcmp(g_blk.f[i].name, name) && !strcmp(g_blk.f[i].value, value)) return 1;
    return 0;
}

static void t_look_keeps_its_identity_fields_over_ours(void) {
    const struct h2_field fl[] = { { "Accept-Language", "ru" }, { "Sec-Fetch-Mode", "navigate" },
                                   { "DNT", "0" }, { "sec-ch-ua", "x" }, { "X-A", "1" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 5 };
    go_req(&r);
    check("identity: one accept-language", 1, count_named(&g_blk, "accept-language"));
    check("identity: accept-language is the look's", 0,
          strcmp(g_blk.f[hr_find(&g_blk, "accept-language")].value, "en-US,en;q=0.9"));
    check("identity: one sec-fetch-mode", 1, count_named(&g_blk, "sec-fetch-mode"));
    check("identity: sec-fetch-mode is cors", 0,
          strcmp(g_blk.f[hr_find(&g_blk, "sec-fetch-mode")].value, "cors"));
    check("identity: header[\"DNT\"] beside Header.Add's Dnt, two dnt", 2, count_named(&g_blk, "dnt"));
    check("identity: header[\"DNT\"] beside Header.Add's Dnt, 0 and 1", 1, has_value("dnt", "0") && has_value("dnt", "1"));
    check("identity: header[\"Sec-CH-UA\"] beside Header.Add's Sec-Ch-Ua, two sec-ch-ua", 2,
          count_named(&g_blk, "sec-ch-ua"));
    check("identity: header[\"Sec-CH-UA\"] beside Header.Add's Sec-Ch-Ua, x among them", 1, has_value("sec-ch-ua", "x"));
    check("identity: an unrelated field stays", 0, strcmp(g_blk.f[hr_find(&g_blk, "x-a")].value, "1"));
    check("identity: list size equals the listed fields", (int)decoded_size(&g_blk),
          (int)h2w_list_size(&r, 1));
}

static void t_no_look_sends_only_the_fields(void) {
    const struct h2_field fl[] = { { "User-Agent", "MyApp/1" }, { "referer", "r" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 2, .look = H2L_NONE };
    go_req(&r);
    check("no look: four pseudo-headers, two fields and accept-encoding", 7, (int)g_blk.n);
    check("no look: user-agent is ours", 0,
          strcmp(g_blk.f[hr_find(&g_blk, "user-agent")].value, "MyApp/1"));
    check("no look: no sec-ch-ua", -1, hr_find(&g_blk, "sec-ch-ua"));
    check("no look: no pragma", -1, hr_find(&g_blk, "pragma"));
    check("no look: list size equals the listed fields", (int)decoded_size(&g_blk),
          (int)h2w_list_size(&r, 1));
}

static const char *gval(const char *name) {
    int i = hr_find(&g_blk, name);
    return i < 0 ? NULL : g_blk.f[i].value;
}

static int gis(const char *name, const char *value) {
    const char *v = gval(name);
    return v && strcmp(v, value) == 0 && count_named(&g_blk, name) == 1;
}

/* catches: a cookie value sent as one field where Go splits it per cookie-pair */
static void t_go_cookie_split(void) {
    char v[] = "a=1; b=2;  c=3;;d=4;";
    const struct h2_field fl[] = { { "Cookie", v }, { "x-z", "q" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 2, .look = H2L_NONE };
    uint64_t rng = 7;
    check("cookie split: listed", 0, h2w_go_fields(&r, &rng, &g_gl));
    memset(v, 'z', sizeof v - 1);
    const char *want[] = { "a=1", "b=2", "c=3", "", "d=4" };
    size_t at = 0;
    while (at < g_gl.n && strcmp(g_gl.f[at].name, "cookie")) at++;
    check("cookie split: twelve fields", 12, (int)g_gl.n);
    for (size_t i = 0; i < 5; i++)
        check("cookie split: pair in order, spaces after ; stripped", 1,
              at + i < g_gl.n && !strcmp(g_gl.f[at + i].name, "cookie") && !strcmp(g_gl.f[at + i].value, want[i]));
    const struct h2_field one[] = { { "cookie", "s=2" } };
    r.fields = one;
    r.fields_n = 1;
    check("cookie split: a single pair listed", 0, h2w_go_fields(&r, &rng, &g_gl));
    check("cookie split: a single pair stays one field", 7, (int)g_gl.n);
    char big[2100];
    memset(big, 'k', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    big[2090] = ';';
    const struct h2_field over[] = { { "cookie", big } };
    r.fields = over;
    check("cookie split: pairs past the copy room refused", H2_ETOOBIG, h2w_go_fields(&r, &rng, &g_gl));
}

static void t_rng_splitmix(void) {
    uint64_t st = 0;
    /* catches: a generator other than splitmix64 from the seed */
    check("splitmix64: first of seed 0", 1, h2w_rng(&st) == 0xe220a8397b1dcdafull);
    check("splitmix64: second of seed 0", 1, h2w_rng(&st) == 0x6e789e6aa1b965f4ull);
    check("splitmix64: third of seed 0", 1, h2w_rng(&st) == 0x06c45d188009454full);
    st = 1;
    check("splitmix64: first of seed 1", 1, h2w_rng(&st) == 0x910a2dec89025cc1ull);
    check("splitmix64: state moves by the golden gamma", 1, st == 0x9e3779b97f4a7c16ull);
}

static void t_go_fields_look(void) {
    const struct h2_field fl[] = { { "referer", "https://a/p" }, { "Connection", "keep-alive" },
                                   { "Keep-Alive", "5" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 3 };
    /* catches: a look field lost or changed with the order, or a connection header Go drops sent */
    go_req(&r);
    check("go look: 4 pseudo, 13 look, referer, accept-encoding", 19, (int)g_blk.n);
    check("go look: :authority first", 0, strcmp(g_blk.f[0].name, ":authority"));
    check("go look: :method second", 0, strcmp(g_blk.f[1].name, ":method"));
    check("go look: :path third", 0, strcmp(g_blk.f[2].name, ":path"));
    check("go look: :scheme fourth", 0, strcmp(g_blk.f[3].name, ":scheme"));
    check("go look: :scheme https", 0, strcmp(g_blk.f[3].value, "https"));
    check("go look: accept-encoding last", 0, strcmp(g_blk.f[18].name, "accept-encoding"));
    check("go look: gzip", 0, strcmp(g_blk.f[18].value, "gzip"));
    check("go look: sec-ch-ua", 1, gis("sec-ch-ua",
          "\"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\""));
    check("go look: sec-ch-ua-mobile", 1, gis("sec-ch-ua-mobile", "?0"));
    check("go look: sec-ch-ua-platform", 1, gis("sec-ch-ua-platform", "\"Windows\""));
    check("go look: dnt", 1, gis("dnt", "1"));
    check("go look: user-agent", 1, gis("user-agent",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/149.0.0.0 Safari/537.36"));
    check("go look: accept", 1, gis("accept", "*/*"));
    check("go look: sec-fetch-site", 1, gis("sec-fetch-site", "same-origin"));
    check("go look: sec-fetch-mode", 1, gis("sec-fetch-mode", "cors"));
    check("go look: sec-fetch-dest", 1, gis("sec-fetch-dest", "empty"));
    check("go look: accept-language", 1, gis("accept-language", "en-US,en;q=0.9"));
    check("go look: priority", 1, gis("priority", "u=1, i"));
    check("go look: cache-control", 1, gis("cache-control", "no-cache"));
    check("go look: pragma", 1, gis("pragma", "no-cache"));
    check("go look: referer", 1, gis("referer", "https://a/p"));
    check("go look: no connection", -1, hr_find(&g_blk, "connection"));
    check("go look: no keep-alive", -1, hr_find(&g_blk, "keep-alive"));
}

static void t_go_default_ua(void) {
    const char *go = "Go-http-client/2.0";
    const struct h2_field xk[] = { { "X-K", "v" } };
    const struct h2_field gl[] = { { "User-Agent", "golang" } };
    const struct h2_field em[] = { { "User-Agent", "" } };
    const struct h2_field foo[] = { { "User-Agent", "Foo" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = xk, .fields_n = 1, .look = H2L_GOLANG };
    /* catches: the default UA missing, placed before accept-encoding or content-length, sent beside an empty or look user-agent, or left out of the budget */
    go_req(&r);
    check("default ua: golang GET, 7 fields", 7, (int)g_blk.n);
    check("default ua: golang GET, accept-encoding sixth", 1,
          g_blk.n == 7 && !strcmp(g_blk.f[5].name, "accept-encoding") && !strcmp(g_blk.f[5].value, "gzip"));
    check("default ua: golang GET, Go's user-agent last", 1,
          g_blk.n == 7 && !strcmp(g_blk.f[6].name, "user-agent") && !strcmp(g_blk.f[6].value, go));
    check("default ua: golang GET, size", (int)decoded_size(&g_blk), (int)h2w_list_size(&r, 1));
    r.method = "POST";
    r.end_stream = 0;
    r.body_len = 10;
    go_req(&r);
    check("default ua: golang POST, 8 fields", 8, (int)g_blk.n);
    check("default ua: golang POST, content-length sixth", 1,
          g_blk.n == 8 && !strcmp(g_blk.f[5].name, "content-length") && !strcmp(g_blk.f[5].value, "10"));
    check("default ua: golang POST, accept-encoding seventh", 1,
          g_blk.n == 8 && !strcmp(g_blk.f[6].name, "accept-encoding"));
    check("default ua: golang POST, Go's user-agent last", 1,
          g_blk.n == 8 && !strcmp(g_blk.f[7].name, "user-agent") && !strcmp(g_blk.f[7].value, go));
    check("default ua: golang POST, size", (int)decoded_size(&g_blk), (int)h2w_list_size(&r, 1));
    r.method = "GET";
    r.end_stream = 1;
    r.body_len = 0;
    r.fields = gl;
    go_req(&r);
    check("default ua: golang word dropped, Go's user-agent once", 1, gis("user-agent", go));
    check("default ua: golang word, size", (int)decoded_size(&g_blk), (int)h2w_list_size(&r, 1));
    r.fields = em;
    r.look = H2L_NONE;
    go_req(&r);
    check("default ua: empty user-agent sends none", -1, hr_find(&g_blk, "user-agent"));
    check("default ua: empty user-agent, 5 fields", 5, (int)g_blk.n);
    check("default ua: empty user-agent, size", (int)decoded_size(&g_blk), (int)h2w_list_size(&r, 1));
    r.fields = foo;
    go_req(&r);
    check("default ua: literal user-agent once", 1, gis("user-agent", "Foo"));
    check("default ua: literal, size", (int)decoded_size(&g_blk), (int)h2w_list_size(&r, 1));
    r.fields = xk;
    r.look = H2L_CHROME;
    go_req(&r);
    check("default ua: chrome look's user-agent once", 1, gis("user-agent",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/149.0.0.0 Safari/537.36"));
    check("default ua: chrome, size", (int)decoded_size(&g_blk), (int)h2w_list_size(&r, 1));
}

#define T_CHROME_UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
    "Chrome/149.0.0.0 Safari/537.36"
#define T_FIREFOX_UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0"
#define T_SAFARI_UA "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 " \
    "(KHTML, like Gecko) Version/26.6 Safari/605.1.15"

static void look_req(int look, const struct h2_field *fl, size_t n) {
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = n, .look = look };
    go_req(&r);
    check("look: list size equals the listed fields", (int)decoded_size(&g_blk), (int)h2w_list_size(&r, 1));
}

static void t_go_fields_edge(void) {
    /* catches: edge sent as Chrome, or Edge's brands out of getGreasedChUa's order */
    look_req(H2L_EDGE, NULL, 0);
    check("edge: 4 pseudo, 13 look, accept-encoding", 18, (int)g_blk.n);
    check("edge: accept-encoding last", 1, g_blk.n == 18 && !strcmp(g_blk.f[17].name, "accept-encoding"));
    check("edge: user-agent", 1, gis("user-agent", T_CHROME_UA "Edg/149.0.0.0"));
    check("edge: sec-ch-ua", 1, gis("sec-ch-ua",
          "\"Microsoft Edge\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\""));
    check("edge: sec-ch-ua-mobile", 1, gis("sec-ch-ua-mobile", "?0"));
    check("edge: sec-ch-ua-platform", 1, gis("sec-ch-ua-platform", "\"Windows\""));
    check("edge: dnt", 1, gis("dnt", "1"));
    check("edge: accept", 1, gis("accept", "*/*"));
    check("edge: sec-fetch-site", 1, gis("sec-fetch-site", "same-origin"));
    check("edge: sec-fetch-mode", 1, gis("sec-fetch-mode", "cors"));
    check("edge: sec-fetch-dest", 1, gis("sec-fetch-dest", "empty"));
    check("edge: accept-language", 1, gis("accept-language", "en-US,en;q=0.9"));
    check("edge: priority", 1, gis("priority", "u=1, i"));
    check("edge: cache-control", 1, gis("cache-control", "no-cache"));
    check("edge: pragma", 1, gis("pragma", "no-cache"));
}

static void t_go_fields_firefox(void) {
    /* catches: Chrome's client hints or q=0.9 or u=1, i sent for firefox */
    look_req(H2L_FIREFOX, NULL, 0);
    check("firefox: 4 pseudo, 10 look, accept-encoding", 15, (int)g_blk.n);
    check("firefox: user-agent", 1, gis("user-agent", T_FIREFOX_UA));
    check("firefox: dnt", 1, gis("dnt", "1"));
    check("firefox: accept-language", 1, gis("accept-language", "en-US,en;q=0.5"));
    check("firefox: sec-fetch-mode", 1, gis("sec-fetch-mode", "cors"));
    check("firefox: sec-fetch-dest", 1, gis("sec-fetch-dest", "empty"));
    check("firefox: sec-fetch-site", 1, gis("sec-fetch-site", "same-origin"));
    check("firefox: priority", 1, gis("priority", "u=4"));
    check("firefox: cache-control", 1, gis("cache-control", "no-cache"));
    check("firefox: pragma", 1, gis("pragma", "no-cache"));
    check("firefox: accept", 1, gis("accept", "*/*"));
    check("firefox: accept-encoding", 1, gis("accept-encoding", "gzip"));
    check("firefox: no sec-ch-ua", -1, hr_find(&g_blk, "sec-ch-ua"));
    check("firefox: no sec-ch-ua-mobile", -1, hr_find(&g_blk, "sec-ch-ua-mobile"));
    check("firefox: no sec-ch-ua-platform", -1, hr_find(&g_blk, "sec-ch-ua-platform"));
}

static void t_go_fields_safari(void) {
    /* catches: dnt sent for safari, or the ws variant's Sec-Fetch-Dest websocket used for fetch */
    look_req(H2L_SAFARI, NULL, 0);
    check("safari: 4 pseudo, 9 look, accept-encoding", 14, (int)g_blk.n);
    check("safari: user-agent", 1, gis("user-agent", T_SAFARI_UA));
    check("safari: accept-language", 1, gis("accept-language", "en-US,en;q=0.9"));
    check("safari: sec-fetch-mode", 1, gis("sec-fetch-mode", "cors"));
    check("safari: sec-fetch-dest", 1, gis("sec-fetch-dest", "empty"));
    check("safari: sec-fetch-site", 1, gis("sec-fetch-site", "same-origin"));
    check("safari: priority", 1, gis("priority", "u=3, i"));
    check("safari: cache-control", 1, gis("cache-control", "no-cache"));
    check("safari: pragma", 1, gis("pragma", "no-cache"));
    check("safari: accept", 1, gis("accept", "*/*"));
    check("safari: no dnt", -1, hr_find(&g_blk, "dnt"));
    check("safari: no sec-ch-ua", -1, hr_find(&g_blk, "sec-ch-ua"));
    check("safari: no sec-ch-ua-mobile", -1, hr_find(&g_blk, "sec-ch-ua-mobile"));
    check("safari: no sec-ch-ua-platform", -1, hr_find(&g_blk, "sec-ch-ua-platform"));
}

static void t_go_fields_curl(void) {
    /* catches: the fetch variant applied to curl */
    look_req(H2L_CURL, NULL, 0);
    check("curl: 4 pseudo, user-agent, accept-encoding", 6, (int)g_blk.n);
    check("curl: user-agent fifth", 1, g_blk.n == 6 && !strcmp(g_blk.f[4].name, "user-agent") &&
          !strcmp(g_blk.f[4].value, "curl/8.20.0"));
    check("curl: accept-encoding last", 1, g_blk.n == 6 && !strcmp(g_blk.f[5].name, "accept-encoding") &&
          !strcmp(g_blk.f[5].value, "gzip"));
    check("curl: no accept", -1, hr_find(&g_blk, "accept"));
    check("curl: no sec-fetch-mode", -1, hr_find(&g_blk, "sec-fetch-mode"));
    check("curl: no priority", -1, hr_find(&g_blk, "priority"));
}

static void t_go_fields_soft_per_look(void) {
    const struct h2_field pr[] = { { "Priority", "u=0" } };
    const struct h2_field al[] = { { "Accept-Language", "ru" } };
    /* catches: soft and forced kinds taken from Chrome's table for another look */
    look_req(H2L_FIREFOX, pr, 1);
    check("firefox soft: priority is ours, once", 1, gis("priority", "u=0"));
    look_req(H2L_FIREFOX, al, 1);
    check("firefox forced: accept-language is the look's, once", 1, gis("accept-language", "en-US,en;q=0.5"));
}

static void t_look_exact_keys(void) {
    const struct h2_field ch[] = { { "DNT", "0" }, { "sec-ch-ua", "x" }, { "Sec-CH-UA-Platform", "\"Linux\"" } };
    const struct h2_field dnt[] = { { "DNT", "0" } };
    const struct h2_field ed[] = { { "DNT", "0" }, { "sec-ch-ua-mobile", "?1" } };
    const struct h2_field cu[] = { { "sec-ch-ua", "x" } };
    const struct h2_field lit[] = { { "User-Agent", "A" }, { "DNT", "0" } };
    /* catches: an exact-key look field still replacing the custom one, or a custom field dropped for a look that has no such field */
    look_req(H2L_CHROME, ch, 3);
    check("exact keys chrome: two dnt", 2, count_named(&g_blk, "dnt"));
    check("exact keys chrome: dnt 0 and 1", 1, has_value("dnt", "0") && has_value("dnt", "1"));
    check("exact keys chrome: two sec-ch-ua", 2, count_named(&g_blk, "sec-ch-ua"));
    check("exact keys chrome: sec-ch-ua x and Chrome's", 1, has_value("sec-ch-ua", "x") &&
          has_value("sec-ch-ua", "\"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\""));
    check("exact keys chrome: two sec-ch-ua-platform", 2, count_named(&g_blk, "sec-ch-ua-platform"));
    check("exact keys chrome: platform Linux and Windows", 1, has_value("sec-ch-ua-platform", "\"Linux\"") &&
          has_value("sec-ch-ua-platform", "\"Windows\""));
    look_req(H2L_EDGE, ed, 2);
    check("exact keys edge: two dnt", 2, count_named(&g_blk, "dnt"));
    check("exact keys edge: dnt 0 and 1", 1, has_value("dnt", "0") && has_value("dnt", "1"));
    check("exact keys edge: two sec-ch-ua-mobile", 2, count_named(&g_blk, "sec-ch-ua-mobile"));
    check("exact keys edge: mobile ?1 and ?0", 1, has_value("sec-ch-ua-mobile", "?1") &&
          has_value("sec-ch-ua-mobile", "?0"));
    look_req(H2L_CHROME, ed, 2);
    check("exact keys chrome: two sec-ch-ua-mobile", 2, count_named(&g_blk, "sec-ch-ua-mobile"));
    look_req(H2L_FIREFOX, dnt, 1);
    check("exact keys firefox: two dnt", 2, count_named(&g_blk, "dnt"));
    look_req(H2L_CURL, dnt, 1);
    check("exact keys curl: one dnt, ours", 1, gis("dnt", "0"));
    look_req(H2L_GOLANG, cu, 1);
    check("exact keys golang: one sec-ch-ua, ours", 1, gis("sec-ch-ua", "x"));
    look_req(H2L_NONE, lit, 2);
    check("exact keys literal: one dnt, ours", 1, gis("dnt", "0"));
}

static void t_look_soft_empty(void) {
    const struct h2_field em[] = { { "Priority", "" }, { "Accept", "" } };
    const struct h2_field ac[] = { { "Accept", "text/html" } };
    /* catches: an empty custom value taken as set, sending an empty field Xray replaces */
    look_req(H2L_CHROME, em, 2);
    check("soft empty: one priority, the look's", 1, gis("priority", "u=1, i"));
    check("soft empty: one accept, the look's", 1, gis("accept", "*/*"));
    look_req(H2L_CHROME, ac, 1);
    check("soft set: one accept, ours", 1, gis("accept", "text/html"));
}

static void t_go_fields_dropped(void) {
    const struct h2_field fl[] = { { "Host", "h" }, { "Content-Length", "9" }, { "Proxy-Connection", "x" },
                                   { "Transfer-Encoding", "chunked" }, { "Upgrade", "h2c" },
                                   { "User-Agent", "A/1" }, { "user-agent", "B/2" }, { "X-K", "v" } };
    const struct h2_field fe[] = { { "User-Agent", "" }, { "User-Agent", "C/3" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 8, .look = H2L_NONE };
    /* catches: a field Go drops sent, a second user-agent kept, or an empty one sent */
    go_req(&r);
    check("go drops: pseudo, user-agent, x-k, accept-encoding", 7, (int)g_blk.n);
    check("go drops: the first user-agent only", 1, gis("user-agent", "A/1"));
    check("go drops: x-k kept", 1, gis("x-k", "v"));
    check("go drops: no host", -1, hr_find(&g_blk, "host"));
    check("go drops: no user content-length", -1, hr_find(&g_blk, "content-length"));
    r.fields = fe;
    r.fields_n = 2;
    go_req(&r);
    check("go drops: an empty first user-agent drops both", -1, hr_find(&g_blk, "user-agent"));
    check("go drops: pseudo and accept-encoding", 5, (int)g_blk.n);
}

static void t_go_fields_uniform(void) {
    const struct h2_field fl[] = { { "a", "1" }, { "b", "2" }, { "cookie", "c=1" }, { "cookie", "d=2" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 4, .look = H2L_NONE };
    static const char *const orders[6] = { "abc", "acb", "bac", "bca", "cab", "cba" };
    int seen[6] = { 0 }, glued = 1, shape = 1;
    /* catches: an order other than the documented uniform permutation, or cookies split apart */
    for (uint64_t seed = 1; seed <= 6000; seed++) {
        uint64_t rng = seed;
        if (h2w_go_fields(&r, &rng, &g_gl) || g_gl.n != 10) { shape = 0; continue; }
        char o[4] = { 0 };
        int k = 0;
        for (size_t i = 4; i < 8; i++) {
            char c = g_gl.f[i].name[0];
            if (k < 3 && (!k || o[k - 1] != c)) o[k++] = c;
            if (!strcmp(g_gl.f[i].name, "cookie") && !strcmp(g_gl.f[i].value, "c=1"))
                glued &= i + 1 < 8 && !strcmp(g_gl.f[i + 1].value, "d=2");
        }
        for (int j = 0; j < 6; j++) seen[j] += strcmp(o, orders[j]) == 0;
    }
    check("uniform: every list shaped", 1, shape);
    check("uniform: c=1 directly before d=2", 1, glued);
    int total = 0;
    for (int j = 0; j < 6; j++) {
        char what[64];
        snprintf(what, sizeof what, "uniform: order %s between 850 and 1150", orders[j]);
        check(what, 1, seen[j] >= 850 && seen[j] <= 1150);
        total += seen[j];
    }
    check("uniform: 6000 lists of three units", 6000, total);
}

static const char *go_cl(const char *method, int64_t body_len) {
    struct h2_req r = { .authority = "a", .path = "/p", .method = method, .look = H2L_NONE, .body_len = body_len };
    go_req(&r);
    return gval("content-length");
}

static void t_content_length_rule(void) {
    /* catches: content-length sent for an unknown or empty GET body, or missing for an empty POST, PUT or PATCH */
    check("content-length: GET 0 none", 1, go_cl("GET", 0) == NULL);
    check("content-length: GET 5", 1, go_cl("GET", 5) && !strcmp(go_cl("GET", 5), "5"));
    check("content-length: POST 0", 1, go_cl("POST", 0) && !strcmp(go_cl("POST", 0), "0"));
    check("content-length: PUT 0", 1, go_cl("PUT", 0) && !strcmp(go_cl("PUT", 0), "0"));
    check("content-length: PATCH 0", 1, go_cl("PATCH", 0) && !strcmp(go_cl("PATCH", 0), "0"));
    check("content-length: POST unknown none", 1, go_cl("POST", -1) == NULL);
    check("content-length: POST 1000000", 1, go_cl("POST", 1000000) && !strcmp(go_cl("POST", 1000000), "1000000"));
    go_cl("POST", 1000000);
    check("content-length: before accept-encoding", 1,
          g_blk.n >= 3 && !strcmp(g_blk.f[g_blk.n - 3].name, "content-length") &&
          !strcmp(g_blk.f[g_blk.n - 2].name, "accept-encoding"));
}

static void t_gzip_rule(void) {
    const struct h2_field ae[] = { { "Accept-Encoding", "br" }, { "x-a", "1" } };
    const struct h2_field rg[] = { { "Range", "bytes=0-" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .look = H2L_NONE,
                        .fields = ae, .fields_n = 2 };
    /* catches: gzip asked beside a user Accept-Encoding, a range, or a HEAD, or not last otherwise */
    go_req(&r);
    check("gzip: user accept-encoding kept alone", 1, gis("accept-encoding", "br"));
    check("gzip: user accept-encoding among the units", 1, hr_find(&g_blk, "accept-encoding") >= 4);
    r.fields = rg;
    r.fields_n = 1;
    go_req(&r);
    check("gzip: none with a range", -1, hr_find(&g_blk, "accept-encoding"));
    check("gzip: the range kept", 1, gis("range", "bytes=0-"));
    r.fields_n = 0;
    r.method = "HEAD";
    go_req(&r);
    check("gzip: none for HEAD", -1, hr_find(&g_blk, "accept-encoding"));
    r.method = "GET";
    go_req(&r);
    check("gzip: otherwise before Go's user-agent", 1, g_blk.n == 6 && !strcmp(g_blk.f[4].name, "accept-encoding") &&
          !strcmp(g_blk.f[4].value, "gzip"));
}

static void t_list_size_go(void) {
    const struct h2_field fl[] = { { "referer", "r" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "POST", .fields = fl, .fields_n = 1,
                        .body_len = 1000000 };
    /* catches: the list size leaving out content-length or accept-encoding, or counting a dropped field */
    check("list size go: packet POST, 1018 + 53 + 51", 1122, (int)h2w_list_size(&r, 1));
    r.body_len = -1;
    check("list size go: unknown body, 1018 + 51", 1069, (int)h2w_list_size(&r, 1));
    r.body_len = 0;
    check("list size go: empty POST body, 1018 + 47 + 51", 1116, (int)h2w_list_size(&r, 1));
}

int main(void) {
    t_go_fields_look();
    t_go_cookie_split();
    t_go_fields_dropped();
    t_go_default_ua();
    t_go_fields_edge();
    t_go_fields_firefox();
    t_go_fields_safari();
    t_go_fields_curl();
    t_go_fields_soft_per_look();
    t_look_exact_keys();
    t_look_soft_empty();
    t_go_fields_uniform();
    t_rng_splitmix();
    t_content_length_rule();
    t_gzip_rule();
    t_list_size_go();
    t_user_fields_join_the_look();
    t_field_named_like_a_look_field_replaces_it();
    t_look_keeps_its_identity_fields_over_ours();
    t_no_look_sends_only_the_fields();
    t_req_put_method_not_collapsed_to_post();
    t_req_fields_lowercase();
    t_list_size_counts_32_per_field();
    t_list_size_browser_matches_decoded_block();
    t_block_too_big_writes_nothing();
    t_block_at_16384_fits_16385_refused();
    {
        /* A window gone negative: the server announced INITIAL_WINDOW_SIZE = 1024, taking
         * 64511 bytes off the default 65535 already granted. */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        h2_open(&h, &io);
        io.feed = feed;
        io.feed_n = settings_frame(feed, 0x0004, 1024);
        io.feed_pos = 0;

        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        h2_read(&h, out, sizeof(out), &got);
        check("SETTINGS INITIAL_WINDOW_SIZE=1024: stream window becomes 1024",
              1024, h.send_win);

        h.send_win = -60000;             /* the server cut the window below what was sent */
        unsigned char payload[16384];
        memset(payload, 'x', sizeof(payload));
        io.sent_n = 0;
        check("window -60000: h2_write refuses",
              H2_EWINDOW, h2_write(&h, payload, sizeof(payload)));
        check("window -60000: not a byte goes to the network", 0, (int)io.sent_n);
    }
    {
        /* The boundary: exactly as much as allowed passes, one byte more does not. */
        struct h2 h;
        struct fake_io io;
        h2_open(&h, &io);
        h.send_win = 16384;
        h.send_win_conn = 16384;
        unsigned char payload[16384];
        memset(payload, 'x', sizeof(payload));
        check("window exactly the data size: the write is allowed",
              0, h2_write(&h, payload, sizeof(payload)));
        check("after the write the stream window is 0", 0, h.send_win);
        check("after the write the connection window is 0", 0, h.send_win_conn);
        check("window 0 on the next write: refused",
              H2_EWINDOW, h2_write(&h, payload, 1));
        h.send_win = 16384;
        check("connection window spent by the write: refused with the stream window open",
              H2_EWINDOW, h2_write(&h, payload, 1));
    }
    {
        /* The CONNECTION window is checked apart from the stream window: each has its own
         * counter. */
        struct h2 h;
        struct fake_io io;
        h2_open(&h, &io);
        h.send_win = 65535;
        h.send_win_conn = -1;
        unsigned char payload[16];
        memset(payload, 'x', sizeof(payload));
        check("negative connection window: refused with the stream window open",
              H2_EWINDOW, h2_write(&h, payload, sizeof(payload)));
    }
    {
        /* A DATA body reaches the caller whole: a base check that window handling does not break
         * reading itself. */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        h2_open(&h, &io);
        feed[0] = 0; feed[1] = 0; feed[2] = 4;
        feed[3] = FR_DATA; feed[4] = 0;
        /* The stream number comes FROM THE STATE, not a constant. */
        put32(feed + 5, h.sid);
        memcpy(feed + 9, "abcd", 4);
        io.feed = feed;
        io.feed_n = 13;
        io.feed_pos = 0;

        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        int rc = h2_read(&h, out, sizeof(out), &got);
        check("DATA frame: h2_read succeeds", 0, rc);
        check("DATA frame: 4 body bytes returned", 4, (int)got);
        check("DATA frame: body unchanged", 0, memcmp(out, "abcd", 4));

        /* The same frame with its header cut by a record boundary: the first five header bytes
         * must wait for the other four, not be dropped or read as a frame of their own. */
        h2_open(&h, &io);
        io.feed = feed; io.feed_n = 5; io.feed_pos = 0;
        rc = h2_read(&h, out, sizeof(out), &got);
        size_t first = got;
        io.feed = feed + 5; io.feed_n = 8; io.feed_pos = 0;
        if (rc == 0) rc = h2_read(&h, out, sizeof(out), &got);
        check("DATA header split by a record: no error", 0, rc);
        check("DATA header split by a record: 4 body bytes, all after the rest of the header",
              4, first == 0 ? (int)got : -1);
        check("DATA header split by a record: body unchanged",
              0, got == 4 ? memcmp(out, "abcd", 4) : 1);
    }

    {
        /* WINDOW_UPDATE near the limit: the window must NOT overflow into the negative.
         *
         * Adding without a check is signed overflow (undefined behavior), and what shows is a
         * window negative FOREVER: h2_write then always answers H2_EWINDOW, and sending on the
         * connection stops for good. A server gets there with two frames, each legal on its own.
         * RFC 7540 §6.9.1 says going past 2^31-1 is an error, so we expect a reset, not silence. */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        h2_open(&h, &io);
        feed[0] = 0; feed[1] = 0; feed[2] = 4;
        feed[3] = FR_WINDOW_UPDATE; feed[4] = 0;
        put32(feed + 5, 1);              /* our stream */
        put32(feed + 9, 0x7FFFFFFF);
        io.feed = feed; io.feed_n = 13; io.feed_pos = 0;

        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        int rc = h2_read(&h, out, sizeof(out), &got);
        check("WINDOW_UPDATE past 2^31-1: connection reset", H2_ERESET, rc);
        check("and the window did not go negative", 1, h.send_win >= 0);
    }
    {
        /* A WINDOW_UPDATE that fits opens the window it names, by its increment: our stream's
         * on our stream, the connection's on stream 0, and neither touches the other. */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64], inc[4];
        h2_open(&h, &io);
        put32(inc, 1000);
        size_t fn = put_frame(feed, FR_WINDOW_UPDATE, 0, h.sid, inc, 4);
        put32(inc, 2000);
        fn += put_frame(feed + fn, FR_WINDOW_UPDATE, 0, 0, inc, 4);
        put32(inc, 4000);
        fn += put_frame(feed + fn, FR_WINDOW_UPDATE, 0, h.sid + 2, inc, 4);
        io.feed = feed; io.feed_n = fn; io.feed_pos = 0;
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        check("WINDOW_UPDATE on our stream and on stream 0: no error",
              0, h2_read(&h, out, sizeof(out), &got));
        check("WINDOW_UPDATE on our stream: the stream window grows by it", 66535, h.send_win);
        check("WINDOW_UPDATE on stream 0: the connection window grows by it",
              67535, h.send_win_conn);
        check("WINDOW_UPDATE on another stream: neither window moves",
              1, h.send_win == 66535 && h.send_win_conn == 67535);
    }
    {
        /* The same SETTINGS twice: the window must stay where it is. A shift counted from 65535
         * every time would apply the difference again on the second identical SETTINGS and move the
         * window by an amount the server never granted (RFC 7540 §6.9.2). */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        h2_open(&h, &io);
        io.feed = feed; io.feed_n = settings_frame(feed, 0x0004, 1024); io.feed_pos = 0;
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;
        h2_read(&h, out, sizeof(out), &got);
        int after_first = h.send_win;
        io.feed_n = settings_frame(feed, 0x0004, 1024); io.feed_pos = 0;
        h2_read(&h, out, sizeof(out), &got);
        check("same SETTINGS twice: the window does not move again", after_first, h.send_win);
    }

    {
        /* ---- RECEIVE window: the connection counts apart from the stream ---------
         *
         * The receive window is replenished by WINDOW_UPDATE, at two levels: stream and
         * connection. Bytes received on any stream spend BOTH, so they must be returned to the
         * server on both too; otherwise the window we announced shrinks steadily to zero and the
         * server stops writing. From outside a transfer stalls on a large file, the later the
         * larger the window.
         *
         * A DATA frame of another stream does not go into the body, but it has spent the
         * connection window.
         *
         * Behavior is checked, not a field: the sum of increments in all WINDOW_UPDATE frames sent
         * on stream 0 must equal the number of DATA bytes received. */
        struct h2 h;
        struct fake_io io;
        static unsigned char feed[2 * (9 + 16384)];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        h2_open(&h, &io);
        size_t fn = put_data(feed, 3, 16384);
        fn += put_data(feed + fn, 3, 16384);
        /* The first 16384 bytes from another stream: below the replenish threshold (32 KB), so
         * no WINDOW_UPDATE yet. */
        io.feed = feed; io.feed_n = 9 + 16384; io.feed_pos = 0;
        while (io.feed_pos < io.feed_n)
            if (h2_read(&h, out, sizeof(out), &got) != 0) break;
        check("below the threshold: no window update", 0, (int)wu_sum(&io, 0));
        /* As much again: it does not go into the body, but it spends the window. 32 KB of them
         * would also reach the stream threshold if our stream counted them. */
        io.feed_n = fn;
        while (io.feed_pos < io.feed_n)
            if (h2_read(&h, out, sizeof(out), &got) != 0) break;
        check("frames of another stream: connection window returned in full",
              32768, (int)wu_sum(&io, 0));
        check("and our stream gets no update for those bytes", 0, (int)wu_sum(&io, h.sid));
    }

    {
        /* ---- :status with a Huffman-coded value ----------------------------------
         *
         * A Go server (Xray) writes the status as a literal with name index 8 and a Huffman value
         * when that is shorter: "502" is two bytes 0x6C 0x02 instead of three digits. Such a status
         * must read as 502, that is end in H2_ESTATUS with the code, not in silence. */
        static const unsigned char st502[] = { 0x48, 0x82, 0x6C, 0x02 };
        static const unsigned char st200[] = { 0x48, 0x82, 0x10, 0x01 };
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        h2_open(&h, &io);
        g_last_status = 0;
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS, h.sid, st502, sizeof st502);
        check("Huffman :status 502: H2_ESTATUS", H2_ESTATUS, h2_read(&h, out, sizeof(out), &got));
        check("Huffman :status 502: code 502 recorded", 502, g_last_status);
        /* "5A0": 'A' has the 6-bit code 100001, past the digits' 011001..011111. Not a status,
         * and not "610" either. */
        static const unsigned char st5a0[] = { 0x6E, 0x10, 0x7F };
        static const unsigned char st502h[] = { 0x6C, 0x02 };
        check("Huffman decoder: \"502\" reads as 502", 502, status_huff(st502h, 2));
        check("Huffman decoder: a non-digit symbol is not a status", -1, status_huff(st5a0, 3));

        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS, h.sid, st200, sizeof st200);
        check("Huffman :status 200: not an error", 0, h2_read(&h, out, sizeof(out), &got));
        check("Huffman :status 200: status 200", 200, h.status);

        /* The same code with a zero bit for padding: not valid Huffman (RFC 7541 §5.2), so no
         * status at all rather than a guessed 200. */
        static const unsigned char st200z[] = { 0x48, 0x82, 0x10, 0x00 };
        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS, h.sid, st200z, sizeof st200z);
        h2_read(&h, out, sizeof(out), &got);
        check("Huffman :status with zero padding: not read as a status", -1, h.status);
    }

    {
        /* ---- RST_STREAM of another stream does not break ours ----------------------
         *
         * It ends another stream, not ours: the connection must live. RST on our stream is still
         * a reset. */
        static const unsigned char no_error[4] = { 0, 0, 0, 0 };
        struct h2 h;
        struct fake_io io;
        unsigned char feed[64];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_RST_STREAM, 0, 3, no_error, 4);
        check("RST_STREAM of another stream: no error", 0, h2_read(&h, out, sizeof(out), &got));
        io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_RST_STREAM, 0, h.sid, no_error, 4);
        check("RST_STREAM of our stream: reset", H2_ERESET, h2_read(&h, out, sizeof(out), &got));
    }

    {
        /* ---- PADDED and PRIORITY -------------------------------------------------
         *
         * DATA and HEADERS may carry padding (PADDED: a length byte in front, padding at the end),
         * HEADERS also five bytes of priority (PRIORITY). Neither is data: the length byte and the
         * padding must not get into the body, and the status comes after the priority. The window
         * is charged for the WHOLE frame, padding included (RFC 7540 §6.9.1), or the window we
         * announce drifts from the server's count. */
        struct h2 h;
        struct fake_io io;
        unsigned char feed[128];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        /* HEADERS: padding 2, priority, :status 404 by index, two zero padding bytes. */
        static const unsigned char hdrs[] = { 2, 0, 0, 0, 0, 16, 0x8D, 0, 0 };
        h2_open(&h, &io);
        g_last_status = 0;
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS | 0x08 | 0x20, h.sid,
                              hdrs, sizeof hdrs);
        check("HEADERS with PADDED and PRIORITY: 404 gives H2_ESTATUS",
              H2_ESTATUS, h2_read(&h, out, sizeof(out), &got));
        check("HEADERS with PADDED and PRIORITY: code 404 recorded", 404, g_last_status);

        /* HEADERS with PRIORITY only: :status 200. */
        static const unsigned char hdrs_pri[] = { 0, 0, 0, 0, 16, 0x88 };
        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_HEADERS, FLAG_END_HEADERS | 0x20, h.sid,
                              hdrs_pri, sizeof hdrs_pri);
        check("HEADERS with PRIORITY: not an error", 0, h2_read(&h, out, sizeof(out), &got));
        check("HEADERS with PRIORITY: status 200", 200, h.status);

        /* DATA: padding 3, body "abcd". */
        static const unsigned char data[] = { 3, 'a', 'b', 'c', 'd', 0, 0, 0 };
        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_DATA, 0x08, h.sid, data, sizeof data);
        int rc = h2_read(&h, out, sizeof(out), &got);
        check("DATA with PADDED: no error", 0, rc);
        check("DATA with PADDED: 4 body bytes returned", 4, (int)got);
        check("DATA with PADDED: body unchanged", 0, got == 4 ? memcmp(out, "abcd", 4) : 1);
        check("DATA with PADDED: connection window charged the whole frame", 8, h.recv_credit_conn);
        check("DATA with PADDED: stream window charged the whole frame", 8, h.recv_credit);

        /* The same frame split by record boundaries: the header and the length byte, then two
         * body bytes, then the rest of the body with the padding. */
        static const unsigned char data2[] = { 3, 'a', 'b', 'c', 'd', 0, 0, 0 };
        h2_open(&h, &io);
        size_t fn = put_frame(feed, FR_DATA, 0x08, h.sid, data2, sizeof data2);
        size_t cuts[] = { 10, 12, fn };
        size_t from = 0, total = 0;
        unsigned char body[16];
        for (int i = 0; i < 3; i++) {
            io.feed = feed + from; io.feed_n = cuts[i] - from; io.feed_pos = 0;
            if (h2_read(&h, out, sizeof(out), &got) != 0) { total = 99; break; }
            if (total + got <= sizeof body) memcpy(body + total, out, got);
            total += got;
            from = cuts[i];
        }
        check("DATA with PADDED in three records: 4 bytes returned", 4, (int)total);
        check("DATA with PADDED in three records: body unchanged",
              0, total == 4 ? memcmp(body, "abcd", 4) : 1);

        /* A record boundary INSIDE the padding: padding 5, body "abcd", the first record ends two
         * bytes into the padding. The rest of the padding in the second record is not data. */
        static const unsigned char data3[] = { 5, 'a', 'b', 'c', 'd', 0, 0, 0, 0, 0 };
        h2_open(&h, &io);
        fn = put_frame(feed, FR_DATA, 0x08, h.sid, data3, sizeof data3);
        size_t cut = 9 + 1 + 4 + 2;
        total = 0;
        rc = 0;
        io.feed = feed; io.feed_n = cut; io.feed_pos = 0;
        rc = h2_read(&h, out, sizeof(out), &got);
        if (rc == 0 && got <= sizeof body) { memcpy(body, out, got); total = got; }
        io.feed = feed + cut; io.feed_n = fn - cut; io.feed_pos = 0;
        if (rc == 0) rc = h2_read(&h, out, sizeof(out), &got);
        if (rc == 0 && total + got <= sizeof body) memcpy(body + total, out, got);
        if (rc == 0) total += got;
        check("DATA: boundary inside the padding, no error", 0, rc);
        check("DATA: boundary inside the padding, 4 bytes returned", 4, (int)total);
        check("DATA: boundary inside the padding, body unchanged",
              0, total == 4 ? memcmp(body, "abcd", 4) : 1);
        check("DATA: boundary inside the padding, window charged the whole frame",
              (int)sizeof data3, h.recv_credit_conn);

        /* Padding longer than the frame is a protocol error (RFC 7540 §6.1), not a read past
         * the end. */
        static const unsigned char bad[] = { 9, 'a', 'b' };
        h2_open(&h, &io);
        io.feed = feed; io.feed_pos = 0;
        io.feed_n = put_frame(feed, FR_DATA, 0x08, h.sid, bad, sizeof bad);
        check("DATA with padding longer than the frame: H2_EPROTO",
              H2_EPROTO, h2_read(&h, out, sizeof(out), &got));
    }

    {
        /* ---- H2_ETOOBIG does not lose the rest of a record -----------------------
         *
         * A buffer smaller than H2_MIN_READ_CAP breaks the caller's contract, but the outcome
         * must still be clean: a refusal after which the connection can be read on. A refusal
         * in the middle of a frame that dropped the record read so far but kept the body
         * counter would make the next frame read as a continuation of the previous one, its
         * header going into the body. */
        struct h2 h;
        struct fake_io io;
        static unsigned char feed[256];
        unsigned char small[64];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0;

        h2_open(&h, &io);
        size_t n1 = put_data(feed, h.sid, 100);
        io.feed = feed; io.feed_n = n1; io.feed_pos = 0;
        check("buffer below the contract: H2_ETOOBIG",
              H2_ETOOBIG, h2_read(&h, small, sizeof(small), &got));
        /* Then reads by the contract: the frame "abcd" must arrive as is. */
        size_t n2 = put_frame(feed + n1, FR_DATA, 0, h.sid, (const unsigned char *)"abcd", 4);
        io.feed_n = n1 + n2;
        size_t total = 0;
        int rc = 0;
        static unsigned char all[256], want[104];
        while (io.feed_pos < io.feed_n && rc == 0) {
            rc = h2_read(&h, out, sizeof(out), &got);
            if (total + got <= sizeof all) memcpy(all + total, out, got);
            total += got;
        }
        memset(want, 'q', 100);
        memcpy(want + 100, "abcd", 4);
        check("after the refusal: the following reads succeed", 0, rc);
        check("after the refusal: both frames arrive whole", 104, (int)total);
        check("after the refusal: the two bodies in order, no frame header among them",
              0, total == 104 ? memcmp(all, want, 104) : 1);
    }

    {
        /* ---- the end of a stream in the SAME record as the last data -------------------
         *
         * Xray (grpc-go) ends a stream whose target has closed by flushing the data, the closing
         * HEADERS with END_STREAM and RST_STREAM(NO_ERROR) in one TLS record. The data must be
         * returned and the end come from the NEXT call: callers look at the code before got, so
         * returning the reset at once dropped the data (a node probe failed on a working node,
         * and the end of client responses was lost). */
        static const unsigned char hdr200[] = { 0x88 };
        static const unsigned char trailers[] = { 0x88 };      /* not read */
        static const unsigned char no_error[4] = { 0, 0, 0, 0 };
        struct h2 h;
        struct fake_io io;
        static unsigned char feed[512];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0, n = 0;

        h2_open(&h, &io);
        n += put_frame(feed + n, FR_HEADERS, FLAG_END_HEADERS, h.sid, hdr200, sizeof hdr200);
        n += put_frame(feed + n, FR_DATA, 0, h.sid, (const unsigned char *)"hello", 5);
        n += put_frame(feed + n, FR_DATA, 0, h.sid, (const unsigned char *)" world", 6);
        n += put_frame(feed + n, FR_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, h.sid, trailers,
                       sizeof trailers);
        n += put_frame(feed + n, FR_RST_STREAM, 0, h.sid, no_error, 4);
        io.feed = feed; io.feed_n = n; io.feed_pos = 0;
        int rc = h2_read(&h, out, sizeof(out), &got);
        check("data + END_STREAM + RST_STREAM in one record: first call, no error", 0, rc);
        check("  all the data returned (11 bytes)", 11, (int)got);
        check("  and intact", 0, got == 11 ? memcmp(out, "hello world", 11) : 1);
        io.feed_pos = io.feed_n;
        rc = h2_read(&h, out, sizeof(out), &got);
        check("  second call: end of stream", H2_ERESET, rc);
        check("  the reason names RST_STREAM and its code", 1,
              strstr(h2_strerror(H2_ERESET), "RST_STREAM NO_ERROR") != NULL);
        check("  and the same end after that", H2_ERESET, h2_read(&h, out, sizeof(out), &got));

        /* The same without END_STREAM: the server reset the stream mid-response. */
        h2_open(&h, &io);
        n = 0;
        n += put_frame(feed + n, FR_DATA, 0, h.sid, (const unsigned char *)"abc", 3);
        static const unsigned char cancel[4] = { 0, 0, 0, 8 };
        n += put_frame(feed + n, FR_RST_STREAM, 0, h.sid, cancel, 4);
        io.feed = feed; io.feed_n = n; io.feed_pos = 0;
        rc = h2_read(&h, out, sizeof(out), &got);
        check("data + RST_STREAM(CANCEL): data returned", 3, rc == 0 ? (int)got : -1);
        rc = h2_read(&h, out, sizeof(out), &got);
        check("  then the reset, with its code named", 1,
              rc == H2_ERESET && strstr(h2_strerror(rc), "CANCEL") != NULL);

        /* RST_STREAM with no data before it: the reset at once. */
        h2_open(&h, &io);
        n = put_frame(feed, FR_RST_STREAM, 0, h.sid, cancel, 4);
        io.feed = feed; io.feed_n = n; io.feed_pos = 0;
        check("RST_STREAM without data: reset at once", H2_ERESET, h2_read(&h, out, sizeof(out), &got));
    }

    {
        /* ---- GOAWAY (RFC 9113 §6.8) ------------------------------------------------------
         *
         * GOAWAY(NO_ERROR) with last_stream_id at or above our id is a graceful close: the
         * server finishes the streams in progress. The stream ends only on an error code
         * (ENHANCE_YOUR_CALM for too many PINGs, PROTOCOL_ERROR ...) or when our id is past
         * last_stream_id. */
        struct h2 h;
        struct fake_io io;
        static unsigned char feed[256];
        unsigned char out[H2_MIN_READ_CAP];
        size_t got = 0, n;
        unsigned char ga[8];

        h2_open(&h, &io);
        put32(ga, 0x7FFFFFFFu); put32(ga + 4, 0);
        n = put_frame(feed, FR_GOAWAY, 0, 0, ga, 8);
        n += put_frame(feed + n, FR_DATA, 0, h.sid, (const unsigned char *)"tail", 4);
        io.feed = feed; io.feed_n = n; io.feed_pos = 0;
        int rc = h2_read(&h, out, sizeof(out), &got);
        check("GOAWAY(NO_ERROR, last >= our id): the stream goes on", 0, rc);
        check("  data after GOAWAY arrives", 4, (int)got);

        h2_open(&h, &io);
        put32(ga, 1); put32(ga + 4, 11);
        n = put_frame(feed, FR_DATA, 0, h.sid, (const unsigned char *)"xy", 2);
        n += put_frame(feed + n, FR_GOAWAY, 0, 0, ga, 8);
        io.feed = feed; io.feed_n = n; io.feed_pos = 0;
        rc = h2_read(&h, out, sizeof(out), &got);
        check("data + GOAWAY(ENHANCE_YOUR_CALM): data returned", 2, rc == 0 ? (int)got : -1);
        rc = h2_read(&h, out, sizeof(out), &got);
        check("  then the end, the reason names the code", 1,
              rc == H2_ERESET && strstr(h2_strerror(rc), "GOAWAY ENHANCE_YOUR_CALM") != NULL);

        /* Our stream past last_stream_id was never reached: the end, NO_ERROR or not. */
        h2_open(&h, &io);
        put32(ga, 0); put32(ga + 4, 0);
        n = put_frame(feed, FR_GOAWAY, 0, 0, ga, 8);
        io.feed = feed; io.feed_n = n; io.feed_pos = 0;
        rc = h2_read(&h, out, sizeof(out), &got);
        /* catches: a GOAWAY that did not reach our stream read as a graceful close */
        check("GOAWAY(last=0) on stream 1: the end", H2_ERESET, rc);
    }

    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed");

    return fails ? 1 : 0;
}
