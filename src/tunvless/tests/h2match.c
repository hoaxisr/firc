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

static void look_req(struct fake_io *io, const struct h2_req *r) {
    memset(io, 0, sizeof *io);
    io->sent_n = h2w_preface(io->sent, sizeof io->sent, 1);
    size_t n = h2w_headers(io->sent + io->sent_n + 9, DEFAULT_MAX_FRAME, r, 1);
    unsigned char flags = (unsigned char)(FLAG_END_HEADERS | (r->end_stream ? FLAG_END_STREAM : 0));
    h2w_frame_hdr(io->sent + io->sent_n, (uint32_t)n, FR_HEADERS, flags, 1);
    io->sent_n += 9 + n;
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
    look_req(&io, &g);
    hr_first_headers(io.sent, io.sent_n, &g_blk);
    check("GET request: :method indexed 2", 1, g_blk.f[0].kind == 'i' && g_blk.f[0].index == 2);
    check("GET request: END_STREAM on HEADERS", 1, (io.sent[24 + 21 + 13 + 4] & 0x01) != 0);
}

static void t_req_fields_slot_order_and_lowercase(void) {
    struct fake_io io;
    const struct h2_field fl[] = { { "X-A", "1" }, { "cookie", "s=2" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "POST",
                        .fields = fl, .fields_n = 2 };
    look_req(&io, &r);
    check("browser request with fields: HEADERS decode", 0,
          hr_first_headers(io.sent, io.sent_n, &g_blk));
    int dest = hr_find(&g_blk, "sec-fetch-dest");
    check("sec-fetch-dest present", 1, dest > 0);
    check("first field right after sec-fetch-dest, lowercased", 0,
          strcmp(g_blk.f[dest + 1].name, "x-a"));
    check("first field value", 0, strcmp(g_blk.f[dest + 1].value, "1"));
    check("second field next", 0, strcmp(g_blk.f[dest + 2].name, "cookie"));
    check("second field value", 0, strcmp(g_blk.f[dest + 2].value, "s=2"));
    check("accept-language after the fields", dest + 3, hr_find(&g_blk, "accept-language"));
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
    struct fake_io io;
    const struct h2_field fl[] = { { "X-Pad", "abc" }, { "referer", "https://a/p" } };
    struct h2_req r = { .authority = "a", .path = "/p", .content_type = "application/grpc",
                        .method = "PATCH", .fields = fl, .fields_n = 2 };
    look_req(&io, &r);
    hr_first_headers(io.sent, io.sent_n, &g_blk);
    size_t want = 0;
    for (size_t i = 0; i < g_blk.n; i++)
        want += strlen(g_blk.f[i].name) + strlen(g_blk.f[i].value) + 32;
    check("browser list size: 20 fields decoded", 20, (int)g_blk.n);
    check("browser list size equals the decoded block", (int)want, (int)h2w_list_size(&r, 1));
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

static void t_lead_fields_before_the_look_not_after_dest(void) {
    struct fake_io io;
    const struct h2_field fl[] = { { "X-A", "1" }, { "referer", "https://a/p" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 2, .lead_n = 1 };
    look_req(&io, &r);
    check("lead: HEADERS decode", 0, hr_first_headers(io.sent, io.sent_n, &g_blk));
    check("lead: x-a right after the pseudo-headers", 4, hr_find(&g_blk, "x-a"));
    check("lead: the look follows it", 5, hr_find(&g_blk, "sec-ch-ua"));
    check("lead: referer still right after sec-fetch-dest",
          hr_find(&g_blk, "sec-fetch-dest") + 1, hr_find(&g_blk, "referer"));
    check("lead: list size equals the decoded block", (int)decoded_size(&g_blk),
          (int)h2w_list_size(&r, 1));
}

static void t_field_named_like_a_look_field_replaces_it(void) {
    struct fake_io io;
    const struct h2_field fl[] = { { "Accept", "text/html" }, { "Pragma", "p" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 2, .lead_n = 2 };
    look_req(&io, &r);
    check("replace: HEADERS decode", 0, hr_first_headers(io.sent, io.sent_n, &g_blk));
    check("replace: one accept", 1, count_named(&g_blk, "accept"));
    check("replace: accept is ours", 0,
          strcmp(g_blk.f[hr_find(&g_blk, "accept")].value, "text/html"));
    check("replace: one pragma (a tail field)", 1, count_named(&g_blk, "pragma"));
    check("replace: pragma is ours", 0, strcmp(g_blk.f[hr_find(&g_blk, "pragma")].value, "p"));
    check("replace: the rest of the look stays", 1, hr_find(&g_blk, "sec-fetch-dest") > 0);
    check("replace: list size equals the decoded block", (int)decoded_size(&g_blk),
          (int)h2w_list_size(&r, 1));
}

static void t_look_keeps_its_identity_fields_over_ours(void) {
    struct fake_io io;
    const struct h2_field fl[] = { { "Accept-Language", "ru" }, { "Sec-Fetch-Mode", "navigate" },
                                   { "DNT", "0" }, { "sec-ch-ua", "x" }, { "X-A", "1" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 5, .lead_n = 2 };
    look_req(&io, &r);
    check("identity: HEADERS decode", 0, hr_first_headers(io.sent, io.sent_n, &g_blk));
    check("identity: one accept-language", 1, count_named(&g_blk, "accept-language"));
    check("identity: accept-language is the look's", 0,
          strcmp(g_blk.f[hr_find(&g_blk, "accept-language")].value, "en-US,en;q=0.9"));
    check("identity: one sec-fetch-mode", 1, count_named(&g_blk, "sec-fetch-mode"));
    check("identity: sec-fetch-mode is cors", 0,
          strcmp(g_blk.f[hr_find(&g_blk, "sec-fetch-mode")].value, "cors"));
    check("identity: one dnt", 1, count_named(&g_blk, "dnt"));
    check("identity: dnt is 1", 0, strcmp(g_blk.f[hr_find(&g_blk, "dnt")].value, "1"));
    check("identity: one sec-ch-ua", 1, count_named(&g_blk, "sec-ch-ua"));
    check("identity: sec-ch-ua is not ours", 1, strcmp(g_blk.f[hr_find(&g_blk, "sec-ch-ua")].value, "x") != 0);
    check("identity: an unrelated field stays", 0, strcmp(g_blk.f[hr_find(&g_blk, "x-a")].value, "1"));
    check("identity: list size equals the decoded block", (int)decoded_size(&g_blk),
          (int)h2w_list_size(&r, 1));
}

static void t_no_look_sends_only_the_fields(void) {
    struct fake_io io;
    const struct h2_field fl[] = { { "User-Agent", "MyApp/1" }, { "referer", "r" } };
    struct h2_req r = { .authority = "a", .path = "/p", .method = "GET", .end_stream = 1,
                        .fields = fl, .fields_n = 2, .lead_n = 1, .no_look = 1 };
    look_req(&io, &r);
    check("no look: HEADERS decode", 0, hr_first_headers(io.sent, io.sent_n, &g_blk));
    check("no look: four pseudo-headers and two fields", 6, (int)g_blk.n);
    check("no look: user-agent is ours", 0,
          strcmp(g_blk.f[hr_find(&g_blk, "user-agent")].value, "MyApp/1"));
    check("no look: no sec-ch-ua", -1, hr_find(&g_blk, "sec-ch-ua"));
    check("no look: no pragma", -1, hr_find(&g_blk, "pragma"));
    check("no look: list size equals the decoded block", (int)decoded_size(&g_blk),
          (int)h2w_list_size(&r, 1));
}

int main(void) {
    t_lead_fields_before_the_look_not_after_dest();
    t_field_named_like_a_look_field_replaces_it();
    t_look_keeps_its_identity_fields_over_ours();
    t_no_look_sends_only_the_fields();
    t_req_put_method_not_collapsed_to_post();
    t_req_fields_slot_order_and_lowercase();
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
