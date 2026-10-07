/* A minimal HTTP/2 client: one stream open at a time, a body both ways.
 *
 * The grpc and xhttp transports are HTTP/2: the server expects the preface, frames and flow
 * control, and without them the connection just hangs.
 *
 * Deliberately NOT here, and why that is fine:
 *
 *   - multiplexing. Requests on a connection follow one another, and every VLESS connection
 *     gets its own TCP+TLS (Xray instead shares one between many: a cached gRPC connection
 *     per node, XMUX for xhttp). Multiplexing would save handshakes but needs a window
 *     scheduler between streams, code that costs more to debug on a single-core router than
 *     it is worth;
 *   - HPACK on receive. Response headers are not parsed; only :status is extracted: a static
 *     index, or a literal with an indexed name as digits or Huffman code (a Go server sends
 *     502, 401, 301 this way, see status_huff). Full HPACK needs a dynamic table, i.e. memory
 *     per connection;
 *   - PUSH_PROMISE. Disabled in SETTINGS, so it cannot arrive;
 *   - priorities and trailers. The first decides nothing, the second only closes the stream.
 *
 * Memory: one state per VLESS connection (two for xhttp with an upload link), and a loop
 * thread holds hundreds of connections (MAX_CONNS in stack.c), so there is no frame buffer.
 * Records are read into a per-thread buffer, and only what cannot be parsed at once carries
 * over between calls: a split frame header (9 bytes), a control frame body (64) and the count
 * of unread body. A 16 KB frame buffer per connection would add up to megabytes.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#include "h2.h"
#include "tls13.h"

#define FR_DATA          0x00
#define FR_HEADERS       0x01
#define FR_RST_STREAM    0x03
#define FR_SETTINGS      0x04
#define FR_PING          0x06
#define FR_GOAWAY        0x07
#define FR_WINDOW_UPDATE 0x08

#define FLAG_END_STREAM  0x01
#define FLAG_ACK         0x01
#define FLAG_END_HEADERS 0x04
#define FLAG_PADDED      0x08
#define FLAG_PRIORITY    0x20


/* Our receive window. Large on purpose: with the default 65535 every 64 KB of download waits
 * for a WINDOW_UPDATE, which on a 100 ms link caps speed at about 5 Mbit/s whatever the
 * bandwidth. A megabyte costs nothing: it only lets the server send; we hold no memory for it. */
#define OUR_WINDOW       (1024 * 1024)
/* Refill every 32 KB, not every frame: a refill per frame is an extra TLS record per 16 KB of
 * data, a visible pattern in the stream. */
#define WINDOW_REFILL    (32 * 1024)

/* The largest frame a server must accept by default (RFC 7540 §4.2); more only if the server
 * allows it in SETTINGS. */
#define DEFAULT_MAX_FRAME 16384

/* How the server last ended a stream, for h2_strerror. Per thread, like g_last_status. */
static __thread char g_reset_why[64];

static void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}
static uint32_t get32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

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

/* ---- frames ------------------------------------------------------------------ */
static int frame_out(struct h2 *h, unsigned char type, unsigned char flags, uint32_t sid,
                     const unsigned char *body, size_t n) {
    unsigned char hdr[9];
    hdr[0] = (unsigned char)(n >> 16); hdr[1] = (unsigned char)(n >> 8); hdr[2] = (unsigned char)n;
    hdr[3] = type;
    hdr[4] = flags;
    put32(hdr + 5, sid);
    /* Header and body in one write: split across TLS records they make a recognizable length
     * pattern (9 + N, 9 + N, …), the very thing Vision exists to remove. */
    static __thread unsigned char one[9 + DEFAULT_MAX_FRAME];
    if (n > DEFAULT_MAX_FRAME) return H2_ETOOBIG;
    memcpy(one, hdr, 9);
    if (n) memcpy(one + 9, body, n);
    return h->io.write(h->io.ctx, one, 9 + n);
}

/* HEADERS of one request. Pseudo-headers must come before the other fields (RFC 7540
 * §8.1.2.1).
 *
 * One function for every request of a connection (packet-up sends a series of short POSTs):
 * two places building headers would drift apart, and the symptom would be a server that
 * answers the first request and not the second. */
/* Track a stream's response: opened (open_add), ended (open_end). Ids past H2_OPEN_MAX are not
 * tracked: callers that bound the count never get there. */
static void open_add(struct h2 *h, uint32_t sid) {
    if (h->open_n < H2_OPEN_MAX) h->open_sid[h->open_n++] = sid;
}

static void open_end(struct h2 *h, uint32_t sid) {
    for (unsigned i = 0; i < h->open_n; i++)
        if (h->open_sid[i] == sid) { h->open_sid[i] = h->open_sid[--h->open_n]; return; }
}

int h2_open_streams(const struct h2 *h) { return h->open_n; }

uint32_t h2_oldest_open(const struct h2 *h) {
    uint32_t m = 0;
    for (unsigned i = 0; i < h->open_n; i++)
        if (!m || h->open_sid[i] < m) m = h->open_sid[i];
    return m;
}

static int put_headers(struct h2 *h, struct wbuf *b, const char *authority,
                       const char *path, const char *content_type, const char *referer,
                       int method, int end_stream) {
    const int browser = h->browser;
    /* 4 KB: the browser look is a dozen headers, and with them goes a Referer of up to 1400
     * bytes with the padding (2 KB was too small); a size failure would look like a dead
     * node. One buffer per thread. */
    static __thread unsigned char hb[4096];
    struct wbuf hp = { hb, 0, sizeof(hb) };
    hp_indexed(&hp, method == H2_GET ? HP_METHOD_GET : HP_METHOD_POST);
    hp_indexed(&hp, HP_SCHEME_HTTPS);
    hp_field(&hp, HP_PATH, path);
    hp_field(&hp, HP_AUTHORITY, authority);
    if (content_type) hp_field(&hp, HP_CONTENT_TYPE, content_type);
    if (browser) {
        /* Chrome's order: client hints, then who it is, then what it wants and where it came
         * from. Referer carries the xhttp padding and stands where a browser puts it. */
        hp_new(&hp, "sec-ch-ua", UA_CH_CHROME);
        hp_new(&hp, "sec-ch-ua-mobile", "?0");
        hp_new(&hp, "sec-ch-ua-platform", "\"Windows\"");
        hp_new(&hp, "dnt", "1");
        hp_field(&hp, HP_USER_AGENT, UA_CHROME);
        hp_field(&hp, HP_ACCEPT, "*/*");
        hp_new(&hp, "sec-fetch-site", "same-origin");
        hp_new(&hp, "sec-fetch-mode", "cors");
        hp_new(&hp, "sec-fetch-dest", "empty");
        if (referer) hp_field(&hp, HP_REFERER, referer);
        hp_field(&hp, HP_ACCEPT_LANG, "en-US,en;q=0.9");
        hp_new(&hp, "priority", "u=1, i");
        hp_field(&hp, HP_CACHE_CTRL, "no-cache");
        hp_new(&hp, "pragma", "no-cache");
    } else {
        if (referer) hp_field(&hp, HP_REFERER, referer);
        /* te: trailers is the one connection-specific header HTTP/2 explicitly allows, and
         * gRPC requires it. */
        hp_new(&hp, "te", "trailers");
        hp_field(&hp, HP_USER_AGENT, "grpc-go/1.60.0");
    }
    if (hp.n > sizeof(hb)) return -1;

    /* END_STREAM as the caller asks. A long-lived stream has none: the request body is the
     * upstream channel and lives as long as the connection. A download GET has no body, and
     * the server waits for the close right here. END_HEADERS always: the headers are short and
     * need no CONTINUATION. */
    unsigned char hdr[9];
    hdr[0] = (unsigned char)(hp.n >> 16); hdr[1] = (unsigned char)(hp.n >> 8);
    hdr[2] = (unsigned char)hp.n;
    hdr[3] = FR_HEADERS;
    hdr[4] = (unsigned char)(FLAG_END_HEADERS | (end_stream ? FLAG_END_STREAM : 0));
    put32(hdr + 5, h->sid);
    wb(b, hdr, 9);
    wb(b, hb, hp.n);
    return 0;
}

int h2_start_ex(struct h2 *h, const struct h2_io *io, const char *authority,
                const char *path, const char *content_type, const char *referer,
                int method, int end_stream, int browser) {
    memset(h, 0, sizeof(*h));
    h->io = *io;
    h->browser = browser;
    h->sid = 1;                          /* a client's first stream: the first odd id */
    h->open_n = 0;
    open_add(h, h->sid);
    h->send_win = 65535;                 /* the default until the server's SETTINGS */
    h->send_win_conn = 65535;
    h->peer_init_win = 65535;            /* the same default; shifts count from it */

    static __thread unsigned char buf[4096];
    struct wbuf b = { buf, 0, sizeof(buf) };

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
    {
        unsigned char wu[4];
        put32(wu, OUR_WINDOW - 65535);
        unsigned char hdr[9] = { 0, 0, 4, FR_WINDOW_UPDATE, 0, 0, 0, 0, 0 };
        wb(&b, hdr, 9);
        wb(&b, wu, 4);
    }

    if (put_headers(h, &b, authority, path, content_type, referer, method, end_stream) != 0)
        return H2_ETOOBIG;

    if (b.n > sizeof(buf)) return H2_ETOOBIG;
    /* All in one write: preface, SETTINGS, WINDOW_UPDATE and the request leave together, as a
     * browser sends them; separately they would make a run of records of telltale lengths.
     *
     * The answer is NOT awaited. The server will send its SETTINGS and HEADERS, but waiting
     * for them would add a round trip before the first data byte, and HTTP/2 allows sending
     * data at once. The status shows on the first read. */
    h->started = 1;
    return h->io.write(h->io.ctx, buf, b.n);
}

int h2_start(struct h2 *h, const struct h2_io *io, const char *authority,
             const char *path, const char *content_type, const char *referer) {
    /* POST with an open body and gRPC headers (browser = 0): the grpc transport. xhttp calls
     * h2_start_ex for the browser look. */
    return h2_start_ex(h, io, authority, path, content_type, referer, H2_POST, 0, 0);
}

int h2_next(struct h2 *h, const char *authority, const char *path,
            const char *content_type, const char *referer, int method) {
    if (!h->started) return H2_EPROTO;
    /* After GOAWAY the server takes no new streams (RFC 9113 §6.8): the request would get no
     * answer. Refusing now means reconnecting now, not after a timeout. */
    if (h->goaway) {
        snprintf(h->why, sizeof(h->why), "GOAWAY: no new streams");
        snprintf(g_reset_why, sizeof(g_reset_why), "%s", h->why);
        return H2_ERESET;
    }
    h->pend_err = 0;                 /* the previous chunk's end does not carry over */

    /* The id grows by two: client streams are odd (RFC 7540 §5.1.1). Reusing a closed
     * stream's id is a connection error, not a stream error: the whole connection drops. */
    h->sid += 2;
    open_add(h, h->sid);

    /* Fresh STREAM state, CONNECTION state untouched. The connection window and the server's
     * settings are shared by all requests, while each stream's window is granted anew at the
     * initial value from the server's SETTINGS. Resetting the shared state too would forget
     * how much we were already allowed and overrun the connection window. */
    h->status = 0;
    h->done = 0;
    h->send_win = h->peer_init_win;
    /* The STREAM credit is dropped: the old stream is closed, its window need not grow.
     * recv_credit_conn is NOT touched: it belongs to the connection, and zeroing it would never
     * return window the server already spent. */
    h->recv_credit = 0;

    /* The same size as in h2_start_ex: the same headers (browser look, a Referer of up to
     * 1400 bytes, a long node path); 2 KB was too small for them. */
    static __thread unsigned char buf[4096];
    struct wbuf b = { buf, 0, sizeof(buf) };
    if (put_headers(h, &b, authority, path, content_type, referer, method, 0) != 0)
        return H2_ETOOBIG;
    if (b.n > sizeof(buf)) return H2_ETOOBIG;
    return h->io.write(h->io.ctx, buf, b.n);
}

int h2_end_stream(struct h2 *h) {
    if (!h->started) return H2_EPROTO;
    /* An empty DATA with END_STREAM, a frame of its own: h2_write takes no flags and does not
     * know which data is the last. */
    return frame_out(h, FR_DATA, FLAG_END_STREAM, h->sid, NULL, 0);
}

/* Refills the receive windows when enough has accumulated. Both levels: connection and stream
 * are counted apart, and forgetting one stalls at its limit. */
static int window_refill(struct h2 *h) {
    unsigned char wu[4];
    /* Each level is checked and refilled by ITS OWN count: the connection's is larger, since it
     * includes frames of closed streams. One number for both would refill the connection
     * window by less than was spent. */
    if (h->recv_credit >= WINDOW_REFILL) {
        put32(wu, (uint32_t)h->recv_credit);
        int rc = frame_out(h, FR_WINDOW_UPDATE, 0, h->sid, wu, 4);
        if (rc) return rc;
        h->recv_credit = 0;
    }
    if (h->recv_credit_conn >= WINDOW_REFILL) {
        put32(wu, (uint32_t)h->recv_credit_conn);
        int rc = frame_out(h, FR_WINDOW_UPDATE, 0, 0, wu, 4);
        if (rc) return rc;
        h->recv_credit_conn = 0;
    }
    return 0;
}


/* The name of an HTTP/2 error code (RFC 9113 §7), for the log: CANCEL (the server finished its
 * handler), FLOW_CONTROL_ERROR (we overran the window) and ENHANCE_YOUR_CALM (too many PINGs) are
 * different problems. */
static const char *h2_err_name(uint32_t code) {
    static const char *const n[] = {
        "NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT",
        "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR",
        "CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED",
    };
    return code < sizeof(n) / sizeof(n[0]) ? n[code] : "unknown code";
}

/* Record how the stream ended and return H2_ERESET. Kept in the connection's state: other
 * connections of the same loop thread may be read before the code reaches the caller. */
static int h2_reset(struct h2 *h, const char *what, uint32_t code) {
    snprintf(h->why, sizeof(h->why), "%s %s", what, h2_err_name(code));
    return H2_ERESET;
}

/* Handles a control frame whose body is complete. */
static int ctl_handle(struct h2 *h) {
    switch (h->frame_type) {
        case FR_SETTINGS:
            if (h->frame_flags & FLAG_ACK) return 0;
            /* INITIAL_WINDOW_SIZE shifts the SEND window of the open stream by the difference
             * (RFC 7540 §6.9.2); without it we either waste the window or overrun it. */
            for (size_t i = 0; i + 6 <= h->ctl_n; i += 6) {
                unsigned id = ((unsigned)h->ctl[i] << 8) | h->ctl[i + 1];
                uint32_t v = get32(h->ctl + i + 2);
                /* The server's MAX_FRAME_SIZE is ignored on purpose: it cannot be below
                 * 16384, and we never send more, which is legal under any setting. Larger
                 * frames would gain nothing and need a larger send buffer. */
                if (id == 0x04) {
                    /* Only the STREAM window shifts; SETTINGS never change the connection
                     * window, only WINDOW_UPDATE does. The difference is from the PREVIOUS
                     * value, not from 65535: a repeated identical SETTINGS must not shift the
                     * window again. */
                    if (v > 0x7FFFFFFFu) return H2_ERESET;
                    int64_t w = (int64_t)h->send_win + ((int64_t)v - h->peer_init_win);
                    if (w > 0x7FFFFFFF || w < -0x7FFFFFFF) return H2_ERESET;
                    h->send_win = (int32_t)w;
                    h->peer_init_win = (int32_t)v;
                }
            }
            return frame_out(h, FR_SETTINGS, FLAG_ACK, 0, NULL, 0);

        case FR_PING:
            if (h->frame_flags & FLAG_ACK) return 0;
            /* Must be answered: the server sends PING as a keep-alive and takes silence for a
             * dead connection. */
            return frame_out(h, FR_PING, FLAG_ACK, 0, h->ctl, h->ctl_n);

        case FR_WINDOW_UPDATE: {
            if (h->ctl_n < 4) return 0;
            /* A late one for an earlier stream (packet-up opens one per chunk) opens nothing of
             * ours: adding it to the connection window would overrun the server's. */
            if (h->frame_sid != 0 && !h->frame_ours) return 0;
            int32_t inc = (int32_t)(get32(h->ctl) & 0x7FFFFFFF);
            /* The 2^31-1 limit is mandatory (RFC 7540 §6.9.1). Adding without the check is
             * signed overflow; in practice the window goes NEGATIVE for good, h2_write answers
             * H2_EWINDOW forever and uploads on this connection stall. One WINDOW_UPDATE of
             * 0x7FFFFFFF from the server is enough. The RFC makes exceeding the limit an
             * error, so the connection is dropped rather than the window clamped: a clamped
             * window would disagree with the server's count and stall anyway, for no visible
             * reason. */
            int64_t w = (int64_t)(h->frame_ours ? h->send_win : h->send_win_conn) + inc;
            if (w > 0x7FFFFFFF) return h2_reset(h, "window past 2^31-1,", 3);
            if (h->frame_ours) h->send_win = (int32_t)w;
            else h->send_win_conn = (int32_t)w;
            return 0;
        }

        case FR_RST_STREAM:
            open_end(h, h->frame_sid);
            /* A reset of a CLOSED stream is not our end. A Go server sends
             * RST_STREAM(NO_ERROR) on a stream whose handler has finished; with packet-up it
             * arrives for an earlier chunk while the next one is open. */
            if (!h->frame_ours) return 0;
            return h2_reset(h, "RST_STREAM", h->ctl_n >= 4 ? get32(h->ctl) : 0);

        case FR_GOAWAY: {
            /* The end of the CONNECTION: no new streams after it (h2_next refuses). The current
             * stream is not necessarily over: last_stream_id says how far the server will go
             * (RFC 9113 §6.8). A Go server closes gracefully with GOAWAY(NO_ERROR, the highest
             * id), then PING and a second GOAWAY, and finishes the streams in progress. The
             * stream ends here only on an error code or when our id is past last_stream_id. */
            uint32_t last = h->ctl_n >= 4 ? get32(h->ctl) & 0x7FFFFFFFu : 0;
            uint32_t code = h->ctl_n >= 8 ? get32(h->ctl + 4) : 0;
            h->goaway = 1;
            if (code != 0) return h2_reset(h, "GOAWAY", code);
            if (h->sid > last) {
                snprintf(h->why, sizeof(h->why), "GOAWAY: stream not accepted");
                return H2_ERESET;
            }
            return 0;
        }
    }
    return 0;
}

/* The last non-200 status, to name it in the error. Per thread: several threads run
 * connections at once, and a shared one would be overwritten. */
static __thread int g_last_status;

/* Three status digits in HPACK Huffman code (RFC 7541, appendix B). A Go server (Xray)
 * Huffman-codes a value whenever that is shorter: "502", "401", "301" take two bytes instead of
 * three. Without this the status stays -1, and a refusal looks like an answer without data.
 *
 * Only digits are needed: "0", "1", "2" have 5-bit codes 00000…00010, "3"…"9" 6-bit codes
 * 011001…011111. Any other symbol means this is not a status: -1. After three digits only
 * padding of ones shorter than a byte is allowed (§5.2). */
static int status_huff(const unsigned char *p, size_t n) {
    uint32_t acc = 0;
    unsigned bits = 0;
    size_t i = 0;
    int v = 0;
    for (int d = 0; d < 3; d++) {
        while (bits < 6 && i < n) { acc = (acc << 8) | p[i++]; bits += 8; }
        if (bits < 5) return -1;
        unsigned c5 = (acc >> (bits - 5)) & 0x1F;
        if (c5 <= 2) { v = v * 10 + (int)c5; bits -= 5; }
        else {
            if (bits < 6) return -1;
            unsigned c6 = (acc >> (bits - 6)) & 0x3F;
            if (c6 < 0x19 || c6 > 0x1F) return -1;
            v = v * 10 + (int)(c6 - 0x19 + 3);
            bits -= 6;
        }
        acc &= (1u << bits) - 1;
    }
    if (i != n || bits >= 8 || acc != (1u << bits) - 1) return -1;
    return v;
}

/* The response status from the first bytes of HEADERS, without the dynamic table. In practice
 * the server sends ":status 200" as index 8, the single byte 0x88. Anything unknown gives -1,
 * NOT an error: a guessed status is worse than none, and the read shows whether data came. */
static void status_peek(struct h2 *h, const unsigned char *p, size_t n) {
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
    if (i >= n) { h->status = -1; return; }
    switch (p[i]) {
        case 0x88: h->status = 200; break;
        case 0x89: h->status = 204; break;
        case 0x8A: h->status = 206; break;
        case 0x8B: h->status = 304; break;
        case 0x8C: h->status = 400; break;
        case 0x8D: h->status = 404; break;
        case 0x8E: h->status = 500; break;
        default:
            /* A literal with the :status name (index 8): the value as three digits. */
            if ((p[i] & 0x0F) == 0x08 && i + 2 < n) {
                size_t len = p[i + 1] & 0x7F;
                if (!(p[i + 1] & 0x80) && len == 3 && i + 4 < n) {
                    h->status = (p[i + 2] - '0') * 100 + (p[i + 3] - '0') * 10 + (p[i + 4] - '0');
                    break;
                }
                /* The same value in Huffman code: three digits take 15 to 18 bits. */
                if ((p[i + 1] & 0x80) && len >= 2 && len <= 3 && i + 1 + len < n) {
                    int v = status_huff(p + i + 2, len);
                    if (v >= 100) { h->status = v; break; }
                }
            }
            h->status = -1;
    }
}

/* Stop parsing the record with rc. Data this call has already put in out is RETURNED and rc
 * postponed to the next call (pend_err): callers look at the code before got. */
#define H2_STOP(code) do { int e_ = (code); if (*got) { h->pend_err = e_; goto deliver; } return e_; } while (0)

static int h2_read_in(struct h2 *h, unsigned char *out, size_t cap, size_t *got) {
    *got = 0;
    if (!h->started) return H2_EPROTO;
    if (h->pend_err) {
        int e = h->pend_err;
        h->pend_err = 0;
        h->done = 1;                 /* the same end from now on */
        return e;
    }
    if (h->done) return H2_ERESET;
    /* The contract is checked BEFORE reading. A failure mid-frame (below) would drop the
     * record already read while the body counter stays, and the next frame would be read as a
     * continuation of the old one. Failing here touches neither the network nor the state. */
    if (cap < H2_MIN_READ_CAP) return H2_ETOOBIG;

    /* One buffer per thread, not per connection: 16 KB per connection would add up to
     * megabytes. */
    static __thread unsigned char rec[TLS13_MAX_PLAIN + sizeof(h->pend)];
    size_t avail = 0;
    if (h->pend_n) {
        memcpy(rec, h->pend, h->pend_n);
        avail = h->pend_n;
        h->pend_n = 0;
    }

    size_t r = 0;
    int rc = h->io.read(h->io.ctx, rec + avail, sizeof(rec) - avail, &r);
    if (rc) return rc;
    avail += r;

    size_t p = 0;
    while (p < avail) {
        if (h->frame_left) {
            if (h->pad_wait) {
                /* The pad length byte. Padding and priority must fit into the rest of the
                 * frame, or it is a protocol error (RFC 7540 §6.1), not a reason to read past
                 * the end. */
                h->pad_wait = 0;
                if ((uint32_t)rec[p] + h->skip_left > h->frame_left - 1) H2_STOP(H2_EPROTO);
                h->pad_left = rec[p];
                if (h->frame_type == FR_DATA) {
                    h->recv_credit_conn += 1;
                    if (h->frame_ours) h->recv_credit += 1;
                }
                p++;
                h->frame_left--;
            }
            if (h->skip_left) {
                /* HEADERS priority: five bytes we do not need. If not all arrived, the rest
                 * is skipped in the next record, and take below comes out zero. */
                size_t sk = h->skip_left < avail - p ? h->skip_left : avail - p;
                h->skip_left = (unsigned char)(h->skip_left - sk);
                p += sk;
                h->frame_left -= (uint32_t)sk;
            }
            size_t take = h->frame_left < avail - p ? h->frame_left : avail - p;
            /* The content is what precedes the padding; the padding is only skipped. When a
             * record boundary falls inside the padding, frame_left is already below pad_left:
             * no content is left, and the unsigned difference would wrap, putting the rest of
             * the padding into the body. */
            size_t body = h->frame_left > h->pad_left ? h->frame_left - h->pad_left : 0;
            size_t real = take < body ? take : body;
            if (h->frame_type == FR_DATA) {
                /* The CONNECTION window is always credited, even for a frame of the closed
                 * stream of an earlier chunk: the bytes came out of the shared window, and it
                 * is on us to return them. Padding counts too: the window pays for the whole
                 * frame (RFC 7540 §6.9.1). */
                h->recv_credit_conn += (int32_t)take;
                if (h->frame_ours) {
                    if (*got + real > cap) H2_STOP(H2_ETOOBIG);
                    memcpy(out + *got, rec + p, real);
                    *got += real;
                    h->recv_credit += (int32_t)take;
                }
            } else if (h->frame_type == FR_HEADERS) {
                if (h->frame_ours && h->status == 0 && real) status_peek(h, rec + p, real);
                else if (!h->frame_ours && !h->frame_peeked && real) {
                    /* An answer on an earlier stream (packet-up: the previous chunk). Only
                     * the start of the frame is looked at, as for our own: the status is the
                     * first field. status_peek writes h->status, which the current stream must
                     * not see. */
                    int keep = h->status;
                    h->status = 0;
                    status_peek(h, rec + p, real);
                    if (h->status > 0 && h->status != 200) h->old_status = h->status;
                    h->status = keep;
                }
                if (real) h->frame_peeked = 1;
            } else {
                /* A control frame: collect what fits of the body and drop the rest. Nothing
                 * that matters is lost except SETTINGS entries past the tenth; GOAWAY debug data
                 * and unknown frames are never looked at. */
                size_t room = sizeof(h->ctl) - h->ctl_n;
                size_t cp = take < room ? take : room;
                if (cp) memcpy(h->ctl + h->ctl_n, rec + p, cp);
                h->ctl_n = (unsigned char)(h->ctl_n + cp);
            }
            p += take;
            h->frame_left -= (uint32_t)take;
            if (h->frame_left == 0) {
                if (h->frame_type != FR_DATA && h->frame_type != FR_HEADERS) {
                    rc = ctl_handle(h);
                    if (rc) H2_STOP(rc);
                }
                if ((h->frame_flags & FLAG_END_STREAM) &&
                    (h->frame_type == FR_DATA || h->frame_type == FR_HEADERS)) {
                    open_end(h, h->frame_sid);
                    if (h->frame_ours) h->done = 1;
                }
                h->frame_type = 0xFF;
            }
            continue;
        }

        if (avail - p < 9) {
            /* The frame header is split by the record boundary; carry its bytes over. */
            h->pend_n = avail - p;
            memcpy(h->pend, rec + p, h->pend_n);
            break;
        }

        uint32_t len = ((uint32_t)rec[p] << 16) | ((uint32_t)rec[p + 1] << 8) | rec[p + 2];
        h->frame_type = rec[p + 3];
        h->frame_flags = rec[p + 4];
        uint32_t sid = get32(rec + p + 5) & 0x7FFFFFFF;
        /* "Ours" is only the CURRENT stream. packet-up leaves the closed streams of earlier
         * chunks behind, and the server may still send HEADERS and END_STREAM on them after
         * we opened the next. Such frames count toward the connection window (the body
         * parsing does that) and are dropped: their content is an empty 200 answer to an
         * upload. A non-200 status there goes to old_status. */
        h->frame_ours = (sid == h->sid);
        h->frame_sid = sid;
        h->frame_peeked = 0;
        h->frame_left = len;
        h->ctl_n = 0;
        p += 9;
        h->pad_left = 0;
        h->pad_wait = 0;
        h->skip_left = 0;
        if (h->frame_type == FR_DATA || h->frame_type == FR_HEADERS) {
            h->pad_wait = (h->frame_flags & FLAG_PADDED) != 0;
            if (h->frame_type == FR_HEADERS && (h->frame_flags & FLAG_PRIORITY))
                h->skip_left = 5;
            if (h->pad_wait + h->skip_left > len) H2_STOP(H2_EPROTO);
        }

        /* A frame without a body is handled at once: the loop above would wait for bytes
         * that never come. */
        if (len == 0) {
            if (h->frame_type != FR_DATA && h->frame_type != FR_HEADERS) {
                rc = ctl_handle(h);
                if (rc) H2_STOP(rc);
            }
            if ((h->frame_flags & FLAG_END_STREAM) &&
                (h->frame_type == FR_DATA || h->frame_type == FR_HEADERS)) {
                open_end(h, h->frame_sid);
                if (h->frame_ours) h->done = 1;
            }
            h->frame_type = 0xFF;
        }
    }

deliver:
    if (h->status > 0 && h->status != 200) { g_last_status = h->status; return H2_ESTATUS; }
    if (h->old_status) { g_last_status = h->old_status; return H2_ESTATUS; }
    if (h->pend_err) return 0;       /* the stream is over: no point growing its window */
    rc = window_refill(h);
    if (rc) return rc;
    /* Zero bytes is a legal result: the record may have held only a PING or SETTINGS. An
     * error here would drop a working connection over a control frame. The caller must tell
     * "nothing to give" from "end of stream", which is why the end comes as a code (H2_ERESET
     * from the next call), not as zero. */
    return 0;
}

int h2_read(struct h2 *h, unsigned char *out, size_t cap, size_t *got) {
    int rc = h2_read_in(h, out, cap, got);
    if (rc == H2_ERESET)
        snprintf(g_reset_why, sizeof(g_reset_why), "%s", h->why[0] ? h->why : "end of stream");
    return rc;
}

/* Sends the data WHOLE or not at all.
 *
 * "Or nothing" is the only option without a buffer. Vision sits above us, and half a frame
 * sent breaks the stream for good. So either we keep the unsent rest (16 KB for each of 64
 * connections), or we send nothing and tell the caller.
 *
 * The latter also suits TCP: a closed window means the server cannot keep up, and the right
 * reaction is NOT to acknowledge the packet to the client. The client retransmits it as after
 * a loss, and no memory is needed. That is why there is no waiting for the window and no
 * reading here: both would mean someone must put already-read data somewhere. */
int h2_write(struct h2 *h, const unsigned char *d, size_t n) {
    if (!h->started) return H2_EPROTO;
    /* The comparison is SIGNED. send_win and send_win_conn are int32_t and may legally go
     * negative: a SETTINGS with INITIAL_WINDOW_SIZE below 65535 subtracts the difference from
     * the window already granted (RFC 7540 §6.9.2). Cast to size_t, -60000 would become
     * 1.8·10^19, the check would never fire, the frame would overrun the window, and the
     * server would answer RST_STREAM with FLOW_CONTROL_ERROR. */
    if (n > INT32_MAX) return H2_ETOOBIG;
    if ((int32_t)n > h->send_win || (int32_t)n > h->send_win_conn) return H2_EWINDOW;

    while (n) {
        size_t chunk = n > DEFAULT_MAX_FRAME ? DEFAULT_MAX_FRAME : n;
        int rc = frame_out(h, FR_DATA, 0, h->sid, d, chunk);
        if (rc) return rc;
        h->send_win -= (int32_t)chunk;
        h->send_win_conn -= (int32_t)chunk;
        d += chunk;
        n -= chunk;
    }
    return 0;
}

long h2_room(const struct h2 *h) {
    if (!h->started) return 0;
    int32_t w = h->send_win < h->send_win_conn ? h->send_win : h->send_win_conn;
    return w > 0 ? w : 0;
}

const char *h2_strerror(int rc) {
    switch (rc) {
        case H2_EIO: return "HTTP/2 connection lost";
        case H2_EPROTO: return "unexpected HTTP/2 frame";
        /* The CODE is named, not hidden behind "not 200": 404, 403 and 502 mean "wrong path",
         * "not let in" and "nothing behind the server", three different problems to take to
         * the node's owner. */
        case H2_ESTATUS: {
            static __thread char st[64];
            if (g_last_status > 0) snprintf(st, sizeof st, "server answered %d instead of 200", g_last_status);
            else                   snprintf(st, sizeof st, "server answered with a status other than 200");
            return st;
        }
        case H2_ERESET: {
            static __thread char rs[112];
            if (g_reset_why[0]) snprintf(rs, sizeof rs, "stream closed by the server (%s)", g_reset_why);
            else                snprintf(rs, sizeof rs, "stream closed by the server (RST/GOAWAY)");
            return rs;
        }
        case H2_ETOOBIG: return "HTTP/2 frame too large";
        case H2_EWINDOW: return "HTTP/2 window closed";
        default: return "unknown HTTP/2 error";
    }
}
