/* A minimal HTTP/2 client, one stream at a time. Why it exists and its limits: h2.c. */
#ifndef STEER_H2_H
#define STEER_H2_H
#include <stdint.h>
#include <stddef.h>

#define H2_EIO      (-50)
#define H2_EPROTO   (-51)   /* a frame that cannot occur here */
#define H2_ESTATUS  (-52)   /* the server did not answer 200 */
#define H2_ERESET   (-53)   /* RST_STREAM, GOAWAY, end of stream, or a flow-control error */
#define H2_ETOOBIG  (-54)
#define H2_EWINDOW  (-55)   /* the send window is closed */

/* The I/O below us. Not direct tls13_* calls: the transport may run without TLS
 * (security=none), and HTTP/2 does not care. */
struct h2_io {
    void *ctx;
    int (*write)(void *ctx, const unsigned char *d, size_t n);
    int (*read)(void *ctx, unsigned char *d, size_t cap, size_t *got);
};

/* Kept SMALL on purpose: one per VLESS connection (two for xhttp with an upload link), and a
 * loop thread holds hundreds of connections. There is no frame buffer: records are read into a
 * per-thread buffer, and only what cannot be parsed at once carries over between calls: a split
 * frame header, a control frame body and the count of unread body. A 16 KB frame buffer per
 * connection would add up to megabytes. */
#define H2_OPEN_MAX 16

struct h2 {
    struct h2_io io;
    int started;
    int status;                 /* 200; 0 — not known yet; -1 — could not parse */
    int done;                   /* END_STREAM from the server */
    /* A server refusal on an EARLIER stream of this connection: a non-200 code from the HEADERS
     * of a stream that is no longer current. Only packet-up does this (the answer to a chunk
     * arrives when the next one is open); without this field the refusal would be lost with the
     * frame of a closed stream. h2_next does NOT reset it: the refused chunk is lost, and the
     * VLESS stream after it cannot be whole. 0 — no refusal seen. */
    int old_status;
    unsigned char frame_peeked; /* the status of this HEADERS frame has been looked at */

    /* A frame header cut off by the end of the previous record. */
    unsigned char pend[9];
    size_t pend_n;

    /* The current frame: body bytes left, type and flags. */
    uint32_t frame_left;
    unsigned char frame_type;
    unsigned char frame_flags;
    int frame_ours;             /* the frame belongs to the current stream */
    uint32_t frame_sid;         /* the frame's stream: 0 the connection, sid ours, other closed */
    /* An end (RST_STREAM, GOAWAY, a parse failure) found by h2_read after it had already
     * gathered data in the same call. The data is returned (code 0) and this code by the next
     * call: callers look at the code before got, and Xray sends a response's last data, the
     * closing HEADERS and RST_STREAM(NO_ERROR) in one TLS record. 0: none. */
    int pend_err;
    /* GOAWAY came (RFC 9113 §6.8): no new streams on this connection; the current one, if its
     * id is within last_stream_id and the code is NO_ERROR, is served to the end. */
    unsigned char goaway;
    char why[56];               /* how the server ended the stream: "RST_STREAM CANCEL" ... */
    /* Framing inside DATA and HEADERS bodies that is not data (RFC 7540 §6.1, §6.2):
     * pad_wait — the pad length byte is still ahead (PADDED); skip_left — HEADERS priority
     * bytes left to skip (PRIORITY); pad_left — padding length at the end of the frame. They
     * carry over between calls: a TLS record boundary can fall anywhere. */
    unsigned char pad_wait;
    unsigned char pad_left;
    unsigned char skip_left;

    /* The body of a control frame is collected here: WINDOW_UPDATE, SETTINGS, PING and RST
     * must be seen WHOLE to act on them, and TLS record and HTTP/2 frame boundaries do not line
     * up. They are all short: 64 bytes hold ten settings. */
    unsigned char ctl[64];
    unsigned char ctl_n;

    /* Flow control. Our receive window is refilled as we read; the SEND window belongs to the
     * server, and overrunning it earns a RST_STREAM.
     *
     * Bytes read since the last WINDOW_UPDATE. TWO counters, because there are two receive
     * windows: the stream's and the connection's (RFC 7540 §6.9.1).
     *
     * The stream counter gets only what came on the CURRENT stream, and h2_next zeroes it:
     * the old stream is closed, there is no point growing its window.
     *
     * The connection counter gets EVERYTHING, including frames of the closed streams of earlier
     * packet-up chunks: the bytes came out of the shared window whoever they were for, and it
     * is on us to return them. Otherwise the window announced to the server shrinks toward zero
     * and the server eventually goes silent. */
    int32_t recv_credit;
    int32_t recv_credit_conn;
    int32_t send_win;           /* the stream window the server gave */
    int32_t send_win_conn;      /* the connection window */
    /* The previous SETTINGS_INITIAL_WINDOW_SIZE. RFC 7540 §6.9.2 shifts the window by the
     * difference from the PREVIOUS value, not from 65535; otherwise a server sending the same
     * SETTINGS twice would shift it twice. Starts at 65535, set by h2_start_ex. */
    int32_t peer_init_win;

    /* The CURRENT stream id. packet-up uploads as a series of short requests, and an HTTP/2
     * stream id cannot be reused: it grows by two (RFC 7540 §5.1.1).
     *
     * Only ONE stream is open at a time. There is no multiplexer: requests go one after
     * another, each closed before the next opens, so windows need no scheduling between
     * streams. Late frames of a closed stream are recognized by id and dropped (their DATA
     * still counts toward the connection window, a non-200 status still goes to old_status);
     * see the frame header parsing in h2_read. */
    uint32_t sid;
    /* Streams we opened whose response has not ended (END_STREAM or RST_STREAM from the server),
     * by id, up to H2_OPEN_MAX. packet-up leaves each chunk's request open until its 200 comes,
     * and the number of those is what it must bound (see packet-up in trxhttp.c). */
    uint32_t open_sid[H2_OPEN_MAX];
    unsigned char open_n;

    /* Who we claim to be in the headers: 0 — gRPC (te: trailers and its User-Agent), 1 — a
     * browser (Chrome for xhttp, see put_headers in h2.c). Kept in the STATE, not passed as an
     * argument: packet-up sends a series of requests, and a flag passed to each is a flag
     * someone forgets once. Set once when the connection opens. */
    int browser;
};

/* Chrome's look in request headers: xhttp (put_headers in h2.c, which says where the set comes
 * from) and the Upgrade request of ws and httpupgrade (proto/transport/trupgrade.c). One place
 * for both, so the browser version cannot differ between transports.
 *
 * THE NUMBER IS FIXED, NOT DERIVED FROM THE CLOCK. Xray derives the version from the date
 * (common/utils/browser.go: 144 on 2026-01-13, plus one per 35 days, minus a lag of 35 to 140
 * days seeded from the CPU), but a router with a wrong clock (common without an RTC battery)
 * would then claim a Chrome from the future or from years ago, which stands out more than a
 * slightly old version. Update it with the rest of the fingerprint when the ClientHello is
 * updated. */
#define UA_CHROME_MAJOR "149"
#define UA_CHROME \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " \
    "Chrome/" UA_CHROME_MAJOR ".0.0.0 Safari/537.36"
#define UA_CH_CHROME \
    "\"Google Chrome\";v=\"" UA_CHROME_MAJOR "\", \"Chromium\";v=\"" UA_CHROME_MAJOR \
    "\", \"Not)A;Brand\";v=\"24\""

/* The room a h2_read caller must give. A TLS record carries up to 16384 bytes, all of which
 * may be DATA body, plus a carried-over header fragment. A smaller buffer would mean
 * H2_ETOOBIG on a perfectly legal frame. */
#define H2_MIN_READ_CAP (16384 + 16)

/* Request method. GET is only for the xhttp download stream (stream-down): it has no body, and
 * the server tells download from upload by the method (hub.go in Xray). */
#define H2_POST 0
#define H2_GET  1

/* Opens a stream with the gRPC headers (browser = 0): preface, SETTINGS, WINDOW_UPDATE,
 * HEADERS. content_type and referer may be NULL; gRPC sends no referer. */
int h2_start(struct h2 *h, const struct h2_io *io, const char *authority,
             const char *path, const char *content_type, const char *referer);

/* The same with a method, the option to close our half of the stream at once, and the header
 * set (browser, see struct h2). GET needs end_stream: it has no body, and the server waits for
 * END_STREAM right on HEADERS. referer is for xhttp, where it carries the padding. */
int h2_start_ex(struct h2 *h, const struct h2_io *io, const char *authority,
                const char *path, const char *content_type, const char *referer,
                int method, int end_stream, int browser);

/* The NEXT request on the same connection: a new stream id and fresh stream state; settings
 * and the connection window are not sent again. For packet-up, where each upload chunk is a
 * separate POST. The previous stream must already be closed on our side (h2_end_stream), or
 * the server sees two open streams. */
int h2_next(struct h2 *h, const char *authority, const char *path,
            const char *content_type, const char *referer, int method);

/* Closes our half of the current stream: an empty DATA with END_STREAM. */
int h2_end_stream(struct h2 *h);

/* Sends the data in DATA frames, all or nothing (H2_EWINDOW); see h2.c. */
int h2_write(struct h2 *h, const unsigned char *d, size_t n);
/* Streams opened whose response has not ended yet (see open_sid). */
int h2_open_streams(const struct h2 *h);
/* The oldest of them (the lowest id), 0 if none. */
uint32_t h2_oldest_open(const struct h2 *h);
/* The largest n h2_write takes now: the smaller of the stream and connection windows, 0 if
 * either is closed (or negative, RFC 7540 §6.9.2). */
long h2_room(const struct h2 *h);

/* Reads the response body. cap must be at least H2_MIN_READ_CAP, so that one call returns
 * everything a record brought. 0 with *got == 0 is legal: the record held only control
 * frames. */
int h2_read(struct h2 *h, unsigned char *out, size_t cap, size_t *got);

const char *h2_strerror(int rc);

#endif
