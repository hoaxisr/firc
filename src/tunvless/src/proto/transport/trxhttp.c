/* The xhttp transport: the protocol stream in HTTP/2 request bodies, over one request or two
 * links.
 *
 * In stream-one mode xhttp wraps nothing: the request body is the stream up, the response body
 * the stream down. But it needs padding: the server checks the x_padding length in Referer and
 * answers 400 without it (see Xray hub.go). The stream-up and packet-up modes are described at
 * enum xhttp_mode in transport.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include "osrand.h"

#include "transport.h"

/* The xhttp path, with a leading and a trailing slash.
 *
 * The trailing slash matters: the server takes the rest of the path after its own as the session
 * id and recognizes stream-one by an EMPTY rest. Without the trailing slash the rest is not
 * empty, the server switches to packet-up and answers 400, which looks like a dead node. */
static void xhttp_path(const struct tr_node *n, char *out, size_t cap) {
    const char *p = n->path[0] ? n->path : "/";
    size_t len = strlen(p);
    snprintf(out, cap, "%s%s%s", p[0] == '/' ? "" : "/", p,
             len && p[len - 1] == '/' ? "" : "/");
}

/* The node's xhttp mode. Empty and "auto" resolve as in Xray's client (splithttp/dialer.go):
 * stream-one with reality, packet-up otherwise (tls, none). A server may accept only the mode it
 * was set to, and a packet-up server answers 400 to stream-one, so auto must pick what Xray's
 * client would. Other modes are named in the link, and the node parser has dropped what we do
 * not support (sl_link_usable_post in sublink.c), so only these three arrive here. */
static enum xhttp_mode xhttp_mode_of(const struct tr_node *n) {
    if (!strcmp(n->mode, "packet-up")) return XH_PACKET_UP;
    if (!strcmp(n->mode, "stream-up")) return XH_STREAM_UP;
    if (!strcmp(n->mode, "stream-one")) return XH_STREAM_ONE;
    return n->security && !strcmp(n->security, "reality") ? XH_STREAM_ONE : XH_PACKET_UP;
}

/* The session id. The server ties the upload requests to the download request by it, so it must
 * be unpredictable: whoever guesses it could inject bytes into someone else's session. Its form
 * is Xray's default, a UUID string, which also appears in ordinary application paths and does
 * not stand out. */
static void session_id(char *out, size_t cap) {
    unsigned char r[16];
    if (os_getrandom(r, sizeof r, 0) != (ssize_t)sizeof r) {
        /* The random source failed. Zero random bytes would be WORSE than failing: the session
         * would be predictable while looking valid. Use the nil UUID, which no real session
         * has: the server accepts it, but such a node does not come up, and that gets noticed. */
        snprintf(out, cap, "00000000-0000-0000-0000-000000000000");
        return;
    }
    r[6] = (unsigned char)((r[6] & 0x0F) | 0x40);   /* version 4 */
    r[8] = (unsigned char)((r[8] & 0x3F) | 0x80);   /* variant   */
    snprintf(out, cap,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
             r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
}

/* Referer with padding for one request.
 *
 * Each request gets its own length, not one per connection: packet-up sends a series of
 * requests, and the same padding length in all of them would turn the padding itself into a
 * signature, the very thing it is there against. */
static int xhttp_referer(char *out, size_t cap, const char *authority, const char *path,
                         uint16_t pf, uint16_t pt) {
    /* THE SERVER SETS THE RANGE, NOT US. It comes in the link as `xPaddingBytes` (see
     * sl_pad_range in sublink.c), and the server CHECKS it: outside the range means 400. A
     * fixed range that fits Xray's default fails every xhttp node of a provider that announces,
     * say, "50-150": TLS passes, Reality accepts, then 400, and the nodes look dead.
     *
     * Not announced: Xray's default 100..1000 (GetNormalizedXPaddingBytes), to match upstream in
     * both the bounds and the middle. */
    size_t lo = pt ? pf : 100;
    size_t hi = pt ? pt : 1000;
    unsigned char r = 0;
    if (os_getrandom(&r, 1, 0) != 1) r = 128;
    size_t pad = lo + (size_t)r * (hi - lo + 1) / 256;
    if (pad < lo) pad = lo;
    if (pad > hi) pad = hi;
    int k = snprintf(out, cap, "https://%s%s?x_padding=", authority, path);
    if (k < 0 || (size_t)k + pad + 1 > cap) return H2_ETOOBIG;
    memset(out + k, 'X', pad);
    out[k + pad] = '\0';
    return 0;
}

/* ---- the second link, for the upload -------------------------------------------------- */

static int up_write(void *ctx, const unsigned char *d, size_t n) {
    struct xh_up *u = ctx;
    return tr_link_write(&u->link, d, n);
}

static int up_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    struct xh_up *u = ctx;
    /* No direct copy here: Vision lives on the DOWNLOAD stream, and this link only writes. The
     * server's answers to the upload are empty 200s, read only to process the HTTP/2 control
     * frames and keep the window from filling.
     *
     * NO WAITING HERE. The answers are drained along with sending, and a blocking read would
     * stop the upload until an answer arrives, turning the stream into "send and wait". Over
     * TLS there is no waiting: tls13_read polls the socket with a zero timeout and returns zero
     * bytes when no record is there. A bare socket (security=none) does not behave like that,
     * and we poll ourselves; hence this link has its own read, not tr_link_read of the main
     * one. */
    if (u->link.plain) {
        struct pollfd p = { .fd = u->link.fd, .events = POLLIN };
        if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN)) { *got = 0; return 0; }
        ssize_t r = read(u->link.fd, d, cap);
        if (r == 0) return TR_ECLOSED;
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) { *got = 0; return 0; }
            return TR_EIO;
        }
        *got = (size_t)r;
        return 0;
    }
    return tls13_read(&u->link.tls, d, cap, got);
}

/* Drain what the server answered to the upload.
 *
 * WHY. For each packet-up chunk the server answers an empty 200: headers, an empty DATA,
 * END_STREAM, tens of bytes. Not reading them piles them up in the socket receive buffer; once
 * it is full the server stops writing, and its side of the parsing stalls too: the upload
 * hangs, the later the bigger the buffer, so "sometimes, on big files". The same call also
 * takes the HTTP/2 control frames (SETTINGS, WINDOW_UPDATE, PING); without them the connection
 * window would never be replenished.
 *
 * It does not wait and returns no data: what it reads is dropped. It does return a FAILURE: the
 * xhttp server answers non-200 to a chunk it refused (for example 400 to a padding of the wrong
 * length), and that chunk is lost, so the stream after it cannot be whole. Without this the
 * node looks alive while no traffic flows. Other h2_read codes are not failures here: H2_ERESET
 * in packet-up is the normal end of a chunk's answer, and a broken link is reported by the next
 * write. */
static int up_drain(struct xh_up *u) {
    if (!u->started) return 0;
    static __thread unsigned char sink[H2_MIN_READ_CAP];
    /* Until the link is empty, bounded so one call cannot spin. NOT until a read returns no
     * data: on this link no read ever does (the answers are bodiless 200s), and stopping there
     * took one record per call, with a chunk's answer behind WINDOW_UPDATEs and SETTINGS. */
    for (int i = 0; i < 64; i++) {
        /* packet-up: the CURRENT chunk answered (done) says nothing of the older ones, whose
         * answers may still be on the way: the server answers in any order. h2_read would refuse
         * to read once done was set, and the oldest chunk's answer was never read: its window
         * stayed full and the upload stalled for good (no new chunk, so no h2_next to clear it). */
        if (u->h2.done && !u->h2.pend_err && h2_open_streams(&u->h2) > 0) u->h2.done = 0;
        int more = !u->link.plain && tls13_has_record(&u->link.tls);
        if (!more) {
            struct pollfd p = { .fd = u->link.fd, .events = POLLIN };
            more = poll(&p, 1, 0) > 0 && (p.revents & POLLIN);
        }
        if (!more) return 0;
        size_t got = 0;
        int rc = h2_read(&u->h2, sink, sizeof(sink), &got);
        if (rc == H2_ESTATUS) return rc;
        if (rc) return 0;
    }
    return 0;
}

/* Open the second link the same way as the main one: TCP, then nothing (security=none), Reality,
 * or TLS with verification. ALPN is always h2. */
static int up_connect(struct transport *t, const struct tr_node *n, int timeout_s) {
    struct xh_up *u = &t->xh.up;
    memset(u, 0, sizeof(*u));
    int rc = tr_link_open(&u->link, n, "h2", timeout_s);
    if (rc) return rc;
    if (!u->link.plain && u->link.tls.alpn[0] && strcmp(u->link.tls.alpn, "h2") != 0) {
        tls13_free(&u->link.tls); close(u->link.fd); u->link.fd = -1;
        return TR_ENOH2;
    }
    return 0;
}

/* Open the next upload request. seq < 0: the long-lived stream-up request (no number); otherwise
 * the packet-up chunk number. */
static int up_request(struct transport *t, long long seq) {
    struct xh_state *x = &t->xh;
    struct xh_up *u = &x->up;
    struct h2_io io = { .ctx = u, .write = up_write, .read = up_read };
    char path[320];
    if (seq < 0) snprintf(path, sizeof(path), "%s", x->up_path);
    else         snprintf(path, sizeof(path), "%s/%lld", x->up_path, seq);

    static __thread char ref[1400];
    if (xhttp_referer(ref, sizeof(ref), x->authority, path, x->pad_from, x->pad_to))
        return H2_ETOOBIG;

    /* Content-Type: application/grpc on the stream-up request only. Xray sets it on stream
     * requests (stream-up, stream-one), never on packet-up chunks; the server does not check it,
     * but a chunk that carries it does not look like Xray's. */
    const char *ctype = seq < 0 ? "application/grpc" : NULL;
    if (!u->started) {
        int rc = h2_start_ex(&u->h2, &io, x->authority, path, ctype, ref, H2_POST, 0, 1);
        if (rc) return rc;
        u->started = 1;
        return 0;
    }
    return h2_next(&u->h2, x->authority, path, ctype, ref, H2_POST);
}

/* Start the upload if this mode needs one. stream-one needs nothing: there the upload is the
 * body of the same single request. */
static int up_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    if (t->xh.mode == XH_STREAM_ONE) return 0;

    int rc = up_connect(t, n, timeout_s);
    if (rc) return rc;

    /* stream-up opens its POST at once and keeps it open for the life of the connection: the
     * body of that request is the upstream channel.
     *
     * packet-up opens NOTHING in advance. A request there lives for exactly one chunk; opening
     * it before the chunk exists would hold an empty upload on the server, with number 0, which
     * would then have to be skipped. The first request opens on the first send. */
    if (t->xh.mode == XH_STREAM_UP) return up_request(t, -1);
    t->xh.seq = 0;
    return 0;
}

/* ---- the transport -------------------------------------------------------------------- */

static int xhttp_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    struct xh_state *x = &t->xh;
    struct h2_io io = { .ctx = &t->link, .write = tr_link_write, .read = tr_link_read };
    /* :authority as Xray's client builds the URL: the node's host setting, else the SNI (the
     * camouflage domain the server hides behind), else the address. A server with host set
     * compares it with :authority and answers 404 to anything else (hub.go). */
    const char *authority = n->http_host && n->http_host[0] ? n->http_host
                          : n->sni[0] ? n->sni : n->host;
    char path[320];

    x->mode = xhttp_mode_of(n);
    xhttp_path(n, path, sizeof(path));
    snprintf(x->authority, sizeof(x->authority), "%s", authority);
    x->pad_from = n->pad_from;
    x->pad_to = n->pad_to;
    /* One value per connection from the node's range, as Xray's client picks it (dialer.go). */
    x->post_max = 0;
    if (n->post_to) {
        uint32_t r = 0;
        if (os_getrandom(&r, sizeof r, 0) != (ssize_t)sizeof r) r = 0;
        x->post_max = n->post_from + r % (n->post_to - n->post_from + 1);
    }

    /* __thread, not plain static: several threads would overwrite one shared array. A copy per
     * thread is 1.4 KB. */
    static __thread char ref[1400];

    if (x->mode == XH_STREAM_ONE) {
        if (xhttp_referer(ref, sizeof(ref), authority, path, n->pad_from, n->pad_to))
            return H2_ETOOBIG;
        /* Content-Type: application/grpc here too, as Xray does (FillStreamRequest sets it on
         * every request WITH A BODY), and proxies do not try to buffer the stream because of
         * it. Everything else in the headers is the look of a BROWSER, not gRPC: see
         * put_headers in h2.c. */
        return h2_start_ex(&t->h2, &io, authority, path, "application/grpc", ref,
                           H2_POST, 0, 1);
    }

    /* The other two modes start the same way: the session gets a name, by which the server then
     * ties the upload requests to it. The name is appended to the path: Xray's default (session
     * placement = path), and hub.go reads it there. */
    char sid[40];
    session_id(sid, sizeof(sid));
    if (snprintf(x->up_path, sizeof(x->up_path), "%s%s", path, sid) >= (int)sizeof(x->up_path))
        return H2_ETOOBIG;

    /* THIS link is for the download, and its request is a GET without a body. The method
     * matters: the server tells the upload from the download by it (hub.go: a GET without a
     * chunk number is stream-down). The server would take a bodiless POST for an upload, wait
     * for bytes that never come, and send nothing down. */
    if (xhttp_referer(ref, sizeof(ref), authority, x->up_path, n->pad_from, n->pad_to))
        return H2_ETOOBIG;
    int rc = h2_start_ex(&t->h2, &io, authority, x->up_path, NULL, ref, H2_GET, 1, 1);
    if (rc) return rc;
    return up_open(t, n, timeout_s);
}

/* packet-up: what all chunks of a write may carry together (the connection window). */
static long packet_conn_room(const struct xh_up *u) {
    if (!u->started) return 65535;
    return u->h2.send_win_conn > 0 ? u->h2.send_win_conn : 0;
}

/* packet-up: how far ahead of the oldest unanswered chunk a new one may go, in chunks. The
 * server takes each POST in a goroutine of its own and puts the chunks back in order by seq,
 * holding at most scMaxBufferedPosts (default 30) past a missing one; beyond that it tears the
 * connection down without an HTTP error ("packet queue is too large", upload_queue.go), and the
 * flow simply ends. Sent back to back, our chunks got there under load: one slow goroutine is a
 * gap, and everything sent meanwhile piles up behind it. Bounding the number of unanswered
 * chunks is not enough: later ones get answered and free their slots while the gap stays. So the
 * bound is a window over seq, as in TCP: no chunk more than PACKET_INFLIGHT past the oldest
 * unanswered one. Eight keeps well under the server's default, and under a lowered one too. */
#define PACKET_INFLIGHT 8
#define PACKET_SLOT 8192

/* packet-up: what the next chunk's request can carry. Before the first request the windows are
 * the default 65535. */
/* Chunks that may still be sent before the window over seq is full (see PACKET_INFLIGHT). The
 * stream ids go up by two per chunk. */
static long packet_slots(const struct xh_up *u) {
    if (!u->started) return PACKET_INFLIGHT;
    uint32_t oldest = h2_oldest_open(&u->h2);
    if (!oldest) return PACKET_INFLIGHT;
    long ahead = (long)(u->h2.sid - oldest) / 2 + 1;   /* chunks from the oldest to the last */
    return ahead >= PACKET_INFLIGHT ? 0 : PACKET_INFLIGHT - ahead;
}

static long packet_room(const struct xh_up *u) {
    if (!u->started) return 65535;
    if (packet_slots(u) <= 0) return 0;
    const struct h2 *h = &u->h2;
    int32_t r = h->send_win_conn < h->peer_init_win ? h->send_win_conn : h->peer_init_win;
    return r > 0 ? r : 0;
}

static int xhttp_write(struct transport *t, const unsigned char *d, size_t n) {
    struct xh_state *x = &t->xh;
    switch (x->mode) {
        case XH_STREAM_ONE:
            return h2_write(&t->h2, d, n);
        case XH_STREAM_UP: {
            /* One long POST for the whole connection: write into it and drain whatever the
             * server has answered meanwhile. A closed window may only mean an unread
             * WINDOW_UPDATE: drain and try once more before refusing. */
            int rc = h2_write(&x->up.h2, d, n);
            if (rc == H2_EWINDOW && up_drain(&x->up) == 0) rc = h2_write(&x->up.h2, d, n);
            int dr = up_drain(&x->up);
            return rc ? rc : dr;
        }
        case XH_PACKET_UP: {
            /* A chunk is a request of its own: open, write, close our half.
             *
             * NO BATCHING. Xray gathers small writes into chunks of up to a megabyte and says
             * outright that without it the bandwidth is "extremely limited". We have nothing
             * to batch with: a batcher needs a flush deadline, i.e. a timer or a thread per
             * connection, while the tunnel calls send itself and knows nothing of time. So one
             * request per call: the honest price of a mode chosen when the others do not pass
             * at all. */
            /* A chunk the windows cannot take now must not open its request: h2_write would
             * refuse it after the HEADERS went out, leaving a stream without END_STREAM, and the
             * retry would open another one for the same seq. Before the first request the
             * windows are the default 65535. */
            /* The server refuses a POST body over its scMaxEachPostBytes with 413: a write larger
             * than post_max goes as several chunks. All or nothing still holds (h2_write's
             * contract, which Vision above relies on): the windows are checked for the whole
             * write before the first chunk opens, the connection window for the sum and each new
             * stream's window for one chunk. */
            size_t piece = x->post_max && x->post_max < n ? x->post_max : n;
            /* The chunks this write needs must fit among the unanswered ones; a write that needs
             * more than PACKET_INFLIGHT alone (a tiny scMaxEachPostBytes) waits for none. */
            int pieces = (int)((n + piece - 1) / piece);
#define PACKET_FITS() ((long)piece <= packet_room(&x->up) && (long)n <= packet_conn_room(&x->up) && \
                       (packet_slots(&x->up) >= pieces || \
                        (pieces > PACKET_INFLIGHT && !h2_open_streams(&x->up.h2))))
            if (!PACKET_FITS()) up_drain(&x->up);
            if (!PACKET_FITS()) return H2_EWINDOW;
#undef PACKET_FITS
            int rc = 0;
            for (size_t off = 0; off < n && !rc; off += piece) {
                size_t m = n - off < piece ? n - off : piece;
                rc = up_request(t, (long long)x->seq);
                if (!rc) rc = h2_write(&x->up.h2, d + off, m);
                if (!rc) rc = h2_end_stream(&x->up.h2);
                if (!rc) x->seq++;
            }
            int dr = up_drain(&x->up);
            return rc ? rc : dr;
        }
    }
    return h2_write(&t->h2, d, n);
}

static int xhttp_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    return h2_read(&t->h2, d, cap, got);
}

/* TWO self-pointers: the download's (h2.io.ctx, the main link) and the upload's (up.h2.io.ctx,
 * the second link; for stream-up it is set before the move, during open). Fixing only the first
 * sends the upload of a connection taken from the spare pool through the second link of another
 * spare session, set up in the same slot right after. */
/* The download's end is known but only the next read can report it (see grpc_pending). Only
 * the download stream counts: the answers to upload chunks (up.h2) end with every chunk. */
static int xhttp_pending(const struct transport *t) { return t->h2.done || t->h2.pend_err; }

static void xhttp_moved(struct transport *t) {
    t->h2.io.ctx = &t->link;
    t->xh.up.h2.io.ctx = &t->xh.up;
}

/* The second link exists only in stream-up and packet-up. Otherwise (stream-one, or an open that
 * failed before up_connect) its fd is still 0 from transport_open's memset, hence "> 0", not
 * "!= -1". */
static void xhttp_close(struct transport *t) {
    struct xh_up *u = &t->xh.up;
    if (u->link.fd > 0) close(u->link.fd);
    u->link.fd = -1;
    if (!u->link.plain) tls13_free(&u->link.tls);
    u->link.tls.ready = 0;
    u->started = 0;
}

/* What xhttp_write takes now, mode by mode: the same windows it checks.
 *
 * stream-up and packet-up upload over their own link, which the tunnel loop does not watch: it
 * reads only the download link. The server's WINDOW_UPDATEs for the upload were read only by
 * up_drain after a write, and once the client's window was sized by the room (dialer_ops.room),
 * a closed room meant no writes, so no reads, so the room stayed closed: stream-up uploads fell
 * from 3 GB to 14 MB in 20 s. So a low room drains the upload link before it is reported. */
#define UP_ROOM_LOW 65536
static long xhttp_room(struct transport *t) {
    struct xh_state *x = &t->xh;
    switch (x->mode) {
        case XH_STREAM_ONE: return h2_room(&t->h2);
        case XH_STREAM_UP:
            if (h2_room(&x->up.h2) < UP_ROOM_LOW) up_drain(&x->up);
            return h2_room(&x->up.h2);
        case XH_PACKET_UP: {
            /* In BYTES the free chunk slots can carry, not the HTTP/2 window: the window may
             * be megabytes while only PACKET_INFLIGHT chunks can be unanswered. Granted the
             * window, the client sent far more than the slots took, and every refused segment
             * waited out a retransmission timeout (11 MB uploaded in 20 s). A slot is counted
             * at PACKET_SLOT bytes, below what the stack gathers into one send (up to 16 KB),
             * so a granted window fills whole chunks; post_max when the node's is smaller. */
            if (packet_room(&x->up) < UP_ROOM_LOW || packet_slots(&x->up) <= PACKET_INFLIGHT / 2)
                up_drain(&x->up);
            long r = packet_room(&x->up);
            long slots = packet_slots(&x->up);
            long per = x->post_max && x->post_max < PACKET_SLOT ? (long)x->post_max : PACKET_SLOT;
            if (slots < 0) slots = 0;
            if (r > slots * per) r = slots * per;
            if (r > packet_conn_room(&x->up)) r = packet_conn_room(&x->up);
            return r;
        }
    }
    return h2_room(&t->h2);
}

const struct transport_ops tr_xhttp = {
    .name = "xhttp", .alpn = "h2", .zc = 0,
    .open = xhttp_open, .write = xhttp_write, .read = xhttp_read,
    .moved = xhttp_moved, .close = xhttp_close, .pending = xhttp_pending, .room = xhttp_room,
};
