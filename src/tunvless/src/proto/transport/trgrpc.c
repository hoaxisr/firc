/* The grpc transport: the protocol stream in gRPC messages inside one HTTP/2 stream (the top
 * layer in transport.h).
 *
 * grpc is close to xhttp's stream-one mode: both open one HTTP/2 stream with a POST and carry the
 * bytes in its body. grpc has its own path (grpc_path) and wraps the data in gRPC messages;
 * xhttp sends the data bare, with padding in Referer (trxhttp.c).
 *
 * gRPC message format (gRPC over HTTP/2 spec plus Xray's schema from stream.proto):
 *
 *   compressed flag  1 byte  (0 — not compressed; compression is never offered or accepted)
 *   length           4 bytes big-endian
 *   body             protobuf message Hunk { bytes data = 1 }: 0x0A, length, bytes
 *
 * MultiHunk (mode=multi) differs only in that field 1 may repeat. On send a single field is a
 * valid MultiHunk, so it is the same as Hunk; on receive repeats are handled because fields are
 * read to the end of the message.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "transport.h"

/* The gRPC request path.
 *
 * Usual form: serviceName without a leading slash, the path is /<service>/Tun. Xray's newer form:
 * serviceName starts with a slash and ALREADY holds the full method name, so it is the path
 * itself. Mixing them up calls a method that does not exist, the server answers 404, and the node
 * looks broken. */
static void grpc_path(const struct tr_node *n, char *out, size_t cap) {
    int multi = !strcmp(n->mode, "multi");
    if (n->service[0] == '/') {
        /* "/a/b/MyTun" or "/a/b/MyTun|MyTunMulti": take the half the mode needs. */
        const char *bar = strchr(n->service, '|');
        size_t len = bar ? (size_t)(bar - n->service) : strlen(n->service);
        if (multi && bar) {
            const char *slash = strrchr(n->service, '/');
            size_t head = slash ? (size_t)(slash - n->service) : 0;
            snprintf(out, cap, "%.*s/%s", (int)head, n->service, bar + 1);
            return;
        }
        snprintf(out, cap, "%.*s", (int)len, n->service);
        return;
    }
    snprintf(out, cap, "/%s/%s", n->service, multi ? "TunMulti" : "Tun");
}

static size_t grpc_wrap(const unsigned char *d, size_t n, unsigned char *out, size_t cap) {
    unsigned char pb[8];
    size_t pb_n = 0;
    pb[pb_n++] = 0x0A;                    /* field 1, wire type 2 (bytes) */
    size_t v = n;
    while (v >= 128) { pb[pb_n++] = (unsigned char)((v & 0x7F) | 0x80); v >>= 7; }
    pb[pb_n++] = (unsigned char)v;

    size_t msg = pb_n + n;
    if (5 + msg > cap) return 0;
    out[0] = 0;                            /* not compressed */
    out[1] = (unsigned char)(msg >> 24); out[2] = (unsigned char)(msg >> 16);
    out[3] = (unsigned char)(msg >> 8);    out[4] = (unsigned char)msg;
    memcpy(out + 5, pb, pb_n);
    memcpy(out + 5 + pb_n, d, n);
    return 5 + msg;
}

/* Unwraps the data from a stream of gRPC messages, in chunks of any size: the state lives in
 * struct grpc_de, because message and record boundaries do not coincide. */
static int grpc_unwrap(struct grpc_de *de, const unsigned char *in, size_t n,
                       unsigned char *out, size_t cap, size_t *out_n) {
    *out_n = 0;
    size_t i = 0;
    while (i < n) {
        if (de->msg_left == 0) {
            /* Message header: compressed flag and length. */
            while (de->hdr_n < 5 && i < n) de->hdr[de->hdr_n++] = in[i++];
            if (de->hdr_n < 5) break;
            if (de->hdr[0] != 0) return TR_EGRPC;   /* compression was not offered */
            de->msg_left = ((uint32_t)de->hdr[1] << 24) | ((uint32_t)de->hdr[2] << 16) |
                           ((uint32_t)de->hdr[3] << 8) | de->hdr[4];
            de->hdr_n = 0;
            de->pb_n = 0;
            de->field_left = 0;
            /* An empty message is legal: the server uses it to check the stream is alive. */
            continue;
        }
        if (de->field_left == 0) {
            /* Tag and length of the protobuf field. Collected byte by byte: the tag and the
             * varint can be split across records like everything else. */
            int complete = 0;
            while (i < n && de->msg_left > 0) {
                unsigned char b = in[i++];
                de->msg_left--;
                /* The tag and at most 5 varint bytes: a 32-bit length needs no more, and a 6th
                 * would be shifted past 32 bits below. */
                if (de->pb_n >= 1 + 5) return TR_EGRPC;
                if (de->pb_n == 0 && b != 0x0A) return TR_EGRPC;  /* only field 1 is expected */
                de->pb[de->pb_n++] = b;
                if (de->pb_n > 1 && !(b & 0x80)) { complete = 1; break; }
            }
            if (!complete) break;                  /* the rest comes next time */
            uint32_t v = 0;
            unsigned shift = 0;
            for (unsigned k = 1; k < de->pb_n; k++) {
                v |= (uint32_t)(de->pb[k] & 0x7F) << shift;
                shift += 7;
            }
            de->field_left = v;
            de->pb_n = 0;
            /* An empty field is legal, there is just nothing to return. */
            if (de->field_left == 0) continue;
        }
        size_t take = de->field_left;
        if (take > n - i) take = n - i;
        if (take > de->msg_left) take = de->msg_left;
        if (*out_n + take > cap) return H2_ETOOBIG;
        memcpy(out + *out_n, in + i, take);
        *out_n += take;
        i += take;
        de->field_left -= (uint32_t)take;
        de->msg_left -= (uint32_t)take;
    }
    return 0;
}

static int grpc_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    (void)timeout_s;
    struct h2_io io = { .ctx = &t->link, .write = tr_link_write, .read = tr_link_read };
    /* :authority carries the cover domain, as SNI does: the server hides behind it, and a
     * request for another name would give the client away at once. */
    const char *authority = n->sni[0] ? n->sni : n->host;
    char path[320];
    grpc_path(n, path, sizeof(path));
    memset(&t->de, 0, sizeof(t->de));
    return h2_start(&t->h2, &io, authority, path, "application/grpc", NULL);
}

static int grpc_write(struct transport *t, const unsigned char *d, size_t n) {
    static __thread unsigned char msg[H2_MIN_READ_CAP + 16];
    size_t mn = grpc_wrap(d, n, msg, sizeof(msg));
    if (!mn) return H2_ETOOBIG;
    return h2_write(&t->h2, msg, mn);
}

static int grpc_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    /* One buffer per THREAD, not per connection: 16 KB per connection adds up on a router, and
     * there are only a few threads. A buffer shared between threads would mix chunks of different
     * connections. */
    static __thread unsigned char raw[H2_MIN_READ_CAP];
    size_t rn = 0;
    int rc = h2_read(&t->h2, raw, sizeof(raw), &rn);
    if (rc) return rc;
    if (!rn) return 0;
    return grpc_unwrap(&t->de, raw, rn, d, cap, got);
}

/* h2 keeps a pointer to the connection's link (io.ctx); once the struct moves it would point to
 * the old location. */
static void grpc_moved(struct transport *t) { t->h2.io.ctx = &t->link; }

/* The end of the stream is known (END_STREAM came with the last data, or an end waits for the
 * next h2_read: pend_err) but only the next read can report it. The socket stays silent once
 * the server has sent everything, so without this the client got no FIN until idle cleanup. */
static int grpc_pending(const struct transport *t) { return t->h2.done || t->h2.pend_err; }

/* A gRPC message adds 5 bytes of header and up to 4 of protobuf tag and length to each write. */
static long grpc_room(struct transport *t) {
    long r = h2_room(&t->h2) - 9;
    return r > 0 ? r : 0;
}

const struct transport_ops tr_grpc = {
    .name = "grpc", .alpn = "h2", .zc = 0,
    .open = grpc_open, .write = grpc_write, .read = grpc_read,
    .moved = grpc_moved, .close = NULL, .pending = grpc_pending, .room = grpc_room,
};
