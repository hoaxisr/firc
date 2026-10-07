/* XTLS-Vision: the VLESS stream wrapped in padded frames.
 *
 * Plain VLESS inside TLS is recognisable: right after the handshake comes a record exactly the
 * size of the VLESS header, then the data. That sequence of record lengths tells the connection
 * from real HTTPS without decrypting it. Vision adds random padding to each frame, so record
 * lengths stop being predictable.
 *
 * Frame format (XtlsPadding in Xray's proxy/proxy.go), integers big-endian:
 *
 *   [UUID 16 bytes]   only in the very first frame
 *   command  1 byte   0=continue, 1=end, 2=direct
 *   length   2 bytes  payload length
 *   padding  2 bytes  number of random bytes after the payload
 *   payload  N
 *   padding  M random bytes
 *
 * `end` tells the peer that padding is over and a plain stream follows. `direct` switches to
 * direct copy; we never send it: it is faster, but record lengths become honest again.
 *
 * We send `end` on the first data frame: the padding is there to hide the VLESS header, and
 * after it only encrypted records are visible inside TLS anyway.
 */
#define _GNU_SOURCE
#include <string.h>
#include "osrand.h"
#include <errno.h>

#include "vision.h"

/* Padding length bounds, the same as Xray's (testseed there). They are tuned so that record
 * lengths look like HTTPS; changing them weakens the camouflage. */
#define PAD_SHORT_THRESHOLD 900
#define PAD_LONG_RANGE      500
#define PAD_LONG_BASE       900
#define PAD_SHORT_RANGE     256

static int rnd_bytes(unsigned char *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = os_getrandom(b + got, n - got, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)r;
    }
    return 0;
}

static unsigned rnd_below(unsigned limit) {
    if (limit == 0) return 0;
    unsigned char b[2];
    if (rnd_bytes(b, 2) != 0) return limit / 2;
    return (((unsigned)b[0] << 8) | b[1]) % limit;
}

void vision_init(struct vision *v, const unsigned char uuid[16]) {
    memset(v, 0, sizeof(*v));
    memcpy(v->uuid, uuid, 16);
    v->need_uuid = 1;
}

/* Wraps data in a frame. Returns the frame length, or 0 if it does not fit in cap.
 *
 * After the end frame nothing is wrapped: the server reads the stream as is, and a 5-byte
 * header written later would reach the destination as part of the request. */
size_t vision_wrap(struct vision *v, const unsigned char *data, size_t n,
                   unsigned char *out, size_t cap) {
    if (v->sent_end) {
        if (n > cap) return 0;
        memcpy(out, data, n);
        return n;
    }
    /* Long padding while the VLESS header is being hidden (the first frame, short data);
     * otherwise short padding, which costs less bandwidth. */
    unsigned pad;
    if (n < PAD_SHORT_THRESHOLD && v->need_uuid) {
        unsigned r = rnd_below(PAD_LONG_RANGE);
        pad = r + PAD_LONG_BASE > n ? (unsigned)(r + PAD_LONG_BASE - n) : 0;
    } else {
        pad = rnd_below(PAD_SHORT_RANGE);
    }

    size_t head = (v->need_uuid ? 16u : 0u) + 5u;
    if (head + n + pad > cap) {
        /* Cut the padding, not the data: less padding only makes the record length a little
         * more recognisable. */
        if (head + n > cap) return 0;
        pad = (unsigned)(cap - head - n);
    }

    size_t i = 0;
    if (v->need_uuid) {
        memcpy(out, v->uuid, 16);
        i = 16;
        v->need_uuid = 0;
    }
    /* end at once: the padding has hidden the header. */
    out[i++] = VISION_CMD_END;
    out[i++] = (unsigned char)(n >> 8);
    out[i++] = (unsigned char)n;
    out[i++] = (unsigned char)(pad >> 8);
    out[i++] = (unsigned char)pad;
    if (n) { memcpy(out + i, data, n); i += n; }
    if (pad) {
        if (rnd_bytes(out + i, pad) != 0) return 0;
        i += pad;
    }
    v->sent_frames++;
    v->sent_end = 1;
    return i;
}

/* Unwraps the incoming stream. Each call consumes part of in (*consumed) and returns at most
 * one piece of payload; the caller calls again until in is used up.
 *
 * The server answers with the same frames until `end`; after it the stream is plain. State is
 * kept in v because TLS record and Vision frame boundaries need not coincide: a frame may span
 * several calls. */
int vision_unwrap(struct vision *v, const unsigned char *in, size_t n,
                  size_t *consumed, const unsigned char **payload, size_t *payload_n) {
    *consumed = 0;
    *payload = NULL;
    *payload_n = 0;
    if (!n) return 0;

    if (v->recv_done) {
        *consumed = n;
        *payload = in;
        *payload_n = n;
        return 0;
    }

    /* The server's first frame also starts with the UUID, just like ours: it marks the start
     * of the wrapped stream in both directions. */
    if (!v->recv_uuid_seen) {
        /* Collect the start of the stream byte by byte, like the frame header below: a short
         * read is a normal state, not an error. */
        while (v->rx_pre_n < sizeof(v->rx_pre) && *consumed < n)
            v->rx_pre[v->rx_pre_n++] = in[(*consumed)++];
        if (v->rx_pre_n < sizeof(v->rx_pre)) return 0;   /* the rest comes in a later call */

        if (memcmp(v->rx_pre, v->uuid, 16) != 0) {
            /* Not our UUID: the stream is not wrapped at all, which is legal. The collected
             * bytes are returned from rx_pre, since they are no longer contiguous with in;
             * the caller passes the rest of this record in the next call, under recv_done. */
            v->recv_done = 1;
            *payload = v->rx_pre;
            *payload_n = v->rx_pre_n;
            return 0;
        }
        v->recv_uuid_seen = 1;
        /* The 5 bytes after the UUID are the first frame header: put them into rx_hdr so the
         * header has a single parse path below. */
        memcpy(v->rx_hdr, v->rx_pre + 16, 5);
        v->rx_hdr_n = 5;
        in += *consumed;
        n -= *consumed;
    }

    /* Streaming from here on: a frame's length may cover more data than one TLS record
     * carries, which is common on any transfer of more than a couple of kilobytes. Dropping a
     * partial frame would lose sync for the rest of the stream. */
    size_t i = 0;

    if (v->rx_data_left) {
        size_t take = v->rx_data_left < n - i ? v->rx_data_left : n - i;
        *payload = in + i;
        *payload_n = take;
        v->rx_data_left -= (uint32_t)take;
        i += take;
        *consumed += i;
        if (!v->rx_data_left && !v->rx_pad_left && v->rx_end_after) v->recv_done = 1;
        return 0;
    }

    /* Padding is discarded. */
    if (v->rx_pad_left) {
        size_t take = v->rx_pad_left < n - i ? v->rx_pad_left : n - i;
        v->rx_pad_left -= (uint32_t)take;
        i += take;
        *consumed += i;
        if (!v->rx_pad_left && v->rx_end_after) v->recv_done = 1;
        return 0;
    }

    /* The next frame header, byte by byte too: a record boundary may split it. */
    while (v->rx_hdr_n < 5 && i < n) v->rx_hdr[v->rx_hdr_n++] = in[i++];
    *consumed += i;
    if (v->rx_hdr_n < 5) return 0;              /* the rest comes in a later call */

    unsigned char cmd = v->rx_hdr[0];
    if (cmd > VISION_CMD_DIRECT) return VISION_EPROTO;
    v->rx_data_left = ((uint32_t)v->rx_hdr[1] << 8) | v->rx_hdr[2];
    v->rx_pad_left = ((uint32_t)v->rx_hdr[3] << 8) | v->rx_hdr[4];
    v->rx_end_after = (cmd == VISION_CMD_END || cmd == VISION_CMD_DIRECT);
    /* direct is not just another end: from now on the server writes the destination's stream
     * to the socket without its own TLS, and it must be read bypassing decryption. Parsed as
     * our records, it gives nonsense lengths and AEAD failures mid-transfer, at a point that
     * depends on when the server spotted TLS inside. */
    if (cmd == VISION_CMD_DIRECT) v->recv_direct = 1;
    v->rx_hdr_n = 0;
    /* A frame with neither payload nor padding: the server ends padding this way. */
    if (!v->rx_data_left && !v->rx_pad_left && v->rx_end_after) v->recv_done = 1;
    return 0;
}
