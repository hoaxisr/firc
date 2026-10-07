/* VLESS dialer: how the tunnel stack (stack.c) carries client flows to a VLESS node. The stack
 * sees only the vless_dialer table.
 *
 * The session is struct vl_sess (vldial.h): the flow state (header, Vision, datagram assembly)
 * and the link to the node (struct transport). The link can be set up in advance: VLESS sends
 * the destination in the request header with the first data, and until then the link belongs
 * to nobody (DC_PRECONNECT). So the stack keeps spare links, and take moves only the link out
 * of a spare.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "osrand.h"

#include "vless.h"
#include "vless_proto.h"
#include "vision.h"
#include "client.h"
#include "vldial.h"
#include "stack.h"
#include "pool.h"

#define LOG_W  "tunvless[warn] tunnel: "

/* The stack's buffer must hold a whole transport record plus room for the VLESS header and
 * Vision padding. TUNNEL_BUF (dialer.h) is a plain number; it is checked here. */
_Static_assert(TUNNEL_BUF >= VLESS_MIN_RECV_CAP + 2048,
               "TUNNEL_BUF is smaller than a transport record plus room for VLESS and Vision");

static int g_trace;
#define TR(...) do { if (g_trace) fprintf(stderr, "tun: " __VA_ARGS__); } while (0)

void vl_set_trace(int on) { g_trace = on; }

/* ---- node ------------------------------------------------------------------------------ */

static const char *vl_peer(const void *ctx) {
    const struct vless_node *node = ctx;
    return node->host;
}

static void vl_describe(const void *ctx, char *out, size_t n) {
    const struct vless_node *node = ctx;
    snprintf(out, n, "%s (%s:%u %s%s)", node->name, node->host, node->port, node->type,
             node->flow[0] ? " +vision" : "");
}

/* ---- link ------------------------------------------------------------------------------ */

static int vl_connect(const void *ctx, void *sess, int timeout_s) {
    struct vl_sess *s = sess;
    return vless_connect(ctx, &s->t, timeout_s);
}

/* Moves the link from a spare session into the connection's session. Only struct transport is
 * copied: the UUID and Vision state in dst are already set up (flow_open), and overwriting them
 * would lose the flow.
 *
 * h2 keeps a pointer to its own link (io.ctx), which after the move points into the abandoned
 * spare slot; xhttp has two such self-pointers (xhttp_moved in trxhttp.c). transport_moved
 * fixes them, not the dialer. */
static void vl_take(void *dst, void *src) {
    struct vl_sess *d = dst;
    struct vl_sess *s = src;
    memcpy(&d->t, &s->t, sizeof(d->t));
    transport_moved(&d->t);
}

static void vl_close(void *sess) {
    struct vl_sess *s = sess;
    transport_close(&s->t);
}

/* Clears only what the dialer itself reads. A memset of the transport (about 40 KB) on every
 * close would pull 40 KB of zeros through the cache, and transport_open overwrites them anyway
 * (it starts with a memset of its struct). Likewise only the datagram counters are reset, not
 * the 4 KB buffer. Everything touched here lies at the start of the session (field order in
 * vldial.h). */
static void vl_clear(void *sess) {
    struct vl_sess *s = sess;
    s->header_sent = 0;
    s->established = 0;
    s->t.link.fd = -1;
    memset(&s->vis, 0, sizeof(s->vis));
    s->dg_want = s->dg_have = 0;
    s->dg_skip = 0;
    s->lenb_n = 0;
    s->xs = 0;
    s->xdiscard = 0;
}

static int vl_fd(const void *sess) {
    const struct vl_sess *s = sess;
    return transport_fd(&s->t);
}

static int vl_has_data(const void *sess) {
    const struct vl_sess *s = sess;
    return transport_has_data(&s->t);
}

/* ---- flow ------------------------------------------------------------------------------ */

/* The node's id does not parse, and the connection is closed. Say why: from outside a silent
 * close looks like "no traffic". It cannot happen today (a node with a bad UUID is dropped when
 * the nodes are parsed, and vless_tunnel_run checks the first node's before the device comes
 * up), so the line is rate limited rather than per packet. The UUID is not printed: it is the
 * key to the node. */
static void node_id_refused(const struct vless_node *node, const char *what) {
    static __thread time_t said;
    time_t now = stack_now_s();
    if (now - said < 5) return;
    said = now;
    fprintf(stderr, LOG_W "the UUID of node %s does not parse — %s refused; "
                    "check the node's link\n", node->name, what);
}

static int vl_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)k;
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    s->header_sent = 0;
    s->established = 0;
    if (vless_uuid_parse(node->uuid, s->uuid) != 0) {
        node_id_refused(node, udp ? "UDP connection" : "TCP connection");
        return -1;
    }
    /* For UDP, Vision is set up only for a node with flow: there UDP goes as a Mux command with
     * XUDP frames over the Vision stream (vl_send). Without flow the UDP request declares none,
     * and there are no Vision frames in either direction. */
    if (!udp || node->flow[0]) vision_init(&s->vis, s->uuid);
    return 0;
}

/* ---- XUDP: UDP over Vision (Mux.Cool, as the Xray client does) ----------------------------
 *
 * A UDP request (command 2) to an account with flow=xtls-rprx-vision does not work everywhere:
 * Xray-core refuses it with the vision flow ("doesn't support UDP") and accepts it only with an
 * empty flow, while sing-box checks the flow against the account for any command and rejects
 * both an empty flow and vision. Xray's own client does it differently
 * (proxy/vless/outbound/outbound.go: with vision the UDP command becomes Mux with the
 * v1.mux.cool:666 service): a Mux.Cool stream of XUDP frames (common/xudp), the whole stream
 * wrapped in Vision as for TCP. So does this code, for nodes with flow. Nodes without flow stay
 * on command 2: it is simpler, shorter on the wire and accepted by every server.
 *
 * Frame (the general Mux.Cool layout, common/mux/frame.go):
 *   [metadata length u16][session id u16 = 0][status u8][options u8][...]
 *   [data length u16][data]
 *   status: 1 New, 2 Keep, 3 End, 4 KeepAlive. Options: bit 0 has data, bit 1 error.
 * The first datagram of a flow is New: after the options come the network (2 = UDP), port,
 * address type and destination address, then the GlobalID (8 bytes; by it an Xray server
 * returns the same UDP socket for a new stream, "full cone"). Then Keep without an address: the
 * destination does not change, and for Keep without an address the server uses New's
 * destination (sing-box: metadata length 4, no address). One flow, one destination, as with
 * command 2: a single mux session, no multiplexing of destinations.
 *
 * Not implemented: several sessions in one stream, and Mux for TCP (concurrency). For TCP they
 * only save handshakes, and the stack has spare links for that. */
enum { XS_LEN = 0, XS_META, XS_DLEN, XS_DATA, XS_SKIP };

/* GlobalID: an opaque 8-byte key for "this source", by which the server picks the socket. Made
 * from the client's source and a random per-process key: the same for all flows of one source,
 * different between sources, unpredictable from outside. It needs no cryptographic strength:
 * it is not a secret, only a key in the server's table. */
static unsigned char g_xudp_key[16];
static pthread_once_t g_xudp_once = PTHREAD_ONCE_INIT;
static void xudp_key_init(void) {
    if (os_getrandom(g_xudp_key, sizeof g_xudp_key, 0) != (ssize_t)sizeof g_xudp_key) {
        struct timespec t;
        clock_gettime(CLOCK_REALTIME, &t);
        memcpy(g_xudp_key, &t, sizeof t < sizeof g_xudp_key ? sizeof t : sizeof g_xudp_key);
    }
}

static void xudp_gid(const struct flow_key *k, unsigned char gid[8]) {
    pthread_once(&g_xudp_once, xudp_key_init);
    uint64_t h = 1469598103934665603ULL;               /* FNV-1a, 64 bits */
    unsigned char in[16 + 6];
    memcpy(in, g_xudp_key, 16);
    memcpy(in + 16, &k->src, 4);
    in[20] = (unsigned char)(k->sport >> 8);
    in[21] = (unsigned char)k->sport;
    for (size_t i = 0; i < sizeof in; i++) { h ^= in[i]; h *= 1099511628211ULL; }
    h ^= h >> 32;
    for (int i = 0; i < 8; i++) gid[i] = (unsigned char)(h >> (56 - 8 * i));
}

/* Datagrams [length u16][data] (as dgram_frame frames them) to XUDP frames. first: the flow's
 * first frame (New with the address); the rest are Keep. Returns the result length, 0 if it does
 * not fit or the input is malformed. */
static size_t xudp_frames(const struct flow_key *k, int first, const unsigned char *in, size_t n,
                          unsigned char *out, size_t cap) {
    size_t o = 0;
    while (n) {
        if (n < 2) return 0;
        size_t dl = ((size_t)in[0] << 8) | in[1];
        in += 2;
        n -= 2;
        if (dl > n) return 0;
        unsigned char meta[40];
        size_t m = 0;
        meta[m++] = 0; meta[m++] = 0;                  /* session id: a single one, 0 */
        if (first) {
            meta[m++] = 1;                             /* New */
            meta[m++] = 1;                             /* options: has data */
            meta[m++] = 2;                             /* network: UDP */
            meta[m++] = (unsigned char)(k->dport >> 8);
            meta[m++] = (unsigned char)k->dport;       /* port, then address type and address */
            meta[m++] = VLESS_ADDR_IPV4;
            memcpy(meta + m, &k->dst, 4);
            m += 4;
            xudp_gid(k, meta + m);
            m += 8;
            first = 0;
        } else {
            meta[m++] = 2;                             /* Keep */
            meta[m++] = 1;
        }
        if (o + 2 + m + 2 + dl > cap) return 0;
        out[o++] = (unsigned char)(m >> 8);
        out[o++] = (unsigned char)m;
        memcpy(out + o, meta, m);
        o += m;
        out[o++] = (unsigned char)(dl >> 8);
        out[o++] = (unsigned char)dl;
        memcpy(out + o, in, dl);
        o += dl;
        in += dl;
        n -= dl;
    }
    return o;
}

/* Parses the stream of XUDP frames from the node (Vision already removed) and passes the
 * datagrams to the client. Streaming, like udp_downstream: XUDP frame, Vision frame and TLS
 * record boundaries do not coincide. Returns 0 or -1.
 *
 * Rules follow PacketReader in common/xudp: Keep with data is a datagram; KeepAlive is control,
 * its data (if any) is discarded; End, New and anything else end the stream. The sender address
 * in Keep is skipped: the flow's destination is fixed, and the answer reaches the client from
 * it, as with command 2. */
static int xudp_downstream(struct vl_sess *s, const unsigned char *d, size_t n,
                           dialer_emit_fn emit, void *arg) {
    while (n) {
        switch (s->xs) {
        case XS_LEN:
        case XS_DLEN: {
            unsigned v;
            if (!s->lenb_n && n >= 2) { v = (unsigned)(d[0] << 8 | d[1]); d += 2; n -= 2; }
            else if (!s->lenb_n) { s->lenb = d[0]; s->lenb_n = 1; return 0; }
            else { v = (unsigned)(s->lenb << 8 | d[0]); s->lenb_n = 0; d++; n--; }
            if (s->xs == XS_LEN) {
                if (v < 4 || v > 512) return -1;        /* Xray: < 4 ends, > 512 is malformed */
                s->xneed = (uint16_t)v;
                s->dg_have = 0;
                s->xs = XS_META;
            } else if (!v) {
                s->xs = XS_LEN;
            } else if (v > UDP_DGRAM_MAX) {
                s->dg_skip = v;                          /* drop exactly v bytes (udp_downstream) */
                s->xdiscard = 1;
                s->xs = XS_SKIP;
            } else {
                s->dg_want = (uint16_t)v;
                s->dg_have = 0;
                s->xs = XS_DATA;
            }
            break;
        }
        case XS_META: {
            size_t take = (size_t)s->xneed - s->dg_have;
            if (take > n) take = n;
            memcpy(s->dg + s->dg_have, d, take);
            s->dg_have = (uint16_t)(s->dg_have + take);
            d += take;
            n -= take;
            if (s->dg_have < s->xneed) return 0;
            unsigned status = s->dg[2], opt = s->dg[3];
            if (status != 2 && status != 4) return -1;   /* End, New, unknown: end of stream */
            if (opt & 2) return -1;                      /* the "error" option */
            s->xdiscard = status == 4;
            s->xs = (opt & 1) ? XS_DLEN : XS_LEN;
            break;
        }
        case XS_DATA: {
            size_t take = (size_t)s->dg_want - s->dg_have;
            if (take > n) take = n;
            memcpy(s->dg + s->dg_have, d, take);
            s->dg_have = (uint16_t)(s->dg_have + take);
            d += take;
            n -= take;
            if (s->dg_have < s->dg_want) return 0;
            s->xs = XS_LEN;
            if (!s->xdiscard && emit(arg, s->dg, s->dg_want) != 0) return -1;
            s->dg_want = 0;
            s->dg_have = 0;
            break;
        }
        default: {                                       /* XS_SKIP */
            uint32_t take = s->dg_skip < n ? s->dg_skip : (uint32_t)n;
            d += take;
            n -= take;
            s->dg_skip -= take;
            if (!s->dg_skip) { s->xs = XS_LEN; s->xdiscard = 0; }
            break;
        }
        }
    }
    return 0;
}

/* Sends data to the node in the right form: with the VLESS header before the first data, and
 * wrapped in Vision if the node requires it. */
static int vl_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *data, size_t n) {
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    /* out is needed only to join the header or the Vision frame and the data into one write.
     * Usually there is nothing to join (the header goes once per connection, and Vision ends
     * padding with its first frame), and the data goes straight from the packet, uncopied. */
    static __thread unsigned char out[TUNNEL_BUF];
    const unsigned char *body = data;
    size_t len = 0;

    /* UDP to a node with flow: XUDP frames instead of length-prefixed datagrams (see XUDP above).
     * The data framed by dgram_frame is repacked into xb; from there the path is shared with
     * TCP: Vision, then the write. */
    const int xudp = udp && node->flow[0];
    if (xudp) {
        static __thread unsigned char xb[TUNNEL_BUF];
        size_t xn = xudp_frames(k, !s->header_sent, data, n, xb, sizeof xb);
        if (!xn) return SEND_FATAL;
        data = xb;
        n = xn;
        body = xb;
        if (!s->header_sent) {
            /* Mux has no port and address in the header (vless_build_request): the
             * v1.mux.cool:666 service is implied by the command. */
            len = vless_build_request(s->uuid, VLESS_CMD_MUX, NULL, NULL, 0, node->flow,
                                      out, sizeof(out));
            if (!len) return SEND_FATAL;
        }
    } else if (!s->header_sent) {
        /* The destination comes from the packet: there is no name, the client has already
         * resolved it. */
        unsigned char ip4[4];
        memcpy(ip4, &k->dst, 4);
        /* UDP gets here only for a node without flow (see XUDP above) and is declared with
         * command 2 and no flow: Vision (xtls-rprx-vision) is about TCP, it replaces the copying
         * of the stream after the handshake, and datagrams have no such stream.
         *
         * dport is already in host order (struct flow_key in tun.h). */
        len = vless_build_request(s->uuid, udp ? VLESS_CMD_UDP : VLESS_CMD_TCP,
                                  NULL, ip4, k->dport,
                                  udp ? NULL : node->flow, out, sizeof(out));
        if (!len) return SEND_FATAL;
    }

    /* n == 0 (the stack's call for a silent client, dialer.h): the header alone, as Xray's client
     * flushes it after 100 ms without data. Vision starts with the first real data. */
    if (!n && !len) return SEND_OK;

    /* Wrap only until Vision has ended padding: after the end frame vision_wrap is a plain
     * copy, and the data would be copied for nothing (tls13_write copies it once more, which
     * it must: encryption is done in place in the record). So there are zero or one copies
     * before encryption.
     *
     * The Vision state is saved before wrapping and restored if the send fails. Otherwise the
     * first frame is lost for good on a closed HTTP/2 window: vision_wrap has marked the UUID
     * sent and padding ended, while h2_write sent nothing (it sends all or nothing). The client
     * retransmits the same packet, it goes out without the frame and the UUID, and the server
     * closes the stream. */
    struct vision vis_before = s->vis;
    if (node->flow[0] && !s->vis.sent_end && n) {
        size_t fn = vision_wrap(&s->vis, data, n, out + len, sizeof(out) - len);
        if (!fn) return SEND_FATAL;
        len += fn;
        body = out;
    } else if (len) {
        if (len + n > sizeof(out)) return SEND_FATAL;
        memcpy(out + len, data, n);
        len += n;
        body = out;
    } else {
        len = n;
    }

    /* The transport knows the framing (tcp, grpc, xhttp), not the dialer. */
    int rc = transport_write(&s->t, body, len);
    if (rc == H2_EWINDOW) {
        /* The HTTP/2 window is closed: the server is not keeping up. This is not a failure,
         * it is what flow control is for. Nothing was sent (h2_write sends all or nothing), so
         * it is enough not to acknowledge the packet: the client retransmits it as after a
         * loss, and by then the window has usually opened. Treating it as an error would cut
         * uploads at a random point. */
        s->vis = vis_before;                /* the frame did not leave: undo the wrapping */
        return SEND_AGAIN;
    }
    if (rc == H2_ESTATUS) {
        /* The xhttp server refused the upload (stream-up, packet-up): the chunk is lost, and
         * the stream after it cannot be whole. Close as on any send failure, but name the
         * reason: otherwise a node that refuses every chunk looks alive. */
        static __thread time_t said;
        time_t now = stack_now_s();
        if (now - said >= 5) {
            said = now;
            fprintf(stderr, LOG_W "node %s refused the data: %s — connection closed; "
                            "check the node's xhttp settings\n", node->name, vless_strerror(rc));
        }
    }
    if (rc) return SEND_FATAL;
    /* Mark the header sent only now: marked earlier, a retry would go without it, and the
     * server would not know where to connect. */
    s->header_sent = 1;
    return SEND_OK;
}

/* A datagram for the node: the two-byte length and the data in one piece. h2_write sends all
 * or nothing, and a datagram split over two calls could leave half-sent on a closed window: the
 * server would read the length and wait for a tail that never comes, and the next datagram
 * would land inside the previous one. */
static size_t vl_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > UDP_DGRAM_MAX || 2 + n > cap) return 0;
    out[0] = (unsigned char)(n >> 8);
    out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return 2 + n;
}

/* Through the transport, not tls13_read directly: for grpc and xhttp there is HTTP/2 between
 * TLS and VLESS, and reading past it would return frames instead of data.
 *
 * The _zc variant returns a pointer to the decrypted record where no copy is needed: on plain
 * tcp the data stays in the connection's buffer. The stack's buffer is still needed for
 * transports over HTTP/2, where a frame is assembled from several records. */
static int vl_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data,
                   size_t *got) {
    struct vl_sess *s = sess;
    return transport_read_zc(&s->t, buf, cap, data, got);
}

/* Parses the stream of datagrams from the node and passes them to the client.
 *
 * The assembly state lives in the session between calls: datagram, HTTP/2 frame and TLS record
 * boundaries need not coincide, and reading on to the end of a datagram would block and stall
 * the whole loop. Returns 0 or -1. */
static int udp_downstream(struct vl_sess *s, const unsigned char *d, size_t n,
                          dialer_emit_fn emit, void *arg) {
    while (n) {
        /* An oversized datagram is discarded by exactly its length. Stopping early would read
         * its tail as the next length and desync the stream for good: one such datagram would
         * kill the connection. */
        if (s->dg_skip) {
            uint32_t take = s->dg_skip < n ? s->dg_skip : (uint32_t)n;
            d += take;
            n -= take;
            s->dg_skip -= take;
            continue;
        }
        if (!s->dg_want) {
            if (s->lenb_n) {                        /* the first length byte came earlier */
                s->dg_want = (uint16_t)((s->lenb << 8) | d[0]);
                s->lenb_n = 0;
                d++;
                n--;
            } else if (n == 1) {
                /* The record ended exactly between the two length bytes. Rare, but a lost
                 * length byte shifts the whole stream after it, not just one datagram. */
                s->lenb = d[0];
                s->lenb_n = 1;
                return 0;
            } else {
                s->dg_want = (uint16_t)((d[0] << 8) | d[1]);
                d += 2;
                n -= 2;
            }
            if (!s->dg_want) continue;              /* length 0: nothing to pass on */
            if (s->dg_want > UDP_DGRAM_MAX) {
                static __thread time_t said;
                time_t now = stack_now_s();
                if (now - said >= 10) {
                    said = now;
                    fprintf(stderr, LOG_W "datagram of %u bytes exceeds the limit %d — "
                            "dropped\n", s->dg_want, UDP_DGRAM_MAX);
                }
                s->dg_skip = s->dg_want;
                s->dg_want = 0;
                continue;
            }
            s->dg_have = 0;
        }
        size_t need = (size_t)s->dg_want - s->dg_have;
        size_t take = n < need ? n : need;
        memcpy(s->dg + s->dg_have, d, take);
        s->dg_have = (uint16_t)(s->dg_have + take);
        d += take;
        n -= take;
        if (s->dg_have < s->dg_want) return 0;      /* the tail comes in a later record */

        /* A whole datagram goes to the client. The stack refreshes the connection's timestamp
         * on every datagram passed; otherwise a receive-only flow would be evicted as idle while
         * it works. */
        if (emit(arg, s->dg, s->dg_want) != 0) return -1;
        s->dg_want = 0;
        s->dg_have = 0;
    }
    return 0;
}

static int vl_deliver(const void *ctx, void *sess, int udp, const unsigned char *rx, size_t got,
                      dialer_emit_fn emit, void *arg) {
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    /* Parse order: first the VLESS response header, then Vision frames. The server answers
     * [version|addons_len|addons] and only then the stream in Vision frames: the response
     * header is not wrapped, just as the request header goes before the first frame, not
     * inside it. */
    const unsigned char *cur = rx;
    size_t left = got;

    if (!s->established) {
        size_t skip = 0;
        if (vless_parse_response(cur, left, &skip) != 0) {
            TR("VLESS response not parsed (%zu bytes)\n", left);
            return -1;
        }
        cur += skip;
        left -= skip;
        s->established = 1;
        TR("response header stripped (%zu bytes), %zu left\n", skip, left);
    }

    /* UDP to a node with flow: Vision frames carrying XUDP frames. */
    if (udp && node->flow[0]) {
        while (left) {
            size_t used = 0, pl_n = 0;
            const unsigned char *pl = NULL;
            int ur = vision_unwrap(&s->vis, cur, left, &used, &pl, &pl_n);
            if (ur == VISION_EPROTO) return -1;
            if (ur != 0 || (!used && !pl_n)) break;
            cur += used;
            left -= used;
            if (pl_n && xudp_downstream(s, pl, pl_n, emit, arg) != 0) return -1;
        }
        return 0;
    }
    /* Here the paths split: TCP is a stream in Vision frames, UDP without flow is datagrams with
     * a two-byte length and no Vision (the UDP request did not declare it). */
    if (udp)
        return left ? udp_downstream(s, cur, left, emit, arg) : 0;

    while (left) {
        const unsigned char *p = cur;
        size_t pn = left;

        if (node->flow[0]) {
            size_t used = 0;
            const unsigned char *pl = NULL;
            size_t pl_n = 0;
            int ur = vision_unwrap(&s->vis, cur, left, &used, &pl, &pl_n);
            /* An invalid frame command ends the connection; it is not a pause. The parser
             * returns EPROTO without resetting the collected header, so every later call
             * rereads the same bad frame and consumes nothing. A plain break would keep the
             * connection alive: the tunnel would read and decrypt records (the costliest work
             * on this hardware) and throw them away, while the client waits until the idle
             * eviction. */
            if (ur == VISION_EPROTO) {
                TR("invalid Vision frame: closing the connection, %zu left\n", left);
                return -1;
            }
            if (ur != 0 || (!used && !pl_n)) {
                /* A short read is not an error: the parser is streaming and collects the
                 * start of the stream itself (rx_pre in vision.h). Nothing consumed and
                 * nothing returned means there is no progress to make. */
                TR("frame not parsed: ur=%d, %zu left\n", ur, left);
                break;
            }
            p = pl;
            pn = pl_n;
            cur += used;
            left -= used;

        } else {
            cur += left;
            left = 0;
        }

        /* Each piece goes out at once: collecting them in one buffer would copy all traffic
         * and add a size limit. */
        if (pn && emit(arg, p, pn) != 0) return -1;
    }

    /* The server announced direct copy: tell the link, so the next read bypasses decryption.
     * It is set here because the command lives in Vision frames, which only this code knows.
     * Under VLESS encryption there is no direct copy: the encryption layer's records stay
     * records to the end of the connection (Xray has CanSpliceCopy = 3 there, and the server
     * never sends the command). */
    if (s->vis.recv_direct && !s->t.link.rx_direct && !s->t.enc) {
        transport_direct(&s->t);
        TR("server switched to direct copy — reading the socket as is\n");
    }
    return 0;
}

/* ---- startup --------------------------------------------------------------------------- */

int vless_tunnel_run(const struct tun_cfg *tc, const struct pool_cfg *pc, stack_ready_fn ready,
                     void *arg) {
    /* The node's id is checked before the device and the threads exist, while the node can still be
     * named: past this point it is parsed per connection (vl_flow_open), and a failure there would
     * mean a tunnel that is up but closes everything. */
    const struct vless_node *node = pc->node(pc->first);
    unsigned char id[16];
    if (vless_uuid_parse(node->uuid, id) != 0) {
        fprintf(stderr, "tunvless[warn]: the UUID of node %s does not parse — %s is not brought up; "
                        "check the node's link\n", node->name, tc->dev);
        return 1;
    }
    g_trace = getenv("STEER_TUN_TRACE") != NULL;
    return pool_run(tc, pc, ready, arg);
}

/* What vl_send takes now (dialer_ops.room): the transport's room less what vl_send adds in front
 * of the data — the request header until it is sent, a Vision frame (with padding of up to
 * about 1400 bytes) until Vision has ended padding. */
static long vl_room(const void *ctx, void *sess) {
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    long r = transport_room(&s->t);
    if (r < 0) return -1;
    if (!s->header_sent) r -= 64;
    if (node->flow[0] && !s->vis.sent_end) r -= 2048;
    return r > 0 ? r : 0;
}

const struct dialer_ops vless_dialer = {
    .name = "vless",
    .caps = DC_PRECONNECT,
    .sess_size = sizeof(struct vl_sess),
    .peer = vl_peer,
    .describe = vl_describe,
    .strerror = vless_strerror,
    .connect = vl_connect,
    .take = vl_take,
    .close = vl_close,
    .clear = vl_clear,
    .fd = vl_fd,
    .has_data = vl_has_data,
    .flow_open = vl_flow_open,
    .send = vl_send,
    .room = vl_room,
    .dgram_frame = vl_dgram_frame,
    .read = vl_read,
    .deliver = vl_deliver,
};
