/* Connection to a VLESS node and the check that the node accepted us.
 *
 * Reality has no negative answer. A server that does not recognise the client does not refuse:
 * it proxies the connection to the real site it hides behind. The handshake can complete, the
 * keys agree, TLS comes up, and it is still that site, not the tunnel.
 *
 * Only the first byte of the VLESS response tells them apart: the server answers with version 0,
 * the real site with anything else (HTTP, HTML, a redirect). So vless_probe() below is the only
 * honest check of a node; the node choice at startup and the pool's health check use it.
 *
 * Connection setup (TCP to every address, security, transports) lives in proto/transport. This
 * file holds what knows VLESS: the node as transport parameters and the probe with a VLESS request.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>

#include "vless.h"
#include "vless_proto.h"
#include "vision.h"
#include "client.h"
#include "sublink.h"

int vless_connect(const struct vless_node *node, struct transport *conn, int timeout_s) {
    struct tr_node tn;
    sl_tr_node(node, &tn);
    return transport_open(conn, &tn, timeout_s);
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* The node check: the only way to learn whether Reality accepted us.
 *
 * Ask the server to connect to a known live address and look at the first byte of the answer.
 * Version 0 is a VLESS response: the server is ours. Anything else means we were not accepted
 * and talk to the real site; that connection works and a page loads, so without this check the
 * node would look healthy. The answer also measures latency over the path real traffic takes.
 *
 * Two targets, not one: a node may not pass a given address (the server's provider blocks it,
 * the hoster runs its own DNS on it, a rule on the server), and with a single target such a
 * node would be rejected as a whole. The second target is tried only when the target may be
 * to blame: the server connection came up but no data came back. A handshake failure or a
 * Reality rejection belongs to the node, and retrying it would double the probe time of every
 * dead node. */
struct probe_target { unsigned char ip[4]; const char *host; };
static const struct probe_target PROBE_TARGETS[] = {
    { { 1, 1, 1, 1 }, "1.1.1.1" },
    { { 8, 8, 8, 8 }, "8.8.8.8" },
};

static int probe_once(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms,
                      const struct probe_target *tg, int *connected);

int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n) {
    return vless_probe_timed(node, timeout_s, why, why_n, NULL, NULL);
}

int vless_probe_timed(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms) {
    int rc = TR_EIO;
    for (size_t i = 0; i < sizeof(PROBE_TARGETS) / sizeof(PROBE_TARGETS[0]); i++) {
        int connected = 0;
        rc = probe_once(node, timeout_s, why, why_n, handshake_ms, ttfb_ms,
                        &PROBE_TARGETS[i], &connected);
        if (rc == 0) return 0;
        /* The server was not reached or did not accept us: not the target's fault. */
        if (!connected || rc == VLESS_CONN_EREJECTED || rc == VLESS_CONN_EBADUUID)
            return rc;
    }
    return rc;
}

static int probe_once(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms,
                      const struct probe_target *tg, int *connected) {
    if (handshake_ms) *handshake_ms = -1;
    if (ttfb_ms) *ttfb_ms = -1;
    *connected = 0;

    struct transport c;
    int64_t t0 = now_ms();
    int rc = vless_connect(node, &c, timeout_s);
    if (rc) {
        snprintf(why, why_n, "%s", vless_strerror(rc));
        return rc;
    }
    if (handshake_ms) *handshake_ms = (int)(now_ms() - t0);
    *connected = 1;

    unsigned char uuid[16];
    if (vless_uuid_parse(node->uuid, uuid) != 0) {
        transport_close(&c);
        snprintf(why, why_n, "bad UUID");
        return VLESS_CONN_EBADUUID;
    }

    unsigned char req[512];
    size_t req_n = vless_build_request(uuid, VLESS_CMD_TCP, NULL, tg->ip, 80,
                                       node->flow, req, sizeof(req));
    if (!req_n) { transport_close(&c); snprintf(why, why_n, "cannot build the request header"); return TR_EIO; }

    /* A minimal HTTP request goes with the header: the server does not answer until it has
     * data to forward, and without it the probe would wait for the timeout. */
    char http[128];
    int http_n = snprintf(http, sizeof(http),
                          "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", tg->host);
    /* How much data actually follows the header. Vision below subtracts exactly this to split
     * the VLESS header from the data, and the HTTP request may not have fit. */
    size_t http_used = 0;
    if (http_n > 0 && req_n + (size_t)http_n <= sizeof(req)) {
        memcpy(req + req_n, http, (size_t)http_n);
        req_n += (size_t)http_n;
        http_used = (size_t)http_n;
    }

    /* With Vision the VLESS header goes raw, immediately followed by the first Vision frame
     * with the data; the header is not inside the frame. In Xray's XtlsPadding the wrapping
     * applies to data buffers, and "we do a long padding to hide vless header" means the next
     * frame's padding hides the header by sharing its TLS record. With the header inside the
     * frame the server matches the frame's UUID, then reads the VLESS version and the start of
     * the header's UUID as the command and lengths, and closes the connection, which looks
     * like a key rejection. */
    if (node->flow[0]) {
        struct vision vis;
        vless_uuid_parse(node->uuid, uuid);
        vision_init(&vis, uuid);
        static __thread unsigned char framed[8192];
        size_t header_n = req_n - http_used;
        size_t fn = vision_wrap(&vis, req + header_n, req_n - header_n,
                                framed, sizeof(framed));
        if (!fn) { transport_close(&c); snprintf(why, why_n, "cannot build the Vision frame"); return TR_EIO; }
        /* One write: the header and the frame must leave together, or their split across
         * records becomes a recognisable feature itself. */
        static __thread unsigned char together[8704];
        if (header_n + fn > sizeof(together)) { transport_close(&c); snprintf(why, why_n, "request too large"); return TR_EIO; }
        memcpy(together, req, header_n);
        memcpy(together + header_n, framed, fn);
        rc = transport_write(&c, together, header_n + fn);
    } else {
        rc = transport_write(&c, req, req_n);
    }
    if (rc) { transport_close(&c); snprintf(why, why_n, "request not sent: %s", vless_strerror(rc)); return rc; }
    int64_t t_sent = now_ms();

    /* Sized by the transport's minimum: over HTTP/2 one read returns up to a whole TLS record,
     * and a smaller buffer would fail on a legal frame. */
    static __thread unsigned char buf[VLESS_MIN_RECV_CAP];
    size_t got = 0;
    /* Wait for data by the clock, not by a number of attempts. A read of zero bytes means
     * "nothing yet": an HTTP/2 control frame (SETTINGS, WINDOW_UPDATE) or a record not fully
     * arrived. Reads are non-blocking (the tunnel runs one loop for all connections), so a
     * fixed number of attempts passes in microseconds, before the answer can arrive, and fails
     * a working node. Wait on the socket, not in a busy loop. */
    int64_t rx_deadline = now_ms() + (int64_t)(timeout_s > 0 ? timeout_s : 8) * 1000;
    for (;;) {
        rc = transport_read(&c, buf, sizeof(buf), &got);
        if (rc) { transport_close(&c); snprintf(why, why_n, "no response: %s", vless_strerror(rc)); return rc; }
        if (got) break;
        if (now_ms() >= rx_deadline) break;
        struct pollfd pw = { .fd = transport_fd(&c), .events = POLLIN, .revents = 0 };
        poll(&pw, 1, 200);
    }
    if (!got) { transport_close(&c); snprintf(why, why_n, "server sent no data"); return TR_EIO; }
    /* Timed before parsing: parsing waits for nothing, and counting it would measure our own
     * work. */
    if (ttfb_ms) *ttfb_ms = (int)(now_ms() - t_sent);

    /* The VLESS response header comes first and is not wrapped, even with Vision (vl_deliver
     * in vldial.c parses it the same way). rv is zeroed, so its all-zero UUID does not match
     * the first 16 bytes and vision_unwrap only hands back the first bytes unchanged: the parse
     * below reads the raw header either way. */
    const unsigned char *body = buf;
    size_t body_n = got;
    if (node->flow[0]) {
        struct vision rv;
        memset(&rv, 0, sizeof(rv));
        size_t used = 0;
        const unsigned char *pl = NULL;
        size_t pl_n = 0;
        if (vision_unwrap(&rv, buf, got, &used, &pl, &pl_n) == 0 && pl) {
            body = pl;
            body_n = pl_n;
        }
    }

    size_t skip = 0;
    int pr = vless_parse_response(body, body_n, &skip);
    transport_close(&c);

    if (pr == VLESS_EPROTO) {
        /* The silent Reality rejection. Say it plainly: otherwise it looks like a working
         * node, since TLS is up and an answer came, only from the cover site. */
        snprintf(why, why_n,
                 "server did not accept the key — the cover site answers, not the tunnel "
                 "(check pbk, sid and sni)");
        return VLESS_CONN_EREJECTED;
    }
    if (pr == VLESS_EAGAIN) {
        snprintf(why, why_n, "response too short (%zu bytes)", got);
        return TR_EIO;
    }
    snprintf(why, why_n, "ok, VLESS response (%zu bytes)", got);
    return 0;
}

const char *vless_strerror(int rc) {
    switch (rc) {
        case VLESS_CONN_EBADUUID: return "bad UUID";
        case VLESS_CONN_EREJECTED: return "server did not accept the key";
        default: return transport_strerror(rc);
    }
}
