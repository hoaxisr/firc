/* VLESS: the request header and the response.
 *
 * VLESS is deliberately bare: no encryption and no checksums of its own. The TLS below already
 * does that, and doing it twice would add a distinguishable feature to a stream that must look
 * like plain HTTPS.
 *
 * Request (integers big-endian):
 *   version(1) | UUID(16) | addons_len(1) | addons | command(1) | port(2) | addr_type(1) |
 *   address | data...
 *
 * The server's response is two bytes (version, addons_len) plus the addons, then the data.
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "vless_proto.h"

/* SHA-1 of a short message, used only to derive a UUID from a non-UUID id (see below).
 *
 * Own code rather than the crypto library: vless_proto.c needs no library, so the unit tests
 * (tests/submatch.c) build it without one. SHA-1 is not a protection here but a fixed
 * derivation the server must reproduce, and any error shows at once as a rejected user. It is
 * pinned to the NIST "abc" vector in tests/submatch.c.
 *
 * The message is always shorter than a block: 16 zero bytes plus at most 30 characters, 46
 * bytes at most. The padding fits one 64-byte block, so there is no multi-block loop; longer
 * input is refused. */
static int sha1_short(const unsigned char *msg, size_t n, unsigned char out[20]) {
    unsigned char b[64];
    uint32_t w[80], h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu,
                             0x10325476u, 0xC3D2E1F0u };
    if (n > 55) return -1;              /* 55 = 64 - 1 padding byte - 8 length bytes */
    memset(b, 0, sizeof(b));
    memcpy(b, msg, n);
    b[n] = 0x80;
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) b[63 - i] = (unsigned char)(bits >> (8 * i));

    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 |
               (uint32_t)b[4 * i + 2] << 8 | (uint32_t)b[4 * i + 3];
    for (int i = 16; i < 80; i++) {
        uint32_t v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (v << 1) | (v >> 31);
    }

    uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (bb & c) | (~bb & d);              k = 0x5A827999u; }
        else if (i < 40) { f = bb ^ c ^ d;                        k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (bb & c) | (bb & d) | (c & d);     k = 0x8F1BBCDCu; }
        else             { f = bb ^ c ^ d;                        k = 0xCA62C1D6u; }
        uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = c; c = (bb << 30) | (bb >> 2); bb = a; a = t;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;

    for (int i = 0; i < 5; i++) {
        out[4 * i]     = (unsigned char)(h[i] >> 24);
        out[4 * i + 1] = (unsigned char)(h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(h[i] >> 8);
        out[4 * i + 3] = (unsigned char)h[i];
    }
    return 0;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if ((c | 32) >= 'a' && (c | 32) <= 'f') return (c | 32) - 'a' + 10;
    return -1;
}

/* Groups 8-4-4-4-12 as in Xray: at most one hyphen before each group, only hex digits inside.
 * out may be NULL to only validate.
 *
 * Like Xray, the tail after the last group is ignored: the length is already capped at 36, so
 * "32 hex digits plus 4 arbitrary characters" parses by the first 32. Being stricter would
 * reject links every other client accepts, and cannot cause a mismatch with the server, which
 * never sees our string. */
static int hex_groups(const char *s, size_t n, unsigned char *out) {
    static const size_t groups[5] = { 8, 4, 4, 4, 12 };
    size_t i = 0, o = 0;
    for (int g = 0; g < 5; g++) {
        if (i < n && s[i] == '-') i++;
        if (n - i < groups[g]) return -1;
        for (size_t k = 0; k < groups[g]; k += 2) {
            int hi = hexval(s[i + k]), lo = hexval(s[i + k + 1]);
            if (hi < 0 || lo < 0) return -1;
            if (out) out[o] = (unsigned char)((hi << 4) | lo);
            o++;
        }
        i += groups[g];
    }
    return 0;
}

/* The form of the id is decided by the string's length, as in Xray (common/uuid/uuid.go,
 * ParseString). A panel id such as "TMG_74317ba5f91" is valid VLESS: the UUID is derived from
 * it by a hash, and both ends must derive the same bytes. */
int vless_uuid_form(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n >= 32 && n <= 36)
        return hex_groups(s, n, NULL) == 0 ? VLESS_UUID_HEX : VLESS_UUID_NOTHEX;
    if (n == 0) return VLESS_UUID_EMPTY;
    if (n == 31) return VLESS_UUID_GAP;
    if (n > 36) return VLESS_UUID_TOOLONG;
    return VLESS_UUID_DERIVED;
}

/* The branch is chosen by the one rule above: two separate decisions on the length could
 * silently disagree. */
int vless_uuid_parse(const char *s, unsigned char out[16]) {
    switch (vless_uuid_form(s)) {
    case VLESS_UUID_HEX:
        return hex_groups(s, strlen(s), out);
    case VLESS_UUID_DERIVED: {
        /* The first 16 bytes of sha1(16 zero bytes || string), then version 5 in the high
         * nibble of byte 6 and the RFC 4122 variant in byte 8, exactly as in Xray. The zero
         * bytes are not a salt: Xray hashes the string into an empty UUID (h.Write(uuid[:])
         * before the text), and without them the result differs. */
        size_t n = strlen(s);
        unsigned char msg[16 + 30], dg[20];
        memset(msg, 0, 16);
        memcpy(msg + 16, s, n);
        if (sha1_short(msg, 16 + n, dg) != 0) return -1;
        memcpy(out, dg, 16);
        out[6] = (unsigned char)((out[6] & 0x0f) | 0x50);
        out[8] = (unsigned char)((out[8] & 0x3f) | 0x80);
        return 0;
    }
    default:
        return -1;
    }
}

/* The request header. The address goes as a name when one is known, so the server resolves
 * it and the lookup does not leak through local DNS. Traffic from TUN has only an address.
 * Returns the header length, or 0 if it does not fit in cap or the flow or host is too long. */
size_t vless_build_request(const unsigned char uuid[16], enum vless_cmd cmd,
                           const char *host, const unsigned char ip4[4],
                           uint16_t port, const char *flow,
                           unsigned char *out, size_t cap) {
    size_t i = 0;
    if (cap < 24) return 0;
    out[i++] = 0;                       /* protocol version */
    memcpy(out + i, uuid, 16); i += 16;

    /* Addons. For XTLS-Vision this is the protobuf message Addons with the flow in field 1,
     * schema from Xray's addons.proto:
     *
     *   message Addons { string Flow = 1; bytes Seed = 2; }
     *
     * Encoded by hand, since a message of one string field is three bytes plus the name:
     *   0x0A (field 1, wire type 2) | length | string bytes
     *
     * Without it a server with flow=xtls-rprx-vision does not answer at all: it expects
     * Vision and gets plain VLESS. */
    if (flow && flow[0]) {
        size_t fl = strlen(flow);
        if (fl > 120 || i + 3 + fl > cap) return 0;
        out[i++] = (unsigned char)(2 + fl);   /* protobuf message length */
        out[i++] = 0x0A;                      /* field 1, wire type 2 (string) */
        out[i++] = (unsigned char)fl;
        memcpy(out + i, flow, fl); i += fl;
    } else {
        out[i++] = 0;                         /* no addons */
    }
    out[i++] = (unsigned char)cmd;
    /* Mux (command 3) has no port and address in the header: the v1.mux.cool:666 service is
     * implied by the command. Xray-core (proxy/vless/encoding, EncodeRequestHeader) writes
     * nothing after the command and sing-box (vless.ReadRequest) reads nothing after it, so
     * extra bytes would become the start of the Mux stream. */
    if (cmd == VLESS_CMD_MUX) return i;
    out[i++] = (unsigned char)(port >> 8);
    out[i++] = (unsigned char)port;

    if (host && host[0]) {
        size_t hl = strlen(host);
        if (hl > 255 || i + 2 + hl > cap) return 0;
        out[i++] = VLESS_ADDR_DOMAIN;
        out[i++] = (unsigned char)hl;
        memcpy(out + i, host, hl); i += hl;
    } else {
        if (i + 5 > cap) return 0;
        out[i++] = VLESS_ADDR_IPV4;
        memcpy(out + i, ip4, 4); i += 4;
    }
    return i;
}

/* Response: version and addons length. Returns 0 with the bytes to drop before the data in
 * *skip, VLESS_EAGAIN if more is needed, VLESS_EPROTO on a bad response.
 *
 * A bad response is the key signal: when Reality does not accept us, the server proxies to the
 * real site, and the first bytes are HTTP or TLS, not VLESS. This check is what tells success
 * from silent failure. */
int vless_parse_response(const unsigned char *buf, size_t n, size_t *skip) {
    if (n < 2) return VLESS_EAGAIN;
    if (buf[0] != 0) return VLESS_EPROTO;      /* not our version: almost surely the real site */
    size_t extra = buf[1];
    if (n < 2 + extra) return VLESS_EAGAIN;
    *skip = 2 + extra;
    return 0;
}
