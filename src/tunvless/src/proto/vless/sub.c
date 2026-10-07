/* Subscription parsing: the VLESS nodes of a subscription file.
 *
 * A subscription is a list of links (plain or base64, one per line), an Xray or sing-box JSON
 * config, or Clash YAML. Parsing needs no network and no cryptography, so the subscription tests
 * build this file without libraries.
 *
 * Links and Clash proxies of other protocols are skipped but counted (foreign): a subscription is
 * usually shared, and "26 nodes in it, 17 used" must be explained by numbers, not guessed.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "vless.h"
#include "sublink.h"
/* vless_uuid_form: the rule that turns the id into 16 bytes lives in one place, vless_proto.c
 * (no libraries). */
#include "vless_proto.h"
/* vencp_parse: a VLESS encryption string is checked here, before connecting. Strings only, no
 * cryptography. */
#include "vencp.h"

/* Link strings, transport and security parameters, long values and certificate checks are in
 * sublink.c. Here: whole subscriptions and the VLESS fields (flow, encryption, the id). */

/* Marker of an encryption value that did not parse; node_usable names the reason. */
static const char SUB_BAD_ENC[] = "!encryption";

/* Empty and "none" mean no encryption. Anything else must parse by Xray's rule (vencp.h), or the
 * node is marked and node_usable rejects it. v is already percent-decoded. */
static void set_encryption(struct vless_node *n, const char *v) {
    n->encryption = NULL;
    if (!v[0] || !strcmp(v, "none")) return;
    struct venc_cfg c;
    if (vencp_parse(v, &c, NULL) != 0) { n->encryption = SUB_BAD_ENC; return; }
    n->encryption = sl_intern(v, strlen(v));
}

static int node_usable(struct vless_node *n);

/* The VLESS parameters of a link: flow and encryption (Xray-core's post-quantum encryption, a
 * long value, see sl_intern). The rest go to sl_link_param. */
static int vless_own(struct vless_node *n, const char *k, size_t klen, const char *v, size_t vlen) {
    if (klen == 4 && !strncmp(k, "flow", 4)) sl_set_pct(n->flow, sizeof(n->flow), v, vlen);
    else if (klen == 10 && !strncmp(k, "encryption", 10)) {
        char *d = sl_param_dup(v, vlen);
        if (d) { set_encryption(n, d); free(d); } else n->encryption = SUB_BAD_ENC;
    }
    else return 0;
    return 1;
}

/* vless://UUID@host:port?params#name. An unusable node is not an error of the subscription: the
 * server may offer a transport the client does not support, and only that node is skipped. */
int vless_parse_url(const char *url, struct vless_node *n) {
    /* Omitted fields default to type=tcp and security=none (sl_link_parse, node_usable).
     * security=none is plain VLESS over TCP, without TLS: supported, and sensible inside a
     * trusted network or over an already protected channel. */
    int rc = sl_link_parse(url, "vless://", n, vless_own, NULL, NULL);
    if (rc) return rc;
    /* Checked here, not at connect time, so that an unusable node never becomes a candidate. */
    return node_usable(n);
}

/* Whether a parsed node is usable: 0 — yes, 1 — no, reason in n->skip_reason. Every parser
 * (links, Xray, sing-box, Clash) goes through it, so a node cannot be usable in one form and
 * unusable in another. */
static int node_usable(struct vless_node *n) {
    if (!n->security[0]) snprintf(n->security, sizeof(n->security), "none");

    /* flow=xtls-rprx-vision-udp443 is Vision with UDP to port 443 allowed: without the suffix
     * Xray's client refuses UDP/443 over Vision ("XTLS rejected UDP/443 traffic") to push QUIC
     * back to TCP. This client never refuses it, so the suffix changes nothing, and the name
     * becomes the usual one: Xray also sends the flow without the suffix in the VLESS request. */
    if (!strcmp(n->flow, "xtls-rprx-vision-udp443")) snprintf(n->flow, sizeof(n->flow), "xtls-rprx-vision");

    if (n->encryption == SUB_BAD_ENC) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "encryption is not supported");
        return 1;
    }
    if (sl_link_usable_pre(n)) return 1;

    /* The user id, by Xray's rule (vless_uuid_form): a hex UUID of 32-36 characters, or a
     * string of up to 30 characters that is hashed into a UUID. Panels use both, and
     * "TMG_74317ba5f91" is a valid id. Unusable: an empty string, exactly 31 characters (too
     * long to hash, too short for a UUID), longer than a UUID, or a UUID-length string with a
     * character that is not hex. */
    switch (vless_uuid_form(n->uuid)) {
    case VLESS_UUID_EMPTY:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "id is empty");
        return 1;
    case VLESS_UUID_GAP:
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "id: 31 characters, need a UUID");
        return 1;
    case VLESS_UUID_TOOLONG:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "id longer than a UUID");
        return 1;
    case VLESS_UUID_NOTHEX:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "UUID with an invalid character");
        return 1;
    default:
        break;
    }

    return sl_link_usable_post(n);
}

/* ---- a subscription as an Xray config -----------------------------------------------------------
 *
 * Panels that bind subscriptions to devices pick the format of the answer by User-Agent, and a
 * list of vless:// links may not be among the formats at all. An unknown client (curl, sing-box,
 * Nekoray) may get a stub of ss:// links to localhost:1234 named "Wrong client"; Happ, v2rayNG
 * and Streisand get an Xray config in JSON, Clash its YAML, SFI a sing-box config.
 *
 * What is read: an array of configs `[{...},{...}]` or one config `{...}`; in each, the
 * `outbounds` whose `protocol` is `vless`. Everything else (dns, routing, inbounds, freedom,
 * blackhole) configures the client, not a node, and is skipped.
 *
 * The parser is small and walks only the expected form; it is not a general JSON parser. It is
 * lenient where a subscription needs it: a node name longer than its buffer is cut, not
 * rejected, since a long label must not cost the node. The subscription tests
 * (tests/submatch.c) build this file without libraries.
 */
struct sj { const char *p; };

static void sj_ws(struct sj *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r') j->p++;
}

/* A string into buf, cut to n. Escapes are handled only so that \" does not end the string:
 * panels write UTF-8 as is, not \uXXXX. An escaped character is taken literally, which beats a
 * refusal: a name may contain anything. */
static int sj_str(struct sj *j, char *buf, size_t n) {
    sj_ws(j);
    if (*j->p != '"') return -1;
    j->p++;
    size_t i = 0;
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\' && j->p[1]) j->p++;
        if (i + 1 < n) buf[i++] = *j->p;
        j->p++;
    }
    if (*j->p != '"') return -1;
    j->p++;
    if (n) buf[i] = '\0';
    return 0;
}

/* Skip one value of any type, so that an unknown key is skipped rather than misread. */
static void sj_skip(struct sj *j) {
    sj_ws(j);
    if (*j->p == '"') { char t[8]; sj_str(j, t, sizeof(t)); return; }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p, close = open == '{' ? '}' : ']';
        int depth = 0;
        do {
            if (*j->p == '"') { char t[8]; sj_str(j, t, sizeof(t)); continue; }
            if (*j->p == open) depth++;
            else if (*j->p == close) depth--;
            j->p++;
        } while (*j->p && depth > 0);
        return;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
}

/* Enter an object and return its keys one by one: 0 — a key in key, 1 — the object ended,
 * -1 — not an object. The caller reads the value, or must call sj_skip. */
static int sj_obj_key(struct sj *j, int *first, char *key, size_t key_n) {
    sj_ws(j);
    if (*first) {
        if (*j->p != '{') return -1;
        j->p++;
        *first = 0;
    } else {
        sj_ws(j);
        if (*j->p == ',') j->p++;
    }
    sj_ws(j);
    if (*j->p == '}') { j->p++; return 1; }
    if (sj_str(j, key, key_n) != 0) return -1;
    sj_ws(j);
    if (*j->p != ':') return -1;
    j->p++;
    return 0;
}

/* The same for an array: 0 — an element starts here, 1 — the array ended, -1 — malformed. */
static int sj_arr_next(struct sj *j, int *first) {
    sj_ws(j);
    if (*first) {
        if (*j->p != '[') return -1;
        j->p++;
        *first = 0;
    } else {
        sj_ws(j);
        if (*j->p == ',') j->p++;
        /* After an element only a comma or the end of the array may follow. Anything else
         * must stop the parse: neither this nor the element reader would move, and malformed
         * JSON (`[null]`, `[}`) would loop forever. */
        else if (*j->p != ']') return -1;
    }
    sj_ws(j);
    if (*j->p == ']') { j->p++; return 1; }
    return 0;
}

/* ws or httpupgrade settings of a config, held until it is known which of the two the node uses.
 * A config may carry both objects (and xhttpSettings) at once, and network, which decides, may
 * come after them; so they are collected here and moved into the node at the end (xray_stream).
 * Otherwise the path from wsSettings would overwrite the path of an xhttp node. */
struct upg_cfg {
    char path[sizeof(((struct vless_node *)0)->path)];
    char host[sizeof(((struct vless_node *)0)->http_host)];
    char headers[sizeof(((struct vless_node *)0)->headers)];
    uint8_t bad;
};

static int ci_eq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
    }
    return *a == *b;
}

/* headers of an Xray config (map[string]string) into "Name: value\n" lines.
 *
 * A bad header marks the node (bad) rather than being dropped: the headers are part of the look
 * the seller chose for the server or the CDN in front of it, and a node without them may answer
 * 403 and look dead. Bad:
 *   - a value that is not a string: Xray does not load such a config;
 *   - a name not of HTTP token characters or longer than 40, a value with a control character (a
 *     line break would turn one header into two) or longer than 250: the request is built from
 *     these strings;
 *   - for ws, Upgrade, Connection and Sec-WebSocket-Key/Version/Extensions: gorilla refuses them
 *     ("duplicate header not allowed"), so the node would not open with Xray either. httpupgrade
 *     in Xray accepts them (the key as written; the transport sets Connection and Upgrade on top
 *     with its canonical keys), and so does this parser: the request follows Xray (trupgrade.c);
 *   - Host for httpupgrade: Xray rejects the config (`"headers" can't contain "host"`). For
 *     ws, Xray moves Host from headers into host (if that is empty) and drops it from headers,
 *     and so does this parser;
 *   - more than the node's buffer holds. */
static void xray_headers(struct sj *j, struct upg_cfg *u, int hu) {
    int f = 1;
    char key[64], val[256];
    size_t o = strlen(u->headers);
    while (sj_obj_key(j, &f, key, sizeof(key)) == 0) {
        sj_ws(j);
        if (*j->p != '"') { sj_skip(j); u->bad = 1; continue; }
        val[0] = '\0';
        sj_str(j, val, sizeof(val));
        size_t kn = strlen(key), vn = strlen(val);
        if (ci_eq(key, "host")) {
            if (hu) u->bad = 1;
            else if (!u->host[0]) sl_set_field(u->host, sizeof(u->host), val, vn);
            continue;
        }
        int ok = sl_hdr_valid(key, val);
        if (!hu && (ci_eq(key, "upgrade") || ci_eq(key, "connection") ||
                    ci_eq(key, "sec-websocket-key") || ci_eq(key, "sec-websocket-version") ||
                    ci_eq(key, "sec-websocket-extensions")))
            ok = 0;
        if (!ok || o + kn + 2 + vn + 1 >= sizeof(u->headers)) { u->bad = 1; continue; }
        o += (size_t)snprintf(u->headers + o, sizeof(u->headers) - o, "%s: %s\n", key, val);
    }
}

/* wsSettings and httpupgradeSettings: path, host, headers. An empty host does not overwrite Host
 * from headers (in Xray an empty host means "not set"). */
static void xray_upg(struct sj *j, struct upg_cfg *u, int hu) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof(k)) == 0) {
        sj_ws(j);
        if (!strcmp(k, "path") && *j->p == '"') sj_str(j, u->path, sizeof(u->path));
        else if (!strcmp(k, "host") && *j->p == '"') {
            char h[sizeof(u->host)] = "";
            sj_str(j, h, sizeof(h));
            if (h[0]) snprintf(u->host, sizeof(u->host), "%s", h);
        } else if (!strcmp(k, "headers") && *j->p == '{') xray_headers(j, u, hu);
        else sj_skip(j);
    }
}

static int sj_bool(struct sj *j);

/* streamSettings: the transport, security and everything that depends on them. */
static void xray_stream(struct sj *j, struct vless_node *n) {
    int first = 1;
    char k[64];
    struct upg_cfg ws, hu;
    memset(&ws, 0, sizeof(ws));
    memset(&hu, 0, sizeof(hu));
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "network")) {
            sj_str(j, n->type, sizeof(n->type));
            /* raw is Xray's name for tcp since 24.9.30. */
            if (!strcmp(n->type, "raw")) snprintf(n->type, sizeof(n->type), "tcp");
            /* websocket is another name for ws in Xray (infra/conf: case "ws", "websocket"). */
            if (!strcmp(n->type, "websocket")) snprintf(n->type, sizeof(n->type), "ws");
        }
        else if (!strcmp(k, "tcpSettings") || !strcmp(k, "rawSettings")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (strcmp(k2, "header") != 0) { sj_skip(j); continue; }
                int f3 = 1;
                char k3[64], ty[16] = "";
                while (sj_obj_key(j, &f3, k3, sizeof(k3)) == 0) {
                    if (!strcmp(k3, "type")) sj_str(j, ty, sizeof ty); else sj_skip(j);
                }
                if (!strcmp(ty, "http")) n->tcp_http = 1;
            }
        }
        else if (!strcmp(k, "wsSettings")) xray_upg(j, &ws, 0);
        else if (!strcmp(k, "httpupgradeSettings")) xray_upg(j, &hu, 1);
        else if (!strcmp(k, "security")) sj_str(j, n->security, sizeof(n->security));
        else if (!strcmp(k, "realitySettings") || !strcmp(k, "tlsSettings")) {
            /* Both carry serverName and fingerprint; only reality has publicKey and shortId.
             * One parser serves both because the field names do not clash and a node declares
             * exactly one of the two. */
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "serverName")) sj_str(j, n->sni, sizeof(n->sni));
                else if (!strcmp(k2, "fingerprint")) sj_str(j, n->fp, sizeof(n->fp));
                else if (!strcmp(k2, "publicKey")) sj_str(j, n->pbk, sizeof(n->pbk));
                else if (!strcmp(k2, "shortId")) sj_str(j, n->sid, sizeof(n->sid));
                else if (!strcmp(k2, "mldsa65Verify") || !strcmp(k2, "pqv")) {
                    char *pv = malloc(4096);
                    if (pv) { pv[0] = '\0'; sj_str(j, pv, 4096); sl_set_pqv(n, pv); free(pv); }
                    else sj_skip(j);
                }
                else if (!strcmp(k2, "pinnedPeerCertSha256") || !strcmp(k2, "pcs")) {
                    char pv[1100] = "";
                    sj_str(j, pv, sizeof pv);
                    sl_add_pins(n, pv, 0);
                }
                else if (!strcmp(k2, "verifyPeerCertByName") || !strcmp(k2, "vcn")) {
                    char vv[300] = "";
                    sj_str(j, vv, sizeof vv);
                    sl_set_vcn(n, vv);
                }
                else if (!strcmp(k2, "allowInsecure")) { if (sj_bool(j)) n->allow_insecure = 1; }
                else if (!strcmp(k2, "echConfigList")) {
                    char ev[1400] = "";
                    sj_str(j, ev, sizeof ev);
                    sl_set_ech(n, ev);
                }
                else sj_skip(j);
            }
        } else if (!strcmp(k, "grpcSettings")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "serviceName")) sj_str(j, n->service, sizeof(n->service));
                else sj_skip(j);
            }
        } else if (!strcmp(k, "xhttpSettings") || !strcmp(k, "splithttpSettings")) {
            /* splithttpSettings is the old name of xhttpSettings; some panels still use it. */
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "path")) sj_str(j, n->path, sizeof(n->path));
                else if (!strcmp(k2, "mode")) sj_str(j, n->mode, sizeof(n->mode));
                /* In a config this field is right here, not in `extra`: `extra` is how a
                 * link wraps the same settings when there is no config. */
                else if (!strcmp(k2, "xPaddingBytes")) {
                    char pb[32];
                    sj_str(j, pb, sizeof(pb));
                    sl_pad_range(n, pb);
                }
                /* A number or a "from-to" string: the raw token, parsed as in a link. */
                else if (!strcmp(k2, "scMaxEachPostBytes")) {
                    sj_ws(j);
                    const char *b = j->p;
                    sj_skip(j);
                    char raw[48];
                    size_t l = (size_t)(j->p - b);
                    if (l < sizeof raw) { memcpy(raw, b, l); raw[l] = 0; sl_post_range(n, raw); }
                }
                else if (!strcmp(k2, "extra")) {
                    /* A nested extra (the link form inside a config): read as in a link. */
                    const char *b = j->p;
                    sj_skip(j);
                    size_t l = (size_t)(j->p - b);
                    char *cp = malloc(l + 1);
                    if (cp) { memcpy(cp, b, l); cp[l] = 0; sl_parse_extra(n, cp); free(cp); }
                }
                else if (!strcmp(k2, "downloadSettings")) {
                    sj_ws(j);
                    if (strncmp(j->p, "null", 4) != 0) n->xh_extra = 1;
                    sj_skip(j);
                }
                else if (!strcmp(k2, "sessionPlacement") || !strcmp(k2, "sessionIDPlacement") ||
                         !strcmp(k2, "seqPlacement") || !strcmp(k2, "uplinkDataPlacement") ||
                         !strcmp(k2, "xPaddingMethod")) {
                    char v[32] = "";
                    sj_ws(j);
                    if (*j->p == '"') sj_str(j, v, sizeof v); else sj_skip(j);
                    if (sl_xh_setting_bad(k2, v)) n->xh_extra = 1;
                }
                else if (!strcmp(k2, "xPaddingObfsMode")) { if (sj_bool(j)) n->xh_extra = 1; }
                else sj_skip(j);
            }
        } else sj_skip(j);
    }
    const struct upg_cfg *u = !strcmp(n->type, "ws") ? &ws : !strcmp(n->type, "httpupgrade") ? &hu : NULL;
    if (u) {
        snprintf(n->path, sizeof(n->path), "%s", u->path);
        snprintf(n->http_host, sizeof(n->http_host), "%s", u->host);
        snprintf(n->headers, sizeof(n->headers), "%s", u->headers);
        n->headers_bad = u->bad;
    }
}

static void json_encryption(struct sj *j, struct vless_node *n) {
    char *ev = malloc(4096);
    if (!ev) { sj_skip(j); return; }
    ev[0] = '\0';
    if (sj_str(j, ev, 4096) == 0) set_encryption(n, ev);
    free(ev);
}

/* settings of a vless outbound: vnext[0] gives the address, the port and the first user. Only
 * the first: a subscription describes a node for one user. */
static void xray_settings(struct sj *j, struct vless_node *n) {
    int first = 1;
    char k[64];
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        /* The short outbound form (Xray 25+): address, port, id, flow and encryption right in
         * settings, without vnext and users. */
        if (!strcmp(k, "address")) { sj_str(j, n->host, sizeof(n->host)); continue; }
        if (!strcmp(k, "id")) { sj_str(j, n->uuid, sizeof(n->uuid)); continue; }
        if (!strcmp(k, "flow")) { sj_str(j, n->flow, sizeof(n->flow)); continue; }
        if (!strcmp(k, "encryption")) { json_encryption(j, n); continue; }
        if (!strcmp(k, "port")) {
            sj_ws(j);
            char num[16];
            if (*j->p == '"') sj_str(j, num, sizeof(num));
            else {
                size_t i = 0;
                while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof(num)) num[i++] = *j->p++;
                num[i] = '\0';
                if (!i) sj_skip(j);
            }
            n->port = sl_port_of(num);
            continue;
        }
        if (strcmp(k, "vnext") != 0) { sj_skip(j); continue; }
        int fa = 1, taken = 0;
        while (sj_arr_next(j, &fa) == 0) {
            if (taken) { sj_skip(j); continue; }
            taken = 1;
            int fo = 1;
            char k2[64];
            while (sj_obj_key(j, &fo, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "address")) sj_str(j, n->host, sizeof(n->host));
                else if (!strcmp(k2, "port")) {
                    sj_ws(j);
                    char num[16];
                    /* A number, or a number as a string: panels write both. Anything else is
                     * skipped as a value, so the parse stays in step with the object. */
                    if (*j->p == '"') sj_str(j, num, sizeof(num));
                    else {
                        size_t i = 0;
                        while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof(num))
                            num[i++] = *j->p++;
                        num[i] = '\0';
                        if (!i) sj_skip(j);
                    }
                    n->port = sl_port_of(num);
                } else if (!strcmp(k2, "users")) {
                    int fu = 1, u_taken = 0;
                    while (sj_arr_next(j, &fu) == 0) {
                        if (u_taken) { sj_skip(j); continue; }
                        u_taken = 1;
                        int fu2 = 1;
                        char k3[64];
                        while (sj_obj_key(j, &fu2, k3, sizeof(k3)) == 0) {
                            if (!strcmp(k3, "id")) sj_str(j, n->uuid, sizeof(n->uuid));
                            else if (!strcmp(k3, "flow")) sj_str(j, n->flow, sizeof(n->flow));
                            else if (!strcmp(k3, "encryption")) json_encryption(j, n);
                            else sj_skip(j);
                        }
                    }
                } else sj_skip(j);
            }
        }
    }
}

/* ---- sing-box: outbounds with type=vless --------------------------------------------------------
 *
 * Panels that serve a sing-box config (to SFI, Hiddify, Karing) put nodes into the same `outbounds`
 * array as Xray, but flat: type/tag/server/server_port/uuid/flow and the tls and transport
 * objects. The differences that need a parser of their own: the kind is in type, not protocol;
 * the port is the number server_port; TLS is an object with nested utls and reality; the Host of
 * a transport is a string or an array of strings. ws early data: max_early_data +
 * early_data_header_name; with the name Sec-WebSocket-Protocol this is Xray's `?ed=N`, which our
 * ws supports. With an empty name sing-box puts the data into the path, a form Xray does not
 * have; early data then stays off (a sing-box server accepts a plain request too). */
/* Append "Name: value\n" to the headers buffer (sing-box and Clash); -1 if it does not fit or the
 * header is not valid (sl_hdr_valid). No snprintf: it warns about truncation that the length check
 * already rules out. */
static int hdr_append(char *dst, size_t cap, const char *k, const char *v) {
    size_t o = strlen(dst), kn = strlen(k), vn = strlen(v);
    if (!sl_hdr_valid(k, v) || o + kn + vn + 4 >= cap) return -1;
    memcpy(dst + o, k, kn);
    dst[o + kn] = ':'; dst[o + kn + 1] = ' ';
    memcpy(dst + o + kn + 2, v, vn);
    dst[o + kn + 2 + vn] = '\n'; dst[o + kn + 3 + vn] = '\0';
    return 0;
}

static uint16_t port_of_num(long v) { return (v > 0 && v < 65536) ? (uint16_t)v : 0; }

static int sj_bool(struct sj *j) {
    sj_ws(j);
    if (!strncmp(j->p, "true", 4)) { j->p += 4; return 1; }
    if (!strncmp(j->p, "false", 5)) { j->p += 5; return 0; }
    sj_skip(j);
    return 0;
}

/* A number: 123 or "123". */
static long sj_num(struct sj *j) {
    sj_ws(j);
    char b[24] = "";
    if (*j->p == '"') sj_str(j, b, sizeof b);
    else { size_t i = 0; while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof b) b[i++] = *j->p++; b[i] = 0; if (!i) sj_skip(j); }
    return atol(b);
}

struct sb_ws { long ed; char ed_hdr[40]; };

static void sb_tls(struct sj *j, struct vless_node *n, int *enabled, int *reality) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof k) == 0) {
        if (!strcmp(k, "enabled")) *enabled = sj_bool(j);
        else if (!strcmp(k, "server_name")) sj_str(j, n->sni, sizeof n->sni);
        else if (!strcmp(k, "insecure")) { if (sj_bool(j)) n->allow_insecure = 1; }
        else if (!strcmp(k, "ech")) {
            /* {"enabled": true, "config": ["-----BEGIN ECH CONFIGS-----", "base64…",
             * "-----END ECH CONFIGS-----"]}. The PEM lines are joined without the frame lines.
             * Without config (only query_server_name) it is a DNS lookup: not supported. */
            int f2 = 1, on = 1, have = 0;
            char k2[64], joined[1400] = "";
            size_t jl = 0;
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                if (!strcmp(k2, "enabled")) on = sj_bool(j);
                else if (!strcmp(k2, "config")) {
                    int fa = 1;
                    char line[1400];
                    int r = sj_arr_next(j, &fa);          /* < 0: a single string, not an array */
                    do {
                        line[0] = '\0';
                        if (sj_str(j, line, sizeof line) != 0) break;
                        size_t ll = strlen(line);
                        if (line[0] != '-' && jl + ll < sizeof joined) { memcpy(joined + jl, line, ll + 1); jl += ll; have = 1; }
                        r = r < 0 ? 1 : sj_arr_next(j, &fa);
                    } while (r == 0);
                } else sj_skip(j);
            }
            if (on && have) sl_set_ech(n, joined);
            else if (on) n->ech = SL_ECH_DNS;
        }
        else if (!strcmp(k, "certificate_public_key_sha256")) {
            /* Base64 SHA-256 hashes of the SubjectPublicKeyInfo: an array, or a single string. */
            char pv[80];
            int fa = 1;
            int r = sj_arr_next(j, &fa);
            if (r == 0) {
                do { pv[0] = '\0'; sj_str(j, pv, sizeof pv); sl_add_pins(n, pv, 1); } while (sj_arr_next(j, &fa) == 0);
            } else if (r < 0) { pv[0] = '\0'; sj_str(j, pv, sizeof pv); sl_add_pins(n, pv, 1); }
        }
        else if (!strcmp(k, "utls")) {
            int f2 = 1, on = 1;
            char k2[64], fp[sizeof n->fp] = "";
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                if (!strcmp(k2, "enabled")) on = sj_bool(j);
                else if (!strcmp(k2, "fingerprint")) sj_str(j, fp, sizeof fp);
                else sj_skip(j);
            }
            if (on && fp[0]) snprintf(n->fp, sizeof n->fp, "%s", fp);
        } else if (!strcmp(k, "reality")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                if (!strcmp(k2, "enabled")) *reality = sj_bool(j);
                else if (!strcmp(k2, "public_key")) sj_str(j, n->pbk, sizeof n->pbk);
                else if (!strcmp(k2, "short_id")) sj_str(j, n->sid, sizeof n->sid);
                else sj_skip(j);
            }
        } else sj_skip(j);
    }
}

static void sb_transport(struct sj *j, struct vless_node *n, struct sb_ws *w, struct upg_cfg *u) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof k) == 0) {
        if (!strcmp(k, "type")) {
            sj_str(j, n->type, sizeof n->type);
            if (!strcmp(n->type, "websocket")) snprintf(n->type, sizeof n->type, "ws");
        }
        else if (!strcmp(k, "path")) sj_str(j, u->path, sizeof u->path);
        else if (!strcmp(k, "host")) {
            sj_ws(j);
            if (*j->p == '[') { int fa = 1; char h[sizeof u->host]; int got = 0;
                while (sj_arr_next(j, &fa) == 0) { if (got++) sj_skip(j); else sj_str(j, h, sizeof h); }
                if (got) snprintf(u->host, sizeof u->host, "%s", h); }
            else sj_str(j, u->host, sizeof u->host);
        }
        else if (!strcmp(k, "service_name")) sj_str(j, n->service, sizeof n->service);
        else if (!strcmp(k, "max_early_data")) w->ed = sj_num(j);
        else if (!strcmp(k, "early_data_header_name")) sj_str(j, w->ed_hdr, sizeof w->ed_hdr);
        else if (!strcmp(k, "headers")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                sj_ws(j);
                char v[sizeof u->host] = "";
                if (*j->p == '[') { int fa = 1, got = 0;
                    while (sj_arr_next(j, &fa) == 0) { if (got++) sj_skip(j); else sj_str(j, v, sizeof v); } }
                else if (*j->p == '"') sj_str(j, v, sizeof v);
                else { sj_skip(j); u->bad = 1; continue; }
                if (ci_eq(k2, "host")) { if (!u->host[0]) snprintf(u->host, sizeof u->host, "%s", v); }
                else {
                    if (hdr_append(u->headers, sizeof u->headers, k2, v) != 0) u->bad = 1;
                }
            }
        } else sj_skip(j);
    }
}

/* A sing-box outbound: it has type where Xray has protocol. xray_outbound calls it after looking
 * ahead; it reads the whole object. */
static void sb_outbound_body(struct sj *j, struct vless_node *n, char *proto, size_t proto_n) {
    int first = 1, tls_on = 0, reality = 0;
    char k[64];
    struct sb_ws w; struct upg_cfg u;
    memset(&w, 0, sizeof w); memset(&u, 0, sizeof u);
    while (sj_obj_key(j, &first, k, sizeof k) == 0) {
        if (!strcmp(k, "type")) sj_str(j, proto, proto_n);
        else if (!strcmp(k, "tag")) { sj_str(j, n->name, sizeof n->name); sl_utf8_trim_tail(n->name); }
        else if (!strcmp(k, "server")) sj_str(j, n->host, sizeof n->host);
        else if (!strcmp(k, "server_port")) n->port = port_of_num(sj_num(j));
        else if (!strcmp(k, "uuid")) sj_str(j, n->uuid, sizeof n->uuid);
        else if (!strcmp(k, "flow")) sj_str(j, n->flow, sizeof n->flow);
        else if (!strcmp(k, "tls")) sb_tls(j, n, &tls_on, &reality);
        else if (!strcmp(k, "transport")) sb_transport(j, n, &w, &u);
        else sj_skip(j);
    }
    snprintf(n->security, sizeof n->security, "%s", reality ? "reality" : tls_on ? "tls" : "none");
    if (!n->type[0]) snprintf(n->type, sizeof n->type, "tcp");
    if (!strcmp(n->type, "ws") && w.ed > 0 && !strcmp(w.ed_hdr, "Sec-WebSocket-Protocol") && !strchr(u.path, '?')) {
        size_t o = strlen(u.path);
        if (!o) { u.path[0] = '/'; u.path[1] = 0; o = 1; }
        snprintf(u.path + o, sizeof u.path - o, "?ed=%ld", w.ed);
    }
    if (!strcmp(n->type, "ws") || !strcmp(n->type, "httpupgrade")) {
        snprintf(n->path, sizeof n->path, "%s", u.path);
        snprintf(n->http_host, sizeof n->http_host, "%s", u.host);
        snprintf(n->headers, sizeof n->headers, "%s", u.headers);
        n->headers_bad = u.bad;
    }
}

/* One outbound. 1 — a vless node, written into n; 0 — not ours. */
static int xray_outbound(struct sj *j, struct vless_node *n) {
    memset(n, 0, sizeof(*n));
    /* tcp by default, as in a link: a config without streamSettings or network is valid, and
     * Xray then means tcp. */
    snprintf(n->type, sizeof(n->type), "tcp");
    int first = 1, is_vless = 0;
    char k[64], proto[32] = "";
    /* Xray (protocol) or sing-box (type)? Look ahead at the top-level keys, as for remarks: the
     * key order is not defined, and the parse is a single pass. */
    {
        const char *save = j->p;
        int f0 = 1, has_protocol = 0, has_type = 0;
        char k0[64];
        while (sj_obj_key(j, &f0, k0, sizeof k0) == 0) {
            if (!strcmp(k0, "protocol")) has_protocol = 1;
            else if (!strcmp(k0, "type")) has_type = 1;
            sj_skip(j);
        }
        j->p = save;
        if (has_type && !has_protocol) {
            sb_outbound_body(j, n, proto, sizeof proto);
            return !strcmp(proto, "vless");
        }
    }
    /* The key order is not defined, so protocol may come after settings: read everything and
     * decide at the end. Parsing another protocol's outbound into the fields does no harm, the
     * node is not taken. */
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "protocol")) sj_str(j, proto, sizeof(proto));
        /* tag is cut by bytes like a link's name, so an incomplete UTF-8 tail is dropped the
         * same way. */
        else if (!strcmp(k, "tag")) { sj_str(j, n->name, sizeof(n->name)); sl_utf8_trim_tail(n->name); }
        else if (!strcmp(k, "settings")) xray_settings(j, n);
        else if (!strcmp(k, "streamSettings")) xray_stream(j, n);
        else sj_skip(j);
    }
    is_vless = !strcmp(proto, "vless");
    return is_vless;
}

/* The name the panel shows lives in the config's remarks, not in the outbound's tag: panels give
 * many outbounds the same tag ("proxy"), or a tag with a random suffix that changes on every
 * request ("tl-8-1-43al6bgvgg4"), and only remarks ("Germany", "Finland", …) tells nodes apart.
 *
 * remarks may come after outbounds, so the config object is first scanned for remarks alone
 * (sj_skip copies nothing) and then parsed from its start. The scan covers one config, not the
 * whole subscription.
 *
 * remarks is not percent-decoded, unlike a link's #fragment: in a JSON field "%2F" means exactly
 * these three characters. */
static void xray_remarks(struct sj *j, char *out, size_t n) {
    out[0] = '\0';
    const char *save = j->p;
    int first = 1;
    char k[64];
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "remarks")) { sj_str(j, out, n); sl_utf8_trim_tail(out); }
        else sj_skip(j);
    }
    j->p = save;
}

/* Node name from the config's remarks; ord counts the vless outbounds of this config. The second
 * and later get a number, since a config with a balancer has a main and a spare node. The number
 * is in parentheses ("Mobile #1 (2)") because panels number their nodes with '#' themselves.
 * When remarks nearly fills the buffer the number is dropped rather than cutting the name. */
static void xray_name(struct vless_node *nd, const char *remarks, size_t ord) {
    char num[24] = "";
    if (ord) snprintf(num, sizeof(num), " (%zu)", ord + 1);
    size_t room = sizeof(nd->name) - 1;
    size_t rl = strnlen(remarks, room);
    size_t nl = strlen(num);
    if (nl > room - rl) nl = room - rl;
    memcpy(nd->name, remarks, rl);
    memcpy(nd->name + rl, num, nl);
    nd->name[rl + nl] = '\0';
    sl_utf8_trim_tail(nd->name);
}

/* A whole config: an array of configs or one config. Returns the number of usable nodes. */
static size_t parse_xray(const char *text, struct vless_node *out, size_t max,
                         struct vless_sub_stats *st) {
    struct sj j = { text };
    size_t n = 0;
    sj_ws(&j);
    /* A single config is treated as an array of one. */
    int wrapped = (*j.p == '{');
    int fa = 1;
    if (wrapped) fa = 0;                    /* no array: parse the object at once */
    for (;;) {
        if (!wrapped) {
            int r = sj_arr_next(&j, &fa);
            if (r != 0) break;
        }
        const char *cfg_before = j.p;
        /* One config: nodes from outbounds, their names from remarks (xray_remarks). */
        char remarks[sizeof(((struct vless_node *)0)->name)];
        xray_remarks(&j, remarks, sizeof(remarks));
        size_t ord = 0;
        int fc = 1;
        char k[64];
        int seen_ob = 0;
        while (sj_obj_key(&j, &fc, k, sizeof(k)) == 0) {
            if (strcmp(k, "outbounds") != 0) { sj_skip(&j); continue; }
            seen_ob = 1;
            int fo = 1;
            while (sj_arr_next(&j, &fo) == 0) {
                struct vless_node node;
                const char *before = j.p;
                int ours = xray_outbound(&j, &node);
                if (j.p == before) break;               /* no progress: stop */
                if (!ours) continue;
                /* Before the usability check: sl_skip_note uses the name as its example, and
                 * it should be the name the panel shows. */
                if (remarks[0]) xray_name(&node, remarks, ord);
                ord++;
                if (n >= max) {
                    /* No room left: count the node as skipped, so the numbers add up. */
                    sl_skip_node(st, &node, "more nodes than fit");
                    continue;
                }
                if (node_usable(&node) == 0) { sl_node_ok(&node); out[n++] = node; }
                else sl_skip_node(st, &node, node.skip_reason);
            }
        }
        (void)seen_ob;
        if (wrapped) break;
        if (j.p == cfg_before) break;                   /* the config did not parse: do not loop */
    }
    return n;
}

/* ---- Clash / Mihomo: proxies with type: vless ---------------------------------------------------
 *
 * Panels give Clash clients YAML: a `proxies:` list, each node a flat set of keys and nested
 * *-opts (ws-opts, reality-opts, grpc-opts, xhttp-opts). Nodes come in block form (`- name: x`
 * and indented keys) and in flow form (`- {name: x, type: vless, reality-opts: {public-key: k}}`,
 * as converters write), and both must parse.
 *
 * No general YAML parser: one that refuses anchors and aliases would lose every node of a
 * subscription with an anchor in proxy-groups, and the tests build this file without libyaml.
 * Instead each node is flattened into path=value pairs (`reality-opts.public-key`,
 * `ws-opts.headers.Host`, `alpn.0`) and built from the paths. A value that does not parse (an
 * alias `*a`, a multi-line scalar) is skipped, and the node gets the rest. Anchors `&a` before a
 * value are dropped. */
#define YF_MAX 96
struct yflat {
    char buf[12288];
    size_t used, n;
    struct { const char *k, *v; } kv[YF_MAX];
};

static void yf_add(struct yflat *f, const char *path, size_t pn, const char *val, size_t vn) {
    if (f->n >= YF_MAX || f->used + pn + vn + 2 > sizeof f->buf) return;
    char *k = f->buf + f->used;
    memcpy(k, path, pn); k[pn] = 0;
    char *v = k + pn + 1;
    memcpy(v, val, vn); v[vn] = 0;
    f->used += pn + vn + 2;
    f->kv[f->n].k = k; f->kv[f->n].v = v; f->n++;
}

static const char *yf_get(const struct yflat *f, const char *path) {
    for (size_t i = 0; i < f->n; i++) if (!strcmp(f->kv[i].k, path)) return f->kv[i].v;
    return NULL;
}
/* Case-insensitive: Host or host in headers. */
static const char *yf_geti(const struct yflat *f, const char *path) {
    for (size_t i = 0; i < f->n; i++) if (ci_eq(f->kv[i].k, path)) return f->kv[i].v;
    return NULL;
}

/* The scalar at p, quoted or plain. flow != 0: a plain scalar ends at , } ]. Returns a pointer past
 * the scalar; the value (unquoted) goes to out, its length to *on. */
static const char *y_scalar(const char *p, const char *end, int flow, char *out, size_t cap, size_t *on) {
    size_t o = 0;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    /* An anchor or a tag before the value. */
    while (p < end && (*p == '&' || *p == '!')) { while (p < end && *p != ' ' && *p != '\t') p++; while (p < end && (*p == ' ' || *p == '\t')) p++; }
    if (p < end && (*p == '"' || *p == '\'')) {
        char q = *p++;
        while (p < end && *p != q) {
            if (q == '"' && *p == '\\' && p + 1 < end) p++;
            else if (q == '\'' && *p == '\'' && p + 1 < end && p[1] == '\'') p++;
            if (o + 1 < cap) out[o++] = *p;
            p++;
        }
        if (p < end) p++;
    } else {
        const char *st0 = p;
        while (p < end && *p != '\n' && *p != '\r') {
            if (flow && (*p == ',' || *p == '}' || *p == ']')) break;
            /* flow == 2: a key, which ends at ':' followed by a blank or the end. */
            if (flow == 2 && *p == ':' && (p + 1 >= end || p[1] == ' ' || p[1] == '\n' || p[1] == '\r')) break;
            if (*p == '#' && p > st0 && (p[-1] == ' ' || p[-1] == '\t')) break;
            if (o + 1 < cap) out[o++] = *p;
            p++;
        }
        while (o && (out[o - 1] == ' ' || out[o - 1] == '\t')) o--;
    }
    out[o] = 0;
    *on = o;
    return p;
}

static const char *y_flow(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth);

/* A value in flow form: {…}, […] or a scalar. */
static const char *y_flow_val(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (p < end && (*p == '{' || *p == '[')) return y_flow(f, p, end, path, pn, depth + 1);
    char v[3300];
    size_t vn;
    p = y_scalar(p, end, 1, v, sizeof v, &vn);
    if (v[0] != '*') yf_add(f, path, pn, v, vn);
    return p;
}

static const char *y_flow(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth) {
    if (depth > 6 || p >= end) return end;
    char open = *p++;
    unsigned idx = 0;
    for (;;) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')) p++;
        if (p >= end) return end;
        if (*p == '}' || *p == ']') return p + 1;
        char np[200];
        size_t npn;
        if (open == '{') {
            char key[96];
            size_t kn;
            p = y_scalar(p, end, 2, key, sizeof key, &kn);
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            if (p < end && *p == ':') p++;
            npn = (size_t)snprintf(np, sizeof np, "%.*s%s%s", (int)pn, path, pn ? "." : "", key);
        } else {
            npn = (size_t)snprintf(np, sizeof np, "%.*s%s%u", (int)pn, path, pn ? "." : "", idx++);
        }
        if (npn >= sizeof np) npn = sizeof np - 1;
        p = y_flow_val(f, p, end, np, npn, depth);
    }
}

/* A line of a block: its indent, and the text without it. */
static const char *y_line(const char *p, const char *end, size_t *ind, const char **e) {
    size_t i = 0;
    while (p + i < end && p[i] == ' ') i++;
    const char *s = p + i, *q = s;
    while (q < end && *q != '\n') q++;
    *ind = i;
    *e = q;
    return s;
}

/* One node of a block: p starts its "- …" line (indent dash). Returns the line after the node. */
static const char *y_item(struct yflat *f, const char *p, const char *end, size_t dash) {
    struct lvl { size_t ind; char path[200]; } st[6];
    int sp = 1, first = 1;
    st[0].ind = 0; st[0].path[0] = 0;
    char lastkey[200] = "";
    unsigned seq = 0;
    while (p < end) {
        size_t ind;
        const char *e;
        const char *s = y_line(p, end, &ind, &e);
        const char *next = e < end ? e + 1 : e;
        if (e > s && e[-1] == '\r') e--;
        if (s >= e || *s == '#' || (e - s >= 3 && !strncmp(s, "---", 3))) { p = next; continue; }
        if (first) {
            first = 0;
            s += 1; ind += 1;                                   /* the dash */
            while (s < e && *s == ' ') { s++; ind++; }
            if (s < e && *s == '{') {
                char none[1] = "";
                y_flow(f, s, end, none, 0, 0);
                int d = 0;
                const char *q = s;
                for (; q < end; q++) { if (*q == '{') d++; else if (*q == '}' && --d == 0) break; }
                while (q < end && *q != '\n') q++;
                return q < end ? q + 1 : q;
            }
        } else if (ind <= dash) {
            if (!(ind == dash && 0)) return p;
        }
        if (!first && ind > dash && (*s == '-' && (e - s == 1 || s[1] == ' '))) {
            char v[3300];
            size_t vn;
            y_scalar(s + 1, e, 0, v, sizeof v, &vn);
            char np[200];
            int n2 = snprintf(np, sizeof np, "%s.%u", lastkey, seq++);
            if (lastkey[0] && n2 > 0 && n2 < (int)sizeof np && v[0] != '*') yf_add(f, np, (size_t)n2, v, vn);
            p = next;
            continue;
        }
        while (sp > 1 && st[sp - 1].ind >= ind) sp--;
        char key[96];
        size_t kn;
        const char *c = y_scalar(s, e, 2, key, sizeof key, &kn);
        while (c < e && (*c == ' ' || *c == '\t')) c++;
        if (c >= e || *c != ':') { p = next; continue; }
        c++;
        char np[200];
        int n2 = snprintf(np, sizeof np, "%s%s%s", st[sp - 1].path, st[sp - 1].path[0] ? "." : "", key);
        if (n2 <= 0 || n2 >= (int)sizeof np) { p = next; continue; }
        while (c < e && (*c == ' ' || *c == '\t')) c++;
        if (c >= e || *c == '#') {
            snprintf(lastkey, sizeof lastkey, "%s", np);
            seq = 0;
            if (sp < 6) { st[sp].ind = ind; snprintf(st[sp].path, sizeof st[sp].path, "%s", np); sp++; }
        } else if (*c == '{' || *c == '[') {
            y_flow(f, c, end, np, (size_t)n2, 0);
        } else {
            char v[3300];
            size_t vn;
            y_scalar(c, e, 0, v, sizeof v, &vn);
            if (v[0] != '*') yf_add(f, np, (size_t)n2, v, vn);
        }
        p = next;
    }
    return p;
}

/* A flattened node into a vless node. 1 — it is vless, written into n. */
static int clash_node(const struct yflat *f, struct vless_node *n) {
    memset(n, 0, sizeof *n);
    const char *v;
    if (!(v = yf_get(f, "type")) || strcmp(v, "vless")) return 0;
    snprintf(n->type, sizeof n->type, "tcp");
    if ((v = yf_get(f, "name"))) { sl_set_field(n->name, sizeof n->name, v, strlen(v)); sl_utf8_trim_tail(n->name); }
    if ((v = yf_get(f, "server"))) sl_set_field(n->host, sizeof n->host, v, strlen(v));
    if ((v = yf_get(f, "port"))) n->port = sl_port_of(v);
    if ((v = yf_get(f, "uuid"))) sl_set_field(n->uuid, sizeof n->uuid, v, strlen(v));
    if ((v = yf_get(f, "flow"))) sl_set_field(n->flow, sizeof n->flow, v, strlen(v));
    if ((v = yf_get(f, "servername")) || (v = yf_get(f, "sni"))) sl_set_field(n->sni, sizeof n->sni, v, strlen(v));
    if ((v = yf_get(f, "client-fingerprint"))) sl_set_field(n->fp, sizeof n->fp, v, strlen(v));
    /* Clash/mihomo: `fingerprint` is the SHA-256 of the node's certificate (Xray's
     * pinnedPeerCertSha256), `skip-cert-verify` is allowInsecure. */
    if ((v = yf_get(f, "fingerprint")) && v[0]) sl_add_pins(n, v, 0);
    if ((v = yf_get(f, "skip-cert-verify")) && sl_truthy(v)) n->allow_insecure = 1;
    if ((v = yf_get(f, "ech-opts.config")) && v[0]) sl_set_ech(n, v);
    const char *pbk = yf_get(f, "reality-opts.public-key");
    if (pbk) {
        sl_set_field(n->pbk, sizeof n->pbk, pbk, strlen(pbk));
        if ((v = yf_get(f, "reality-opts.short-id"))) sl_set_field(n->sid, sizeof n->sid, v, strlen(v));
        if ((v = yf_get(f, "reality-opts.mldsa65-verify")) || (v = yf_get(f, "reality-opts.pqv"))) sl_set_pqv(n, v);
        snprintf(n->security, sizeof n->security, "reality");
    } else {
        v = yf_get(f, "tls");
        snprintf(n->security, sizeof n->security, "%s", v && (!strcmp(v, "true") || !strcmp(v, "True")) ? "tls" : "none");
    }
    if ((v = yf_get(f, "encryption"))) set_encryption(n, v);
    const char *net = yf_get(f, "network");
    if (net) {
        if (!strcmp(net, "raw")) net = "tcp";
        sl_set_field(n->type, sizeof n->type, net, strlen(net));
    }
    const char *upg = yf_get(f, "ws-opts.v2ray-http-upgrade");
    if (!strcmp(n->type, "ws") && upg && !strcmp(upg, "true")) snprintf(n->type, sizeof n->type, "httpupgrade");
    if (!strcmp(n->type, "ws") || !strcmp(n->type, "httpupgrade")) {
        struct upg_cfg u;
        memset(&u, 0, sizeof u);
        if ((v = yf_get(f, "ws-opts.path"))) sl_set_field(u.path, sizeof u.path, v, strlen(v));
        if ((v = yf_geti(f, "ws-opts.headers.host"))) sl_set_field(u.host, sizeof u.host, v, strlen(v));
        for (size_t i = 0; i < f->n; i++) {
            const char *k = f->kv[i].k;
            if (strncmp(k, "ws-opts.headers.", 16) != 0 || ci_eq(k + 16, "host")) continue;
            if (hdr_append(u.headers, sizeof u.headers, k + 16, f->kv[i].v) != 0) u.bad = 1;
        }
        const char *ed = yf_get(f, "ws-opts.max-early-data"), *eh = yf_get(f, "ws-opts.early-data-header-name");
        if (ed && atol(ed) > 0 && eh && !strcmp(eh, "Sec-WebSocket-Protocol") && !strchr(u.path, '?')) {
            size_t o = strlen(u.path);
            if (!o) { u.path[0] = '/'; u.path[1] = 0; o = 1; }
            snprintf(u.path + o, sizeof u.path - o, "?ed=%ld", atol(ed));
        }
        snprintf(n->path, sizeof n->path, "%s", u.path);
        snprintf(n->http_host, sizeof n->http_host, "%s", u.host);
        snprintf(n->headers, sizeof n->headers, "%s", u.headers);
        n->headers_bad = u.bad;
    } else if (!strcmp(n->type, "grpc")) {
        if ((v = yf_get(f, "grpc-opts.grpc-service-name"))) sl_set_field(n->service, sizeof n->service, v, strlen(v));
    } else if (!strcmp(n->type, "xhttp")) {
        if ((v = yf_get(f, "xhttp-opts.path"))) sl_set_field(n->path, sizeof n->path, v, strlen(v));
        if ((v = yf_get(f, "xhttp-opts.mode"))) sl_set_field(n->mode, sizeof n->mode, v, strlen(v));
        if ((v = yf_get(f, "xhttp-opts.x-padding-bytes"))) sl_pad_range(n, v);
    }
    return 1;
}

/* Whole Clash YAML. Returns the number of usable nodes; other protocols count in st->foreign. */
static size_t parse_clash(const char *text, struct vless_node *out, size_t max, struct vless_sub_stats *st) {
    const char *end = text + strlen(text), *p = text;
    size_t n = 0, dash = 0;
    int in_list = 0;
    struct yflat *f = malloc(sizeof *f);
    if (!f) return 0;
    while (p < end) {
        size_t ind;
        const char *e;
        const char *s = y_line(p, end, &ind, &e);
        const char *next = e < end ? e + 1 : e;
        if (!in_list) {
            if (ind == 0 && (!strncmp(s, "proxies:", 8) || !strncmp(s, "Proxy:", 6))) {
                const char *c = s + (s[0] == 'p' ? 8 : 6);
                while (c < e && *c == ' ') c++;
                if (c < e && *c != '#') break;                 /* "proxies: []" etc.: no nodes */
                in_list = 1;
                dash = (size_t)-1;
            }
            p = next;
            continue;
        }
        if (s >= e || *s == '#') { p = next; continue; }
        if (ind == 0 && *s != '-') break;                     /* the next top-level key */
        if (*s == '-' && (s + 1 == e || s[1] == ' ')) {
            if (dash == (size_t)-1) dash = ind;
            if (ind != dash) { p = next; continue; }
            f->n = 0; f->used = 0;
            p = y_item(f, p, end, dash);
            struct vless_node node;
            if (!clash_node(f, &node)) { if (st) st->foreign++; continue; }
            if (n >= max) { sl_skip_node(st, &node, "more nodes than fit"); continue; }
            if (node_usable(&node) == 0) { sl_node_ok(&node); out[n++] = node; }
            else sl_skip_node(st, &node, node.skip_reason);
            continue;
        }
        p = next;
    }
    free(f);
    return n;
}

/* Clash YAML? A line starts with "proxies:" (or "Proxy:", the old name). A list of links or base64
 * has no such line: base64 has no colon. */
static int looks_clash(const char *t) {
    for (const char *p = t; *p; ) {
        if (!strncmp(p, "proxies:", 8) || !strncmp(p, "Proxy:", 6)) return 1;
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* Limit on the length of one link. A Reality link with a post-quantum signature (Xray-core 25.9+)
 * carries `pqv`, a whole ML-DSA-65 public key: 1952 bytes, 2603 base64url characters, about 2860
 * bytes for the whole link. 8192 leaves room for ML-DSA-87 (2592 bytes, 3456 characters).
 *
 * pqv is a signature key, not a key exchange: Reality's post-quantum exchange is the
 * X25519MLKEM768 group in key_share (reality.h). With pqv the server also signs its temporary
 * certificate, and the client checks that signature when pqv is set (tls13.c →
 * cert_reality_check_pq).
 *
 * The buffer is on the stack: subscriptions are parsed only on the main thread at startup, never
 * in the threads with small stacks (the stack's connectors have 128 KB). */
#define SUB_LINE_MAX 8192

/* A character of a scheme name: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
 * (RFC 3986 §3.1), lowercase only, as subscriptions write schemes. */
static int scheme_ch(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '+' || c == '.' || c == '-';
}

/* A link glued to this one without a separator, with a scheme the splitter does not know.
 * Returns the "://" of the glued link, or NULL.
 *
 * The splitter in vless_parse_sub steps back by known scheme names on purpose: a rule by form
 * would read "…#one" + "vless://…" as "onevless://", and the second link would stop being a
 * vless link. When the list finds nothing the pair is still glued, but the boundary is unknown,
 * so the node is reported unusable rather than split by a guess.
 *
 * The scheme is not named, for the same reason: stepping back from "://" over scheme characters
 * in "…#oneanytls://…" gives "oneanytls". The example gives what is known for sure, the tail's
 * length and first bytes, which locate the glue in the subscription text.
 *
 * The glued link must also have '@' before any '#': sellers put their channel into node names
 * ("#channel https://t.me/shop"), and a proxy link carries credentials before the host while a
 * channel address does not. Schemes without '@' (vmess as base64, the old ss form) are in the
 * splitter's list and never get here.
 *
 * The first occurrence is returned: the earliest glued point is where the loss starts. */
static const char *glued_tail(const char *b, const char *e) {
    for (const char *q = b + 1; q + 3 <= e; q++) {
        if (strncmp(q, "://", 3) != 0) continue;
        const char *sc = q;
        while (sc > b && scheme_ch(sc[-1])) sc--;
        /* Back at the start of the link: this is its own scheme, nothing to split. */
        if (sc == b) continue;
        size_t sl = (size_t)(q - sc);
        /* 2 to 15 characters: a one-letter "x://" is more likely an accident in a node name
         * than a protocol, and proxy schemes are never longer than 15. The first character
         * is a letter, as RFC 3986 requires. */
        if (sl < 2 || sl > 15 || sc[0] < 'a' || sc[0] > 'z') continue;
        int creds = 0;
        for (const char *t = q + 3; t < e && *t != '#'; t++)
            if (*t == '@') { creds = 1; break; }
        if (!creds) continue;
        return q;
    }
    return NULL;
}

/* Count a glued pair as skipped. Its end is e, not a terminator: the too-long branch does not
 * copy the link and must report a glued pair too, or a glued pair and a really long link would
 * read the same ("link longer than 8191 bytes") although they need different fixes. */
static void glue_note(struct vless_sub_stats *st, const char *glue, const char *e) {
    size_t tail = (size_t)(e - glue);
    size_t show = tail < 32 ? tail : 32;
    struct vless_node t;
    memset(&t, 0, sizeof t);
    snprintf(t.name, sizeof t.name, "tail of %zu bytes: %.*s", tail, (int)show, glue);
    sl_skip_note(st, &t, "links glued without a separator");
}

/* Parse subscription text (already decoded from base64) into nodes. Returns the number of usable
 * nodes; the rest is counted in st (may be NULL). */
size_t vless_parse_sub(const char *text, struct vless_node *out, size_t max,
                       struct vless_sub_stats *st) {
    size_t n = 0;
    if (st) memset(st, 0, sizeof(*st));
    const char *p = text;
    /* The form is told by the first non-blank character, not by a substring search: only JSON
     * starts with '[' or '{'. A search for "://" would match an Xray config only by accident
     * (an https:// URL in its DNS settings). */
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return parse_xray(p, out, max, st);
    if (looks_clash(p)) return parse_clash(p, out, max, st);
    while (*p) {
        while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        /* A link ends at a line break or where the next link's scheme starts: some panels
         * glue links without any separator. */
        const char *e = p;
        while (*e && *e != '\n' && *e != '\r') {
            if (e > p && !strncmp(e, "://", 3)) {
                /* Step back to the start of the scheme by its name, not by character
                 * class: stepping back over letters and digits would take in the tail of
                 * the node name ("…#onevless://b@…"), and the second link would no longer
                 * be a vless link.
                 *
                 * The list is sorted longest first and the first match wins: "ss" matches
                 * the end of "vless", so a shorter name must lose to a longer one. For the
                 * same reason shorter names are not tried after the longest match: if it
                 * is the start of this link, there is nothing to split.
                 *
                 * A node name that ends like a scheme ("…#Express" before "ss://") still
                 * splits right: only the bytes before "://" are compared. */
                static const char *const schemes[] = {
                    "hysteria2", "wireguard", "hysteria", "trojan", "vmess",
                    "vless", "tuic", "hy2", "ssr", "ss"
                };
                const char *s2 = NULL;
                for (size_t si = 0; si < sizeof(schemes) / sizeof(*schemes); si++) {
                    size_t sl = strlen(schemes[si]);
                    if ((size_t)(e - p) < sl) continue;
                    if (strncmp(e - sl, schemes[si], sl) != 0) continue;
                    /* Strictly greater: equal means the scheme of this link itself. */
                    if ((size_t)(e - p) > sl) s2 = e - sl;
                    break;
                }
                if (s2) { e = s2; break; }
            }
            e++;
        }

        char line[SUB_LINE_MAX];
        size_t len = (size_t)(e - p);
        if (len >= sizeof(line)) {
            /* A link longer than the buffer is counted as unusable, not dropped, so the
             * counters still add up. The limit in the message comes from the buffer size, so
             * the two cannot drift apart. */
            char why[64];
            snprintf(why, sizeof why, "link longer than %zu bytes", sizeof(line) - 1);
            const char *glue = strncmp(p, "vless://", 8) ? NULL : glued_tail(p, e);
            if (glue) {
                /* A glued pair is reported before the length: the length is only its
                 * consequence, and "link longer than 8191 bytes" does not tell what to fix. */
                glue_note(st, glue, e);
            } else if (!strncmp(p, "vless://", 8)) {
                /* The example gives the length and the start of the address, telling a link
                 * just over the limit from a blob of many kilobytes; the reason itself cannot,
                 * since sl_skip_note groups by it. It starts after '@': the id before it does
                 * not belong in a log. */
                const char *at = memchr(p, '@', len);
                const char *from = at ? at + 1 : p;
                size_t rest = (size_t)(e - from);
                struct vless_node t;
                memset(&t, 0, sizeof t);
                snprintf(t.name, sizeof t.name, "%zu bytes: %s%.*s", len, at ? "…@" : "",
                         (int)(rest < 32 ? rest : 32), from);
                sl_skip_note(st, &t, why);
            }
            /* A long link of another protocol is counted in foreign, like a short one, so
             * that usable + skipped + foreign still adds up. The test is the same ("://"
             * present), bounded by e since the link was not copied. */
            else if (st) {
                for (const char *q = p; q + 3 <= e; q++)
                    if (!strncmp(q, "://", 3)) { st->foreign++; break; }
            }
        } else {
            memcpy(line, p, len);
            line[len] = '\0';
            /* One reason for every glued pair; what tells the cases apart goes into the
             * example. A glued link is not parsed at all: its name is certainly wrong and its
             * address may be, and a "may be" is worse than a refusal. */
            const char *glue = strncmp(line, "vless://", 8)
                                   ? NULL : glued_tail(line, line + len);
            if (glue) {
                glue_note(st, glue, line + len);
            } else if (!strncmp(line, "vless://", 8)) {
                struct vless_node node;
                int rc = vless_parse_url(line, &node);
                /* rc 1: the parser named the reason. rc -1: the link did not parse at all
                 * (an IPv6 literal host, for one), so the reason is named here. Both are
                 * counted, and so is a node that does not fit: usable + skipped + foreign
                 * must add up to the number of links. */
                if (rc == 0 && n < max) { sl_node_ok(&node); out[n++] = node; }
                else if (rc == 0) sl_skip_node(st, &node, "more nodes than fit");
                else sl_skip_node(st, &node, rc > 0 ? node.skip_reason
                                                 : "cannot parse the link");
            } else if (strstr(line, "://") && st) {
                /* Another protocol: counted, not parsed. */
                st->foreign++;
            }
        }
        p = e;
    }
    return n;
}

/* Turn a subscription file as read into text that vless_parse_sub understands:
 *   '[' or '{' first   — a JSON config, returned as is;
 *   a "proxies:" line  — Clash YAML, returned as is;
 *   "://" anywhere     — a list of links, returned as is;
 *   otherwise          — base64, decoded into dec.
 * Returns raw or dec; both are the caller's buffers. */
const char *vless_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n) {
    const char *p = raw;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return raw;
    if (looks_clash(p)) return raw;
    if (strstr(raw, "://")) return raw;
    b64_decode(raw, raw_n, dec, dec_n);
    return dec;
}

/* How many times "vless" occurs in text, in any case: every VLESS node has it in its own text
 * (vless://, "protocol": "vless", "type": "vless", type: vless), so this bounds the node count. */
static size_t count_vless(const char *text) {
    size_t n = 0;
    for (const char *q = text; *q; q++)
        if ((*q == 'v' || *q == 'V') && !strncasecmp(q, "vless", 5)) n++;
    return n;
}

/* A whole subscription file. Buffers and the node array are on the heap, sized by the file: one
 * node slot per "vless" in the text.
 * The 64 MiB cap guards against a file that is not a subscription (a thousand nodes take hundreds
 * of kilobytes). NULL — the file did not open, is too large, or no memory; otherwise an array to
 * free, *cnt — usable nodes. */
#define VLESS_SUB_FILE_MAX ((size_t)64 << 20)
struct vless_node *vless_load_sub(const char *path, size_t *cnt, struct vless_sub_stats *st) {
    *cnt = 0;
    if (st) memset(st, 0, sizeof(*st));
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fl = ftell(f);
    rewind(f);
    if (fl < 0 || (size_t)fl > VLESS_SUB_FILE_MAX) { fclose(f); return NULL; }
    size_t sz = (size_t)fl;
    char *raw = malloc(sz + 1), *dec = malloc(sz + 16);
    if (!raw || !dec) { fclose(f); free(raw); free(dec); return NULL; }
    size_t n = fread(raw, 1, sz, f);
    fclose(f);
    raw[n] = '\0';
    dec[0] = '\0';
    const char *text = vless_sub_text(raw, n, dec, sz + 16);
    size_t hint = 1 + count_vless(text);
    struct vless_node *nodes = calloc(hint, sizeof(*nodes));
    if (nodes) *cnt = vless_parse_sub(text, nodes, hint, st);
    free(raw);
    free(dec);
    return nodes;
}
