/* The transport and security half of a node link: link strings, transport and security
 * parameters, and whether they are usable. sublink.h says what is here and what is in sub.c. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "vless.h"
#include "sublink.h"
/* tr_upgrade_target: a ws or httpupgrade path is checked here by the same rule the transport
 * builds the request with (src/proto/transport/trpath.c: strings only, no network or libraries). */
#include "trpath.h"
/* vencp_b64url_len: the pqv key length uses the same base64url arithmetic as VLESS encryption.
 * Strings only, no cryptography. */
#include "vencp.h"

/* base64 decoding as subscriptions need it: line breaks inside, '=' padding optional, and the
 * URL-safe alphabet accepted too (some panels serve it). */
static int b64val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

size_t b64_decode(const char *in, size_t n, char *out, size_t out_n) {
    size_t o = 0;
    /* Unsigned and masked: only the low bits+8 bits are ever read (bits is at most 7 after the
     * decrement). A signed accumulator that kept the high bits overflowed on a long
     * subscription, which is undefined behaviour on untrusted text. */
    unsigned acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        /* '=' ends a block: the leftover bits are its remainder, not the start of the next
         * one. Without the reset, concatenated padded blocks ("QQ==QQ==") would shift
         * everything after them. */
        if (in[i] == '=') { acc = 0; bits = 0; continue; }
        int v = b64val((unsigned char)in[i]);
        if (v < 0) continue;                  /* line breaks, junk */
        acc = ((acc << 6) | (unsigned)v) & 0x3FFFu;   /* 14 bits are enough: 7 + 6 + 1 */
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o + 1 < out_n) out[o++] = (char)((acc >> bits) & 0xFF);
        }
    }
    if (o < out_n) out[o] = '\0';
    return o;
}

/* An address where no peer can ever be: unspecified (0.0.0.0, ::), loopback (127.0.0.0/8, ::1)
 * and broadcast. Private networks are not on the list: a node in 10.0.0.0/8 is a valid setup
 * inside a LAN or over another tunnel.
 *
 * Names are not resolved: a parser of untrusted text does not go to the network. Panel stubs
 * write the address in digits, so comparing strings is enough.
 */
int sl_host_leads_nowhere(const char *h) {
    if (!h || !h[0]) return 1;
    if (!strcmp(h, "0.0.0.0") || !strcmp(h, "::") || !strcmp(h, "[::]")) return 1;
    if (!strcmp(h, "::1") || !strcmp(h, "[::1]")) return 1;
    if (!strcmp(h, "255.255.255.255")) return 1;
    /* All of 127.0.0.0/8: stubs use both 127.0.0.1 and 127.0.0.53. */
    if (!strncmp(h, "127.", 4)) {
        const char *p = h + 4;
        while (*p) { if ((*p < '0' || *p > '9') && *p != '.') return 0; p++; }
        return 1;
    }
    return 0;
}

/* A name or an address. security=tls needs to know: certificates are issued to names, so a node
 * given by an address without sni has nothing to verify against.
 *
 * Judged as a string, without inet_pton or network headers: a colon or a bracket means IPv6, only
 * digits and dots mean IPv4, anything else is a name. A wrong guess can only call something a
 * name, and the certificate is still verified for real. */
int sl_host_is_name(const char *h) {
    if (!h || !h[0]) return 0;
    if (strchr(h, ':') || h[0] == '[') return 0;
    for (const char *p = h; *p; p++)
        if ((*p < '0' || *p > '9') && *p != '.') return 1;
    return 0;
}

static int pct_hex(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c |= 32;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

void sl_pct_decode(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '%' && r[1] && r[2]) {
            /* Both must be hex digits: otherwise "%@@" in a node name would become a byte of
             * broken UTF-8. */
            int hi = pct_hex(r[1]), lo = pct_hex(r[2]);
            if (hi >= 0 && lo >= 0) {
                *w++ = (char)((hi << 4) | lo);
                r += 2;
                continue;
            }
        }
        *w++ = *r;
    }
    *w = '\0';
}

void sl_set_field(char *dst, size_t n, const char *src, size_t len) {
    if (len >= n) len = n - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Decode first, then cut: a path in percent form (`%2Fstatic%2Fv1…`, as many panels encode it)
 * is up to three times longer than the path, and cutting it first sends a different path: the
 * xhttp or ws server answers 404 although the node is fine. */
void sl_set_pct(char *dst, size_t n, const char *src, size_t len) {
    char tmp[512];
    sl_set_field(tmp, sizeof(tmp), src, len);
    sl_pct_decode(tmp);
    sl_set_field(dst, n, tmp, strlen(tmp));
}

/* Drop an incomplete UTF-8 sequence from the end. A buffer cuts strings by byte, and the cut may
 * fall inside a character; what is left is a byte no consumer can interpret, so losing the last
 * character is better. */
void sl_utf8_trim_tail(char *s) {
    size_t n = strlen(s);
    if (!n) return;
    unsigned char last = (unsigned char)s[n - 1];
    if (last < 0x80) return;                       /* ASCII: nothing was cut */
    if ((last & 0xC0) != 0x80) { s[n - 1] = '\0'; return; }  /* a lead byte with no continuation */

    /* A continuation byte last: step back to the lead byte and check the length. */
    size_t at = n - 1, cont = 1;
    while (at && ((unsigned char)s[at - 1] & 0xC0) == 0x80) { at--; cont++; }
    if (!at) { s[0] = '\0'; return; }              /* only continuation bytes: all junk */
    unsigned char lead = (unsigned char)s[at - 1];
    /* ASCII before the continuation bytes: there is no lead byte, so only the continuation
     * bytes go and "ab\x80" keeps its "b". */
    if (lead < 0x80) { s[at] = '\0'; return; }
    size_t need = (lead & 0xE0) == 0xC0 ? 1 :
                  (lead & 0xF0) == 0xE0 ? 2 :
                  (lead & 0xF8) == 0xF0 ? 3 : 0;
    if (need && cont == need) return;              /* the sequence is complete */
    s[at - 1] = '\0';
}

/* Node name: the one field where a subscription puts anything, UTF-8 included, so a cut by bytes
 * shows. Order matters: drop a percent escape the cut left incomplete, decode, then drop an
 * incomplete UTF-8 sequence (it may come from the percent form or from raw bytes in the
 * fragment). */
void sl_set_name(char *dst, size_t n, const char *src) {
    size_t len = strlen(src);
    int cut = len >= n;
    sl_set_field(dst, n, src, len);
    if (cut) {
        size_t l = strlen(dst);
        if (l >= 1 && dst[l - 1] == '%') dst[l - 1] = '\0';
        else if (l >= 2 && dst[l - 2] == '%') dst[l - 2] = '\0';
    }
    sl_pct_decode(dst);
    sl_utf8_trim_tail(dst);
}

/* xhttp padding length from `xPaddingBytes`: a number ("512") or a range ("50-150"), both valid
 * in Xray. Parsed by hand rather than with sscanf, since the text is untrusted.
 *
 * If nothing parses, the fields stay as they are and Xray's default applies: unreadable padding
 * is no reason to reject the node, and the default suits most servers. */
static int sl_range(const char *v, unsigned long max, unsigned long *from, unsigned long *to) {
    unsigned long a = 0, b = 0;
    const char *p = v;
    while (*p == ' ' || *p == '"') p++;
    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') { a = a * 10 + (unsigned)(*p - '0'); p++; if (a > max) return -1; }
    if (*p == '-') {
        p++;
        if (*p < '0' || *p > '9') return -1;
        while (*p >= '0' && *p <= '9') { b = b * 10 + (unsigned)(*p - '0'); p++; if (b > max) return -1; }
    } else {
        b = a;
    }
    if (b < a) return -1;
    *from = a;
    *to = b;
    return 0;
}

void sl_pad_range(struct vless_node *n, const char *v) {
    unsigned long a, b;
    if (sl_range(v, 65535, &a, &b) != 0) return;
    n->pad_from = (uint16_t)a;
    n->pad_to = (uint16_t)b;
}

/* xhttp `scMaxEachPostBytes`, in the same forms. 0 is no limit Xray would accept (its client
 * cannot split by it): left at the default. */
void sl_post_range(struct vless_node *n, const char *v) {
    unsigned long a, b;
    if (sl_range(v, 100000000, &a, &b) != 0 || a == 0) return;
    n->post_from = (uint32_t)a;
    n->post_to = (uint32_t)b;
}

/* xhttp settings that change the requests on the wire into a form the client does not produce
 * (Xray 26.3 names): the session id or seq outside the path, upload data in headers or cookies,
 * tokenish padding, obfuscated padding, a separate download server. A node with one of them
 * would not open, since the server expects a different request, so rejecting it early with a
 * reason loses nothing.
 *
 * By VALUE, not by presence: panels write the defaults out ("path", "auto", "repeat-x"), and those
 * are exactly what the client sends. uplinkHTTPMethod and xPaddingPlacement are not here: the
 * server does not check the method, and the placement matters only with xPaddingObfsMode. */
int sl_xh_setting_bad(const char *key, const char *val) {
    if (!val || !val[0] || !strcmp(val, "null")) return 0;
    if (!strcmp(key, "downloadSettings")) return 1;
    if (!strcmp(key, "sessionPlacement") || !strcmp(key, "sessionIDPlacement") ||
        !strcmp(key, "seqPlacement"))
        return strcmp(val, "path") != 0;
    if (!strcmp(key, "uplinkDataPlacement")) return strcmp(val, "auto") && strcmp(val, "body");
    if (!strcmp(key, "xPaddingMethod")) return strcmp(val, "repeat-x") != 0;
    if (!strcmp(key, "xPaddingObfsMode")) return !strcmp(val, "true");
    return 0;
}

static int xh_extra_bad(const char *json) {
    static const char *const keys[] = { "downloadSettings", "sessionPlacement", "sessionIDPlacement",
                                        "seqPlacement", "uplinkDataPlacement", "xPaddingMethod",
                                        "xPaddingObfsMode" };
    for (size_t i = 0; i < sizeof keys / sizeof *keys; i++) {
        char q[32];
        snprintf(q, sizeof q, "\"%s\"", keys[i]);
        const char *k = strstr(json, q);
        if (!k || !(k = strchr(k + strlen(q), ':'))) continue;
        k++;
        while (*k == ' ') k++;
        /* The value: a string's contents, or the bare token (true, null, an object's brace). */
        char v[32];
        size_t l = 0;
        if (*k == '"') {
            k++;
            while (k[l] && k[l] != '"' && l < sizeof v - 1) l++;
        } else {
            while (k[l] && k[l] != ',' && k[l] != '}' && k[l] != ' ' && l < sizeof v - 1) l++;
            if (*k == '{') l = 1;
        }
        memcpy(v, k, l);
        v[l] = 0;
        if (sl_xh_setting_bad(keys[i], v)) return 1;
    }
    return 0;
}

/* `extra` is xhttp settings in JSON (a link's is percent-decoded first). Only the padding length
 * and the obfuscation keys matter here; the rest (xmux, connection reuse) belongs to a
 * multiplexer the client does not have. So the keys are searched for by name instead of parsing
 * the object. */
void sl_parse_extra(struct vless_node *n, const char *extra) {
    if (xh_extra_bad(extra)) n->xh_extra = 1;
    const char *k = strstr(extra, "\"xPaddingBytes\"");
    if (k && (k = strchr(k + 15, ':'))) sl_pad_range(n, k + 1);
    k = strstr(extra, "\"scMaxEachPostBytes\"");
    if (k && (k = strchr(k + 20, ':'))) sl_post_range(n, k + 1);
}


/* ---- long node values: encryption, pqv, certificate pins ----------------------------------------
 *
 * The values are long (an ML-DSA-65 key is 2603 base64url characters, a VLESS encryption string
 * with an ML-KEM-768 key about 1600), and a field for them would add kilobytes to every node for
 * what few nodes have. So a node holds a pointer into a shared table where equal values are
 * stored once. Strings are never freed: the pointer must outlive the node and its copies (nodes
 * are copied by value), and parsing the same subscription again finds them already there. The
 * table is bounded: when it is full the node is unusable with a named reason, so a hostile
 * subscription with random keys cannot keep growing memory. */
#define SUB_INTERN_MAX 256
static const char *g_intern[SUB_INTERN_MAX];
static volatile int g_intern_lock;
/* Markers of unusable values (did not parse, or the table is full); sl_link_usable_pre names
 * the reason. */
const char SL_BAD_PQV[] = "!pqv";
const char SL_FULL[] = "!full";

static __thread const char *(*g_interner)(const char *v, size_t n);

void sl_set_interner(const char *(*fn)(const char *v, size_t n)) { g_interner = fn; }

const char *sl_intern(const char *v, size_t n) {
    if (g_interner) {
        const char *r = g_interner(v, n);
        return r ? r : SL_FULL;
    }
    while (__atomic_test_and_set(&g_intern_lock, __ATOMIC_ACQUIRE)) { }
    const char *r = SL_FULL;
    for (int i = 0; i < SUB_INTERN_MAX; i++) {
        if (!g_intern[i]) {
            char *c = malloc(n + 1);
            if (c) { memcpy(c, v, n); c[n] = '\0'; g_intern[i] = c; r = c; }
            break;
        }
        if (strlen(g_intern[i]) == n && !memcmp(g_intern[i], v, n)) { r = g_intern[i]; break; }
    }
    __atomic_clear(&g_intern_lock, __ATOMIC_RELEASE);
    return r;
}

void sl_intern_reset(void) {
    while (__atomic_test_and_set(&g_intern_lock, __ATOMIC_ACQUIRE)) { }
    for (int i = 0; i < SUB_INTERN_MAX; i++) {
        free((void *)g_intern[i]);
        g_intern[i] = NULL;
    }
    __atomic_clear(&g_intern_lock, __ATOMIC_RELEASE);
}

/* pqv / mldsa65Verify: an ML-DSA-65 public key, base64url, exactly 1952 bytes. */
void sl_set_pqv(struct vless_node *n, const char *v) {
    n->pqv = NULL;
    if (!v[0]) return;
    if (vencp_b64url_len(v, strlen(v)) != 1952) { n->pqv = SL_BAD_PQV; return; }
    n->pqv = sl_intern(v, strlen(v));
}

/* ---- certificate checks of a node: pcs, pks, vcn, allowInsecure ---------------------------------
 *
 * Xray-core (transport/internet/tls/config.go, infra/conf/transport_security.go) has two ways not
 * to rely on the root store: pinnedPeerCertSha256 (`pcs` in a link) — hex SHA-256 of the
 * certificate, comma separated, OpenSSL colons allowed; verifyPeerCertByName (`vcn`) — names the
 * chain is verified against INSTEAD of the SNI. Xray dropped allowInsecure (a config with it does
 * not load), but links and other subscriptions still carry it. sing-box pins differently: base64
 * SHA-256 of the SubjectPublicKeyInfo (`certificate_public_key_sha256`). It is kept apart (pks)
 * because it hashes another part of the certificate, and the two kinds must not be mixed.
 *
 * A pin is brought to one form (64 lowercase hex digits) here, when parsed: a bad pin makes the
 * node unusable with a named reason, rather than a check that silently compares nothing. */
const char SL_BAD_PIN[] = "!pin";

static const char *pin_slot(const struct vless_node *n, int spki) { return spki ? n->pks : n->pcs; }

static void add_pins(struct vless_node *n, const char *v, int spki, int hex) {
    const char *cur = pin_slot(n, spki);
    if (cur == SL_BAD_PIN || cur == SL_FULL) return;
    char buf[1100];
    size_t bl = 0;
    if (cur) bl = (size_t)snprintf(buf, sizeof buf, "%s", cur);
    const char *p = v;
    int bad = 0;
    while (*p && !bad) {
        const char *e = strchr(p, ',');
        size_t tn = e ? (size_t)(e - p) : strlen(p);
        while (tn && (*p == ' ' || *p == '\t')) { p++; tn--; }
        while (tn && (p[tn - 1] == ' ' || p[tn - 1] == '\t')) tn--;
        unsigned char raw[32] = { 0 };
        if (tn) {
            if (!hex) {
                char d[48];
                bad = tn < 43 || tn > 44 || b64_decode(p, tn, d, sizeof d) != 32;
                if (!bad) memcpy(raw, d, 32);
            } else {
                /* Colons are the usual OpenSSL notation (`AB:CD:…`); Xray drops them. */
                size_t k = 0;
                for (size_t i = 0; i < tn && !bad; i++) {
                    int c = (unsigned char)p[i], h;
                    if (c == ':') continue;
                    h = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                        : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
                    if (h < 0 || k >= 64) { bad = 1; break; }
                    if (k & 1) raw[k / 2] = (unsigned char)(raw[k / 2] << 4 | h);
                    else raw[k / 2] = (unsigned char)h;
                    k++;
                }
                if (!bad && k != 64) bad = 1;
            }
            if (!bad) {
                if (bl + 66 >= sizeof buf) bad = 1;
                else {
                    if (bl) buf[bl++] = ',';
                    for (int i = 0; i < 32; i++) bl += (size_t)snprintf(buf + bl, 3, "%02x", raw[i]);
                }
            }
        }
        if (!e) break;
        p = e + 1;
    }
    const char *r = bad ? SL_BAD_PIN : bl ? sl_intern(buf, bl) : NULL;
    if (spki) n->pks = r; else n->pcs = r;
}

void sl_add_pins(struct vless_node *n, const char *v, int spki) { add_pins(n, v, spki, !spki); }

/* verifyPeerCertByName: comma separated names, surrounding blanks dropped, empty ones skipped
 * (as Xray reads it). */
void sl_set_vcn(struct vless_node *n, const char *v) {
    char buf[300];
    size_t bl = 0;
    n->vcn = NULL;
    const char *p = v;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t tn = e ? (size_t)(e - p) : strlen(p);
        while (tn && (*p == ' ' || *p == '\t')) { p++; tn--; }
        while (tn && (p[tn - 1] == ' ' || p[tn - 1] == '\t')) tn--;
        if (tn) {
            if (bl + tn + 2 >= sizeof buf) { n->vcn = SL_BAD_PIN; return; }
            if (bl) buf[bl++] = ',';
            memcpy(buf + bl, p, tn);
            bl += tn;
        }
        if (!e) break;
        p = e + 1;
    }
    if (bl) n->vcn = sl_intern(buf, bl);
}

/* ECH: the node's ECHConfigList in base64 (Xray echConfigList, `ech=` in a link, Clash
 * ech-opts.config, sing-box ech.config). Only the form is checked here: the list starts with its
 * length and holds a version 0xfe0d entry. Which entry is usable is decided by ech_pick at connect
 * time (ech.c is not linked into the subscription tests). A "domain+https://DNS server" value
 * (Xray fetches the config from DNS) is not supported: the node is skipped with a reason rather
 * than sent without ECH, since sending the name in clear is what ECH is there to prevent. */
const char SL_BAD_ECH[] = "!ech";
const char SL_ECH_DNS[] = "!ech-dns";
void sl_set_ech(struct vless_node *n, const char *v) {
    char raw[1100];
    n->ech = NULL;
    if (!v[0]) return;
    if (strstr(v, "://")) { n->ech = SL_ECH_DNS; return; }
    size_t bl = b64_decode(v, strlen(v), raw, sizeof raw);
    int ok = bl >= 8 && bl < sizeof raw && (size_t)(((unsigned char)raw[0] << 8) | (unsigned char)raw[1]) + 2 == bl;
    if (ok) {
        ok = 0;
        for (size_t p = 2; p + 4 <= bl;) {
            size_t l = ((unsigned char)raw[p + 2] << 8) | (unsigned char)raw[p + 3];
            if (p + 4 + l > bl) { ok = 0; break; }
            if ((((unsigned char)raw[p] << 8) | (unsigned char)raw[p + 1]) == 0xfe0d) ok = 1;
            p += 4 + l;
        }
    }
    n->ech = ok ? sl_intern(v, strlen(v)) : SL_BAD_ECH;
}

/* allowInsecure / insecure / skip-cert-verify: 1, true, yes — on. Anything else, empty included, is
 * off: certificate checks are never turned off by a guess. */
static int sl_printable(const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (*p < 0x20 || *p == 0x7f) return 0;
    return 1;
}

int sl_truthy(const char *v) {
    return !strcmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "yes");
}

/* --insecure (vless.h). */
static volatile int g_insecure;
void vless_set_insecure(int on) { g_insecure = on ? 1 : 0; }
int vless_insecure(void) { return g_insecure; }

/* On the heap, at the value's full length: pqv and encryption values run to thousands of
 * characters, and a fixed buffer would cut them. */
char *sl_param_dup(const char *v, size_t vlen) {
    char *c = malloc(vlen + 1);
    if (!c) return NULL;
    memcpy(c, v, vlen);
    c[vlen] = '\0';
    sl_pct_decode(c);
    return c;
}

int sl_uuid_parse(const char *s, unsigned char out[16]) {
    int hi = -1;
    size_t k = 0;
    for (; *s && k < 16; s++) {
        if (*s == '-') continue;
        int c = (unsigned char)*s, v;
        v = c >= '0' && c <= '9' ? c - '0' : (c | 32) >= 'a' && (c | 32) <= 'f' ? (c | 32) - 'a' + 10 : -1;
        if (v < 0) return -1;
        if (hi < 0) hi = v;
        else { out[k++] = (unsigned char)(hi << 4 | v); hi = -1; }
    }
    /* Exactly 16 bytes, no dangling nibble, and nothing after it but hyphens. */
    while (*s == '-') s++;
    return (k == 16 && hi < 0 && !*s) ? 0 : -1;
}

uint16_t sl_port_of(const char *s) {
    if (!*s) return 0;
    unsigned long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
        v = v * 10 + (unsigned long)(*s - '0');
        if (v > 65535) return 0;
    }
    return (uint16_t)v;
}


/* A header the request can carry as it is: a name of HTTP token characters, up to 40, and a value
 * up to 250 without control characters (a line break would turn one header into two). */
int sl_hdr_valid(const char *key, const char *val) {
    size_t kn = strlen(key), vn = strlen(val);
    if (!kn || kn > 40 || vn > 250) return 0;
    for (size_t i = 0; i < kn; i++) {
        unsigned char c = (unsigned char)key[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              strchr("!#$%&'*+-.^_`|~", c)))
            return 0;
    }
    for (size_t i = 0; i < vn; i++) {
        unsigned char c = (unsigned char)val[i];
        if ((c < 0x20 && c != '\t') || c == 0x7f) return 0;
    }
    return 1;
}

static int hdr_lines_ok(const char *s, int ws) {
    while (*s) {
        const char *e = strchr(s, '\n'), *c = strchr(s, ':');
        if (!e || !c || c > e || c[1] != ' ') return 0;
        char k[64], v[256];
        size_t kn = (size_t)(c - s), vn = (size_t)(e - c - 2);
        if (kn >= sizeof k || vn >= sizeof v) return 0;
        memcpy(k, s, kn); k[kn] = '\0';
        memcpy(v, c + 2, vn); v[vn] = '\0';
        if (!sl_hdr_valid(k, v) || !strcasecmp(k, "host")) return 0;
        if (ws && (!strcasecmp(k, "upgrade") || !strcasecmp(k, "connection") || !strcasecmp(k, "sec-websocket-key") ||
                   !strcasecmp(k, "sec-websocket-version") || !strcasecmp(k, "sec-websocket-extensions")))
            return 0;
        s = e + 1;
    }
    return 1;
}

/* A ws or httpupgrade node: what Xray itself would fail on, caught in advance with a reason.
 * 1 — unusable (reason in skip_reason).
 *
 *   - no Vision (flow xtls-rprx-vision) over them: Xray needs bare TLS or REALITY for Vision and
 *     refuses ("failed to use xtls-rprx-vision, maybe "security" is not "tls"…"), and this
 *     client's Vision direct copy would read the raw socket, bypassing the ws framing;
 *   - a path Xray would not parse unambiguously, or ws would not open at all (trpath.h): the same
 *     rule as the transport, so "usable" here means "opens" there;
 *   - host is the Host header: no blanks or control characters, or the request line breaks;
 *   - config headers that did not fit or are invalid (headers_bad, see xray_headers in sub.c). */
static int upg_node_bad(struct vless_node *n, int ws) {
    if (n->flow[0]) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "vision cannot run over %s", n->type);
        return 1;
    }
    char tgt[1024];
    const char *why = "";
    if (tr_upgrade_target(n->path, ws, tgt, sizeof(tgt), &why) != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%s", why);
        return 1;
    }
    for (const char *p = n->http_host; *p; p++) {
        if ((unsigned char)*p <= 0x20 || *p == 0x7f) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "invalid host for %s", n->type);
            return 1;
        }
    }
    if (n->headers_bad || !hdr_lines_ok(n->headers, ws)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "invalid headers for %s", n->type);
        return 1;
    }
    return 0;
}


int sl_link_param(struct vless_node *n, const char *k, size_t klen, const char *v, size_t vlen) {
    if (klen == 4 && !strncmp(k, "type", 4)) sl_set_pct(n->type, sizeof(n->type), v, vlen);
    else if (klen == 8 && !strncmp(k, "security", 8)) sl_set_pct(n->security, sizeof(n->security), v, vlen);
    else if (klen == 3 && !strncmp(k, "sni", 3)) sl_set_pct(n->sni, sizeof(n->sni), v, vlen);
    else if (klen == 2 && !strncmp(k, "fp", 2)) sl_set_pct(n->fp, sizeof(n->fp), v, vlen);
    else if (klen == 3 && !strncmp(k, "pbk", 3)) sl_set_pct(n->pbk, sizeof(n->pbk), v, vlen);
    else if (klen == 3 && !strncmp(k, "sid", 3)) sl_set_pct(n->sid, sizeof(n->sid), v, vlen);
    else if (klen == 10 && !strncmp(k, "headerType", 10)) { if (vlen == 4 && !strncmp(v, "http", 4)) n->tcp_http = 1; }
    /* pqv: Xray-core's post-quantum check of Reality, an ML-DSA-65 signature in the server's
     * temporary certificate. A long value, see sl_intern. */
    else if (klen == 3 && !strncmp(k, "pqv", 3)) {
        char *d = sl_param_dup(v, vlen);
        if (d) { sl_set_pqv(n, d); free(d); } else n->pqv = SL_BAD_PQV;
    }
    /* pcs / vcn: Xray-core's pinnedPeerCertSha256 and verifyPeerCertByName. A subscription may
     * carry allowInsecure (or insecure, as panels write it), but cannot turn the check off by
     * itself: see sl_link_usable_pre. */
    else if ((klen == 3 && !strncmp(k, "pcs", 3)) || (klen == 3 && !strncmp(k, "vcn", 3))) {
        char *d = sl_param_dup(v, vlen);
        if (d) {
            if (k[0] == 'p') sl_add_pins(n, d, 0); else sl_set_vcn(n, d);
            free(d);
        } else if (k[0] == 'p') n->pcs = SL_BAD_PIN; else n->vcn = SL_BAD_PIN;
    }
    else if (klen == 3 && !strncmp(k, "pks", 3)) {
        char *d = sl_param_dup(v, vlen);
        if (d) { add_pins(n, d, 1, 1); free(d); } else n->pks = SL_BAD_PIN;
    }
    else if (klen == 7 && !strncmp(k, "headers", 7)) {
        char *d = sl_param_dup(v, vlen);
        if (d && strlen(d) < sizeof(n->headers) && hdr_lines_ok(d, 0)) snprintf(n->headers, sizeof(n->headers), "%s", d);
        else n->headers_bad = 1;
        free(d);
    }
    else if (klen == 3 && !strncmp(k, "ech", 3)) {
        char *d = sl_param_dup(v, vlen);
        if (d) { sl_set_ech(n, d); free(d); } else n->ech = SL_BAD_ECH;
    }
    else if ((klen == 13 && !strncmp(k, "allowInsecure", 13)) || (klen == 8 && !strncmp(k, "insecure", 8))) {
        char *d = sl_param_dup(v, vlen);
        if (d) { if (sl_truthy(d)) n->allow_insecure = 1; free(d); }
    }
    else if (klen == 4 && !strncmp(k, "path", 4)) sl_set_pct(n->path, sizeof(n->path), v, vlen);
    else if (klen == 11 && !strncmp(k, "serviceName", 11)) sl_set_pct(n->service, sizeof(n->service), v, vlen);
    else if (klen == 4 && !strncmp(k, "mode", 4)) sl_set_pct(n->mode, sizeof(n->mode), v, vlen);
    /* host: the Host header of ws and httpupgrade. xhttp links carry it too, but xhttp does not
     * use it: its :authority is the sni, else the address. */
    else if (klen == 4 && !strncmp(k, "host", 4)) sl_set_pct(n->http_host, sizeof(n->http_host), v, vlen);
    /* extra: xhttp settings in JSON, read for the padding length (the server checks it and
     * answers 400 to a wrong one) and obfuscation. The buffer is sized for the percent form, up
     * to three times longer than the JSON: it is cut before decoding, and a buffer sized for the
     * JSON would silently lose xPaddingBytes further in. */
    else if (klen == 5 && !strncmp(k, "extra", 5)) {
        char ex[2048];
        sl_set_field(ex, sizeof(ex), v, vlen);
        sl_pct_decode(ex);
        sl_parse_extra(n, ex);
    }
    else return 0;
    return 1;
}

int sl_link_parse(const char *url, const char *scheme, struct vless_node *n, sl_own_fn own,
                  const char **secret, size_t *secret_n) {
    memset(n, 0, sizeof(*n));
    size_t scl = strlen(scheme);
    if (strncmp(url, scheme, scl) != 0) return -1;
    const char *p = url + scl;

    const char *at = strchr(p, '@');
    if (!at) return -1;
    sl_set_field(n->uuid, sizeof(n->uuid), p, (size_t)(at - p));
    if (secret) *secret = p;
    if (secret_n) *secret_n = (size_t)(at - p);

    p = at + 1;
    /* Host and port end at '?' or '#', parameters end at '#': a name "Fast?type=ws" is not
     * parameters, and "host?type=tcp#name:1" has no port 1. */
    const char *hash = strchr(p, '#');
    const char *hp_end = hash ? hash : p + strlen(p);
    const char *qmark = memchr(p, '?', (size_t)(hp_end - p));
    const char *colon = memchr(p, ':', (size_t)((qmark ? qmark : hp_end) - p));
    if (!colon) return -1;
    sl_set_field(n->host, sizeof(n->host), p, (size_t)(colon - p));
    {
        /* Digits only, up to the end of the host, 1..65535: atoi with a cast would turn
         * ":70000" into 4464, ":-1" into 65535 and ":443abc" into 443. */
        char pnum[8];
        const char *pe = colon + 1;
        size_t pl = 0;
        while (pe < (qmark ? qmark : hp_end) && *pe >= '0' && *pe <= '9' && pl + 1 < sizeof(pnum))
            pnum[pl++] = *pe++;
        pnum[pl] = '\0';
        if (!pl || pe != (qmark ? qmark : hp_end)) return -1;
        n->port = sl_port_of(pnum);
    }
    if (!n->port) return -1;

    if (hash) {
        sl_set_name(n->name, sizeof(n->name), hash + 1);
    }

    /* Defaults VLESS implies for omitted fields: type=tcp here, security=none in
     * sl_link_usable_pre. */
    snprintf(n->type, sizeof(n->type), "tcp");
    if (qmark) {
        const char *end = hash && hash > qmark ? hash : qmark + strlen(qmark);
        const char *k = qmark + 1;
        while (k < end) {
            const char *amp = memchr(k, '&', (size_t)(end - k));
            const char *stop = amp ? amp : end;
            const char *eq = memchr(k, '=', (size_t)(stop - k));
            if (eq) {
                size_t klen = (size_t)(eq - k), vlen = (size_t)(stop - eq - 1);
                const char *v = eq + 1;
                if (!own || !own(n, k, klen, v, vlen)) sl_link_param(n, k, klen, v, vlen);
            }
            if (!amp) break;
            k = amp + 1;
        }
    }

    return 0;
}

/* First half of the usability check (sublink.h). Reasons must fit in skip_reason (96 bytes). */
int sl_link_usable_pre(struct vless_node *n) {
    if (!n->security[0]) snprintf(n->security, sizeof(n->security), "none");

    /* Post-quantum fields. The markers come from parsing (set_encryption in sub.c, sl_set_pqv): a
     * value that breaks Xray's rule, or a full table of long values. */
    if (!sl_printable(n->type) || !sl_printable(n->security) || !sl_printable(n->mode)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "control byte in type, security or mode");
        return 1;
    }
    if (n->pqv == SL_BAD_PQV) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "pqv: not an ML-DSA-65 key");
        return 1;
    }
    if (n->tcp_http && !strcmp(n->type, "tcp")) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "tcp headerType=http is not supported");
        return 1;
    }
    if (n->xh_extra && !strcmp(n->type, "xhttp")) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "xhttp: obfuscation is not supported");
        return 1;
    }
    if (n->encryption == SL_FULL || n->pqv == SL_FULL || n->pcs == SL_FULL || n->pks == SL_FULL ||
        n->vcn == SL_FULL) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "too many distinct keys");
        return 1;
    }
    /* Certificate checks concern only security=tls: reality proves the server by its own
     * protocol, and pcs/vcn/allowInsecure in such a link mean nothing. A bad pin on tls makes the
     * node unusable rather than leaving a check that silently verifies nothing. */
    if (!strcmp(n->security, "tls")) {
        if (n->ech == SL_BAD_ECH) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "ech: not a base64 ECHConfigList");
            return 1;
        }
        if (n->ech == SL_ECH_DNS) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "ech: DNS lookup is not supported");
            return 1;
        }
        if (n->ech == SL_FULL) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "too many distinct keys");
            return 1;
        }
        if (n->pcs == SL_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "pcs: not a hex SHA-256");
            return 1;
        }
        if (n->pks == SL_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "certificate_public_key_sha256: not a SHA-256");
            return 1;
        }
        if (n->vcn == SL_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "vcn: name list too long");
            return 1;
        }
        /* A security decision: a subscription cannot turn certificate checks off by itself. A
         * node with allowInsecure is usable only when the user gave --insecure. */
        if (n->allow_insecure && !g_insecure) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "allowInsecure: needs --insecure");
            return 1;
        }
        n->insecure = g_insecure ? 1 : 0;
    }

    return 0;
}

/* Second half (sublink.h): what VLESS checks after the id. */
int sl_link_usable_post(struct vless_node *n) {
    if (strcmp(n->security, "reality") != 0 && strcmp(n->security, "none") != 0 &&
        strcmp(n->security, "tls") != 0) {
        /* xtls is not TLS with chain verification but an exchange of its own, which the client
         * does not have. tls is supported (certverify.c). */
        snprintf(n->skip_reason, sizeof(n->skip_reason), "security=%s is not supported",
                 n->security);
        return 1;
    }

    /* Plain TLS needs a name: the sni is what the certificate is verified against. Without it
     * that is the address, and a certificate is almost never issued to an IP. Saying so here is
     * clearer than a failed handshake that blames the server. (For reality an empty sni is
     * valid, see below.) */
    if (strcmp(n->security, "tls") == 0 && !n->sni[0] && !sl_host_is_name(n->host)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "tls to an IP address without sni: nothing to verify");
        return 1;
    }
    /* Reality needs the server key. It does not need sni: the server matches the name against
     * its `serverNames`, and an empty string there is valid — the server then expects a
     * ClientHello without server_name, which is what Xray clients send. Panels serve such nodes
     * in every format (vless://, Clash YAML), so it is the server owner's choice, not a loss on
     * the way. reality.c builds the ClientHello without a name. */
    if (!strcmp(n->security, "reality") && !n->pbk[0]) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "reality without pbk");
        return 1;
    }
    const int upg_ws = !strcmp(n->type, "ws"), upg = upg_ws || !strcmp(n->type, "httpupgrade");
    if (strcmp(n->type, "tcp") != 0 && strcmp(n->type, "grpc") != 0 &&
        strcmp(n->type, "xhttp") != 0 && !upg) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "transport %s is not supported", n->type);
        return 1;
    }
    if (upg && upg_node_bad(n, upg_ws)) return 1;

    /* A node that leads nowhere gets a reason of its own rather than failing to connect. Panels
     * that bind a subscription to devices answer an unknown client with a stub: valid vless://
     * links to `0.0.0.0:1`, with the message for the user in the node name ("📱 Wrong client",
     * "🔌 Device limit reached"). Such a link parses, but nothing can answer there: connect
     * would reach this machine (the kernel takes 0.0.0.0 as local) or someone else's network.
     * The reason is reported with the node name as its example, so the panel's message reaches
     * the user. Private networks are not rejected (sl_host_leads_nowhere). */
    if (sl_host_leads_nowhere(n->host)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%.20s: nobody to answer", n->host);
        return 1;
    }

    /* Supported xhttp modes (empty means auto):
     *
     *   stream-one — one POST, the request body goes up and the response body down. The
     *     cheapest, and Xray picks it for reality with mode=auto, so auto means stream-one;
     *   stream-up  — a GET for the download and a long POST for the upload;
     *   packet-up  — a GET for the download and a series of short POSTs, a chunk in each.
     *
     * Anything else is rejected, stream-down included: it has no upload at all, being half of a
     * pair with a separate download server, which the client does not support. */
    if (!strcmp(n->type, "xhttp") && n->mode[0] &&
        strcmp(n->mode, "auto") != 0 && strcmp(n->mode, "stream-one") != 0 &&
        strcmp(n->mode, "stream-up") != 0 && strcmp(n->mode, "packet-up") != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "xhttp mode=%s is not supported", n->mode);
        return 1;
    }
    return 0;
}

/* The only place skipped grows, so the counter and the reasons always agree. */
static vless_node_fn g_node_fn;
static void *g_node_ud;

void vless_set_node_hook(vless_node_fn fn, void *ud) {
    g_node_fn = fn;
    g_node_ud = ud;
}

void sl_node_ok(const struct vless_node *n) {
    if (g_node_fn) g_node_fn(g_node_ud, n, NULL);
}

void sl_skip_node(struct vless_sub_stats *st, const struct vless_node *n, const char *reason) {
    if (g_node_fn) g_node_fn(g_node_ud, n, reason);
    sl_skip_note(st, n, reason);
}

void sl_skip_note(struct vless_sub_stats *st, const struct vless_node *n, const char *reason) {
    if (!st) return;
    st->skipped++;
    for (size_t i = 0; i < st->reasons_n; i++) {
        if (!strcmp(st->reasons[i].reason, reason)) { st->reasons[i].count++; return; }
    }
    if (st->reasons_n >= VLESS_SKIP_REASONS) { st->reasons_dropped++; return; }
    struct vless_skip *s = &st->reasons[st->reasons_n++];
    snprintf(s->reason, sizeof(s->reason), "%s", reason);
    /* The example ties the reason to a node in the subscription. A link without '#' has no
     * name, and one that did not parse may have no host: the example then stays empty. */
    if (n && n->name[0]) snprintf(s->example, sizeof(s->example), "%s", n->name);
    else if (n && n->host[0]) snprintf(s->example, sizeof(s->example), "%s:%u",
                                      n->host, n->port);
    s->count = 1;
}

