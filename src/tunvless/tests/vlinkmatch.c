#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unit.h"
#include "vless.h"
#include "sublink.h"
#include "vlink.h"
#include "fmask.h"
#include "sub-pq-samples.h"
#include "reality.h"

#define UUID "b831381d-6324-4d53-ad4f-8cda48b30811"
#define U2 "11111111-2222-3333-4444-555555555555"
#define SBU "8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124"
#define PBK "K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng"
#define H1 "f8c71232f26e142a9ec780c297bd500dcbfadd2bde91f4a97876ab4d73631c12"
#define H2 "a0cf13f5063002c9f3cf982cda1fdebcb9f1277a1f56969cfa1b1d7837becfc7"
#define ECH "AEX+DQBBNwAgACANG785NbYxf2vAoHiUugO7PDLchnWNz2f+95epg2DJewAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
#define XO(stream) "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"h\"," \
                   "\"port\":443,\"users\":[{\"id\":\"u\"}]}]},\"streamSettings\":" stream "}]}"

static const char *const g_fields[] = {
    "name", "host", "port", "uuid", "type", "security", "sni", "fp", "pbk", "sid", "flow", "path",
    "service", "mode", "http_host", "headers", "pad_from", "pad_to", "post_from", "post_to", "pqv",
    "encryption", "tcp_http", "pcs", "pks", "vcn", "ech", "allow_insecure", "insecure", "xhx",
    "fm", "dl",
};
#define NFIELDS (sizeof g_fields / sizeof *g_fields)
static unsigned g_cover[NFIELDS];
static int g_bad, g_in_dl;

static void hit(const char *f) {
    if (g_in_dl) return;
    for (size_t i = 0; i < NFIELDS; i++)
        if (!strcmp(g_fields[i], f)) { g_cover[i]++; return; }
    printf("no coverage slot for %s\n", f);
    g_bad = 1;
}

static int marker(const char *p) {
    return p && (p == SL_BAD_PQV || p == SL_FULL || p == SL_BAD_PIN || p == SL_BAD_ECH || p == SL_ECH_DNS ||
                 p == SL_BAD_XHX || p == SL_BAD_XHX_JSON || p == SL_BAD_FM);
}

static int same_ptr(const char *a, const char *b) {
    if (!a || !b) return a == b;
    return !strcmp(a, b);
}

#define FS(f) do { if (n->f[0]) hit(#f); if (strcmp(n->f, m->f)) bad = #f; } while (0)
#define FN(f) do { if (n->f) hit(#f); if (n->f != m->f) bad = #f; } while (0)
#define FP(f) do { if (n->f && !marker(n->f)) hit(#f); \
                   if (marker(n->f) ? m->f != NULL : !same_ptr(n->f, m->f)) bad = #f; } while (0)

static const char *diff(const struct vless_node *n, const struct vless_node *m) {
    const char *bad = NULL;
    FS(name); FS(host); FN(port); FS(uuid); FS(type); FS(security); FS(sni); FS(fp); FS(pbk);
    FS(sid); FS(flow); FS(path); FS(service); FS(mode); FS(http_host); FS(headers);
    FN(pad_from); FN(pad_to); FN(post_from); FN(post_to); FP(pqv); FP(encryption);
    FN(tcp_http); FP(pcs); FP(pks); FP(vcn); FP(ech); FN(allow_insecure);
    FN(insecure); FP(xhx); FP(fm);
    if (!n->dl != !m->dl || (n->dl == &SL_DL_FULL) != (m->dl == &SL_DL_FULL)) bad = "dl";
    else if (n->dl && n->dl != &SL_DL_FULL) {
        static char why[48];
        hit("dl");
        g_in_dl++;
        const char *d = diff(n->dl, m->dl);
        g_in_dl--;
        if (d) { snprintf(why, sizeof why, "dl.%s", d); bad = why; }
    }
    if (n->headers_bad != m->headers_bad) bad = "headers_bad";
    if (strcmp(n->skip_reason, m->skip_reason)) bad = "skip_reason";
    if (marker(n->pcs) || marker(n->pks) || marker(n->vcn) || marker(n->ech))
        if (!strcmp(n->security, "tls")) bad = "marker on tls";
    return bad;
}

struct tally { int seen, ok, skipped, refused; };

static void roundtrip(struct tally *t, const char *group, size_t at, const struct vless_node *n) {
    static char buf[32768];
    struct vless_node m;
    t->seen++;
    size_t l = vless_node_link(n, buf, sizeof buf);
    const char *why = NULL;
    if (!l) why = "no link";
    else if (vless_parse_url(buf, &m) != 0) why = "link does not parse back as usable";
    else if ((why = diff(n, &m)) != NULL) { }
    else if (strpbrk(buf, "\r\n\t\x7f")) why = "link is not one line of printable bytes";
    else if (vless_node_link(n, buf, l) != 0) why = "a buffer one byte short is not refused";
    else if (vless_node_link(n, buf, l + 1) != l) why = "an exact buffer is refused";
    if (why) printf("FAIL %s, input %zu, node %s: %s\n", group, at, n->name, why);
    else t->ok++;
}

static void report(const char *group, const struct tally *t) {
    char what[128];
    snprintf(what, sizeof what, "%s: %d usable nodes round-trip", group, t->seen);
    check(what, t->seen, t->ok);
    snprintf(what, sizeof what, "%s: has usable nodes", group);
    check(what, 1, t->seen > 0);
    if (t->skipped) {
        snprintf(what, sizeof what, "%s: no link for %d skipped nodes", group, t->skipped);
        check(what, t->skipped, t->refused);
    }
}

static void links(const char *group, const char *const *v, size_t k) {
    struct tally t = { 0 };
    for (size_t i = 0; i < k; i++) {
        struct vless_node n;
        char buf[64];
        int rc = vless_parse_url(v[i], &n);
        if (rc == 0) roundtrip(&t, group, i, &n);
        else if (rc == 1) {
            t.skipped++;
            if (n.skip_reason[0] && vless_node_link(&n, buf, sizeof buf) == 0 &&
                vless_node_link(&n, NULL, 0) == 0)
                t.refused++;
            else
                printf("FAIL %s, input %zu: skipped node given a link\n", group, i);
        } else printf("FAIL %s, input %zu: corpus link does not parse\n", group, i);
    }
    report(group, &t);
}

static void subs(const char *group, const char *const *v, size_t k) {
    struct tally t = { 0 };
    static struct vless_node out[64];
    static char dec[65536];
    for (size_t i = 0; i < k; i++) {
        const char *text = vless_sub_text(v[i], strlen(v[i]), dec, sizeof dec);
        size_t c = text ? vless_parse_sub(text, out, 64, NULL) : 0;
        for (size_t j = 0; j < c; j++) roundtrip(&t, group, i, &out[j]);
    }
    report(group, &t);
}

#define N(a) (sizeof(a) / sizeof *(a))

struct skips { int n; char name[4][128]; char reason[4][96]; };

static void on_skip(void *ud, const struct vless_node *n, const char *reason) {
    struct skips *s = ud;
    if (s->n < 4) {
        snprintf(s->name[s->n], sizeof s->name[0], "%s", n->name);
        snprintf(s->reason[s->n], sizeof s->reason[0], "%s", reason ? reason : "");
    }
    s->n++;
}

static char *fmt(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmt(const char *f, ...) {
    char *s = malloc(16384);
    va_list ap;
    va_start(ap, f);
    vsnprintf(s, 16384, f, ap);
    va_end(ap);
    return s;
}

static char *xlink(const char *main, const char *json) {
    char *s = malloc(32768);
    size_t o = (size_t)snprintf(s, 32768, "vless://" UUID "@m.example:443?%s&extra=", main);
    for (const unsigned char *p = (const unsigned char *)json; *p && o + 4 < 32768; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) s[o++] = (char)*p;
        else o += (size_t)snprintf(s + o, 32768 - o, "%%%02X", *p);
    }
    snprintf(s + o, 32768 - o, "#d");
    return s;
}

static const char *g_own_last;
static int g_own_calls, g_own_fail;
static const char *own_intern(const char *v, size_t n) {
    static char buf[4096];
    g_own_calls++;
    if (g_own_fail || n >= sizeof buf) return NULL;
    memcpy(buf, v, n);
    buf[n] = 0;
    return g_own_last = buf;
}

#define FMF "{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"packets\":\"tlshello\",\"length\":\"10-20\"}}]}"
#define FMB "{\"tcp\":[{\"type\":\"filter\",\"settings\":{\"allowedSourceIPs\":[\"10.0.0.1\"]}}]}"

static size_t fm_pct(char *o, const char *s) {
    size_t k = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || strchr("-._~", *p))
            o[k++] = (char)*p;
        else k += (size_t)sprintf(o + k, "%%%02X", *p);
    }
    o[k] = '\0';
    return k;
}

static void fm_fill(char *o, char ch, size_t total) {
    static const char a[] = "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":{\"clients\":[[{\"type\":\"str\",\"packet\":\"";
    static const char b[] = "\"}]]}}]}";
    size_t f = total - (sizeof a - 1) - (sizeof b - 1);
    memcpy(o, a, sizeof a - 1);
    memset(o + sizeof a - 1, ch, f);
    memcpy(o + sizeof a - 1 + f, b, sizeof b);
}

static void fm_ech(char *o, size_t bl) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char raw[1099];
    size_t e = 0;
    raw[0] = (unsigned char)((bl - 2) >> 8), raw[1] = (unsigned char)(bl - 2);
    raw[2] = 0xfe, raw[3] = 0x0d, raw[4] = (unsigned char)((bl - 6) >> 8), raw[5] = (unsigned char)(bl - 6);
    for (size_t i = 6; i < bl; i++) raw[i] = (unsigned char)"\xfb\xef\xbe"[i % 3];
    for (size_t i = 0; i < bl; i += 3) {
        unsigned v = (unsigned)raw[i] << 16 | (i + 1 < bl ? (unsigned)raw[i + 1] << 8 : 0) | (i + 2 < bl ? raw[i + 2] : 0);
        o[e++] = b64[v >> 18 & 63], o[e++] = b64[v >> 12 & 63];
        o[e++] = i + 1 < bl ? b64[v >> 6 & 63] : '=', o[e++] = i + 2 < bl ? b64[v & 63] : '=';
    }
    o[e] = '\0';
}

static char *fm_worst(size_t main_fm, size_t block_fm, int block_long, size_t name) {
    static char fm1[FM_JSON_MAX + 1], fm2[FM_JSON_MAX + 1], enc[10000], ech[1500], dech[1500], pins[1100], extra[16384];
    char k63[64], m15[16], blong[8192] = "";
    char *url = malloc(65536), *p = enc;
    if (main_fm) fm_fill(fm1, '!', main_fm);
    fm_fill(fm2, '*', block_fm);
    p += sprintf(p, "mlkem768x25519plus.native.0rtt.");
    for (int i = 0; i < 16; i++) p += sprintf(p, "65535-65535-65535-a.");
    for (int i = 0; i < 6; i++) { memset(p, 'A', 1579); p += 1579; *p++ = '.'; }
    p[-1] = '\0';
    fm_ech(ech, 1099);
    fm_ech(dech, 1047);
    for (int i = 0; i < 16; i++) sprintf(pins + 65 * i, "%s%s", i ? "," : "", H1);
    memset(k63, '!', 63), k63[63] = '\0';
    memset(m15, '!', 15), m15[15] = '\0';
    if (block_long)
        snprintf(blong, sizeof blong, ",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"d.example\","
                 "\"mldsa65Verify\":\"%s\"}", PQV_KEY);
    if (block_long > 1)
        snprintf(blong, sizeof blong, ",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"d.example\","
                 "\"mldsa65Verify\":\"%s\",\"echConfigList\":\"%s\",\"pinnedPeerCertSha256\":\"%s\"},"
                 "\"xhttpSettings\":{\"sessionPlacement\":\"header\",\"sessionKey\":\"%s\",\"seqPlacement\":\"header\","
                 "\"seqKey\":\"%s\",\"uplinkDataPlacement\":\"header\",\"uplinkDataKey\":\"%s\",\"xPaddingObfsMode\":true,"
                 "\"xPaddingKey\":\"%s\",\"xPaddingHeader\":\"%s\",\"xPaddingPlacement\":\"header\"}",
                 PQV_KEY, dech, pins, k63, k63, k63, k63, k63);
    snprintf(extra, sizeof extra,
             "{\"sessionPlacement\":\"header\",\"sessionKey\":\"%s\",\"seqPlacement\":\"header\",\"seqKey\":\"%s\","
             "\"uplinkDataPlacement\":\"header\",\"uplinkDataKey\":\"%s\",\"xPaddingObfsMode\":true,\"xPaddingKey\":\"%s\","
             "\"xPaddingHeader\":\"%s\",\"xPaddingPlacement\":\"header\",\"uplinkHTTPMethod\":\"%s\",\"downloadSettings\":"
             "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"finalmask\":%s%s}}",
             k63, k63, k63, k63, k63, m15, fm2, blong);
    p = url + sprintf(url, "vless://" UUID "@m.example:443?type=xhttp&security=tls&sni=m.example&mode=packet-up&path=/x"
                      "&encryption=%s&pqv=%s&ech=", enc, PQV_KEY);
    p += fm_pct(p, ech);
    if (main_fm) {
        p += sprintf(p, "&fm=");
        p += fm_pct(p, fm1);
    }
    p += sprintf(p, "&extra=");
    p += fm_pct(p, extra);
    *p++ = '#';
    memset(p, 'n', name);
    p[name] = '\0';
    return url;
}

static void t_fm_roundtrip(void) {
    static char buf[32768], big[65536], want[16384];
    struct vless_node n, m;
    sl_intern_reset();
    char *u = xlink("type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=packet-up&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A"
                    "%22fragment%22%2C%22settings%22%3A%7B%22packets%22%3A%22tlshello%22%2C%22length%22%3A%2210-20%22%7D%7D%5D%7D",
                    "{\"downloadSettings\":{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"finalmask\":" FMB "}}");
    int rc = vless_parse_url(u, &n);
    free(u);
    /* catches: fm lost by vlink, or a masked node vanishing from the link list without a reason */
    check("fm round trip: usable", 0, rc);
    check_str("fm round trip: main mask", FMF, n.fm ? n.fm : "(null)");
    check_str("fm round trip: block mask", FMB, vless_dl(&n) && vless_dl(&n)->fm ? vless_dl(&n)->fm : "(null)");
    size_t l = vless_node_link(&n, buf, sizeof buf);
    check("fm round trip: a link", 1, l > 0);
    strcpy(want, "&fm=");
    fm_pct(want + 4, FMF);
    check("fm round trip: fm= is the encoded compact JSON", 1, strstr(buf, want) != NULL);
    char *ex = strstr(buf, "&extra=");
    if (ex) {
        snprintf(big, sizeof big, "%s", ex + 7);
        char *amp = strchr(big, '&');
        if (amp) *amp = '\0';
        sl_pct_decode(big);
    } else big[0] = '\0';
    char *ds = strstr(big, "\"downloadSettings\":{");
    check("fm round trip: extra has the block's finalmask raw", 1,
          ds && strstr(ds, "\"finalmask\":" FMB) != NULL && strstr(big, "\"finalmask\":" FMB) == strstr(ds, "\"finalmask\""));
    check("fm round trip: re-parsed", 0, l ? vless_parse_url(buf, &m) : -1);
    check("fm round trip: same main pointer", 1, l && m.fm == n.fm);
    check("fm round trip: same block pointer", 1, l && vless_dl(&m) && vless_dl(&m)->fm == vless_dl(&n)->fm);
    struct tr_node t, td;
    sl_tr_nodes(&n, &t, &td);
    check("fm round trip: the transport sees both masks", 1, t.fm == n.fm && t.dl == &td && td.fm == vless_dl(&n)->fm);
    m = n;
    m.fm = SL_BAD_FM;
    l = vless_node_link(&m, buf, sizeof buf);
    check("fm round trip: a marker is never written", 1, l > 0 && !strstr(buf, "&fm="));
    static const char *const v[] = {
        "vless://" UUID "@h.example:443?type=tcp&security=tls&sni=h.example&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22filter%22%7D%5D%7D#f",
        "vless://" UUID "@h.example:443?type=tcp&security=tls&sni=h.example&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22sudoku%22%7D%5D%7D#s",
    };
    links("fm links", v, N(v));

    sl_intern_reset();
    u = fm_worst(FM_JSON_MAX, FM_JSON_MAX, 0, 0);
    rc = vless_parse_url(u, &n);
    free(u);
    check("fm worst: usable", 0, rc);
    check("fm worst: main mask at the cap", FM_JSON_MAX, n.fm ? (long)strlen(n.fm) : -1);
    check("fm worst: block mask at the cap", FM_JSON_MAX, vless_dl(&n) && vless_dl(&n)->fm ? (long)strlen(vless_dl(&n)->fm) : -1);
    check("fm worst: longest encryption", 9830, n.encryption ? (long)strlen(n.encryption) : -1);
    check("fm worst: longest ech", 1468, n.ech ? (long)strlen(n.ech) : -1);
    l = vless_node_link(&n, buf, sizeof buf);
    check("fm worst: a link in 32768", 1, l > 0);
    check("fm worst: re-parsed", 0, l ? vless_parse_url(buf, &m) : -1);
    check("fm worst: the same node", 1, l && diff(&n, &m) == NULL);

    int fit = 0, over = 0, bad = 0;
    for (size_t i = 0; i < 3 * (FM_JSON_MAX / 2 + 1); i++) {
        sl_intern_reset();
        u = fm_worst(FM_JSON_MAX / 2 + i / 3, FM_JSON_MAX, 1, i % 3 + 1);
        rc = vless_parse_url(u, &n);
        free(u);
        if (rc == 0) {
            fit++;
            if (!vless_node_link(&n, buf, sizeof buf)) bad++;
        } else {
            over++;
            if (strcmp(n.skip_reason, "finalmask: too long for a link")) bad++;
            n.skip_reason[0] = '\0';
            if (vless_node_link(&n, buf, sizeof buf) || !vless_node_link(&n, big, sizeof big)) bad++;
        }
    }
    int cut_saved = 0, cut_bad = 0;
    for (size_t i = 0; i <= FM_JSON_MAX / 2; i++) {
        char *full = malloc(VLESS_LINK_MAX * 2);
        sl_intern_reset();
        u = fm_worst(FM_JSON_MAX / 2 + i, FM_JSON_MAX, 1, 127);
        rc = vless_parse_url(u, &n);
        free(u);
        int skipped = rc != 0;
        n.skip_reason[0] = '\0';
        size_t whole = vless_node_link(&n, full, VLESS_LINK_MAX * 2);
        vless_name_cut(n.name);
        int fits = vless_node_link(&n, buf, sizeof buf) > 0;
        if (skipped == fits) cut_bad++;
        if (!skipped && whole >= VLESS_LINK_MAX) cut_saved++;
        free(full);
    }
    /* catches: a node measured with the name the link will not carry */
    check("fm overflow, cut name: refused exactly when the cut link does not fit", 0, cut_bad);
    check("fm overflow, cut name: a node fits only with its name cut", 1, cut_saved > 0);
    sl_intern_reset();
    u = fm_worst(0, FM_JSON_MAX, 2, 1);
    rc = vless_parse_url(u, &n);
    free(u);
    check("fm overflow by the block's mask: skipped", 1, rc);
    check_str("fm overflow by the block's mask: reason", "finalmask: too long for a link", n.skip_reason);
    check("fm overflow by the block's mask: no main mask", 1, n.fm == NULL && vless_dl(&n) && vless_dl(&n)->fm);
    n.skip_reason[0] = '\0';
    check("fm overflow by the block's mask: the link does not fit", 1,
          !vless_node_link(&n, buf, sizeof buf) && vless_node_link(&n, big, sizeof big));
    sl_intern_reset();
    check("fm overflow: some masked nodes fit", 1, fit > 0);
    check("fm overflow: some masked nodes overflow", 1, over > 0);
    check("fm overflow: refused exactly when the link does not fit", 0, bad);
}

int main(void) {
    vless_set_insecure(0);

    {
        static const char *const v[] = {
            "vless://" U2 "@example.com:8443?security=reality&sni=www.microsoft.com&pbk=ABCDEF&sid=aa11"
            "&fp=chrome&type=tcp&flow=xtls-rprx-vision#%D0%A3%D0%B7%D0%B5%D0%BB",
            "vless://u@node.example.org:443?security=tls#x",
            "vless://u@9.9.9.9:443?security=tls#x",
            "vless://u@9.9.9.9:443?security=tls&sni=node.example.org#x",
            "vless://u@h:443?security=xtls#x",
            "vless://u@h:443?security=reality&sni=a.com#x",
            "vless://u@h:443?security=reality&pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA&sid=ab12"
            "&flow=xtls-rprx-vision#x",
            "vless://u@h:443?security=none&type=kcp#x",
            "vless://u@h:443#x",
            "vless://TMG_74317ba5f91@203.0.113.7:443?type=xhttp&encryption=none&path=%2FdRh-l74-MZE3z"
            "&host=amazon.com&mode=auto&security=reality&fp=firefox&pbk=KEY&sni=amazon.com&sid=9392"
            "&spx=%2F#TMG_74317ba5f91-%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F",
            "vless://0123456789abcdef0123456789abcde@h:443?security=none#x",
            "vless://@h:443?security=none#x",
            "vless://0123456789abcdef0123456789abcdeZ@h:443?security=none#x",
            "vless://" U2 "@10.8.0.1:443?security=none#Свой",
            "vless://" U2 "@127.0.0.1:443?security=none#Петля",
            "vless://" U2 "@127a.example.com:443?security=none#Имя",
            "vless://" U2 "@127.node.example.com:443?security=none#Имя",
            "vless://u@h:443#Fast?type=ws",
            "vless://u@h:443#a%40%40b",
            "vless://u@h:443#a%@@b",
        };
        /* catches: a basic field (host, port, id, sni, fp, pbk, sid, flow, name) dropped or misread */
        links("plain links", v, N(v));
    }
    {
        static const char *const v[] = {
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xmux%22%3A%7B"
            "%22maxConcurrency%22%3A%2216-32%22%7D%2C%22xPaddingBytes%22%3A%2250-150%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A512%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%22ой%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%22900-100%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22scMaxEachPostBytes%22%3A4096%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22scMaxEachPostBytes%22%3A"
            "%22500000-1000000%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22uplinkDataPlacement%22%3A"
            "%22auto%22%2C%22sessionPlacement%22%3A%22path%22%2C%22seqPlacement%22%3A%22path%22%2C%22xPaddingMethod%22%3A"
            "%22repeat-x%22%2C%22xPaddingObfsMode%22%3Afalse%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22uplinkDataPlacement%22%3A%22header%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22sessionPlacement%22%3A%22query%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xPaddingMethod%22%3A%22tokenish%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xPaddingObfsMode%22%3Atrue%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22downloadSettings%22%3A%7B"
            "%22address%22%3A%22d.example%22%2C%22port%22%3A443%2C%22network%22%3A%22xhttp%22%7D%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=auto#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=stream-one#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=stream-up#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=packet-up#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=stream-down#x",
            "vless://" UUID "@example.org:443?type=xhttp&security=none&path=/x&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D#x",
            "vless://" UUID "@example.org:443?type=grpc&security=none&serviceName=svc%2Fa&headerType=http#g",
            "vless://" UUID "@example.org:443?type=grpc&security=none&serviceName=s&mode=multi%2Bx#g",
            "vless://" UUID "@example.org:443?type=tcp&security=none&extra=%7B%22xPaddingObfsMode%22%3Atrue%7D#o",
            "vless://" UUID "@example.org:443?type=tcp&security=none&headerType=http#h",
            "vless://" UUID "@example.org:443?type=tcp&security=none&headerType=none#h",
        };
        /* catches: xhttp padding, post size, mode, extra or headerType lost or read as another value */
        links("xhttp and grpc links", v, N(v));
    }
    {
        static const char *const v[] = {
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22sessionPlacement%22%3A%22path%22%2C%22seqPlacement%22%3A%22path%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22sessionPlacement%22%3A%22header%22%2C%22sessionKey%22%3A%22X-S%22%2C%22seqPlacement%22%3A%22header%22%2C%22seqKey%22%3A%22X-Q%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22sessionPlacement%22%3A%22cookie%22%2C%22sessionKey%22%3A%22sid%22%2C%22seqPlacement%22%3A%22query%22%2C%22seqKey%22%3A%22q%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22sessionIDPlacement%22%3A%22query%22%2C%22sessionIDKey%22%3A%22k%22%2C%22sessionIDTable%22%3A%22hex%22%2C%22sessionIDLength%22%3A%2216-20%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22uplinkDataPlacement%22%3A%22body%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22uplinkDataPlacement%22%3A%22header%22%2C%22uplinkDataKey%22%3A%22X-D%22%2C%22uplinkChunkSize%22%3A%22100-200%22%7D&mode=packet-up#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22uplinkChunkSize%22%3A%224096%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xPaddingMethod%22%3A%22repeat-x%22%2C%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingKey%22%3A%22pk%22%2C%22xPaddingHeader%22%3A%22X-P%22%2C%22xPaddingPlacement%22%3A%22header%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingObfsMode%22%3Afalse%2C%22xPaddingPlacement%22%3A%22queryInHeader%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%2C%22scMaxEachPostBytes%22%3A%22500-900%22%2C%22uplinkChunkSize%22%3A%2210-20%22%2C%22xPaddingObfsMode%22%3Atrue%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=packet-up&extra=%7B%22uplinkHTTPMethod%22%3A%22GET%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=packet-up&extra=%7B%22scMaxBufferedPosts%22%3A40%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=stream-up&extra=%7B%22noGRPCHeader%22%3Atrue%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&extra=%7B%22noGRPCHeader%22%3Afalse%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=packet-up&extra=%7B%22serverMaxHeaderBytes%22%3A4096%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=packet-up&extra=%7B%22scMinPostsIntervalMs%22%3A%2210-50%22%7D#x",
            "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=packet-up&extra=%7B%22scMinPostsIntervalMs%22%3A%22-5--1%22%7D#x",
        };
        links("xhttp-extra", v, N(v));
    }
    {
        struct vless_node n;
        char buf[1024];
        int rc = vless_parse_url("vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx&mode=stream-up"
                                 "&extra=%7B%22scMinPostsIntervalMs%22%3A%7B%22from%22%3A50%2C%22to%22%3A10%7D%2C%22serverMaxHeaderBytes%22"
                                 "%3A4096%2C%22noGRPCHeader%22%3Atrue%2C%22seqKey%22%3A%22q%22%7D#x", &n);
        size_t l = rc ? 0 : vless_node_link(&n, buf, sizeof buf);
        /* catches: noGRPCHeader, serverMaxHeaderBytes or scMinPostsIntervalMs lost on the way to tunvless, or out of order */
        check("xhttp-extra: noGRPCHeader bare, the server limit and the interval after it", 0, l ? strcmp(buf,
              "vless://u@h:443?type=xhttp&security=reality&sni=a.com&pbk=K&path=%2Fx&mode=stream-up"
              "&extra=%7B%22seqKey%22%3A%22q%22%2C%22noGRPCHeader%22%3Atrue%2C%22serverMaxHeaderBytes%22%3A%224096%22"
              "%2C%22scMinPostsIntervalMs%22%3A%2250-10%22%7D#x") : -1);
    }
    {
        const char *v[] = {
            xlink("type=xhttp&security=tls&sni=m.example&path=%2Fx",
                  "{\"xmux\":{\"maxConcurrency\":\"900-600\",\"cMaxReuseTimes\":8,\"hMaxRequestTimes\":\"600-900\","
                  "\"hMaxReusableSecs\":\"1800-3000\",\"hKeepAlivePeriod\":-5}}"),
            xlink("type=xhttp&security=tls&sni=m.example&path=%2Fx",
                  "{\"seqKey\":\"q\",\"xmux\":{\"maxConnections\":\"20-40\"},\"downloadSettings\":{\"address\":\"d.example\","
                  "\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":{\"xmux\":{\"maxConnections\":\"20-40\","
                  "\"cMaxReuseTimes\":\"1-2\",\"hMaxRequestTimes\":3,\"hMaxReusableSecs\":4,\"hKeepAlivePeriod\":-1}}}}"),
            xlink("type=xhttp&security=tls&sni=m.example&path=%2Fx",
                  "{\"downloadSettings\":{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":"
                  "{\"xmux\":{\"maxConcurrency\":\"2-1\",\"hKeepAlivePeriod\":0}}}}"),
        };
        /* catches: an xmux key lost, flattened or rewritten on the way to tunvless */
        links("xhttp-xmux", v, N(v));
        struct vless_node n, m;
        char buf[2048];
        int rc = vless_parse_url(v[0], &n);
        size_t l = rc ? 0 : vless_node_link(&n, buf, sizeof buf);
        check("xhttp-xmux: one nested member, values as written", 0, l ? strcmp(buf,
              "vless://" UUID "@m.example:443?type=xhttp&security=tls&sni=m.example&path=%2Fx"
              "&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%22900-600%22%2C%22cMaxReuseTimes%22%3A%228%22"
              "%2C%22hMaxRequestTimes%22%3A%22600-900%22%2C%22hMaxReusableSecs%22%3A%221800-3000%22"
              "%2C%22hKeepAlivePeriod%22%3A-5%7D%7D#d") : -1);
        rc = vless_parse_url(v[1], &n);
        l = rc ? 0 : vless_node_link(&n, buf, sizeof buf);
        rc = l ? vless_parse_url(buf, &m) : -1;
        check("xhttp-xmux: block read back", 0, rc);
        check_str("xhttp-xmux: block keeps every key", "xmux.maxConnections=20-40\nxmux.cMaxReuseTimes=1-2\n"
                  "xmux.hMaxRequestTimes=3\nxmux.hMaxReusableSecs=4\nxmux.hKeepAlivePeriod=-1\n",
                  !rc && m.dl && m.dl != &SL_DL_FULL && m.dl->xhx ? m.dl->xhx : "");
        check_str("xhttp-xmux: main keeps its own", "seqKey=q\nxmux.maxConnections=20-40\n", !rc && m.xhx ? m.xhx : "");
        for (size_t i = 0; i < N(v); i++) free((void *)v[i]);
    }
    {
        static char big[2048] = "%7B%22headers%22%3A%7B";
        for (int i = 0; i < 40; i++) {
            char kv[96];
            snprintf(kv, sizeof kv, "%s%%22h%d%%22%%3A%%22vvvvvvvvvvvvvvvv%%22", i ? "%2C" : "", i);
            strncat(big, kv, sizeof big - strlen(big) - 1);
        }
        strncat(big, "%7D%2C%22xPaddingBytes%22%3A%2250-150%22%7D", sizeof big - strlen(big) - 1);
        char pct[512] = "node", raw[512] = "", cut5[512] = "nodex", cut6[512] = "nodexy";
        for (int i = 0; i < 70; i++) {
            strcat(pct, "%D0%9F");
            strcat(raw, "\xD0\x9F");
            strcat(cut5, "%D0%9F");
            strcat(cut6, "%D0%9F");
        }
        const char *v[] = {
            fmt("vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%%2Fx&extra=%s#x", big),
            fmt("vless://" U2 "@example.com:8443?security=reality&sni=a.example&pbk=k&fp=chrome#%s", pct),
            fmt("vless://" U2 "@example.com:8443?security=reality&sni=a.example&pbk=k&fp=chrome#%s", raw),
            fmt("vless://" U2 "@example.com:8443?security=reality&sni=a.example&pbk=k&fp=chrome#%s", cut5),
            fmt("vless://" U2 "@example.com:8443?security=reality&sni=a.example&pbk=k&fp=chrome#%s", cut6),
            fmt("vless://" UUID "@h.example:443?security=none#a%%23b%%25c%%20d%%20%%D0%%A3%%D0%%B7%%D0%%B5%%D0%%BB"),
            fmt("vless://" UUID "@h.example:443?security=none#100%% off # top \xF0\x9F\x87\xA9\xF0\x9F\x87\xAA"),
            fmt("vless://" UUID "@h.example:443?security=none#tab%%09and%%0Anewline"),
            fmt("vless://" UUID "@h.example:443?security=none#50%%25AB%%25zz"),
        };
        /* catches: a name with #, %, spaces, control bytes or UTF-8, or a long extra, not read back the same */
        links("names and long values", v, N(v));
        for (size_t i = 0; i < N(v); i++) free((void *)v[i]);
    }
    {
        static const char *const v[] = {
            "vless://u@h:443?type=ws&security=tls&sni=s.example&path=%2Fws%3Fed%3D2048&host=cdn.example#w",
            "vless://u@h:443?type=httpupgrade&path=/up#h",
            "vless://u@h:443?type=ws&path=%2F%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61"
            "%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61#w",
            "vless://u@h:443?type=ws&flow=xtls-rprx-vision#w",
            "vless://u@h:443?type=ws&path=/a%25zz#w",
            "vless://u@h:443?type=httpupgrade&path=/a%25zz#w",
            "vless://u@h:443?type=ws&host=a%20b#w",
            "vless://u@h:443?type=ws&security=reality&pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA#w",
        };
        /* catches: a ws or httpupgrade path or Host header altered by encoding */
        links("ws links", v, N(v));
    }
    {
        const char *v[] = {
            fmt("vless://" UUID "@example.org:443?encryption=%s&type=tcp&security=none#a", ENC_X25519),
            fmt("vless://" UUID "@example.org:443?encryption=%s&type=tcp&security=none#a", ENC_MLKEM),
            fmt("vless://" UUID "@example.org:443?encryption=mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111.50-0-3333."
                "YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ&type=tcp&security=none#m"),
            fmt("vless://" UUID "@example.org:443?encryption=mlkem768x25519plus.xorpub.1rtt.100-111-1111.75-0-111.50-0-3333."
                "YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ&type=tcp&security=none#m"),
            fmt("vless://" UUID "@example.org:443?encryption=mlkem768x25519plus.random.1rtt.100-111-1111.75-0-111.50-0-3333."
                "YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ&type=tcp&security=none#m"),
            fmt("vless://" UUID "@example.org:443?encryption=none&type=tcp&security=none#n"),
            fmt("vless://" UUID "@example.org:443?encryption=&type=tcp&security=none#n"),
            fmt("vless://" UUID "@example.org:443?encryption=aes-128-gcm&type=tcp&security=none#n"),
            fmt("vless://" UUID "@example.org:443?encryption=mlkem768x25519plus.native.0rtt.100-35-35."
                "YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ&type=tcp&security=none#n"),
            fmt("vless://" UUID "@example.org:443?type=tcp&security=reality&pbk=" PBK "&sid=01&sni=example.com&fp=chrome&pqv=%s#p", PQV_KEY),
            fmt("vless://" UUID "@example.org:443?type=tcp&security=reality&pbk=" PBK "&sid=01&sni=example.com&pqv=%.100s#p", PQV_KEY),
            fmt("vless://" UUID "@example.org:443?type=tcp&security=reality&pbk=" PBK "&sid=01&sni=e.com&flow=xtls-rprx-vision-udp443#f"),
            fmt("vless://" UUID "@example.org:443?type=tcp&security=reality&pbk=" PBK "&sid=01&sni=example.com&fp=chrome"
                "&pqv=%s&encryption=%s#both", PQV_KEY, ENC_MLKEM),
        };
        /* catches: a long post-quantum value (pqv, encryption) cut, re-encoded or dropped */
        links("post-quantum links", v, N(v));
        for (size_t i = 0; i < N(v); i++) free((void *)v[i]);
    }
    {
        static const char *const v[] = {
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&pcs=" H1,
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&pcs=F8:C7:12:32:F2:6E:14:2A:9E:C7:80:C2:97:BD:50:0D:CB:FA:DD:2B:DE"
            ":91:F4:A9:78:76:AB:4D:73:63:1C:12," H2 "&vcn=a.example,%20b.example",
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&pcs=abcd",
            "vless://" UUID "@example.org:443?security=reality&pbk=" PBK "&sid=0123&pcs=abcd",
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&allowInsecure=1",
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&insecure=1",
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&allowInsecure=0",
            "vless://" UUID "@example.org:443?security=reality&pbk=" PBK "&sid=0123&allowInsecure=1",
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&ech=AEX%2BDQBBNwAgACANG785NbYxf2vAoHiUugO7PDLchnWNz2f%2B95epg2DJewA"
            "EAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA%3D",
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&ech=AAb+DQACAAA=",
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&ech=AAAA",
            "vless://" UUID "@example.org:443?security=tls&sni=t.example&ech=cloudflare-ech.com%2Bhttps://1.1.1.1/dns-query",
            "vless://" UUID "@example.org:443?security=reality&pbk=" PBK "&sid=0123&ech=AAAA",
        };
        /* catches: a certificate pin, name list, ECH config or allowInsecure lost on the way back */
        links("certificate links", v, N(v));
        vless_set_insecure(1);
        /* catches: allowInsecure and the --insecure mark not carried by the link */
        links("certificate links, --insecure", v, N(v));
        vless_set_insecure(0);
    }
    {
        const char *v[] = {
            xlink("type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=packet-up",
                  "{\"downloadSettings\":{\"address\":\"d.example\",\"port\":8443,\"network\":\"xhttp\",\"security\":\"tls\","
                  "\"tlsSettings\":{\"serverName\":\"dl.example\",\"fingerprint\":\"firefox\",\"pinnedPeerCertSha256\":\"" H1 "\","
                  "\"verifyPeerCertByName\":\"a.example,b.example\",\"echConfigList\":\"" ECH "\"}}}"),
            fmt("vless://" UUID "@m.example:443?type=xhttp&security=reality&pbk=" PBK "&sid=01&sni=m.example&path=%%2Fxp"
                "&pqv=%s&extra=%%7B%%22downloadSettings%%22%%3A%%7B%%22address%%22%%3A%%22r.example%%22%%2C%%22port%%22%%3A443"
                "%%2C%%22network%%22%%3A%%22xhttp%%22%%2C%%22security%%22%%3A%%22reality%%22%%2C%%22realitySettings%%22%%3A%%7B"
                "%%22serverName%%22%%3A%%22rs.example%%22%%2C%%22fingerprint%%22%%3A%%22chrome%%22%%2C%%22publicKey%%22%%3A%%22"
                PBK "%%22%%2C%%22shortId%%22%%3A%%22ab%%22%%2C%%22mldsa65Verify%%22%%3A%%22%s%%22%%7D%%7D%%7D#r", PQV_KEY, PQV_KEY),
            xlink("type=xhttp&security=none&path=%2Fxp&mode=packet-up",
                  "{\"downloadSettings\":{\"address\":\"[2001:db8::5]\",\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":"
                  "{\"host\":\"cdn.example\",\"path\":\"/dl?k=v\",\"headers\":{\"X-Q\":\"a\\\"b\\\\c\",\"X-T\":\"1\\t2\"},"
                  "\"xPaddingBytes\":\"20-40\",\"scMaxEachPostBytes\":\"500-900\"}}}"),
            xlink("type=xhttp&security=none&path=%2Fxp",
                  "{\"downloadSettings\":{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":"
                  "{\"path\":\"/a\\\"b\\\\c\"}}}"),
            xlink("type=xhttp&security=none&path=%2Fxp&mode=packet-up",
                  "{\"sessionIDTable\":\"hex\",\"sessionIDLength\":\"16-20\",\"downloadSettings\":{\"address\":\"d.example\","
                  "\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":{\"sessionIDPlacement\":\"header\",\"sessionIDKey\":\"X-S\","
                  "\"seqPlacement\":\"header\",\"seqKey\":\"X-Q\",\"uplinkDataPlacement\":\"header\",\"uplinkDataKey\":\"X-D\","
                  "\"uplinkChunkSize\":\"100-200\",\"uplinkHTTPMethod\":\"GET\",\"xPaddingObfsMode\":true,\"xPaddingKey\":\"pk\","
                  "\"xPaddingHeader\":\"X-P\",\"xPaddingPlacement\":\"header\",\"xPaddingMethod\":\"tokenish\","
                  "\"scMaxBufferedPosts\":40}}}"),
            xlink("type=xhttp&security=none&path=%2Fxp",
                  "{\"xPaddingBytes\":\"30-60\",\"downloadSettings\":{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\","
                  "\"xhttpSettings\":{\"sessionPlacement\":\"cookie\",\"sessionKey\":\"sid\",\"xPaddingObfsMode\":false}}}"),
            xlink("type=xhttp&security=tls&sni=m.example&path=%2Fxp",
                  "{\"downloadSettings\":{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"security\":\"tls\","
                  "\"tlsSettings\":{\"serverName\":\"dl.example\",\"allowInsecure\":true}}}"),
        };
        /* catches: a block field lost or an unescaped quote breaking the JSON on the way to tunvless */
        links("xhttp-download", v, N(v));
        vless_set_insecure(1);
        links("xhttp-download, --insecure", v, N(v));
        struct vless_node n, m;
        char buf[512];
        int w = vless_parse_url(v[N(v) - 1], &n);
        size_t l = w ? 0 : vless_node_link(&n, buf, sizeof buf);
        vless_set_insecure(0);
        int r = l ? vless_parse_url(buf, &m) : -2;
        /* catches: an allowInsecure block written under --insecure taken by a reader without it */
        check("xhttp-download: insecure block written under --insecure", 1, w == 0 && l > 0);
        check("xhttp-download: insecure block read without --insecure, skipped", 1, r);
        check_str("xhttp-download: insecure block read without --insecure, reason",
                  "downloadSettings: allowInsecure: needs --insecure", r == 1 ? m.skip_reason : "");
        for (size_t i = 0; i < N(v); i++) free((void *)v[i]);
    }
    {
        static const char *const v[] = {
            "proxies:\n  - name: cdl\n    type: vless\n    server: m.example\n    port: 443\n    uuid: " UUID "\n"
            "    network: xhttp\n    tls: true\n    servername: m.example\n    client-fingerprint: chrome\n"
            "    xhttp-opts:\n      path: /xp\n      download-settings:\n        server: d.example\n        path: /dl\n",
        };
        /* catches: a Clash block's inherited port, tls, servername or fingerprint lost on the way to tunvless */
        subs("xhttp-download Clash", v, N(v));
    }
    {
        static const char *const v[] = {
            "{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"xn\",\"settings\":{\"vnext\":[{\"address\":\"m.example\","
            "\"port\":443,\"users\":[{\"id\":\"" UUID "\"}]}]},\"streamSettings\":{\"network\":\"xhttp\",\"security\":\"tls\","
            "\"tlsSettings\":{\"serverName\":\"m.example\"},\"xhttpSettings\":{\"path\":\"/xp\",\"downloadSettings\":"
            "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"security\":\"none\","
            "\"tlsSettings\":{\"serverName\":\"dl.example\"}}}}}]}",
        };
        /* catches: a block's tls fields dropped when its security is none or reality */
        subs("xhttp-download Xray none block", v, N(v));
    }
    {
        static const char *const v[] = {
            "proxies:\n  - name: cdr\n    type: vless\n    server: m.example\n    port: 443\n    uuid: " UUID "\n"
            "    network: xhttp\n    tls: true\n    servername: m.example\n    client-fingerprint: chrome\n"
            "    fingerprint: " H1 "\n    skip-cert-verify: true\n    ech-opts:\n      enable: true\n      config: \"" ECH "\"\n"
            "    reality-opts:\n      public-key: " PBK "\n      short-id: ab\n"
            "    xhttp-opts:\n      path: /xp\n      download-settings:\n        server: d.example\n        port: 8443\n",
        };
        vless_set_insecure(1);
        /* catches: a block's tls fields dropped when its security is none or reality */
        subs("xhttp-download Clash reality block", v, N(v));
        vless_set_insecure(0);
    }
    {
        static const char want[] =
            "vless://u@m.example:443?type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=packet-up&extra="
            "%7B%22downloadSettings%22%3A%7B%22address%22%3A%222001%3Adb8%3A%3A5%22%2C%22port%22%3A8443%2C"
            "%22network%22%3A%22xhttp%22%2C%22security%22%3A%22tls%22%2C%22tlsSettings%22%3A%7B%22serverName%22%3A"
            "%22d.example%22%7D%2C%22xhttpSettings%22%3A%7B%22host%22%3A%22cdn.example%22%2C%22path%22%3A"
            "%22%2Fdl%3Fk%3Dv%22%2C%22headers%22%3A%7B%22X-Q%22%3A%22a%5C%22b%5C%5Cc%22%2C%22X-T%22%3A"
            "%221%5Cu00092%22%7D%2C%22xPaddingBytes%22%3A%2220-40%22%2C%22seqKey%22%3A%22q%22%7D%7D%7D#d";
        static const char want0[] =
            "vless://u@h:443?type=xhttp&security=reality&sni=a.com&pbk=K&path=%2Fx&extra=%7B%22xPaddingBytes%22%3A%2250-150%22%7D#x";
        struct vless_node n;
        char buf[2048];
        int rc = vless_parse_url(
            "vless://u@m.example:443?mode=packet-up&path=/xp&sni=m.example&security=tls&type=xhttp&extra="
            "%7B%22downloadSettings%22%3A%7B%22network%22%3A%22xhttp%22%2C%22xhttpSettings%22%3A%7B%22seqKey%22%3A"
            "%22q%22%2C%22headers%22%3A%7B%22X-Q%22%3A%22a%5Cu0022b%5C%5Cc%22%2C%22X-T%22%3A%221%5Ct2%22%7D%2C"
            "%22path%22%3A%22%2Fdl%3Fk%3Dv%22%2C%22host%22%3A%22cdn.example%22%2C%22xPaddingBytes%22%3A%2220-40%22%7D"
            "%2C%22port%22%3A8443%2C%22tlsSettings%22%3A%7B%22serverName%22%3A%22d.example%22%7D%2C%22security%22%3A"
            "%22tls%22%2C%22address%22%3A%22%5B2001%3Adb8%3A%3A5%5D%22%7D%7D#d", &n);
        size_t l = rc ? 0 : vless_node_link(&n, buf, sizeof buf);
        /* catches: a block member out of order, unescaped, or escaped another way than JSON */
        check("xhttp-download: the block written as JSON members in order", 0, l ? strcmp(buf, want) : -1);
        rc = vless_parse_url("vless://u@m.example:443?type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=packet-up"
                             "&extra=%7B%22downloadSettings%22%3A%7B%22address%22%3A%22d.example%22%2C%22port%22%3A443%2C"
                             "%22network%22%3A%22xhttp%22%2C%22tlsSettings%22%3A%7B%7D%2C%22xhttpSettings%22%3A%7B%7D%7D%7D#d", &n);
        l = rc ? 0 : vless_node_link(&n, buf, sizeof buf);
        /* catches: an empty tlsSettings or xhttpSettings written into the block */
        check("xhttp-download: a bare block written without empty objects", 0, l ? strcmp(buf,
              "vless://u@m.example:443?type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=packet-up&extra="
              "%7B%22downloadSettings%22%3A%7B%22address%22%3A%22d.example%22%2C%22port%22%3A443%2C"
              "%22network%22%3A%22xhttp%22%2C%22security%22%3A%22none%22%7D%7D#d") : -1);
        rc = vless_parse_url("vless://u@m.example:443?type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=packet-up"
                             "&extra=%7B%22downloadSettings%22%3A%7B%22security%22%3A%22none%22%2C%22tlsSettings%22%3A%7B"
                             "%22serverName%22%3A%22dl.example%22%7D%2C%22address%22%3A%22d.example%22%2C%22port%22%3A443%2C"
                             "%22network%22%3A%22xhttp%22%7D%7D#d", &n);
        l = rc ? 0 : vless_node_link(&n, buf, sizeof buf);
        /* catches: a none block's serverName written under another object name or dropped */
        check("xhttp-download: a none block keeps its serverName in tlsSettings", 0, l ? strcmp(buf,
              "vless://u@m.example:443?type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=packet-up&extra="
              "%7B%22downloadSettings%22%3A%7B%22address%22%3A%22d.example%22%2C%22port%22%3A443%2C"
              "%22network%22%3A%22xhttp%22%2C%22security%22%3A%22none%22%2C%22tlsSettings%22%3A%7B"
              "%22serverName%22%3A%22dl.example%22%7D%7D%7D#d") : -1);
        rc = vless_parse_url("vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx"
                             "&extra=%7B%22xPaddingBytes%22%3A%2250-150%22%7D#x", &n);
        l = rc ? 0 : vless_node_link(&n, buf, sizeof buf);
        /* catches: a node without a block given any downloadSettings member */
        check("xhttp-download: a node without a block keeps its bytes", 0, l ? strcmp(buf, want0) : -1);
    }
    {
        static const char *const v[] = {
            "vless://a@h1:443#one" "vless://b@h2:443#two",
            "vless://a@h1:443" "vless://b@h2:8443",
            "vless://a@h1:443#Express" "ss://b@h2:443#other",
            "vless://a@h1:443#канал https://t.me/shop",
            "vless://a@1.2.3.4:443?security=reality&pbk=K&sni=x.com#ok\n"
            "vless://b@[2001:db8::1]:443?security=reality&pbk=K&sni=x.com#ipv6\n"
            "vless://c@5.6.7.8:0?security=reality&pbk=K&sni=x.com#zero-port\n"
            "vless://d@9.9.9.9:443?security=tls#tls\n"
            "hy2://e@10.0.0.1:443#foreign\n",
            "vless://TMG_74317ba5f91@1.2.3.4:443?security=reality&pbk=K&sni=x.com#Короткий\n"
            "vless://" U2 "@5.6.7.8:443?security=reality&pbk=K&sni=x.com#UUID\n"
            "vless://0123456789abcdef0123456789abcde@9.9.9.9:443?security=reality&pbk=K&sni=x.com#Щель\n",
            "vless://a@h1:443#one\nvless://b@h2:443#two\nss://c@h3:443#x\n",
            "dmxlc3M6Ly9hQGg6NDQz",
        };
        /* catches: a node of a plain or base64 link list not read back the same */
        subs("link lists", v, N(v));
    }
    {
        static const char *const v[] = {
            "[{\"dns\":{\"servers\":[{\"address\":\"https://dns.google/dns-query\"}]},"
            " \"outbounds\":["
            "  {\"tag\":\"ch01_tcp\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"179.237.82.105\",\"port\":443,"
            "     \"users\":[{\"id\":\"" U2 "\",\"flow\":\"xtls-rprx-vision\",\"encryption\":\"none\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"ch01.example.org\","
            "       \"fingerprint\":\"chrome\",\"publicKey\":\"PBK123\",\"shortId\":\"a1b2\"}}},"
            "  {\"tag\":\"direct\",\"protocol\":\"freedom\",\"settings\":{}}"
            " ]},"
            " {\"outbounds\":["
            "  {\"settings\":{\"vnext\":[{\"address\":\"87.120.126.31\",\"port\":2087,"
            "     \"users\":[{\"id\":\"" U2 "\"}]}]},"
            "   \"streamSettings\":{\"network\":\"grpc\",\"security\":\"reality\","
            "     \"grpcSettings\":{\"serviceName\":\"svc\"},"
            "     \"realitySettings\":{\"serverName\":\"de01.example.org\",\"publicKey\":\"PBK456\"}},"
            "   \"protocol\":\"vless\",\"tag\":\"de01_grpc\"}"
            " ]}]",
            "[{\"outbounds\":["
            "  {\"tag\":\"proxy\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"de.example.org\",\"port\":443,"
            "     \"users\":[{\"id\":\"" U2 "\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P1\"}}}],"
            " \"remarks\":\"🇩🇪 Германия\"},"
            " {\"outbounds\":["
            "  {\"tag\":\"tl-8-1-43al6bgvgg4\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"de.example.org\",\"port\":443,"
            "     \"users\":[{\"id\":\"" U2 "\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P2\"}}},"
            "  {\"tag\":\"tl-8-2-8mj546dasfg\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"backup.example.org\",\"port\":443,"
            "     \"users\":[{\"id\":\"" U2 "\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P3\"}}}],"
            " \"remarks\":\"МОБИЛЬНЫЙ АВТО\"}]",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"h\",\"port\":443,"
            "\"users\":[{\"id\":\"u\"}]}]}}]}",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"h\",\"port\":443,"
            "\"users\":[{\"id\":\"u\"}]}]},\"streamSettings\":{\"network\":\"raw\"}}]}",
            XO("{\"wsSettings\":{\"path\":\"/w?ed=2048\",\"headers\":{\"Host\":\"hdr.example\",\"X-A\":\"1\"}},"
               "\"xhttpSettings\":{\"path\":\"/x\"},\"network\":\"websocket\"}"),
            XO("{\"network\":\"ws\",\"wsSettings\":{\"host\":\"h1\",\"headers\":{\"host\":\"h2\"}}}"),
            XO("{\"network\":\"httpupgrade\",\"httpupgradeSettings\":{\"path\":\"/u\",\"host\":\"c\",\"headers\":{\"x-b\":\"2\"}}}"),
            XO("{\"network\":\"httpupgrade\",\"httpupgradeSettings\":{\"headers\":{\"connection\":\"keep-alive\"}}}"),
            XO("{\"network\":\"ws\",\"wsSettings\":{\"path\":\"/w\",\"headers\":{\"X-A\":\"a b; c=\\\"d\\\"\",\"X-B\":\"\\u00e9\"}}}"),
            XO("{\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/x\"},\"wsSettings\":{\"path\":\"/w\"}}"),
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"x.example\",\"port\":443,"
            "\"users\":[{\"id\":\"" UUID "\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\","
            "\"tlsSettings\":{\"serverName\":\"x.example\",\"pinnedPeerCertSha256\":\"" H1 "\","
            "\"verifyPeerCertByName\":\"v.example\"}}}]}",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"x.example\",\"port\":443,"
            "\"users\":[{\"id\":\"" UUID "\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"tls\","
            "\"tlsSettings\":{\"serverName\":\"x.example\",\"echConfigList\":\"" ECH "\"}}}]}",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"odd\",\"settings\":{\"vnext\":[{\"address\":\"x.example\",\"port\":443,"
            "\"users\":[{\"id\":\"" UUID "\",\"flow\":\"f&l=o%w\"}]}]},\"streamSettings\":{\"network\":\"grpc\",\"security\":\"reality\","
            "\"grpcSettings\":{\"serviceName\":\"svc/svc/svc/svc/svc/svc/svc/svc/svc/svc/svc/svc/svc/svc/a b&\"},"
            "\"realitySettings\":{\"serverName\":\"s n#.example\",\"fingerprint\":\"f%2Fp\",\"publicKey\":\"P+K/=\",\"shortId\":\"a&b\"}}}]}",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"x # 50% off\",\"settings\":{\"vnext\":[{\"address\":\"x.example\",\"port\":443,"
            "\"users\":[{\"id\":\"" UUID "\"}]}]},\"streamSettings\":{\"network\":\"xhttp\",\"security\":\"tls\","
            "\"xhttpSettings\":{\"path\":\"/p q\",\"host\":\"hx.example\",\"mode\":\"packet-up\","
            "\"extra\":{\"xPaddingBytes\":\"20-30\",\"scMaxEachPostBytes\":\"1000-2000\"}},"
            "\"tlsSettings\":{\"serverName\":\"x.example\",\"fingerprint\":\"firefox\"}}}]}",
        };
        /* catches: a field only an Xray config gives (headers, remarks name, raw transport) lost in the link */
        subs("Xray JSON", v, N(v));
    }
    {
        const char *v[] = {
            fmt("[{\"remarks\":\"PQ\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
                "\"settings\":{\"vnext\":[{\"address\":\"example.org\",\"port\":443,\"users\":[{\"id\":\"" UUID "\","
                "\"flow\":\"xtls-rprx-vision\",\"encryption\":\"none\"}]}]},"
                "\"streamSettings\":{\"network\":\"raw\",\"security\":\"reality\",\"realitySettings\":{"
                "\"serverName\":\"example.com\",\"fingerprint\":\"chrome\",\"publicKey\":\"" PBK "\","
                "\"shortId\":\"01\",\"mldsa65Verify\":\"%s\"}}}]},"
                "{\"remarks\":\"ENC\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
                "\"settings\":{\"vnext\":[{\"address\":\"example.net\",\"port\":8443,\"users\":[{\"id\":\"" UUID "\","
                "\"encryption\":\"%s\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}]},"
                "{\"remarks\":\"SIMPLE\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
                "\"settings\":{\"address\":\"example.io\",\"port\":\"9443\",\"id\":\"" UUID "\",\"encryption\":\"%s\"},"
                "\"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}]}]",
                PQV_KEY, ENC_X25519, ENC_MLKEM),
            fmt("vless://" UUID "@a.example:443?encryption=%s&type=tcp&security=none#ok1\n"
                "vless://" UUID "@b.example:443?encryption=bogus&type=tcp&security=none#bad1\n"
                "vless://" UUID "@c.example:443?encryption=%s&type=tcp&security=none#ok2\n", ENC_MLKEM, ENC_X25519),
        };
        /* catches: a post-quantum value from a config or a list lost in the link */
        subs("post-quantum configs", v, N(v));
        for (size_t i = 0; i < N(v); i++) free((void *)v[i]);
    }
    {
        static const char *const v[] = {
            "{\"log\":{},\"outbounds\":[{\"type\":\"selector\",\"tag\":\"sel\",\"outbounds\":[\"a\"]},"
            "{\"type\":\"vless\",\"tag\":\"sb-reality\",\"server\":\"example.org\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"example.com\","
            "\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"},\"reality\":{\"enabled\":true,"
            "\"public_key\":\"" PBK "\",\"short_id\":\"0123456789abcdef\"}}},"
            "{\"type\":\"vless\",\"tag\":\"sb-ws\",\"server\":\"cdn.example.org\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"tls\":{\"enabled\":true,\"server_name\":\"cdn.example.org\"},"
            "\"transport\":{\"type\":\"ws\",\"path\":\"/ws\","
            "\"headers\":{\"Host\":[\"front.example.org\",\"other.example.org\"]},"
            "\"max_early_data\":2048,\"early_data_header_name\":\"Sec-WebSocket-Protocol\"}},"
            "{\"type\":\"trojan\",\"tag\":\"t\",\"server\":\"x\",\"server_port\":1}]}",
            "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"a\",\"server\":\"x.example\","
            "\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"transport\":{\"type\":\"ws\",\"path\":\"/ws\",\"max_early_data\":2048}}]}",
            "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"sb\",\"server\":\"h\","
            "\"server_port\":443,\"uuid\":\"" SBU "\","
            "\"transport\":{\"type\":\"ws\",\"headers\":{\"X-A\":\"1\"}}}]}",
            "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"a\",\"server\":\"x.example\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"tls\":{\"enabled\":true,\"server_name\":\"x.example\","
            "\"certificate_public_key_sha256\":[\"1hD3S62x74la2vO7hT4FuMdtQwscW6lAZrzE1Ua3dn0=\"]}}]}",
            "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"a\",\"server\":\"x.example\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"tls\":{\"enabled\":true,\"server_name\":\"x.example\",\"ech\":{\"enabled\":true,\"config\":["
            "\"-----BEGIN ECH CONFIGS-----\",\"" ECH "\",\"-----END ECH CONFIGS-----\"]}}}]}",
            "{\"outbounds\":["
            "{\"type\":\"vless\",\"tag\":\"sb1\",\"server\":\"h1\",\"server_port\":443,\"uuid\":\"" SBU "\"},"
            "{\"type\":\"vless\",\"tag\":\"sb2\",\"server\":\"h2\",\"server_port\":443,\"uuid\":\"" SBU "\"},"
            "{\"type\":\"vless\",\"tag\":\"sb3\",\"server\":\"h3\",\"server_port\":443,\"uuid\":\"" SBU "\"}]}",
            "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"hu\",\"server\":\"h\",\"server_port\":443,\"uuid\":\"" SBU "\","
            "\"transport\":{\"type\":\"httpupgrade\",\"path\":\"/u p\",\"host\":\"up.example\","
            "\"headers\":{\"X-One\":\"1\",\"X-Two\":\"two words\"}}}]}",
        };
        /* catches: sing-box headers or the SubjectPublicKeyInfo pin (pks) lost in the link */
        subs("sing-box JSON", v, N(v));
    }
    {
        const char *v[] = {
            fmt("port: 7890\nmixed-port: 7891\nproxies:\n"
                "  - name: \"clash-block\"   # комментарий\n"
                "    type: vless\n    server: example.org\n    port: 443\n    uuid: " UUID "\n"
                "    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n"
                "    servername: example.com   # SNI\n"
                "    client-fingerprint: chrome\n    encryption: \"\"\n"
                "    alpn:\n      - h2\n      - http/1.1\n"
                "    reality-opts:\n      public-key: " PBK "\n      short-id: 0123456789abcdef\n"
                "  - {name: clash-flow, type: vless, server: cdn.example.org, port: 8443, uuid: " UUID ", network: ws, tls: true, "
                "servername: cdn.example.org, ws-opts: {path: /ws, headers: {Host: front.example.org}, max-early-data: 2048, "
                "early-data-header-name: Sec-WebSocket-Protocol}}\n"
                "  - name: clash-enc\n    type: vless\n    server: enc.example.org\n    port: 9443\n    uuid: " UUID "\n"
                "    network: tcp\n    encryption: %s\n"
                "  - name: ss-node\n    type: ss\n    server: s\n    port: 1\n    cipher: aes-128-gcm\n    password: p\n"
                "  - name: grpc-node\n    type: vless\n    server: g.example.org\n    port: 443\n    uuid: " UUID "\n"
                "    network: grpc\n    tls: true\n"
                "    grpc-opts:\n      grpc-service-name: svc\n"
                "proxy-groups:\n  - name: auto\n    type: select\n    proxies:\n      - clash-block\n", ENC_X25519),
            fmt("proxies:\n  - name: c1\n    type: vless\n    server: x.example\n    port: 443\n    uuid: " UUID "\n"
                "    network: tcp\n    tls: true\n    servername: x.example\n"
                "    fingerprint: " H1 "\n"
                "  - name: c2\n    type: vless\n    server: y.example\n    port: 443\n    uuid: " UUID "\n"
                "    network: tcp\n    tls: true\n    servername: y.example\n    skip-cert-verify: true\n"),
            fmt("proxies:\n  - name: c1\n    type: vless\n    server: x.example\n    port: 443\n    uuid: " UUID "\n"
                "    network: tcp\n    tls: true\n    servername: x.example\n    ech-opts:\n      enable: true\n"
                "      config: %s\n", ECH),
            fmt("proxies:\n"
                "  - name: c1\n    type: vless\n    server: h1\n    port: 443\n    uuid: " SBU "\n"
                "  - {name: c2, type: vless, server: h2, port: 443, uuid: " SBU "}\n"
                "  - name: c3\n    type: vless\n    server: h3\n    port: 443\n    uuid: " SBU "\n"),
            fmt("proxies:\n  - {name: \"c ws\", type: vless, server: h, port: 443, uuid: " SBU ", network: ws, "
                "ws-opts: {path: /, headers: {X-Hdr: v1, Host: wh.example}}}\n"),
        };
        /* catches: a Clash node (block or flow style, ws-opts headers, pins, ECH) not read back the same */
        subs("Clash YAML", v, N(v));
        vless_set_insecure(1);
        /* catches: skip-cert-verify not carried by the link under --insecure */
        subs("Clash YAML, --insecure", v, N(v));
        vless_set_insecure(0);
        for (size_t i = 0; i < N(v); i++) free((void *)v[i]);
    }

    {
        struct vless_node n, m;
        struct vless_node out[2];
        char buf[2048];
        size_t c = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"v6\",\"server\":\"2001:db8::1\","
                                   "\"server_port\":443,\"uuid\":\"" SBU "\"}]}", out, 2, NULL);
        size_t l = c ? vless_node_link(&out[0], buf, sizeof buf) : 0;
        static const char want6[] = "vless://" SBU "@[2001:db8::1]:443?";
        /* catches: an IPv6 node given a link the dialer cannot use, or a host written without brackets */
        check("IPv6 host: usable from a config", 1, (long)c);
        check("IPv6 host: bare in memory", 0, strcmp(out[0].host, "2001:db8::1"));
        check("IPv6 host: link", 1, l > 0 && !strncmp(buf, want6, sizeof want6 - 1));

        /* catches: bracketed or bare hosts of Xray, sing-box and Clash kept with brackets or lost */
        c = vless_parse_sub("{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"[2001:db8::2]\","
                            "\"port\":443,\"users\":[{\"id\":\"u\"}]}]}}]}", out, 2, NULL);
        check("Xray [v6] address: usable", 1, (long)c);
        check_str("Xray [v6] address: bare", "2001:db8::2", c ? out[0].host : "");
        c = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"server\":\"2001:db8::3\","
                            "\"server_port\":443,\"uuid\":\"" SBU "\"}]}", out, 2, NULL);
        check_str("sing-box v6 server: bare", "2001:db8::3", c ? out[0].host : "");
        c = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"server\":\"[2001:db8::3]\","
                            "\"server_port\":443,\"uuid\":\"" SBU "\"}]}", out, 2, NULL);
        check_str("sing-box [v6] server: bare", "2001:db8::3", c ? out[0].host : "");
        c = vless_parse_sub("proxies:\n  - name: c1\n    type: vless\n    server: 2001:db8::4\n    port: 443\n"
                            "    uuid: " SBU "\n", out, 2, NULL);
        check("Clash plain v6 server: usable", 1, (long)c);
        check_str("Clash plain v6 server: bare", "2001:db8::4", c ? out[0].host : "");
        c = vless_parse_sub("proxies:\n  - name: c1\n    type: vless\n    server: \"[2001:db8::5]\"\n    port: 443\n"
                            "    uuid: " SBU "\n", out, 2, NULL);
        check("Clash [v6] server: usable", 1, (long)c);
        check_str("Clash [v6] server: bare", "2001:db8::5", c ? out[0].host : "");

        /* catches: a bracket, port or character rule of the IPv6 host loosened */
        static const char *const bad6[] = {
            "vless://U@[2001:db8::1:443?security=none#x", "vless://U@[]:443?security=none#x",
            "vless://U@[2001:db8::1]443?security=none#x", "vless://U@[fe80::1%25eth0]:443?security=none#x",
            "vless://U@[2001:db8::1]:0?security=none#x", "vless://U@[x.example]:443?security=none#x",
            "vless://U@[2001:db8::1]?security=none#x", "vless://U@[2001:db8::g]:443?security=none#x",
            "vless://U@[1.2.3.4]:443?security=none#x",
        };
        for (size_t i = 0; i < N(bad6); i++) {
            char w[96];
            snprintf(w, sizeof w, "bad IPv6 host %zu: refused", i);
            check(w, -1, vless_parse_url(bad6[i], &n));
        }
        check("v6 link: parsed", 0, vless_parse_url("vless://U@[2001:db8::1]:443?security=reality&pbk=K&sni=x.com#six", &n));
        check_str("v6 link: host", "2001:db8::1", n.host);
        check("v6 link: port", 443, (long)n.port);
        l = vless_node_link(&n, buf, sizeof buf);
        check("v6 link: written in brackets", 1, !strncmp(buf, "vless://U@[2001:db8::1]:443?", 28));
        check("v6 link: round trip", 0, vless_parse_url(buf, &m) || strcmp(m.host, n.host) || m.port != n.port);

        /* catches: an uppercase-hex v6 host refused, or a mapped address matched case-sensitively */
        check("uppercase v6 link: parsed", 0, vless_parse_url("vless://U@[2001:DB8::1]:443?security=none#x", &n));
        check("uppercase mapped loopback: skipped", 1, vless_parse_url("vless://U@[::FFFF:127.0.0.1]:443?security=none#x", &n));
        check("uppercase mapped unspecified: skipped", 1, vless_parse_url("vless://U@[::FFFF:0.0.0.0]:443?security=none#x", &n));

        /* catches: a v6 branch of the writer accepting what the parser would refuse */
        static const char *const nolink[] = { "h.example:8443", "2001:db8::zz", "fe80::1%eth0", "[2001:db8::2", "2001:db8::2]" };
        for (size_t i = 0; i < N(nolink); i++) {
            struct vless_node z;
            vless_parse_url("vless://U@h:443?security=none#x", &z);
            snprintf(z.host, sizeof z.host, "%s", nolink[i]);
            char w[96];
            snprintf(w, sizeof w, "host %s: no link", nolink[i]);
            check(w, 0, (long)vless_node_link(&z, buf, sizeof buf));
        }
        c = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"server\":\"h.example:8443\","
                            "\"server_port\":443,\"uuid\":\"" SBU "\"}]}", out, 2, NULL);
        check("config host with a name and a colon: no link", 0, c ? (long)vless_node_link(&out[0], buf, sizeof buf) : 0);
        c = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"server\":\"2001:db8::zz\","
                            "\"server_port\":443,\"uuid\":\"" SBU "\"}]}", out, 2, NULL);
        check("config host 2001:db8::zz: no link", 0, c ? (long)vless_node_link(&out[0], buf, sizeof buf) : 0);
        c = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"server\":\"[2001:db8::2\","
                            "\"server_port\":443,\"uuid\":\"" SBU "\"}]}", out, 2, NULL);
        check("config unclosed [ host kept as written", 1, c ? out[0].host[0] == '[' : 1);
        c = vless_parse_sub("{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"address\":\"[2001:db8::3]\","
                            "\"port\":443,\"id\":\"u\"}}]}", out, 2, NULL);
        check_str("Xray short form [v6] address: bare", "2001:db8::3", c ? out[0].host : "");

        /* catches: a mapped loopback or unspecified address dialled */
        check("mapped loopback: skipped", 1, vless_parse_url("vless://U@[::ffff:127.0.0.1]:443?security=none#x", &n));
        check_str("mapped loopback: reason", "::ffff:127.0.0.1: nobody to answer", n.skip_reason);
        check("mapped unspecified: skipped", 1, vless_parse_url("vless://U@[::ffff:0.0.0.0]:443?security=none#x", &n));
        check("unspecified: skipped", 1, vless_parse_url("vless://U@[::]:443?security=none#x", &n));
        check_str("unspecified: reason", "::: nobody to answer", n.skip_reason);
        check("mapped public: usable", 0, vless_parse_url("vless://U@[::ffff:8.8.8.8]:443?security=none#x", &n));
        static const char *const sinks6[] = { "::ffff:7f00:1", "::FFFF:7F35:0", "0:0:0:0:0:0:0:1", "::0", "0::",
                                              "::ffff:0:0", "0:0:0:0:0:ffff:7fff:ffff" };
        for (size_t i = 0; i < N(sinks6); i++) {
            snprintf(buf, sizeof buf, "vless://U@[%s]:443?security=none#x", sinks6[i]);
            char w[96];
            snprintf(w, sizeof w, "%s: skipped", sinks6[i]);
            /* catches: a sink spelled another way than the usual string dialled */
            check(w, 1, vless_parse_url(buf, &n));
        }
        /* catches: a bracketed sink taken as written and dialled */
        check("[::1] as written: leads nowhere", 1, sl_host_leads_nowhere("[::1]"));
        check("[::ffff:7f00:1] as written: leads nowhere", 1, sl_host_leads_nowhere("[::ffff:7f00:1]"));
        check("[2001:db8::1] as written: leads somewhere", 0, sl_host_leads_nowhere("[2001:db8::1]"));
        static const char *const live6[] = { "::2", "::ffff:128.0.0.1", "::ffff:126.255.255.255", "::ffff:0:1", "::1:0", "1::",
                                             "::7f00:1", "::1:ffff:7f00:1", "::fffe:7f00:1" };
        for (size_t i = 0; i < N(live6); i++) {
            snprintf(buf, sizeof buf, "vless://U@[%s]:443?security=none#x", live6[i]);
            char w[96];
            snprintf(w, sizeof w, "%s: usable", live6[i]);
            /* catches: an address next to a sink taken for one */
            check(w, 0, vless_parse_url(buf, &n));
        }

        c = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"at\",\"server\":\"h.example\","
                            "\"server_port\":443,\"uuid\":\"a@b\"}]}", out, 2, NULL);
        /* catches: an id with '@' written raw, which would move the host boundary */
        check("id with '@': usable from a config", 1, (long)c);
        check("id with '@': no link", 0, c ? (long)vless_node_link(&out[0], buf, sizeof buf) : -1);

        /* catches: a header line break from a link reaching the request */
        check("headers= with CR LF: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=ws&headers=X-A%3A%201%0D%0AX-Evil%3A%202%0A#n", &n));
        check_str("headers= with CR LF: reason", "invalid headers for ws", n.skip_reason);
        /* catches: a headers= value longer than the field cut instead of refused */
        snprintf(buf, sizeof buf, "vless://" UUID "@h.example:443?type=ws&headers=");
        for (int i = 0; i < 20; i++) strcat(buf, "X-Long-Name%3A%20vvvv%0A");
        strcat(buf, "#n");
        check("headers= longer than the field: node skipped", 1, vless_parse_url(buf, &n));
        /* catches: headers= lines not in "Name: value" form accepted */
        check("headers= without a colon: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=httpupgrade&headers=X-A%201%0A#n", &n));
        check("headers= with no space after the colon: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=httpupgrade&headers=X-A%3A1%0A#n", &n));
        check("headers= whose colon is on a later line: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=httpupgrade&headers=X-A%201%0AX-B%3A%202%0A#n", &n));
        /* catches: a Host header from a link reaching a request that assumes none */
        check("headers= with Host: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=httpupgrade&headers=Host%3A%20x%0A#n", &n));
        check_str("headers= with Host: reason", "invalid headers for httpupgrade", n.skip_reason);
        check("headers= with a lower-case host on ws: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=ws&headers=host%3A%20x%0A#n", &n));
        /* catches: a header gorilla refuses on ws let through from a link */
        check("headers= with Upgrade on ws: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=ws&headers=Upgrade%3A%20x%0A#n", &n));
        check("headers= with Sec-WebSocket-Key before type=ws: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?headers=Sec-WebSocket-Key%3A%20x%0A&type=ws#n", &n));
        check("headers= with Connection on httpupgrade: usable", 0, vless_parse_url(
            "vless://" UUID "@h.example:443?type=httpupgrade&headers=Connection%3A%20keep-alive%0A#n", &n));
        /* catches: a control byte decoded into type, security or mode echoed into skip_reason */
        check("type with a control byte: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=k%0Acp#n", &n));
        check_str("type with a control byte: fixed reason", "control byte in type, security or mode", n.skip_reason);
        check("security with a control byte: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?security=x%1Btls#n", &n));
        check("mode with a control byte: node skipped", 1, vless_parse_url(
            "vless://" UUID "@h.example:443?type=xhttp&mode=a%0Db#n", &n));
        check("headers= of valid lines: usable", 0, vless_parse_url(
            "vless://" UUID "@h.example:443?type=httpupgrade&headers=X-A%3A%201%0AX-B%3A%20two%20words%0A#n", &n));
        check_str("headers= of valid lines: stored as lines", "X-A: 1\nX-B: two words\n", n.headers);
        /* catches: pks= read as base64 (the sing-box form) instead of the hex the node holds */
        check("pks= hex: usable", 0, vless_parse_url("vless://" UUID "@h.example:443?security=tls&sni=h.example&pks=" H1 "#n", &n));
        check_str("pks= hex: stored", H1, n.pks ? n.pks : "");

        vless_parse_url("vless://" UUID "@h.example:443?type=tcp&security=none#n", &n);
        l = vless_node_link(&n, buf, sizeof buf);
        /* catches: a link longer than what is reported, or not NUL-terminated */
        check("link length is the string length", (long)strlen(buf), (long)l);
    }
    {
        char nm[160];
        memset(nm, 'a', 120);
        nm[120] = '\0';
        vless_name_cut(nm);
        /* catches: a control-mode name longer than 100 bytes kept whole */
        check("name cut: 120 ASCII bytes become 100", 100, (long)strlen(nm));
        memset(nm, 'a', 99);
        strcpy(nm + 99, "\xD0\x9F\xD0\x9F");
        vless_name_cut(nm);
        /* catches: a two-byte character split by the 100-byte cut */
        check("name cut: a split character is dropped", 99, (long)strlen(nm));
        strcpy(nm, "short");
        vless_name_cut(nm);
        /* catches: a short name altered by the cut */
        check_str("name cut: a short name stays", "short", nm);
    }
    {
        struct vless_node n;
        static const char it[] = "\xF0\x9F\x87\xAE\xF0\x9F\x87\xB9 \xF0\x9F\x8E\xAE \xE2\x9A\xA1\xEF\xB8\x8F "
                                 "\xE2\xAD\x90\xEF\xB8\x8F 0.1X - LTE \xE2\x84\x96" "109 - "
                                 "\xD0\x98\xD1\x82\xD0\xB0\xD0\xBB\xD0\xB8\xD1\x8F";
        vless_parse_url("vless://" UUID "@h.example:443?type=tcp&security=none#%F0%9F%87%AE%F0%9F%87%B9%20"
                        "%F0%9F%8E%AE%20%E2%9A%A1%EF%B8%8F%20%E2%AD%90%EF%B8%8F%200.1X%20-%20LTE%20%E2%84%96109"
                        "%20-%20%D0%98%D1%82%D0%B0%D0%BB%D0%B8%D1%8F", &n);
        check_str("name: a percent-encoded name that fits is kept whole", it, n.name);
        char pct[512] = "";
        for (int i = 0; i < 80; i++) strcat(pct, "%D0%9F");
        char *link = fmt("vless://" UUID "@h.example:443?type=tcp&security=none#%s", pct);
        vless_parse_url(link, &n);
        free(link);
        check("name: a long decoded name fills the field by whole characters", 126, (long)strlen(n.name));
    }
    {
        char v[32];
        for (int i = 0; i < 300; i++) {
            snprintf(v, sizeof v, "intern-%d", i);
            sl_intern(v, strlen(v));
        }
        /* catches: the precondition, a table with room left */
        check("intern: a full table answers full", 1, sl_intern("one-more", 8) == SL_FULL);
        sl_intern_reset();
        const char *a = sl_intern("one-more", 8);
        /* catches: a reset that leaves the table full */
        check("intern: after a reset there is room", 1, a != SL_FULL && a && !strcmp(a, "one-more"));
        sl_intern_reset();
    }
    {
        sl_intern_reset();
        sl_set_interner(own_intern);
        struct vless_node n;
        memset(&n, 0, sizeof n);
        int r = vless_parse_url("vless://" UUID "@example.org:443?security=tls&sni=t.example&pcs=" H1 "#own", &n);
        sl_set_interner(NULL);
        /* catches: a runtime node's long value stored in the shared table */
        check("interner: the node's pin comes from the set interner", 1, r == 0 && n.pcs == g_own_last && g_own_calls == 1);
        check("interner: the shared table is left empty", 1, sl_intern(H1, strlen(H1)) != n.pcs);
        g_own_fail = 1;
        sl_set_interner(own_intern);
        memset(&n, 0, sizeof n);
        r = vless_parse_url("vless://" UUID "@example.org:443?security=tls&sni=t.example&pcs=" H1 "#own", &n);
        sl_set_interner(NULL);
        /* catches: an interner out of memory taken as no value */
        check("interner: a failed interner leaves the node unusable", 1, r == 1);
        sl_intern_reset();
    }
    {
        struct skips sk = { 0 };
        vless_set_node_hook(on_skip, &sk);
        static struct vless_node out[8];
        size_t c = vless_parse_sub("vless://" UUID "@h.example:443?security=none#good\n"
                                   "vless://" UUID "@h.example:443?security=xtls#bad-sec\n"
                                   "vless://" UUID "@h.example:443?type=kcp#bad-type\n", out, 8, NULL);
        vless_set_node_hook(NULL, NULL);
        check("node hook: one usable node", 1, (long)c);
        /* catches: a node not reported to the hook, or reported out of body order */
        check("node hook: three nodes", 3, sk.n);
        check_str("node hook: first name", "good", sk.name[0]);
        check_str("node hook: second name", "bad-sec", sk.name[1]);
        check_str("node hook: third name", "bad-type", sk.name[2]);
        /* catches: a usable node given a reason, or a skipped one given none */
        check("node hook: usable has no reason", 1, sk.reason[0][0] == 0 && sk.reason[1][0] && sk.reason[2][0]);
        vless_parse_sub("vless://" UUID "@h.example:443?security=xtls#after\n", out, 8, NULL);
        /* catches: the hook still called once it is cleared */
        check("node hook: cleared hook not called", 3, sk.n);
    }

    {
        static struct vless_node fx[2];
        size_t c = vless_parse_sub("vless://" UUID "@h.example:443?security=reality&pbk=" PBK "&sni=a.com&fp=firefox#f\n"
                                   "vless://" UUID "@h.example:443?security=reality&pbk=" PBK "&sni=a.com&fp=chrome#c\n",
                                   fx, 2, NULL);
        struct tr_node t[6];
        vless_set_fp("chrome");
        sl_tr_node(&fx[0], &t[0]);
        vless_set_fp("firefox");
        sl_tr_node(&fx[1], &t[1]);
        vless_set_fp("");
        sl_tr_node(&fx[0], &t[2]);
        sl_tr_node(&fx[1], &t[3]);
        vless_set_fp("firefox");
        vless_set_fp(NULL);
        sl_tr_node(&fx[0], &t[4]);
        sl_tr_node(&fx[1], &t[5]);
        check("fp switch: both links usable", 2, (long)c);
        /* catches: --fp chrome lost on the way to the transport, or a firefox link kept over it */
        check("fp switch: chrome beats a firefox link", REALITY_FP_CHROME, reality_fp_of(t[0].fp));
        /* catches: --fp firefox lost on the way to the transport, or a chrome link kept over it */
        check("fp switch: firefox beats a chrome link", REALITY_FP_FIREFOX, reality_fp_of(t[1].fp));
        /* catches: an empty switch taken as a choice instead of the link's own fp */
        check("fp switch: empty leaves each link its fp", 10 * REALITY_FP_FIREFOX + REALITY_FP_CHROME,
              10 * reality_fp_of(t[2].fp) + reality_fp_of(t[3].fp));
        /* catches: a switch that NULL does not clear */
        check("fp switch: NULL leaves each link its fp", 10 * REALITY_FP_FIREFOX + REALITY_FP_CHROME,
              10 * reality_fp_of(t[4].fp) + reality_fp_of(t[5].fp));
    }

    t_fm_roundtrip();

    for (size_t i = 0; i < NFIELDS; i++) {
        char what[96];
        snprintf(what, sizeof what, "coverage: %s set in some round-tripped node", g_fields[i]);
        /* catches: a field the corpus never sets, so its round trip is never checked */
        check(what, 1, g_cover[i] > 0);
    }
    check("coverage table complete", 0, g_bad);
    return unit_done("vlinkmatch");
}
