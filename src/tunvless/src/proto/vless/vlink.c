#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vlink.h"
#include "sublink.h"

struct wbuf { char *p; size_t cap, n; int over, q; };

static void put(struct wbuf *w, const char *s, size_t l) {
    if (w->over || w->n + l >= w->cap) { w->over = 1; return; }
    memcpy(w->p + w->n, s, l);
    w->n += l;
    w->p[w->n] = '\0';
}

static void puts_(struct wbuf *w, const char *s) { put(w, s, strlen(s)); }

static void put_hex(struct wbuf *w, unsigned char c) {
    static const char hx[] = "0123456789ABCDEF";
    char e[3] = { '%', hx[c >> 4], hx[c & 15] };
    put(w, e, 3);
}

static int unreserved(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '.' || c == '_' || c == '~';
}

static void put_pct(struct wbuf *w, const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (unreserved(*p)) put(w, (const char *)p, 1);
        else put_hex(w, *p);
    }
}

static void put_name(struct wbuf *w, const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '%' || *p < 0x20 || *p == 0x7f) put_hex(w, *p);
        else put(w, (const char *)p, 1);
    }
}

static void param(struct wbuf *w, const char *k, const char *v) {
    if (!v || !v[0]) return;
    if (w->q++) put(w, "&", 1);
    puts_(w, k);
    put(w, "=", 1);
    put_pct(w, v);
}

static int is_marker(const char *v) {
    return v == SL_BAD_PQV || v == SL_FULL || v == SL_BAD_PIN || v == SL_BAD_ECH || v == SL_ECH_DNS ||
           v == SL_BAD_XHX || v == SL_BAD_XHX_JSON;
}

static void param_long(struct wbuf *w, const char *k, const char *v) {
    if (v && !is_marker(v)) param(w, k, v);
}

static void range(char *dst, size_t n, unsigned long a, unsigned long b) {
    if (a == b) snprintf(dst, n, "%lu", a);
    else snprintf(dst, n, "%lu-%lu", a, b);
}

static int xh_bare(const char *v, size_t l) {
    return (l == 4 && !memcmp(v, "true", 4)) || (l == 5 && !memcmp(v, "false", 5));
}

struct jbuf { char *p; size_t n, cap; int bad; };

static void jb_put(struct jbuf *b, const char *s, size_t l) {
    if (b->bad) return;
    if (b->n + l + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 256;
        while (c < b->n + l + 1) c *= 2;
        char *p = realloc(b->p, c);
        if (!p) { b->bad = 1; return; }
        b->p = p;
        b->cap = c;
    }
    memcpy(b->p + b->n, s, l);
    b->n += l;
    b->p[b->n] = '\0';
}

static void js_strn(struct jbuf *b, const char *s, size_t l) {
    jb_put(b, "\"", 1);
    for (const unsigned char *p = (const unsigned char *)s; p < (const unsigned char *)s + l; p++) {
        char e[8];
        if (*p == '"' || *p == '\\') { e[0] = '\\'; e[1] = (char)*p; jb_put(b, e, 2); }
        else if (*p < 0x20 || *p == 0x7f) { snprintf(e, sizeof e, "\\u%04X", *p); jb_put(b, e, 6); }
        else jb_put(b, (const char *)p, 1);
    }
    jb_put(b, "\"", 1);
}

static void js_str(struct jbuf *b, const char *s) { js_strn(b, s, strlen(s)); }

static void js_key(struct jbuf *b, int *k, const char *key, size_t l) {
    if ((*k)++) jb_put(b, ",", 1);
    js_strn(b, key, l);
    jb_put(b, ":", 1);
}

static void js_field(struct jbuf *b, int *k, const char *key, const char *v) {
    if (!v || !v[0] || is_marker(v)) return;
    js_key(b, k, key, strlen(key));
    js_str(b, v);
}

static void xh_members(struct jbuf *b, int *k, const struct vless_node *n) {
    const char *x = n->xhx && !is_marker(n->xhx) ? n->xhx : "";
    char r[32];
    if (n->pad_to) {
        range(r, sizeof r, n->pad_from, n->pad_to);
        js_field(b, k, "xPaddingBytes", r);
    }
    if (n->post_to) {
        range(r, sizeof r, n->post_from, n->post_to);
        js_field(b, k, "scMaxEachPostBytes", r);
    }
    int xk = 0, *kk = k;
    for (const char *p = x; *p;) {
        const char *e = strchr(p, '\n'), *eq = e ? memchr(p, '=', (size_t)(e - p)) : NULL;
        if (!eq) { b->bad = 1; return; }
        size_t vl = (size_t)(e - eq - 1), kl = (size_t)(eq - p);
        if (kl > 5 && !memcmp(p, "xmux.", 5)) {
            if (kk == k) { js_key(b, k, "xmux", 4); jb_put(b, "{", 1); kk = &xk; }
            p += 5, kl -= 5;
        }
        js_key(b, kk, p, kl);
        if (xh_bare(eq + 1, vl) || (kl == 16 && !memcmp(p, "hKeepAlivePeriod", 16))) jb_put(b, eq + 1, vl);
        else js_strn(b, eq + 1, vl);
        p = e + 1;
    }
    if (kk != k) jb_put(b, "}", 1);
}

static void js_headers(struct jbuf *b, const char *h) {
    int k = 0;
    jb_put(b, "{", 1);
    for (const char *p = h; *p;) {
        const char *e = strchr(p, '\n');
        if (!e) e = p + strlen(p);
        const char *c = memchr(p, ':', (size_t)(e - p));
        if (c) {
            const char *v = c + 1 < e && c[1] == ' ' ? c + 2 : c + 1;
            js_key(b, &k, p, (size_t)(c - p));
            js_strn(b, v, (size_t)(e - v));
        }
        p = *e ? e + 1 : e;
    }
    jb_put(b, "}", 1);
}

static void js_open(struct jbuf *b, int *k, const char *key, size_t *at, int *kat) {
    *at = b->n;
    *kat = *k;
    js_key(b, k, key, strlen(key));
    jb_put(b, "{", 1);
}

static void js_close(struct jbuf *b, int *k, int inner, size_t at, int kat) {
    if (inner || b->bad) { jb_put(b, "}", 1); return; }
    b->n = at;
    b->p[at] = '\0';
    *k = kat;
}

static void dl_json(struct jbuf *b, const struct vless_node *d) {
    char port[8];
    size_t at;
    int k = 0, s = 0, kat;
    jb_put(b, "{", 1);
    js_field(b, &k, "address", d->host);
    snprintf(port, sizeof port, "%u", d->port);
    js_key(b, &k, "port", 4);
    jb_put(b, port, strlen(port));
    js_field(b, &k, "network", "xhttp");
    js_field(b, &k, "security", d->security);
    js_open(b, &k, strcmp(d->security, "reality") ? "tlsSettings" : "realitySettings", &at, &kat);
    js_field(b, &s, "serverName", d->sni);
    js_field(b, &s, "fingerprint", d->fp);
    js_field(b, &s, "publicKey", d->pbk);
    js_field(b, &s, "shortId", d->sid);
    js_field(b, &s, "mldsa65Verify", d->pqv);
    js_field(b, &s, "pinnedPeerCertSha256", d->pcs);
    js_field(b, &s, "verifyPeerCertByName", d->vcn);
    js_field(b, &s, "echConfigList", d->ech);
    if (d->allow_insecure) { js_key(b, &s, "allowInsecure", 13); jb_put(b, "true", 4); }
    js_close(b, &k, s, at, kat);
    s = 0;
    js_open(b, &k, "xhttpSettings", &at, &kat);
    js_field(b, &s, "host", d->http_host);
    js_field(b, &s, "path", d->path);
    if (d->headers[0]) { js_key(b, &s, "headers", 7); js_headers(b, d->headers); }
    xh_members(b, &s, d);
    js_close(b, &k, s, at, kat);
    jb_put(b, "}", 1);
}

static void extra(struct wbuf *w, const struct vless_node *n) {
    struct jbuf b = { NULL, 0, 0, 0 };
    int k = 0;
    jb_put(&b, "{", 1);
    xh_members(&b, &k, n);
    if (n->dl && n->dl != &SL_DL_FULL) {
        js_key(&b, &k, "downloadSettings", 16);
        dl_json(&b, n->dl);
    }
    jb_put(&b, "}", 1);
    if (b.bad) w->over = 1;
    else if (k) param(w, "extra", b.p);
    free(b.p);
}

static int clean(const char *s, const char *bad) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (*p <= 0x20 || *p == 0x7f || strchr(bad, *p)) return 0;
    return 1;
}

size_t vless_node_link(const struct vless_node *n, char *out, size_t cap) {
    if (!out || !cap || n->skip_reason[0] || !n->port || !n->host[0]) return 0;
    int v6 = strchr(n->host, ':') != NULL;
    if (!clean(n->uuid, "@") || !clean(n->host, v6 ? "?#[]@/%" : "?#[]@/:")) return 0;
    if (v6 && strspn(n->host, "0123456789abcdefABCDEF:.") != strlen(n->host)) return 0;
    struct wbuf w = { out, cap, 0, 0, 0 };
    out[0] = '\0';
    puts_(&w, "vless://");
    puts_(&w, n->uuid);
    put(&w, "@", 1);
    if (v6) put(&w, "[", 1);
    puts_(&w, n->host);
    if (v6) put(&w, "]", 1);
    char port[8];
    snprintf(port, sizeof port, ":%u?", n->port);
    puts_(&w, port);
    param(&w, "type", n->type);
    param(&w, "security", n->security);
    param(&w, "sni", n->sni);
    param(&w, "fp", n->fp);
    param(&w, "pbk", n->pbk);
    param(&w, "sid", n->sid);
    param(&w, "flow", n->flow);
    param(&w, "path", n->path);
    param(&w, "serviceName", n->service);
    param(&w, "mode", n->mode);
    param(&w, "host", n->http_host);
    param(&w, "headers", n->headers);
    if (n->tcp_http) param(&w, "headerType", "http");
    extra(&w, n);
    param_long(&w, "pqv", n->pqv);
    param_long(&w, "encryption", n->encryption);
    param_long(&w, "pcs", n->pcs);
    param_long(&w, "pks", n->pks);
    param_long(&w, "vcn", n->vcn);
    param_long(&w, "ech", n->ech);
    if (n->allow_insecure) param(&w, "allowInsecure", "1");
    if (n->name[0]) {
        put(&w, "#", 1);
        put_name(&w, n->name);
    }
    if (w.over) { out[0] = '\0'; return 0; }
    return w.n;
}

void vless_name_cut(char *name) {
    if (strlen(name) <= VLESS_CTL_NAME_MAX) return;
    name[VLESS_CTL_NAME_MAX] = '\0';
    sl_utf8_trim_tail(name);
}
