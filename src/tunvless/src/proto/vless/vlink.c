#include <stdio.h>
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
    return v == SL_BAD_PQV || v == SL_FULL || v == SL_BAD_PIN || v == SL_BAD_ECH || v == SL_ECH_DNS;
}

static void param_long(struct wbuf *w, const char *k, const char *v) {
    if (v && !is_marker(v)) param(w, k, v);
}

static void range(char *dst, size_t n, unsigned long a, unsigned long b) {
    if (a == b) snprintf(dst, n, "%lu", a);
    else snprintf(dst, n, "%lu-%lu", a, b);
}

static void extra(struct wbuf *w, const struct vless_node *n) {
    char js[160], r[32];
    size_t o = 0;
    js[0] = '\0';
    if (n->pad_to) {
        range(r, sizeof r, n->pad_from, n->pad_to);
        o += (size_t)snprintf(js + o, sizeof js - o, "%s\"xPaddingBytes\":\"%s\"", o ? "," : "", r);
    }
    if (n->post_to) {
        range(r, sizeof r, n->post_from, n->post_to);
        o += (size_t)snprintf(js + o, sizeof js - o, "%s\"scMaxEachPostBytes\":\"%s\"", o ? "," : "", r);
    }
    if (n->xh_extra)
        o += (size_t)snprintf(js + o, sizeof js - o, "%s\"xPaddingObfsMode\":true", o ? "," : "");
    if (!o) return;
    char obj[sizeof js + 2];
    snprintf(obj, sizeof obj, "{%s}", js);
    param(w, "extra", obj);
}

static int clean(const char *s, const char *bad) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (*p <= 0x20 || *p == 0x7f || strchr(bad, *p)) return 0;
    return 1;
}

size_t vless_node_link(const struct vless_node *n, char *out, size_t cap) {
    if (!out || !cap || n->skip_reason[0] || !n->port || !n->host[0]) return 0;
    if (!clean(n->uuid, "@") || !clean(n->host, "?#[]@/:")) return 0;
    struct wbuf w = { out, cap, 0, 0, 0 };
    out[0] = '\0';
    puts_(&w, "vless://");
    puts_(&w, n->uuid);
    put(&w, "@", 1);
    puts_(&w, n->host);
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
