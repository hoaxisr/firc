/* The xhttp transport: the protocol stream in HTTP/2 request bodies, over one request or two
 * links.
 *
 * In stream-one mode xhttp wraps nothing: the request body is the stream up, the response body
 * the stream down. But it needs padding: the server checks the x_padding length in Referer and
 * answers 400 without it (see Xray hub.go). The stream-up and packet-up modes are described at
 * enum xhttp_mode in transport.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include "osrand.h"

#include "transport.h"
#include "xhreq.h"

/* The node's xhttp mode. Empty and "auto" resolve as in Xray's client (splithttp/dialer.go):
 * with reality stream-one, or stream-up when the download goes to its own endpoint; packet-up
 * otherwise (tls, none). A server may accept only the mode it was set to, and a packet-up server
 * answers 400 to stream-one, so auto must pick what Xray's client would. Other modes are named
 * in the link, and the node parser has dropped what we do not support (sl_link_usable_post in
 * sublink.c), so only these three arrive here. */
static enum xhttp_mode xhttp_mode_of(const struct tr_node *n) {
    if (!strcmp(n->mode, "packet-up")) return XH_PACKET_UP;
    if (!strcmp(n->mode, "stream-up")) return XH_STREAM_UP;
    if (!strcmp(n->mode, "stream-one")) return XH_STREAM_ONE;
    if (!n->security || strcmp(n->security, "reality")) return XH_PACKET_UP;
    return n->dl ? XH_STREAM_UP : XH_STREAM_ONE;
}

/* ---- the second link, for the upload -------------------------------------------------- */

static int up_write(void *ctx, const unsigned char *d, size_t n) {
    struct xh_up *u = ctx;
    return tr_link_write(&u->link, d, n);
}

static int up_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    struct xh_up *u = ctx;
    /* No direct copy here: Vision lives on the DOWNLOAD stream, and this link only writes. The
     * server's answers to the upload are empty 200s, read only to process the HTTP/2 control
     * frames and keep the window from filling.
     *
     * NO WAITING HERE. The answers are drained along with sending, and a blocking read would
     * stop the upload until an answer arrives, turning the stream into "send and wait". Over
     * TLS there is no waiting: tls13_read polls the socket with a zero timeout and returns zero
     * bytes when no record is there. A bare socket (security=none) does not behave like that,
     * and we poll ourselves; hence this link has its own read, not tr_link_read of the main
     * one. */
    if (u->link.plain) {
        struct pollfd p = { .fd = u->link.fd, .events = POLLIN };
        if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN)) { *got = 0; return 0; }
        ssize_t r = read(u->link.fd, d, cap);
        if (r == 0) return TR_ECLOSED;
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) { *got = 0; return 0; }
            return TR_EIO;
        }
        *got = (size_t)r;
        return 0;
    }
    return tls13_read(&u->link.tls, d, cap, got);
}

/* Drain what the server answered to the upload.
 *
 * WHY. For each packet-up chunk the server answers an empty 200: headers, an empty DATA,
 * END_STREAM, tens of bytes. Not reading them piles them up in the socket receive buffer; once
 * it is full the server stops writing, and its side of the parsing stalls too: the upload
 * hangs, the later the bigger the buffer, so "sometimes, on big files". The same call also
 * takes the HTTP/2 control frames (SETTINGS, WINDOW_UPDATE, PING); without them the connection
 * window would never be replenished.
 *
 * It does not wait and returns no data: what it reads is dropped. It does return a FAILURE: the
 * xhttp server answers non-200 to a chunk it refused (for example 400 to a padding of the wrong
 * length), and that chunk is lost, so the stream after it cannot be whole. Without this the
 * node looks alive while no traffic flows. Other h2_read codes are not failures here: H2_ERESET
 * in packet-up is the normal end of a chunk's answer, and a broken link is reported by the next
 * write. */
static int up_drain(struct xh_up *u) {
    if (!u->started) return 0;
    static __thread unsigned char sink[H2_MIN_READ_CAP];
    /* Until the link is empty, bounded so one call cannot spin. NOT until a read returns no
     * data: on this link no read ever does (the answers are bodiless 200s), and stopping there
     * took one record per call, with a chunk's answer behind WINDOW_UPDATEs and SETTINGS. */
    for (int i = 0; i < 64; i++) {
        /* packet-up: the CURRENT chunk answered (done) says nothing of the older ones, whose
         * answers may still be on the way: the server answers in any order. h2_read would refuse
         * to read once done was set, and the oldest chunk's answer was never read: its window
         * stayed full and the upload stalled for good (no new chunk, so no h2_next_req to clear it). */
        if (u->h2.done && !u->h2.pend_err && h2_open_streams(&u->h2) > 0) u->h2.done = 0;
        int more = !u->link.plain && tls13_has_record(&u->link.tls);
        if (!more) {
            struct pollfd p = { .fd = u->link.fd, .events = POLLIN };
            more = poll(&p, 1, 0) > 0 && (p.revents & POLLIN);
        }
        if (!more) return 0;
        size_t got = 0;
        int rc = h2_read(&u->h2, sink, sizeof(sink), &got);
        if (rc == H2_ESTATUS) return rc;
        if (rc) return 0;
    }
    return 0;
}

static int up_alpn(const struct xh_up *u) {
    return !u->link.plain && u->link.tls.alpn[0] && strcmp(u->link.tls.alpn, "h2") ? TR_ENOH2 : 0;
}

int tr_xhttp_two(const struct tr_node *n) { return xhttp_mode_of(n) != XH_STREAM_ONE; }

#define XH_BLOCK 16384
#define XH_MAIN 72
#define XH_PIECES 256
#define XH_PAIRS 72
#define XH_ARENA 32768
#define XH_SEQ_WORST "18446744073709551615"

enum xh_kind { XK_ONE, XK_DOWN, XK_UP, XK_PACKET };

struct xh_ar { char *p; size_t n, cap; int over; };

static char *ar_begin(struct xh_ar *a) { return a->p + a->n; }

static void ar_cat(struct xh_ar *a, const char *s, size_t n) {
    if (a->over || a->n + n + 1 > a->cap) { a->over = 1; return; }
    memcpy(a->p + a->n, s, n);
    a->n += n;
}

static char *ar_end(struct xh_ar *a, char *start) {
    if (a->over || a->n + 1 > a->cap) { a->over = 1; return NULL; }
    a->p[a->n++] = '\0';
    return start;
}

static const char *ar_str(struct xh_ar *a, const char *s, size_t n) {
    char *b = ar_begin(a);
    ar_cat(a, s, n);
    return ar_end(a, b);
}

static const char *ar_join(struct xh_ar *a, const char *x, const char *sep, const char *y) {
    char *b = ar_begin(a);
    ar_cat(a, x, strlen(x));
    ar_cat(a, sep, strlen(sep));
    ar_cat(a, y, strlen(y));
    return ar_end(a, b);
}

struct xh_kv { const char *k, *v; };

struct xh_rq {
    struct h2_req r;
    struct h2_field main[XH_MAIN], ck[4], dat[XH_PIECES], all[XH_MAIN + 4 + XH_PIECES];
    size_t main_n, ck_n, dat_n, lead;
    struct xh_kv kv[XH_PAIRS];
    size_t kv_n;
    char path[XH_PATH_MAX];
    struct xh_ar a;
};

struct xh_scratch { struct xh_rq q; char arena[XH_ARENA]; };

static __thread struct xh_scratch *g_xs;

static struct xh_rq *rq_get(void) {
    if (!g_xs) g_xs = malloc(sizeof *g_xs);
    return g_xs ? &g_xs->q : NULL;
}

static void rq_field(struct xh_rq *q, const char *name, const char *value) {
    if (!name || !value || q->main_n >= XH_MAIN) { q->a.over = 1; return; }
    q->main[q->main_n++] = (struct h2_field){ name, value };
}

static void rq_cookie(struct xh_rq *q, const char *name, const char *value) {
    const char *c = ar_join(&q->a, name, "=", value);
    if (!c || q->ck_n >= 4) { q->a.over = 1; return; }
    q->ck[q->ck_n++] = (struct h2_field){ "cookie", c };
}

static int rq_shadowed(const struct xh_rq *q, const char *name, int with_data) {
    if (q->r.content_type && !strcasecmp(name, "Content-Type")) return 1;
    for (size_t i = q->lead; i < q->main_n; i++)
        if (!strcasecmp(name, q->main[i].name)) return 1;
    for (size_t i = 0; with_data && i < q->dat_n; i++)
        if (strcmp(q->dat[i].name, "cookie") && !strcasecmp(name, q->dat[i].name)) return 1;
    return 0;
}

static void rq_join(struct xh_rq *q, int with_data) {
    size_t n = 0;
    for (size_t i = 0; i < q->lead; i++)
        if (!rq_shadowed(q, q->main[i].name, with_data)) q->all[n++] = q->main[i];
    q->r.lead_n = n;
    for (size_t i = q->lead; i < q->main_n; i++) q->all[n++] = q->main[i];
    for (size_t i = 0; with_data && i < q->dat_n; i++) q->all[n++] = q->dat[i];
    for (size_t i = 0; i < q->ck_n; i++) q->all[n++] = q->ck[i];
    q->r.fields = q->all;
    q->r.fields_n = n;
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const char *q_unescape(struct xh_ar *a, const char *s, size_t n) {
    char *b = ar_begin(a);
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '+') c = ' ';
        else if (c == '%') {
            if (i + 2 >= n) return NULL;
            int h = hexv(s[i + 1]), l = hexv(s[i + 2]);
            if (h < 0 || l < 0) return NULL;
            c = (char)(h << 4 | l);
            i += 2;
        }
        ar_cat(a, &c, 1);
    }
    return ar_end(a, b);
}

static void q_set(struct xh_rq *q, const char *k, const char *v) {
    size_t j = 0;
    for (size_t i = 0; i < q->kv_n; i++)
        if (strcmp(q->kv[i].k, k)) q->kv[j++] = q->kv[i];
    q->kv_n = j;
    if (q->kv_n >= XH_PAIRS) { q->a.over = 1; return; }
    q->kv[q->kv_n++] = (struct xh_kv){ k, v };
}

static void q_parse(struct xh_rq *q, const char *raw) {
    while (*raw) {
        const char *amp = strchr(raw, '&');
        size_t len = amp ? (size_t)(amp - raw) : strlen(raw);
        const char *eq = memchr(raw, '=', len);
        if (len && !memchr(raw, ';', len) && q->kv_n < XH_PAIRS) {
            size_t kn = eq ? (size_t)(eq - raw) : len;
            const char *k = q_unescape(&q->a, raw, kn);
            const char *v = k ? q_unescape(&q->a, eq ? eq + 1 : raw + len, eq ? len - kn - 1 : 0) : NULL;
            if (k && v) q->kv[q->kv_n++] = (struct xh_kv){ k, v };
        }
        raw += len + (amp ? 1 : 0);
    }
}

static void q_escape(struct xh_ar *a, const char *s) {
    static const char hx[] = "0123456789ABCDEF";
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            ar_cat(a, s, 1);
        } else if (c == ' ') {
            ar_cat(a, "+", 1);
        } else {
            char e[3] = { '%', hx[c >> 4], hx[c & 15] };
            ar_cat(a, e, 3);
        }
    }
}

static const char *q_encode(struct xh_rq *q) {
    for (size_t i = 1; i < q->kv_n; i++)
        for (size_t j = i; j > 0 && strcmp(q->kv[j - 1].k, q->kv[j].k) > 0; j--) {
            struct xh_kv t = q->kv[j];
            q->kv[j] = q->kv[j - 1];
            q->kv[j - 1] = t;
        }
    char *b = ar_begin(&q->a);
    for (size_t i = 0; i < q->kv_n; i++) {
        if (i) ar_cat(&q->a, "&", 1);
        q_escape(&q->a, q->kv[i].k);
        ar_cat(&q->a, "=", 1);
        q_escape(&q->a, q->kv[i].v);
    }
    return ar_end(&q->a, b);
}

static void path_add(char *path, const char *v) {
    size_t n = strlen(path);
    snprintf(path + n, XH_PATH_MAX - n, "%s%s", n && path[n - 1] == '/' ? "" : "/", v);
}

static void trim_sp(const char **v, size_t *vn) {
    while (*vn && (**v == ' ' || **v == '\t')) { (*v)++; (*vn)--; }
    while (*vn && ((*v)[*vn - 1] == ' ' || (*v)[*vn - 1] == '\t')) (*vn)--;
}

static void rq_custom(struct xh_rq *q, const char *h) {
    while (h && *h) {
        const char *eol = strchr(h, '\n');
        size_t ln = eol ? (size_t)(eol - h) : strlen(h);
        const char *colon = memchr(h, ':', ln);
        if (colon) {
            size_t kn = (size_t)(colon - h);
            const char *v = colon + 1;
            size_t vn = ln - kn - 1;
            trim_sp(&v, &vn);
            int host = kn == 4 && !strncasecmp(h, "Host", 4);
            int ua = kn == 10 && !strncasecmp(h, "User-Agent", 10);
            int look = ua && ((vn == 6 && !memcmp(v, "chrome", 6)) || (vn == 4 && !memcmp(v, "edge", 4)));
            if (ua && !look && !q->r.no_look) q->r.no_look = 1;
            if (!host && !look) rq_field(q, ar_str(&q->a, h, kn), ar_str(&q->a, v, vn));
        }
        h += ln + (eol ? 1 : 0);
    }
    q->lead = q->main_n;
}

static size_t pad_worst(const struct xh_side *x) {
    size_t hi = x->pad_to ? x->pad_to : 1000;
    return x->opts.obfs && x->opts.tokenish ? (hi * 5 + 3) / 4 + 150 : hi;
}

/* Each request gets its own length, not one per connection: packet-up sends a series of
 * requests, and the same padding length in all of them would turn the padding itself into a
 * signature, the very thing it is there against. */
static size_t pad_len(const struct xh_side *x) {
    /* THE SERVER SETS THE RANGE, NOT US. It comes in the link as `xPaddingBytes` (see
     * sl_pad_range in sublink.c), and the server CHECKS it: outside the range means 400. A
     * fixed range that fits Xray's default fails every xhttp node of a provider that announces,
     * say, "50-150": TLS passes, Reality accepts, then 400, and the nodes look dead.
     *
     * Not announced: Xray's default 100..1000 (GetNormalizedXPaddingBytes), to match upstream in
     * both the bounds and the middle. */
    size_t lo = x->pad_to ? x->pad_from : 100;
    size_t hi = x->pad_to ? x->pad_to : 1000;
    unsigned char r = 0;
    if (os_getrandom(&r, 1, 0) != 1) r = 128;
    size_t pad = lo + (size_t)r * (hi - lo + 1) / 256;
    if (pad < lo) pad = lo;
    if (pad > hi) pad = hi;
    return pad;
}

static const char *rq_pad(struct xh_rq *q, const struct xh_side *x, const char *prefix, int worst) {
    char *b = ar_begin(&q->a);
    ar_cat(&q->a, prefix, strlen(prefix));
    size_t len = worst ? pad_worst(x) : pad_len(x);
    int tok = x->opts.obfs && x->opts.tokenish && !worst;
    size_t cap = tok ? (len * 5 + 3) / 4 + 152 : len + 1;
    if (len > XH_BLOCK || q->a.over || q->a.n + cap > q->a.cap) { q->a.over = 1; return NULL; }
    if (!tok) memset(q->a.p + q->a.n, 'X', len);
    else len = xh_padding(&x->opts, len, q->a.p + q->a.n, cap);
    q->a.n += len;
    return ar_end(&q->a, b);
}

static void rq_meta(struct xh_rq *q, enum xh_place p, const char *key, const char *v) {
    if (p == XHP_PATH) path_add(q->path, v);
    else if (p == XHP_QUERY) q_set(q, key, v);
    else if (p == XHP_HEADER) rq_field(q, key, v);
    else if (p == XHP_COOKIE) rq_cookie(q, key, v);
}

static int rq_build(struct transport *t, enum xh_kind k, const char *seq, int worst) {
    const struct xh_side *x = k == XK_DOWN ? &t->xh.down_side : &t->xh.main_side;
    const struct xh_opts *o = &x->opts;
    struct xh_rq *q = rq_get();
    if (!q) return TR_EIO;
    memset(&q->r, 0, sizeof q->r);
    q->main_n = q->ck_n = q->dat_n = q->kv_n = q->lead = 0;
    q->a = (struct xh_ar){ g_xs->arena, 0, sizeof g_xs->arena, 0 };
    rq_custom(q, x->headers);

    const char *sid = k == XK_ONE ? NULL : t->xh.sid;
    int padq = o->obfs && o->pad_place == XHP_QUERY;
    int anyq = padq || (sid && o->sess_place == XHP_QUERY) || (seq && o->seq_place == XHP_QUERY);
    if (anyq) q_parse(q, x->query);

    char prefix[600];
    const char *pad;
    if (!o->obfs || o->pad_place == XHP_QUERY_IN_HEADER) {
        const char *key = o->obfs ? o->pad_key : "x_padding";
        snprintf(prefix, sizeof prefix, "https://%s%s?%s=", x->authority, x->base_path, key);
        pad = rq_pad(q, x, prefix, worst);
        rq_field(q, o->obfs ? o->pad_header : "Referer", pad);
    } else {
        pad = rq_pad(q, x, "", worst);
        if (o->pad_place == XHP_HEADER) rq_field(q, o->pad_header, pad);
        else if (pad && pad[0] && o->pad_place == XHP_COOKIE) rq_cookie(q, o->pad_key, pad);
        else if (pad && pad[0]) q_set(q, o->pad_key, pad);
    }

    snprintf(q->path, sizeof q->path, "%s", x->base_path);
    if (sid) rq_meta(q, o->sess_place, o->sess_key, sid);
    if (seq) rq_meta(q, o->seq_place, o->seq_key, seq);
    const char *query = anyq ? q_encode(q) : x->query;
    if (query && query[0]) {
        size_t n = strlen(q->path);
        snprintf(q->path + n, sizeof q->path - n, "?%s", query);
    }
    if (q->a.over || !query || strlen(q->path) + 1 >= sizeof q->path) return H2_ETOOBIG;

    q->r.authority = x->authority;
    q->r.path = q->path;
    q->r.method = k == XK_DOWN ? "GET" : o->method;
    q->r.content_type = (k == XK_ONE || k == XK_UP) && !o->no_grpc ? "application/grpc" : NULL;
    q->r.end_stream = k == XK_DOWN;
    rq_join(q, 0);
    return 0;
}

static int data_meta(const struct xh_opts *o) {
    return o->data_place == XHP_HEADER || o->data_place == XHP_COOKIE;
}

static size_t b64_len(size_t m) { return m / 3 * 4 + (m % 3 ? m % 3 + 1 : 0); }

static size_t ndig(size_t i) {
    size_t d = 1;
    while (i >= 10) { i /= 10; d++; }
    return d;
}

static size_t data_cost(const struct xh_opts *o, size_t e, const uint32_t *cs) {
    size_t kl = strlen(o->data_key), extra = o->data_place == XHP_COOKIE ? 7 : 0, s = 0;
    for (size_t i = 0; e; i++) {
        size_t c = cs && i < XH_PIECES ? cs[i] : o->chunk_from;
        if (c > e) c = e;
        s += c + kl + 1 + ndig(i) + 32 + extra;
        e -= c;
    }
    return s;
}

static size_t data_fit(const struct xh_opts *o, size_t base, size_t budget, size_t hi,
                       const uint32_t *cs) {
    size_t lo = 0;
    if (hi > XH_BLOCK / 4 * 3) hi = XH_BLOCK / 4 * 3;
    if (base >= budget) return 0;
    while (lo < hi) {
        size_t mid = lo + (hi - lo + 1) / 2;
        if (base + data_cost(o, b64_len(mid), cs) <= budget) lo = mid;
        else hi = mid - 1;
    }
    return lo;
}

static size_t meta_budget(const struct xh_state *x) {
    uint32_t b = h2_header_budget(&x->up.h2, x->main_side.opts.max_hdr);
    return b < XH_BLOCK ? b : XH_BLOCK;
}

static size_t packet_cap(struct transport *t) {
    struct xh_state *x = &t->xh;
    if (!x->worst_base) {
        const struct h2 look = { .browser = 1 };
        if (rq_build(t, XK_PACKET, XH_SEQ_WORST, 1)) return 0;
        x->worst_base = h2_list_size(&look, &g_xs->q.r);
    }
    size_t hi = x->post_max ? x->post_max : XH_BLOCK;
    return data_fit(&x->main_side.opts, x->worst_base, meta_budget(x), hi, NULL);
}

static void b64_put(struct xh_ar *a, const unsigned char *d, size_t m, size_t from, size_t cnt) {
    static const char al[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (size_t p = from; p < from + cnt; p++) {
        size_t bit = p * 6, i = bit / 8;
        unsigned v = (unsigned)d[i] << 8 | (i + 1 < m ? d[i + 1] : 0);
        char c = al[(v >> (10 - bit % 8)) & 63];
        ar_cat(a, &c, 1);
    }
}

static int rq_data(struct transport *t, const unsigned char *d, size_t n, size_t *took) {
    struct xh_state *x = &t->xh;
    const struct xh_opts *o = &x->main_side.opts;
    struct xh_rq *q = &g_xs->q;
    uint32_t cs[XH_PIECES], r[XH_PIECES];
    uint32_t span = o->chunk_to - o->chunk_from + 1;
    if (os_getrandom(r, sizeof r, 0) != (ssize_t)sizeof r) memset(r, 0, sizeof r);
    for (size_t i = 0; i < XH_PIECES; i++) cs[i] = o->chunk_from + (span ? r[i] % span : 0);
    const struct h2 look = { .browser = 1 };
    size_t hi = x->post_max && x->post_max < n ? x->post_max : n;
    size_t m = data_fit(o, h2_list_size(&look, &q->r), meta_budget(x), hi, cs);
    if (!m) {
        t->why = "xhttp: the server's header limit leaves no room for data";
        return TR_EIO;
    }
    size_t e = b64_len(m), at = 0;
    for (size_t i = 0; at < e; i++) {
        if (i >= XH_PIECES) return H2_ETOOBIG;
        size_t c = cs[i] < e - at ? cs[i] : e - at;
        char name[80];
        snprintf(name, sizeof name, o->data_place == XHP_COOKIE ? "%s_%zu" : "%s-%zu", o->data_key, i);
        char *b = ar_begin(&q->a);
        if (o->data_place == XHP_COOKIE) {
            ar_cat(&q->a, name, strlen(name));
            ar_cat(&q->a, "=", 1);
        }
        b64_put(&q->a, d, m, at, c);
        const char *v = ar_end(&q->a, b);
        const char *nm = o->data_place == XHP_COOKIE ? "cookie" : ar_str(&q->a, name, strlen(name));
        if (!v || !nm) return H2_ETOOBIG;
        q->dat[q->dat_n++] = (struct h2_field){ nm, v };
        at += c;
    }
    q->r.end_stream = 1;
    rq_join(q, 1);
    *took = m;
    return 0;
}

static int rq_send(struct h2 *h, const struct h2_io *io, int *started) {
    if (*started) return h2_next_req(h, &g_xs->q.r);
    int rc = h2_start_req(h, io, &g_xs->q.r, 1);
    if (!rc) *started = 1;
    return rc;
}

static int up_request_data(struct transport *t, const unsigned char *d, size_t n, size_t *took) {
    struct xh_state *x = &t->xh;
    struct h2_io io = { .ctx = &x->up, .write = up_write, .read = up_read };
    char seq[24];
    snprintf(seq, sizeof seq, "%llu", (unsigned long long)x->seq);
    int rc = rq_build(t, XK_PACKET, seq, 0);
    if (!rc && d) rc = rq_data(t, d, n, took);
    return rc ? rc : rq_send(&x->up.h2, &io, &x->up.started);
}

static int up_request(struct transport *t, long long seq) {
    struct xh_state *x = &t->xh;
    struct h2_io io = { .ctx = &x->up, .write = up_write, .read = up_read };
    if (seq >= 0) return up_request_data(t, NULL, 0, NULL);
    int rc = rq_build(t, XK_UP, NULL, 0);
    return rc ? rc : rq_send(&x->up.h2, &io, &x->up.started);
}

static int down_request(struct transport *t) {
    /* THIS link is for the download, and its request is a GET without a body. The method
     * matters: the server tells the upload from the download by it (hub.go: a GET without a
     * chunk number is stream-down). The server would take a bodiless POST for an upload, wait
     * for bytes that never come, and send nothing down. */
    struct h2_io io = { .ctx = &t->link, .write = tr_link_write, .read = tr_link_read };
    int rc = rq_build(t, t->xh.mode == XH_STREAM_ONE ? XK_ONE : XK_DOWN, NULL, 0);
    return rc ? rc : h2_start_req(&t->h2, &io, &g_xs->q.r, 1);
}

static int side_init(struct xh_side *s, const struct tr_node *n, const char *mode) {
    /* :authority as Xray's client builds the URL: the node's host setting, else the SNI (the
     * camouflage domain the server hides behind), else the address. A server with host set
     * compares it with :authority and answers 404 to anything else (hub.go). */
    char hostbuf[160];
    const char *authority = n->http_host && n->http_host[0] ? n->http_host
                          : n->sni[0] ? n->sni : tr_host_literal(n->host, hostbuf, sizeof(hostbuf));
    if (xh_opts_parse(n->xhx, mode, n->headers, n->pad_to, &s->opts, NULL, 0)) return TR_EIO;
    snprintf(s->authority, sizeof(s->authority), "%s", authority);
    const char *p = n->path ? n->path : "";
    const char *qm = strchr(p, '?');
    size_t pn = qm ? (size_t)(qm - p) : strlen(p);
    int slash = s->opts.sess_place == XHP_PATH || s->opts.seq_place == XHP_PATH;
    if (snprintf(s->base_path, sizeof s->base_path, "%s%.*s", pn && p[0] == '/' ? "" : "/", (int)pn, p)
        >= (int)sizeof s->base_path)
        return H2_ETOOBIG;
    size_t bn = strlen(s->base_path);
    if (slash && s->base_path[bn - 1] != '/') {
        if (bn + 1 >= sizeof s->base_path) return H2_ETOOBIG;
        s->base_path[bn] = '/';
        s->base_path[bn + 1] = '\0';
    }
    snprintf(s->query, sizeof s->query, "%s", qm ? qm + 1 : "");
    s->headers = n->headers;
    s->pad_from = n->pad_from;
    s->pad_to = n->pad_to;
    return 0;
}

static int xh_init(struct transport *t, const struct tr_node *n) {
    struct xh_state *x = &t->xh;
    x->mode = xhttp_mode_of(n);
    int rc = side_init(&x->main_side, n, n->mode);
    if (!rc) rc = side_init(&x->down_side, n->dl ? n->dl : n, n->dl ? "packet-up" : n->mode);
    if (rc) return rc;
    x->worst_base = 0;
    /* One value per connection from the node's range, as Xray's client picks it (dialer.go). */
    x->post_max = 0;
    if (n->post_to) {
        uint32_t r = 0;
        if (os_getrandom(&r, sizeof r, 0) != (ssize_t)sizeof r) r = 0;
        x->post_max = n->post_from + r % (n->post_to - n->post_from + 1);
    }
    x->sid[0] = '\0';
    if (x->mode != XH_STREAM_ONE) xh_session_id(&x->main_side.opts, x->sid, sizeof(x->sid));
    return 0;
}

static int up_start(struct transport *t) {
    /* stream-up opens its POST at once and keeps it open for the life of the connection: the
     * body of that request is the upstream channel.
     *
     * packet-up opens NOTHING in advance. A request there lives for exactly one chunk; opening
     * it before the chunk exists would hold an empty upload on the server, with number 0, which
     * would then have to be skipped. The first request opens on the first send. */
    if (t->xh.mode == XH_STREAM_UP) return up_request(t, -1);
    t->xh.seq = 0;
    return 0;
}

static int xhttp_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    (void)timeout_s;
    int rc = xh_init(t, n);
    if (!rc) rc = down_request(t);
    if (rc || t->xh.mode == XH_STREAM_ONE) return rc;
    rc = up_alpn(&t->xh.up);
    return rc ? rc : up_start(t);
}

/* packet-up: what all chunks of a write may carry together (the connection window). */
static long packet_conn_room(const struct xh_up *u) {
    if (!u->started) return 65535;
    return u->h2.send_win_conn > 0 ? u->h2.send_win_conn : 0;
}

/* packet-up: how far ahead of the oldest unanswered chunk a new one may go, in chunks. The
 * server takes each POST in a goroutine of its own and puts the chunks back in order by seq,
 * holding at most scMaxBufferedPosts (default 30) past a missing one; beyond that it tears the
 * connection down without an HTTP error ("packet queue is too large", upload_queue.go), and the
 * flow simply ends. Sent back to back, our chunks got there under load: one slow goroutine is a
 * gap, and everything sent meanwhile piles up behind it. Bounding the number of unanswered
 * chunks is not enough: later ones get answered and free their slots while the gap stays. So the
 * bound is a window over seq, as in TCP: no chunk more than PACKET_INFLIGHT past the oldest
 * unanswered one: the node's scMaxBufferedPosts when the link carries it, else PACKET_INFLIGHT,
 * and never more streams than the open table or the server's MAX_CONCURRENT_STREAMS. */
#define PACKET_INFLIGHT 24
#define PACKET_SLOT 8192

/* packet-up: what the next chunk's request can carry. Before the first request the windows are
 * the default 65535. */
/* Chunks that may still be sent before the window over seq is full (see PACKET_INFLIGHT). The
 * stream ids go up by two per chunk. */
static long packet_win(const struct xh_state *x) {
    long w = x->main_side.opts.posts ? (long)x->main_side.opts.posts : PACKET_INFLIGHT;
    long c = (long)h2_stream_cap(&x->up.h2);
    return w < c ? w : c;
}

static long packet_slots(const struct xh_state *x) {
    const struct xh_up *u = &x->up;
    long win = packet_win(x);
    if (!u->started) return win;
    uint32_t oldest = h2_oldest_open(&u->h2);
    if (!oldest) return win;
    long ahead = (long)(u->h2.sid - oldest) / 2 + 1;   /* chunks from the oldest to the last */
    return ahead >= win ? 0 : win - ahead;
}

static long packet_room(const struct xh_state *x) {
    const struct xh_up *u = &x->up;
    if (!u->started) return 65535;
    if (packet_slots(x) <= 0) return 0;
    const struct h2 *h = &u->h2;
    int32_t r = h->send_win_conn < h->peer_init_win ? h->send_win_conn : h->peer_init_win;
    return r > 0 ? r : 0;
}

static int packet_meta_write(struct transport *t, const unsigned char *d, size_t n) {
    struct xh_state *x = &t->xh;
    int rc = up_drain(&x->up);
    if (rc) return rc;
    size_t w = packet_cap(t);
    if (!w) {
        t->why = g_xs ? "xhttp: the server's header limit leaves no room for data"
                      : "xhttp: no memory for the request";
        return TR_EIO;
    }
    long pieces = (long)((n + w - 1) / w);
#define META_FITS() (packet_slots(x) >= pieces || \
                     (pieces > packet_win(x) && !h2_open_streams(&x->up.h2)))
    if (!META_FITS()) up_drain(&x->up);
    if (!META_FITS()) return H2_EWINDOW;
#undef META_FITS
    for (size_t off = 0; off < n && !rc;) {
        size_t took = 0;
        rc = up_request_data(t, d + off, n - off, &took);
        if (!rc) { x->seq++; off += took; }
    }
    int dr = up_drain(&x->up);
    return rc ? rc : dr;
}

static int xhttp_write(struct transport *t, const unsigned char *d, size_t n) {
    struct xh_state *x = &t->xh;
    switch (x->mode) {
        case XH_STREAM_ONE:
            return h2_write(&t->h2, d, n);
        case XH_STREAM_UP: {
            /* One long POST for the whole connection: write into it and drain whatever the
             * server has answered meanwhile. A closed window may only mean an unread
             * WINDOW_UPDATE: drain and try once more before refusing. */
            int rc = h2_write(&x->up.h2, d, n);
            if (rc == H2_EWINDOW && up_drain(&x->up) == 0) rc = h2_write(&x->up.h2, d, n);
            int dr = up_drain(&x->up);
            return rc ? rc : dr;
        }
        case XH_PACKET_UP: {
            if (data_meta(&x->main_side.opts)) return packet_meta_write(t, d, n);
            /* A chunk is a request of its own: open, write, close our half.
             *
             * NO BATCHING. Xray gathers small writes into chunks of up to a megabyte and says
             * outright that without it the bandwidth is "extremely limited". We have nothing
             * to batch with: a batcher needs a flush deadline, i.e. a timer or a thread per
             * connection, while the tunnel calls send itself and knows nothing of time. So one
             * request per call: the honest price of a mode chosen when the others do not pass
             * at all. */
            /* A chunk the windows cannot take now must not open its request: h2_write would
             * refuse it after the HEADERS went out, leaving a stream without END_STREAM, and the
             * retry would open another one for the same seq. Before the first request the
             * windows are the default 65535. */
            /* The server refuses a POST body over its scMaxEachPostBytes with 413: a write larger
             * than post_max goes as several chunks. All or nothing still holds (h2_write's
             * contract, which Vision above relies on): the windows are checked for the whole
             * write before the first chunk opens, the connection window for the sum and each new
             * stream's window for one chunk. */
            size_t piece = x->post_max && x->post_max < n ? x->post_max : n;
            /* The chunks this write needs must fit among the unanswered ones; a write that needs
             * more than the whole window alone (a tiny scMaxEachPostBytes) waits for none. */
            int pieces = (int)((n + piece - 1) / piece);
#define PACKET_FITS() ((long)piece <= packet_room(x) && (long)n <= packet_conn_room(&x->up) && \
                       (packet_slots(x) >= pieces || \
                        (pieces > packet_win(x) && !h2_open_streams(&x->up.h2))))
            if (!PACKET_FITS()) up_drain(&x->up);
            if (!PACKET_FITS()) return H2_EWINDOW;
#undef PACKET_FITS
            int rc = 0;
            for (size_t off = 0; off < n && !rc; off += piece) {
                size_t m = n - off < piece ? n - off : piece;
                rc = up_request(t, (long long)x->seq);
                if (!rc) rc = h2_write(&x->up.h2, d + off, m);
                if (!rc) rc = h2_end_stream(&x->up.h2);
                if (!rc) x->seq++;
            }
            int dr = up_drain(&x->up);
            return rc ? rc : dr;
        }
    }
    return h2_write(&t->h2, d, n);
}

static int xhttp_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    return h2_read(&t->h2, d, cap, got);
}

/* TWO self-pointers: the download's (h2.io.ctx, the main link) and the upload's (up.h2.io.ctx,
 * the second link; for stream-up it is set before the move, during open). Fixing only the first
 * sends the upload of a connection taken from the spare pool through the second link of another
 * spare session, set up in the same slot right after. */
/* The download's end is known but only the next read can report it (see grpc_pending). Only
 * the download stream counts: the answers to upload chunks (up.h2) end with every chunk. */
static int xhttp_pending(const struct transport *t) { return t->h2.done || t->h2.pend_err; }

static void xhttp_moved(struct transport *t) {
    t->h2.io.ctx = &t->link;
    t->xh.up.h2.io.ctx = &t->xh.up;
}

/* The second link exists only in stream-up and packet-up. Otherwise (stream-one) its fd is still
 * 0 from transport_open's memset, hence "> 0", not "!= -1". */
static void xhttp_close(struct transport *t) {
    struct xh_up *u = &t->xh.up;
    if (u->link.fd > 0) close(u->link.fd);
    u->link.fd = -1;
    if (!u->link.plain) tls13_free(&u->link.tls);
    u->link.tls.ready = 0;
    u->started = 0;
}

/* What xhttp_write takes now, mode by mode: the same windows it checks.
 *
 * stream-up and packet-up upload over their own link, which the tunnel loop does not watch: it
 * reads only the download link. The server's WINDOW_UPDATEs for the upload were read only by
 * up_drain after a write, and once the client's window was sized by the room (dialer_ops.room),
 * a closed room meant no writes, so no reads, so the room stayed closed: stream-up uploads fell
 * from 3 GB to 14 MB in 20 s. So a low room drains the upload link before it is reported. */
#define UP_ROOM_LOW 65536
static long xhttp_room(struct transport *t) {
    struct xh_state *x = &t->xh;
    switch (x->mode) {
        case XH_STREAM_ONE: return h2_room(&t->h2);
        case XH_STREAM_UP:
            if (h2_room(&x->up.h2) < UP_ROOM_LOW) up_drain(&x->up);
            return h2_room(&x->up.h2);
        case XH_PACKET_UP: {
            if (data_meta(&x->main_side.opts)) {
                if (packet_slots(x) <= packet_win(x) / 2) up_drain(&x->up);
                long slots = packet_slots(x);
                long per = (long)packet_cap(t);
                if (slots < 0) slots = 0;
                if (!per) per = 1;
                if (per > PACKET_SLOT) per = PACKET_SLOT;
                return slots * per;
            }
            /* In BYTES the free chunk slots can carry, not the HTTP/2 window: the window may
             * be megabytes while only packet_win chunks can be unanswered. Granted the
             * window, the client sent far more than the slots took, and every refused segment
             * waited out a retransmission timeout (11 MB uploaded in 20 s). A slot is counted
             * at PACKET_SLOT bytes, below what the stack gathers into one send (up to 16 KB),
             * so a granted window fills whole chunks; post_max when the node's is smaller. */
            if (packet_room(x) < UP_ROOM_LOW || packet_slots(x) <= packet_win(x) / 2)
                up_drain(&x->up);
            long r = packet_room(x);
            long slots = packet_slots(x);
            long per = x->post_max && x->post_max < PACKET_SLOT ? (long)x->post_max : PACKET_SLOT;
            if (slots < 0) slots = 0;
            if (r > slots * per) r = slots * per;
            if (r > packet_conn_room(&x->up)) r = packet_conn_room(&x->up);
            return r;
        }
    }
    return h2_room(&t->h2);
}

const struct transport_ops tr_xhttp = {
    .name = "xhttp", .alpn = "h2", .zc = 0,
    .open = xhttp_open, .write = xhttp_write, .read = xhttp_read,
    .moved = xhttp_moved, .close = xhttp_close, .pending = xhttp_pending, .room = xhttp_room,
};
