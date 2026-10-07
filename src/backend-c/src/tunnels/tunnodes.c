#include "firc/tunnodes.h"

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "vless.h"
#include "vlink.h"

#define LINK_BUF 32768
#define KEY_SUFFIX_ROOM 8
#define NODES_PER_BODY ((size_t)FIRC_TUN_MAX_NODES * 4)
#define ROWS_MAX ((size_t)FIRC_TUN_MAX_NODES * 8)

pthread_mutex_t firc_tun_parse_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    firc_tun_node_t row;
    char base[192];
    size_t seq;
    bool filtered, used;
} cand_t;

typedef struct {
    cand_t *v;
    size_t n, cap;
    const firc_tunnel_t *t;
    regex_t re;
    bool have_re;
    char *buf;
    size_t total, matched;
    firc_err_t err;
} build_t;

typedef struct {
    build_t *b;
    const firc_tun_src_t *src;
    size_t seq;
    size_t *useq;
    size_t n_useq, cap_useq;
} skip_ctx_t;

static void encode_name(char *dst, size_t cap, const char *name)
{
    static const char hx[] = "0123456789ABCDEF";
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)name; *p != 0; p++) {
        bool esc = *p == '%' || *p == ':' || *p == '#';
        size_t need = esc ? 3 : 1;
        if (o + need >= cap) {
            break;
        }
        if (esc) {
            dst[o++] = '%';
            dst[o++] = hx[*p >> 4];
            dst[o++] = hx[*p & 15];
        } else {
            dst[o++] = (char)*p;
        }
    }
    dst[o] = 0;
}

static cand_t *push(build_t *b)
{
    if (b->n >= ROWS_MAX) {
        return NULL;
    }
    if (b->n == b->cap) {
        size_t cap = b->cap == 0 ? 64 : b->cap * 2;
        cand_t *g = realloc(b->v, cap * sizeof *g);
        if (g == NULL) {
            b->err = FIRC_ERR_NOMEM;
            return NULL;
        }
        b->v = g;
        b->cap = cap;
    }
    cand_t *c = &b->v[b->n++];
    memset(c, 0, sizeof *c);
    return c;
}

static const char *source_label(const firc_tun_src_t *src)
{
    return src->kind == FIRC_TUN_SRC_LINK ? "link" : src->sub.name;
}

static bool filtered_out(const build_t *b, const firc_tun_src_t *src, const char *name)
{
    return src->kind == FIRC_TUN_SRC_SUB && b->have_re && regexec(&b->re, name, 0, NULL, 0) != 0;
}

static cand_t *add_cand(build_t *b, const firc_tun_src_t *src, const char *name, size_t seq)
{
    cand_t *c = push(b);
    if (c == NULL) {
        return NULL;
    }
    char cut[128];
    snprintf(cut, sizeof cut, "%s", name);
    vless_name_cut(cut);
    snprintf(c->row.name, sizeof c->row.name, "%.100s", cut);
    snprintf(c->row.source, sizeof c->row.source, "%s", source_label(src));
    char enc[192];
    encode_name(enc, sizeof enc - 9 - KEY_SUFFIX_ROOM, c->row.name);
    snprintf(c->base, sizeof c->base, "%.8s:%.182s", src->id, enc);
    c->seq = seq;
    c->filtered = filtered_out(b, src, c->row.name);
    return c;
}

static void add_skipped(build_t *b, const firc_tun_src_t *src, const char *name, const char *reason, size_t seq)
{
    cand_t *c = add_cand(b, src, name, seq);
    if (c != NULL) {
        snprintf(c->row.skip_reason, sizeof c->row.skip_reason, "%s", reason);
    }
}

static void add_node(build_t *b, const firc_tun_src_t *src, struct vless_node *n, size_t seq)
{
    vless_name_cut(n->name);
    size_t len = vless_node_link(n, b->buf, LINK_BUF);
    if (len == 0) {
        add_skipped(b, src, n->name,
                    strchr(n->host, ':') != NULL ? "IPv6 server is not supported" : "cannot be written as a link",
                    seq);
        return;
    }
    b->total++;
    if (filtered_out(b, src, n->name)) {
        (void)add_cand(b, src, n->name, seq);
        return;
    }
    b->matched++;
    cand_t *c = add_cand(b, src, n->name, seq);
    if (c == NULL) {
        return;
    }
    c->row.link = malloc(len + 1);
    if (c->row.link == NULL) {
        b->err = FIRC_ERR_NOMEM;
        return;
    }
    memcpy(c->row.link, b->buf, len + 1);
    c->row.link_len = len;
}

static void on_node(void *ud, const struct vless_node *n, const char *reason)
{
    skip_ctx_t *s = ud;
    size_t seq = s->seq++;
    if (reason != NULL) {
        add_skipped(s->b, s->src, n->name, reason, seq);
    } else if (s->n_useq < s->cap_useq) {
        s->useq[s->n_useq++] = seq;
    }
}

static void parse_link(build_t *b, const firc_tun_src_t *src)
{
    struct vless_node n;
    memset(&n, 0, sizeof n);
    int r = vless_parse_url(src->link, &n);
    if (r == 0) {
        add_node(b, src, &n, 0);
    } else {
        add_skipped(b, src, r > 0 ? n.name : "", r > 0 ? n.skip_reason : "cannot parse the link", 0);
    }
}

static size_t count_vless(const char *s)
{
    size_t n = 0;
    for (const char *p = s; *p != 0; p++) {
        if ((*p == 'v' || *p == 'V') && strncasecmp(p, "vless", 5) == 0) {
            n++;
        }
    }
    return n;
}

static const firc_tun_body_t *find_body(const firc_tun_body_t *bodies, size_t n, const char *url, uint32_t mark)
{
    for (size_t i = 0; i < n; i++) {
        if (bodies[i].mark == mark && bodies[i].url != NULL && strcmp(bodies[i].url, url) == 0) {
            return &bodies[i];
        }
    }
    return NULL;
}

static void parse_body(build_t *b, const firc_tun_src_t *src, const firc_tun_body_t *body)
{
    char *raw = malloc(body->len + 1);
    char *dec = malloc(body->len + 16);
    if (raw == NULL || dec == NULL) {
        free(raw);
        free(dec);
        b->err = FIRC_ERR_NOMEM;
        return;
    }
    memcpy(raw, body->body, body->len);
    raw[body->len] = 0;
    dec[0] = 0;
    const char *text = vless_sub_text(raw, body->len, dec, body->len + 16);
    size_t hint = 1 + count_vless(text);
    if (hint > NODES_PER_BODY) {
        hint = NODES_PER_BODY;
    }
    struct vless_node *nodes = calloc(hint, sizeof *nodes);
    size_t *useq = calloc(hint, sizeof *useq);
    if (nodes == NULL || useq == NULL) {
        free(nodes);
        free(useq);
        free(raw);
        free(dec);
        b->err = FIRC_ERR_NOMEM;
        return;
    }
    size_t first = b->n;
    skip_ctx_t sk = {b, src, 0, useq, 0, hint};
    vless_set_node_hook(on_node, &sk);
    size_t cnt = vless_parse_sub(text, nodes, hint, NULL);
    vless_set_node_hook(NULL, NULL);
    size_t n_skipped = b->n - first;
    cand_t *skipped = NULL;
    if (n_skipped > 0) {
        skipped = malloc(n_skipped * sizeof *skipped);
        if (skipped == NULL) {
            b->err = FIRC_ERR_NOMEM;
        } else {
            memcpy(skipped, &b->v[first], n_skipped * sizeof *skipped);
        }
        b->n = first;
    }
    for (size_t i = 0; i < cnt && i < hint && b->err == FIRC_OK; i++) {
        add_node(b, src, &nodes[i], i < sk.n_useq ? useq[i] : sk.seq + i);
    }
    for (size_t i = 0; skipped != NULL && i < n_skipped && b->err == FIRC_OK; i++) {
        cand_t *c = push(b);
        if (c != NULL) {
            *c = skipped[i];
        }
    }
    free(skipped);
    free(useq);
    free(nodes);
    free(raw);
    free(dec);
}

static int by_base(const void *x, const void *y)
{
    const cand_t *a = *(cand_t *const *)x;
    const cand_t *b = *(cand_t *const *)y;
    int r = strcmp(a->base, b->base);
    if (r != 0) {
        return r;
    }
    return a->seq < b->seq ? -1 : a->seq > b->seq ? 1 : 0;
}

static int by_key(const void *x, const void *y)
{
    return strcmp((*(cand_t *const *)x)->row.key, (*(cand_t *const *)y)->row.key);
}

static cand_t **sorted_index(build_t *b, size_t from, size_t to, int (*cmp)(const void *, const void *))
{
    cand_t **ix = malloc((to - from + 1) * sizeof *ix);
    if (ix == NULL) {
        b->err = FIRC_ERR_NOMEM;
        return NULL;
    }
    for (size_t i = from; i < to; i++) {
        ix[i - from] = &b->v[i];
    }
    qsort(ix, to - from, sizeof *ix, cmp);
    return ix;
}

static void number_source(build_t *b, size_t from, size_t to)
{
    cand_t **ix = sorted_index(b, from, to, by_base);
    if (ix == NULL) {
        return;
    }
    size_t k = 0;
    for (size_t i = 0; i < to - from; i++) {
        cand_t *c = ix[i];
        k = (i > 0 && strcmp(ix[i - 1]->base, c->base) == 0) ? k + 1 : 1;
        if (k == 1) {
            snprintf(c->row.key, sizeof c->row.key, "%s", c->base);
        } else {
            char suffix[24];
            snprintf(suffix, sizeof suffix, "#%zu", k);
            snprintf(c->row.key, sizeof c->row.key, "%.183s%.8s", c->base, suffix);
        }
    }
    free(ix);
}

static void collect(build_t *b, uint32_t mark, const firc_tun_body_t *bodies, size_t n_bodies)
{
    const firc_tunnel_t *t = b->t;
    for (int pass = 0; pass < 2; pass++) {
        firc_tun_src_kind_t kind = pass == 0 ? FIRC_TUN_SRC_LINK : FIRC_TUN_SRC_SUB;
        for (size_t i = 0; i < t->n_src && b->err == FIRC_OK; i++) {
            const firc_tun_src_t *src = &t->src[i];
            if (src->kind != kind) {
                continue;
            }
            size_t from = b->n;
            if (kind == FIRC_TUN_SRC_LINK) {
                parse_link(b, src);
            } else {
                const firc_tun_body_t *body = find_body(bodies, n_bodies, src->sub.url, mark);
                if (body != NULL) {
                    parse_body(b, src, body);
                }
            }
            if (b->err == FIRC_OK && b->n > from) {
                number_source(b, from, b->n);
            }
        }
    }
}

static int cmp_str(const void *x, const void *y)
{
    return strcmp(*(char *const *)x, *(char *const *)y);
}

static bool in_list(char *const *sorted, size_t n, const char *key)
{
    return n > 0 && bsearch(&key, sorted, n, sizeof *sorted, cmp_str) != NULL;
}

static cand_t *find_key(const build_t *b, cand_t *const *ix, const char *key)
{
    size_t lo = 0, hi = b->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int r = strcmp(ix[mid]->row.key, key);
        if (r == 0) {
            return ix[mid];
        }
        if (r < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return NULL;
}

static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static void pct_decode(char *s)
{
    char *w = s;
    for (const char *r = s; *r != 0; r++) {
        int hi = r[0] == '%' ? hexval(r[1]) : -1;
        int lo = hi >= 0 ? hexval(r[2]) : -1;
        if (lo >= 0) {
            *w++ = (char)(hi * 16 + lo);
            r += 2;
        } else {
            *w++ = *r;
        }
    }
    *w = 0;
}

static void missing_row(const firc_tunnel_t *t, const char *key, firc_tun_node_t *row)
{
    memset(row, 0, sizeof *row);
    snprintf(row->key, sizeof row->key, "%s", key);
    row->missing = true;
    const char *colon = strchr(key, ':');
    if (colon == NULL) {
        return;
    }
    char name[192];
    snprintf(name, sizeof name, "%s", colon + 1);
    char *hash = strchr(name, '#');
    if (hash != NULL) {
        *hash = 0;
    }
    pct_decode(name);
    vless_name_cut(name);
    snprintf(row->name, sizeof row->name, "%.100s", name);
    for (size_t i = 0; i < t->n_src; i++) {
        size_t idl = strlen(t->src[i].id);
        if ((size_t)(colon - key) == idl && strncmp(key, t->src[i].id, idl) == 0) {
            snprintf(row->source, sizeof row->source, "%s", source_label(&t->src[i]));
        }
    }
}

typedef struct {
    firc_tun_nodes_t *out;
    char **excl;
    size_t n_excl;
    size_t sent;
} emit_t;

static void emit(emit_t *e, firc_tun_node_t *row, bool is_new)
{
    row->is_new = is_new;
    if (in_list(e->excl, e->n_excl, row->key)) {
        row->excluded = true;
    }
    if (row->link != NULL && !row->excluded && e->sent >= FIRC_TUN_MAX_NODES) {
        row->over_cap = true;
    }
    if (row->link != NULL && (row->excluded || row->over_cap)) {
        free(row->link);
        row->link = NULL;
        row->link_len = 0;
    }
    if (row->link != NULL) {
        e->sent++;
    }
    e->out->v[e->out->n++] = *row;
    memset(row, 0, sizeof *row);
}

static bool order_seen(const firc_tunnel_t *t, size_t i)
{
    for (size_t j = 0; j < i; j++) {
        if (strcmp(t->order[j], t->order[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void assemble(build_t *b, firc_tun_nodes_t *out)
{
    const firc_tunnel_t *t = b->t;
    out->v = calloc(b->n + t->n_order + 1, sizeof *out->v);
    cand_t **ix = sorted_index(b, 0, b->n, by_key);
    char **excl = t->n_exclude > 0 ? malloc(t->n_exclude * sizeof *excl) : NULL;
    if (out->v == NULL || ix == NULL || (t->n_exclude > 0 && excl == NULL)) {
        b->err = FIRC_ERR_NOMEM;
        free(ix);
        free(excl);
        return;
    }
    if (excl != NULL) {
        memcpy(excl, t->exclude, t->n_exclude * sizeof *excl);
        qsort(excl, t->n_exclude, sizeof *excl, cmp_str);
    }
    emit_t e = {out, excl, t->n_exclude, 0};
    for (size_t i = 0; i < t->n_order; i++) {
        if (order_seen(t, i)) {
            continue;
        }
        cand_t *c = find_key(b, ix, t->order[i]);
        if (c == NULL) {
            firc_tun_node_t row;
            missing_row(t, t->order[i], &row);
            emit(&e, &row, false);
        } else if (!c->used) {
            c->used = true;
            if (!c->filtered) {
                emit(&e, &c->row, false);
            }
        }
    }
    for (size_t i = 0; i < b->n; i++) {
        cand_t *c = &b->v[i];
        if (!c->used && !c->filtered) {
            c->used = true;
            emit(&e, &c->row, true);
        }
    }
    free(ix);
    free(excl);
}

static void build_free(build_t *b)
{
    for (size_t i = 0; i < b->n; i++) {
        free(b->v[i].row.link);
    }
    free(b->v);
    free(b->buf);
    if (b->have_re) {
        regfree(&b->re);
    }
}

firc_err_t firc_tun_nodes_build(const firc_tunnel_t *t, uint32_t mark, const firc_tun_body_t *bodies,
                                size_t n_bodies, firc_tun_nodes_t *out)
{
    memset(out, 0, sizeof *out);
    build_t b = {.t = t, .err = FIRC_OK};
    if (t->filter != NULL && t->filter[0] != 0) {
        if (regcomp(&b.re, t->filter, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
            return FIRC_ERR_INVAL;
        }
        b.have_re = true;
    }
    b.buf = malloc(LINK_BUF);
    if (b.buf == NULL) {
        build_free(&b);
        return FIRC_ERR_NOMEM;
    }
    pthread_mutex_lock(&firc_tun_parse_mutex);
    sl_intern_reset();
    vless_set_insecure(t->insecure ? 1 : 0);
    collect(&b, mark, bodies, n_bodies);
    vless_set_insecure(0);
    sl_intern_reset();
    pthread_mutex_unlock(&firc_tun_parse_mutex);
    if (b.err == FIRC_OK) {
        assemble(&b, out);
    }
    out->total = b.total;
    out->matched = b.matched;
    firc_err_t err = b.err;
    build_free(&b);
    if (err != FIRC_OK) {
        firc_tun_nodes_free(out);
    }
    return err;
}

void firc_tun_nodes_free(firc_tun_nodes_t *n)
{
    if (n == NULL) {
        return;
    }
    for (size_t i = 0; i < n->n; i++) {
        free(n->v[i].link);
    }
    free(n->v);
    memset(n, 0, sizeof *n);
}
