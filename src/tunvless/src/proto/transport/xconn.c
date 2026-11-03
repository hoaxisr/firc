#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "xconn.h"
#include "osrand.h"

#define XC_NONE    UINT16_MAX
#define XC_CANCEL  8
#define XC_PREFACE (OUR_WINDOW)
#define XC_ST_FIRST 16

struct xc_chunk {
    struct xc_chunk *next;
    uint32_t off, len, pt, ctl;
    size_t pay;
    unsigned char d[XC_CHUNK];
};

static __thread struct xc_host g_host;
static __thread uint32_t g_limit = XC_RX_BUDGET, g_pend_max = XC_PEND_MAX;
static __thread int64_t g_held, g_out;
static __thread size_t g_queued, g_pend;
static __thread struct xc_chunk *g_free;
static __thread unsigned g_free_n, g_links;
static __thread struct xconn *g_list;
static __thread unsigned char g_rbuf[XC_CHUNK];
static __thread unsigned char g_seal[TLS13_MAX_REC + 5];

struct xc_wake { uint16_t owner; uint8_t what; int rc; };
static __thread struct xc_wake g_wq[2 * XC_ENTRIES];
static __thread unsigned g_wq_n;

void xc_set_host(const struct xc_host *h) {
    if (h) g_host = *h;
    else memset(&g_host, 0, sizeof g_host);
}

void xc_budget_set(uint32_t limit) { g_limit = limit; }

void xc_pend_set(uint32_t limit) { g_pend_max = limit; }

uint32_t xc_pend_limit(void) { return g_pend_max; }

size_t xc_queued(void) { return g_queued; }

unsigned xc_free_n(void) { return g_free_n; }

static struct xc_chunk *chunk_get(void) {
    struct xc_chunk *c = g_free;
    if (c) {
        g_free = c->next;
        g_free_n--;
    } else {
        c = malloc(sizeof *c);
        if (!c) return NULL;
    }
    c->next = NULL;
    c->off = c->len = c->pt = c->ctl = 0;
    c->pay = 0;
    return c;
}

static void chunk_put(struct xc_chunk *c) {
    if (g_links && g_free_n < XC_FREE_KEEP) {
        c->next = g_free;
        g_free = c;
        g_free_n++;
    } else {
        free(c);
    }
}

static void free_list_drop(void) {
    while (g_free) {
        struct xc_chunk *c = g_free;
        g_free = c->next;
        free(c);
    }
    g_free_n = 0;
}

static int q_push(struct xc_q *q, const unsigned char *d, size_t n) {
    while (n) {
        struct xc_chunk *t = q->tail;
        if (!t || t->len == XC_CHUNK) {
            t = chunk_get();
            if (!t) return -1;
            if (q->tail) q->tail->next = t;
            else q->head = t;
            q->tail = t;
        }
        size_t k = XC_CHUNK - t->len < n ? XC_CHUNK - t->len : n;
        memcpy(t->d + t->len, d, k);
        t->len += (uint32_t)k;
        q->n += k;
        d += k;
        n -= k;
    }
    return 0;
}

static void q_link(struct xc_q *q, struct xc_chunk *c) {
    c->next = NULL;
    if (q->tail) q->tail->next = c;
    else q->head = c;
    q->tail = c;
    q->n += c->len - c->off;
}

static size_t q_pop(struct xc_q *q, unsigned char *out, size_t cap) {
    size_t got = 0;
    while (got < cap && q->head) {
        struct xc_chunk *h = q->head;
        size_t k = h->len - h->off < cap - got ? h->len - h->off : cap - got;
        memcpy(out + got, h->d + h->off, k);
        h->off += (uint32_t)k;
        got += k;
        q->n -= k;
        if (h->off == h->len) {
            q->head = h->next;
            if (!q->head) q->tail = NULL;
            chunk_put(h);
        }
    }
    return got;
}

static size_t q_clear(struct xc_q *q) {
    size_t pay = 0;
    while (q->head) {
        struct xc_chunk *h = q->head;
        q->head = h->next;
        pay += h->pay;
        chunk_put(h);
    }
    q->tail = NULL;
    q->n = 0;
    return pay;
}

static void wq_add(uint16_t owner, unsigned what, int rc) {
    if (owner == XS_NOWNER) return;
    for (unsigned i = 0; i < g_wq_n; i++)
        if (g_wq[i].owner == owner && g_wq[i].what == what) {
            if (!g_wq[i].rc) g_wq[i].rc = rc;
            return;
        }
    if (g_wq_n < sizeof g_wq / sizeof g_wq[0]) g_wq[g_wq_n++] = (struct xc_wake){ owner, (uint8_t)what, rc };
}

static void wq_run(void) {
    unsigned n = g_wq_n;
    struct xc_wake w[sizeof g_wq / sizeof g_wq[0]];
    memcpy(w, g_wq, n * sizeof w[0]);
    g_wq_n = 0;
    if (!g_host.wake) return;
    for (unsigned i = 0; i < n; i++) g_host.wake(g_host.arg, w[i].owner, w[i].what, w[i].rc);
}

static void wake(struct xconn *x, struct xc_st *e, unsigned what, int rc) {
    if (x->shared) wq_add(e->owner, what, rc);
}

static int64_t link_out(const struct xconn *x) {
    return (int64_t)x->h2.recv_win_conn + x->h2.conn_owed - x->base;
}

static void out_acct(struct xconn *x) {
    if (!x->shared || x->discard || x->state != XC_LIVE) return;
    int64_t now = link_out(x);
    g_out += now - x->out_seen;
    x->out_seen = now;
}

static void held_add(struct xconn *x, int64_t n) {
    x->held_n += n;
    if (x->shared) g_held += n;
}

static void credit_conn(struct xconn *x, uint32_t n) {
    uint64_t q = x->pt_q;
    h2m_credit_conn(&x->h2, n);
    if (x->pt_q != q) x->wu_at = x->pt_q;
}

static void pay(struct xconn *x) {
    if (x->state != XC_LIVE) return;
    if (x->drop) {
        credit_conn(x, x->drop);
        x->drop = 0;
    }
    if (!x->shared) {
        if (x->debt) credit_conn(x, x->debt);
        x->debt = 0;
        return;
    }
    out_acct(x);
    int64_t room = (int64_t)g_limit - (g_held + g_out);
    int64_t k = room < (int64_t)x->debt ? room : (int64_t)x->debt;
    if (k >= WINDOW_REFILL) {
        k -= k % WINDOW_REFILL;
        credit_conn(x, (uint32_t)k);
        x->debt -= (uint32_t)k;
    }
    out_acct(x);
}

static int64_t owed(const struct xconn *x) { return (int64_t)x->debt - x->held_n; }

static void pay_all(struct xconn *x) {
    for (;;) {
        struct xconn *b = NULL;
        for (struct xconn *y = g_list; y; y = y->next)
            if (y->state == XC_LIVE && y->debt >= WINDOW_REFILL && (!b || owed(y) > owed(b))) b = y;
        if (!b) break;
        uint32_t d = b->debt;
        pay(b);
        if (b->debt == d) break;
    }
    pay(x);
}

static struct xc_st *ent(const struct xs *s) {
    if (!s || !s->x || s->slot >= s->x->st_cap) return NULL;
    struct xc_st *e = &s->x->st[s->slot];
    return e->used && e->sid == s->sid ? e : NULL;
}

static struct xc_st *by_slot(struct xconn *x, uint16_t slot) {
    if (slot >= H2M_STREAMS || x->map[slot] == XC_NONE) return NULL;
    return &x->st[x->map[slot]];
}

static void unmap(struct xconn *x, struct xc_st *e) {
    if (e->h2slot != XC_NONE) x->map[e->h2slot] = XC_NONE;
    e->h2slot = XC_NONE;
}

static int check_dead(struct xconn *x, int rc);

static void pend_drop(struct xconn *x, struct xc_st *e) {
    size_t n = e->pend.n;
    q_clear(&e->pend);
    e->pend_end = 0;
    g_pend -= n;
    x->pend_n -= n;
}

static void pend_flush(struct xconn *x) {
    x->pend_due = 0;
    uint16_t n = x->st_cap, at = x->pend_at;
    for (uint16_t j = 0; j < n && x->state == XC_LIVE; j++) {
        uint16_t i = (uint16_t)((at + j) % n);
        struct xc_st *e = &x->st[i];
        if (!e->used || e->h2slot == XC_NONE || (!e->pend.n && !e->pend_end)) continue;
        long w = h2m_room(&x->h2, e->h2slot);
        while (e->pend.n && w > 0) {
            struct xc_chunk *h = e->pend.head;
            size_t k = h->len - h->off;
            if ((long)k > w) k = (size_t)w;
            int last = e->pend_end && k == e->pend.n;
            int rc = h2m_send(&x->h2, e->h2slot, h->d + h->off, k, last);
            if (rc) {
                check_dead(x, rc);
                return;
            }
            h->off += (uint32_t)k;
            e->pend.n -= k;
            g_pend -= k;
            x->pend_n -= k;
            w -= (long)k;
            x->pend_at = (uint16_t)((i + 1) % n);
            if (last) e->pend_end = 0;
            if (h->off == h->len) {
                e->pend.head = h->next;
                if (!e->pend.head) e->pend.tail = NULL;
                chunk_put(h);
            }
        }
        if (!e->pend.n && e->pend_end) {
            e->pend_end = 0;
            int rc = h2m_send(&x->h2, e->h2slot, NULL, 0, 1);
            if (rc) {
                check_dead(x, rc);
                return;
            }
        }
    }
}

static void ent_free(struct xconn *x, struct xc_st *e) {
    pend_drop(x, e);
    size_t n = e->rx.n;
    q_clear(&e->rx);
    held_add(x, -(int64_t)n);
    unmap(x, e);
    memset(e, 0, sizeof *e);
    e->h2slot = XC_NONE;
    x->nstreams--;
    if (!x->nstreams) x->idle_since_ms = x->now_ms;
}

static void ent_end(struct xconn *x, struct xc_st *e, int code) {
    pend_drop(x, e);
    unmap(x, e);
    e->ended = 1;
    e->code = code;
    if (e->owner == XS_NOWNER) ent_free(x, e);
    else wake(x, e, XW_READ, 0);
}

static int seal(struct xconn *x) {
    struct xc_chunk *c = x->stage;
    if (!c) return 0;
    x->stage = NULL;
    if (!c->len) {
        chunk_put(c);
        return 0;
    }
    if (x->link.plain) {
        c->pay = x->stage_pay;
        x->stage_pay = 0;
        c->pt = c->len;
        c->ctl = x->stage_ctl;
        x->stage_ctl = 0;
        q_link(&x->out, c);
        return 0;
    }
    size_t rn = 0;
    uint32_t pt = c->len;
    int rc = tls13_seal(&x->link.tls, c->d, c->len, g_seal, sizeof g_seal, &rn);
    chunk_put(c);
    if (rc) return rc;
    if (q_push(&x->out, g_seal, rn)) return H2_EIO;
    x->out.tail->pt += pt;
    x->out.tail->pay += x->stage_pay;
    x->out.tail->ctl += x->stage_ctl;
    x->stage_pay = x->stage_ctl = 0;
    return 0;
}

static int x_out(void *ctx, const unsigned char *d, size_t n, int control) {
    struct xconn *x = ctx;
    if (x->in_dial) {
        if (x->pre_n + n > sizeof x->pre) return H2_ETOOBIG;
        memcpy(x->pre + x->pre_n, d, n);
        x->pre_n += n;
        return 0;
    }
    if (control && x->q_ctl + n > XC_CTL_MAX) return H2_EIO;
    x->pt_q += n;
    size_t p = !control && n >= 9 && d[3] == FR_DATA ? n - 9 : 0;
    uint32_t cn = control ? (uint32_t)n : 0;
    while (n) {
        if (!x->stage && !(x->stage = chunk_get())) return H2_EIO;
        struct xc_chunk *c = x->stage;
        size_t k = XC_CHUNK - c->len < n ? XC_CHUNK - c->len : n;
        memcpy(c->d + c->len, d, k);
        c->len += (uint32_t)k;
        d += k;
        n -= k;
        if (c->len == XC_CHUNK) {
            int rc = seal(x);
            if (rc) return rc;
        }
    }
    if (x->stage) {
        x->stage_pay += p;
        x->stage_ctl += cn;
    } else {
        x->out.tail->pay += p;
        x->out.tail->ctl += cn;
    }
    x->q_pay += p;
    x->q_ctl += cn;
    if (x->shared) g_queued += p;
    return 0;
}

static void disc_pay(struct xconn *x, struct xc_st *e) {
    if (e && e->disc && e->h2slot != XC_NONE && x->pt_s >= e->wu_at) {
        uint64_t q = x->pt_q;
        h2m_consumed(&x->h2, e->h2slot, e->disc);
        e->disc = 0;
        if (x->pt_q != q) e->wu_at = x->pt_q;
    }
    if (x->disc && x->pt_s >= x->wu_at) {
        uint64_t q = x->pt_q;
        h2m_credit_conn(&x->h2, x->disc);
        x->disc = 0;
        if (x->pt_q != q) x->wu_at = x->pt_q;
    }
}

static void x_data(void *ctx, uint16_t slot, const unsigned char *d, size_t n) {
    struct xconn *x = ctx;
    struct xc_st *e = by_slot(x, slot);
    if (!e) return;
    if (x->discard) {
        e->disc += (uint32_t)n;
        x->disc += (uint32_t)n;
        disc_pay(x, e);
        return;
    }
    if (e->owner == XS_NOWNER) {
        x->drop += (uint32_t)n;
        return;
    }
    if (q_push(&e->rx, d, n)) {
        x->oom = 1;
        x->drop += (uint32_t)n;
        return;
    }
    x->debt += (uint32_t)n;
    held_add(x, (int64_t)n);
    wake(x, e, XW_READ, 0);
}

static void x_status(void *ctx, uint16_t slot, int status) {
    struct xconn *x = ctx;
    struct xc_st *e = by_slot(x, slot);
    if (!e) return;
    e->seen = 1;
    e->status = status;
    if (status == 200) return;
    h2m_reset(&x->h2, slot, XC_CANCEL);
    ent_end(x, e, H2_ESTATUS);
}

static void x_end(void *ctx, uint16_t slot, int code) {
    struct xconn *x = ctx;
    struct xc_st *e = by_slot(x, slot);
    if (!e) return;
    int c = H2_ERESET;
    e->reset = code != 0;
    if (code == H2_EFLOW) c = H2_EFLOW;
    else if (x->h2.goaway && e->sid > x->h2.goaway_last) c = XC_EGOAWAY;
    if (c == XC_EGOAWAY) x->refused++;
    ent_end(x, e, c);
}

static void x_goaway(void *ctx, uint32_t last, uint32_t code) {
    (void)last;
    (void)code;
    ((struct xconn *)ctx)->retired = 1;
}

static void x_ping_ack(void *ctx) { (void)ctx; }

static void x_room(void *ctx, uint16_t slot) {
    struct xconn *x = ctx;
    if (g_pend) x->pend_due = 1;
    if (slot != XC_NONE) {
        struct xc_st *e = by_slot(x, slot);
        if (e) {
            e->win_wait = 0;
            wake(x, e, XW_ROOM, 0);
        }
        return;
    }
    for (uint16_t i = 0; i < x->st_cap; i++) {
        struct xc_st *e = &x->st[i];
        if (e->used && e->win_wait && !e->ended) {
            e->win_wait = 0;
            wake(x, e, XW_ROOM, 0);
        }
    }
}

static const struct h2m_cb XC_CB = { NULL, x_out, x_data, x_status, x_end, x_goaway, x_ping_ack, x_room };

static void list_add(struct xconn *x) {
    if (!x->shared || x->listed) return;
    x->prev = NULL;
    x->next = g_list;
    if (g_list) g_list->prev = x;
    g_list = x;
    x->listed = 1;
}

static void list_del(struct xconn *x) {
    if (!x->listed) return;
    if (x->prev) x->prev->next = x->next;
    else g_list = x->next;
    if (x->next) x->next->prev = x->prev;
    x->prev = x->next = NULL;
    x->listed = 0;
}

struct xconn *xconn_new(const struct tr_node *n, int64_t keepalive_s, int shared) {
    struct xconn *x = calloc(1, sizeof *x);
    if (!x) return NULL;
    x->node = *n;
    x->link.fd = -1;
    x->state = XC_DIALING;
    x->shared = shared ? 1 : 0;
    x->keepalive_ms = keepalive_s == 0 ? XC_KEEPALIVE_MS : keepalive_s < 0 ? -1 : keepalive_s * 1000;
    for (unsigned i = 0; i < H2M_STREAMS; i++) x->map[i] = XC_NONE;
    x->conn_update = 1;
    if (x->shared) {
        if (g_held + g_out + XC_PREFACE <= (int64_t)g_limit) {
            x->out_seen = XC_PREFACE;
            g_out += XC_PREFACE;
        } else {
            x->conn_update = 0;
            x->base = 65535;
        }
    }
    if (x->shared) g_links++;
    return x;
}

void xconn_discard(struct xconn *x) {
    g_out -= x->out_seen;
    x->out_seen = 0;
    x->base = 0;
    x->conn_update = 1;
    x->discard = 1;
}

int xconn_start(struct xconn *x) {
    if (x->state != XC_DIALING || x->link.fd < 0) return H2_EPROTO;
    int rc = 0;
    if (!x->link.plain && x->link.tls.alpn[0] && strcmp(x->link.tls.alpn, "h2")) {
        tr_link_close(&x->link);
        rc = TR_ENOH2;
    }
    if (!rc) {
        struct h2m_cb cb = XC_CB;
        cb.ctx = x;
        x->in_dial = 1;
        x->pre_n = 0;
        rc = h2m_start(&x->h2, &cb, x->conn_update);
        x->in_dial = 0;
        if (!rc) rc = tr_link_write(&x->link, x->pre, x->pre_n);
        if (rc) {
            h2m_free(&x->h2);
            tr_link_close(&x->link);
        }
    }
    x->rc = rc;
    if (rc) x->state = XC_DEAD;
    else if (!x->shared) x->state = XC_LIVE;
    return rc;
}

static int dial_failed(struct xconn *x, int rc) {
    x->rc = rc;
    x->state = XC_DEAD;
    return rc;
}

int xconn_dial(struct xconn *x, int timeout_s) {
    if (x->state != XC_DIALING) return x->state == XC_DEAD ? x->rc : H2_EPROTO;
    int rc = tr_link_open(&x->link, &x->node, "h2", timeout_s);
    return rc ? dial_failed(x, rc) : xconn_start(x);
}

int xconn_dial2(struct xconn *a, struct xconn *b, int timeout_s) {
    if (a->state != XC_DIALING || b->state != XC_DIALING) return H2_EPROTO;
    int rc = tr_link_open2(&a->link, &a->node, &b->link, &b->node, "h2", timeout_s);
    if (rc) {
        dial_failed(b, rc);
        return dial_failed(a, rc);
    }
    rc = xconn_start(a);
    if (rc) {
        tr_link_close(&b->link);
        return dial_failed(b, rc);
    }
    rc = xconn_start(b);
    if (rc) xconn_fail(a, rc);
    return rc;
}

int xconn_adopt(struct xconn *x, uint64_t now_ms) {
    if (x->state == XC_DEAD) return x->rc;
    if (x->state != XC_DIALING || x->link.fd < 0) return H2_EPROTO;
    int rc = tr_link_nonblock(&x->link);
    if (rc) {
        x->state = XC_LIVE;
        xconn_fail(x, rc);
        return rc;
    }
    x->state = XC_LIVE;
    x->now_ms = x->last_rx_ms = x->idle_since_ms = now_ms;
    list_add(x);
    out_acct(x);
    return 0;
}

static void fail_in(struct xconn *x, int err) {
    if (x->state == XC_DEAD) return;
    if (!err) err = TR_EIO;
    for (uint16_t i = 0; i < x->st_cap; i++) {
        struct xc_st *e = &x->st[i];
        if (!e->used) continue;
        pend_drop(x, e);
        if (e->ended) continue;
        x->cut_n++;
        unmap(x, e);
        e->ended = 1;
        e->code = err;
        if (e->owner == XS_NOWNER) ent_free(x, e);
        else wake(x, e, XW_READ, err);
    }
    if (x->stage) {
        chunk_put(x->stage);
        x->stage = NULL;
    }
    q_clear(&x->out);
    if (x->shared) {
        g_queued -= x->q_pay;
        g_out -= x->out_seen;
    }
    x->q_pay = x->stage_pay = 0;
    x->q_ctl = x->stage_ctl = 0;
    x->out_seen = 0;
    x->debt = x->drop = 0;
    x->state = XC_DEAD;
    x->rc = err;
}

void xconn_fail(struct xconn *x, int err) {
    fail_in(x, err);
    wq_run();
}

static int check_dead(struct xconn *x, int rc) {
    if (x->state == XC_LIVE && (x->h2.dead || x->oom)) fail_in(x, x->h2.dead ? x->h2.dead : H2_EIO);
    if (x->state == XC_DEAD) return x->rc;
    return rc;
}

static int feed(struct xconn *x, const unsigned char *d, size_t n) {
    int rc = h2m_feed(&x->h2, d, n);
    if (rc || x->oom) {
        fail_in(x, rc ? rc : H2_EIO);
        return x->rc;
    }
    x->disc += h2m_take_lost(&x->h2);
    if (x->pend_due) pend_flush(x);
    pay_all(x);
    return check_dead(x, 0);
}

static int read_shared(struct xconn *x, uint64_t now) {
    size_t total = 0;
    while (total < XC_READ_MAX || (!x->link.plain && tls13_has_record(&x->link.tls))) {
        if (x->link.plain) {
            ssize_t r = recv(x->link.fd, g_rbuf, sizeof g_rbuf, MSG_DONTWAIT);
            if (r == 0) return TR_ECLOSED;
            if (r < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
                return TR_EIO;
            }
            x->last_rx_ms = now;
            total += (size_t)r;
            int rc = feed(x, g_rbuf, (size_t)r);
            if (rc) return rc;
            continue;
        }
        uint64_t seq = x->link.tls.rd_seq;
        const unsigned char *body = NULL;
        size_t n = 0;
        int rc = tls13_read_ref(&x->link.tls, &body, &n);
        if (rc) return rc;
        if (!n) {
            if (x->link.tls.rd_seq == seq && !tls13_has_record(&x->link.tls)) return 0;
            x->last_rx_ms = now;
            continue;
        }
        x->last_rx_ms = now;
        total += n;
        rc = feed(x, body, n);
        if (rc) return rc;
    }
    return 0;
}

static int read_one(struct xconn *x) {
    if (x->link.plain) {
        ssize_t r = recv(x->link.fd, g_rbuf, sizeof g_rbuf, MSG_DONTWAIT);
        if (r == 0) return TR_ECLOSED;
        if (r < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : TR_EIO;
        return feed(x, g_rbuf, (size_t)r);
    }
    const unsigned char *body = NULL;
    size_t n = 0;
    int rc = tls13_read_ref(&x->link.tls, &body, &n);
    if (rc) return rc;
    return n ? feed(x, body, n) : 0;
}

static void low_water(void) {
    if (g_queued >= XC_OUT_LOW) return;
    for (struct xconn *y = g_list; y; y = y->next)
        for (uint16_t i = 0; i < y->st_cap; i++) {
            struct xc_st *e = &y->st[i];
            if (e->used && e->starved && !e->ended) {
                e->starved = 0;
                wake(y, e, XW_ROOM, 0);
            }
        }
}

static int flush_in(struct xconn *x) {
    if (x->state != XC_LIVE) return x->state == XC_DEAD ? x->rc : 0;
    int sent = 0;
    for (uint16_t i = 0; i < x->st_cap; i++) sent |= x->st[i].up_cur;
    for (uint16_t i = 0; sent && i < x->st_cap; i++) {
        x->st[i].up_last = x->st[i].up_cur;
        x->st[i].up_cur = 0;
    }
    int rc = seal(x);
    if (rc) {
        fail_in(x, rc);
        return rc;
    }
    while (x->out.head) {
        struct xc_chunk *h = x->out.head;
        ssize_t w = send(x->link.fd, h->d + h->off, h->len - h->off, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            fail_in(x, TR_EIO);
            return TR_EIO;
        }
        h->off += (uint32_t)w;
        x->out.n -= (size_t)w;
        if (h->off < h->len) continue;
        x->out.head = h->next;
        if (!x->out.head) x->out.tail = NULL;
        x->pt_s += h->pt;
        x->q_pay -= h->pay;
        x->q_ctl -= h->ctl;
        if (x->shared) g_queued -= h->pay;
        chunk_put(h);
    }
    for (uint16_t i = 0; x->discard && i < x->st_cap; i++)
        if (x->st[i].used) disc_pay(x, &x->st[i]);
    disc_pay(x, NULL);
    if ((rc = check_dead(x, 0))) return rc;
    if (x->shared) low_water();
    return 0;
}

int xconn_flush(struct xconn *x) {
    int rc = flush_in(x);
    wq_run();
    return rc;
}

int xconn_wants_out(const struct xconn *x) {
    return x->state == XC_LIVE && (x->out.head || (x->stage && x->stage->len));
}

int xconn_io(struct xconn *x, uint32_t ev, uint64_t now_ms) {
    if (x->state == XC_DEAD) return x->rc;
    if (x->state != XC_LIVE) return H2_EPROTO;
    x->now_ms = now_ms;
    int rc = 0;
    if (ev & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
        rc = read_shared(x, now_ms);
        if (rc) fail_in(x, rc);
    }
    if (!rc && (ev & EPOLLOUT)) rc = flush_in(x);
    wq_run();
    return x->state == XC_DEAD ? x->rc : rc;
}

static void orphans(struct xconn *x) {
    for (uint16_t i = 0; i < x->st_cap; i++) {
        struct xc_st *e = &x->st[i];
        if (!e->used || e->ended || !e->post || !e->local_end || e->h2slot == XC_NONE) continue;
        if (e->seen && e->owner != XS_NOWNER) continue;
        if (x->now_ms < e->half_at + XC_ORPHAN_MS) continue;
        h2m_reset(&x->h2, e->h2slot, XC_CANCEL);
        ent_end(x, e, H2_ERESET);
    }
}

int xconn_tick(struct xconn *x, uint64_t now_ms) {
    if (x->state == XC_DEAD) return x->rc;
    if (x->state != XC_LIVE) return 0;
    x->now_ms = now_ms;
    if (x->h2.ping_out) {
        if (now_ms >= x->ping_at_ms + XC_PING_TIMEOUT_MS) {
            xconn_fail(x, XC_EPING);
            return XC_EPING;
        }
    } else if (x->keepalive_ms >= 0 && now_ms >= x->last_rx_ms + (uint64_t)x->keepalive_ms) {
        unsigned char op[8];
        if (os_rand_seed(op, sizeof op)) memset(op, 0x5a, sizeof op);
        h2m_ping(&x->h2, op);
        x->ping_at_ms = now_ms;
    }
    orphans(x);
    int rc = check_dead(x, 0);
    wq_run();
    if (rc) return rc;
    if (!x->nstreams && (x->retired || now_ms >= x->idle_since_ms + XC_IDLE_MS)) return XC_IDLE;
    return 0;
}

unsigned xconn_streams(const struct xconn *x) { return x->nstreams; }

void xconn_free(struct xconn *x) {
    if (!x) return;
    list_del(x);
    for (uint16_t i = 0; i < x->st_cap; i++) {
        struct xc_st *e = &x->st[i];
        if (!e->used) continue;
        pend_drop(x, e);
        size_t n = e->rx.n;
        q_clear(&e->rx);
        held_add(x, -(int64_t)n);
    }
    free(x->st);
    if (x->stage) chunk_put(x->stage);
    q_clear(&x->out);
    if (x->shared) {
        g_queued -= x->q_pay;
        g_out -= x->out_seen;
    }
    h2m_free(&x->h2);
    tr_link_close(&x->link);
    int shared = x->shared;
    free(x);
    if (shared && g_links && !--g_links) free_list_drop();
}

static int ent_new(struct xconn *x, uint16_t *idx) {
    for (uint16_t i = 0; i < x->st_cap; i++)
        if (!x->st[i].used) {
            *idx = i;
            return 0;
        }
    if (x->st_cap >= XC_ENTRIES) return H2_EFULL;
    uint16_t cap = x->st_cap ? (uint16_t)(x->st_cap * 2) : XC_ST_FIRST;
    struct xc_st *st = realloc(x->st, cap * sizeof *st);
    if (!st) return H2_EFULL;
    memset(st + x->st_cap, 0, (size_t)(cap - x->st_cap) * sizeof *st);
    for (uint16_t i = x->st_cap; i < cap; i++) st[i].h2slot = XC_NONE;
    *idx = x->st_cap;
    x->st = st;
    x->st_cap = cap;
    return 0;
}

int xs_open(struct xconn *x, const struct h2_req *r, uint16_t owner, struct xs *s) {
    s->x = NULL;
    if (x->state == XC_DEAD) return x->rc;
    if (x->state != XC_LIVE) return H2_EPROTO;
    if (x->retired) return H2_ERESET;
    uint16_t idx;
    int rc = ent_new(x, &idx);
    if (rc) return rc;
    uint16_t hs = XC_NONE;
    rc = h2m_open(&x->h2, r, 1, &hs);
    if (rc) return check_dead(x, rc);
    struct xc_st *e = &x->st[idx];
    memset(e, 0, sizeof *e);
    e->used = 1;
    e->owner = owner;
    e->h2slot = hs;
    e->sid = x->h2.st[hs].sid;
    e->local_end = r->end_stream ? 1 : 0;
    e->post = !e->local_end;
    e->half_at = x->now_ms;
    x->map[hs] = idx;
    x->nstreams++;
    s->x = x;
    s->slot = idx;
    s->sid = e->sid;
    if (!x->shared) return flush_in(x);
    return 0;
}

#define XC_MARKS 1024
static __thread uint32_t g_mark[XC_MARKS], g_mark_ep;

static unsigned uploaders(const struct xconn *x, uint16_t owner) {
    if (!++g_mark_ep) {
        memset(g_mark, 0, sizeof g_mark);
        g_mark_ep = 1;
    }
    unsigned u = 1;
    for (uint16_t i = 0; i < x->st_cap; i++) {
        const struct xc_st *e = &x->st[i];
        if (!e->used || !e->up_last || e->owner == owner) continue;
        if (e->owner < XC_MARKS) {
            if (g_mark[e->owner] == g_mark_ep) continue;
            g_mark[e->owner] = g_mark_ep;
        }
        u++;
    }
    return u;
}

static long q_free(const struct xconn *x) {
    long q = (long)(x->shared ? g_queued + g_pend : x->q_pay);
    return q < XC_OUT_HIGH ? XC_OUT_HIGH - q : 0;
}

static long admit(const struct xconn *x, uint16_t owner, struct xc_st *e) {
    long free_q = q_free(x);
    long c = h2m_conn_room(&x->h2) - (long)x->pend_n;
    if (c < 0) c = 0;
    long a = (c < free_q ? c : free_q) / (long)uploaders(x, owner);
    if (a >= XC_MSS) return a;
    if (e && free_q < c) e->starved = 1;
    else if (e) e->win_wait = 1;
    return XC_MSS;
}

long xs_room(const struct xs *s) {
    struct xc_st *e = ent(s);
    if (!e) return 0;
    struct xconn *x = s->x;
    if (x->state != XC_LIVE || e->ended || e->local_end || e->h2slot == XC_NONE) return 0;
    long w = h2m_room(&x->h2, e->h2slot);
    if (!x->shared) {
        if (w <= 0) {
            e->win_wait = 1;
            return 0;
        }
        long a = admit(x, e->owner, e);
        if (w < a) e->win_wait = 1;
        return a < w ? a : w;
    }
    long a = admit(x, e->owner, e);
    if (w < a) e->win_wait = 1;
    long base = w <= 0 ? 0 : a < w ? a : w;
    long u = (long)uploaders(x, e->owner);
    long head = XC_PEND_STREAM - (long)e->pend.n;
    if (head < 0) head = 0;
    long qa = q_free(x) / u, r = base + head;
    if (r > qa) r = qa > base ? qa : base;
    long left = (long)g_pend_max - (long)g_pend;
    left = left > 0 ? left / u : 0;
    if (r - base > left) r = base + left;
    return r;
}

long xc_room_new(const struct xconn *x, uint16_t owner) {
    if (x->state != XC_LIVE || x->retired || x->h2.goaway || h2m_open_n(&x->h2) >= h2m_cap(&x->h2)) return 0;
    long c = h2m_conn_room(&x->h2) - (long)x->pend_n;
    long w = x->h2.peer_init_win < c ? x->h2.peer_init_win : c;
    if (w <= 0) return 0;
    long a = admit(x, owner, NULL);
    return a < w ? a : w;
}

int xs_send(const struct xs *s, const unsigned char *d, size_t n, int end) {
    struct xc_st *e = ent(s);
    if (!e) return H2_ERESET;
    struct xconn *x = s->x;
    if (x->state == XC_DEAD) return x->rc;
    if (x->state != XC_LIVE) return H2_EPROTO;
    if (e->ended || e->h2slot == XC_NONE) return e->code ? e->code : H2_ERESET;
    if (e->pend_end) return H2_EPROTO;
    long w = h2m_room(&x->h2, e->h2slot);
    int rc;
    if (x->shared && (e->pend.n || (long)n > w)) {
        size_t k = e->pend.n || w <= 0 ? 0 : (size_t)w;
        if (g_pend + (n - k) > g_pend_max) return H2_EWINDOW;
        if (k && (rc = h2m_send(&x->h2, e->h2slot, d, k, 0))) return check_dead(x, rc);
        if (q_push(&e->pend, d + k, n - k)) {
            x->oom = 1;
            return check_dead(x, H2_EIO);
        }
        g_pend += n - k;
        x->pend_n += n - k;
        e->pend_end = end ? 1 : 0;
    } else if ((rc = h2m_send(&x->h2, e->h2slot, d, n, end))) {
        return check_dead(x, rc);
    }
    if (n) e->up_cur = 1;
    if (end) {
        e->local_end = 1;
        e->half_at = x->now_ms;
    }
    if (!x->shared) return flush_in(x);
    return 0;
}

int xs_read(const struct xs *s, unsigned char *out, size_t cap, size_t *got) {
    *got = 0;
    struct xc_st *e = ent(s);
    if (!e) return H2_ERESET;
    struct xconn *x = s->x;
    if (!x->shared && !e->rx.n && !e->ended && x->state == XC_LIVE) {
        int rc = read_one(x);
        if (rc) fail_in(x, rc);
        if (x->state == XC_LIVE) flush_in(x);
    }
    if (e->rx.n) {
        size_t k = q_pop(&e->rx, out, cap);
        *got = k;
        held_add(x, -(int64_t)k);
        if (x->state == XC_LIVE) {
            if (e->h2slot != XC_NONE) h2m_consumed(&x->h2, e->h2slot, (uint32_t)k);
            pay_all(x);
            check_dead(x, 0);
            if (!x->shared && x->state == XC_LIVE) flush_in(x);
        }
        wq_run();
        return 0;
    }
    wq_run();
    if (e->ended) return e->code;
    return 0;
}

int xc_q_push(struct xc_q *q, const unsigned char *d, size_t n) { return q_push(q, d, n); }

size_t xc_q_peek(const struct xc_q *q, unsigned char *out, size_t cap) {
    size_t got = 0;
    for (const struct xc_chunk *h = q->head; h && got < cap; h = h->next) {
        size_t k = h->len - h->off < cap - got ? h->len - h->off : cap - got;
        memcpy(out + got, h->d + h->off, k);
        got += k;
    }
    return got;
}

size_t xc_q_pop(struct xc_q *q, unsigned char *out, size_t cap) { return q_pop(q, out, cap); }

void xc_q_drop(struct xc_q *q) { q_clear(q); }

int xs_status(const struct xs *s) {
    struct xc_st *e = ent(s);
    return e ? e->status : 0;
}

int xs_ready(const struct xs *s) {
    struct xc_st *e = ent(s);
    return !e || e->rx.n || e->ended;
}

int xs_failed(const struct xs *s) {
    struct xc_st *e = ent(s);
    return !e || (e->ended && (e->reset || e->status != 200 || e->code != H2_ERESET));
}

void xs_close(struct xs *s) {
    struct xc_st *e = ent(s);
    struct xconn *x = s->x;
    s->x = NULL;
    if (!e) return;
    size_t n = e->rx.n;
    q_clear(&e->rx);
    held_add(x, -(int64_t)n);
    if (x->state == XC_LIVE && e->h2slot != XC_NONE) {
        if (e->post && e->local_end && !e->seen) {
            e->owner = XS_NOWNER;
            pay_all(x);
            wq_run();
            return;
        }
        h2m_reset(&x->h2, e->h2slot, XC_CANCEL);
        unmap(x, e);
    }
    ent_free(x, e);
    if (x->state == XC_LIVE) {
        pay_all(x);
        check_dead(x, 0);
        if (!x->shared && x->state == XC_LIVE) flush_in(x);
    }
    wq_run();
}

static int room_open(const struct xs *s) {
    struct xc_st *e = ent(s);
    return e && !e->ended && !e->local_end && e->h2slot != XC_NONE && h2m_room(&s->x->h2, e->h2slot) > 0;
}

static uint64_t mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

int xs_wait(const struct xs *s, int timeout_ms) {
    if (!ent(s)) return 1;
    struct xconn *x = s->x;
    uint64_t dl = mono_ms() + (uint64_t)(timeout_ms > 0 ? timeout_ms : 0);
    int had_room = room_open(s);
    for (;;) {
        if (xs_ready(s)) return 1;
        if (x->state != XC_LIVE) return 1;
        if (!had_room && room_open(s)) return 0;
        int queued = xconn_wants_out(x);
        if (!x->link.plain && tls13_has_record(&x->link.tls)) {
            int rc = read_one(x);
            if (rc) fail_in(x, rc);
            else flush_in(x);
            continue;
        }
        uint64_t now = mono_ms();
        if (now >= dl) return 0;
        struct pollfd p = { .fd = x->link.fd, .events = (short)(POLLIN | (queued ? POLLOUT : 0)) };
        int pr = poll(&p, 1, (int)(dl - now));
        if (pr < 0) {
            if (errno == EINTR) continue;
            fail_in(x, TR_EIO);
            continue;
        }
        if (!pr) return 0;
        if (p.revents & POLLOUT) {
            if (flush_in(x)) continue;
            if (queued && !xconn_wants_out(x)) return 0;
        }
        if (p.revents & (POLLIN | POLLHUP | POLLERR)) {
            int rc = read_one(x);
            if (rc) fail_in(x, rc);
            else flush_in(x);
        }
    }
}
