#ifndef TUNVLESS_HY2PEER_H
#define TUNVLESS_HY2PEER_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quic.h"
#include "hy2wire.h"
#include "hy2-frozen.h"
#include "osrand.h"

#define HP_MAXST 1100
#define HP_MAXDG 64
#define HP_MAXHDR 16

enum { HP_AUTH_OK, HP_AUTH_FIN, HP_AUTH_JUNK, HP_AUTH_SILENT, HP_AUTH_NOUDP, HP_AUTH_RX };

struct hp_buf {
    uint8_t *p;
    size_t n, cap, off;
    int fin, fin_done, dead;
};

struct hp_st {
    int used;
    int64_t sid;
    struct hp_buf in, out, held, seen;
    size_t got, payload, unconsumed, pbad;
    int parsed, bad_prefix, responded, fin, closed, rx_reset, tx_stopped, pa_reset, pa_stopped;
    uint64_t rx_err, tx_err;
    char addr[256];
};

struct hp_dg { uint32_t sid; uint16_t pkt; uint8_t frag, count; size_t data_n; char addr[64]; };

struct hy2peer {
    struct qc *q;
    int hs, closed, reason, app;
    uint64_t code;
    char why[160];
    uint64_t hs_ms;
    int auth_mode;
    const char *cred;
    const char *rx_answer;
    size_t answer_after;
    int refuse;
    size_t refuse_tail;
    int resp_bad;
    int fin_first;
    int echo;
    const char *mute[2];
    const char *refuse_addr, *fin_addr;
    const uint8_t *refuse_raw;
    size_t refuse_raw_n;
    int keep;
    int no_consume;
    size_t send_bytes;
    size_t ctl_extra;
    const uint8_t *pat;
    struct hy2_field hdr[HP_MAXHDR];
    int nhdr, auth_done, auth_fin, auth_status;
    uint8_t ctl[16];
    size_t ctl_n;
    int ctl_fin, ctl_streams;
    unsigned dg_n;
    struct hp_dg dg[HP_MAXDG];
    int dg_echo;
    int64_t own_ctl;
    struct hp_buf own;
    int drop;
    int follow_peer;
    struct qc_filter flt;
    uint8_t cid[4];
    size_t cid_n, reason_n;
    struct hp_st st[HP_MAXST];
};

static uint64_t hp_ms(void);

static struct hp_st *hp_st(struct hy2peer *p, int64_t sid) {
    for (int i = 0; i < HP_MAXST; i++)
        if (p->st[i].used && p->st[i].sid == sid) return &p->st[i];
    for (int i = 0; i < HP_MAXST; i++)
        if (!p->st[i].used) {
            memset(&p->st[i], 0, sizeof p->st[i]);
            p->st[i].used = 1;
            p->st[i].sid = sid;
            return &p->st[i];
        }
    return NULL;
}

static void hp_put(struct hp_buf *b, const uint8_t *d, size_t n) {
    if (b->n + n > b->cap) {
        size_t cap = (b->n + n) * 2 + 256;
        uint8_t *x = realloc(b->p, cap);
        if (!x) abort();
        b->p = x;
        b->cap = cap;
    }
    if (n) memcpy(b->p + b->n, d, n);
    b->n += n;
}

static void hp_buf_free(struct hp_buf *b) {
    free(b->p);
    memset(b, 0, sizeof *b);
}

static void hp_drain_one(struct qc *q, int64_t sid, struct hp_buf *o) {
    if (o->dead || (o->off == o->n && (!o->fin || o->fin_done))) return;
    ssize_t w = qc_stream_send(q, sid, o->p ? o->p + o->off : NULL, o->n - o->off, o->fin);
    if (w == QC_EAGAIN) return;
    if (w < 0) { o->dead = 1; return; }
    o->off += (size_t)w;
    if (o->fin && o->off == o->n) o->fin_done = 1;
}

static void hp_drain(struct hy2peer *p) {
    if (!p->q || p->closed) return;
    if (p->own_ctl >= 0) hp_drain_one(p->q, p->own_ctl, &p->own);
    for (int i = 0; i < HP_MAXST; i++)
        if (p->st[i].used) hp_drain_one(p->q, p->st[i].sid, &p->st[i].out);
}

static void hp_auth(struct hy2peer *p, struct hp_st *s) {
    const uint8_t *d = s->in.p;
    size_t n = s->in.n;
    uint64_t type, len;
    size_t a = hy2_varint_get(d, n, &type);
    if (!a) return;
    size_t b = hy2_varint_get(d + a, n - a, &len);
    if (!b || len > n - a - b) return;
    p->auth_done = 1;
    const uint8_t *q = d + a + b, *end = q + len;
    int ok = type == 1 && hy2_qpack_start(&q, end) == 0;
    struct hy2_field f;
    int rc = 0;
    const char *method = "", *auth = "", *path = "", *host = "";
    while (ok && (rc = hy2_qpack_next(&q, end, &f)) == 1) {
        if (p->nhdr < HP_MAXHDR) p->hdr[p->nhdr++] = f;
    }
    for (int i = 0; i < p->nhdr; i++) {
        if (!strcmp(p->hdr[i].name, ":method")) method = p->hdr[i].value;
        if (!strcmp(p->hdr[i].name, ":authority")) host = p->hdr[i].value;
        if (!strcmp(p->hdr[i].name, ":path")) path = p->hdr[i].value;
        if (!strcmp(p->hdr[i].name, "hysteria-auth")) auth = p->hdr[i].value;
    }
    int pass = ok && !strcmp(method, "POST") && !strcmp(host, "hysteria") && !strcmp(path, "/auth") &&
               p->cred && !strcmp(auth, p->cred);
    p->auth_status = pass ? 233 : 404;
    uint8_t hdr[16];
    size_t k;
    switch (p->auth_mode) {
    case HP_AUTH_OK:
    case HP_AUTH_NOUDP: {
        int nu = p->auth_mode == HP_AUTH_NOUDP;
        const uint8_t *sec = !pass ? hy2_frozen_404 : nu ? hy2_frozen_ok_noudp : hy2_frozen_ok;
        size_t sn = !pass ? sizeof hy2_frozen_404 : nu ? sizeof hy2_frozen_ok_noudp : sizeof hy2_frozen_ok;
        k = hy2_varint_put(hdr, sizeof hdr, 1);
        k += hy2_varint_put(hdr + k, sizeof hdr - k, sn);
        hp_put(&s->out, hdr, k);
        hp_put(&s->out, sec, sn);
        s->out.fin = 1;
        break;
    }
    case HP_AUTH_RX: {
        static const uint8_t st[] = { 0x00, 0x00, 0x5f, 0x09, 0x03, '2', '3', '3' };
        uint8_t sec[64];
        size_t sn = sizeof st, rn = p->rx_answer ? strlen(p->rx_answer) : 0;
        if (!pass || rn > 32) abort();
        memcpy(sec, st, sizeof st);
        if (p->rx_answer) {
            sec[sn++] = 0x27;
            sec[sn++] = 0x07;
            memcpy(sec + sn, "hysteria-cc-rx", 14);
            sn += 14;
            sec[sn++] = (uint8_t)rn;
            memcpy(sec + sn, p->rx_answer, rn);
            sn += rn;
        }
        k = hy2_varint_put(hdr, sizeof hdr, 1);
        k += hy2_varint_put(hdr + k, sizeof hdr - k, sn);
        hp_put(&s->out, hdr, k);
        hp_put(&s->out, sec, sn);
        s->out.fin = 1;
        break;
    }
    case HP_AUTH_FIN:
        s->out.fin = 1;
        break;
    case HP_AUTH_JUNK: {
        static const uint8_t junk[1021];
        for (int i = 0; i < 32; i++) {
            k = hy2_varint_put(hdr, sizeof hdr, 0x21);
            k += hy2_varint_put(hdr + k, sizeof hdr - k, sizeof junk);
            hp_put(&s->out, hdr, k);
            hp_put(&s->out, junk, sizeof junk);
        }
        break;
    }
    default:
        break;
    }
}

static int hp_echoes(const struct hy2peer *p, const struct hp_st *s) {
    if (!p->echo) return 0;
    for (int i = 0; i < 2; i++)
        if (p->mute[i] && !strcmp(p->mute[i], s->addr)) return 0;
    return 1;
}

static int hp_refuses(const struct hy2peer *p, const struct hp_st *s) {
    return p->refuse || (p->refuse_addr && !strcmp(p->refuse_addr, s->addr));
}

static void hp_answer(struct hy2peer *p, struct hp_st *s) {
    uint8_t r[512];
    if (p->fin_first || (p->fin_addr && !strcmp(p->fin_addr, s->addr))) {
        s->responded = 1;
        s->out.fin = 1;
        return;
    }
    if (p->resp_bad) {
        static const uint8_t bad[] = { 0x00, 0x4b, 0xb8, 0x00 };
        s->responded = 1;
        hp_put(&s->out, bad, sizeof bad);
        if (p->send_bytes) hp_put(&s->out, p->pat, p->send_bytes);
        return;
    }
    int no = hp_refuses(p, s);
    size_t k = hy2_tcp_response_put(r, sizeof r, !no, no ? "connection refused" : "", 128);
    if (no && p->refuse_raw) {
        k = 0;
        r[k++] = 1;
        k += hy2_varint_put(r + k, sizeof r - k, p->refuse_raw_n);
        memcpy(r + k, p->refuse_raw, p->refuse_raw_n);
        k += p->refuse_raw_n;
        k += hy2_varint_put(r + k, sizeof r - k, 0);
    }
    s->responded = 1;
    hp_put(&s->out, r, k);
    if (no) {
        if (p->refuse_tail) hp_put(&s->out, p->pat, p->refuse_tail);
        s->out.fin = 1;
        return;
    }
    if (hp_echoes(p, s) && s->held.n) hp_put(&s->out, s->held.p, s->held.n);
    hp_buf_free(&s->held);
    if (p->send_bytes) hp_put(&s->out, p->pat, p->send_bytes);
}

static void hp_pay(struct hy2peer *p, struct hp_st *s, const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (s->payload + i < 2097152 && d[i] != p->pat[s->payload + i]) s->pbad++;
    s->payload += n;
    if (p->keep) hp_put(&s->seen, d, n);
}

static void hp_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct hy2peer *p = u;
    struct hp_st *s = hp_st(p, sid);
    if (!s) return;
    s->got += n;
    if (fin) s->fin = 1;
    if ((sid & 3) == 2) {
        p->ctl_streams += s->got == n;
        for (size_t i = 0; i < n && p->ctl_n < sizeof p->ctl; i++) p->ctl[p->ctl_n++] = d[i];
        if (fin) p->ctl_fin = 1;
        qc_stream_consumed(p->q, sid, n);
        return;
    }
    if (sid == 0) {
        qc_stream_consumed(p->q, sid, n);
        if (fin) p->auth_fin = 1;
        if (p->auth_done) return;
        hp_put(&s->in, d, n);
        hp_auth(p, s);
        return;
    }
    if (p->no_consume) s->unconsumed += n;
    else qc_stream_consumed(p->q, sid, n);
    if (!s->parsed) {
        hp_put(&s->in, d, n);
        if (s->in.n < 2) return;
        if (s->in.p[0] != 0x44 || s->in.p[1] != 0x01) { s->bad_prefix = 1; s->parsed = -1; return; }
        size_t used = 0;
        int rc = hy2_tcp_request_parse(s->in.p + 2, s->in.n - 2, s->addr, sizeof s->addr, &used);
        if (rc == 0) return;
        if (rc < 0) { s->parsed = -1; return; }
        s->parsed = 1;
        size_t rest = s->in.n - 2 - used;
        hp_pay(p, s, s->in.p + 2 + used, rest);
        if (p->echo && rest) hp_put(&s->held, s->in.p + 2 + used, rest);
        hp_buf_free(&s->in);
    } else if (s->parsed == 1) {
        hp_pay(p, s, d, n);
        if (hp_echoes(p, s) && !hp_refuses(p, s)) {
            if (s->responded) hp_put(&s->out, d, n);
            else hp_put(&s->held, d, n);
        }
    }
    if (s->parsed == 1 && !s->responded && s->payload >= p->answer_after) hp_answer(p, s);
}

static void hp_consume_all(struct hy2peer *p) {
    for (int i = 0; i < HP_MAXST; i++) {
        struct hp_st *s = &p->st[i];
        if (!s->used || !s->unconsumed) continue;
        qc_stream_consumed(p->q, s->sid, s->unconsumed);
        s->unconsumed = 0;
    }
}

static void hp_sclose(void *u, int64_t sid, int rx_reset, uint64_t rx_err, int tx_stopped, uint64_t tx_err) {
    struct hy2peer *p = u;
    struct hp_st *s = hp_st(p, sid);
    if (!s) return;
    s->closed++;
    s->rx_reset = rx_reset;
    s->rx_err = rx_err;
    s->tx_stopped = tx_stopped;
    s->tx_err = tx_err;
}

static void hp_writable(void *u, int64_t sid) { (void)u; (void)sid; }

static void hp_pabort(void *u, int64_t sid, int reset, uint64_t rx_err, int stopped, uint64_t tx_err) {
    (void)rx_err; (void)tx_err;
    struct hp_st *s = hp_st(u, sid);
    if (!s) return;
    s->pa_reset += reset;
    s->pa_stopped += stopped;
}

static void hp_hs(void *u) {
    struct hy2peer *p = u;
    p->hs++;
    p->hs_ms = hp_ms();
    if (qc_stream_open_uni(p->q, &p->own_ctl) != 0) { p->own_ctl = -1; return; }
    static const uint8_t set[] = { 0x00, 0x04, 0x07, 0x06, 0x80, 0x10, 0x00, 0x00, 0x08, 0x01 };
    hp_put(&p->own, set, sizeof set);
    if (p->ctl_extra) {
        uint8_t h[16];
        size_t k = hy2_varint_put(h, sizeof h, 0x21);
        k += hy2_varint_put(h + k, sizeof h - k, p->ctl_extra);
        hp_put(&p->own, h, k);
        uint8_t *z = calloc(1, p->ctl_extra);
        if (!z) abort();
        hp_put(&p->own, z, p->ctl_extra);
        free(z);
    }
}

static void hp_dgram(void *u, const uint8_t *d, size_t n) {
    struct hy2peer *p = u;
    struct hy2_udp_msg m;
    if (hy2_udp_parse(d, n, &m) != 0) return;
    if (p->dg_n < HP_MAXDG) {
        struct hp_dg *g = &p->dg[p->dg_n];
        g->sid = m.sid;
        g->pkt = m.pkt;
        g->frag = m.frag;
        g->count = m.count;
        g->data_n = m.data_n;
        size_t an = m.addr_n < sizeof g->addr - 1 ? m.addr_n : sizeof g->addr - 1;
        memcpy(g->addr, m.addr, an);
        g->addr[an] = 0;
    }
    p->dg_n++;
    if (p->dg_echo) (void)qc_datagram_send(p->q, d, n);
}

static void hp_closed(void *u, int reason, int app, uint64_t code, const char *why) {
    struct hy2peer *p = u;
    p->closed++;
    p->reason = reason;
    p->app = app;
    p->code = code;
    p->reason_n = qc_close_reason_len(p->q);
    snprintf(p->why, sizeof p->why, "%s", why ? why : "");
}

static const struct qc_ops hp_ops = {
    .on_handshake = hp_hs,
    .on_stream_data = hp_data,
    .on_stream_writable = hp_writable,
    .on_stream_peer_abort = hp_pabort,
    .on_stream_close = hp_sclose,
    .on_datagram = hp_dgram,
    .on_closed = hp_closed,
};

static void hp_init(struct hy2peer *p, const uint8_t *pat) {
    memset(p, 0, sizeof *p);
    p->own_ctl = -1;
    p->pat = pat;
    p->echo = 1;
    p->cred = "secret";
}

enum { HP_DROP_NONE, HP_DROP_ALL, HP_DROP_GARBLE };

static size_t hp_ftx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct hy2peer *p = u;
    if (p->drop == HP_DROP_ALL) return 0;
    memcpy(dst, src, n);
    if (p->drop == HP_DROP_GARBLE && n) dst[n - 1] ^= 0x5a;
    return n;
}

static size_t hp_frx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct hy2peer *p = u;
    if (n > 5 && !(src[0] & 0x80)) {
        memcpy(p->cid, src + 1, 4);
        p->cid_n = 4;
    }
    memcpy(dst, src, n);
    return n;
}

static int hp_listen(struct hy2peer *p, struct qc_srv_cfg *sc) {
    struct qc_srv_cfg s = *sc;
    s.follow_peer = p->follow_peer;
    if (!s.filter) {
        p->flt.tx = hp_ftx;
        p->flt.rx = hp_frx;
        p->flt.user = p;
        p->flt.overhead = 0;
        s.filter = &p->flt;
    }
    return qc_listen(&s, &hp_ops, p, &p->q);
}

static void hp_free(struct hy2peer *p) {
    qc_free(p->q);
    p->q = NULL;
    hp_buf_free(&p->own);
    for (int i = 0; i < HP_MAXST; i++) {
        hp_buf_free(&p->st[i].in);
        hp_buf_free(&p->st[i].out);
        hp_buf_free(&p->st[i].held);
        hp_buf_free(&p->st[i].seen);
    }
}

#endif
