#include <stdlib.h>
#include <string.h>

#include "h2mux.h"

#define ST_LIVE      0x01
#define ST_LOCAL_END 0x02
#define ST_STATUS    0x04

#define NO_SLOT  UINT16_MAX
#define WIN_MAX  0x7FFFFFFF
#define ST_FIRST 16
#define CAP_PRE  100

#define E_FLOW_CONTROL 3
#define E_NO_ERROR     0

static __thread unsigned char g_frame[9 + DEFAULT_MAX_FRAME];

static int die(struct h2m *m, int rc) {
    if (!m->dead) m->dead = rc;
    return m->dead;
}

static int emit(struct h2m *m, unsigned char type, unsigned char flags, uint32_t sid,
                const unsigned char *body, size_t n, int control) {
    h2w_frame_hdr(g_frame, (uint32_t)n, type, flags, sid);
    if (n) memcpy(g_frame + 9, body, n);
    int rc = m->cb.out(m->cb.ctx, g_frame, 9 + n, control);
    return rc ? die(m, rc) : 0;
}

static int emit_u32(struct h2m *m, unsigned char type, uint32_t sid, uint32_t v) {
    unsigned char b[4];
    put32(b, v);
    return emit(m, type, 0, sid, b, 4, 1);
}

static int live(const struct h2m *m, uint16_t slot) {
    return slot < m->st_cap && (m->st[slot].state & ST_LIVE);
}

static uint16_t slot_of(const struct h2m *m, uint32_t sid) {
    if (!sid) return NO_SLOT;
    for (uint16_t i = 0; i < m->st_cap; i++)
        if ((m->st[i].state & ST_LIVE) && m->st[i].sid == sid) return i;
    return NO_SLOT;
}

static void conn_credit(struct h2m *m, uint32_t n) {
    if (m->dead) return;
    m->conn_owed += n;
    if (m->conn_owed < WINDOW_REFILL) return;
    if (emit_u32(m, FR_WINDOW_UPDATE, 0, m->conn_owed)) return;
    m->recv_win_conn += (int32_t)m->conn_owed;
    m->conn_owed = 0;
}

static void stream_credit(struct h2m *m, uint16_t slot, uint32_t n) {
    struct h2m_stream *s = &m->st[slot];
    s->recv_owed += n;
    if (s->recv_owed < WINDOW_REFILL) return;
    if (emit_u32(m, FR_WINDOW_UPDATE, s->sid, s->recv_owed)) return;
    s->recv_win += (int32_t)s->recv_owed;
    s->recv_owed = 0;
}

static void free_slot(struct h2m *m, uint16_t slot) {
    m->st[slot].state = 0;
    m->open_n--;
    if (m->f_slot != slot) return;
    m->f_slot = NO_SLOT;
    if (m->f_type == FR_DATA && !m->paid) {
        m->paid = 1;
        if (m->f_left > m->pad_left) m->lost += m->f_left - m->pad_left;
    }
}

static void end_stream(struct h2m *m, uint16_t slot, int code) {
    free_slot(m, slot);
    m->cb.end(m->cb.ctx, slot, code);
}

static int flow_reset(struct h2m *m, uint16_t slot) {
    int rc = emit_u32(m, FR_RST_STREAM, m->st[slot].sid, E_FLOW_CONTROL);
    end_stream(m, slot, H2_EFLOW);
    return rc;
}

static int remote_end(struct h2m *m, uint16_t slot) {
    int rc = 0;
    if (!(m->st[slot].state & ST_LOCAL_END))
        rc = emit_u32(m, FR_RST_STREAM, m->st[slot].sid, E_NO_ERROR);
    end_stream(m, slot, 0);
    return rc;
}

static int grow(struct h2m *m) {
    if (m->st_cap >= H2M_STREAMS) return -1;
    uint16_t cap = (uint16_t)(m->st_cap * 2);
    struct h2m_stream *st = realloc(m->st, cap * sizeof(*st));
    if (!st) return -1;
    memset(st + m->st_cap, 0, (size_t)(cap - m->st_cap) * sizeof(*st));
    m->st = st;
    m->st_cap = cap;
    return 0;
}

int h2m_start(struct h2m *m, const struct h2m_cb *cb, int conn_update) {
    memset(m, 0, sizeof(*m));
    m->cb = *cb;
    m->st = calloc(ST_FIRST, sizeof(*m->st));
    if (!m->st) return H2_EIO;
    m->st_cap = ST_FIRST;
    m->next_sid = 1;
    m->send_win_conn = 65535;
    m->peer_init_win = 65535;
    m->recv_win_conn = conn_update ? OUR_WINDOW : 65535;
    m->f_slot = NO_SLOT;
    size_t n = h2w_preface(g_frame, sizeof(g_frame), conn_update);
    int rc = m->cb.out(m->cb.ctx, g_frame, n, 0);
    return rc ? die(m, rc) : 0;
}

void h2m_free(struct h2m *m) {
    free(m->st);
    m->st = NULL;
    m->st_cap = 0;
    m->open_n = 0;
}

uint32_t h2m_cap(const struct h2m *m) {
    if (!m->peer_settings_seen) return CAP_PRE;
    if (!m->peer_max_set || m->peer_max_streams > H2M_STREAMS) return H2M_STREAMS;
    return m->peer_max_streams;
}

uint32_t h2m_header_budget(const struct h2m *m, uint32_t server_max) {
    if (!m->peer_settings_seen) return server_max && server_max < 8192 ? server_max : 8192;
    return m->peer_hdr_set ? m->peer_hdr_list : 16384;
}

unsigned h2m_open_n(const struct h2m *m) { return m->open_n; }

int h2m_open(struct h2m *m, const struct h2_req *r, int browser, uint16_t *slot) {
    if (m->dead) return m->dead;
    if (m->goaway || m->next_sid > WIN_MAX) return H2_ERESET;
    if (m->open_n >= h2m_cap(m)) return H2_EFULL;
    uint16_t s = 0;
    while (s < m->st_cap && (m->st[s].state & ST_LIVE)) s++;
    if (s == m->st_cap && grow(m)) return H2_EFULL;
    size_t bn = h2w_headers(g_frame + 9, DEFAULT_MAX_FRAME, r, browser);
    if (!bn) return H2_ETOOBIG;
    h2w_frame_hdr(g_frame, (uint32_t)bn, FR_HEADERS,
                  (unsigned char)(FLAG_END_HEADERS | (r->end_stream ? FLAG_END_STREAM : 0)), m->next_sid);
    int rc = m->cb.out(m->cb.ctx, g_frame, 9 + bn, 0);
    if (rc) return die(m, rc);
    struct h2m_stream *st = &m->st[s];
    st->sid = m->next_sid;
    st->send_win = m->peer_init_win;
    st->recv_win = OUR_WINDOW;
    st->recv_owed = 0;
    st->state = (uint8_t)(ST_LIVE | (r->end_stream ? ST_LOCAL_END : 0));
    m->next_sid += 2;
    m->open_n++;
    *slot = s;
    return 0;
}

long h2m_room(const struct h2m *m, uint16_t slot) {
    if (!live(m, slot) || (m->st[slot].state & ST_LOCAL_END)) return 0;
    int32_t w = m->st[slot].send_win < m->send_win_conn ? m->st[slot].send_win : m->send_win_conn;
    return w > 0 ? w : 0;
}

long h2m_conn_room(const struct h2m *m) {
    return m->send_win_conn > 0 ? m->send_win_conn : 0;
}

int h2m_send(struct h2m *m, uint16_t slot, const unsigned char *d, size_t n, int end) {
    if (m->dead) return m->dead;
    if (!live(m, slot)) return H2_ERESET;
    struct h2m_stream *s = &m->st[slot];
    if (s->state & ST_LOCAL_END) return H2_EPROTO;
    if (n > INT32_MAX) return H2_ETOOBIG;
    if (n && ((int32_t)n > s->send_win || (int32_t)n > m->send_win_conn)) return H2_EWINDOW;
    size_t at = 0;
    do {
        size_t chunk = n - at > DEFAULT_MAX_FRAME ? DEFAULT_MAX_FRAME : n - at;
        if (!chunk && !end) break;
        unsigned char flags = end && at + chunk == n ? FLAG_END_STREAM : 0;
        int rc = emit(m, FR_DATA, flags, s->sid, chunk ? d + at : NULL, chunk, 0);
        if (rc) return rc;
        s->send_win -= (int32_t)chunk;
        m->send_win_conn -= (int32_t)chunk;
        at += chunk;
    } while (at < n);
    if (end) s->state |= ST_LOCAL_END;
    return 0;
}

int h2m_reset(struct h2m *m, uint16_t slot, uint32_t code) {
    if (m->dead) return m->dead;
    if (!live(m, slot)) return H2_ERESET;
    int rc = emit_u32(m, FR_RST_STREAM, m->st[slot].sid, code);
    free_slot(m, slot);
    return rc;
}

void h2m_consumed(struct h2m *m, uint16_t slot, uint32_t n) {
    if (m->dead || !live(m, slot)) return;
    stream_credit(m, slot, n);
}

void h2m_credit_conn(struct h2m *m, uint32_t n) { conn_credit(m, n); }

uint32_t h2m_take_lost(struct h2m *m) {
    uint32_t n = m->lost;
    m->lost = 0;
    return n;
}

int h2m_ping(struct h2m *m, const unsigned char op[8]) {
    if (m->dead) return m->dead;
    int rc = emit(m, FR_PING, 0, 0, op, 8, 1);
    if (rc) return rc;
    memcpy(m->ping_op, op, 8);
    m->ping_out = 1;
    return 0;
}

static int setting(struct h2m *m, const unsigned char *e) {
    unsigned id = ((unsigned)e[0] << 8) | e[1];
    uint32_t v = get32(e + 2);
    if (id == 0x03) {
        m->peer_max_streams = v;
        m->peer_max_set = 1;
    } else if (id == 0x06) {
        m->peer_hdr_list = v;
        m->peer_hdr_set = 1;
    } else if (id == 0x04) {
        if (v > WIN_MAX) return H2_EFLOW;
        int64_t delta = (int64_t)v - m->peer_init_win;
        for (uint16_t i = 0; i < m->st_cap; i++) {
            if (!(m->st[i].state & ST_LIVE)) continue;
            int64_t w = (int64_t)m->st[i].send_win + delta;
            if (w > WIN_MAX) return H2_EFLOW;
            m->st[i].send_win = (int32_t)w;
        }
        if (delta > 0) m->grew = 1;
        m->peer_init_win = (int32_t)v;
    }
    return 0;
}

static int settings_end(struct h2m *m) {
    if (m->f_flags & FLAG_ACK) return 0;
    m->peer_settings_seen = 1;
    int rc = emit(m, FR_SETTINGS, FLAG_ACK, 0, NULL, 0, 1);
    if (rc || !m->grew) return rc;
    m->grew = 0;
    for (uint16_t i = 0; i < m->st_cap; i++)
        if ((m->st[i].state & (ST_LIVE | ST_LOCAL_END)) == ST_LIVE) m->cb.room(m->cb.ctx, i);
    return 0;
}

static int window_update(struct h2m *m) {
    if (m->ctl_n < 4) return 0;
    uint32_t inc = get32(m->ctl) & 0x7FFFFFFFu;
    if (!inc) return 0;
    if (m->f_sid == 0) {
        if ((int64_t)m->send_win_conn + inc > WIN_MAX) return H2_EFLOW;
        m->send_win_conn += (int32_t)inc;
        m->cb.room(m->cb.ctx, NO_SLOT);
        return 0;
    }
    uint16_t s = slot_of(m, m->f_sid);
    if (s == NO_SLOT) return 0;
    if ((int64_t)m->st[s].send_win + inc > WIN_MAX) return flow_reset(m, s);
    m->st[s].send_win += (int32_t)inc;
    if (!(m->st[s].state & ST_LOCAL_END)) m->cb.room(m->cb.ctx, s);
    return 0;
}

static void goaway(struct h2m *m) {
    if (m->ctl_n < 8) return;
    uint32_t last = get32(m->ctl) & 0x7FFFFFFFu;
    uint32_t code = get32(m->ctl + 4);
    m->goaway = 1;
    m->goaway_last = last;
    m->cb.goaway(m->cb.ctx, last, code);
    for (uint16_t i = 0; i < m->st_cap; i++)
        if ((m->st[i].state & ST_LIVE) && m->st[i].sid > last) end_stream(m, i, H2_ERESET);
}

static int frame_begin(struct h2m *m) {
    m->f_len = m->f_left = h2w_frame_len(m->hdr);
    m->f_type = m->hdr[3];
    m->f_flags = m->hdr[4];
    m->f_sid = get32(m->hdr + 5) & 0x7FFFFFFFu;
    m->f_slot = NO_SLOT;
    m->ctl_n = 0;
    m->pad_wait = m->pad_left = m->skip_left = 0;
    m->peek = m->paid = 0;
    if (m->cont && (m->f_type != FR_CONTINUATION || m->f_sid != m->cont_sid)) return H2_EPROTO;
    if (!m->cont && m->f_type == FR_CONTINUATION) return H2_EPROTO;
    switch (m->f_type) {
        case FR_DATA:
            m->pad_wait = (m->f_flags & FLAG_PADDED) != 0;
            if (m->pad_wait > m->f_len) return H2_EPROTO;
            if ((int64_t)m->f_len > m->recv_win_conn) return H2_EFLOW;
            m->recv_win_conn -= (int32_t)m->f_len;
            m->f_slot = slot_of(m, m->f_sid);
            if (m->f_slot != NO_SLOT && (int64_t)m->f_len > m->st[m->f_slot].recv_win) {
                uint16_t s = m->f_slot;
                m->f_slot = NO_SLOT;
                int rc = flow_reset(m, s);
                if (rc) return rc;
            }
            if (m->f_slot == NO_SLOT) {
                m->paid = 1;
                m->lost += m->f_len;
            } else {
                m->st[m->f_slot].recv_win -= (int32_t)m->f_len;
            }
            return 0;
        case FR_HEADERS:
            m->pad_wait = (m->f_flags & FLAG_PADDED) != 0;
            m->skip_left = (m->f_flags & FLAG_PRIORITY) ? 5 : 0;
            if (m->pad_wait + m->skip_left > m->f_len) return H2_EPROTO;
            m->f_slot = slot_of(m, m->f_sid);
            m->peek = m->f_slot != NO_SLOT && !(m->st[m->f_slot].state & ST_STATUS);
            if (!(m->f_flags & FLAG_END_HEADERS)) {
                m->cont = 1;
                m->cont_sid = m->f_sid;
                m->cont_end = (m->f_flags & FLAG_END_STREAM) != 0;
            }
            return 0;
        case FR_CONTINUATION:
            m->f_slot = slot_of(m, m->f_sid);
            return 0;
    }
    return 0;
}

static int frame_end(struct h2m *m) {
    uint16_t s = m->f_slot;
    switch (m->f_type) {
        case FR_DATA:
            if ((m->f_flags & FLAG_END_STREAM) && s != NO_SLOT) return remote_end(m, s);
            return 0;
        case FR_HEADERS:
            if (m->peek && s != NO_SLOT) {
                m->st[s].state |= ST_STATUS;
                int st = h2w_status(m->ctl, m->ctl_n);
                m->cb.status(m->cb.ctx, s, st ? st : -1);
                s = m->f_slot;
            }
            if ((m->f_flags & (FLAG_END_HEADERS | FLAG_END_STREAM)) == (FLAG_END_HEADERS | FLAG_END_STREAM) &&
                s != NO_SLOT)
                return remote_end(m, s);
            return 0;
        case FR_CONTINUATION:
            if (!(m->f_flags & FLAG_END_HEADERS)) return 0;
            m->cont = 0;
            if (m->cont_end && s != NO_SLOT) return remote_end(m, s);
            return 0;
        case FR_SETTINGS:
            return settings_end(m);
        case FR_PING:
            if (m->f_len != 8) return 0;
            if (!(m->f_flags & FLAG_ACK)) return emit(m, FR_PING, FLAG_ACK, 0, m->ctl, 8, 1);
            if (m->ping_out && memcmp(m->ping_op, m->ctl, 8) == 0) {
                m->ping_out = 0;
                m->cb.ping_ack(m->cb.ctx);
            }
            return 0;
        case FR_WINDOW_UPDATE:
            return window_update(m);
        case FR_RST_STREAM:
            s = slot_of(m, m->f_sid);
            if (m->ctl_n >= 4 && s != NO_SLOT) {
                uint32_t code = get32(m->ctl);
                end_stream(m, s, code ? (int)(code & 0x7FFFFFFFu) : H2_ERESET);
            }
            return 0;
        case FR_GOAWAY:
            goaway(m);
            return 0;
    }
    return 0;
}

static int content(struct h2m *m, const unsigned char *d, size_t n) {
    if (!n) return 0;
    if (m->f_type == FR_DATA) {
        if (m->f_slot != NO_SLOT) m->cb.data(m->cb.ctx, m->f_slot, d, n);
        return 0;
    }
    if (m->f_type == FR_HEADERS) {
        if (!m->peek) return 0;
    } else if (m->f_type == FR_SETTINGS) {
        if (m->f_flags & FLAG_ACK) return 0;
        for (size_t i = 0; i < n; i++) {
            m->ctl[m->ctl_n++] = d[i];
            if (m->ctl_n < 6) continue;
            m->ctl_n = 0;
            int rc = setting(m, m->ctl);
            if (rc) return rc;
        }
        return 0;
    } else if (m->f_type == FR_CONTINUATION) {
        return 0;
    }
    size_t room = sizeof(m->ctl) - m->ctl_n;
    size_t cp = n < room ? n : room;
    memcpy(m->ctl + m->ctl_n, d, cp);
    m->ctl_n = (uint8_t)(m->ctl_n + cp);
    return 0;
}

static int body(struct h2m *m, const unsigned char *d, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (m->pad_wait) {
            m->pad_wait = 0;
            if ((uint32_t)d[i] + m->skip_left > m->f_left - 1) return H2_EPROTO;
            m->pad_left = d[i];
            i++;
            m->f_left--;
            if (m->f_type == FR_DATA && !m->paid) {
                m->st[m->f_slot].recv_owed += (uint32_t)m->pad_left + 1;
                m->lost += (uint32_t)m->pad_left + 1;
            }
            continue;
        }
        if (m->skip_left) {
            size_t k = m->skip_left < n - i ? m->skip_left : n - i;
            m->skip_left = (uint8_t)(m->skip_left - k);
            m->f_left -= (uint32_t)k;
            i += k;
            continue;
        }
        size_t k = n - i;
        size_t want = m->f_left > m->pad_left ? m->f_left - m->pad_left : 0;
        size_t real = k < want ? k : want;
        m->f_left -= (uint32_t)k;
        int rc = content(m, d + i, real);
        if (rc) return rc;
        i += k;
    }
    return 0;
}

int h2m_feed(struct h2m *m, const unsigned char *d, size_t n) {
    if (m->dead) return m->dead;
    size_t p = 0;
    while (p < n) {
        int rc;
        if (m->hdr_n < 9) {
            size_t k = 9 - m->hdr_n;
            if (k > n - p) k = n - p;
            memcpy(m->hdr + m->hdr_n, d + p, k);
            m->hdr_n = (uint8_t)(m->hdr_n + k);
            p += k;
            if (m->hdr_n < 9) break;
            rc = frame_begin(m);
        } else {
            size_t k = m->f_left < n - p ? m->f_left : n - p;
            rc = body(m, d + p, k);
            p += k;
        }
        if (!rc && m->hdr_n == 9 && m->f_left == 0) {
            rc = frame_end(m);
            m->hdr_n = 0;
            m->f_slot = NO_SLOT;
        }
        if (rc) return die(m, rc);
        if (m->dead) return m->dead;
    }
    return 0;
}
