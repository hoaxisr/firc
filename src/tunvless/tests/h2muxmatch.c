#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unit.h"
#include "hpackread.h"
#include "h2mux.h"

struct rec {
    struct h2m *m;
    unsigned char sent[1 << 17];
    size_t sent_n;
    unsigned outs;
    int last_control;
    char log[4096];
    size_t log_n;
    int last_kind;
    uint16_t last_slot;
    unsigned long last_len;
    size_t last_at;
    unsigned char body[4][64];
    size_t body_n[4];
    int credit_on_data;
    int reset_on_data;
};

static int r_out(void *ctx, const unsigned char *d, size_t n, int control) {
    struct rec *r = ctx;
    if (r->sent_n + n > sizeof r->sent) return H2_EIO;
    memcpy(r->sent + r->sent_n, d, n);
    r->sent_n += n;
    r->outs++;
    r->last_control = control;
    return 0;
}

static void r_log(struct rec *r, const char *s) {
    size_t n = strlen(s);
    if (r->log_n + n < sizeof r->log) {
        memcpy(r->log + r->log_n, s, n + 1);
        r->log_n += n;
    }
    r->last_kind = 0;
}

static void r_data(void *ctx, uint16_t slot, const unsigned char *d, size_t n) {
    struct rec *r = ctx;
    if (slot < 4)
        for (size_t i = 0; i < n && r->body_n[slot] < sizeof r->body[slot]; i++)
            r->body[slot][r->body_n[slot]++] = d[i];
    if (r->last_kind == 'D' && r->last_slot == slot) {
        r->log_n = r->last_at;
        r->last_len += n;
    } else {
        r->last_at = r->log_n;
        r->last_len = n;
    }
    char s[48];
    snprintf(s, sizeof s, "D%u:%lu ", slot, r->last_len);
    r_log(r, s);
    r->last_kind = 'D';
    r->last_slot = slot;
    if (r->credit_on_data) h2m_credit_conn(r->m, (uint32_t)n);
    if (r->reset_on_data) {
        r->reset_on_data = 0;
        h2m_reset(r->m, slot, 8);
    }
}

static void r_status(void *ctx, uint16_t slot, int status) {
    char s[32];
    snprintf(s, sizeof s, "S%u:%d ", slot, status);
    r_log(ctx, s);
}

static void r_end(void *ctx, uint16_t slot, int code) {
    char s[32];
    snprintf(s, sizeof s, "E%u:%d ", slot, code);
    r_log(ctx, s);
}

static void r_goaway(void *ctx, uint32_t last, uint32_t code) {
    char s[32];
    snprintf(s, sizeof s, "G%u:%u ", (unsigned)last, (unsigned)code);
    r_log(ctx, s);
}

static void r_ping_ack(void *ctx) { r_log(ctx, "P "); }

static void r_room(void *ctx, uint16_t slot) {
    char s[32];
    if (slot == UINT16_MAX) snprintf(s, sizeof s, "RC ");
    else snprintf(s, sizeof s, "R%u ", slot);
    r_log(ctx, s);
}

static struct h2m g_m;
static struct rec g_r;

static void r_clear(struct rec *r) {
    r->sent_n = 0;
    r->outs = 0;
    r->log_n = 0;
    r->log[0] = '\0';
    r->last_kind = 0;
    memset(r->body_n, 0, sizeof r->body_n);
}

static int start(struct h2m *m, struct rec *r, int conn_update) {
    memset(r, 0, sizeof *r);
    r->m = m;
    struct h2m_cb cb = { r, r_out, r_data, r_status, r_end, r_goaway, r_ping_ack, r_room };
    return h2m_start(m, &cb, conn_update);
}

static const struct h2_req REQ_POST = { .authority = "a.example", .path = "/up", .method = "POST" };
static const struct h2_req REQ_GET = { .authority = "a.example", .path = "/down", .method = "GET",
                                       .end_stream = 1 };

static uint16_t open1(struct h2m *m, const struct h2_req *q) {
    uint16_t slot = UINT16_MAX;
    int rc = h2m_open(m, q, 1, &slot);
    if (rc) printf("     open failed: %d\n", rc);
    return slot;
}

static size_t fr(unsigned char *o, uint32_t len, unsigned char type, unsigned char flags, uint32_t sid,
                 const void *body) {
    o[0] = (unsigned char)(len >> 16);
    o[1] = (unsigned char)(len >> 8);
    o[2] = (unsigned char)len;
    o[3] = type;
    o[4] = flags;
    o[5] = (unsigned char)(sid >> 24);
    o[6] = (unsigned char)(sid >> 16);
    o[7] = (unsigned char)(sid >> 8);
    o[8] = (unsigned char)sid;
    if (len && body) memcpy(o + 9, body, len);
    else if (len) memset(o + 9, 'q', len);
    return 9 + len;
}

static size_t fr_u32(unsigned char *o, unsigned char type, uint32_t sid, uint32_t v) {
    unsigned char b[4] = { (unsigned char)(v >> 24), (unsigned char)(v >> 16), (unsigned char)(v >> 8),
                           (unsigned char)v };
    return fr(o, 4, type, 0, sid, b);
}

static size_t fr_setting(unsigned char *o, uint16_t id, uint32_t v) {
    unsigned char b[6] = { (unsigned char)(id >> 8), (unsigned char)id, (unsigned char)(v >> 24),
                           (unsigned char)(v >> 16), (unsigned char)(v >> 8), (unsigned char)v };
    return fr(o, 6, 0x04, 0, 0, b);
}

static int feed(struct h2m *m, const unsigned char *d, size_t n) { return h2m_feed(m, d, n); }

static int find_frame(const struct rec *r, unsigned char type, uint32_t sid, size_t *at) {
    size_t p = 0;
    while (p + 9 <= r->sent_n) {
        uint32_t len = ((uint32_t)r->sent[p] << 16) | ((uint32_t)r->sent[p + 1] << 8) | r->sent[p + 2];
        uint32_t fsid = ((uint32_t)r->sent[p + 5] << 24) | ((uint32_t)r->sent[p + 6] << 16) |
                        ((uint32_t)r->sent[p + 7] << 8) | r->sent[p + 8];
        if (r->sent[p + 3] == type && fsid == sid) { *at = p; return 1; }
        p += 9 + len;
    }
    return 0;
}

typedef void (*setup_fn)(struct h2m *m, struct rec *r);

static unsigned char g_whole_sent[1 << 17];
static char g_whole_log[4096];

static int split_run(setup_fn setup, const unsigned char *d, size_t n, size_t k, size_t *sent_n,
                     int *rc) {
    struct h2m m;
    static struct rec r;
    setup(&m, &r);
    r_clear(&r);
    int a = feed(&m, d, k);
    int b = a ? a : feed(&m, d + k, n - k);
    *rc = b;
    *sent_n = r.sent_n;
    char fp[96];
    snprintf(fp, sizeof fp, "| %lu %ld %u %ld %ld %ld %ld", (unsigned long)h2m_cap(&m), h2m_conn_room(&m),
             h2m_open_n(&m), h2m_room(&m, 0), h2m_room(&m, 1), h2m_room(&m, 2), h2m_room(&m, 3));
    r_log(&r, fp);
    int same = 1;
    if (k == n) {
        memcpy(g_whole_sent, r.sent, r.sent_n);
        snprintf(g_whole_log, sizeof g_whole_log, "%s", r.log);
    } else {
        same = strcmp(g_whole_log, r.log) == 0;
    }
    if (same && k != n) same = memcmp(g_whole_sent, r.sent, r.sent_n) == 0;
    h2m_free(&m);
    return same;
}

static int near_boundary(const unsigned char *d, size_t n, size_t k) {
    size_t p = 0;
    while (p + 9 <= n) {
        if (k + 12 >= p && k <= p + 12) return 1;
        p += 9 + (((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2]);
    }
    return k + 12 >= n;
}

static void check_splits(const char *what, setup_fn setup, const unsigned char *d, size_t n) {
    size_t whole_n, s_n;
    int whole_rc, rc;
    split_run(setup, d, n, n, &whole_n, &whole_rc);
    long bad = 0;
    for (size_t k = 0; k < n; k++) {
        if (n > 4096 && !near_boundary(d, n, k) && k % 97) continue;
        if (!split_run(setup, d, n, k, &s_n, &rc) || s_n != whole_n || rc != whole_rc) {
            if (!bad) printf("     first differing split at %zu\n", k);
            bad++;
        }
    }
    check(what, 0, bad);
}

static void t_preface_bytes(void) {
    static const unsigned char want[58] = {
        'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n', '\r', '\n',
        'S', 'M', '\r', '\n', '\r', '\n',
        0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x10, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0f, 0x00, 0x01,
    };
    /* catches: the wire look of the preface changed */
    check("preface with WINDOW_UPDATE: started", 0, start(&g_m, &g_r, 1));
    check("preface with WINDOW_UPDATE: 58 bytes", 58, (long)g_r.sent_n);
    check_mem("preface with WINDOW_UPDATE: bytes", want, g_r.sent, 58);
    h2m_free(&g_m);
    check("preface without WINDOW_UPDATE: started", 0, start(&g_m, &g_r, 0));
    check("preface without WINDOW_UPDATE: 45 bytes", 45, (long)g_r.sent_n);
    check_mem("preface without WINDOW_UPDATE: bytes", want, g_r.sent, 45);
    unsigned char out[64];
    check("h2w_preface with WINDOW_UPDATE: 58", 58, (long)h2w_preface(out, sizeof out, 1));
    check_mem("h2w_preface with WINDOW_UPDATE: bytes", want, out, 58);
    check("h2w_preface without WINDOW_UPDATE: 45", 45, (long)h2w_preface(out, sizeof out, 0));
    check("h2w_preface past cap: 0", 0, (long)h2w_preface(out, 57, 1));
    h2m_free(&g_m);
}

static void t_ids(void) {
    /* catches: stream ids reused or not odd, or END_STREAM set where the request has none */
    start(&g_m, &g_r, 1);
    r_clear(&g_r);
    struct h2_req a = REQ_POST, c = REQ_POST;
    a.path = "/one";
    c.path = "/three";
    struct h2_req b = REQ_GET;
    b.path = "/two";
    uint16_t s1 = open1(&g_m, &a), s2 = open1(&g_m, &b), s3 = open1(&g_m, &c);
    check("ids: slots 0, 1, 2", 1, s1 == 0 && s2 == 1 && s3 == 2);
    check("ids: three HEADERS", 3, hr_count_frames(g_r.sent, g_r.sent_n, 0x01));
    size_t at;
    check("ids: HEADERS on 1", 1, find_frame(&g_r, 0x01, 1, &at));
    check("ids: stream 1 END_HEADERS only", 0x04, g_r.sent[at + 4]);
    check("ids: HEADERS on 3", 1, find_frame(&g_r, 0x01, 3, &at));
    check("ids: stream 3 END_HEADERS and END_STREAM", 0x05, g_r.sent[at + 4]);
    check("ids: HEADERS on 5", 1, find_frame(&g_r, 0x01, 5, &at));
    check("ids: stream 5 END_HEADERS only", 0x04, g_r.sent[at + 4]);
    static struct hr_block blk;
    check("ids: second HEADERS decodes", 0, hr_nth_headers(g_r.sent, g_r.sent_n, 1, &blk));
    int i = hr_find(&blk, ":method");
    check_str("ids: second is GET", "GET", i >= 0 ? blk.f[i].value : "");
    i = hr_find(&blk, ":path");
    check_str("ids: second path", "/two", i >= 0 ? blk.f[i].value : "");
    i = hr_find(&blk, ":authority");
    check_str("ids: authority", "a.example", i >= 0 ? blk.f[i].value : "");
    i = hr_find(&blk, "user-agent");
    check_str("ids: browser look", UA_CHROME, i >= 0 ? blk.f[i].value : "");
    check("ids: three open", 3, h2m_open_n(&g_m));
    check("ids: HEADERS not control", 0, g_r.last_control);
    h2m_free(&g_m);
}

static void setup_two(struct h2m *m, struct rec *r) {
    start(m, r, 1);
    open1(m, &REQ_POST);
    open1(m, &REQ_POST);
}

static void t_two_streams_demux(void) {
    static const unsigned char in[] = {
        0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'b', 'b', 'b',
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'a', 'a',
        0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x88,
    };
    /* catches: frames routed by a current stream */
    setup_two(&g_m, &g_r);
    r_clear(&g_r);
    check("demux: feed", 0, feed(&g_m, in, sizeof in));
    check_str("demux: callbacks in order", "D1:3 D0:2 S0:200 ", g_r.log);
    check_mem("demux: A got aa", "aa", g_r.body[0], 2);
    check_mem("demux: B got bbb", "bbb", g_r.body[1], 3);
    check("demux: nothing sent", 0, (long)g_r.sent_n);
    h2m_free(&g_m);
    check_splits("demux: every split gives the same", setup_two, in, sizeof in);
}

static void t_send_windows(void) {
    unsigned char in[64], buf[70000];
    memset(buf, 'u', sizeof buf);
    /* catches: stream and connection windows mixed up */
    setup_two(&g_m, &g_r);
    r_clear(&g_r);
    size_t n = fr_setting(in, 0x04, 100);
    check("windows: SETTINGS 100", 0, feed(&g_m, in, n));
    check("windows: room A 100", 100, h2m_room(&g_m, 0));
    r_clear(&g_r);
    check("windows: 101 bytes refused", H2_EWINDOW, h2m_send(&g_m, 0, buf, 101, 0));
    check("windows: refused sends nothing", 0, (long)g_r.sent_n);
    check("windows: 100 bytes taken", 0, h2m_send(&g_m, 0, buf, 100, 0));
    unsigned char want[9] = { 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    check("windows: one DATA of 100", 109, (long)g_r.sent_n);
    check_mem("windows: DATA header", want, g_r.sent, 9);
    check("windows: DATA not control", 0, g_r.last_control);
    check("windows: room A 0", 0, h2m_room(&g_m, 0));
    check("windows: room B 100", 100, h2m_room(&g_m, 1));
    r_clear(&g_r);
    n = fr_u32(in, 0x08, 1, 50);
    check("windows: WINDOW_UPDATE(1, 50)", 0, feed(&g_m, in, n));
    check("windows: room A 50", 50, h2m_room(&g_m, 0));
    check_str("windows: room(A) once", "R0 ", g_r.log);
    h2m_free(&g_m);

    setup_two(&g_m, &g_r);
    n = fr_setting(in, 0x04, 1048576);
    feed(&g_m, in, n);
    r_clear(&g_r);
    check("windows: 40000 on A", 0, h2m_send(&g_m, 0, buf, 40000, 0));
    check("windows: 25535 on B", 0, h2m_send(&g_m, 1, buf, 25535, 0));
    check("windows: DATA frames of at most 16384", 5, hr_count_frames(g_r.sent, g_r.sent_n, 0x00));
    check("windows: connection room 0", 0, h2m_conn_room(&g_m));
    check("windows: room A 0 by connection", 0, h2m_room(&g_m, 0));
    check("windows: room B 0 by connection", 0, h2m_room(&g_m, 1));
    check("windows: one more byte refused", H2_EWINDOW, h2m_send(&g_m, 1, buf, 1, 0));
    r_clear(&g_r);
    n = fr_u32(in, 0x08, 0, 10);
    check("windows: WINDOW_UPDATE(0, 10)", 0, feed(&g_m, in, n));
    check("windows: room A 10", 10, h2m_room(&g_m, 0));
    check("windows: room B 10", 10, h2m_room(&g_m, 1));
    check("windows: connection room 10", 10, h2m_conn_room(&g_m));
    check_str("windows: connection room once", "RC ", g_r.log);
    h2m_free(&g_m);
}

static void setup_bare(struct h2m *m, struct rec *r) {
    start(m, r, 1);
    open1(m, &REQ_POST);
}

static void t_settings_acked(void) {
    unsigned char in[64];
    static const unsigned char ack[9] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
    /* catches: a SETTINGS left unacknowledged, or an ACK answered */
    start(&g_m, &g_r, 1);
    r_clear(&g_r);
    size_t n = fr_setting(in, 0x03, 50);
    check("settings: feed", 0, feed(&g_m, in, n));
    check("settings: one ACK", 9, (long)g_r.sent_n);
    check_mem("settings: ACK bytes", ack, g_r.sent, 9);
    check("settings: ACK is control", 1, g_r.last_control);
    r_clear(&g_r);
    n = fr(in, 0, 0x04, 0x01, 0, NULL);
    check("settings: peer ACK", 0, feed(&g_m, in, n));
    check("settings: peer ACK answered by nothing", 0, (long)g_r.sent_n);
    h2m_free(&g_m);
    unsigned char two[12] = { 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0a };
    n = fr(in, 12, 0x04, 0, 0, two);
    n += fr(in + n, 4, 0x08, 0, 1, (unsigned char[4]){ 0x00, 0x00, 0x00, 0x05 });
    setup_bare(&g_m, &g_r);
    r_clear(&g_r);
    feed(&g_m, in, n);
    check("settings: two entries, the limit", 7, (long)h2m_cap(&g_m));
    check("settings: two entries, the window", 15, h2m_room(&g_m, 0));
    h2m_free(&g_m);
    check_splits("settings: every split gives the same", setup_bare, in, n);
}

static void t_settings_shift(void) {
    unsigned char in[64], buf[128];
    memset(buf, 'u', sizeof buf);
    /* catches: the shift applied to one stream, computed from 65535, or applied twice */
    start(&g_m, &g_r, 1);
    open1(&g_m, &REQ_POST);
    open1(&g_m, &REQ_POST);
    open1(&g_m, &REQ_POST);
    size_t n = fr_setting(in, 0x04, 100);
    feed(&g_m, in, n);
    h2m_send(&g_m, 1, buf, 40, 0);
    h2m_send(&g_m, 2, buf, 100, 0);
    check("shift: before, A 100", 100, h2m_room(&g_m, 0));
    check("shift: before, B 60", 60, h2m_room(&g_m, 1));
    check("shift: before, C 0", 0, h2m_room(&g_m, 2));
    n = fr_setting(in, 0x04, 150);
    r_clear(&g_r);
    check("shift: SETTINGS 150", 0, feed(&g_m, in, n));
    check_str("shift: room for every stream", "R0 R1 R2 ", g_r.log);
    check("shift: A 150", 150, h2m_room(&g_m, 0));
    check("shift: B 110", 110, h2m_room(&g_m, 1));
    check("shift: C 50", 50, h2m_room(&g_m, 2));
    r_clear(&g_r);
    check("shift: the same SETTINGS again", 0, feed(&g_m, in, n));
    check_str("shift: no room callback without a shift", "", g_r.log);
    check("shift: A still 150", 150, h2m_room(&g_m, 0));
    check("shift: B still 110", 110, h2m_room(&g_m, 1));
    check("shift: C still 50", 50, h2m_room(&g_m, 2));
    uint16_t d = open1(&g_m, &REQ_POST);
    check("shift: a new stream starts at 150", 150, h2m_room(&g_m, d));
    h2m_free(&g_m);
}

static void t_stream_credit_steps(void) {
    unsigned char in[40100];
    static const unsigned char wu1[13] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
                                           0x00, 0x00, 0x9c, 0x40 };
    static const unsigned char wu0[13] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x9c, 0x40 };
    /* catches: a WINDOW_UPDATE per frame (a visible pattern), or credit never returned */
    start(&g_m, &g_r, 1);
    open1(&g_m, &REQ_POST);
    r_clear(&g_r);
    size_t n = fr(in, 16384, 0x00, 0, 1, NULL);
    n += fr(in + n, 3616, 0x00, 0, 1, NULL);
    check("credit: 20000 bytes", 0, feed(&g_m, in, n));
    check_str("credit: delivered", "D0:20000 ", g_r.log);
    h2m_consumed(&g_m, 0, 20000);
    check("credit: 20000 consumed, nothing sent", 0, (long)g_r.sent_n);
    feed(&g_m, in, n);
    h2m_consumed(&g_m, 0, 20000);
    check("credit: 40000 consumed, one WINDOW_UPDATE", 13, (long)g_r.sent_n);
    check_mem("credit: WINDOW_UPDATE(1, 40000)", wu1, g_r.sent, 13);
    check("credit: WINDOW_UPDATE is control", 1, g_r.last_control);
    r_clear(&g_r);
    h2m_credit_conn(&g_m, 20000);
    check("credit: connection 20000, nothing sent", 0, (long)g_r.sent_n);
    h2m_credit_conn(&g_m, 20000);
    check("credit: connection 40000, one WINDOW_UPDATE", 13, (long)g_r.sent_n);
    check_mem("credit: WINDOW_UPDATE(0, 40000)", wu0, g_r.sent, 13);
    h2m_free(&g_m);
}

static void t_padding_credited(void) {
    static unsigned char in[2 * (9 + 16384)];
    static unsigned char body[16384];
    /* catches: padding never credited back, so the windows shrink by every padded frame */
    memset(body, 'p', sizeof body);
    body[0] = 255;
    start(&g_m, &g_r, 1);
    open1(&g_m, &REQ_POST);
    r_clear(&g_r);
    size_t n = fr(in, 16384, 0x00, 0x08, 1, body);
    n += fr(in + n, 16384, 0x00, 0x08, 1, body);
    check("padding: feed", 0, feed(&g_m, in, n));
    check_str("padding: only content delivered", "D0:32256 ", g_r.log);
    check("padding: no credit yet", 0, (long)g_r.sent_n);
    static const unsigned char wu1[13] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
                                           0x00, 0x00, 0x80, 0x00 };
    static const unsigned char wu0[13] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x80, 0x00 };
    h2m_consumed(&g_m, 0, 32256);
    check("padding: stream credit with the padding", 13, (long)g_r.sent_n);
    check_mem("padding: WINDOW_UPDATE(1, 32768)", wu1, g_r.sent, 13);
    r_clear(&g_r);
    check("padding: the connection share handed over", 512, (long)h2m_take_lost(&g_m));
    h2m_credit_conn(&g_m, 32256 + 512);
    check("padding: connection credit with the padding", 13, (long)g_r.sent_n);
    check_mem("padding: WINDOW_UPDATE(0, 32768)", wu0, g_r.sent, 13);
    h2m_free(&g_m);
}

/* catches: padding credit sent by the engine on its own, past the link's one pending update */
static void t_padding_coalesced(void) {
    static unsigned char in[256 * (9 + 256)];
    unsigned char body[256];
    memset(body, 0, sizeof body);
    body[0] = 255;
    start(&g_m, &g_r, 1);
    open1(&g_m, &REQ_GET);
    r_clear(&g_r);
    size_t n = 0;
    for (int i = 0; i < 256; i++) n += fr(in + n, 256, 0x00, 0x08, 1, body);
    check("pad coalesced: 256 padded frames fed", 0, feed(&g_m, in, n));
    check("pad coalesced: nothing sent for 65536 bytes of padding", 0, (long)g_r.sent_n);
    check("pad coalesced: the connection share handed over", 65536, (long)h2m_take_lost(&g_m));
    static const unsigned char wu1[13] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
                                           0x00, 0x01, 0x00, 0x01 };
    h2m_consumed(&g_m, 0, 1);
    check("pad coalesced: one stream update at the next read", 13, (long)g_r.sent_n);
    check_mem("pad coalesced: WINDOW_UPDATE(1, 65537)", wu1, g_r.sent, 13);
    h2m_free(&g_m);
}

static unsigned char g_big[70 * (9 + 16384)];

static size_t overrun_bytes(void) {
    size_t n = 0;
    for (int i = 0; i < 64; i++) n += fr(g_big + n, 16384, 0x00, 0, 1, NULL);
    n += fr(g_big + n, 1, 0x00, 0, 1, NULL);
    n += fr(g_big + n, 2, 0x00, 0, 3, "bb");
    return n;
}

static void setup_two_credit(struct h2m *m, struct rec *r) {
    setup_two(m, r);
    r->credit_on_data = 1;
}

static void t_recv_overrun(void) {
    static const unsigned char rst[13] = { 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
                                           0x00, 0x00, 0x00, 0x03 };
    /* catches: one stream's overrun ending the connection */
    size_t n = overrun_bytes();
    setup_two_credit(&g_m, &g_r);
    r_clear(&g_r);
    check("overrun: feed goes on", 0, feed(&g_m, g_big, n));
    check_str("overrun: A ends with H2_EFLOW, B still served", "D0:1048576 E0:-61 D1:2 ", g_r.log);
    size_t at;
    check("overrun: RST_STREAM on 1", 1, find_frame(&g_r, 0x03, 1, &at));
    check_mem("overrun: RST_STREAM(1, FLOW_CONTROL_ERROR)", rst, g_r.sent + at, 13);
    check("overrun: A no longer open", 1, h2m_open_n(&g_m));
    h2m_free(&g_m);
    check_splits("overrun: every split gives the same", setup_two_credit, g_big, n);
}

static void t_conn_overrun(void) {
    unsigned char in[5 * (9 + 16384)];
    /* catches: the connection window never checked, or the preface ruling's 65535 forgotten */
    start(&g_m, &g_r, 0);
    open1(&g_m, &REQ_POST);
    size_t n = 0;
    for (int i = 0; i < 3; i++) n += fr(in + n, 16384, 0x00, 0, 1, NULL);
    n += fr(in + n, 16383, 0x00, 0, 1, NULL);
    check("connection overrun: 65535 bytes fit", 0, feed(&g_m, in, n));
    n = fr(in, 1, 0x00, 0, 1, NULL);
    check("connection overrun: one more byte", H2_EFLOW, feed(&g_m, in, n));
    check("connection overrun: no new stream after", H2_EFLOW, h2m_open(&g_m, &REQ_POST, 1, &(uint16_t){0}));
    h2m_free(&g_m);
}

static void t_reset_inside_data(void) {
    static unsigned char in[2 * (9 + 16384)];
    static const unsigned char wu0[13] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x80, 0x00 };
    /* catches: the rest of a frame whose stream we reset mid-frame never credited to the connection */
    start(&g_m, &g_r, 1);
    open1(&g_m, &REQ_POST);
    g_r.credit_on_data = 1;
    g_r.reset_on_data = 1;
    size_t n = fr(in, 16384, 0x00, 0, 1, NULL);
    n += fr(in + n, 16384, 0x00, 0, 9, NULL);
    r_clear(&g_r);
    check("reset inside data: first byte", 0, feed(&g_m, in, 10));
    check_str("reset inside data: one byte delivered", "D0:1 ", g_r.log);
    check("reset inside data: the rest", 0, feed(&g_m, in + 10, n - 10));
    check_str("reset inside data: nothing more delivered", "D0:1 ", g_r.log);
    check("reset inside data: the rest reported as lost", 32767, (long)h2m_take_lost(&g_m));
    check("reset inside data: taken once", 0, (long)h2m_take_lost(&g_m));
    h2m_credit_conn(&g_m, 32767);
    size_t at;
    check("reset inside data: WINDOW_UPDATE on 0", 1, find_frame(&g_r, 0x08, 0, &at));
    check_mem("reset inside data: WINDOW_UPDATE(0, 32768)", wu0, g_r.sent + at, 13);
    h2m_free(&g_m);
}

static unsigned char g_closed[40 * 1009 + 64];

static size_t closed_bytes(uint32_t sid) {
    size_t n = 0;
    for (int i = 0; i < 33; i++) n += fr(g_closed + n, 1000, 0x00, 0, sid, NULL);
    n += fr_u32(g_closed + n, 0x08, sid, 100);
    n += fr_u32(g_closed + n, 0x03, sid, 2);
    return n;
}

static void setup_closed(struct h2m *m, struct rec *r) {
    unsigned char in[16];
    start(m, r, 1);
    open1(m, &REQ_POST);
    size_t n = fr_u32(in, 0x03, 1, 8);
    feed(m, in, n);
}

static void t_closed_sid_frames(void) {
    static const unsigned char wu0[13] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x80, 0xe8 };
    unsigned char in[16];
    /* catches: frames of a closed stream eating the window or killing the connection */
    start(&g_m, &g_r, 1);
    open1(&g_m, &REQ_POST);
    r_clear(&g_r);
    size_t n = fr_u32(in, 0x03, 1, 8);
    check("closed: RST_STREAM(1, CANCEL)", 0, feed(&g_m, in, n));
    check_str("closed: A ends with CANCEL", "E0:8 ", g_r.log);
    check("closed: nothing sent back", 0, (long)g_r.sent_n);
    check("closed: none open", 0, h2m_open_n(&g_m));
    r_clear(&g_r);
    static unsigned char d[1009];
    n = fr(d, 1000, 0x00, 0, 1, NULL);
    for (int i = 0; i < 32; i++) feed(&g_m, d, n);
    check("closed: 32000 dropped, no credit yet", 0, (long)g_r.sent_n);
    check("closed: 33rd DATA", 0, feed(&g_m, d, n));
    check("closed: reported, not credited by h2m", 0, (long)g_r.sent_n);
    check("closed: 33000 lost", 33000, (long)h2m_take_lost(&g_m));
    h2m_credit_conn(&g_m, 33000);
    check("closed: one WINDOW_UPDATE", 13, (long)g_r.sent_n);
    check_mem("closed: WINDOW_UPDATE(0, 33000)", wu0, g_r.sent, 13);
    check_str("closed: no data delivered", "", g_r.log);
    r_clear(&g_r);
    n = fr_u32(in, 0x08, 1, 100);
    check("closed: WINDOW_UPDATE(1, 100)", 0, feed(&g_m, in, n));
    n = fr_u32(in, 0x03, 1, 2);
    check("closed: RST_STREAM(1, 2)", 0, feed(&g_m, in, n));
    check_str("closed: no callback", "", g_r.log);
    check("closed: no frame", 0, (long)g_r.sent_n);
    check("closed: connection room untouched", 65535, h2m_conn_room(&g_m));
    check("closed: the connection still opens streams", 0, h2m_open(&g_m, &REQ_POST, 1, &(uint16_t){0}));
    h2m_free(&g_m);

    start(&g_m, &g_r, 1);
    open1(&g_m, &REQ_POST);
    r_clear(&g_r);
    n = closed_bytes(9);
    check("never opened 9: feed", 0, feed(&g_m, g_closed, n));
    check_str("never opened 9: no callback", "", g_r.log);
    check("never opened 9: nothing sent by h2m", 0, (long)g_r.sent_n);
    check("never opened 9: 33000 lost", 33000, (long)h2m_take_lost(&g_m));
    h2m_credit_conn(&g_m, 33000);
    check("never opened 9: only the WINDOW_UPDATE", 13, (long)g_r.sent_n);
    check_mem("never opened 9: WINDOW_UPDATE(0, 33000)", wu0, g_r.sent, 13);
    check("never opened 9: A untouched", 1, h2m_open_n(&g_m));
    check("never opened 9: A's room untouched", 65535, h2m_room(&g_m, 0));
    check("never opened 9: connection room untouched", 65535, h2m_conn_room(&g_m));
    h2m_free(&g_m);
    check_splits("closed: every split gives the same", setup_closed, g_closed, closed_bytes(1));
}

static void setup_one_get(struct h2m *m, struct rec *r) {
    start(m, r, 1);
    open1(m, &REQ_GET);
}

static void t_continuation_skipped(void) {
    static unsigned char in[256];
    unsigned char st = 0x88;
    /* catches: CONTINUATION read as a new frame body or dropped with the next frame */
    size_t n = fr(in, 1, 0x01, 0x00, 1, &st);
    n += fr(in + n, 100, 0x09, 0x04, 1, NULL);
    n += fr(in + n, 1, 0x00, 0x00, 1, "x");
    setup_one_get(&g_m, &g_r);
    r_clear(&g_r);
    check("continuation: feed", 0, feed(&g_m, in, n));
    check_str("continuation: status then data", "S0:200 D0:1 ", g_r.log);
    check_mem("continuation: data x", "x", g_r.body[0], 1);
    h2m_free(&g_m);
    check_splits("continuation: every split gives the same", setup_one_get, in, n);
}

static void t_continuation_end_waits(void) {
    static unsigned char in[256];
    unsigned char st = 0x88;
    /* catches: END_STREAM of a HEADERS acted on before its END_HEADERS */
    setup_one_get(&g_m, &g_r);
    r_clear(&g_r);
    size_t n = fr(in, 1, 0x01, 0x01, 1, &st);
    check("continuation: HEADERS with END_STREAM, no END_HEADERS", 0, feed(&g_m, in, n));
    check_str("continuation: no end before the block ends", "S0:200 ", g_r.log);
    n = fr(in, 100, 0x09, 0x04, 1, NULL);
    check("continuation: CONTINUATION with END_HEADERS", 0, feed(&g_m, in, n));
    check_str("continuation: end after it", "S0:200 E0:0 ", g_r.log);
    h2m_free(&g_m);
}

static void t_continuation_interrupted(void) {
    static unsigned char in[256];
    unsigned char st = 0x88;
    /* catches: a frame between HEADERS and its CONTINUATION accepted */
    setup_one_get(&g_m, &g_r);
    size_t n = fr(in, 1, 0x01, 0x00, 1, &st);
    n += fr(in + n, 1, 0x00, 0x00, 1, "x");
    check("continuation: DATA inside a header block", H2_EPROTO, feed(&g_m, in, n));
    h2m_free(&g_m);
}

static void setup_four(struct h2m *m, struct rec *r) {
    start(m, r, 1);
    for (int i = 0; i < 4; i++) open1(m, &REQ_GET);
}

static void t_status_forms(void) {
    static unsigned char in[128];
    unsigned char s200 = 0x88, s404[5] = { 0x0d, 0x03, '4', '0', '4' }, dyn = 0xbe;
    unsigned char h502[4] = { 0x08, 0x82, 0x6c, 0x02 };
    /* catches: a refused request read as 200 */
    size_t n = fr(in, 1, 0x01, 0x04, 1, &s200);
    n += fr(in + n, 5, 0x01, 0x04, 3, s404);
    n += fr(in + n, 1, 0x01, 0x04, 5, &dyn);
    n += fr(in + n, 1, 0x01, 0x05, 7, &s200);
    setup_four(&g_m, &g_r);
    r_clear(&g_r);
    check("status: feed", 0, feed(&g_m, in, n));
    check_str("status: 200, 404, unreadable, then 200 with end", "S0:200 S1:404 S2:-1 S3:200 E3:0 ", g_r.log);
    h2m_free(&g_m);
    check_splits("status: every split gives the same", setup_four, in, n);
    check("h2w_status: Huffman 502", 502, h2w_status(h502, 4));
    check("h2w_status: literal 404 name index 13", 404, h2w_status(s404, 5));
    unsigned char bad[5] = { 0x0d, 0x03, '4', 'x', '4' };
    check("h2w_status: a non-digit literal", -1, h2w_status(bad, 5));
    unsigned char upd = 0x20;
    check("h2w_status: nothing but a table size update", 0, h2w_status(&upd, 1));
    check("h2w_status: empty", 0, h2w_status(&upd, 0));
}

static void setup_three(struct h2m *m, struct rec *r) {
    start(m, r, 1);
    for (int i = 0; i < 3; i++) open1(m, &REQ_POST);
}

static void t_goaway(void) {
    static unsigned char in[128];
    unsigned char ga[8] = { 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00 };
    /* catches: GOAWAY ending streams below last, or new streams after it */
    size_t n = fr(in, 8, 0x07, 0, 0, ga);
    n += fr(in + n, 1, 0x00, 0, 1, "a");
    n += fr(in + n, 1, 0x00, 0, 3, "b");
    setup_three(&g_m, &g_r);
    r_clear(&g_r);
    check("goaway: feed", 0, feed(&g_m, in, n));
    check_str("goaway: callback, stream 5 reset, 1 and 3 served", "G3:0 E2:-53 D0:1 D1:1 ", g_r.log);
    check("goaway: nothing sent", 0, (long)g_r.sent_n);
    check("goaway: two open", 2, h2m_open_n(&g_m));
    check("goaway: no new stream", H2_ERESET, h2m_open(&g_m, &REQ_POST, 1, &(uint16_t){0}));
    check("goaway: 1 still sends", 0, h2m_send(&g_m, 0, (const unsigned char *)"z", 1, 0));
    h2m_free(&g_m);
    check_splits("goaway: every split gives the same", setup_three, in, n);
}

static const unsigned char PING_OP2[8] = { 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };

static void setup_pinged(struct h2m *m, struct rec *r) {
    start(m, r, 1);
    h2m_ping(m, PING_OP2);
}

static void t_ping(void) {
    static unsigned char in[64];
    unsigned char op[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, op2[8] = { 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    static const unsigned char ack[17] = { 0x00, 0x00, 0x08, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00,
                                           1, 2, 3, 4, 5, 6, 7, 8 };
    static const unsigned char ping[17] = { 0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    /* catches: a PING left unanswered, answered with other bytes, or any ACK taken as ours */
    start(&g_m, &g_r, 1);
    r_clear(&g_r);
    size_t n = fr(in, 8, 0x06, 0, 0, op);
    check("ping: peer PING", 0, feed(&g_m, in, n));
    check("ping: one ACK", 17, (long)g_r.sent_n);
    check_mem("ping: ACK with the same bytes", ack, g_r.sent, 17);
    check("ping: ACK is control", 1, g_r.last_control);
    check_str("ping: no callback for the peer's PING", "", g_r.log);
    r_clear(&g_r);
    check("ping: ours", 0, h2m_ping(&g_m, op2));
    check("ping: one PING", 17, (long)g_r.sent_n);
    check_mem("ping: PING bytes", ping, g_r.sent, 17);
    check("ping: PING is control", 1, g_r.last_control);
    r_clear(&g_r);
    n = fr(in, 8, 0x06, 0x01, 0, op);
    check("ping: ACK with other bytes", 0, feed(&g_m, in, n));
    check_str("ping: other bytes, no callback", "", g_r.log);
    n = fr(in, 8, 0x06, 0x01, 0, op2);
    check("ping: ACK of ours", 0, feed(&g_m, in, n));
    check_str("ping: ping_ack", "P ", g_r.log);
    check("ping: an ACK sends nothing", 0, (long)g_r.sent_n);
    h2m_free(&g_m);
    n = fr(in, 8, 0x06, 0, 0, op);
    n += fr(in + n, 8, 0x06, 0x01, 0, op);
    n += fr(in + n, 8, 0x06, 0x01, 0, PING_OP2);
    check_splits("ping: every split gives the same", setup_pinged, in, n);
}

static void t_cap(void) {
    static unsigned char in[64];
    uint16_t slot;
    unsigned char s200 = 0x88;
    /* catches: the server's stream limit ignored, a freed slot never reused, or the table not grown */
    start(&g_m, &g_r, 1);
    check("cap: 100 before SETTINGS", 100, (long)h2m_cap(&g_m));
    int ok = 1;
    for (int i = 0; i < 100; i++) ok &= h2m_open(&g_m, &REQ_POST, 1, &slot) == 0 && slot == i;
    check("cap: 100 streams in slots 0..99", 1, ok);
    check("cap: the 101st refused", H2_EFULL, h2m_open(&g_m, &REQ_POST, 1, &slot));
    r_clear(&g_r);
    size_t n = fr(in, 1, 0x00, 0, 1, "a");
    n += fr(in + n, 1, 0x00, 0, 199, "z");
    feed(&g_m, in, n);
    check_str("cap: slots stable over growth", "D0:1 D99:1 ", g_r.log);
    n = fr_setting(in, 0x03, 1000);
    feed(&g_m, in, n);
    check("cap: at most 256", 256, (long)h2m_cap(&g_m));
    h2m_free(&g_m);

    start(&g_m, &g_r, 1);
    n = fr_setting(in, 0x03, 2);
    feed(&g_m, in, n);
    check("cap: the server's 2", 2, (long)h2m_cap(&g_m));
    uint16_t a = open1(&g_m, &REQ_GET), b = open1(&g_m, &REQ_GET);
    check("cap: two opened", 1, a == 0 && b == 1);
    check("cap: third refused", H2_EFULL, h2m_open(&g_m, &REQ_GET, 1, &slot));
    check("cap: two open", 2, h2m_open_n(&g_m));
    r_clear(&g_r);
    n = fr(in, 1, 0x01, 0x05, 1, &s200);
    feed(&g_m, in, n);
    check_str("cap: A answered and ended", "S0:200 E0:0 ", g_r.log);
    check("cap: open after the end", 0, h2m_open(&g_m, &REQ_GET, 1, &slot));
    check("cap: the freed slot reused", 0, slot);
    size_t at;
    check("cap: on stream 5", 1, find_frame(&g_r, 0x01, 5, &at));
    h2m_free(&g_m);

    start(&g_m, &g_r, 1);
    n = fr(in, 0, 0x04, 0, 0, NULL);
    feed(&g_m, in, n);
    check("cap: SETTINGS without the limit, 256", 256, (long)h2m_cap(&g_m));
    h2m_free(&g_m);
}

static void t_budget_follows_peer_settings(void) {
    static unsigned char in[64];
    /* catches: the header budget not following the server's MAX_HEADER_LIST_SIZE */
    start(&g_m, &g_r, 1);
    check("budget before the peer's SETTINGS", 8192, (long)h2m_header_budget(&g_m, 0));
    feed(&g_m, in, fr_setting(in, 0x06, 9000));
    check("budget after MAX_HEADER_LIST_SIZE 9000", 9000, (long)h2m_header_budget(&g_m, 0));
    h2m_free(&g_m);
    start(&g_m, &g_r, 1);
    feed(&g_m, in, fr_setting(in, 0x04, 70000));
    check("budget after a SETTINGS without 0x06", 16384, (long)h2m_header_budget(&g_m, 0));
    h2m_free(&g_m);
}

static void t_budget_before_settings_follows_the_server_limit(void) {
    static unsigned char in[64];
    start(&g_m, &g_r, 1);
    /* catches: a server limit below 8192 ignored before SETTINGS, or one above 8192 taken */
    check("server limit 4096: budget before SETTINGS", 4096, (long)h2m_header_budget(&g_m, 4096));
    check("server limit 8191: budget before SETTINGS", 8191, (long)h2m_header_budget(&g_m, 8191));
    check("server limit 16384: budget before SETTINGS stays 8192", 8192, (long)h2m_header_budget(&g_m, 16384));
    feed(&g_m, in, fr_setting(in, 0x06, 9000));
    /* catches: the server limit capping the budget after the announced one */
    check("server limit 4096: budget after 0x06 9000", 9000, (long)h2m_header_budget(&g_m, 4096));
    check("server limit 16384: budget after 0x06 9000", 9000, (long)h2m_header_budget(&g_m, 16384));
    h2m_free(&g_m);
    start(&g_m, &g_r, 1);
    feed(&g_m, in, fr_setting(in, 0x04, 70000));
    check("server limit 4096: budget after a SETTINGS without 0x06", 16384, (long)h2m_header_budget(&g_m, 4096));
    h2m_free(&g_m);
}

static void t_budget_reset_by_a_later_settings(void) {
    static unsigned char in[64];
    start(&g_m, &g_r, 1);
    size_t n = fr_setting(in, 0x06, 9000);
    n += fr_setting(in + n, 0x04, 70000);
    /* catches: a later SETTINGS without 0x06 putting the budget back to 16384 */
    feed(&g_m, in, n);
    check("later SETTINGS without 0x06: budget stays 9000", 9000, (long)h2m_header_budget(&g_m, 0));
    h2m_free(&g_m);
}

static void t_reset_and_end_ours(void) {
    static const unsigned char rst[13] = { 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
                                           0x00, 0x00, 0x00, 0x08 };
    static const unsigned char end[9] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03 };
    /* catches: our reset or end not on the wire, or a stream ended twice */
    setup_two(&g_m, &g_r);
    r_clear(&g_r);
    check("ours: reset A", 0, h2m_reset(&g_m, 0, 8));
    check("ours: one RST_STREAM", 13, (long)g_r.sent_n);
    check_mem("ours: RST_STREAM(1, CANCEL)", rst, g_r.sent, 13);
    check("ours: RST is control", 1, g_r.last_control);
    check_str("ours: no callback for our own reset", "", g_r.log);
    check("ours: one open", 1, h2m_open_n(&g_m));
    check("ours: A no longer sends", H2_ERESET, h2m_send(&g_m, 0, (const unsigned char *)"z", 1, 0));
    r_clear(&g_r);
    check("ours: end B", 0, h2m_send(&g_m, 1, NULL, 0, 1));
    check("ours: one empty DATA", 9, (long)g_r.sent_n);
    check_mem("ours: DATA(3) END_STREAM", end, g_r.sent, 9);
    r_clear(&g_r);
    check("ours: second end", H2_EPROTO, h2m_send(&g_m, 1, NULL, 0, 1));
    check("ours: second end sends nothing", 0, (long)g_r.sent_n);
    check("ours: B open until the answer", 1, h2m_open_n(&g_m));
    check("ours: no room after our end", 0, h2m_room(&g_m, 1));
    h2m_free(&g_m);
}

static void t_end_past_negative_window(void) {
    unsigned char in[64], buf[100];
    static const unsigned char end[9] = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };
    memset(buf, 'u', sizeof buf);
    /* catches: an empty END_STREAM refused because a SETTINGS decrease left the window negative */
    start(&g_m, &g_r, 1);
    open1(&g_m, &REQ_POST);
    check("negative window: 100 bytes", 0, h2m_send(&g_m, 0, buf, 100, 0));
    size_t n = fr_setting(in, 0x04, 50);
    check("negative window: SETTINGS 50", 0, feed(&g_m, in, n));
    check("negative window: room 0", 0, h2m_room(&g_m, 0));
    r_clear(&g_r);
    check("negative window: one byte refused", H2_EWINDOW, h2m_send(&g_m, 0, buf, 1, 0));
    check("negative window: empty end taken", 0, h2m_send(&g_m, 0, NULL, 0, 1));
    check("negative window: one empty DATA", 9, (long)g_r.sent_n);
    check_mem("negative window: DATA(1) END_STREAM", end, g_r.sent, 9);
    h2m_free(&g_m);
}

static void t_remote_end_closes_ours(void) {
    static unsigned char in[64];
    unsigned char s200 = 0x88;
    static const unsigned char rst[13] = { 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
                                           0x00, 0x00, 0x00, 0x00 };
    /* catches: a stream the server ended left open on our side, or closed with another code than x/net's NO_ERROR */
    setup_two(&g_m, &g_r);
    h2m_send(&g_m, 1, NULL, 0, 1);
    r_clear(&g_r);
    size_t n = fr(in, 1, 0x01, 0x05, 1, &s200);
    n += fr(in + n, 1, 0x01, 0x05, 3, &s200);
    check("remote end: feed", 0, feed(&g_m, in, n));
    check_str("remote end: both end", "S0:200 E0:0 S1:200 E1:0 ", g_r.log);
    check("remote end: one RST_STREAM", 13, (long)g_r.sent_n);
    check_mem("remote end: NO_ERROR for the half we kept open", rst, g_r.sent, 13);
    check("remote end: none open", 0, h2m_open_n(&g_m));
    h2m_free(&g_m);
}

static void t_errors_named(void) {
    /* catches: a new code without its text */
    check("errors: H2_EFULL is -60", -60, H2_EFULL);
    check("errors: H2_EFLOW is -61", -61, H2_EFLOW);
    check("errors: H2_EFULL named", 0, strcmp(h2_strerror(H2_EFULL), "unknown HTTP/2 error") == 0);
    check("errors: H2_EFLOW named", 0, strcmp(h2_strerror(H2_EFLOW), "unknown HTTP/2 error") == 0);
}

int main(void) {
    t_preface_bytes();
    t_ids();
    t_two_streams_demux();
    t_send_windows();
    t_settings_acked();
    t_settings_shift();
    t_stream_credit_steps();
    t_padding_credited();
    t_padding_coalesced();
    t_recv_overrun();
    t_conn_overrun();
    t_reset_inside_data();
    t_closed_sid_frames();
    t_continuation_skipped();
    t_continuation_end_waits();
    t_continuation_interrupted();
    t_status_forms();
    t_goaway();
    t_ping();
    t_cap();
    t_budget_follows_peer_settings();
    t_budget_before_settings_follows_the_server_limit();
    t_budget_reset_by_a_later_settings();
    t_reset_and_end_ours();
    t_end_past_negative_window();
    t_remote_end_closes_ours();
    t_errors_named();
    return unit_done("h2muxmatch");
}
