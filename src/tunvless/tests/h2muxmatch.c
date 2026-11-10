#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "unit.h"
#include "hpackread.h"
#include "h2mux.h"

void *__real_calloc(size_t k, size_t n);
static size_t g_cfail;
static int g_cfail_tries;

void *__wrap_calloc(size_t k, size_t n) {
    if (g_cfail && k * n == g_cfail) {
        g_cfail_tries++;
        errno = ENOMEM;
        return NULL;
    }
    return __real_calloc(k, n);
}

struct rec {
    struct h2m *m;
    unsigned char sent[1 << 17];
    size_t sent_n;
    unsigned outs;
    int last_control;
    char calls[1024];
    size_t calls_n;
    char log[4096];
    size_t log_n;
    int last_kind;
    uint16_t last_slot;
    unsigned long last_len;
    size_t last_at;
    unsigned char body[4][64];
    size_t body_n[4];
    int reset_on_data;
    struct h2m_in end_in;
};

static int r_out(void *ctx, const unsigned char *d, size_t n, unsigned flags) {
    struct rec *r = ctx;
    if (r->sent_n + n > sizeof r->sent) return H2_EIO;
    memcpy(r->sent + r->sent_n, d, n);
    r->sent_n += n;
    r->outs++;
    r->last_control = (flags & H2M_CTL) != 0;
    int k = snprintf(r->calls + r->calls_n, sizeof r->calls - r->calls_n, "%zu:%u ", n, flags);
    if (k > 0 && (size_t)k < sizeof r->calls - r->calls_n) r->calls_n += (size_t)k;
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

static void r_end(void *ctx, uint16_t slot, int code, const struct h2m_in *in) {
    ((struct rec *)ctx)->end_in = *in;
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
    r->calls_n = 0;
    r->calls[0] = '\0';
    r->log_n = 0;
    r->log[0] = '\0';
    r->last_kind = 0;
    memset(r->body_n, 0, sizeof r->body_n);
}

static int start(struct h2m *m, struct rec *r) {
    memset(r, 0, sizeof *r);
    r->m = m;
    struct h2m_cb cb = { r, r_out, r_data, r_status, r_end, r_goaway, r_ping_ack, r_room };
    return h2m_start(m, &cb, 1);
}

static const struct h2_req REQ_POST = { .authority = "a.example", .path = "/up", .method = "POST" };
static const struct h2_req REQ_GET = { .authority = "a.example", .path = "/down", .method = "GET",
                                       .end_stream = 1 };

static uint16_t open1(struct h2m *m, const struct h2_req *q) {
    uint16_t slot = UINT16_MAX;
    int rc = h2m_open(m, q, &slot);
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

static const unsigned char GO_PREFACE[70] = {
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a,
    0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
    0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x40, 0x00, 0x00,
    0x00, 0x05, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x06, 0x00, 0xa0, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00,
};

static void t_preface_go(void) {
    unsigned char out[80];
    /* catches: tunvless's 58/45 B preface, or SETTINGS out of Go's order */
    check("go preface: started", 0, start(&g_m, &g_r));
    check_str("go preface: one call, 70 B, END", "70:4 ", g_r.calls);
    check_mem("go preface: bytes", GO_PREFACE, g_r.sent, 70);
    check("go preface: connection inflow 1<<30 + 65535", 1073807359, (long)g_m.in_conn.avail);
    check("go preface: nothing unsent", 0, (long)g_m.in_conn.unsent);
    uint16_t a = open1(&g_m, &REQ_GET);
    check("go preface: stream inflow 4 MiB", 4194304, (long)g_m.st[a].in.avail);
    check("go preface: stream inflow carries its id", 1, (long)g_m.st[a].in.sid);
    check("h2w_go_preface: 70", 70, (long)h2w_go_preface(out, sizeof out));
    check_mem("h2w_go_preface: bytes", GO_PREFACE, out, 70);
    check("h2w_go_preface past cap: 0", 0, (long)h2w_go_preface(out, 69));
    h2m_free(&g_m);
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
    /* catches: gRPC's preface changed by the xhttp one */
    unsigned char out[64];
    check("h2w_preface with WINDOW_UPDATE: 58", 58, (long)h2w_preface(out, sizeof out, 1));
    check_mem("h2w_preface with WINDOW_UPDATE: bytes", want, out, 58);
    check("h2w_preface without WINDOW_UPDATE: 45", 45, (long)h2w_preface(out, sizeof out, 0));
    check_mem("h2w_preface without WINDOW_UPDATE: bytes", want, out, 45);
    check("h2w_preface past cap: 0", 0, (long)h2w_preface(out, 57, 1));
}

static void t_inflow_rule(void) {
    struct h2m_in f = { 1, 5000, 0, 0 };
    /* catches: the remainder rule missing, or a 32 KiB threshold */
    f.avail -= 3000;
    check("inflow: 2500 reaches the remainder 2000", 2500, (long)h2m_in_add(&f, 2500));
    check("inflow: avail 4500", 4500, (long)f.avail);
    check("inflow: nothing unsent", 0, (long)f.unsent);
    check("inflow: 100 kept", 0, (long)h2m_in_add(&f, 100));
    check("inflow: 100 unsent", 100, (long)f.unsent);
    check("inflow: avail still 4500", 4500, (long)f.avail);
    check("inflow: 3996 more reaches 4096", 4096, (long)h2m_in_add(&f, 3996));
    check("inflow: avail 8596", 8596, (long)f.avail);
    check("inflow: unsent back to 0", 0, (long)f.unsent);
    check("inflow: 4095 kept", 0, (long)h2m_in_add(&f, 4095));
    check("inflow: add 0 sends nothing below both", 0, (long)h2m_in_add(&f, 0));
}

static void t_ids(void) {
    /* catches: stream ids reused or not odd, or END_STREAM set where the request has none */
    start(&g_m, &g_r);
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
    start(m, r);
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
    start(m, r);
    open1(m, &REQ_POST);
}

static void t_settings_acked(void) {
    unsigned char in[64];
    static const unsigned char ack[9] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00 };
    /* catches: a SETTINGS left unacknowledged, or an ACK answered */
    start(&g_m, &g_r);
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
    start(&g_m, &g_r);
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

static size_t wu_pair(unsigned char *o, uint32_t c, uint32_t sid, uint32_t s) {
    size_t n = 0;
    if (c) n += fr_u32(o, 0x08, 0, c);
    if (s) n += fr_u32(o + n, 0x08, sid, s);
    return n;
}

static void check_sent(const char *what, uint32_t c, uint32_t sid, uint32_t s) {
    unsigned char want[26];
    size_t n = wu_pair(want, c, sid, s);
    check(what, (long)n, (long)g_r.sent_n);
    if (n == g_r.sent_n) check_mem(what, want, g_r.sent, n);
}

static size_t data_hdr(unsigned char *o, uint32_t len, uint32_t sid) {
    fr(o, 0, 0x00, 0, sid, NULL);
    o[0] = (unsigned char)(len >> 16);
    o[1] = (unsigned char)(len >> 8);
    o[2] = (unsigned char)len;
    return 9;
}

static void t_credit_pair(void) {
    static unsigned char in[2 * (9 + 16384)];
    /* catches: stream first, two units, or credit per frame */
    start(&g_m, &g_r);
    uint16_t a = open1(&g_m, &REQ_GET);
    size_t n = fr(in, 16384, 0x00, 0, 1, NULL);
    n += fr(in + n, 3616, 0x00, 0, 1, NULL);
    r_clear(&g_r);
    check("pair: 20000 on A", 0, feed(&g_m, in, n));
    check("pair: nothing on arrival", 0, (long)g_r.sent_n);
    h2m_consumed(&g_m, a, NULL, 8192, 1);
    check_str("pair: one unit", "26:5 ", g_r.calls);
    check_sent("pair: WU(0, 8192) then WU(1, 8192)", 8192, 1, 8192);
    r_clear(&g_r);
    h2m_consumed(&g_m, a, NULL, 3616, 1);
    check("pair: 3616 kept", 0, (long)g_r.sent_n);
    h2m_consumed(&g_m, a, NULL, 1000, 1);
    check_str("pair: one unit again", "26:5 ", g_r.calls);
    check_sent("pair: WU(0, 4616) then WU(1, 4616)", 4616, 1, 4616);
    check("pair: connection avail back", 1073807359 - 20000 + 12808, (long)g_m.in_conn.avail);
    check("pair: stream avail back", 4194304 - 20000 + 12808, (long)g_m.st[a].in.avail);
    h2m_free(&g_m);
}

static void t_withheld_flush(void) {
    static unsigned char in[9 + 8192];
    /* catches: withheld credit lost, or the connection's withheld too */
    start(&g_m, &g_r);
    uint16_t a = open1(&g_m, &REQ_GET);
    feed(&g_m, in, fr(in, 8192, 0x00, 0, 1, NULL));
    r_clear(&g_r);
    h2m_consumed(&g_m, a, NULL, 8192, 0);
    check_str("withheld: one unit", "13:5 ", g_r.calls);
    check_sent("withheld: WU(0, 8192) alone", 8192, 1, 0);
    check("withheld: stream withheld 8192", 8192, (long)g_m.st[a].in.wh);
    check("withheld: none of it unsent", 0, (long)g_m.st[a].in.unsent);
    r_clear(&g_r);
    check("withheld: DATA 100 arrives", 0, feed(&g_m, in, fr(in, 100, 0x00, 0, 1, NULL)));
    check("withheld: the arrival keeps it withheld", 0, (long)g_r.sent_n);
    check("withheld: flush leaves nothing unsent", 0, (long)h2m_stream_flush(&g_m, a, NULL));
    check_str("withheld: flush one unit", "13:5 ", g_r.calls);
    check_sent("withheld: WU(1, 8192) alone", 0, 1, 8192);
    r_clear(&g_r);
    check("withheld: second flush leaves 0", 0, (long)h2m_stream_flush(&g_m, a, NULL));
    check("withheld: second flush sends nothing", 0, (long)g_r.sent_n);
    h2m_consumed(&g_m, a, NULL, 1000, 0);
    r_clear(&g_r);
    check("withheld: 1000 below the threshold stays", 1000, (long)h2m_stream_flush(&g_m, a, NULL));
    check("withheld: nothing sent for 1000", 0, (long)g_r.sent_n);
    h2m_free(&g_m);
}

static void t_hold_keeps_withheld(void) {
    static unsigned char in[2 * (9 + 8192)];
    /* catches: the hold release freeing credit the budget withheld */
    start(&g_m, &g_r);
    uint16_t a = open1(&g_m, &REQ_GET);
    uint16_t b = open1(&g_m, &REQ_GET);
    size_t n = fr(in, 8192, 0x00, 0, 1, NULL);
    n += fr(in + n, 8192, 0x00, 0, 3, NULL);
    feed(&g_m, in, n);
    r_clear(&g_r);
    h2m_hold(&g_m, 1);
    h2m_consumed(&g_m, a, NULL, 8192, 0);
    h2m_consumed(&g_m, b, NULL, 8192, 1);
    check("hold withheld: nothing written while held", 0, (long)g_r.sent_n);
    h2m_hold(&g_m, 0);
    check_str("hold withheld: release one unit", "26:5 ", g_r.calls);
    check_sent("hold withheld: WU(0, 16384) then WU(3, 8192)", 16384, 3, 8192);
    check("hold withheld: A still withholds 8192", 8192, (long)g_m.st[a].in.wh);
    r_clear(&g_r);
    check("hold withheld: the budget's flush leaves nothing", 0, (long)h2m_stream_flush(&g_m, a, NULL));
    check_sent("hold withheld: then WU(1, 8192) alone", 0, 1, 8192);
    feed(&g_m, in, fr(in, 8192, 0x00, 0, 1, NULL));
    r_clear(&g_r);
    h2m_consumed(&g_m, a, NULL, 4096, 0);
    check_sent("hold withheld: a withheld read sends WU(0, 4096) alone", 4096, 0, 0);
    r_clear(&g_r);
    h2m_consumed(&g_m, a, NULL, 4096, 1);
    check_sent("hold withheld: a giving read returns both, WU(1, 8192)", 4096, 1, 8192);
    check("hold withheld: nothing left withheld", 0, (long)g_m.st[a].in.wh);
    h2m_free(&g_m);
}

static void t_padding_refund(void) {
    static unsigned char in[9 + 4000];
    unsigned char body[1000];
    memset(body, 'p', sizeof body);
    body[0] = 99;
    /* catches: padding never refunded, or refunded to the connection only */
    start(&g_m, &g_r);
    uint16_t a = open1(&g_m, &REQ_GET);
    r_clear(&g_r);
    check("pad refund: padded DATA", 0, feed(&g_m, in, fr(in, 1000, 0x00, 0x08, 1, body)));
    check_str("pad refund: 900 delivered", "D0:900 ", g_r.log);
    check("pad refund: 100 refunded below the threshold", 0, (long)g_r.sent_n);
    check("pad refund: DATA 4000", 0, feed(&g_m, in, fr(in, 4000, 0x00, 0, 1, NULL)));
    check("pad refund: still nothing", 0, (long)g_r.sent_n);
    h2m_consumed(&g_m, a, NULL, 4000, 1);
    check_sent("pad refund: WU(0, 4100) then WU(1, 4100)", 4100, 1, 4100);
    check("pad refund: connection window less the 900 unread", 1073807359 - 900,
          (long)g_m.in_conn.avail + g_m.in_conn.unsent);
    check("pad refund: stream window less the 900 unread", 4194304 - 900,
          (long)g_m.st[a].in.avail + g_m.st[a].in.unsent);
    h2m_free(&g_m);
}

static void t_padding_credited(void) {
    static unsigned char in[2 * (9 + 16384)];
    static unsigned char body[16384];
    /* catches: padding never credited back, so the windows shrink by every padded frame */
    memset(body, 'p', sizeof body);
    body[0] = 255;
    start(&g_m, &g_r);
    open1(&g_m, &REQ_POST);
    r_clear(&g_r);
    size_t n = fr(in, 16384, 0x00, 0x08, 1, body);
    n += fr(in + n, 16384, 0x00, 0x08, 1, body);
    check("padding: feed", 0, feed(&g_m, in, n));
    check_str("padding: only content delivered", "D0:32256 ", g_r.log);
    check("padding: 512 refunded below the threshold", 0, (long)g_r.sent_n);
    h2m_consumed(&g_m, 0, NULL, 32256, 1);
    check_sent("padding: WU(0, 32768) then WU(1, 32768)", 32768, 1, 32768);
    h2m_free(&g_m);
}

static void t_padding_refund_cadence(void) {
    static unsigned char in[256 * (9 + 256)];
    unsigned char body[256], want[16 * 26];
    memset(body, 0, sizeof body);
    body[0] = 255;
    /* catches: padding held until a read, or refunded per frame below the threshold */
    start(&g_m, &g_r);
    open1(&g_m, &REQ_GET);
    r_clear(&g_r);
    size_t n = 0;
    for (int i = 0; i < 256; i++) n += fr(in + n, 256, 0x00, 0x08, 1, body);
    check("pad cadence: 256 padded frames fed", 0, feed(&g_m, in, n));
    size_t w = 0;
    for (int i = 0; i < 16; i++) w += wu_pair(want + w, 4096, 1, 4096);
    check("pad cadence: a pair per 4096 B of padding", (long)w, (long)g_r.sent_n);
    check_mem("pad cadence: 16 pairs of 4096", want, g_r.sent, w);
    check("pad cadence: 16 units", 16, (long)g_r.outs);
    h2m_free(&g_m);
}

static unsigned char g_big[4 * (9 + 1048576) + 64];

static size_t overrun_bytes(void) {
    size_t n = 0;
    for (int i = 0; i < 4; i++) n += fr(g_big + n, 1048576, 0x00, 0, 1, NULL);
    n += fr(g_big + n, 1, 0x00, 0, 1, NULL);
    n += fr(g_big + n, 2, 0x00, 0, 3, "bb");
    return n;
}

static void t_recv_overrun(void) {
    static const unsigned char rst[13] = { 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
                                           0x00, 0x00, 0x00, 0x03 };
    /* catches: one stream's overrun ending the connection, or a 1 MiB stream window */
    size_t n = overrun_bytes();
    setup_two(&g_m, &g_r);
    r_clear(&g_r);
    check("overrun: feed goes on", 0, feed(&g_m, g_big, n));
    check_str("overrun: A ends with H2_EFLOW, B still served", "D0:4194304 E0:-61 D1:2 ", g_r.log);
    check("overrun: only the RST_STREAM sent", 13, (long)g_r.sent_n);
    check_mem("overrun: RST_STREAM(1, FLOW_CONTROL_ERROR)", rst, g_r.sent, 13);
    check("overrun: A's window was spent", 0, (long)g_r.end_in.avail);
    check("overrun: A no longer open", 1, h2m_open_n(&g_m));
    h2m_free(&g_m);
    check_splits("overrun: every split gives the same", setup_two, g_big, n);
}

static unsigned char g_mib[1048576];

static int fill_conn(void) {
    unsigned char in[64];
    start(&g_m, &g_r);
    int rc = feed(&g_m, in, fr_setting(in, 0x03, 256));
    for (int i = 0; i < 256; i++) open1(&g_m, &REQ_GET);
    r_clear(&g_r);
    for (uint32_t sid = 1; sid < 512 && !rc; sid += 2)
        for (int j = 0; j < 4 && !rc; j++) {
            rc = feed(&g_m, in, data_hdr(in, 1048576, sid));
            if (!rc) rc = feed(&g_m, g_mib, sizeof g_mib);
        }
    return rc;
}

static void t_conn_overrun(void) {
    unsigned char in[16];
    /* catches: the connection window never checked, or not 1<<30 + 65535 */
    check("connection overrun: 256 streams of 4 MiB fit", 0, fill_conn());
    check("connection overrun: 256 open", 256, h2m_open_n(&g_m));
    check("connection overrun: 65535 left", 65535, (long)g_m.in_conn.avail);
    check("connection overrun: 65536 more", H2_EFLOW, feed(&g_m, in, data_hdr(in, 65536, 1)));
    check("connection overrun: no new stream after", H2_EFLOW, h2m_open(&g_m, &REQ_POST, &(uint16_t){0}));
    h2m_free(&g_m);
    check("connection overrun: again", 0, fill_conn());
    r_clear(&g_r);
    check("connection overrun: 65535 header", 0, feed(&g_m, in, data_hdr(in, 65535, 1)));
    check("connection overrun: 65535 body", 0, feed(&g_m, g_mib, 65535));
    check_str("connection overrun: the stream's window, not the connection's", "E0:-61 ", g_r.log);
    check("connection overrun: RST_STREAM then the refund", 26, (long)g_r.sent_n);
    size_t at;
    check("connection overrun: WINDOW_UPDATE(0)", 1, find_frame(&g_r, 0x08, 0, &at));
    check("connection overrun: refund 65535", 65535, at + 13 <= g_r.sent_n ? (long)get32(g_r.sent + at + 9) : -1);
    h2m_free(&g_m);
}

static void t_arrival_credit(void) {
    static unsigned char in[2 * (9 + 16384)];
    unsigned char h[9];
    /* catches: Go's inflow.add on DATA arrival missing, so a nearly spent window waits for the next read */
    start(&g_m, &g_r);
    uint16_t a = open1(&g_m, &REQ_GET);
    size_t n = fr(in, 16384, 0x00, 0, 1, NULL);
    n += fr(in + n, 3616, 0x00, 0, 1, NULL);
    feed(&g_m, in, n);
    h2m_consumed(&g_m, a, NULL, 8192, 1);
    h2m_consumed(&g_m, a, NULL, 8192, 1);
    h2m_consumed(&g_m, a, NULL, 3616, 1);
    check("arrival: 3616 unsent", 3616, (long)g_m.st[a].in.unsent);
    check("arrival: stream avail 4190688", 4190688, (long)g_m.st[a].in.avail);
    r_clear(&g_r);
    for (int i = 0; i < 3; i++) {
        feed(&g_m, h, data_hdr(h, 1048576, 1));
        feed(&g_m, g_mib, 1048576);
    }
    feed(&g_m, h, data_hdr(h, 1041343, 1));
    feed(&g_m, g_mib, 1041343);
    check("arrival: avail 3617 above unsent, nothing", 0, (long)g_r.sent_n);
    check("arrival: one more byte", 0, feed(&g_m, in, fr(in, 1, 0x00, 0, 1, NULL)));
    check_str("arrival: one unit", "13:5 ", g_r.calls);
    check_sent("arrival: WU(1, 3616) alone on the frame", 0, 1, 3616);
    check("arrival: stream avail 7232", 7232, (long)g_m.st[a].in.avail);
    check("arrival: connection keeps its 3616", 3616, (long)g_m.in_conn.unsent);
    h2m_free(&g_m);

    start(&g_m, &g_r);
    open1(&g_m, &REQ_GET);
    g_m.in_conn.avail = 5000;
    g_m.in_conn.unsent = 3000;
    r_clear(&g_r);
    check("arrival conn: DATA 2000", 0, feed(&g_m, in, fr(in, 2000, 0x00, 0, 1, NULL)));
    check_sent("arrival conn: WU(0, 3000) alone", 3000, 1, 0);
    h2m_free(&g_m);
}

static void t_hold_release(void) {
    static unsigned char in[3 * (9 + 8192)];
    unsigned char want[3 * 26];
    /* catches: credit written while held, or held credit lost at release */
    start(&g_m, &g_r);
    uint16_t a = open1(&g_m, &REQ_GET), b = open1(&g_m, &REQ_GET);
    size_t n = fr(in, 8192, 0x00, 0, 1, NULL);
    n += fr(in + n, 8192, 0x00, 0, 3, NULL);
    n += fr(in + n, 5000, 0x00, 0, 9, NULL);
    r_clear(&g_r);
    h2m_hold(&g_m, 1);
    check("hold: feed", 0, feed(&g_m, in, n));
    h2m_consumed(&g_m, a, NULL, 8192, 1);
    h2m_consumed(&g_m, b, NULL, 8192, 1);
    check("hold: flush while held", 8192, (long)h2m_stream_flush(&g_m, a, NULL));
    check("hold: nothing written", 0, (long)g_r.sent_n);
    h2m_hold(&g_m, 0);
    size_t w = wu_pair(want, 21384, 1, 8192);
    w += wu_pair(want + w, 0, 3, 8192);
    check("hold: released as connection with A, then B", (long)w, (long)g_r.sent_n);
    check_mem("hold: WU(0, 21384) WU(1, 8192), WU(3, 8192)", want, g_r.sent, w);
    check_str("hold: two units", "26:5 13:5 ", g_r.calls);
    r_clear(&g_r);
    h2m_consumed(&g_m, a, NULL, 8192, 1);
    check_sent("hold: after release, a read pays at once", 8192, 1, 8192);
    h2m_free(&g_m);
}

static void t_conn_refund(void) {
    static unsigned char in[9 + 5000];
    /* catches: a refund sent with the stream's credit, or lost below 4096 */
    start(&g_m, &g_r);
    uint16_t a = open1(&g_m, &REQ_GET);
    r_clear(&g_r);
    h2m_conn_refund(&g_m, 70000);
    check_str("conn refund: one unit", "13:5 ", g_r.calls);
    check_sent("conn refund: WU(0, 70000) alone", 70000, 1, 0);
    r_clear(&g_r);
    h2m_conn_refund(&g_m, 100);
    check("conn refund: 100 kept", 0, (long)g_r.sent_n);
    check("conn refund: DATA 5000 on A", 0, feed(&g_m, in, fr(in, 5000, 0x00, 0, 1, NULL)));
    check("conn refund: nothing on arrival", 0, (long)g_r.sent_n);
    h2m_consumed(&g_m, a, NULL, 5000, 1);
    check_str("conn refund: the read one unit", "26:5 ", g_r.calls);
    check_sent("conn refund: WU(0, 5100) then WU(1, 5000)", 5100, 1, 5000);
    r_clear(&g_r);
    h2m_conn_refund(&g_m, 2000);
    feed(&g_m, in, fr(in, 3000, 0x00, 0, 1, NULL));
    h2m_consumed(&g_m, a, NULL, 3000, 1);
    check_str("conn refund: below 4096 on the stream, one unit", "13:5 ", g_r.calls);
    check_sent("conn refund: WU(0, 5000) and no stream WU", 5000, 1, 0);
    check("conn refund: the stream keeps 3000", 3000, (long)g_m.st[a].in.unsent);
    r_clear(&g_r);
    h2m_hold(&g_m, 1);
    h2m_conn_refund(&g_m, 70000);
    check("conn refund: nothing written while held", 0, (long)g_r.sent_n);
    h2m_hold(&g_m, 0);
    check_str("conn refund: released in one unit", "13:5 ", g_r.calls);
    check_sent("conn refund: WU(0, 70000) at release", 70000, 1, 0);
    h2m_free(&g_m);
}

static void t_reset_inside_data(void) {
    static unsigned char in[2 * (9 + 16384)];
    unsigned char want[39];
    size_t w = fr_u32(want, 0x03, 1, 8);
    w += fr_u32(want + w, 0x08, 0, 16383);
    w += fr_u32(want + w, 0x08, 0, 16384);
    /* catches: the rest of a frame whose stream we reset mid-frame never credited to the connection */
    start(&g_m, &g_r);
    open1(&g_m, &REQ_POST);
    g_r.reset_on_data = 1;
    size_t n = fr(in, 16384, 0x00, 0, 1, NULL);
    n += fr(in + n, 16384, 0x00, 0, 9, NULL);
    r_clear(&g_r);
    check("reset inside data: first byte", 0, feed(&g_m, in, 10));
    check_str("reset inside data: one byte delivered", "D0:1 ", g_r.log);
    check("reset inside data: the rest", 0, feed(&g_m, in + 10, n - 10));
    check_str("reset inside data: nothing more delivered", "D0:1 ", g_r.log);
    check("reset inside data: RST, then each frame's rest refunded", (long)w, (long)g_r.sent_n);
    check_mem("reset inside data: RST(1), WU(0, 16383), WU(0, 16384)", want, g_r.sent, w);
    h2m_free(&g_m);
}

static void t_ended_stream_refund(void) {
    static unsigned char d[9 + 2000];
    /* catches: dropped DATA eating the window, or a stream WU for a reset stream */
    start(&g_m, &g_r);
    uint16_t a = open1(&g_m, &REQ_GET);
    h2m_reset(&g_m, a, 8);
    r_clear(&g_r);
    size_t n = fr(d, 2000, 0x00, 0, 1, NULL);
    feed(&g_m, d, n);
    feed(&g_m, d, n);
    check("ended refund: 4000 kept", 0, (long)g_r.sent_n);
    check("ended refund: third DATA", 0, feed(&g_m, d, n));
    check_sent("ended refund: WU(0, 6000) alone", 6000, 1, 0);
    check_str("ended refund: no callback", "", g_r.log);
    h2m_free(&g_m);
}

static void t_credit_after_end(void) {
    static unsigned char in[2 * (9 + 16384) + 64];
    unsigned char s200 = 0x88;
    /* catches: bytes read after END_STREAM returning connection credit only, unlike Go */
    start(&g_m, &g_r);
    open1(&g_m, &REQ_GET);
    r_clear(&g_r);
    size_t n = fr(in, 1, 0x01, 0x04, 1, &s200);
    n += fr(in + n, 16384, 0x00, 0, 1, NULL);
    n += fr(in + n, 3616, 0x00, 0, 1, NULL);
    n += fr(in + n, 1, 0x01, 0x05, 1, &s200);
    check("after end: feed", 0, feed(&g_m, in, n));
    check_str("after end: answered, 20000, ended", "S0:200 D0:20000 E0:0 ", g_r.log);
    check("after end: nothing sent", 0, (long)g_r.sent_n);
    struct h2m_in f = g_r.end_in;
    check("after end: inflow sid 1", 1, (long)f.sid);
    check("after end: inflow avail 4174304", 4174304, (long)f.avail);
    check("after end: inflow unsent 0", 0, (long)f.unsent);
    h2m_consumed(&g_m, UINT16_MAX, &f, 8192, 1);
    check_sent("after end: WU(0, 8192) then WU(1, 8192)", 8192, 1, 8192);
    check("after end: the ended inflow moved", 4182496, (long)f.avail);
    r_clear(&g_r);
    h2m_consumed(&g_m, UINT16_MAX, NULL, 8192, 1);
    check_sent("after end: no inflow, the connection's alone", 8192, 1, 0);
    h2m_free(&g_m);
}

static unsigned char g_closed[8 * 1009 + 64];

static size_t closed_bytes(uint32_t sid) {
    size_t n = 0;
    for (int i = 0; i < 5; i++) n += fr(g_closed + n, 1000, 0x00, 0, sid, NULL);
    n += fr_u32(g_closed + n, 0x08, sid, 100);
    n += fr_u32(g_closed + n, 0x03, sid, 2);
    return n;
}

static void setup_closed(struct h2m *m, struct rec *r) {
    unsigned char in[16];
    start(m, r);
    open1(m, &REQ_POST);
    size_t n = fr_u32(in, 0x03, 1, 8);
    feed(m, in, n);
}

static void t_closed_sid_frames(void) {
    unsigned char in[16];
    /* catches: frames of a closed stream eating the window or killing the connection */
    start(&g_m, &g_r);
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
    for (int i = 0; i < 4; i++) feed(&g_m, d, n);
    check("closed: 4000 dropped, below the threshold", 0, (long)g_r.sent_n);
    check("closed: 5th DATA", 0, feed(&g_m, d, n));
    check_sent("closed: WU(0, 5000)", 5000, 1, 0);
    check_str("closed: no data delivered", "", g_r.log);
    r_clear(&g_r);
    n = fr_u32(in, 0x08, 1, 100);
    check("closed: WINDOW_UPDATE(1, 100)", 0, feed(&g_m, in, n));
    n = fr_u32(in, 0x03, 1, 2);
    check("closed: RST_STREAM(1, 2)", 0, feed(&g_m, in, n));
    check_str("closed: no callback", "", g_r.log);
    check("closed: no frame", 0, (long)g_r.sent_n);
    check("closed: connection room untouched", 65535, h2m_conn_room(&g_m));
    check("closed: the connection still opens streams", 0, h2m_open(&g_m, &REQ_POST, &(uint16_t){0}));
    h2m_free(&g_m);

    start(&g_m, &g_r);
    open1(&g_m, &REQ_POST);
    r_clear(&g_r);
    n = closed_bytes(9);
    check("never opened 9: feed", 0, feed(&g_m, g_closed, n));
    check_str("never opened 9: no callback", "", g_r.log);
    check_sent("never opened 9: WU(0, 5000) alone", 5000, 1, 0);
    check("never opened 9: A untouched", 1, h2m_open_n(&g_m));
    check("never opened 9: A's room untouched", 65535, h2m_room(&g_m, 0));
    check("never opened 9: A's inflow untouched", 4194304, (long)g_m.st[0].in.avail);
    check("never opened 9: connection room untouched", 65535, h2m_conn_room(&g_m));
    h2m_free(&g_m);
    check_splits("closed: every split gives the same", setup_closed, g_closed, closed_bytes(1));
}

static void setup_one_get(struct h2m *m, struct rec *r) {
    start(m, r);
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
    start(m, r);
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
    start(m, r);
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
    check("goaway: no new stream", H2_ERESET, h2m_open(&g_m, &REQ_POST, &(uint16_t){0}));
    check("goaway: 1 still sends", 0, h2m_send(&g_m, 0, (const unsigned char *)"z", 1, 0));
    h2m_free(&g_m);
    check_splits("goaway: every split gives the same", setup_three, in, n);
}

static const unsigned char PING_OP2[8] = { 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };

static void setup_pinged(struct h2m *m, struct rec *r) {
    start(m, r);
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
    start(&g_m, &g_r);
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
    start(&g_m, &g_r);
    check("cap: 100 before SETTINGS", 100, (long)h2m_cap(&g_m));
    int ok = 1;
    for (int i = 0; i < 100; i++) ok &= h2m_open(&g_m, &REQ_POST, &slot) == 0 && slot == i;
    check("cap: 100 streams in slots 0..99", 1, ok);
    check("cap: the 101st refused", H2_EFULL, h2m_open(&g_m, &REQ_POST, &slot));
    r_clear(&g_r);
    size_t n = fr(in, 1, 0x00, 0, 1, "a");
    n += fr(in + n, 1, 0x00, 0, 199, "z");
    feed(&g_m, in, n);
    check_str("cap: slots stable over growth", "D0:1 D99:1 ", g_r.log);
    n = fr_setting(in, 0x03, 1000);
    feed(&g_m, in, n);
    check("cap: at most 256", 256, (long)h2m_cap(&g_m));
    h2m_free(&g_m);

    start(&g_m, &g_r);
    n = fr_setting(in, 0x03, 2);
    feed(&g_m, in, n);
    check("cap: the server's 2", 2, (long)h2m_cap(&g_m));
    uint16_t a = open1(&g_m, &REQ_GET), b = open1(&g_m, &REQ_GET);
    check("cap: two opened", 1, a == 0 && b == 1);
    check("cap: third refused", H2_EFULL, h2m_open(&g_m, &REQ_GET, &slot));
    check("cap: two open", 2, h2m_open_n(&g_m));
    r_clear(&g_r);
    n = fr(in, 1, 0x01, 0x05, 1, &s200);
    feed(&g_m, in, n);
    check_str("cap: A answered and ended", "S0:200 E0:0 ", g_r.log);
    check("cap: open after the end", 0, h2m_open(&g_m, &REQ_GET, &slot));
    check("cap: the freed slot reused", 0, slot);
    size_t at;
    check("cap: on stream 5", 1, find_frame(&g_r, 0x01, 5, &at));
    h2m_free(&g_m);

    start(&g_m, &g_r);
    n = fr(in, 0, 0x04, 0, 0, NULL);
    feed(&g_m, in, n);
    check("cap: SETTINGS without the limit, 256", 256, (long)h2m_cap(&g_m));
    h2m_free(&g_m);
}

static void t_budget_follows_peer_settings(void) {
    static unsigned char in[64];
    /* catches: the header budget not following the server's MAX_HEADER_LIST_SIZE */
    start(&g_m, &g_r);
    check("budget before the peer's SETTINGS", 8192, (long)h2m_header_budget(&g_m, 0));
    feed(&g_m, in, fr_setting(in, 0x06, 9000));
    check("budget after MAX_HEADER_LIST_SIZE 9000", 9000, (long)h2m_header_budget(&g_m, 0));
    h2m_free(&g_m);
    start(&g_m, &g_r);
    feed(&g_m, in, fr_setting(in, 0x04, 70000));
    check("budget after a SETTINGS without 0x06", 16384, (long)h2m_header_budget(&g_m, 0));
    h2m_free(&g_m);
}

static void t_budget_before_settings_follows_the_server_limit(void) {
    static unsigned char in[64];
    start(&g_m, &g_r);
    /* catches: a server limit below 8192 ignored before SETTINGS, or one above 8192 taken */
    check("server limit 4096: budget before SETTINGS", 4096, (long)h2m_header_budget(&g_m, 4096));
    check("server limit 8191: budget before SETTINGS", 8191, (long)h2m_header_budget(&g_m, 8191));
    check("server limit 16384: budget before SETTINGS stays 8192", 8192, (long)h2m_header_budget(&g_m, 16384));
    feed(&g_m, in, fr_setting(in, 0x06, 9000));
    /* catches: the server limit capping the budget after the announced one */
    check("server limit 4096: budget after 0x06 9000", 9000, (long)h2m_header_budget(&g_m, 4096));
    check("server limit 16384: budget after 0x06 9000", 9000, (long)h2m_header_budget(&g_m, 16384));
    h2m_free(&g_m);
    start(&g_m, &g_r);
    feed(&g_m, in, fr_setting(in, 0x04, 70000));
    check("server limit 4096: budget after a SETTINGS without 0x06", 16384, (long)h2m_header_budget(&g_m, 4096));
    h2m_free(&g_m);
}

static void t_budget_reset_by_a_later_settings(void) {
    static unsigned char in[64];
    start(&g_m, &g_r);
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
    check("ours: RST_STREAM then the first cancel's PING", 30, (long)g_r.sent_n);
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
    start(&g_m, &g_r);
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

static void t_units(void) {
    static unsigned char in[64], buf[20000];
    unsigned char op[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    memset(buf, 'u', sizeof buf);
    /* catches: frames of one pass flushed as one record, or DATA split from its unit */
    start(&g_m, &g_r);
    check_str("units: preface one call, 70 B, END", "70:4 ", g_r.calls);
    r_clear(&g_r);
    check("units: peer SETTINGS", 0, feed(&g_m, in, fr(in, 0, 0x04, 0, 0, NULL)));
    check_str("units: SETTINGS ACK one call, 9 B, CTL|END", "9:5 ", g_r.calls);
    r_clear(&g_r);
    check("units: peer PING", 0, feed(&g_m, in, fr(in, 8, 0x06, 0, 0, op)));
    check_str("units: PING ACK one call, 17 B, CTL|END", "17:5 ", g_r.calls);
    r_clear(&g_r);
    uint16_t g = open1(&g_m, &REQ_GET);
    size_t hn = 9 + (((size_t)g_r.sent[0] << 16) | ((size_t)g_r.sent[1] << 8) | g_r.sent[2]);
    check("units: GET HEADERS frame", 0x01, g_r.sent[3]);
    check("units: GET HEADERS all of what was sent", (long)hn, (long)g_r.sent_n);
    size_t len = strlen(g_r.calls);
    check("units: GET HEADERS ends in END only", 1, len >= 3 && strcmp(g_r.calls + len - 3, ":4 ") == 0);
    long zeros = 0, calls = 0;
    for (const char *c = g_r.calls; (c = strchr(c, ':')); c++) {
        calls++;
        if (c[1] == '0') zeros++;
    }
    check("units: GET HEADERS earlier pieces carry no flag", calls - 1, zeros);
    r_clear(&g_r);
    uint16_t a = open1(&g_m, &REQ_POST);
    r_clear(&g_r);
    check("units: 100 B sent", 0, h2m_send(&g_m, a, buf, 100, 0));
    check_str("units: 100 B as header then payload", "9:0 100:6 ", g_r.calls);
    r_clear(&g_r);
    check("units: 20,000 B sent", 0, h2m_send(&g_m, a, buf, 20000, 0));
    check_str("units: 20,000 B as two units", "9:0 16384:6 9:0 3616:6 ", g_r.calls);
    r_clear(&g_r);
    check("units: empty end sent", 0, h2m_send(&g_m, a, NULL, 0, 1));
    check_str("units: empty END_STREAM DATA one piece END", "9:4 ", g_r.calls);
    r_clear(&g_r);
    check("units: reset", 0, h2m_reset(&g_m, g, 8));
    check_str("units: RST_STREAM then PING, one unit", "13:1 17:5 ", g_r.calls);
    r_clear(&g_r);
    check("units: ping", 0, h2m_ping(&g_m, op));
    check_str("units: PING one call, 17 B, CTL|END", "17:5 ", g_r.calls);
    h2m_free(&g_m);
}

static size_t hex_in(const char *h, unsigned char *out) {
    size_t n = 0;
    unsigned v;
    for (; *h; h++) {
        if (*h == ' ') continue;
        sscanf(h, "%2x", &v);
        out[n++] = (unsigned char)v;
        h++;
    }
    return n;
}

static unsigned char g_blk_out[1 << 16];

static size_t sent_block(const struct rec *r) {
    size_t p = 0, n = 0;
    while (p + 9 <= r->sent_n) {
        uint32_t len = ((uint32_t)r->sent[p] << 16) | ((uint32_t)r->sent[p + 1] << 8) | r->sent[p + 2];
        if (r->sent[p + 3] == 0x01 || r->sent[p + 3] == 0x09) {
            memcpy(g_blk_out + n, r->sent + p + 9, len);
            n += len;
        }
        p += 9 + len;
    }
    return n;
}

static void check_block(const char *what, const char *hex) {
    static unsigned char want[256];
    size_t n = hex_in(hex, want), got = sent_block(&g_r);
    check(what, (long)n, (long)got);
    if (n == got) check_mem(what, want, g_blk_out, n);
}

static const struct h2_req G1 = { .authority = "a.example", .path = "/xp/1", .method = "GET",
                                  .end_stream = 1, .look = H2L_NONE };
static const struct h2_req G2 = { .authority = "a.example", .path = "/xp/2", .method = "GET",
                                  .end_stream = 1, .look = H2L_NONE };
#define G1_BLOCK "41 87 1a e5 f2 3a 6b a0 bf 82 45 84 63 cd 6c 07 87 50 83 9b d9 ab " \
    "7a 8d c4 75 a7 4a 6b 58 94 18 b5 25 81 2e 0f"
#define G2_BLOCK "c1 82 45 84 63 cd 6c 0b 87 c0 bf"

static void t_go_blocks(void) {
    static unsigned char in[64];
    struct h2_req put = G2;
    put.method = "PUT";
    /* catches: pseudo order m,s,p,a, no indexing, no size update after SETTINGS, or content-length missing */
    start(&g_m, &g_r);
    r_clear(&g_r);
    open1(&g_m, &G1);
    check_block("go blocks: first GET", G1_BLOCK);
    check("go blocks: first GET END_STREAM|END_HEADERS", 0x05, g_r.sent[4]);
    check("go blocks: SETTINGS 0x1 4096", 0, feed(&g_m, in, fr_setting(in, 0x01, 4096)));
    r_clear(&g_r);
    open1(&g_m, &G2);
    check_block("go blocks: second GET after the update", "3f e1 1f " G2_BLOCK);
    r_clear(&g_r);
    open1(&g_m, &put);
    check_block("go blocks: PUT with content-length 0", "c2 43 03 50 55 54 bf 87 5c 01 30 c2 c1");
    check("go blocks: PUT END_STREAM|END_HEADERS", 0x05, g_r.sent[4]);
    h2m_free(&g_m);
}

static void t_size_update_from_settings(void) {
    static unsigned char in[64];
    /* catches: two SETTINGS folded into the max only */
    start(&g_m, &g_r);
    open1(&g_m, &G1);
    size_t n = fr_setting(in, 0x01, 0);
    n += fr_setting(in + n, 0x01, 4096);
    check("size update: two SETTINGS", 0, feed(&g_m, in, n));
    r_clear(&g_r);
    open1(&g_m, &G1);
    check_block("size update: min then max, then the first block again", "20 3f e1 1f " G1_BLOCK);
    h2m_free(&g_m);
}

static char g_huge[40001];

static void t_continuation_one_block(void) {
    static unsigned char in[64];
    static struct hr_ctx hc;
    static struct hr_block hb;
    memset(g_huge, 'X', 20000);
    g_huge[20000] = '\0';
    const struct h2_field f = { "x-big", g_huge };
    struct h2_req r = G1;
    r.fields = &f;
    r.fields_n = 1;
    /* catches: H2_ETOOBIG instead of CONTINUATION, or a CONTINUATION unit of its own */
    start(&g_m, &g_r);
    hr_ctx_init(&hc, 4096);
    r_clear(&g_r);
    check("continuation: opened", 0, h2m_open(&g_m, &r, &(uint16_t){0}));
    check_str("continuation: one unit, END on the last piece", "9:0 16384:0 9:0 3663:4 ", g_r.calls);
    check("continuation: HEADERS 16384", 16384, (long)h2w_frame_len(g_r.sent));
    check("continuation: HEADERS END_STREAM without END_HEADERS", 0x01, g_r.sent[4]);
    check("continuation: then CONTINUATION", 0x09, g_r.sent[9 + 16384 + 3]);
    check("continuation: END_HEADERS", 0x04, g_r.sent[9 + 16384 + 4]);
    check("continuation: same stream", 1, (long)get32(g_r.sent + 9 + 16384 + 5));
    size_t bn = sent_block(&g_r);
    check("continuation: joined block decodes", 0, hr_decode_ctx(&hc, g_blk_out, bn, &hb));
    check("continuation: seven fields", 7, (long)hb.n);
    check_str("continuation: :path", "/xp/1", hb.n == 7 ? hb.f[2].value : "");
    check_str("continuation: x-big", "x-big", hb.n == 7 ? hb.f[4].name : "");
    check("continuation: x-big value", 1, hb.n == 7 && strcmp(hb.f[4].value, g_huge) == 0);
    check_str("continuation: accept-encoding sixth", "gzip", hb.n == 7 ? hb.f[5].value : "");
    check_str("continuation: Go's user-agent last", "Go-http-client/2.0", hb.n == 7 ? hb.f[6].value : "");
    check("continuation: SETTINGS 0x5 1048576", 0, feed(&g_m, in, fr_setting(in, 0x05, 1048576)));
    r_clear(&g_r);
    check("continuation: reopened", 0, h2m_open(&g_m, &r, &(uint16_t){0}));
    check_str("continuation: one HEADERS at the larger frame size", "9:0 20016:4 ", g_r.calls);
    check("continuation: END_STREAM|END_HEADERS", 0x05, g_r.sent[4]);
    bn = sent_block(&g_r);
    check("continuation: second block decodes on the same table", 0, hr_decode_ctx(&hc, g_blk_out, bn, &hb));
    check("continuation: second x-big value", 1, hb.n == 7 && strcmp(hb.f[4].value, g_huge) == 0);
    h2m_free(&g_m);
}

static void t_refused_open_keeps_table(void) {
    static unsigned char in[64];
    unsigned char s200 = 0x88;
    memset(g_huge, 'X', 40000);
    g_huge[40000] = '\0';
    const struct h2_field f = { "x-big", g_huge };
    struct h2_req big = G1, other = G1;
    big.path = "/xp/9";
    big.fields = &f;
    big.fields_n = 1;
    other.path = "/xp/3";
    /* catches: a refused request that changed the encoder table */
    start(&g_m, &g_r);
    check("refused: SETTINGS 0x3 1", 0, feed(&g_m, in, fr_setting(in, 0x03, 1)));
    r_clear(&g_r);
    open1(&g_m, &G1);
    check_block("refused: first GET", G1_BLOCK);
    r_clear(&g_r);
    check("refused: second open over the cap", H2_EFULL, h2m_open(&g_m, &other, &(uint16_t){0}));
    check("refused: the cap refusal sends nothing", 0, (long)g_r.sent_n);
    check("refused: first stream ends", 0, feed(&g_m, in, fr(in, 1, 0x01, 0x05, 1, &s200)));
    r_clear(&g_r);
    check("refused: 40,000 B field", H2_ETOOBIG, h2m_open(&g_m, &big, &(uint16_t){0}));
    check("refused: the size refusal sends nothing", 0, (long)g_r.sent_n);
    open1(&g_m, &G2);
    check_block("refused: next block on the untouched table", G2_BLOCK);
    h2m_free(&g_m);
}

static void t_bad_max_frame(void) {
    static unsigned char in[64];
    /* catches: a MAX_FRAME_SIZE outside 16384..16777215 taken, or a legal edge refused */
    start(&g_m, &g_r);
    check("max frame 16383: H2_EPROTO", H2_EPROTO, feed(&g_m, in, fr_setting(in, 0x05, 16383)));
    h2m_free(&g_m);
    start(&g_m, &g_r);
    check("max frame 16777216: H2_EPROTO", H2_EPROTO, feed(&g_m, in, fr_setting(in, 0x05, 16777216)));
    h2m_free(&g_m);
    start(&g_m, &g_r);
    check("max frame 16384: taken", 0, feed(&g_m, in, fr_setting(in, 0x05, 16384)));
    check("max frame 16777215: taken", 0, feed(&g_m, in, fr_setting(in, 0x05, 16777215)));
    h2m_free(&g_m);
}

static void t_errors_named(void) {
    /* catches: a new code without its text */
    check("errors: H2_EFULL is -60", -60, H2_EFULL);
    check("errors: H2_EFLOW is -61", -61, H2_EFLOW);
    check("errors: H2_EFULL named", 0, strcmp(h2_strerror(H2_EFULL), "unknown HTTP/2 error") == 0);
    check("errors: H2_EFLOW named", 0, strcmp(h2_strerror(H2_EFLOW), "unknown HTTP/2 error") == 0);
}

struct big {
    struct rec r;
    unsigned char h[9];
    size_t hn, left;
    uint32_t fl[64];
    unsigned char ff[64];
    unsigned nf, units, data_units, torn;
};

static int b_out(void *ctx, const unsigned char *d, size_t n, unsigned flags) {
    struct big *b = ctx;
    for (size_t i = 0; i < n;) {
        if (b->left) {
            size_t k = b->left < n - i ? b->left : n - i;
            b->left -= k;
            i += k;
            continue;
        }
        b->h[b->hn++] = d[i++];
        if (b->hn < 9) continue;
        b->hn = 0;
        b->left = ((size_t)b->h[0] << 16) | ((size_t)b->h[1] << 8) | b->h[2];
        if (b->h[3] == 0x00 && b->nf < 64) {
            b->fl[b->nf] = (uint32_t)b->left;
            b->ff[b->nf++] = b->h[4];
        }
    }
    if (flags & H2M_END) {
        b->units++;
        if (flags & H2M_PAY) b->data_units++;
        if (b->left || b->hn) b->torn++;
    }
    return 0;
}

static struct big g_b;

static void big_start(int mfs) {
    static unsigned char in[64];
    memset(&g_b, 0, sizeof g_b);
    g_b.r.m = &g_m;
    struct h2m_cb cb = { &g_b, b_out, r_data, r_status, r_end, r_goaway, r_ping_ack, r_room };
    h2m_start(&g_m, &cb, 1);
    g_b.hn = g_b.left = g_b.torn = 0;
    unsigned char st[12] = { 0x00, 0x05, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x7f, 0xff, 0xff, 0xff };
    size_t n = mfs ? fr(in, 12, 0x04, 0, 0, st) : fr(in, 6, 0x04, 0, 0, st + 6);
    n += fr_u32(in + n, 0x08, 0, 2147418112u);
    feed(&g_m, in, n);
    g_b.nf = g_b.units = g_b.data_units = 0;
}

static void t_upload_frames(void) {
    static unsigned char buf[700000];
    memset(buf, 'u', sizeof buf);
    /* catches: 16 KiB frames under a 1 MiB server, or frames past Go's 512 KiB scratch */
    big_start(1);
    uint16_t a = open1(&g_m, &REQ_POST);
    g_b.nf = g_b.units = g_b.data_units = 0;
    check("upload frames: 700,000 B sent", 0, h2m_send(&g_m, a, buf, sizeof buf, 0));
    check("upload frames: two DATA frames", 2, (long)g_b.nf);
    check("upload frames: first 524,288", 524288, (long)g_b.fl[0]);
    check("upload frames: then 175,712", 175712, (long)g_b.fl[1]);
    check("upload frames: no END_STREAM", 0, g_b.ff[0] | g_b.ff[1]);
    check("upload frames: two units", 2, (long)g_b.units);
    check("upload frames: each unit ends a frame", 0, (long)g_b.torn);
    h2m_free(&g_m);
    big_start(0);
    a = open1(&g_m, &REQ_POST);
    g_b.nf = g_b.units = g_b.data_units = 0;
    check("upload frames default: 700,000 B sent", 0, h2m_send(&g_m, a, buf, sizeof buf, 1));
    check("upload frames default: 43 DATA frames", 43, (long)g_b.nf);
    long full = 0;
    for (unsigned i = 0; i < 42 && i < g_b.nf; i++) full += g_b.fl[i] == 16384 && !g_b.ff[i];
    check("upload frames default: 42 of 16,384", 42, full);
    check("upload frames default: last 11,872", 11872, g_b.nf == 43 ? (long)g_b.fl[42] : -1);
    check("upload frames default: END_STREAM on the last", 1, g_b.nf == 43 ? (long)g_b.ff[42] : -1);
    check("upload frames default: 43 units", 43, (long)g_b.units);
    check("upload frames default: each unit ends a frame", 0, (long)g_b.torn);
    h2m_free(&g_m);
}

static void t_send_begin_put(void) {
    static unsigned char in[64], buf[40000];
    static const unsigned char hdr[9] = { 0x00, 0x9c, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };
    memset(buf, 'p', sizeof buf);
    /* catches: a frame header per put, END_STREAM or the unit's end before the last byte */
    start(&g_m, &g_r);
    feed(&g_m, in, fr_setting(in, 0x05, 1048576));
    uint16_t a = open1(&g_m, &REQ_POST);
    r_clear(&g_r);
    check("begin put: past the window refused", H2_EWINDOW, h2m_send_begin(&g_m, a, 65536, 1));
    check("begin put: refused sends nothing", 0, (long)g_r.sent_n);
    check("begin put: room kept", 65535, h2m_room(&g_m, a));
    check("begin put: begin 40,000 end", 0, h2m_send_begin(&g_m, a, 40000, 1));
    check("begin put: put 16,384", 0, h2m_send_put(&g_m, buf, 16384));
    check("begin put: put 16,384 again", 0, h2m_send_put(&g_m, buf + 16384, 16384));
    check("begin put: put 7,232", 0, h2m_send_put(&g_m, buf + 32768, 7232));
    check_str("begin put: one header, END on the last put only", "9:0 16384:2 16384:2 7232:6 ", g_r.calls);
    check_mem("begin put: DATA(1) 40,000 END_STREAM", hdr, g_r.sent, 9);
    check("begin put: 40,009 B", 40009, (long)g_r.sent_n);
    check("begin put: windows taken", 25535, h2m_conn_room(&g_m));
    r_clear(&g_r);
    check("begin put: a put past the begin refused", H2_EPROTO, h2m_send_put(&g_m, buf, 1));
    check("begin put: nothing sent past it", 0, (long)g_r.sent_n);
    h2m_free(&g_m);
}

static void t_inbound_frame_size(void) {
    static unsigned char in[9 + 1048576];
    /* catches: frames past Go's 1 MiB read limit taken, or a 1 MiB frame refused */
    start(&g_m, &g_r);
    open1(&g_m, &REQ_GET);
    r_clear(&g_r);
    size_t n = fr(in, 1048576, 0x00, 0, 1, NULL);
    check("frame in: 1,048,576 taken", 0, feed(&g_m, in, n));
    check_str("frame in: all delivered", "D0:1048576 ", g_r.log);
    n = fr(in, 0, 0x00, 0, 1, NULL);
    in[0] = 0x10;
    in[1] = 0x00;
    in[2] = 0x01;
    check("frame in: 1,048,577 refused", H2_EPROTO, feed(&g_m, in, n));
    h2m_free(&g_m);
}

static const struct h2_req NL_GET = { .authority = "a.example", .path = "/c", .method = "GET",
                                      .end_stream = 1, .look = H2L_NONE };
static const struct h2_req NL_POST = { .authority = "a.example", .path = "/c", .method = "POST",
                                       .look = H2L_NONE };

static size_t rst_ping(unsigned char *o, uint32_t sid, const unsigned char op[8]) {
    size_t n = fr_u32(o, 0x03, sid, 8);
    return n + fr(o + n, 8, 0x06, 0, 0, op);
}

static void reset_is(const char *what, uint16_t slot, uint32_t sid, const unsigned char *op) {
    unsigned char want[30];
    size_t n = op ? rst_ping(want, sid, op) : fr_u32(want, 0x03, sid, 8);
    char w[64];
    r_clear(&g_r);
    check(what, 0, h2m_reset(&g_m, slot, 8));
    check_str(what, op ? "13:1 17:5 " : "13:5 ", g_r.calls);
    check(what, (long)n, (long)g_r.sent_n);
    if (n == g_r.sent_n) check_mem(what, want, g_r.sent, n);
    snprintf(w, sizeof w, "%s: log", what);
    check_str(w, "", g_r.log);
}

static void t_cancel_ping(void) {
    static unsigned char in[64];
    static const unsigned char op1[8] = { 0x91, 0x0a, 0x2d, 0xec, 0x89, 0x02, 0x5c, 0xc1 };
    static const unsigned char op2[8] = { 0xbe, 0xeb, 0x8d, 0xa1, 0x65, 0x8e, 0xec, 0x67 };
    static const unsigned char op3[8] = { 0xf8, 0x93, 0xa2, 0xee, 0xfb, 0x32, 0x55, 0x5e };
    unsigned char ka[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, s200 = 0x88, one = 'x';
    /* catches: a PING with every reset, none at all, Go's suppressions missing, or a host-order opaque */
    start(&g_m, &g_r);
    uint16_t l = open1(&g_m, &NL_GET);
    check("cancel ping: keepalive", 0, h2m_ping(&g_m, ka));
    r_clear(&g_r);
    check("cancel ping: keepalive ACK", 0, feed(&g_m, in, fr(in, 8, 0x06, 0x01, 0, ka)));
    check_str("cancel ping: keepalive acked", "P ", g_r.log);
    reset_is("cancel ping: A RST + PING", open1(&g_m, &NL_GET), 3, op1);
    reset_is("cancel ping: B RST only, pending", open1(&g_m, &NL_GET), 5, NULL);
    r_clear(&g_r);
    check("cancel ping: peer ACK", 0, feed(&g_m, in, fr(in, 8, 0x06, 0x01, 0, op1)));
    check_str("cancel ping: not the keepalive's", "", g_r.log);
    check("cancel ping: an ACK sends nothing", 0, (long)g_r.sent_n);
    reset_is("cancel ping: C RST only, blocked", open1(&g_m, &NL_GET), 7, NULL);
    check("cancel ping: DATA on L", 0, feed(&g_m, in, fr(in, 1, 0x00, 0, g_m.st[l].sid, &one)));
    uint16_t d = open1(&g_m, &NL_GET);
    check("cancel ping: HEADERS on D", 0, feed(&g_m, in, fr(in, 1, 0x01, 0x04, 9, &s200)));
    reset_is("cancel ping: D RST only, read since D", d, 9, NULL);
    reset_is("cancel ping: E RST + PING", open1(&g_m, &NL_GET), 11, op2);
    check("cancel ping: ACK of E's", 0, feed(&g_m, in, fr(in, 8, 0x06, 0x01, 0, op2)));
    check("cancel ping: DATA on L again", 0, feed(&g_m, in, fr(in, 1, 0x00, 0, 1, &one)));
    reset_is("cancel ping: F RST + PING, DATA lifted the block", open1(&g_m, &NL_GET), 13, op3);
    check("cancel ping: ACK of F's", 0, feed(&g_m, in, fr(in, 8, 0x06, 0x01, 0, op3)));
    check("cancel ping: DATA on L once more", 0, feed(&g_m, in, fr(in, 1, 0x00, 0, 1, &one)));
    uint16_t f = open1(&g_m, &NL_GET);
    unsigned char ga[8] = { 0, 0, 0, 99, 0, 0, 0, 0 };
    check("cancel ping: GOAWAY 99", 0, feed(&g_m, in, fr(in, 8, 0x07, 0, 0, ga)));
    reset_is("cancel ping: G RST only after GOAWAY", f, 15, NULL);
    h2m_free(&g_m);

    start(&g_m, &g_r);
    uint16_t p = open1(&g_m, &NL_POST);
    r_clear(&g_r);
    check("cancel ping: NO_ERROR reset", 0, h2m_reset(&g_m, p, 0));
    check_str("cancel ping: NO_ERROR RST only", "13:5 ", g_r.calls);
    p = open1(&g_m, &NL_POST);
    r_clear(&g_r);
    check("cancel ping: FLOW_CONTROL reset", 0, h2m_reset(&g_m, p, 3));
    check_str("cancel ping: FLOW_CONTROL RST only", "13:5 ", g_r.calls);
    open1(&g_m, &NL_POST);
    r_clear(&g_r);
    check("cancel ping: peer ends E", 0, feed(&g_m, in, fr(in, 1, 0x01, 0x05, 5, &s200)));
    check_str("cancel ping: remote_end RST NO_ERROR only", "13:5 ", g_r.calls);
    reset_is("cancel ping: a later CANCEL still pings", open1(&g_m, &NL_GET), 7, op1);
    h2m_free(&g_m);
}

#define TW_N 500

struct tw {
    struct h2m m;
    int k, gate, rc;
    unsigned char sent[1 << 17];
    size_t n;
};

static pthread_mutex_t g_tw_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_tw_cv = PTHREAD_COND_INITIALIZER;
static int g_tw_in, g_tw_done, g_tw_late;
static struct timespec g_tw_dl;

static void tw_wait(const int *v, int want) {
    pthread_mutex_lock(&g_tw_mu);
    while (*v < want && !g_tw_late)
        if (pthread_cond_timedwait(&g_tw_cv, &g_tw_mu, &g_tw_dl) == ETIMEDOUT) g_tw_late = 1;
    pthread_mutex_unlock(&g_tw_mu);
}

static void tw_set(int *v, int to) {
    pthread_mutex_lock(&g_tw_mu);
    *v = to;
    pthread_cond_broadcast(&g_tw_cv);
    pthread_mutex_unlock(&g_tw_mu);
}

static int tw_out(void *ctx, const unsigned char *d, size_t n, unsigned flags) {
    struct tw *w = ctx;
    if (w->gate && (flags & H2M_END)) {
        w->gate = 0;
        tw_set(&g_tw_in, g_tw_in + 1);
        tw_wait(&g_tw_done, g_tw_in);
    }
    if (w->n + n > sizeof w->sent) return H2_EIO;
    memcpy(w->sent + w->n, d, n);
    w->n += n;
    return 0;
}

static void tw_data(void *c, uint16_t s, const unsigned char *d, size_t n) { (void)c; (void)s; (void)d; (void)n; }
static void tw_status(void *c, uint16_t s, int st) { (void)c; (void)s; (void)st; }
static void tw_end(void *c, uint16_t s, int code, const struct h2m_in *in) { (void)c; (void)s; (void)code; (void)in; }
static void tw_goaway(void *c, uint32_t l, uint32_t code) { (void)c; (void)l; (void)code; }
static void tw_ping_ack(void *c) { (void)c; }
static void tw_room(void *c, uint16_t s) { (void)c; (void)s; }

static void tw_op(int k, int i, unsigned char op[8]) {
    unsigned char o[8] = { (unsigned char)k, (unsigned char)(i >> 8), (unsigned char)i, 0xa5, 0x5a, 0xc3, 0x3c, 0x99 };
    memcpy(op, o, 8);
}

static void *tw_run(void *a) {
    struct tw *w = a;
    struct h2m_cb cb = { w, tw_out, tw_data, tw_status, tw_end, tw_goaway, tw_ping_ack, tw_room };
    w->rc = h2m_start(&w->m, &cb, (uint64_t)w->k + 7);
    for (int i = 0; i < TW_N && !w->rc; i++) {
        char path[24];
        snprintf(path, sizeof path, "/%d/%d", w->k, i);
        struct h2_req q = REQ_POST;
        q.path = path;
        unsigned char op[8];
        tw_op(w->k, i, op);
        uint16_t slot = UINT16_MAX;
        if (w->k) tw_wait(&g_tw_in, 2 * i + 1);
        else w->gate = 1;
        w->rc = h2m_open(&w->m, &q, &slot);
        if (!w->rc) w->rc = h2m_reset(&w->m, slot, 0);
        if (w->k) {
            tw_set(&g_tw_done, 2 * i + 1);
            tw_wait(&g_tw_in, 2 * i + 2);
        } else {
            w->gate = 1;
        }
        if (!w->rc) w->rc = h2m_ping(&w->m, op);
        if (w->k) tw_set(&g_tw_done, 2 * i + 2);
    }
    if (w->rc) tw_set(&g_tw_late, 1);
    h2m_free(&w->m);
    return NULL;
}

static int tw_bad(const struct tw *w, int *heads, int *pings) {
    static struct hr_ctx c;
    static struct hr_block b;
    hr_ctx_init(&c, 4096);
    const unsigned char *d = w->sent;
    size_t p = w->n >= 24 && !memcmp(d, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) ? 24 : 0;
    int bad = p ? 0 : 1;
    *heads = *pings = 0;
    while (p + 9 <= w->n) {
        uint32_t len = ((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2];
        if (p + 9 + len > w->n) return bad + 1;
        if (d[p + 3] == 0x01) {
            char want[24];
            snprintf(want, sizeof want, "/%d/%d", w->k, *heads);
            int j = !(d[p + 4] & 0x04) || hr_decode_ctx(&c, d + p + 9, len, &b) ? -1 : hr_find(&b, ":path");
            if (j < 0 || strcmp(b.f[j].value, want)) bad++;
            (*heads)++;
        } else if (d[p + 3] == 0x06) {
            unsigned char op[8];
            tw_op(w->k, *pings, op);
            if (len != 8 || memcmp(d + p + 9, op, 8)) bad++;
            (*pings)++;
        }
        p += 9 + len;
    }
    return bad;
}

static void t_h2mux_two_threads(void) {
    /* catches: the frame or block scratch shared between threads */
    static struct tw w[2];
    pthread_t th[2];
    int up = 0;
    g_tw_in = g_tw_done = g_tw_late = 0;
    clock_gettime(CLOCK_REALTIME, &g_tw_dl);
    g_tw_dl.tv_sec += 20;
    for (int k = 0; k < 2; k++) {
        memset(&w[k], 0, sizeof w[k]);
        w[k].k = k;
        if (pthread_create(&th[k], NULL, tw_run, &w[k]) == 0) up++;
    }
    for (int k = 0; k < up; k++) pthread_join(th[k], NULL);
    check("two threads: both ran", 2, up);
    check("two threads: in step, no deadline hit", 0, g_tw_late);
    for (int k = 0; k < 2; k++) {
        int heads, pings;
        int bad = tw_bad(&w[k], &heads, &pings);
        check(k ? "two threads: thread 1 every call succeeded" : "two threads: thread 0 every call succeeded", 0, w[k].rc);
        check(k ? "two threads: thread 1 500 HEADERS" : "two threads: thread 0 500 HEADERS", TW_N, heads);
        check(k ? "two threads: thread 1 500 PINGs" : "two threads: thread 0 500 PINGs", TW_N, pings);
        check(k ? "two threads: thread 1 every block and PING its own" : "two threads: thread 0 every block and PING its own", 0, bad);
    }
}

static struct h2m g_ns_m;
static struct rec g_ns_r;
static int g_ns_rc[2], g_ns_outs, g_ns_open_n;

static void *ns_run(void *a) {
    (void)a;
    uint16_t slot = UINT16_MAX;
    g_cfail_tries = 0;
    g_cfail = sizeof(struct h2mux_scratch);
    g_ns_rc[0] = h2m_open(&g_ns_m, &REQ_POST, &slot);
    g_cfail = 0;
    g_ns_outs = (int)g_ns_r.outs;
    g_ns_open_n = (int)h2m_open_n(&g_ns_m);
    g_ns_rc[1] = h2m_open(&g_ns_m, &REQ_POST, &slot);
    return NULL;
}

static void t_h2mux_open_no_scratch(void) {
    /* catches: a HEADERS frame built in a NULL block */
    check("open no scratch: started", 0, start(&g_ns_m, &g_ns_r));
    r_clear(&g_ns_r);
    pthread_t th;
    int up = pthread_create(&th, NULL, ns_run, NULL) == 0;
    if (up) pthread_join(th, NULL);
    check("open no scratch: thread ran", 1, up);
    check("open no scratch: one scratch block asked for", 1, g_cfail_tries);
    check("open no scratch: H2_EIO", H2_EIO, g_ns_rc[0]);
    check("open no scratch: nothing through cb.out", 0, g_ns_outs);
    check("open no scratch: no stream open", 0, g_ns_open_n);
    check("open no scratch: the next open succeeds", 0, g_ns_rc[1]);
    check("open no scratch: then one HEADERS", 1, hr_count_frames(g_ns_r.sent, g_ns_r.sent_n, 0x01));
    h2m_free(&g_ns_m);
}

static int g_st_rc[2];
static unsigned g_st_outs[2];

static void *st_run(void *a) {
    (void)a;
    static struct h2m m;
    static struct rec r;
    g_cfail_tries = 0;
    g_cfail = sizeof(struct h2mux_scratch);
    g_st_rc[0] = start(&m, &r);
    g_cfail = 0;
    g_st_outs[0] = r.outs;
    h2m_free(&m);
    g_st_rc[1] = start(&m, &r);
    g_st_outs[1] = r.outs;
    h2m_free(&m);
    return NULL;
}

static void t_h2mux_start_no_scratch(void) {
    /* catches: a preface written from a NULL frame buffer */
    pthread_t th;
    int up = pthread_create(&th, NULL, st_run, NULL) == 0;
    if (up) pthread_join(th, NULL);
    check("start no scratch: thread ran", 1, up);
    check("start no scratch: one scratch block asked for", 1, g_cfail_tries);
    check("start no scratch: H2_EIO", H2_EIO, g_st_rc[0]);
    check("start no scratch: nothing through cb.out", 0, g_st_outs[0]);
    check("start no scratch: the next start succeeds", 0, g_st_rc[1]);
    check("start no scratch: with the preface in one call", 1, g_st_outs[1]);
}

int main(void) {
    t_preface_go();
    t_preface_bytes();
    t_inflow_rule();
    t_ids();
    t_two_streams_demux();
    t_send_windows();
    t_settings_acked();
    t_settings_shift();
    t_credit_pair();
    t_withheld_flush();
    t_hold_keeps_withheld();
    t_padding_refund();
    t_padding_credited();
    t_padding_refund_cadence();
    t_recv_overrun();
    t_conn_overrun();
    t_arrival_credit();
    t_hold_release();
    t_conn_refund();
    t_reset_inside_data();
    t_ended_stream_refund();
    t_credit_after_end();
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
    t_units();
    t_go_blocks();
    t_size_update_from_settings();
    t_continuation_one_block();
    t_refused_open_keeps_table();
    t_bad_max_frame();
    t_upload_frames();
    t_send_begin_put();
    t_inbound_frame_size();
    t_cancel_ping();
    t_h2mux_two_threads();
    t_h2mux_open_no_scratch();
    t_h2mux_start_no_scratch();
    return unit_done("h2muxmatch");
}
