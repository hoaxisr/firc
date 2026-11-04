#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hpackread.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/socket.h>
#include "unit.h"
#include "xmux.h"
#include "trxmux.h"
#include "xconn.h"
#include "reality.h"

static uint32_t g_r, g_n, g_calls;
static int g_news, g_closes;
static void *g_closed[64];
static char g_conns[64];

static uint32_t rnd_script(uint32_t n) {
    g_calls++;
    g_n = n;
    return g_r % n;
}

static uint32_t rnd_zero(uint32_t n) {
    (void)n;
    g_calls++;
    return 0;
}

static uint32_t rnd_top(uint32_t n) {
    g_calls++;
    return n - 1;
}

static void *conn_new(void *ud, struct xm_client *c) {
    (void)ud;
    (void)c;
    return &g_conns[g_news++];
}

static void conn_close(void *ud, void *conn) {
    (void)ud;
    g_closed[g_closes++] = conn;
}

static void *conn_fail(void *ud, struct xm_client *c) {
    (void)ud;
    (void)c;
    g_news++;
    return NULL;
}

static struct xm_env env(uint64_t now) {
    return (struct xm_env){ rnd_script, now, NULL, conn_new, conn_close };
}

static void reset(void) {
    g_r = g_n = g_calls = 0;
    g_news = g_closes = 0;
}

static struct xm_cfg cfg_set(void) {
    struct xm_cfg c;
    memset(&c, 0, sizeof c);
    c.set = 1;
    return c;
}

static void t_draw(void) {
    struct xm_range wide = { 600, 900 }, one = { 5, 5 }, two = { 5, 6 };
    /* catches: an inclusive upper bound */
    check("draw 600-900 low", 600, xm_draw(wide, rnd_zero));
    check("draw 600-900 high", 899, xm_draw(wide, rnd_top));
    g_calls = 0;
    check("draw 5-5", 5, xm_draw(one, rnd_top));
    check("draw 5-6", 5, xm_draw(two, rnd_top));
    check("draw 5-5 and 5-6: no rnd", 0, g_calls);
}

static void t_defaults_three_then_random(void) {
    struct xm_cfg zero, eff;
    struct xm_mgr m;
    struct xm_client *c[4];
    reset();
    memset(&zero, 0, sizeof zero);
    xm_cfg_effective(&zero, &eff);
    struct xm_env e = env(0);
    g_r = 7;
    xm_mgr_init(&m, &m, &eff, &e);
    /* catches: a fourth connection, or round robin */
    check("defaults: connections", 3, m.connections);
    check("defaults: concurrency", 0, m.concurrency);
    for (int i = 0; i < 3; i++) c[i] = xm_pick(&m, &e);
    check("defaults: three conn_new", 3, g_news);
    check("defaults: three clients", 3, m.n);
    check("defaults: distinct 1 2", 1, c[0] != c[1]);
    check("defaults: distinct 2 3", 1, c[1] != c[2] && c[0] != c[2]);
    check("defaults: requests drawn", 607, c[0]->left_requests);
    check("defaults: age drawn in seconds", 1807000, (long)c[0]->unreusable_at_ms);
    check("defaults: no reuse limit", -1, c[0]->left_usage);
    g_r = 1;
    c[3] = xm_pick(&m, &e);
    check("defaults: pick 4 conn_new", 3, g_news);
    check("defaults: pick 4 among three", 3, g_n);
    check("defaults: pick 4 the second", 1, c[3] == c[1]);
    check("defaults: pick 4 left_usage", -1, c[3]->left_usage);
    g_r = 0;
    check("defaults: pick 5 the first", 1, xm_pick(&m, &e) == c[0]);
    xm_retire_all(&m, &e);
    check("defaults: retire closes three", 3, g_closes);
}

static void t_neither_set_one(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *first, *c;
    int same = 1;
    reset();
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: a connection per flow without maxConnections */
    first = xm_pick(&m, &e);
    for (int i = 1; i < 10; i++) {
        c = xm_pick(&m, &e);
        if (c != first) same = 0;
    }
    check("neither: one conn_new", 1, g_news);
    check("neither: same client", 1, same);
    check("neither: no reuse limit", -1, first->left_usage);
    check("neither: no request limit", INT32_MAX, first->left_requests);
    check("neither: no age", 0, (long)first->unreusable_at_ms);
    xm_retire_all(&m, &e);
    check("neither: retire closes", 1, g_closes);
}

static void t_concurrency(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c[10];
    reset();
    cfg.max_conc = (struct xm_range){ 2, 6 };
    struct xm_env e = env(0);
    g_r = 2;
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: concurrency counted by picks instead of running */
    check("concurrency: drawn", 4, m.concurrency);
    for (int i = 0; i < 10; i++) {
        c[i] = xm_pick(&m, &e);
        xm_add_running(c[i]);
    }
    check("concurrency: three conn_new", 3, g_news);
    check("concurrency: first running", 4, m.c[0]->running);
    check("concurrency: second running", 4, m.c[1]->running);
    check("concurrency: third running", 2, m.c[2]->running);
    for (int i = 0; i < 10; i++) xm_done_running(&m, c[i], &e);
    check("concurrency: listed clients stay open", 0, g_closes);
    xm_retire_all(&m, &e);
    check("concurrency: retire closes", 3, g_closes);
}

static void t_c_reuse(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c[4];
    reset();
    cfg.c_reuse = (struct xm_range){ 3, 3 };
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: creation not counted as a use, or a busy client closed */
    c[0] = xm_pick(&m, &e);
    xm_add_running(c[0]);
    check("reuse: pick 1 left", 2, c[0]->left_usage);
    c[1] = xm_pick(&m, &e);
    xm_add_running(c[1]);
    check("reuse: pick 2 same", 1, c[1] == c[0]);
    check("reuse: pick 2 left", 1, c[0]->left_usage);
    c[2] = xm_pick(&m, &e);
    xm_add_running(c[2]);
    check("reuse: pick 3 same", 1, c[2] == c[0]);
    check("reuse: pick 3 left", 0, c[0]->left_usage);
    void *old = c[0]->conn[0];
    c[3] = xm_pick(&m, &e);
    check("reuse: pick 4 creates", 2, g_news);
    check("reuse: pick 4 another", 1, c[3] != c[0]);
    check("reuse: pick 4 busy one kept", 0, g_closes);
    check("reuse: swept off the list", 1, m.n);
    check("reuse: swept not used", 1, c[0]->not_used);
    xm_done_running(&m, c[0], &e);
    check("reuse: done 1 open", 0, g_closes);
    xm_done_running(&m, c[0], &e);
    check("reuse: done 2 open", 0, g_closes);
    xm_done_running(&m, c[0], &e);
    check("reuse: done 3 closed", 1, g_closes);
    check("reuse: done 3 its connection", 1, g_closed[0] == old);
    xm_retire_all(&m, &e);
    check("reuse: retire closes", 2, g_closes);
}

static void t_h_requests(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c, *d;
    int32_t left = -1;
    reset();
    cfg.h_reqs = (struct xm_range){ 5, 5 };
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: retirement by the decrement instead of the sweep */
    c = xm_pick(&m, &e);
    check("requests: drawn", 5, c->left_requests);
    check("requests: first request", 4, xm_request(c));
    for (int i = 0; i < 4; i++) left = xm_request(c);
    check("requests: fifth request", 0, left);
    check("requests: no close before a pick", 0, g_closes);
    check("requests: still listed", 1, m.n);
    void *old = c->conn[0];
    d = xm_pick(&m, &e);
    check("requests: next pick closes idle", 1, g_closes);
    check("requests: closed its connection", 1, g_closed[0] == old);
    check("requests: next pick creates", 2, g_news);
    check("requests: new client drawn", 5, d->left_requests);
    xm_retire_all(&m, &e);
    check("requests: retire closes", 2, g_closes);
}

static void t_h_secs_boundary(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c, *d;
    reset();
    cfg.h_secs = (struct xm_range){ 1800, 1800 };
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: >= where Xray has After */
    c = xm_pick(&m, &e);
    check("age: unreusable at", 1800000, (long)c->unreusable_at_ms);
    e.now_ms = 1800000;
    d = xm_pick(&m, &e);
    check("age: at the limit same", 1, d == c);
    check("age: at the limit no conn_new", 1, g_news);
    e.now_ms = 1800001;
    d = xm_pick(&m, &e);
    check("age: past the limit conn_new", 2, g_news);
    check("age: past the limit closed", 1, g_closes);
    check("age: new client from now", 3600001, (long)d->unreusable_at_ms);
    xm_retire_all(&m, &e);
    check("age: retire closes", 2, g_closes);
}

static void t_failed_retires(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c, *d;
    reset();
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: a failed client given new flows, or closed while running */
    c = xm_pick(&m, &e);
    xm_add_running(c);
    xm_failed(c);
    check("failed: flag", 1, c->closed);
    check("failed: no close at the mark", 0, g_closes);
    d = xm_pick(&m, &e);
    check("failed: next pick creates", 2, g_news);
    check("failed: next pick another", 1, d != c);
    check("failed: running kept open", 0, g_closes);
    xm_done_running(&m, c, &e);
    check("failed: closed at running 0", 1, g_closes);
    xm_retire_all(&m, &e);
    check("failed: retire closes", 2, g_closes);
}

static void t_post_moves(void) {
    struct xm_client c;
    memset(&c, 0, sizeof c);
    /* catches: a move on requests left, == 0 for <= 0, or >= where Xray has After */
    check("moves: left 1 at 0", 0, xm_post_moves(&c, 1, 0));
    check("moves: left 0", 1, xm_post_moves(&c, 0, 0));
    check("moves: left -1", 1, xm_post_moves(&c, -1, 0));
    check("moves: no age at a late time", 0, xm_post_moves(&c, 1, UINT64_MAX));
    c.unreusable_at_ms = 1000;
    check("moves: at the age", 0, xm_post_moves(&c, 5, 1000));
    check("moves: past the age", 1, xm_post_moves(&c, 5, 1001));
}

static void t_refs_keep_conn(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c;
    reset();
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: a retired connection closed under in-flight POSTs */
    c = xm_pick(&m, &e);
    c->refs = 2;
    void *old = c->conn[0];
    xm_failed(c);
    xm_pick(&m, &e);
    check("refs: swept not used", 1, c->not_used);
    check("refs: not closed at the sweep", 0, g_closes);
    xm_unref(&m, c, &e);
    check("refs: one ref left open", 0, g_closes);
    xm_unref(&m, c, &e);
    check("refs: last ref closes", 1, g_closes);
    check("refs: its connection", 1, g_closed[0] == old);
    xm_retire_all(&m, &e);
    check("refs: retire closes", 2, g_closes);
}

static void t_clients_cap(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c[20];
    reset();
    cfg.max_conc = (struct xm_range){ 1, 1 };
    cfg.c_reuse = (struct xm_range){ 3, 3 };
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: XM_CLIENTS overflow, or a pick past the cap not counted as a use */
    for (int i = 0; i < 20; i++) {
        c[i] = xm_pick(&m, &e);
        if (c[i]) xm_add_running(c[i]);
    }
    check("cap: sixteen conn_new", 16, g_news);
    check("cap: sixteen listed", XM_CLIENTS, m.n);
    check("cap: pick 17 a listed client", 1, c[16] == m.c[0]);
    check("cap: pick 17 counted as a use", 1, m.c[0]->left_usage);
    check("cap: fifth not picked again", 2, m.c[4]->left_usage);
    check("cap: pick 18 fewest running", 1, c[17] == m.c[1]);
    check("cap: pick 19 fewest running", 1, c[18] == m.c[2]);
    check("cap: pick 20 fewest running", 1, c[19] == m.c[3]);
    check("cap: first running", 2, m.c[0]->running);
    check("cap: fifth running", 1, m.c[4]->running);
    for (int i = 0; i < 20; i++) xm_done_running(&m, c[i], &e);
    xm_retire_all(&m, &e);
    check("cap: retire closes", 16, g_closes);
}

static void t_conn_new_fails(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c;
    reset();
    struct xm_env e = env(0), bad = e;
    bad.conn_new = conn_fail;
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: a client without a connection listed and handed out */
    check("conn fails: no client", 1, xm_pick(&m, &bad) == NULL);
    check("conn fails: not listed", 0, m.n);
    check("conn fails: nothing to close", 0, g_closes);
    c = xm_pick(&m, &e);
    check("conn fails: next pick a client", 1, c != NULL);
    check("conn fails: one connection", 1, c ? c->conn_n : 0);
    check("conn fails: one listed", 1, m.n);
    xm_retire_all(&m, &e);
    check("conn fails: retire closes", 1, g_closes);
}

static void t_unbalanced_unref(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c;
    reset();
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: refs wrapping below zero and pinning a retired connection */
    c = xm_pick(&m, &e);
    xm_add_running(c);
    xm_unref(&m, c, &e);
    xm_retire_all(&m, &e);
    check("unref: busy open", 0, g_closes);
    xm_done_running(&m, c, &e);
    check("unref: closed at the last done", 1, g_closes);
}

static void t_retire_all(void) {
    struct xm_cfg cfg = cfg_set();
    struct xm_mgr m;
    struct xm_client *c[3];
    reset();
    cfg.max_conns = (struct xm_range){ 3, 3 };
    struct xm_env e = env(0);
    xm_mgr_init(&m, &m, &cfg, &e);
    /* catches: a busy client closed by a retire, or an idle one kept */
    for (int i = 0; i < 3; i++) c[i] = xm_pick(&m, &e);
    xm_add_running(c[1]);
    xm_add_running(c[1]);
    void *busy = c[1]->conn[0];
    xm_retire_all(&m, &e);
    check("retire: idle closed at once", 2, g_closes);
    check("retire: list empty", 0, m.n);
    check("retire: busy not used", 1, c[1]->not_used);
    xm_done_running(&m, c[1], &e);
    check("retire: busy open at done 1", 2, g_closes);
    xm_done_running(&m, c[1], &e);
    check("retire: busy closed at last done", 3, g_closes);
    check("retire: busy connection", 1, g_closed[2] == busy);
    xm_pick(&m, &e);
    check("retire: next pick creates", 4, g_news);
    xm_retire_all(&m, &e);
    check("retire: retire closes", 4, g_closes);
}

void sc_wipe(void *p, size_t n) { memset(p, 0, n); }
int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st, unsigned char *out, size_t out_n,
                        size_t *out_len)
    { (void)cfg; (void)st; (void)out; (void)out_n; *out_len = 0; return -1; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car, unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)car; (void)out; (void)out_n; *out_len = 0; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n, const unsigned char *ss,
                         const struct tls13_auth *auth)
    { (void)t; (void)fd; (void)ch; (void)n; (void)ss; (void)auth; return -1; }
const char *tls13_verify_reason(void) { return ""; }
unsigned tls13_server_group(void) { return 0; }
int xc_b64url_decode(const char *in, unsigned char *out, size_t out_n) { (void)in; (void)out; (void)out_n; return -1; }
int tls13_has_record(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_buffered(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap) { (void)t; (void)out; (void)cap; return 0; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n) { (void)t; (void)d; (void)n; return -1; }
int tls13_seal(struct tls13 *t, const unsigned char *d, size_t n, unsigned char *out, size_t cap, size_t *out_n)
    { (void)t; (void)d; (void)n; (void)out; (void)cap; *out_n = 0; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t cap, size_t *got)
    { (void)t; (void)o; (void)cap; *got = 0; return -1; }
int tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *bn) { (void)t; *b = NULL; *bn = 0; return -1; }
void tls13_free(struct tls13 *t) { (void)t; }

extern unsigned tr_xmux_links_cap, tr_xmux_mgrs_cap;
extern uint32_t (*tr_xmux_rnd)(uint32_t n);
extern size_t tr_xmux_up_budget;
size_t tr_xmux_bat_used(void);

#define PC_MAX 8
#define PS_MAX 32

struct pc {
    int fd, eof, rst, pre, kill, pings, mcs_sent, ep, wu0;
    uint32_t wu0_first, pad_sid;
    int noread;
    long wu0_sum, wus_sum, pad_left, pad_sent;
    uint32_t sid[PS_MAX], rsid[PS_MAX], rcode[PS_MAX];
    int nsid, nrst;
    uint32_t goaway, rst_sid;
    int goaway_due, rst_due, ping_due, release_due;
    uint32_t held[PS_MAX];
    int nheld;
    unsigned char up[256];
    size_t upn;
    struct { unsigned type, flags; uint32_t sid, len; unsigned char body[16]; } fq[4];
    int fqn;
    char ord[128];
    size_t ordn;
    uint32_t refd[PS_MAX];
    int nrefd;
    char paths[1024];
    size_t pathn;
    char cls[256];
    size_t cln;
    char dl[256];
    size_t dln;
    unsigned char b[1 << 18];
    size_t bn;
};

static struct {
    int lfd, lfd2, mcs, stop, refuse;
    int split, hold, refuse_post, refuse_get, post_status, nowu, get_ci, shut, shut2, post_body;
    long pad_post, pad_cap;
    int pad_go, pad_get, noecho, early, over, lim, over_left, over_c0, nosettings, iwin, imcs, mfs;
    uint32_t get_sid;
    uint16_t port, port2;
    struct pc c[PC_MAX];
    int n;
    pthread_t th;
    pthread_mutex_t mu;
} g_p = { .lfd = -1, .lfd2 = -1, .mu = PTHREAD_MUTEX_INITIALIZER };

static void p_write(int fd, unsigned type, unsigned flags, uint32_t sid, const void *body, uint32_t len) {
    unsigned char f[9 + 16384];
    f[0] = (unsigned char)(len >> 16);
    f[1] = (unsigned char)(len >> 8);
    f[2] = (unsigned char)len;
    f[3] = (unsigned char)type;
    f[4] = (unsigned char)flags;
    f[5] = (unsigned char)((sid >> 24) & 0x7f);
    f[6] = (unsigned char)(sid >> 16);
    f[7] = (unsigned char)(sid >> 8);
    f[8] = (unsigned char)sid;
    if (len) memcpy(f + 9, body, len);
    size_t n = 9 + len, off = 0;
    while (off < n) {
        ssize_t w = send(fd, f + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static uint32_t p_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void p_answer(struct pc *c, uint32_t sid) {
    unsigned char st = g_p.post_status == 400 ? 0x8c : 0x88;
    if (!g_p.post_body) {
        p_write(c->fd, 1, 5, sid, &st, 1);
        return;
    }
    static const char body[] = "<html><body>400 Bad Request</body></html>";
    p_write(c->fd, 1, 4, sid, &st, 1);
    p_write(c->fd, 0, 1, sid, body, sizeof body - 1);
}

static void p_split_data(struct pc *c, unsigned flags, uint32_t sid, const unsigned char *body, uint32_t len) {
    if (len <= sizeof c->up - c->upn) {
        memcpy(c->up + c->upn, body, len);
        c->upn += len;
    }
    struct pc *g = &g_p.c[g_p.get_ci];
    if (g_p.get_sid && g->fd >= 0 && !g_p.noecho) p_write(g->fd, 0, 0, g_p.get_sid, body, len);
    unsigned char inc[4] = { 0, 0, (unsigned char)(len >> 8), (unsigned char)len };
    if (!g_p.nowu) {
        p_write(c->fd, 8, 0, 0, inc, 4);
        if (!(flags & 1)) p_write(c->fd, 8, 0, sid, inc, 4);
    }
    if (g_p.split != 2 || !(flags & 1)) return;
    if (!g_p.hold) p_answer(c, sid);
    else if (c->nheld < PS_MAX) c->held[c->nheld++] = sid;
}

static int p_refd(const struct pc *c, uint32_t sid) {
    for (int i = 0; i < c->nrefd; i++)
        if (c->refd[i] == sid) return 1;
    return 0;
}

static struct hr_ctx g_hc[PC_MAX];
static struct hr_block g_hb;

static void p_path(struct pc *c, const unsigned char *b, uint32_t len) {
    struct hr_ctx *hc = &g_hc[c - g_p.c];
    int i = hr_decode_ctx(hc, b, len, &g_hb) ? -1 : hr_find(&g_hb, ":path");
    const char *v = i >= 0 ? g_hb.f[i].value : "?";
    int w = snprintf(c->paths + c->pathn, sizeof c->paths - c->pathn, "%s ", v);
    if (w > 0 && (size_t)w < sizeof c->paths - c->pathn) c->pathn += (size_t)w;
    i = i >= 0 ? hr_find(&g_hb, "content-length") : -1;
    w = snprintf(c->cls + c->cln, sizeof c->cls - c->cln, "%s ", i >= 0 ? g_hb.f[i].value : "-");
    if (w > 0 && (size_t)w < sizeof c->cls - c->cln) c->cln += (size_t)w;
}

static int p_paths_is(int ci, int k, int j) {
    pthread_mutex_lock(&g_p.mu);
    char a[256] = "", b[256] = "";
    const char *s = ci < g_p.n ? g_p.c[ci].paths : "";
    for (int n = 0; *s; n++) {
        const char *e = strchr(s, ' ');
        size_t l = e ? (size_t)(e - s) : strlen(s);
        if (l >= sizeof a) l = sizeof a - 1;
        if (n == k) { memcpy(a, s, l); a[l] = 0; }
        if (n == j) { memcpy(b, s, l); b[l] = 0; }
        s += l + (e ? 1 : 0);
    }
    pthread_mutex_unlock(&g_p.mu);
    int ok = a[0] && strcmp(a, "?") && !strcmp(a, b);
    if (!ok) printf("     paths %d %d: \"%s\" \"%s\"\n", k, j, a, b);
    return ok;
}

static void p_frames(struct pc *c) {
    size_t i = 0;
    if (!c->pre) {
        if (c->bn < 24) return;
        c->pre = 1;
        i = 24;
        unsigned char st[6] = { 0, 3, 0, 0, 0, (unsigned char)g_p.mcs };
        if (!g_p.early && !g_p.nosettings) p_write(c->fd, 4, 0, 0, st, g_p.mcs ? 6 : 0);
        if (g_p.mfs) {
            static const unsigned char mf[12] = { 0, 5, 0, 0x10, 0, 0, 0, 4, 0, 0x10, 0, 0 };
            static const unsigned char wu[4] = { 0, 0x0f, 0, 0x01 };
            p_write(c->fd, 4, 0, 0, mf, 12);
            p_write(c->fd, 8, 0, 0, wu, 4);
        }
    }
    while (i + 9 <= c->bn) {
        const unsigned char *h = c->b + i;
        uint32_t len = ((uint32_t)h[0] << 16) | ((uint32_t)h[1] << 8) | h[2];
        if (i + 9 + len > c->bn) break;
        unsigned type = h[3], flags = h[4];
        uint32_t sid = p_be32(h + 5) & 0x7fffffffu;
        const unsigned char *body = h + 9;
        if (c->ordn + 16 < sizeof c->ord) {
            char tag = type == 4 ? ((flags & 1) ? 'A' : 'S') : type == 8 ? 'W' : type == 1 ? 'H' : '?';
            int w = type == 4 ? snprintf(c->ord + c->ordn, sizeof c->ord - c->ordn, "%c ", tag)
                              : snprintf(c->ord + c->ordn, sizeof c->ord - c->ordn, "%c%u ", tag, (unsigned)sid);
            if (w > 0) c->ordn += (size_t)w;
        }
        if (type == 0 && c->dln + 16 < sizeof c->dl) {
            int w = snprintf(c->dl + c->dln, sizeof c->dl - c->dln, "%u:%u ", (unsigned)len, flags);
            if (w > 0) c->dln += (size_t)w;
        }
        if (type == 1) {
            p_path(c, body, len);
            if (c->nsid < PS_MAX) c->sid[c->nsid++] = sid;
            unsigned char st = 0x88, code[4] = { 0, 0, 0, 2 }, refused[4] = { 0, 0, 0, 7 };
            if (g_p.over && c->nsid > g_p.lim && (!g_p.over_c0 || c == g_p.c) && g_p.over_left >= 0) {
                if (g_p.over_left && !--g_p.over_left) g_p.over_left = -1;
                unsigned char iw[6] = { 0, 4, (unsigned char)(g_p.iwin >> 24), (unsigned char)(g_p.iwin >> 16),
                                        (unsigned char)(g_p.iwin >> 8), (unsigned char)g_p.iwin };
                unsigned char im[12] = { 0, 4, iw[2], iw[3], iw[4], iw[5], 0, 3, 0, 0, 0, (unsigned char)g_p.imcs };
                if (g_p.iwin) p_write(c->fd, 4, 0, 0, im, g_p.imcs ? 12 : 6);
                g_p.iwin = g_p.imcs = 0;
                if (c->nrefd < PS_MAX) c->refd[c->nrefd++] = sid;
                p_write(c->fd, 3, 0, sid, refused, 4);
            } else if (g_p.split && (flags & 1) && g_p.refuse_get) {
                p_write(c->fd, 3, 0, sid, code, 4);
            } else if (g_p.split && (flags & 1)) {
                g_p.get_ci = (int)(c - g_p.c);
                g_p.get_sid = sid;
                p_write(c->fd, 1, 4, sid, &st, 1);
                if (g_p.pad_get) {
                    c->pad_sid = sid;
                    c->pad_left = g_p.pad_post;
                }
            } else if (g_p.split == 2) {
                if (g_p.refuse_post) p_write(c->fd, 3, 0, sid, code, 4);
            } else if (g_p.refuse) {
                p_write(c->fd, 3, 0, sid, code, 4);
            } else {
                p_write(c->fd, 1, 4, sid, &st, 1);
                if (g_p.split == 1 && !(flags & 1) && g_p.pad_post && !g_p.pad_get) {
                    c->pad_sid = sid;
                    c->pad_left = g_p.pad_post;
                }
            }
        } else if (type == 0 && p_refd(c, sid)) {
        } else if (type == 0 && len && g_p.split) {
            p_split_data(c, flags, sid, body, len);
        } else if (type == 0 && len) {
            p_write(c->fd, 0, 0, sid, body, len);
            unsigned char inc[4] = { 0, 0, (unsigned char)(len >> 8), (unsigned char)len };
            p_write(c->fd, 8, 0, 0, inc, 4);
            p_write(c->fd, 8, 0, sid, inc, 4);
        } else if (type == 3 && len == 4) {
            if (c->nrst < PS_MAX) {
                c->rsid[c->nrst] = sid;
                c->rcode[c->nrst++] = p_be32(body);
            }
        } else if (type == 6 && !(flags & 1) && len == 8) {
            c->pings++;
            p_write(c->fd, 6, 1, 0, body, 8);
        } else if (type == 8 && len == 4) {
            uint32_t inc = p_be32(body) & 0x7fffffffu;
            if (!sid) {
                if (!c->wu0++) c->wu0_first = inc;
                c->wu0_sum += inc;
            } else if (sid == c->pad_sid) {
                c->wus_sum += inc;
            }
        } else if (type == 4 && !(flags & 1)) {
            p_write(c->fd, 4, 1, 0, NULL, 0);
        }
        i += 9 + len;
    }
    memmove(c->b, c->b + i, c->bn - i);
    c->bn -= i;
}

static void *p_run(void *arg) {
    (void)arg;
    for (;;) {
        struct pollfd pf[PC_MAX + 2];
        int n = 0;
        pthread_mutex_lock(&g_p.mu);
        if (g_p.stop) {
            pthread_mutex_unlock(&g_p.mu);
            return NULL;
        }
        for (int i = 0; i < g_p.n; i++) {
            struct pc *c = &g_p.c[i];
            if (c->fd >= 0 && c->goaway_due) {
                unsigned char g[8] = { (unsigned char)(c->goaway >> 24), (unsigned char)(c->goaway >> 16),
                                       (unsigned char)(c->goaway >> 8), (unsigned char)c->goaway, 0, 0, 0, 0 };
                p_write(c->fd, 7, 0, 0, g, 8);
                c->goaway_due = 0;
            }
            if (c->fd >= 0 && c->rst_due) {
                unsigned char code[4] = { 0, 0, 0, 2 };
                p_write(c->fd, 3, 0, c->rst_sid, code, 4);
                c->rst_due = 0;
            }
            for (int k = 0; c->fd >= 0 && k < c->fqn; k++)
                p_write(c->fd, c->fq[k].type, c->fq[k].flags, c->fq[k].sid, c->fq[k].body, c->fq[k].len);
            c->fqn = 0;
            if (c->fd >= 0 && c->release_due) {
                for (int k = 0; k < c->nheld; k++) p_answer(c, c->held[k]);
                c->nheld = 0;
                c->release_due = 0;
            }
            if (c->fd >= 0 && c->ping_due) {
                p_write(c->fd, 6, 0, 0, "pingpong", 8);
                c->ping_due = 0;
            }
            if (c->fd >= 0 && c->pad_left > 0 && g_p.pad_go && (!g_p.pad_cap || c->pad_sent < g_p.pad_cap)) {
                struct pollfd w = { .fd = c->fd, .events = POLLOUT };
                if (poll(&w, 1, 0) == 1 && (w.revents & POLLOUT)) {
                    static const unsigned char xs[4096] = { 'X' };
                    long k = c->pad_left < 4096 ? c->pad_left : 4096;
                    if (c->pad_sent + k <= 4194304 + c->wus_sum && c->pad_sent + k <= 65535 + c->wu0_sum) {
                        p_write(c->fd, 0, 0, c->pad_sid, xs, (uint32_t)k);
                        c->pad_left -= k;
                        c->pad_sent += k;
                    }
                }
            }
            if (c->fd >= 0 && c->kill) {
                close(c->fd);
                c->fd = -1;
            }
        }
        if (g_p.shut && g_p.lfd >= 0) {
            close(g_p.lfd);
            g_p.lfd = -1;
        }
        if (g_p.shut2 && g_p.lfd2 >= 0) {
            close(g_p.lfd2);
            g_p.lfd2 = -1;
        }
        pf[n++] = (struct pollfd){ .fd = g_p.lfd, .events = POLLIN };
        pf[n++] = (struct pollfd){ .fd = g_p.lfd2, .events = POLLIN };
        for (int i = 0; i < g_p.n; i++) pf[n++] = (struct pollfd){ .fd = g_p.c[i].noread ? -1 : g_p.c[i].fd, .events = POLLIN };
        pthread_mutex_unlock(&g_p.mu);
        if (poll(pf, (nfds_t)n, 2) <= 0) continue;
        pthread_mutex_lock(&g_p.mu);
        for (int ep = 0; ep < 2; ep++) {
            if (!(pf[ep].revents & POLLIN)) continue;
            int fd = accept(ep ? g_p.lfd2 : g_p.lfd, NULL, NULL);
            if (fd >= 0 && g_p.n < PC_MAX) {
                memset(&g_p.c[g_p.n], 0, sizeof g_p.c[0]);
                hr_ctx_init(&g_hc[g_p.n], 4096);
                g_p.c[g_p.n].ep = ep;
                g_p.c[g_p.n++].fd = fd;
                unsigned char st[6] = { 0, 3, 0, 0, 0, (unsigned char)g_p.early };
                if (g_p.early) p_write(fd, 4, 0, 0, st, 6);
            } else if (fd >= 0) {
                close(fd);
            }
        }
        for (int i = 2; i < n; i++) {
            struct pc *c = &g_p.c[i - 2];
            if (c->fd < 0 || pf[i].fd != c->fd || !(pf[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t r = recv(c->fd, c->b + c->bn, sizeof c->b - c->bn, MSG_DONTWAIT);
            if (r > 0) {
                c->bn += (size_t)r;
                p_frames(c);
                continue;
            }
            if (r < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (r == 0) c->eof = 1;
            else c->rst = 1;
            close(c->fd);
            c->fd = -1;
        }
        pthread_mutex_unlock(&g_p.mu);
    }
}

static uint16_t lo_listen(int *fd) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof a;
    if (bind(l, (struct sockaddr *)&a, sizeof a) || listen(l, 16) || getsockname(l, (struct sockaddr *)&a, &al)) {
        perror("listen");
        exit(2);
    }
    *fd = l;
    return ntohs(a.sin_port);
}

static void p_start(int mcs) {
    memset(g_p.c, 0, sizeof g_p.c);
    g_p.n = 0;
    g_p.mcs = mcs;
    g_p.stop = 0;
    g_p.refuse = g_p.split = g_p.hold = g_p.refuse_post = g_p.post_status = g_p.nowu = g_p.get_ci = 0;
    g_p.shut = g_p.shut2 = g_p.refuse_get = g_p.post_body = 0;
    g_p.pad_post = 0;
    g_p.pad_go = 1;
    g_p.pad_get = g_p.noecho = g_p.early = g_p.over = g_p.lim = g_p.over_left = g_p.over_c0 = g_p.nosettings = g_p.iwin = g_p.imcs = g_p.mfs = 0;
    g_p.pad_cap = 0;
    g_p.get_sid = 0;
    g_p.port = lo_listen(&g_p.lfd);
    g_p.port2 = lo_listen(&g_p.lfd2);
    if (pthread_create(&g_p.th, NULL, p_run, NULL)) exit(2);
}

static void p_stop(void) {
    pthread_mutex_lock(&g_p.mu);
    g_p.stop = 1;
    pthread_mutex_unlock(&g_p.mu);
    pthread_join(g_p.th, NULL);
    for (int i = 0; i < g_p.n; i++)
        if (g_p.c[i].fd >= 0) close(g_p.c[i].fd);
    if (g_p.lfd >= 0) close(g_p.lfd);
    if (g_p.lfd2 >= 0) close(g_p.lfd2);
    g_p.lfd = g_p.lfd2 = -1;
}

static void p_settle(void) {
    for (int i = 0; i < 1000; i++) {
        pthread_mutex_lock(&g_p.mu);
        struct pollfd pf[2] = { { .fd = g_p.lfd, .events = POLLIN }, { .fd = g_p.lfd2, .events = POLLIN } };
        pthread_mutex_unlock(&g_p.mu);
        if (poll(pf, 2, 0) <= 0) return;
        usleep(1000);
    }
}

static int p_get(int what, int ci, int k) {
    if (what == 0 || what == 13) p_settle();
    pthread_mutex_lock(&g_p.mu);
    int v = -1;
    if (what == 0) v = g_p.n;
    else if (what == 16) v = g_p.lfd2;
    else if (what == 22) v = g_p.lfd;
    else if (what >= 13 && what <= 15) {
        v = 0;
        for (int i = 0; i < g_p.n; i++)
            if (g_p.c[i].ep == k) v += what == 13 ? 1 : what == 14 ? g_p.c[i].nsid : (int)g_p.c[i].upn;
    } else if (ci < g_p.n) {
        struct pc *c = &g_p.c[ci];
        if (what == 1) v = c->eof;
        else if (what == 2) v = c->rst;
        else if (what == 3) v = k < c->nsid ? (int)c->sid[k] : -1;
        else if (what == 4) v = c->nsid;
        else if (what == 5) v = c->nrst;
        else if (what == 6) v = k < c->nrst ? (int)c->rsid[k] : -1;
        else if (what == 7) v = k < c->nrst ? (int)c->rcode[k] : -1;
        else if (what == 8) v = c->pings;
        else if (what == 9) v = c->fd >= 0;
        else if (what == 10) v = c->nheld;
        else if (what == 11) v = (int)c->upn;
        else if (what == 12) v = g_p.lfd;
        else if (what == 17) v = c->wu0;
        else if (what == 18) v = (int)c->wu0_first;
        else if (what == 19) v = (int)(c->wu0_sum / 1024);
        else if (what == 20) v = (int)(c->wus_sum / 1024);
        else if (what == 21) v = (int)c->pad_left;
    }
    pthread_mutex_unlock(&g_p.mu);
    return v;
}

#define P_ACCEPTS()   p_get(0, 0, 0)
#define P_EOF(i)      p_get(1, i, 0)
#define P_RST(i)      p_get(2, i, 0)
#define P_SID(i, k)   p_get(3, i, k)
#define P_NSID(i)     p_get(4, i, 0)
#define P_NRST(i)     p_get(5, i, 0)
#define P_RSID(i, k)  p_get(6, i, k)
#define P_RCODE(i, k) p_get(7, i, k)
#define P_PINGS(i)    p_get(8, i, 0)
#define P_OPEN(i)     p_get(9, i, 0)
#define P_NHELD(i)    p_get(10, i, 0)
#define P_UPN(i)      p_get(11, i, 0)
#define P_GONE(i)     (P_EOF(i) == 1 || P_RST(i) == 1)
#define P_ACC(ep)     p_get(13, 0, ep)
#define P_NSID_AT(ep) p_get(14, 0, ep)
#define P_UPN_AT(ep)  p_get(15, 0, ep)
#define P_SET(f, v)                    \
    do {                               \
        pthread_mutex_lock(&g_p.mu);   \
        g_p.f = (v);                   \
        pthread_mutex_unlock(&g_p.mu); \
    } while (0)

static int p_up_is(int ci, const char *want) {
    pthread_mutex_lock(&g_p.mu);
    size_t n = strlen(want);
    int ok = ci < g_p.n && g_p.c[ci].upn == n && !memcmp(g_p.c[ci].up, want, n);
    pthread_mutex_unlock(&g_p.mu);
    return ok;
}

static int p_dl_is(int ci, const char *want, int say) {
    pthread_mutex_lock(&g_p.mu);
    int ok = ci < g_p.n && !strcmp(g_p.c[ci].dl, want);
    if (!ok && say) printf("     data frames: \"%s\"\n", ci < g_p.n ? g_p.c[ci].dl : "");
    pthread_mutex_unlock(&g_p.mu);
    return ok;
}

static int p_cls_is(int ci, const char *want) {
    pthread_mutex_lock(&g_p.mu);
    int ok = ci < g_p.n && !strcmp(g_p.c[ci].cls, want);
    pthread_mutex_unlock(&g_p.mu);
    return ok;
}

static void p_frame_out(int ci, unsigned type, unsigned flags, uint32_t sid, const char *body) {
    pthread_mutex_lock(&g_p.mu);
    struct pc *c = &g_p.c[ci];
    if (c->fqn < 4) {
        c->fq[c->fqn].type = type;
        c->fq[c->fqn].flags = flags;
        c->fq[c->fqn].sid = sid;
        c->fq[c->fqn].len = (uint32_t)strlen(body);
        memcpy(c->fq[c->fqn].body, body, c->fq[c->fqn].len);
        c->fqn++;
    }
    pthread_mutex_unlock(&g_p.mu);
}

static int p_ord_starts(int ci, const char *want) {
    pthread_mutex_lock(&g_p.mu);
    int ok = ci < g_p.n && !strncmp(g_p.c[ci].ord, want, strlen(want));
    if (!ok && ci < g_p.n) printf("     order: \"%s\"\n", g_p.c[ci].ord);
    pthread_mutex_unlock(&g_p.mu);
    return ok;
}

static int p_ord_len(int ci) {
    pthread_mutex_lock(&g_p.mu);
    int n = ci < g_p.n ? (int)g_p.c[ci].ordn : 0;
    pthread_mutex_unlock(&g_p.mu);
    return n;
}

static void p_noread(int ci) {
    pthread_mutex_lock(&g_p.mu);
    if (ci >= 0 && ci < g_p.n) g_p.c[ci].noread = 1;
    pthread_mutex_unlock(&g_p.mu);
}

static void p_read_again(int ci) {
    pthread_mutex_lock(&g_p.mu);
    if (ci >= 0 && ci < g_p.n) g_p.c[ci].noread = 0;
    pthread_mutex_unlock(&g_p.mu);
}

static void p_rcvbuf(int bytes) {
    setsockopt(g_p.lfd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
    setsockopt(g_p.lfd2, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
}

static void p_release(int ci) {
    pthread_mutex_lock(&g_p.mu);
    if (ci < g_p.n) g_p.c[ci].release_due = 1;
    pthread_mutex_unlock(&g_p.mu);
}

static void p_rst(int ci, uint32_t sid) {
    pthread_mutex_lock(&g_p.mu);
    g_p.c[ci].rst_sid = sid;
    g_p.c[ci].rst_due = 1;
    pthread_mutex_unlock(&g_p.mu);
}

static void p_ping_sent(int ci) {
    pthread_mutex_lock(&g_p.mu);
    g_p.c[ci].ping_due = 1;
    pthread_mutex_unlock(&g_p.mu);
    for (int i = 0; i < 1000; i++) {
        pthread_mutex_lock(&g_p.mu);
        int due = g_p.c[ci].ping_due;
        pthread_mutex_unlock(&g_p.mu);
        if (!due) break;
        usleep(1000);
    }
    usleep(20000);
}

static void p_cmd(int ci, int kill, int goaway, uint32_t last) {
    pthread_mutex_lock(&g_p.mu);
    if (ci < g_p.n) {
        if (kill) g_p.c[ci].kill = 1;
        if (goaway) {
            g_p.c[ci].goaway = last;
            g_p.c[ci].goaway_due = 1;
        }
    }
    pthread_mutex_unlock(&g_p.mu);
}

struct gw { uint16_t owner; unsigned what; int rc; };
static struct gw g_gw[512];
static int g_gw_n;
static struct { void *link; int *done; } g_job[64];
static int g_job_n, g_jobs, g_hold, g_ep = -1;
static uint64_t g_now;
static int g_stale_on;
static const void *g_stale_node, *g_stale_node2;

static void gl_wake(void *arg, uint16_t owner, unsigned what, int rc) {
    (void)arg;
    if (g_gw_n < 512) g_gw[g_gw_n++] = (struct gw){ owner, what, rc };
}

static int gl_submit(void *link, int *done) {
    if (g_job_n >= 64) return -1;
    g_job[g_job_n].link = link;
    g_job[g_job_n++].done = done;
    g_jobs++;
    return 0;
}

static unsigned g_wev[1024];

static int gl_watch(unsigned idx, int fd, unsigned ev) {
    if (fd >= 0 && fd < 1024) g_wev[fd] = ev;
    if (!ev) return epoll_ctl(g_ep, EPOLL_CTL_DEL, fd, NULL) == 0 || errno == ENOENT ? 0 : -1;
    struct epoll_event e = { .events = ev, .data = { .u32 = idx } };
    if (epoll_ctl(g_ep, EPOLL_CTL_MOD, fd, &e) == 0) return 0;
    return errno == ENOENT && epoll_ctl(g_ep, EPOLL_CTL_ADD, fd, &e) == 0 ? 0 : -1;
}

static int gl_stale(const struct xc_ref *r) { return g_stale_on && (r->node == g_stale_node || r->node == g_stale_node2); }

static const struct mux_host GL_HOST = { gl_submit, gl_watch, gl_wake, NULL, 1, 8000 };

static void jobs_run(void) {
    while (g_job_n && !g_hold) {
        void *link = g_job[0].link;
        int *done = g_job[0].done;
        memmove(g_job, g_job + 1, (size_t)(g_job_n - 1) * sizeof g_job[0]);
        g_job_n--;
        tr_xmux_dial(link, 2);
        __atomic_store_n(done, 1, __ATOMIC_RELEASE);
    }
}

static void turn(void) {
    jobs_run();
    tr_xmux_pass(g_now, MUXP_EARLY);
    struct epoll_event ev[16];
    int n = epoll_wait(g_ep, ev, 16, 3);
    for (int i = 0; i < n; i++) tr_xmux_event(ev[i].data.u32, ev[i].events);
    tr_xmux_pass(g_now, MUXP_LATE);
}

static void turns(int n) {
    for (int i = 0; i < n; i++) turn();
}

static int done_rc(uint16_t owner) {
    for (int i = 0; i < g_gw_n; i++)
        if (g_gw[i].owner == owner && (g_gw[i].what & XW_DONE)) return g_gw[i].rc;
    return 1;
}

static int room_wakes(uint16_t owner) {
    int k = 0;
    for (int i = 0; i < g_gw_n; i++)
        if (g_gw[i].owner == owner && (g_gw[i].what & XW_ROOM)) k++;
    return k;
}

static int read_wakes(uint16_t owner) {
    int k = 0;
    for (int i = 0; i < g_gw_n; i++)
        if (g_gw[i].owner == owner && (g_gw[i].what & XW_READ)) k++;
    return k;
}

static uint64_t ms_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

#define UNTIL(cond)                                                    \
    do {                                                               \
        uint64_t dl_ = ms_now() + 3000;                                \
        while (!(cond) && ms_now() < dl_) turn();                      \
    } while (0)

static struct transport g_t[8], g_many[64];
static struct xc_ref g_ref;
static char g_key[4];

static struct tr_node gl_node(uint16_t port, const char *xhx) {
    struct tr_node n;
    memset(&n, 0, sizeof n);
    n.host = "127.0.0.1";
    n.port = port;
    n.type = "xhttp";
    n.security = "none";
    n.sni = "";
    n.fp = "chrome";
    n.path = "/x";
    n.mode = "stream-one";
    n.xhx = xhx;
    return n;
}

static int gl_attach(int i, const struct tr_node *n, const void *key) {
    g_ref.node = key;
    tr_xmux_pass(g_now, MUXP_EARLY);
    return tr_xmux_attach(&g_t[i], n, key, NULL, (uint16_t)i, &g_ref);
}

static int gl_ready(int i) { return g_t[i].xh.f.one.x != NULL || g_t[i].xh.f.down.x != NULL; }

static size_t gl_got[8];
static unsigned char gl_buf[8][256];

static int gl_read(int i) {
    size_t got = 0;
    int rc = transport_read(&g_t[i], gl_buf[i] + gl_got[i], sizeof gl_buf[i] - gl_got[i], &got);
    gl_got[i] += got;
    return rc;
}

static int gl_echo(int i, const char *msg) {
    size_t n = strlen(msg);
    gl_got[i] = 0;
    if (transport_write(&g_t[i], (const unsigned char *)msg, n)) return 0;
    uint64_t dl = ms_now() + 3000;
    while (gl_got[i] < n && ms_now() < dl) {
        turn();
        if (gl_read(i)) return 0;
    }
    return gl_got[i] == n && !memcmp(gl_buf[i], msg, n);
}

static void gl_close(int i) {
    transport_close(&g_t[i]);
    memset(&g_t[i], 0, sizeof g_t[i]);
}

static void gl_begin(int mcs) {
    g_gw_n = g_job_n = g_jobs = g_hold = g_stale_on = 0;
    g_stale_node = g_stale_node2 = NULL;
    tr_xmux_links_cap = XC_MAX;
    tr_xmux_mgrs_cap = XM_MGRS;
    memset(g_t, 0, sizeof g_t);
    if (g_ep < 0) g_ep = epoll_create1(0);
    tr_xmux_host(&GL_HOST, gl_stale);
    p_start(mcs);
}

static void gl_end(void) {
    for (int i = 0; i < 8; i++)
        if (g_t[i].fr) gl_close(i);
    g_hold = 0;
    jobs_run();
    tr_xmux_pass(g_now, MUXP_EXIT);
    p_stop();
    g_now += 1000000;
}

static void t_two_flows_one_accept(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    /* catches: a link per flow */
    check("glue one: first waits", XA_WAIT, gl_attach(0, &n, g_key));
    check("glue one: second waits", XA_WAIT, gl_attach(1, &n, g_key));
    UNTIL(gl_ready(0) && gl_ready(1) && P_NSID(0) == 2);
    check("glue one: one dial", 1, g_jobs);
    check("glue one: one accept", 1, P_ACCEPTS());
    check("glue one: sid 1", 1, P_SID(0, 0));
    check("glue one: sid 3", 3, P_SID(0, 1));
    check("glue one: flow 0 echo", 1, gl_echo(0, "alpha"));
    check("glue one: flow 1 echo", 1, gl_echo(1, "bravo-two"));
    gl_end();
}

static void t_first_headers_before_ack(void) {
    gl_begin(0);
    P_SET(early, 100);
    struct tr_node n = gl_node(g_p.port, "");
    /* catches: the adoption read putting the ACK before the first HEADERS */
    check("first headers: flow waits", XA_WAIT, gl_attach(0, &n, g_key));
    jobs_run();
    uint64_t dl = ms_now() + 3000;
    while (P_ACCEPTS() < 1 && ms_now() < dl) usleep(1000);
    check("first headers: peer accepted and wrote SETTINGS", 1, P_ACCEPTS());
    UNTIL(gl_ready(0) && p_ord_len(0) >= 10);
    check("first headers: SETTINGS, WINDOW_UPDATE(0), HEADERS(1), ACK", 1, p_ord_starts(0, "S W0 H1 A "));
    gl_end();
}

static void t_refused_before_settings_retried(void) {
    gl_begin(0);
    P_SET(early, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    /* catches: a stream refused before the server's SETTINGS failing its flow or its client */
    check("refused: first waits", XA_WAIT, gl_attach(0, &n, g_key));
    check("refused: second waits", XA_WAIT, gl_attach(1, &n, g_key));
    jobs_run();
    uint64_t dl = ms_now() + 3000;
    while (P_ACCEPTS() < 1 && ms_now() < dl) usleep(1000);
    UNTIL(gl_ready(0) && gl_ready(1) && read_wakes(1) > 0);
    check("refused: the server refused sid 3", 1, P_NSID(0) == 2);
    check("refused: the read reports no error", 0, gl_read(1));
    check("refused: re-placed on a dialing link", 1, g_t[1].xh.f.wait != NULL);
    check("refused: a read while waiting is quiet", 0, gl_read(1));
    check("refused: a write while waiting is held", H2_EWINDOW, transport_write(&g_t[1], (const unsigned char *)"y", 1));
    int rw = room_wakes(1);
    UNTIL(gl_ready(1) && P_ACCEPTS() == 2 && P_NSID(1) == 1);
    check("refused: served flow told of room", 1, room_wakes(1) > rw);
    check("refused: retried on a second connection", 2, P_ACCEPTS());
    check("refused: same client", 1, g_t[1].xh.f.cl != NULL && g_t[1].xh.f.cl == g_t[0].xh.f.cl);
    check("refused: client not failed", 0, g_t[1].xh.f.cl ? g_t[1].xh.f.cl->closed : -1);
    check("refused: flow 1 echo", 1, gl_echo(1, "bravo"));
    check("refused: flow 0 echo", 1, gl_echo(0, "alpha"));
    gl_end();
}

static void t_refused_after_write_ends(void) {
    gl_begin(0);
    P_SET(early, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    /* catches: a refused stream retried after its bytes went out, or its end failing the client */
    check("refused written: first waits", XA_WAIT, gl_attach(0, &n, g_key));
    check("refused written: second waits", XA_WAIT, gl_attach(1, &n, g_key));
    jobs_run();
    uint64_t dl = ms_now() + 3000;
    while (P_ACCEPTS() < 1 && ms_now() < dl) usleep(1000);
    UNTIL(gl_ready(0) && gl_ready(1));
    check("refused written: write before the refusal", 0, transport_write(&g_t[1], (const unsigned char *)"x", 1));
    UNTIL(read_wakes(1) > 0);
    check("refused written: the flow ends refused", XC_EREFUSED, gl_read(1));
    check("refused written: a cut without lost", 2, tr_xmux_cut(&g_t[1]));
    struct xm_client *cl = g_t[1].xh.f.cl;
    gl_close(1);
    check("refused written: no second connection", 1, P_ACCEPTS());
    check("refused written: client not failed", 0, cl ? cl->closed : -1);
    check("refused written: flow 0 echo", 1, gl_echo(0, "alpha"));
    gl_end();
}

static void t_refused_retry_fails(void) {
    gl_begin(0);
    P_SET(early, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    /* catches: a re-placed flow whose new link failed reading as if nothing happened */
    check("refused retry fails: first waits", XA_WAIT, gl_attach(0, &n, g_key));
    check("refused retry fails: second waits", XA_WAIT, gl_attach(1, &n, g_key));
    jobs_run();
    uint64_t dl = ms_now() + 3000;
    while (P_ACCEPTS() < 1 && ms_now() < dl) usleep(1000);
    UNTIL(gl_ready(0) && gl_ready(1) && read_wakes(1) > 0);
    check("refused retry fails: re-placed", 0, gl_read(1));
    P_SET(shut, 1);
    dl = ms_now() + 3000;
    while (p_get(22, 0, 0) >= 0 && ms_now() < dl) usleep(1000);
    int rw = read_wakes(1);
    UNTIL(read_wakes(1) > rw);
    check("refused retry fails: the read reports the dial", TR_ECONNREFUSED, gl_read(1));
    check("refused retry fails: and keeps reporting it", TR_ECONNREFUSED, gl_read(1));
    gl_end();
}

static const uint32_t *g_script;
static int g_script_k;

static uint32_t rnd_three(uint32_t n) {
    if (n == 3) return g_script[g_script_k++];
    return 0;
}

static void t_default_three(void) {
    static const uint32_t s[] = { 0, 2 };
    gl_begin(0);
    g_script = s;
    g_script_k = 0;
    tr_xmux_rnd = rnd_three;
    struct tr_node n = gl_node(g_p.port, NULL);
    /* catches: the default of 3 not applied on the wire */
    for (int i = 0; i < 3; i++) gl_attach(i, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && gl_ready(2) && P_NSID(2) == 1);
    check("glue default: three accepts", 3, P_ACCEPTS());
    check("glue default: flow 4 ready", XA_READY, gl_attach(3, &n, g_key));
    check("glue default: flow 5 ready", XA_READY, gl_attach(4, &n, g_key));
    UNTIL(P_NSID(0) == 2 && P_NSID(2) == 2);
    check("glue default: still three accepts", 3, P_ACCEPTS());
    check("glue default: flow 4 on link 1", 3, P_SID(0, 1));
    check("glue default: link 2 one stream", 1, P_NSID(1));
    check("glue default: flow 5 on link 3", 3, P_SID(2, 1));
    check("glue default: two picks drawn", 2, g_script_k);
    check("glue default: flow 4 echo", 1, gl_echo(3, "four"));
    tr_xmux_rnd = rnd_zero;
    gl_end();
}

static void t_waiters_share_a_dial(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    g_hold = 1;
    /* catches: one dial per waiter */
    check("glue waiters: first waits", XA_WAIT, gl_attach(0, &n, g_key));
    check("glue waiters: second waits", XA_WAIT, gl_attach(1, &n, g_key));
    check("glue waiters: one connector job", 1, g_jobs);
    turns(2);
    check("glue waiters: nothing before the dial", 2, done_rc(0) + done_rc(1));
    g_hold = 0;
    jobs_run();
    tr_xmux_pass(g_now, MUXP_EARLY);
    check("glue waiters: first done in the pass", 0, done_rc(0));
    check("glue waiters: second done in the same pass", 0, done_rc(1));
    UNTIL(P_NSID(0) == 2);
    check("glue waiters: HEADERS 1 after the preface", 1, P_SID(0, 0));
    check("glue waiters: HEADERS 3 after the preface", 3, P_SID(0, 1));
    gl_end();
}

/* catches: a failed dial never retried, retried more than once, or its code lost */
static void t_dial_fail_retries_once(void) {
    gl_begin(0);
    int fd;
    uint16_t dead = lo_listen(&fd);
    close(fd);
    struct tr_node n = gl_node(dead, "xmux.maxConnections=1\n");
    check("glue dial fail: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(done_rc(0) != 1);
    turns(3);
    check("glue dial fail: two dials", 2, g_jobs);
    check("glue dial fail: refused", TR_ECONNREFUSED, done_rc(0));
    gl_end();
}

static void t_close_cancels(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    gl_echo(0, "x");
    /* catches: a flow end that leaves the stream open, or closes the shared link */
    gl_close(0);
    UNTIL(P_NRST(0) == 1);
    check("glue close: RST_STREAM sid", 1, P_RSID(0, 0));
    check("glue close: RST_STREAM CANCEL", 8, P_RCODE(0, 0));
    turns(3);
    check("glue close: link open", 1, P_OPEN(0));
    check("glue close: next flow ready", XA_READY, gl_attach(1, &n, g_key));
    check("glue close: no second dial", 1, g_jobs);
    gl_end();
}

static void t_kill_resets_both(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    gl_attach(0, &n, g_key);
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && P_NSID(0) == 2);
    struct xm_client *cl = g_t[0].xh.f.cl;
    int before = g_gw_n;
    /* catches: flows left on a dead link */
    p_cmd(0, 1, 0, 0);
    UNTIL(read_wakes(0) && read_wakes(1));
    check("glue kill: both woken", 1, read_wakes(0) && read_wakes(1) && g_gw_n > before);
    check("glue kill: read 0 fails", 1, gl_read(0) < 0);
    check("glue kill: read 1 fails", 1, gl_read(1) < 0);
    check("glue kill: cut 0 tells lost", 1, tr_xmux_cut(&g_t[0]));
    check("glue kill: cut 1", 1, tr_xmux_cut(&g_t[1]));
    check("glue kill: client failed", 1, cl->closed);
    gl_close(0);
    gl_close(1);
    check("glue kill: next flow waits", XA_WAIT, gl_attach(2, &n, g_key));
    UNTIL(gl_ready(2) && P_ACCEPTS() == 2);
    check("glue kill: a new link", 2, P_ACCEPTS());
    check("glue kill: under a new client", INT32_MAX - 1, g_t[2].xh.f.cl->left_requests);
    check("glue kill: the new client not failed", 0, g_t[2].xh.f.cl->closed);
    check("glue kill: new flow echo", 1, gl_echo(2, "again"));
    gl_end();
}

static void t_idle_redial(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hMaxRequestTimes=5\nxmux.hKeepAlivePeriod=-1\n");
    gl_attach(0, &n, g_key);
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && P_NSID(0) == 2);
    struct xm_client *cl = g_t[0].xh.f.cl;
    gl_close(0);
    gl_close(1);
    uint64_t t0 = g_now;
    /* catches: no idle close, or the client's counters reset by a re-dial */
    for (g_now = t0 + 1000; g_now < t0 + 300000; g_now += 1000) turn();
    g_now = t0 + 299000;
    turns(3);
    check("glue idle: open at 299 s", 1, P_OPEN(0));
    g_now = t0 + 300000;
    UNTIL(P_EOF(0));
    check("glue idle: peer EOF at 300 s", 1, P_EOF(0));
    check("glue idle: no TCP reset", 0, P_RST(0));
    check("glue idle: client not failed", 0, cl->closed);
    check("glue idle: third flow waits", XA_WAIT, gl_attach(2, &n, g_key));
    check("glue idle: same client", 1, g_t[2].xh.f.cl == cl);
    check("glue idle: left_requests", 2, cl->left_requests);
    UNTIL(gl_ready(2) && P_ACCEPTS() == 2);
    check("glue idle: a new TCP", 2, P_ACCEPTS());
    gl_end();
}

static void t_retire_after_requests(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hMaxRequestTimes=2\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0));
    gl_echo(0, "one");
    gl_close(0);
    check("glue retire: flow 2 ready", XA_READY, gl_attach(1, &n, g_key));
    gl_echo(1, "two");
    gl_close(1);
    turns(5);
    /* catches: retirement by a timer or at the last flow instead of the next sweep */
    check("glue retire: open after flow 2", 1, P_OPEN(0));
    check("glue retire: flow 3 waits", XA_WAIT, gl_attach(2, &n, g_key));
    UNTIL(P_GONE(0) && gl_ready(2) && P_ACCEPTS() == 2);
    check("glue retire: swept at flow 3", 1, P_GONE(0));
    check("glue retire: second accept", 2, P_ACCEPTS());
    check("glue retire: flow 3 echo", 1, gl_echo(2, "three"));
    gl_end();
}

static void t_goaway_no_new_flow(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    gl_attach(0, &n, g_key);
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && P_NSID(0) == 2);
    int jobs = g_jobs;
    /* catches: the amendment's GOAWAY split lost in the glue */
    p_cmd(0, 0, 1, 1);
    UNTIL(read_wakes(1));
    check("glue goaway: sid 3 ends", XC_EGOAWAY, gl_read(1));
    check("glue goaway: sid 3 gets RST, the node no lost", 2, tr_xmux_cut(&g_t[1]));
    check("glue goaway: sid 1 finishes", 1, gl_echo(0, "still"));
    check("glue goaway: new flow waits", XA_WAIT, gl_attach(2, &n, g_key));
    check("glue goaway: a new dial", jobs + 1, g_jobs);
    check("glue goaway: under a new client", 1, g_t[2].xh.f.cl != g_t[0].xh.f.cl);
    UNTIL(gl_ready(2) && P_ACCEPTS() == 2);
    check("glue goaway: new link", 2, P_ACCEPTS());
    gl_close(1);
    gl_close(0);
    UNTIL(P_GONE(0));
    check("glue goaway: old link closed after its last flow", 1, P_GONE(0));
    /* catches: the last flow's RST_STREAM dropped when its close frees the link */
    check("glue goaway: the last RST_STREAM sent before the close", 1, P_RSID(0, P_NRST(0) - 1));
    gl_end();
}

static void t_goaway_none_refused(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hMaxRequestTimes=10\n");
    gl_attach(0, &n, g_key);
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && P_NSID(0) == 2);
    struct xm_client *cl = g_t[0].xh.f.cl;
    /* catches: a GOAWAY that refused nothing retiring the client and its counters */
    p_cmd(0, 0, 1, 3);
    turns(20);
    check("glue goaway kept: sid 3 still works", 1, gl_echo(1, "kept"));
    check("glue goaway kept: client not failed", 0, cl->closed);
    check("glue goaway kept: new flow waits", XA_WAIT, gl_attach(2, &n, g_key));
    check("glue goaway kept: same client", 1, g_t[2].xh.f.cl == cl);
    check("glue goaway kept: counters kept", 7, cl->left_requests);
    UNTIL(gl_ready(2) && P_ACCEPTS() == 2);
    check("glue goaway kept: a new link", 2, P_ACCEPTS());
    check("glue goaway kept: new flow echo", 1, gl_echo(2, "new"));
    gl_end();
}

static void t_reset_before_headers(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    gl_echo(0, "fine");
    struct xm_client *cl = g_t[0].xh.f.cl;
    /* catches: a stream reset after its 200 marking the client failed */
    p_rst(0, 1);
    UNTIL(gl_read(0) != 0);
    gl_close(0);
    check("glue reset after 200: client kept", 0, cl->closed);
    pthread_mutex_lock(&g_p.mu);
    g_p.refuse = 1;
    pthread_mutex_unlock(&g_p.mu);
    /* catches: a request refused before its answer leaving the client in use, as Xray's IsClosed would not */
    check("glue reset before headers: ready", XA_READY, gl_attach(1, &n, g_key));
    UNTIL(read_wakes(1) && gl_read(1) != 0);
    check("glue reset before headers: ends as a reset", H2_ERESET, gl_read(1));
    gl_close(1);
    check("glue reset before headers: client failed", 1, cl->closed);
    gl_end();
}

static void t_close_sends_fin(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hMaxRequestTimes=1\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0));
    gl_echo(0, "only");
    gl_close(0);
    turns(5);
    p_ping_sent(0);
    /* catches: a link closed with unread bytes in its socket, which the kernel answers with RST */
    gl_attach(1, &n, g_key);
    UNTIL(P_EOF(0) || P_RST(0));
    check("glue clean close: peer EOF", 1, P_EOF(0));
    check("glue clean close: no TCP reset", 0, P_RST(0));
    gl_end();
}

static void t_overflow_by_stream_cap(void) {
    gl_begin(1);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(5);
    /* catches: the server's limit breaking the second flow */
    check("glue cap: second waits", XA_WAIT, gl_attach(1, &n, g_key));
    UNTIL(gl_ready(1) && P_ACCEPTS() == 2);
    check("glue cap: two accepts", 2, P_ACCEPTS());
    check("glue cap: one client", 1, g_t[0].xh.f.cl == g_t[1].xh.f.cl);
    check("glue cap: running 2", 2, g_t[0].xh.f.cl->running);
    check("glue cap: second echo", 1, gl_echo(1, "over"));
    gl_end();
}

static void t_links_cap_closes_idle(void) {
    static const uint32_t s[] = { 1, 0 };
    gl_begin(0);
    tr_xmux_links_cap = 2;
    g_script = s;
    g_script_k = 0;
    tr_xmux_rnd = rnd_three;
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=3\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0));
    gl_close(0);
    g_now += 1000;
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(1));
    gl_close(1);
    g_now += 1000;
    /* catches: a link table that grows past its cap or closes a busy or dialing link */
    g_hold = 1;
    check("glue links cap: third waits", XA_WAIT, gl_attach(2, &n, g_key));
    UNTIL(P_GONE(0));
    check("glue links cap: LRU closed", 1, P_GONE(0));
    check("glue links cap: second kept", 1, P_OPEN(1));
    check("glue links cap: third dialled", 3, g_jobs);
    gl_close(2);
    g_now += 1000;
    check("glue links cap: on the kept link", XA_READY, gl_attach(3, &n, g_key));
    gl_close(3);
    g_now += 1000;
    check("glue links cap: first client re-dials", XA_WAIT, gl_attach(4, &n, g_key));
    UNTIL(P_GONE(1));
    check("glue links cap: idle live link closed, not the dialing one", 1, P_GONE(1));
    check("glue links cap: two dialing", 2, tr_xmux_busy());
    check("glue links cap: four dials", 4, g_jobs);
    tr_xmux_rnd = rnd_zero;
    gl_end();
}

static void t_links_cap_shares_busy(void) {
    gl_begin(1);
    tr_xmux_links_cap = 2;
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(5);
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(1) && P_NSID(1) == 1);
    turns(5);
    /* catches: a flow refused while a usable link exists, or a link opened past the cap */
    check("glue share busy: waits on a link", XA_WAIT, gl_attach(2, &n, g_key));
    check("glue share busy: no dial", 2, g_jobs);
    gl_close(0);
    UNTIL(gl_ready(2) && P_NSID(0) == 2);
    check("glue share busy: served", 0, done_rc(2));
    check("glue share busy: still two accepts", 2, P_ACCEPTS());
    check("glue share busy: on the first link", 3, P_SID(0, 1));
    static char other[4];
    struct tr_node n2 = gl_node(g_p.port, "xmux.maxConnections=1\n");
    check("glue share busy: a client with no link fails", 1, gl_attach(3, &n2, other) < 0);
    check("glue share busy: still no dial", 2, g_jobs);
    gl_end();
}

static void t_mgrs_cap(void) {
    static char k1[4], k2[4], k3[4];
    gl_begin(0);
    tr_xmux_mgrs_cap = 2;
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hKeepAlivePeriod=-1\n");
    gl_attach(0, &n, k1);
    gl_attach(1, &n, k2);
    UNTIL(gl_ready(0) && gl_ready(1));
    /* catches: manager table overflow */
    check("glue mgrs: third node per flow", XA_NONE, gl_attach(2, &n, k3));
    check("glue mgrs: no state taken", 0, g_t[2].fr != NULL);
    gl_close(0);
    turns(3);
    check("glue mgrs: a manager with a link stays", XA_NONE, gl_attach(2, &n, k3));
    uint64_t t0 = g_now;
    for (g_now = t0 + 1000; g_now <= t0 + 300000; g_now += 1000) turn();
    UNTIL(P_GONE(0));
    check("glue mgrs: node 1 link closed", 1, P_GONE(0));
    check("glue mgrs: third node shares now", XA_WAIT, gl_attach(2, &n, k3));
    check("glue mgrs: node 1 lost its slot", XA_NONE, gl_attach(3, &n, k1));
    gl_end();
}

static void t_stale_node_closes(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=2\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0));
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(1) && P_ACCEPTS() == 2);
    gl_close(0);
    turns(3);
    check("glue stale: idle link open while fresh", 1, P_OPEN(0));
    /* catches: a connection kept alive by PING to a removed node */
    g_stale_on = 1;
    g_stale_node = g_key;
    g_now += 1000;
    UNTIL(P_GONE(0));
    check("glue stale: idle link closed", 1, P_GONE(0));
    turns(3);
    check("glue stale: busy link kept", 1, P_OPEN(1));
    gl_close(1);
    UNTIL(P_GONE(1));
    check("glue stale: busy link closed at its flow's end", 1, P_GONE(1));
    gl_end();
}

static void t_ping_wired(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hKeepAlivePeriod=2\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(5);
    uint64_t t0 = g_now;
    /* catches: the keepalive built but not called */
    g_now = t0 + 1000;
    turns(5);
    check("glue ping: none at 1 s", 0, P_PINGS(0));
    g_now = t0 + 2000;
    UNTIL(P_PINGS(0) == 1);
    check("glue ping: one at 2 s", 1, P_PINGS(0));
    gl_end();
}

static void t_encryption_stays_private(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, NULL);
    n.encryption = "mlkem768x25519plus.native.0rtt.AAAA";
    /* catches: an encryption node put on a shared link, whose handshake would block the loop */
    check("glue encryption: per flow", XA_NONE, gl_attach(0, &n, g_key));
    check("glue encryption: no dial", 0, g_jobs);
    gl_end();
}

static int gl_send(int i, const char *msg) {
    uint64_t dl = ms_now() + 3000;
    int rc;
    while ((rc = transport_write(&g_t[i], (const unsigned char *)msg, strlen(msg))) == H2_EWINDOW && ms_now() < dl)
        turn();
    return rc;
}

static int gl_until_read(int i) {
    uint64_t dl = ms_now() + 3000;
    int rc = 0;
    while (!(rc = gl_read(i)) && ms_now() < dl) turn();
    return rc;
}

static struct tr_node gl_mode(const char *xhx, const char *mode) {
    static char buf[8][256];
    static int k;
    if (!strcmp(mode, "packet-up") && !strstr(xhx, "scMinPostsIntervalMs")) {
        char *b = buf[k++ % 8];
        snprintf(b, sizeof buf[0], "%sscMinPostsIntervalMs=-1\n", xhx);
        xhx = b;
    }
    struct tr_node n = gl_node(g_p.port, xhx);
    n.mode = mode;
    return n;
}

static int gl_post(int i, const char *msg) {
    int rc = transport_write(&g_t[i], (const unsigned char *)msg, strlen(msg));
    UNTIL(!g_t[i].xh.f.bat.n);
    return rc;
}

static void t_refused_stream_up_reads_again(void) {
    gl_begin(0);
    P_SET(split, 1);
    P_SET(early, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    P_SET(over_c0, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "stream-up");
    /* catches: a re-placed stream-up flow left answering every read with nothing */
    check("refused up: waits", XA_WAIT, gl_attach(0, &n, g_key));
    jobs_run();
    uint64_t dl = ms_now() + 3000;
    while (P_ACCEPTS() < 1 && ms_now() < dl) usleep(1000);
    UNTIL(gl_ready(0) && read_wakes(0) > 0 && P_NSID(0) == 2);
    check("refused up: the POST refused, the read reports no error", 0, gl_read(0));
    UNTIL(gl_ready(0) && g_t[0].xh.f.up.x && P_ACCEPTS() == 2 && P_NSID(1) == 2);
    check("refused up: GET and POST on the second connection", 2, P_NSID(1));
    check("refused up: echo through the new GET", 1, gl_echo(0, "upward"));
    gl_end();
}

static void t_refused_twice_ends(void) {
    gl_begin(0);
    P_SET(over, 1);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    /* catches: a refused flow re-placed again and again */
    check("refused twice: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && read_wakes(0) > 0);
    int rc = 0;
    for (uint64_t dl = ms_now() + 3000; !rc && ms_now() < dl;) {
        turn();
        rc = gl_read(0);
    }
    check("refused twice: the flow ends refused", XC_EREFUSED, rc);
    check("refused twice: exactly one retry", 2, P_NSID(0));
    check("refused twice: on one connection", 1, P_ACCEPTS());
    gl_end();
}

static void t_refused_post_resent(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(nosettings, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    P_SET(over_left, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    /* catches: a POST refused before the server's SETTINGS losing its bytes, ending the flow or failing its client */
    check("refused post: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("refused post: seq 0 taken", 0, gl_post(0, "p0"));
    gl_got[0] = 0;
    uint64_t dl = ms_now() + 3000;
    int rc = 0;
    while (gl_got[0] < 2 && ms_now() < dl && !(rc = gl_read(0))) turn();
    check("refused post: refused once, sent again", 3, P_NSID(0));
    check("refused post: sent again with the same path and seq", 1, p_paths_is(0, 1, 2));
    check("refused post: the server got its bytes once", 1, p_up_is(0, "p0"));
    check("refused post: the flow reads on", 0, rc);
    check("refused post: the echo arrives", 1, gl_got[0] == 2 && !memcmp(gl_buf[0], "p0", 2));
    check("refused post: client not failed", 0, g_t[0].xh.f.cl ? g_t[0].xh.f.cl->closed : -1);
    check("refused post: one connection", 1, P_ACCEPTS());
    gl_end();
}

static void t_refused_get_reopened(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(lim, 0);
    P_SET(over, 1);
    P_SET(over_left, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    /* catches: a refused GET ending a flow that already wrote */
    check("refused get: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0));
    check("refused get: written before the refusal", 0, transport_write(&g_t[0], (const unsigned char *)"g0", 2));
    UNTIL(P_UPN(0) == 2 && read_wakes(0) > 0);
    check("refused get: the read reports no error", 0, gl_read(0));
    UNTIL(P_NSID(0) == 3 && g_t[0].xh.f.down.x);
    check("refused get: GET opened again", 3, P_NSID(0));
    check("refused get: the server got g0", 1, p_up_is(0, "g0"));
    check("refused get: echo through the new GET", 1, gl_echo(0, "g1"));
    check("refused get: client not failed", 0, g_t[0].xh.f.cl ? g_t[0].xh.f.cl->closed : -1);
    gl_end();
}

static void t_refused_post_unkept(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(lim, 1);
    P_SET(over, 1);
    P_SET(over_left, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    /* catches: a POST refused after the server's SETTINGS failing the client */
    check("refused post unkept: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("refused post unkept: seq 0 taken", 0, gl_post(0, "p0"));
    int rc = 0;
    for (uint64_t dl = ms_now() + 3000; !rc && ms_now() < dl;) {
        turn();
        rc = gl_read(0);
    }
    check("refused post unkept: the flow ends refused", XC_EREFUSED, rc);
    check("refused post unkept: not sent again", 2, P_NSID(0));
    check("refused post unkept: client not failed", 0, g_t[0].xh.f.cl ? g_t[0].xh.f.cl->closed : -1);
    gl_end();
}

static void t_refused_post_bounded(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(nosettings, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    /* catches: a refused POST sent again without a bound */
    check("refused post bounded: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("refused post bounded: seq 0 taken", 0, gl_post(0, "p0"));
    int rc = 0;
    for (uint64_t dl = ms_now() + 3000; !rc && ms_now() < dl;) {
        turn();
        rc = gl_read(0);
    }
    check("refused post bounded: the flow ends refused", XC_EREFUSED, rc);
    check("refused post bounded: GET and three tries of seq 0", 4, P_NSID(0));
    check("refused post bounded: client not failed", 0, g_t[0].xh.f.cl ? g_t[0].xh.f.cl->closed : -1);
    gl_end();
}

static void t_refused_get_twice_ends(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(lim, 0);
    P_SET(over, 1);
    P_SET(over_left, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    /* catches: a refused GET opened again and again */
    check("refused get twice: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0));
    int rc = 0;
    for (uint64_t dl = ms_now() + 3000; !rc && ms_now() < dl;) {
        turn();
        rc = gl_read(0);
    }
    check("refused get twice: the flow ends refused", XC_EREFUSED, rc);
    check("refused get twice: exactly one retry", 2, P_NSID(0));
    gl_end();
}

static void t_refused_get_waits(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(hold, 1);
    P_SET(early, 2);
    P_SET(lim, 0);
    P_SET(over, 1);
    P_SET(over_left, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    struct tr_node nb = gl_node(g_p.port, "xmux.maxConnections=1\n");
    /* catches: a refused GET re-opened on a full link, or never opened when its link comes */
    check("refused get waits: waits", XA_WAIT, gl_attach(0, &n, g_key));
    jobs_run();
    uint64_t dl = ms_now() + 3000;
    while (P_ACCEPTS() < 1 && ms_now() < dl) usleep(1000);
    UNTIL(gl_ready(0) && read_wakes(0) > 0);
    check("refused get waits: written after the refusal", 0, transport_write(&g_t[0], (const unsigned char *)"g0", 2));
    UNTIL(P_NSID(0) == 2 && P_UPN(0) == 2);
    gl_attach(1, &nb, g_key);
    UNTIL(gl_ready(1) && P_NSID(0) == 3);
    check("refused get waits: a POST and another flow fill the link", 3, P_NSID(0));
    check("refused get waits: the read reports no error", 0, gl_read(0));
    check("refused get waits: the GET waits for a link", 1, g_t[0].xh.f.wait != NULL);
    UNTIL(g_t[0].xh.f.down.x && P_ACCEPTS() == 2 && P_NSID(1) == 1);
    check("refused get waits: GET opened on the second connection", 1, P_NSID(1));
    p_release(0);
    check("refused get waits: echo through the new GET", 1, gl_echo(0, "g1"));
    check("refused get waits: the flow kept its seq", 2, (long)g_t[0].xh.seq);
    gl_end();
}

static void t_refused_post_past_window(void) {
    static char big[201];
    memset(big, 'w', 200);
    gl_begin(0);
    P_SET(split, 2);
    P_SET(nosettings, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    P_SET(over_left, 1);
    P_SET(iwin, 64);
    xc_pend_set(150);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    /* catches: a re-sent POST larger than the server's stream window held back for ever, or held for more than its excess */
    check("refused past window: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("refused past window: 200 B taken", 0, gl_post(0, big));
    gl_got[0] = 0;
    uint64_t dl = ms_now() + 3000;
    int rc = 0;
    while (gl_got[0] < 200 && ms_now() < dl && !(rc = gl_read(0))) turn();
    check("refused past window: sent again", 3, P_NSID(0));
    check("refused past window: the server got all 200 B once", 1, p_up_is(0, big));
    check("refused past window: GET without, both POSTs with content-length 200", 1, p_cls_is(0, "- 200 200 "));
    check("refused past window: the flow reads on", 0, rc);
    check("refused past window: the echo arrives", 1, gl_got[0] == 200 && !memcmp(gl_buf[0], big, 200));
    check("refused past window: nothing waits to be sent again", 0, g_t[0].xh.f.redo_n);
    gl_end();
    xc_pend_set(XC_PEND_MAX);
}

static void t_refused_post_past_pend(void) {
    static char big[201];
    memset(big, 'w', 200);
    gl_begin(0);
    P_SET(split, 2);
    P_SET(nosettings, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    P_SET(over_left, 1);
    P_SET(iwin, 64);
    xc_pend_set(100);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    /* catches: a re-send the held bytes cannot carry left hanging or sent in part */
    check("refused past pend: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("refused past pend: 200 B taken", 0, gl_post(0, big));
    int rc = 0;
    for (uint64_t dl = ms_now() + 3000; !rc && ms_now() < dl;) {
        turn();
        rc = gl_read(0);
    }
    check("refused past pend: the flow ends refused", XC_EREFUSED, rc);
    check("refused past pend: not sent again", 2, P_NSID(0));
    check("refused past pend: client not failed", 0, g_t[0].xh.f.cl ? g_t[0].xh.f.cl->closed : -1);
    gl_end();
    xc_pend_set(XC_PEND_MAX);
}

static unsigned char g_stk[512 * 1024] __attribute__((aligned(4096)));
struct stk_job { void (*fn)(void); };

static void *stk_run(void *a) {
    ((struct stk_job *)a)->fn();
    return NULL;
}

static size_t stack_used(void (*fn)(void)) {
    memset(g_stk, 0xa5, sizeof g_stk);
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstack(&at, g_stk, sizeof g_stk);
    struct stk_job j = { fn };
    pthread_t th;
    if (pthread_create(&th, &at, stk_run, &j)) return SIZE_MAX;
    pthread_join(th, NULL);
    pthread_attr_destroy(&at);
    size_t i = 0;
    while (i < sizeof g_stk && g_stk[i] == 0xa5) i++;
    return sizeof g_stk - i;
}

static void stk_idle(void) {}

/* catches: block-sized buffers on the loop stack in the re-send path */
static void t_redo_stack(void) {
    size_t base = stack_used(stk_idle), used = stack_used(t_refused_post_past_window);
    printf("     redo path stack: %zu B over %zu B\n", used - base, base);
#ifndef __SANITIZE_ADDRESS__
    check("redo stack: the re-send path under 16 KiB", 1, used - base < 16384);
#endif
}

static void t_refused_post_pend_busy(void) {
    static char big[201];
    memset(big, 'w', 200);
    gl_begin(0);
    P_SET(split, 2);
    P_SET(nosettings, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    P_SET(over_left, 2);
    P_SET(iwin, 64);
    xc_pend_set(50);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    n.post_from = n.post_to = 100;
    /* catches: a re-send that finds the held bytes busy failing the flow instead of waiting for room */
    check("refused pend busy: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("refused pend busy: 200 B taken", 0, gl_post(0, big));
    gl_got[0] = 0;
    uint64_t dl = ms_now() + 3000;
    int rc = 0;
    while (gl_got[0] < 200 && ms_now() < dl && !(rc = gl_read(0))) turn();
    check("refused pend busy: two POSTs refused, both sent again", 5, P_NSID(0));
    check("refused pend busy: the flow reads on", 0, rc);
    check("refused pend busy: the echo arrives", 1, gl_got[0] == 200 && !memcmp(gl_buf[0], big, 200));
    check("refused pend busy: nothing waits to be sent again", 0, g_t[0].xh.f.redo_n);
    gl_end();
    xc_pend_set(XC_PEND_MAX);
}

static void t_refused_post_waits_for_slot(void) {
    static char big[201];
    memset(big, 'w', 200);
    gl_begin(0);
    P_SET(split, 2);
    P_SET(nosettings, 1);
    P_SET(lim, 1);
    P_SET(over, 1);
    P_SET(over_left, 1);
    P_SET(iwin, 64);
    P_SET(imcs, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    struct tr_node nb = gl_node(g_p.port, "xmux.maxConnections=1\n");
    /* catches: a re-send opened on a full link */
    check("refused slot: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("refused slot: 200 B taken", 0, gl_post(0, big));
    UNTIL(read_wakes(0) > 0 && P_NSID(0) == 2);
    gl_attach(1, &nb, g_key);
    UNTIL(gl_ready(1) && P_NSID(0) == 3);
    check("refused slot: the read reports no error", 0, gl_read(0));
    turns(3);
    check("refused slot: the re-send waits for a slot", 1, g_t[0].xh.f.redo_n);
    gl_close(1);
    gl_got[0] = 0;
    uint64_t dl = ms_now() + 3000;
    int rc = 0;
    while (gl_got[0] < 200 && ms_now() < dl && !(rc = gl_read(0))) turn();
    check("refused slot: sent again once the slot is free", 4, P_NSID(0));
    check("refused slot: the flow reads on", 0, rc);
    check("refused slot: the echo arrives", 1, gl_got[0] == 200 && !memcmp(gl_buf[0], big, 200));
    gl_end();
}

static void t_refused_get_own_deadline(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(hold, 1);
    P_SET(early, 2);
    P_SET(lim, 0);
    P_SET(over, 1);
    P_SET(over_left, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    struct tr_node nb = gl_node(g_p.port, "xmux.maxConnections=1\n");
    /* catches: a GET opened again waiting under the deadline of its first placement */
    check("get deadline: waits", XA_WAIT, gl_attach(0, &n, g_key));
    jobs_run();
    uint64_t dl = ms_now() + 3000;
    while (P_ACCEPTS() < 1 && ms_now() < dl) usleep(1000);
    UNTIL(gl_ready(0) && read_wakes(0) > 0);
    transport_write(&g_t[0], (const unsigned char *)"g0", 2);
    UNTIL(P_NSID(0) == 2 && P_UPN(0) == 2);
    gl_attach(1, &nb, g_key);
    UNTIL(gl_ready(1) && P_NSID(0) == 3);
    g_hold = 1;
    g_now += 7000;
    turn();
    check("get deadline: the read reports no error", 0, gl_read(0));
    check("get deadline: the GET waits for a dial", 1, g_t[0].xh.f.wait != NULL);
    g_now += 2000;
    turns(3);
    check("get deadline: still waiting 9 s after placement", 1, g_t[0].xh.f.wait != NULL);
    check("get deadline: no error yet", 0, gl_read(0));
    g_now += 7000;
    int rw = read_wakes(0);
    UNTIL(read_wakes(0) > rw);
    check("get deadline: its own deadline passed", TR_ECONNTIMEOUT, gl_read(0));
    g_hold = 0;
    gl_end();
}

static void t_stream_up_same_link(void) {
    gl_begin(0);
    P_SET(split, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\nxmux.hMaxRequestTimes=10\n", "stream-up");
    /* catches: the POST on another client, or running counted twice */
    check("stream-up: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 2);
    struct xh_flow *f = &g_t[0].xh.f;
    check("stream-up: one accept", 1, P_ACCEPTS());
    check("stream-up: GET sid 1", 1, P_SID(0, 0));
    check("stream-up: POST sid 3", 3, P_SID(0, 1));
    check("stream-up: GET and POST on one link", 1, f->down.x && f->down.x == f->up.x);
    check("stream-up: the link is shared, under the budget", 1, f->down.x->shared);
    check("stream-up: running 1", 1, f->cl->running);
    check("stream-up: two requests", 8, f->cl->left_requests);
    check("stream-up: echo through the GET", 1, gl_echo(0, "upward"));
    gl_end();
}

static void t_packet_up_posts_move(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.hMaxRequestTimes=3\n", "packet-up");
    check("packet move: waits", XA_WAIT, gl_attach(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xh_flow *f = &g_t[0].xh.f;
    struct xm_client *a = f->cl;
    check("packet move: GET on A", 2, a->left_requests);
    /* catches: the move done before the decrement, or the new client decremented */
    check("packet move: seq 0 sent", 0, gl_post(0, "s0"));
    check("packet move: seq 0 on A", 1, a->left_requests);
    check("packet move: still A", 1, f->cl_post == a);
    UNTIL(P_UPN(0) == 2);
    g_hold = 1;
    check("packet move: seq 1 taken while B is not there", 0, transport_write(&g_t[0], (const unsigned char *)"s1", 2));
    turns(3);
    check("packet move: A used up", 0, a->left_requests);
    check("packet move: A swept", 1, a->not_used);
    struct xm_client *b = f->cl_post;
    check("packet move: B created", 1, b != a);
    check("packet move: B full", 3, b->left_requests);
    check("packet move: seq 1 held for B's dial", 2, (int)f->bat.n);
    check("packet move: decided once while held", 0, a->left_requests);
    g_hold = 0;
    UNTIL(!f->bat.n);
    check("packet move: seq 1 not counted on B", 3, b->left_requests);
    check("packet move: seq 2 sent", 0, gl_post(0, "s2"));
    check("packet move: seq 2 on B", 2, b->left_requests);
    UNTIL(P_UPN(1) == 4);
    check("packet move: two accepts", 2, P_ACCEPTS());
    check("packet move: A saw GET and seq 0", 2, P_NSID(0));
    check("packet move: A got s0", 1, p_up_is(0, "s0"));
    check("packet move: B saw seq 1 and 2", 2, P_NSID(1));
    check("packet move: B got s1 s2", 1, p_up_is(1, "s1s2"));
    gl_got[0] = 0;
    uint64_t dl = ms_now() + 3000;
    while (gl_got[0] < 6 && ms_now() < dl && !gl_read(0)) turn();
    check("packet move: the GET on A carries all three", 1, gl_got[0] == 6 && !memcmp(gl_buf[0], "s0s1s2", 6));
    check("packet move: running counted once", 1, a->running);
    check("packet move: B not running", 0, b->running);
    gl_end();
}

/* catches: a GOAWAY-refused stream missed because its owner had closed it already */
static void t_goaway_refused_orphan(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(hold, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    check("goaway orphan: seq 0 sent", 0, gl_send(0, "s0"));
    UNTIL(P_NHELD(0) == 1);
    gl_close(0);
    turns(3);
    check("goaway orphan: the unanswered POST kept", 1, P_OPEN(0));
    check("goaway orphan: client not failed yet", 0, a->closed);
    p_cmd(0, 0, 1, 1);
    UNTIL(P_GONE(0));
    check("goaway orphan: the link closed with its last stream", 1, P_GONE(0));
    check("goaway orphan: the refused POST fails the client", 1, a->closed);
    gl_end();
}

/* catches: streams that ended normally counted as refused by a later GOAWAY */
static void t_goaway_after_answers_keeps_client(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    check("goaway answered: seq 0 sent", 0, gl_post(0, "s0"));
    check("goaway answered: seq 1 sent", 0, gl_post(0, "s1"));
    UNTIL(P_UPN(0) == 4 && P_NSID(0) == 3);
    turns(5);
    p_cmd(0, 0, 1, 99);
    UNTIL(g_t[0].xh.f.down.x && g_t[0].xh.f.down.x->h2.goaway);
    turns(5);
    check("goaway answered: the link saw the GOAWAY", 1, g_t[0].xh.f.down.x && g_t[0].xh.f.down.x->h2.goaway);
    check("goaway answered: client kept", 0, a->closed);
    gl_end();
}

static void t_posts_keep_a_retired_link(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(hold, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\nxmux.hMaxReusableSecs=10\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("retired posts: seq 0 sent", 0, gl_send(0, "s0"));
    UNTIL(P_NHELD(0) == 1);
    gl_close(0);
    g_now += 11000;
    check("retired posts: next flow on a new link", XA_WAIT, gl_attach(1, &n, g_key));
    UNTIL(gl_ready(1) && P_ACCEPTS() == 2);
    turns(10);
    /* catches: a retired link closed under a POST still waiting for its answer */
    check("retired posts: A open while seq 0 waits", 1, P_OPEN(0));
    p_release(0);
    UNTIL(P_GONE(0));
    check("retired posts: A closed after the answer", 1, P_GONE(0));
    gl_end();
}

static void t_post_reset_closes_client(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(refuse_post, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    check("post reset: sent", 0, gl_send(0, "x"));
    /* catches: IsClosed set on the wrong outcome */
    check("post reset: the flow ends", H2_ERESET, gl_until_read(0));
    check("post reset: client closed", 1, a->closed);
    check("post reset: next write fails", 1, transport_write(&g_t[0], (const unsigned char *)"y", 1) < 0);
    check("post reset: next flow waits", XA_WAIT, gl_attach(1, &n, g_key));
    check("post reset: on another client", 1, g_t[1].xh.f.cl != a);
    UNTIL(gl_ready(1) && P_ACCEPTS() == 2);
    check("post reset: a new link", 2, P_ACCEPTS());
    gl_end();
}

static void t_post_400_keeps_client(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(post_status, 400);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    check("post 400: sent", 0, gl_send(0, "x"));
    /* catches: IsClosed set on the wrong outcome */
    check("post 400: the flow fails", H2_ESTATUS, gl_until_read(0));
    check("post 400: client kept", 0, a->closed);
    check("post 400: next flow ready", XA_READY, gl_attach(1, &n, g_key));
    check("post 400: on the same client", 1, g_t[1].xh.f.cl == a);
    gl_end();
}

static void t_streamup_post_fail_keeps_client(void) {
    gl_begin(0);
    P_SET(split, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "stream-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 2);
    struct xm_client *a = g_t[0].xh.f.cl;
    p_rst(0, 3);
    /* catches: uploadOnly failures marking the client closed */
    check("stream-up post fail: the flow ends", 1, gl_until_read(0) < 0);
    gl_close(0);
    check("stream-up post fail: client kept", 0, a->closed);
    check("stream-up post fail: next flow ready", XA_READY, gl_attach(1, &n, g_key));
    check("stream-up post fail: on the same client", 1, g_t[1].xh.f.cl == a);
    gl_end();
}

static void t_streamup_clean_end_keeps_flow(void) {
    gl_begin(0);
    P_SET(split, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "stream-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 2);
    p_frame_out(0, 0, 1, 3, "");
    UNTIL(read_wakes(0));
    turns(5);
    /* catches: the server's clean end of the upload response ending the flow before its download */
    check("stream-up clean end: no error yet", 0, gl_read(0));
    p_frame_out(0, 0, 0, 1, "tail");
    gl_got[0] = 0;
    uint64_t dl = ms_now() + 3000;
    int rc = 0;
    while (gl_got[0] < 4 && ms_now() < dl && !(rc = gl_read(0))) turn();
    check("stream-up clean end: the download goes on", 1, !rc && gl_got[0] == 4 && !memcmp(gl_buf[0], "tail", 4));
    gl_end();
}

static void t_packet_window_across_links(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(hold, 1);
    struct tr_node n = gl_mode("xmux.hMaxRequestTimes=3\nscMaxBufferedPosts=2\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("window across: seq 0", 0, gl_post(0, "s0"));
    check("window across: seq 1", 0, gl_post(0, "s1"));
    UNTIL(P_NHELD(0) == 1 && P_NHELD(1) == 1);
    check("window across: seq 1 moved", 1, g_t[0].xh.f.cl_post != g_t[0].xh.f.cl);
    /* catches: the window over seq counting only the POSTs of the current link */
    check("window across: seq 2 taken", 0, transport_write(&g_t[0], (const unsigned char *)"s2", 2));
    turns(10);
    check("window across: seq 2 held", 2, (int)g_t[0].xh.f.bat.n);
    check("window across: B got only seq 1", 2, P_UPN(1));
    p_release(0);
    UNTIL(P_UPN(1) == 4);
    check("window across: seq 2 after seq 0's answer", 1, p_up_is(1, "s1s2"));
    gl_end();
}

static void t_post_waits_for_a_stream_slot(void) {
    gl_begin(3);
    P_SET(split, 2);
    P_SET(hold, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && P_NSID(0) == 2);
    turns(3);
    check("stream slot: flow 0 takes the last slot", 0, gl_post(0, "s0"));
    UNTIL(P_NHELD(0) == 1);
    /* catches: a POST opened past the server's MAX_CONCURRENT_STREAMS while other flows hold the slots */
    check("stream slot: flow 1 taken", 0, transport_write(&g_t[1], (const unsigned char *)"t0", 2));
    turns(10);
    check("stream slot: flow 1 held", 2, (int)g_t[1].xh.f.bat.n);
    check("stream slot: no third stream", 3, P_NSID(0));
    p_release(0);
    UNTIL(P_UPN(0) == 4);
    check("stream slot: flow 1 after the answer", 4, P_NSID(0));
    check("stream slot: one accept", 1, P_ACCEPTS());
    gl_end();
}

static int gl_answered(int i) {
    const struct xh_flow *f = &g_t[i].xh.f;
    for (unsigned k = 0; k < f->post_n; k++)
        if (!xs_ready(&f->post[k].s)) return 0;
    return f->post_n > 0;
}

static void t_header_post_waits_for_a_stream_slot(void) {
    gl_begin(3);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\nuplinkDataPlacement=header\n", "packet-up");
    gl_attach(0, &n, g_key);
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && P_NSID(0) == 2);
    turns(3);
    check("header slot: flow 0 takes the last slot", 0, gl_post(0, "a"));
    UNTIL(P_NSID(0) == 3);
    /* catches: a POST with its data in headers opened past the server's MAX_CONCURRENT_STREAMS */
    check("header slot: flow 1 taken", 0, transport_write(&g_t[1], (const unsigned char *)"b", 1));
    turns(10);
    check("header slot: flow 1 held", 1, (int)g_t[1].xh.f.bat.n);
    check("header slot: flow 1 not failed", 0, g_t[1].xh.err);
    check("header slot: no fourth stream", 3, P_NSID(0));
    gl_end();
}

static void t_stream_up_needs_two_slots(void) {
    gl_begin(3);
    P_SET(split, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "stream-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 2);
    turns(3);
    /* catches: a stream-up flow started on a link with one free slot for its two streams */
    check("two slots: second flow waits", XA_WAIT, gl_attach(1, &n, g_key));
    UNTIL(gl_ready(1) && P_ACCEPTS() == 2 && P_NSID(1) == 2);
    check("two slots: a second link", 2, P_ACCEPTS());
    check("two slots: both streams there", 2, P_NSID(1));
    check("two slots: second echo", 1, gl_echo(1, "two"));
    gl_end();
}

static void t_post_dial_fail(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.hMaxRequestTimes=3\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    check("post dial fail: seq 0", 0, gl_post(0, "s0"));
    P_SET(shut, 1);
    UNTIL(p_get(12, 0, 0) < 0);
    check("post dial fail: seq 1 taken", 0, transport_write(&g_t[0], (const unsigned char *)"s1", 2));
    UNTIL(g_t[0].xh.f.cl_post != a);
    struct xm_client *b = g_t[0].xh.f.cl_post;
    check("post dial fail: waiting for B", 1, g_t[0].xh.f.wait != NULL);
    /* catches: a write refused while its batch waits for a dial */
    check("post dial fail: more taken meanwhile", 0, transport_write(&g_t[0], (const unsigned char *)"s2", 2));
    /* catches: a POST whose connection failed retried as a new flow, or not failing the upload */
    check("post dial fail: the flow fails", 1, gl_until_read(0) < 0);
    check("post dial fail: B failed", 1, b->closed);
    check("post dial fail: the GET's client still runs it", 1, a->running);
    check("post dial fail: the flow still on A", 1, g_t[0].xh.f.cl == a);
    gl_end();
}

static void t_post_goaway_redials(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    p_cmd(0, 0, 1, 1);
    UNTIL(g_t[0].xh.f.down.x->h2.goaway);
    turns(3);
    /* catches: POSTs that can no longer open on the GET's link failing the flow instead of a new connection of the client */
    check("post goaway: seq 0 sent", 0, gl_post(0, "s0"));
    check("post goaway: same client", 1, g_t[0].xh.f.cl_post == a);
    check("post goaway: a new connection", 2, P_ACCEPTS());
    UNTIL(P_UPN(1) == 2);
    check("post goaway: it got seq 0", 1, p_up_is(1, "s0"));
    gl_got[0] = 0;
    uint64_t dl = ms_now() + 3000;
    while (gl_got[0] < 2 && ms_now() < dl && !gl_read(0)) turn();
    check("post goaway: the GET goes on", 1, gl_got[0] == 2 && !memcmp(gl_buf[0], "s0", 2));
    gl_end();
}

static void t_post_link_survives_lru(void) {
    static char other[4];
    gl_begin(0);
    P_SET(split, 2);
    tr_xmux_links_cap = 2;
    struct tr_node n = gl_mode("xmux.hMaxRequestTimes=3\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("lru: seq 0", 0, gl_post(0, "s0"));
    check("lru: seq 1 on B", 0, gl_post(0, "s1"));
    UNTIL(P_UPN(1) == 2);
    gl_got[0] = 0;
    uint64_t dl = ms_now() + 3000;
    while (gl_got[0] < 4 && ms_now() < dl && !gl_read(0)) turn();
    UNTIL((transport_room(&g_t[0]), !xconn_streams(g_t[0].xh.f.post_x)));
    turns(10);
    check("lru: B has no stream", 0, (int)xconn_streams(g_t[0].xh.f.post_x));
    g_now += 1000;
    struct tr_node n2 = gl_mode("xmux.maxConnections=1\n", "packet-up");
    /* catches: the link a flow posts on closed as idle between its POSTs */
    check("lru: no link to take", 1, gl_attach(1, &n2, other) < 0);
    check("lru: B open", 1, P_OPEN(1));
    check("lru: seq 2 on B", 0, gl_send(0, "s2"));
    UNTIL(P_UPN(1) == 4);
    check("lru: B got it", 1, p_up_is(1, "s1s2"));
    gl_end();
}

static void t_get_reset_closes_client(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(refuse_get, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    check("get reset: the flow ends", H2_ERESET, gl_until_read(0));
    check("get reset: a second flow keeps the client", XA_READY, gl_attach(1, &n, g_key));
    gl_close(0);
    /* catches: a GET refused before its answer leaving the client in use */
    check("get reset: client closed", 1, a->closed);
    gl_end();
}

static void t_swept_post_client_kept(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\nxmux.hMaxRequestTimes=3\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("swept post client: seq 0", 0, gl_post(0, "s0"));
    check("swept post client: seq 1 on B", 0, gl_post(0, "s1"));
    struct xm_client *b = g_t[0].xh.f.cl_post;
    UNTIL(P_UPN(1) == 2);
    P_SET(refuse_get, 1);
    check("swept post client: flow 1 on B", XA_READY, gl_attach(1, &n, g_key));
    check("swept post client: same B", 1, g_t[1].xh.f.cl == b);
    check("swept post client: its GET refused", H2_ERESET, gl_until_read(1));
    gl_close(1);
    check("swept post client: B failed", 1, b->closed);
    P_SET(refuse_get, 0);
    check("swept post client: flow 2 sweeps B", XA_WAIT, gl_attach(2, &n, g_key));
    UNTIL(gl_ready(2) && P_ACCEPTS() == 3);
    /* catches: a client the flow posts on freed when another flow sweeps it */
    check("swept post client: B swept", 1, b->not_used);
    int before = P_UPN(1);
    check("swept post client: seq 2 sent", 0, gl_send(0, "s2"));
    UNTIL(P_UPN(1) == before + 2);
    check("swept post client: seq 2 on B's link", before + 2, P_UPN(1));
    check("swept post client: no new connection", 3, P_ACCEPTS());
    gl_end();
}

static void t_dead_post_link_redials(void) {
    static char other[4];
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.hMaxRequestTimes=3\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("dead post link: seq 0", 0, gl_post(0, "s0"));
    check("dead post link: seq 1 on B", 0, gl_post(0, "s1"));
    UNTIL(gl_answered(0));
    check("dead post link: seq 1 answered, not yet reaped", 1, g_t[0].xh.f.post_n >= 1);
    struct xm_client *b = g_t[0].xh.f.cl_post;
    p_cmd(1, 1, 0, 0);
    turns(20);
    struct tr_node n2 = gl_mode("xmux.maxConnections=1\n", "stream-one");
    check("dead post link: another node's flow", XA_WAIT, gl_attach(1, &n2, other));
    UNTIL(gl_ready(1) && P_ACCEPTS() == 3);
    /* catches: a dead link the flow posts on freed under it, its address then taken by another link */
    check("dead post link: seq 2 sent", 0, gl_send(0, "s2"));
    UNTIL(P_ACCEPTS() == 4 && P_UPN(3) == 2);
    check("dead post link: seq 2 on a new connection of B", 1, p_up_is(3, "s2"));
    check("dead post link: still B", 1, g_t[0].xh.f.cl_post == b);
    check("dead post link: B not failed by an idle death", 0, b->closed);
    gl_end();
}

static unsigned char gl_big[65536];

static void t_room_never_decides(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\nxmux.hMaxReusableSecs=10\nxmux.hMaxRequestTimes=10\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    for (int i = 0; i < 5; i++) transport_room(&g_t[0]);
    g_now += 11000;
    turns(5);
    for (int i = 0; i < 5; i++) transport_room(&g_t[0]);
    gl_read(0);
    turns(5);
    /* catches: a POST decided, or a move dialled, for a flow with nothing to upload */
    check("download only: no request counted", 9, a->left_requests);
    check("download only: no move", 1, g_t[0].xh.f.cl_post == a);
    check("download only: no dial", 1, g_jobs);
    check("download only: room stays at the floor", 16384, transport_room(&g_t[0]));
    check("download only: an upload moves at its POST", 0, gl_post(0, "s0"));
    UNTIL(P_ACCEPTS() == 2 && P_UPN(1) == 2);
    check("download only: A counted the POST", 8, a->left_requests);
    check("download only: the POST went to B", 1, p_up_is(1, "s0"));
    gl_end();
}

static void t_writes_coalesce(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\nxmux.hMaxRequestTimes=10\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    /* catches: one POST per write instead of one per batch */
    check("coalesce: ab", 0, transport_write(&g_t[0], (const unsigned char *)"ab", 2));
    check("coalesce: room less ab", 16382, transport_room(&g_t[0]));
    check("coalesce: cd", 0, transport_write(&g_t[0], (const unsigned char *)"cd", 2));
    UNTIL(P_UPN(0) == 4);
    turns(3);
    check("coalesce: one POST", 2, P_NSID(0));
    check("coalesce: both writes in it", 1, p_up_is(0, "abcd"));
    check("coalesce: one request", 8, g_t[0].xh.f.cl->left_requests);
    gl_end();
}

static void t_posts_paced(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\nscMinPostsIntervalMs=100-200\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    tr_xmux_rnd = rnd_top;
    check("paced: a", 0, transport_write(&g_t[0], (const unsigned char *)"a", 1));
    check("paced: the first POST at once, nothing left due", 0, tr_xmux_pass(g_now, MUXP_LATE));
    UNTIL(P_UPN(0) == 1);
    /* catches: scMinPostsIntervalMs not kept between POSTs, or its deadline not told to the loop */
    check("paced: b", 0, transport_write(&g_t[0], (const unsigned char *)"b", 1));
    check("paced: due in 199 ms (100 + 99)", 199, tr_xmux_pass(g_now, MUXP_LATE));
    g_now += 198;
    turns(5);
    check("paced: held at 198 ms", 1, P_UPN(0));
    g_now += 1;
    UNTIL(P_UPN(0) == 2);
    check("paced: sent at 199 ms", 1, p_up_is(0, "ab"));
    tr_xmux_rnd = rnd_zero;
    gl_end();
}

static size_t bat_acct(struct transport *ts, int n) {
    size_t sum = 0;
    for (int i = 0; i < n; i++) sum += ts[i].xh.f.bat.n + ts[i].xh.f.bres;
    return sum;
}

#define ACCT_OK() (tr_xmux_bat_used() == bat_acct(g_t, 8) + bat_acct(g_many, 64))

static void t_room_budget_wake(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    tr_xmux_up_budget = 1000;
    check("budget: room is what the budget has", 1000, transport_room(&g_t[0]));
    check("budget: reserved at once", 1000, (long)tr_xmux_bat_used());
    check("budget: written", 0, transport_write(&g_t[0], gl_big, 1000));
    check("budget: spent", 0, transport_room(&g_t[0]));
    /* catches: a write past its reservation taken from a spent budget */
    check("budget: one byte more refused", H2_EWINDOW, transport_write(&g_t[0], gl_big, 1));
    check("budget: still 1000", 1000, (long)tr_xmux_bat_used());
    check("budget: counted exactly", 1, ACCT_OK());
    int w = room_wakes(0);
    /* catches: a flow whose room the budget closed never told when bytes leave */
    tr_xmux_pass(g_now, MUXP_LATE);
    check("budget: woken", w + 1, room_wakes(0));
    check("budget: room back", 1000, transport_room(&g_t[0]));
    check("budget: counted exactly after the flush", 1, ACCT_OK());
    gl_end();
}

static void t_reservation_ramps(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    /* catches: every flow reserving its whole share at once, or an uploader never growing past the floor */
    check("ramp: the floor first", 16384, transport_room(&g_t[0]));
    transport_write(&g_t[0], gl_big, 16384);
    tr_xmux_pass(g_now, MUXP_LATE);
    check("ramp: a full POST doubles it", 32768, transport_room(&g_t[0]));
    transport_write(&g_t[0], gl_big, 32768);
    tr_xmux_pass(g_now, MUXP_LATE);
    check("ramp: and again", 65536, transport_room(&g_t[0]));
    transport_write(&g_t[0], gl_big, 1000);
    tr_xmux_pass(g_now, MUXP_LATE);
    check("ramp: a small POST does not grow it", 65536, transport_room(&g_t[0]));
    check("ramp: counted exactly", 1, ACCT_OK());
    gl_end();
}

static void t_idle_reservation_shrinks(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    transport_room(&g_t[0]);
    transport_write(&g_t[0], gl_big, 16384);
    tr_xmux_pass(g_now, MUXP_LATE);
    check("idle: grown", 32768, transport_room(&g_t[0]));
    g_now += 999;
    tr_xmux_pass(g_now, MUXP_LATE);
    check("idle: kept within the second", 32768, (long)tr_xmux_bat_used());
    /* catches: a reservation an idle flow holds for ever */
    g_now += 1;
    tr_xmux_pass(g_now, MUXP_LATE);
    check("idle: back to the floor", 16384, (long)tr_xmux_bat_used());
    check("idle: room at the floor", 16384, transport_room(&g_t[0]));
    check("idle: counted exactly", 1, ACCT_OK());
    gl_end();
}

static void t_share_among_uploaders(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    gl_attach(1, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && P_NSID(0) == 2);
    turns(3);
    tr_xmux_up_budget = 100000;
    for (int k = 0; k < 3; k++) {
        for (int i = 0; i < 2; i++) transport_write(&g_t[i], gl_big, (size_t)transport_room(&g_t[i]));
        UNTIL(!g_t[0].xh.f.bat.n && !g_t[1].xh.f.bat.n);
    }
    /* catches: an uploader's room growing past its share of the budget among the uploaders */
    check("share: flow 0 capped at 100000/2", 50000, transport_room(&g_t[0]));
    check("share: flow 1 capped at 100000/2", 50000, transport_room(&g_t[1]));
    check("share: counted exactly", 1, ACCT_OK());
    gl_end();
}

static void t_ramp_round(int a, int b) {
    for (int k = 0; k < 3; k++) {
        for (int i = a; i <= b; i++) transport_write(&g_t[i], gl_big, (size_t)transport_room(&g_t[i]));
        UNTIL(!g_t[a].xh.f.bat.n && !g_t[b].xh.f.bat.n);
    }
}

static void t_uploaders_counted_exactly(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    for (int i = 0; i < 3; i++) gl_attach(i, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && gl_ready(2) && P_NSID(0) == 3);
    turns(3);
    tr_xmux_up_budget = 32768;
    t_ramp_round(0, 1);
    size_t b0 = g_t[0].xh.f.blim, b1 = g_t[1].xh.f.blim;
    check("uploaders: one grew to the budget", 32768, (long)(b0 > b1 ? b0 : b1));
    check("uploaders: the other held at the floor share", 1, (b0 > b1 ? b1 : b0) <= 16384);
    gl_close(0);
    gl_close(1);
    turns(3);
    /* catches: a flow kept at the floor counted as an uploader for good, pinning later ones at 16 KiB */
    t_ramp_round(2, 2);
    check("uploaders: a new one grows past the floor again", 32768, transport_room(&g_t[2]));
    gl_end();
}

static void t_idle_shrink_is_a_deadline(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    transport_room(&g_t[0]);
    transport_write(&g_t[0], gl_big, 16384);
    UNTIL(!g_t[0].xh.f.bat.n);
    check("idle due: grown", 32768, transport_room(&g_t[0]));
    g_now = g_t[0].xh.f.bw_at + 400;
    /* catches: the idle shrink left to whatever pass comes next instead of the loop's wait */
    check("idle due: the shrink 600 ms ahead", 600, tr_xmux_pass(g_now, MUXP_LATE));
    gl_end();
}

static void t_idle_due_is_the_nearest(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\nscMinPostsIntervalMs=5000\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    transport_room(&g_t[0]);
    transport_write(&g_t[0], gl_big, 16384);
    tr_xmux_pass(g_now, MUXP_LATE);
    check("nearest: grown", 32768, transport_room(&g_t[0]));
    transport_write(&g_t[0], gl_big, 100);
    /* catches: the loop told the batch's later deadline when the idle shrink comes first */
    check("nearest: the shrink at 1000 before the POST at 5000", 1000, tr_xmux_pass(g_now, MUXP_LATE));
    gl_end();
}

static void t_budget_hard_many(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    g_ref.node = g_key;
    for (int i = 0; i < 64; i++) {
        tr_xmux_attach(&g_many[i], &n, g_key, NULL, (uint16_t)(100 + i), &g_ref);
        g_many[i].xh.f.blim = 1000000;
    }
    long sum = 0;
    for (int i = 0; i < 64; i++) sum += transport_room(&g_many[i]);
    /* catches: rooms of many flows each asking for 1 MB granted together past 4 MiB */
    check("many: rooms together within 4 MiB", 1, sum <= 4194304);
    check("many: the budget reserved, no more", 4194304, (long)tr_xmux_bat_used());
    int ok = 0;
    for (int i = 0; i < 64; i++) {
        long r = transport_room(&g_many[i]);
        int good = 1;
        for (long off = 0; off < r; off += 65536)
            good &= !transport_write(&g_many[i], gl_big, (size_t)(r - off < 65536 ? r - off : 65536));
        ok += good;
    }
    check("many: every granted room taken", 64, ok);
    check("many: held is the budget, no more", 4194304, (long)tr_xmux_bat_used());
    check("many: counted exactly", 1, ACCT_OK());
    for (int i = 0; i < 64; i++) {
        transport_close(&g_many[i]);
        memset(&g_many[i], 0, sizeof g_many[i]);
    }
    check("many: all given back at close", 0, (long)tr_xmux_bat_used());
    gl_end();
}

static void t_wake_after_all_flushes(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    tr_xmux_up_budget = 1000;
    check("cross wake: alone, the whole budget", 1000, transport_room(&g_t[0]));
    check("cross wake: flow 0 holds it", 0, transport_write(&g_t[0], gl_big, 1000));
    check("cross wake: flow 1 attaches", XA_READY, gl_attach(1, &n, g_key));
    check("cross wake: flow 1 starved", 0, transport_room(&g_t[1]));
    int w = room_wakes(1);
    /* catches: a starved flow checked before the flush that frees its budget, left asleep */
    tr_xmux_pass(g_now, MUXP_LATE);
    check("cross wake: flow 1 woken in the same pass", w + 1, room_wakes(1));
    check("cross wake: the freed budget reserved", 1000, (long)g_t[1].xh.f.bres);
    check("cross wake: counted exactly", 1, ACCT_OK());
    gl_end();
}

static void t_close_frees_wakes(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    tr_xmux_up_budget = 1000;
    transport_room(&g_t[0]);
    check("close wake: flow 0 holds the budget", 0, transport_write(&g_t[0], gl_big, 1000));
    gl_attach(1, &n, g_key);
    check("close wake: flow 1 starved", 0, transport_room(&g_t[1]));
    int w = room_wakes(1);
    /* catches: budget freed by a closing flow that wakes nobody until some later event */
    gl_close(0);
    check("close wake: woken by the close itself", w + 1, room_wakes(1));
    check("close wake: the whole budget now", 1000, transport_room(&g_t[1]));
    check("close wake: counted exactly", 1, ACCT_OK());
    /* catches: a reservation with no bytes behind it kept after its flow closed */
    gl_close(1);
    check("close wake: the reservation given back", 0, (long)tr_xmux_bat_used());
    gl_end();
}

static void t_wake_no_double(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node y = gl_mode("xmux.maxConnections=1\nscMinPostsIntervalMs=1000\n", "packet-up");
    y.post_from = y.post_to = 300;
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &y, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    tr_xmux_up_budget = 999;
    transport_room(&g_t[0]);
    check("no double: flow 0 holds the budget", 0, transport_write(&g_t[0], gl_big, 999));
    gl_attach(1, &n, g_key);
    gl_attach(2, &n, g_key);
    check("no double: flow 1 starved", 0, transport_room(&g_t[1]));
    check("no double: flow 2 starved", 0, transport_room(&g_t[2]));
    int w1 = room_wakes(1), w2 = room_wakes(2);
    tr_xmux_pass(g_now, MUXP_LATE);
    /* catches: the same freed bytes handed to several starved flows */
    check("no double: one POST of 300 freed", 699, (long)g_t[0].xh.f.bat.n);
    check("no double: one flow woken", 1, (room_wakes(1) - w1) + (room_wakes(2) - w2));
    check("no double: it holds the 300", 300, (long)(g_t[1].xh.f.bres + g_t[2].xh.f.bres));
    check("no double: within the budget", 1, tr_xmux_bat_used() <= 999);
    check("no double: counted exactly", 1, ACCT_OK());
    gl_end();
}

static int g_send_calls, g_send_fail_at;
extern int (*tr_xh_send_q)(const struct xs *s, struct xc_q *q, size_t n, int end);

static int send_fails(const struct xs *s, struct xc_q *q, size_t n, int end) {
    static unsigned char sink[32768];
    if (++g_send_calls == g_send_fail_at) {
        xc_q_pop(q, sink, sizeof sink);
        return H2_EIO;
    }
    return xs_send_q(s, q, n, end);
}

static void t_partial_send_counts(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    check("partial: 40000 taken", 0, transport_write(&g_t[0], gl_big, 40000));
    g_send_calls = 0;
    g_send_fail_at = 1;
    tr_xh_send_q = send_fails;
    tr_xmux_pass(g_now, MUXP_LATE);
    tr_xh_send_q = xs_send_q;
    /* catches: bytes taken from the batch for a POST that failed partway kept in the budget */
    check("partial: two pieces taken, 7232 left", 7232, (long)g_t[0].xh.f.bat.n);
    check("partial: the flow failed", 1, g_t[0].xh.err != 0);
    check("partial: counted exactly", 1, ACCT_OK());
    gl_close(0);
    check("partial: nothing left after close", 0, (long)tr_xmux_bat_used());
    gl_end();
}

static void t_post_one_frame(void) {
    static unsigned char big[100000];
    memset(big, 'o', sizeof big);
    gl_begin(0);
    P_SET(split, 2);
    P_SET(mfs, 1);
    P_SET(noecho, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    check("one frame: 100,000 taken", 0, transport_write(&g_t[0], big, sizeof big));
    UNTIL(!g_t[0].xh.f.bat.n && P_NSID(0) == 2 && p_dl_is(0, "100000:1 ", 0));
    /* catches: POST bodies still cut into 16 KiB frames */
    check("one frame: one POST", 2, P_NSID(0));
    check("one frame: its body one DATA of 100,000 with END_STREAM", 1, p_dl_is(0, "100000:1 ", 1));
    check("one frame: the flow fine", 0, g_t[0].xh.err);
    gl_end();
}

static void t_room_batch_full_wake(void) {
    gl_begin(2);
    P_SET(split, 2);
    P_SET(hold, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    tr_xmux_up_budget = 4;
    check("batch full: seq 0", 0, gl_post(0, "s0s0"));
    UNTIL(P_NHELD(0) == 1);
    check("batch full: seq 1", 0, transport_write(&g_t[0], (const unsigned char *)"s1s1", 4));
    check("batch full: no room", 0, transport_room(&g_t[0]));
    turns(5);
    int w = room_wakes(0);
    check("batch full: held behind the stream limit", 4, (int)g_t[0].xh.f.bat.n);
    /* catches: a flow whose batch waited for a stream slot never woken when it leaves */
    p_release(0);
    UNTIL(P_UPN(0) == 8);
    check("batch full: woken when the batch left", 1, room_wakes(0) > w);
    check("batch full: room back", 4, transport_room(&g_t[0]));
    gl_end();
}

static void t_batch_holds_a_write_past_post_max(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    n.post_from = n.post_to = 4096;
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    /* catches: a batch no larger than scMaxEachPostBytes, which no write of the stack fits */
    check("post max: room past 4096", 16384, transport_room(&g_t[0]));
    check("post max: a 16384-byte write taken", 0, transport_write(&g_t[0], gl_big, 16384));
    UNTIL(!g_t[0].xh.f.bat.n && P_NSID(0) == 5);
    check("post max: four POSTs of 4096", 5, P_NSID(0));
    gl_end();
}

static void t_post_waits_for_window(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(nowu, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    check("window: 60000", 0, gl_post(0, "x") || transport_write(&g_t[0], gl_big, 59999));
    UNTIL(!g_t[0].xh.f.bat.n);
    check("window: 10000 more", 0, transport_write(&g_t[0], gl_big, 10000));
    turns(10);
    /* catches: a POST cut to a nearly closed window, or bytes refused instead of held for it */
    check("window: held, 5535 is too small a POST", 10000, (int)g_t[0].xh.f.bat.n);
    check("window: two POSTs only", 3, P_NSID(0));
    gl_end();
}

static void t_serve_skips_big_waiter(void) {
    gl_begin(2);
    P_SET(split, 1);
    tr_xmux_links_cap = 1;
    struct tr_node one = gl_mode("xmux.maxConnections=1\n", "stream-one");
    struct tr_node up = gl_mode("xmux.maxConnections=1\n", "stream-up");
    gl_attach(0, &one, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    turns(3);
    check("serve: second stream-one on the link", XA_READY, gl_attach(3, &one, g_key));
    check("serve: stream-up waits for two slots", XA_WAIT, gl_attach(1, &up, g_key));
    check("serve: stream-one waits for one", XA_WAIT, gl_attach(2, &one, g_key));
    gl_close(0);
    turns(5);
    /* catches: a waiter needing two slots holding back one that needs one */
    check("serve: the one-slot waiter served", 0, done_rc(2));
    check("serve: the two-slot waiter still waits", 1, done_rc(1));
    gl_end();
}

static char g_dkey[4];
static struct tr_node g_dn;

static struct tr_node gl_dl(const char *xhx, const char *dxhx, const char *mode) {
    struct tr_node n = gl_mode(xhx, mode);
    g_dn = gl_node(g_p.port2, dxhx);
    n.dl = &g_dn;
    return n;
}

static int gl_attach_dl(int i, const struct tr_node *n, const void *key) {
    g_ref.node = key;
    tr_xmux_pass(g_now, MUXP_EARLY);
    return tr_xmux_attach(&g_t[i], n, key, g_dkey, (uint16_t)i, &g_ref);
}

static void job_at(int k) {
    void *link = g_job[k].link;
    int *done = g_job[k].done;
    memmove(g_job + k, g_job + k + 1, (size_t)(g_job_n - k - 1) * sizeof g_job[0]);
    g_job_n--;
    tr_xmux_dial(link, 2);
    __atomic_store_n(done, 1, __ATOMIC_RELEASE);
}

/* catches: the block sharing the main pool, taking main's xmux or node, or running counted twice */
static void t_dl_two_pools(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=2\n", "packet-up");
    for (int i = 0; i < 3; i++) gl_attach_dl(i, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && gl_ready(2) && P_NSID_AT(1) == 3);
    check("dl pools: post 0", 0, gl_post(0, "p0"));
    check("dl pools: post 1", 0, gl_post(1, "p1"));
    check("dl pools: post 2", 0, gl_post(2, "p2"));
    UNTIL(P_UPN_AT(0) == 6 && P_NSID_AT(0) == 3);
    check("dl pools: main one accept", 1, P_ACC(0));
    check("dl pools: block two accepts", 2, P_ACC(1));
    check("dl pools: three GETs on the block", 3, P_NSID_AT(1));
    check("dl pools: three POSTs on main", 3, P_NSID_AT(0));
    check("dl pools: uploads on main", 6, P_UPN_AT(0));
    check("dl pools: no upload on the block", 0, P_UPN_AT(1));
    struct xh_flow *f0 = &g_t[0].xh.f, *f1 = &g_t[1].xh.f, *f2 = &g_t[2].xh.f;
    check("dl pools: one main client", 1, f0->cl == f1->cl && f1->cl == f2->cl);
    check("dl pools: two block clients", 1, f0->cl_dl != f1->cl_dl && f2->cl_dl == f0->cl_dl);
    check("dl pools: main running once per flow", 3, f0->cl->running);
    check("dl pools: block running once per flow", 1, f0->cl_dl->running == 2 && f1->cl_dl->running == 1);
    check("dl pools: a main link carries no block", 1, f0->post_x && !f0->post_x->node.dl);
    gl_end();
}

/* catches: a flow started before its block is live, or a retry keeping its clients */
static void t_dl_waits_for_both(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=2\n", "packet-up");
    g_hold = 1;
    check("dl wait: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    check("dl wait: both dials at once", 2, g_jobs);
    job_at(0);
    turns(3);
    check("dl wait: main live, block dialing: no wake", 1, done_rc(0));
    check("dl wait: no stream yet", 0, gl_ready(0));
    job_at(0);
    turn();
    check("dl wait: ready when the block's dial ends", 0, done_rc(0));
    g_hold = 0;
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    struct xm_client *a = g_t[0].xh.f.cl;
    int before = a->running;
    P_SET(shut2, 1);
    UNTIL(p_get(16, 0, 0) < 0);
    check("dl wait: a second flow waits for a new block link", XA_WAIT, gl_attach_dl(1, &n, g_key));
    check("dl wait: it runs on main meanwhile", before + 1, a->running);
    UNTIL(done_rc(1) != 1);
    turns(3);
    check("dl wait: refused after one retry", TR_ECONNREFUSED, done_rc(1));
    check("dl wait: two more dials", 4, g_jobs);
    check("dl wait: no second main accept", 1, P_ACC(0));
    check("dl wait: main running back", before, a->running);
    check("dl wait: no client held", 1, !g_t[1].xh.f.cl && !g_t[1].xh.f.cl_dl && !g_t[1].xh.f.cl_post);
    gl_close(1);
    check("dl wait: still back after the close", before, a->running);
    check("dl wait: the first flow goes on", 1, gl_echo(0, "still"));
    gl_end();
}

/* catches: a flow served from the block starting before main is ready */
static void t_dl_waits_for_main(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    g_hold = 1;
    check("dl main wait: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    job_at(1);
    turns(3);
    check("dl main wait: block live, main dialing: no wake", 1, done_rc(0));
    check("dl main wait: no stream yet", 0, gl_ready(0));
    job_at(0);
    turn();
    check("dl main wait: ready when main's dial ends", 0, done_rc(0));
    g_hold = 0;
    check("dl main wait: echo", 1, gl_echo(0, "late"));
    gl_end();
}

/* catches: the block taking main's xmux instead of its own defaults */
static void t_dl_defaults_per_block(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", NULL, "packet-up");
    for (int i = 0; i < 4; i++) gl_attach_dl(i, &n, g_key);
    UNTIL(gl_ready(0) && gl_ready(1) && gl_ready(2) && gl_ready(3) && P_NSID_AT(1) == 4);
    check("dl defaults: the block opens three", 3, P_ACC(1));
    check("dl defaults: main keeps its one", 1, P_ACC(0));
    gl_end();
}

/* catches: the GET counted on the main client, or the long POST not counted */
static void t_dl_requests_per_side(void) {
    gl_begin(0);
    P_SET(split, 1);
    struct tr_node n = gl_dl("xmux.maxConnections=1\nxmux.hMaxRequestTimes=10\n",
                             "xmux.maxConnections=1\nxmux.hMaxRequestTimes=10\n", "stream-up");
    check("dl stream-up: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    UNTIL(gl_ready(0) && P_NSID_AT(0) == 1 && P_NSID_AT(1) == 1);
    struct xh_flow *f = &g_t[0].xh.f;
    struct xm_client *a = f->cl, *d = f->cl_dl;
    check("dl stream-up: GET and POST on two links", 1, f->down.x && f->up.x && f->down.x != f->up.x);
    check("dl stream-up: one accept each", 1, P_ACC(0) == 1 && P_ACC(1) == 1);
    check("dl stream-up: the POST counted on main", 9, a->left_requests);
    check("dl stream-up: the GET counted on the block", 9, d->left_requests);
    check("dl stream-up: main running", 1, a->running);
    check("dl stream-up: block running", 1, d->running);
    check("dl stream-up: echo", 1, gl_echo(0, "upward"));
    gl_close(0);
    check("dl stream-up: main running back", 0, a->running);
    check("dl stream-up: block running back", 0, d->running);
    gl_end();

    gl_begin(0);
    P_SET(split, 2);
    n = gl_dl("xmux.maxConnections=1\nxmux.hMaxRequestTimes=10\n", "xmux.maxConnections=1\nxmux.hMaxRequestTimes=10\n",
              "packet-up");
    gl_attach_dl(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    a = g_t[0].xh.f.cl;
    d = g_t[0].xh.f.cl_dl;
    check("dl packet: the GET not counted on main", 10, a->left_requests);
    check("dl packet: the GET counted on the block", 9, d->left_requests);
    check("dl packet: echo", 1, gl_echo(0, "hello"));
    check("dl packet: the POST counted on main", 9, a->left_requests);
    check("dl packet: not on the block", 9, d->left_requests);
    check("dl packet: the POST went to main", 5, P_UPN_AT(0));
    gl_end();
}

/* catches: a GET refused before HEADERS failing the main client instead of the block's */
static void t_dl_get_reset_fails_block_client(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(refuse_get, 1);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    gl_attach_dl(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    struct xm_client *a = g_t[0].xh.f.cl, *d = g_t[0].xh.f.cl_dl;
    check("dl get reset: the flow ends", H2_ERESET, gl_until_read(0));
    gl_close(0);
    check("dl get reset: block client closed", 1, d->closed);
    check("dl get reset: main client kept", 0, a->closed);
    gl_end();
}

static int p_nth_on(int ep, int k) {
    for (int i = 0; i < P_ACCEPTS(); i++) {
        pthread_mutex_lock(&g_p.mu);
        int on = g_p.c[i].ep == ep;
        pthread_mutex_unlock(&g_p.mu);
        if (on && !k--) return i;
    }
    return -1;
}

static int p_first_on(int ep) { return p_nth_on(ep, 0); }

/* catches: a POST after GOAWAY redialed to the block instead of main */
static void t_dl_post_redials_main(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    gl_attach_dl(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    check("dl post goaway: seq 0", 0, gl_post(0, "s0"));
    UNTIL(P_UPN_AT(0) == 2);
    p_cmd(p_first_on(0), 0, 1, 1);
    UNTIL(g_t[0].xh.f.post_x->h2.goaway);
    turns(3);
    check("dl post goaway: seq 1", 0, gl_post(0, "s1"));
    UNTIL(P_UPN_AT(0) == 4);
    check("dl post goaway: a new main connection", 2, P_ACC(0));
    check("dl post goaway: none to the block", 1, P_ACC(1));
    check("dl post goaway: seq 1 on main", 4, P_UPN_AT(0));
    gl_end();
}

/* catches: packet-up POSTs moving to the block, or running counted on the new client */
static void t_dl_posts_move_on_main(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.hMaxRequestTimes=2\n", "xmux.maxConnections=1\n", "packet-up");
    gl_attach_dl(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    struct xh_flow *f = &g_t[0].xh.f;
    struct xm_client *a = f->cl, *d = f->cl_dl;
    check("dl move: seq 0", 0, gl_post(0, "s0"));
    check("dl move: seq 1", 0, gl_post(0, "s1"));
    UNTIL(P_UPN_AT(0) == 4);
    check("dl move: moved", 1, f->cl_post != a);
    check("dl move: a new main connection", 2, P_ACC(0));
    check("dl move: none to the block", 1, P_ACC(1));
    check("dl move: main running once", 1, a->running);
    check("dl move: the new client not running", 0, f->cl_post->running);
    check("dl move: block running once", 1, d->running);
    gl_end();
}

/* catches: a dl flow taking one manager slot, or evicting its own main manager for the block */
static void t_dl_mgr_slots(void) {
    static char k1[4], k2[4];
    gl_begin(0);
    tr_xmux_mgrs_cap = 1;
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    check("dl mgrs: two slots needed", XA_NONE, gl_attach_dl(0, &n, g_key));
    check("dl mgrs: no state taken", 0, g_t[0].fr != NULL);
    check("dl mgrs: no dial", 0, g_jobs);
    tr_xmux_mgrs_cap = 2;
    struct tr_node m = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hKeepAlivePeriod=-1\n");
    gl_attach(1, &m, k1);
    UNTIL(gl_ready(1));
    gl_close(1);
    uint64_t t0 = g_now;
    for (g_now = t0 + 1000; g_now <= t0 + 300000; g_now += 1000) turn();
    UNTIL(P_GONE(0));
    gl_attach(2, &m, k2);
    UNTIL(gl_ready(2));
    struct tr_node n1 = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    check("dl mgrs: its main manager is not evicted for the block", XA_NONE, gl_attach_dl(3, &n1, k1));
    check("dl mgrs: no state taken again", 0, g_t[3].fr != NULL);
    gl_end();
}

/* catches: a refused dl attach keeping main running */
static void t_dl_no_link_gives_back(void) {
    gl_begin(0);
    tr_xmux_links_cap = 1;
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    check("dl no link: refused", 1, gl_attach_dl(0, &n, g_key) < 0);
    check("dl no link: no client held", 1, !g_t[0].xh.f.cl && !g_t[0].xh.f.cl_dl && !g_t[0].xh.f.cl_post);
    tr_xmux_links_cap = XC_MAX;
    gl_attach_dl(1, &n, g_key);
    check("dl no link: the next flow alone runs main", 1, g_t[1].xh.f.cl && g_t[1].xh.f.cl->running == 1);
    gl_close(0);
    check("dl no link: still one after the close", 1, g_t[1].xh.f.cl->running == 1);
    gl_end();
}

/* catches: a stream-up dl flow needing two slots on each side */
static void t_dl_stream_up_one_slot_each(void) {
    gl_begin(1);
    P_SET(split, 1);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "stream-up");
    gl_attach_dl(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID_AT(0) == 1 && P_NSID_AT(1) == 1);
    gl_close(0);
    UNTIL(P_NRST(p_first_on(1)) == 1);
    turns(5);
    check("dl one slot: ready on the open links", XA_READY, gl_attach_dl(1, &n, g_key));
    UNTIL(P_NSID_AT(0) == 2 && P_NSID_AT(1) == 2);
    check("dl one slot: no new main connection", 1, P_ACC(0));
    check("dl one slot: no new block connection", 1, P_ACC(1));
    check("dl one slot: echo", 1, gl_echo(1, "slot"));
    gl_end();
}

/* catches: a found idle block manager evicted for a new main */
static void t_dl_found_block_kept(void) {
    static char k1[4], k2[4], k3[4];
    gl_begin(0);
    tr_xmux_mgrs_cap = 2;
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\nxmux.hKeepAlivePeriod=-1\n",
                             "xmux.maxConnections=1\nxmux.hKeepAlivePeriod=-1\n", "packet-up");
    gl_attach_dl(0, &n, k1);
    UNTIL(gl_ready(0));
    gl_close(0);
    uint64_t t0 = g_now;
    for (g_now = t0 + 1000; g_now <= t0 + 300000; g_now += 1000) turn();
    UNTIL(P_GONE(0) && P_GONE(1));
    struct tr_node m = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hKeepAlivePeriod=-1\n");
    check("dl kept: another node takes the idle main slot", XA_WAIT, gl_attach(1, &m, k2));
    UNTIL(gl_ready(1));
    check("dl kept: a new main node does not evict its block", XA_NONE, gl_attach_dl(2, &n, k3));
    check("dl kept: no state taken", 0, g_t[2].fr != NULL);
    gl_end();
}

/* catches: a failed flow's managers freed before its close */
static void t_dl_failed_flow_keeps_its_managers(void) {
    static char k3[4];
    gl_begin(0);
    tr_xmux_mgrs_cap = 2;
    P_SET(split, 2);
    P_SET(shut2, 1);
    UNTIL(p_get(16, 0, 0) < 0);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    check("dl failed: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    UNTIL(done_rc(0) != 1);
    check("dl failed: refused", TR_ECONNREFUSED, done_rc(0));
    turns(3);
    struct tr_node m = gl_node(g_p.port, NULL);
    check("dl failed: its managers stay until its close", XA_NONE, gl_attach(1, &m, k3));
    gl_close(0);
    check("dl failed: the block's slot free after the close", XA_WAIT, gl_attach(1, &m, k3));
    gl_end();
}

static void job_link(const void *x) {
    for (int k = 0; k < g_job_n; k++)
        if (g_job[k].link == x) {
            job_at(k);
            return;
        }
}

/* catches: the served block link evicted or closed under its flow when main finds no link */
static void t_dl_serve_keeps_its_link(void) {
    static char k2[4];
    gl_begin(0);
    tr_xmux_links_cap = 2;
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    g_hold = 1;
    check("dl serve pin: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    P_SET(shut, 1);
    UNTIL(p_get(22, 0, 0) < 0);
    job_at(0);
    turns(3);
    struct tr_node m = gl_mode("xmux.maxConnections=1\n", "packet-up");
    m.port = g_p.port2;
    gl_attach(1, &m, k2);
    job_at(1);
    turns(3);
    UNTIL(gl_ready(1));
    job_at(0);
    turns(3);
    check("dl serve pin: no link left for main", H2_EFULL, done_rc(0));
    check("dl serve pin: the block link not closed under it", 1, P_OPEN(p_nth_on(1, 1)));
    struct xh_flow *f = &g_t[0].xh.f;
    check("dl serve pin: nothing held", 1, !f->cl && !f->cl_dl && !f->hold[0] && !f->hold[1]);
    g_hold = 0;
    check("dl serve pin: the other node's flow goes on", 1, gl_echo(1, "on"));
    gl_end();
}

/* catches: after() touching a link that serve() freed through its client's close */
static void t_dl_serve_frees_its_link(void) {
    static char k2[4];
    gl_begin(0);
    tr_xmux_links_cap = 2;
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    g_hold = 1;
    check("dl serve free: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    P_SET(shut, 1);
    UNTIL(p_get(22, 0, 0) < 0);
    job_at(0);
    turns(3);
    struct tr_node m = gl_mode("xmux.maxConnections=1\n", "packet-up");
    m.port = g_p.port2;
    gl_attach(1, &m, k2);
    job_at(1);
    turns(3);
    UNTIL(gl_ready(1));
    struct xm_client *d = g_t[0].xh.f.cl_dl;
    g_stale_node = g_key;
    g_stale_on = 1;
    g_now += 1000;
    turn();
    check("dl serve free: the block client retired while the flow runs it", 1, d->not_used && d->running == 1);
    job_at(0);
    turns(3);
    check("dl serve free: no link left for main", H2_EFULL, done_rc(0));
    UNTIL(P_GONE(p_nth_on(1, 1)));
    check("dl serve free: the retired block link closed", 1, P_GONE(p_nth_on(1, 1)));
    struct xh_flow *f = &g_t[0].xh.f;
    check("dl serve free: nothing held", 1, !f->cl && !f->cl_dl && !f->hold[0] && !f->hold[1]);
    g_stale_on = 0;
    g_hold = 0;
    check("dl serve free: the other node's flow goes on", 1, gl_echo(1, "on"));
    gl_end();
}

/* catches: the dl choose evicting the idle main link the flow just chose */
static void t_dl_place_keeps_its_main_link(void) {
    static char k1[4], k2[4];
    gl_begin(1);
    tr_xmux_links_cap = 3;
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    gl_attach_dl(0, &n, k1);
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    gl_close(0);
    turns(5);
    gl_attach_dl(1, &n, k2);
    UNTIL(gl_ready(1) && P_NSID_AT(1) == 2);
    turns(3);
    check("dl place pin: waits for the block's slot", XA_WAIT, gl_attach_dl(2, &n, k1));
    turns(5);
    check("dl place pin: no new link", 3, P_ACCEPTS());
    check("dl place pin: the idle main link kept for it", 1, P_OPEN(p_first_on(0)));
    gl_close(1);
    UNTIL(gl_ready(2));
    check("dl place pin: runs once the block frees", 1, gl_ready(2));
    check("dl place pin: no link added meanwhile", 3, P_ACCEPTS());
    check("dl place pin: echo", 1, gl_echo(2, "kept"));
    gl_end();
}

/* catches: POST response bytes on a main link held or never credited */
static void t_dl_post_padding_discarded(void) {
    gl_begin(0);
    P_SET(split, 1);
    P_SET(pad_post, 1572864);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "stream-up");
    gl_attach_dl(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID_AT(0) == 1 && P_NSID_AT(1) == 1);
    int mc = p_first_on(0);
    UNTIL(p_get(21, mc, 0) == 0 && p_get(20, mc, 0) >= (1572864 - 4095) / 1024);
    turns(5);
    check("dl padding: all of it sent", 0, p_get(21, mc, 0));
    check("dl padding: the stream credited", 1, p_get(20, mc, 0) >= (1572864 - 4095) / 1024);
    check("dl padding: the connection credited past the preface", 1, p_get(19, mc, 0) >= (1073741824 + 1572864 - 4095) / 1024);
    check("dl padding: main link open", 1, P_OPEN(mc));
    check("dl padding: echo after", 1, gl_echo(0, "after"));
    gl_end();
}

/* catches: a 400 POST answer with a body not failing the next write */
static void t_dl_post_400_body_fails_the_write(void) {
    gl_begin(0);
    P_SET(split, 2);
    P_SET(post_status, 400);
    P_SET(post_body, 1);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    gl_attach_dl(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    check("dl 400 body: sent", 0, gl_post(0, "x"));
    UNTIL(gl_answered(0));
    turns(3);
    check("dl 400 body: the next write fails", H2_ESTATUS, transport_write(&g_t[0], (const unsigned char *)"y", 1));
    gl_end();
}

/* catches: a manager evicted for a dl attach that then fails for want of its second slot */
static void t_dl_no_eviction_without_both_slots(void) {
    static char k1[4], k2[4], k3[4];
    gl_begin(0);
    tr_xmux_mgrs_cap = 2;
    struct tr_node m = gl_node(g_p.port, "xmux.maxConnections=1\nxmux.hKeepAlivePeriod=-1\nxmux.hMaxRequestTimes=10\n");
    gl_attach(0, &m, k1);
    UNTIL(gl_ready(0));
    gl_close(0);
    uint64_t t0 = g_now;
    for (g_now = t0 + 1000; g_now <= t0 + 300000; g_now += 1000) turn();
    UNTIL(P_GONE(0));
    gl_attach(1, &m, k2);
    UNTIL(gl_ready(1));
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    check("dl both slots: refused", XA_NONE, gl_attach_dl(2, &n, k3));
    check("dl both slots: the idle node's flow", XA_WAIT, gl_attach(3, &m, k1));
    check("dl both slots: its manager was kept", 8, g_t[3].xh.f.cl->left_requests);
    gl_end();
}

/* catches: a block shared by two nodes retired when only one goes stale */
static void t_dl_shared_block_outlives_one_stale_node(void) {
    static char k1[4], k2[4];
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    gl_attach_dl(0, &n, k1);
    UNTIL(gl_ready(0));
    gl_attach_dl(1, &n, k2);
    UNTIL(gl_ready(1));
    struct xm_client *d = g_t[0].xh.f.cl_dl;
    check("dl stale: one block client", 1, d == g_t[1].xh.f.cl_dl);
    g_stale_on = 1;
    g_stale_node = k1;
    g_now += 1000;
    turns(5);
    check("dl stale: the stale node's main retired", 1, g_t[0].xh.f.cl->not_used);
    check("dl stale: the shared block kept", 0, d->not_used);
    g_stale_node2 = k2;
    g_now += 1000;
    turns(5);
    check("dl stale: retired once no live node uses it", 1, d->not_used);
    gl_end();
}

/* catches: an idle block link evicted while main's choose fills the table */
static void t_dl_block_pinned_while_main_is_chosen(void) {
    static char k1[4];
    gl_begin(1);
    tr_xmux_links_cap = 3;
    P_SET(split, 1);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=2\n", "stream-up");
    gl_attach_dl(0, &n, k1);
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    gl_close(0);
    turns(5);
    gl_attach_dl(1, &n, k1);
    UNTIL(gl_ready(1) && P_ACC(1) == 2);
    turns(5);
    check("dl block pin: waits on main", XA_WAIT, gl_attach_dl(2, &n, k1));
    check("dl block pin: holds the idle block link", 1, g_t[2].xh.f.hold[1] != NULL);
    turns(5);
    check("dl block pin: no new link", 3, P_ACCEPTS());
    check("dl block pin: the block link not closed under it", 1, P_OPEN(p_first_on(1)));
    gl_close(1);
    UNTIL(gl_ready(2));
    UNTIL(P_NSID(p_first_on(1)) == 2);
    check("dl block pin: the GET on the block link it held", 2, P_NSID(p_first_on(1)));
    gl_end();
}

/* catches: two flows each holding the side the other waits on */
static void t_dl_cross_wait_no_deadlock(void) {
    gl_begin(1);
    tr_xmux_links_cap = 2;
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    gl_attach_dl(2, &n, g_key);
    UNTIL(gl_ready(2) && P_NSID_AT(1) == 1);
    turns(5);
    check("dl cross: A waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    check("dl cross: D waits", XA_WAIT, gl_attach_dl(1, &n, g_key));
    check("dl cross: A holds nothing while it waits on the block", 1, !g_t[0].xh.f.hold[0] && !g_t[0].xh.f.hold[1]);
    check("dl cross: D holds nothing while it waits on the block", 1, !g_t[1].xh.f.hold[0] && !g_t[1].xh.f.hold[1]);
    gl_close(2);
    UNTIL(gl_ready(0) || gl_ready(1));
    int first = gl_ready(0) ? 0 : 1;
    check("dl cross: one starts once the block frees", 1, gl_ready(first));
    check("dl cross: the other still waits", 0, gl_ready(1 - first));
    gl_close(first);
    UNTIL(gl_ready(1 - first));
    check("dl cross: the other starts after it", 1, gl_ready(1 - first));
    gl_end();
}

/* catches: a waiting flow with no deadline, or its waited links keeping weight after it */
static void t_dl_wait_deadline(void) {
    gl_begin(1);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    g_hold = 1;
    check("dl deadline: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    uint64_t t0 = g_now;
    for (g_now = t0 + 1000; g_now < t0 + 8000; g_now += 1000) turn();
    check("dl deadline: still waiting before the dial timeout", 1, done_rc(0));
    check("dl deadline: not retried yet", 0, g_t[0].xh.f.wait_n);
    g_now = t0 + 8000;
    turns(2);
    check("dl deadline: retried at the dial timeout", 1, g_t[0].xh.f.wait_n);
    check("dl deadline: no wake yet", 1, done_rc(0));
    for (g_now = t0 + 9000; g_now < t0 + 16000; g_now += 1000) turn();
    check("dl deadline: still waiting on the retry", 1, done_rc(0));
    g_now = t0 + 16000;
    turns(2);
    check("dl deadline: fails as a dial failure", TR_ECONNTIMEOUT, done_rc(0));
    check("dl deadline: nothing held", 1, !g_t[0].xh.f.cl && !g_t[0].xh.f.cl_dl && !g_t[0].xh.f.wait);
    g_hold = 0;
    jobs_run();
    turns(3);
    gl_close(0);
    check("dl deadline: a later flow", 1, gl_attach_dl(1, &n, g_key) >= 0);
    UNTIL(gl_ready(1));
    turns(5);
    check("dl deadline: the links it waited on keep no weight", 1, P_ACC(0) == 1 && P_ACC(1) == 1);
    gl_end();
}

/* catches: a held block that dies left in the flow or its client kept */
static void t_dl_held_block_dies(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    g_hold = 1;
    check("dl held dies: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    job_link(g_t[0].xh.f.wait);
    turns(3);
    check("dl held dies: holds the block while main dials", 1, g_t[0].xh.f.hold[1] != NULL);
    struct xm_client *d = g_t[0].xh.f.cl_dl;
    p_cmd(p_first_on(1), 1, 0, 0);
    UNTIL(!g_t[0].xh.f.hold[1]);
    check("dl held dies: the hold is gone with the link", 1, !g_t[0].xh.f.hold[1]);
    check("dl held dies: its client failed", 1, d->closed);
    g_hold = 0;
    UNTIL(gl_ready(0) && P_ACC(1) == 2);
    check("dl held dies: started", 1, gl_ready(0));
    check("dl held dies: on a new block link", 2, P_ACC(1));
    gl_end();
}

/* catches: another flow taking the stream slot a held link reserved */
static void t_dl_held_block_slot_not_taken(void) {
    gl_begin(1);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    g_hold = 1;
    check("dl held slot: A waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    job_link(g_t[0].xh.f.wait);
    turns(3);
    struct xconn *b1 = g_t[0].xh.f.hold[1];
    check("dl held slot: A holds the block while main dials", 1, b1 && g_t[0].xh.f.wait != b1);
    check("dl held slot: C waits", XA_WAIT, gl_attach_dl(1, &n, g_key));
    check("dl held slot: C does not take A's block slot", 1, !g_t[1].xh.f.hold[1] && g_t[1].xh.f.wait != b1);
    g_hold = 0;
    UNTIL(gl_ready(0) && gl_ready(1));
    check("dl held slot: A's GET on the block link it held", 1, g_t[0].xh.f.down.x == b1);
    check("dl held slot: C's GET elsewhere", 1, g_t[1].xh.f.down.x && g_t[1].xh.f.down.x != b1);
    gl_end();
}

/* catches: a waiter served into a slot a holder reserved */
static void t_dl_waiter_behind_a_hold(void) {
    gl_begin(1);
    tr_xmux_links_cap = 2;
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    g_hold = 1;
    check("dl behind hold: A waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    job_link(g_t[0].xh.f.wait);
    turns(3);
    struct xconn *b1 = g_t[0].xh.f.hold[1];
    check("dl behind hold: A holds the block", 1, b1 != NULL);
    check("dl behind hold: C waits", XA_WAIT, gl_attach_dl(1, &n, g_key));
    check("dl behind hold: C waits on the block A holds", 1, g_t[1].xh.f.wait == b1);
    turns(3);
    check("dl behind hold: C not started", 0, gl_ready(1));
    g_hold = 0;
    UNTIL(gl_ready(0));
    check("dl behind hold: A starts on it", 1, g_t[0].xh.f.down.x == b1);
    turns(3);
    check("dl behind hold: C still waits", 0, gl_ready(1));
    gl_close(0);
    UNTIL(gl_ready(1));
    check("dl behind hold: C starts once A is gone", 1, g_t[1].xh.f.down.x == b1);
    gl_end();
}

/* catches: a flow kept on a held block after GOAWAY, or its retry spent on it */
static void t_dl_held_block_goaway(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    g_hold = 1;
    check("dl held goaway: waits", XA_WAIT, gl_attach_dl(0, &n, g_key));
    job_link(g_t[0].xh.f.wait);
    turns(3);
    struct xconn *b1 = g_t[0].xh.f.hold[1];
    check("dl held goaway: holds the block", 1, b1 != NULL);
    p_cmd(p_first_on(1), 0, 1, 0);
    UNTIL(b1->h2.goaway);
    turns(3);
    job_link(g_t[0].xh.f.wait);
    turns(3);
    check("dl held goaway: waits on a new block link", 1, g_t[0].xh.f.wait && g_t[0].xh.f.wait->state == XC_DIALING);
    check("dl held goaway: holds nothing while it waits on the block", 1, !g_t[0].xh.f.hold[0] && !g_t[0].xh.f.hold[1]);
    g_hold = 0;
    UNTIL(done_rc(0) != 1 && gl_ready(0));
    check("dl held goaway: started", 0, done_rc(0));
    check("dl held goaway: a held link going away costs no retry", 0, g_t[0].xh.f.wait_n);
    UNTIL(P_ACC(1) >= 2);
    check("dl held goaway: a new block connection", 2, P_ACC(1));
    UNTIL(P_NSID(p_nth_on(1, 1)) == 1);
    check("dl held goaway: the GET on the new one", 1, P_NSID(p_nth_on(1, 1)));
    check("dl held goaway: none on the one that went away", 0, P_NSID(p_nth_on(1, 0)));
    gl_end();
}

/* catches: discard credit queued per frame while the socket does not drain */
static void t_dl_discard_credit_coalesced(void) {
    gl_begin(0);
    p_rcvbuf(4096);
    P_SET(split, 1);
    P_SET(pad_post, 983040);
    P_SET(pad_go, 0);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "stream-up");
    gl_attach_dl(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID_AT(0) == 1 && P_NSID_AT(1) == 1);
    turns(3);
    struct xconn *m = g_t[0].xh.f.up.x;
    int sb = 4096;
    setsockopt(m->link.fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    int mc = p_first_on(0);
    p_noread(mc);
    for (int i = 0; i < 128 && transport_write(&g_t[0], gl_big, 1024) == 0; i++) turn();
    turns(5);
    size_t b0 = m->out.n;
    check("dl coalesce: the main link's socket is blocked", 1, b0 > 0);
    P_SET(pad_go, 1);
    UNTIL(p_get(21, mc, 0) == 0);
    turns(10);
    size_t b1 = m->out.n;
    check("dl coalesce: all padding sent", 0, p_get(21, mc, 0));
    check("dl coalesce: at most one update queued for the stream and one for the connection", 1, b1 >= b0 && b1 - b0 <= 26);
    p_read_again(mc);
    UNTIL(p_get(20, mc, 0) >= (983040 - 4095) / 1024);
    check("dl coalesce: the held-back credit is paid once the socket drains", 1, p_get(20, mc, 0) >= (983040 - 4095) / 1024);
    gl_end();
}

/* catches: a batched POST taking the freed slot ahead of a waiting flow */
static void t_waiter_beats_queued_posts(void) {
    gl_begin(2);
    tr_xmux_links_cap = 1;
    P_SET(split, 2);
    P_SET(hold, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("waiter: seq 0", 0, gl_post(0, "s0"));
    UNTIL(P_NHELD(0) == 1);
    check("waiter: B waits on the full link", XA_WAIT, gl_attach(1, &n, g_key));
    check("waiter: seq 1 batched", 0, transport_write(&g_t[0], (const unsigned char *)"s1", 2));
    turns(3);
    check("waiter: seq 1 held for a slot", 2, (int)g_t[0].xh.f.bat.n);
    p_release(0);
    UNTIL(gl_ready(1));
    turns(3);
    check("waiter: B took the freed slot", 1, gl_ready(1));
    check("waiter: seq 1 still waits behind it", 2, (int)g_t[0].xh.f.bat.n);
    gl_end();
}

/* catches: a POST waiting on a held dial with no deadline */
static void t_post_wait_deadline(void) {
    gl_begin(0);
    P_SET(split, 2);
    struct tr_node n = gl_mode("xmux.hMaxRequestTimes=3\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("post deadline: seq 0", 0, gl_post(0, "s0"));
    g_hold = 1;
    check("post deadline: seq 1 taken", 0, transport_write(&g_t[0], (const unsigned char *)"s1", 2));
    turns(3);
    check("post deadline: the POST waits for a dial", 1, g_t[0].xh.f.post_wait);
    uint64_t t0 = g_now;
    for (g_now = t0 + 1000; g_now < t0 + 8000; g_now += 1000) turn();
    check("post deadline: still waiting before the dial timeout", 1, g_t[0].xh.f.post_wait);
    g_now = t0 + 8000;
    turns(2);
    check("post deadline: the upload fails as a dial failure", TR_ECONNTIMEOUT, gl_until_read(0));
    g_hold = 0;
    gl_end();
}

/* catches: the LATE pass flushing batched POSTs before it serves waiters */
static void t_late_serves_before_batched_posts(void) {
    gl_begin(3);
    tr_xmux_links_cap = 1;
    P_SET(split, 2);
    P_SET(hold, 1);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "packet-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    check("late order: C ready", XA_READY, gl_attach(2, &n, g_key));
    UNTIL(P_NSID(0) == 2);
    check("late order: seq 0", 0, gl_post(0, "s0"));
    UNTIL(P_NHELD(0) == 1);
    check("late order: B waits on the full link", XA_WAIT, gl_attach(1, &n, g_key));
    check("late order: seq 1 batched", 0, transport_write(&g_t[0], (const unsigned char *)"s1", 2));
    turns(3);
    check("late order: seq 1 held for a slot", 2, (int)g_t[0].xh.f.bat.n);
    gl_close(2);
    tr_xmux_pass(g_now, MUXP_LATE);
    check("late order: B takes the slot freed by a local close", 1, gl_ready(1));
    check("late order: seq 1 still waits behind it", 2, (int)g_t[0].xh.f.bat.n);
    gl_end();
}

/* catches: DATA on a dead stream refunded later than Go's 4096 B rule, or twice */
static void t_dead_stream_credit_per_frame(void) {
    gl_begin(0);
    p_rcvbuf(4096);
    P_SET(split, 1);
    P_SET(noecho, 1);
    P_SET(pad_get, 1);
    P_SET(pad_post, 40960 + 983040);
    P_SET(pad_cap, 40960);
    P_SET(pad_go, 0);
    struct tr_node n = gl_mode("xmux.maxConnections=1\n", "stream-up");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 2);
    turns(3);
    long before = (long)p_get(19, 0, 0);
    struct xconn *x = g_t[0].xh.f.up.x;
    int sb = 4096;
    setsockopt(x->link.fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    p_noread(0);
    for (int i = 0; i < 128 && transport_write(&g_t[0], gl_big, 1024) == 0; i++) turn();
    turns(5);
    P_SET(pad_go, 1);
    gl_got[0] = 0;
    for (uint64_t dl = ms_now() + 3000; ms_now() < dl;) {
        turn();
        size_t got = 0;
        unsigned char sink[4096];
        if (transport_read(&g_t[0], sink, sizeof sink, &got)) break;
        gl_got[0] += got;
        if (gl_got[0] >= 40960) break;
    }
    check("dead credit: the live part read", 40960, (long)gl_got[0]);
    turns(5);
    gl_close(0);
    turns(5);
    size_t b0 = x->out.n;
    check("dead credit: the socket is blocked", 1, b0 > 0);
    P_SET(pad_cap, 0);
    UNTIL(p_get(21, 0, 0) == 0);
    turns(10);
    size_t b1 = x->out.n;
    check("dead credit: all DATA on the reset stream sent", 0, p_get(21, 0, 0));
    check("dead credit: one WINDOW_UPDATE(0, 4096) per 4096 B frame", 240 * 13, (long)(b1 - b0));
    p_read_again(0);
    long want = before + (40960 + 983040 - 4095) / 1024;
    UNTIL(p_get(19, 0, 0) >= want);
    turns(10);
    long after = (long)p_get(19, 0, 0);
    check("dead credit: paid once the socket drains", 1, after >= want);
    check("dead credit: paid once, not twice", 1, after <= before + (40960 + 983040) / 1024 + 1);
    gl_end();
}

/* catches: the main pin left set after the block's choose */
static void t_pin_is_released(void) {
    static char k1[4], k2[4];
    gl_begin(0);
    tr_xmux_links_cap = 2;
    P_SET(split, 2);
    struct tr_node n = gl_dl("xmux.maxConnections=1\n", "xmux.maxConnections=1\n", "packet-up");
    gl_attach_dl(0, &n, k1);
    UNTIL(gl_ready(0) && P_NSID_AT(1) == 1);
    gl_close(0);
    turns(5);
    struct tr_node m = gl_mode("xmux.maxConnections=2\n", "packet-up");
    check("pin released: a flow of another node takes an idle link", XA_WAIT, gl_attach(1, &m, k2));
    UNTIL(gl_ready(1));
    check("pin released: a second one takes the last idle link", XA_WAIT, gl_attach(2, &m, k2));
    UNTIL(gl_ready(2));
    check("pin released: both run", 1, gl_ready(1) && gl_ready(2));
    gl_end();
}

static void t_budget_per_loop(void) {
    gl_begin(0);
    struct mux_host h = GL_HOST;
    h.loops = 4096;
    tr_xmux_host(&h, gl_stale);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    static unsigned char msg[9000];
    memset(msg, 'b', sizeof msg);
    /* catches: every loop given the whole process ceiling */
    check("loop budget: 9000 written", 0, transport_write(&g_t[0], msg, sizeof msg));
    struct xconn *x = g_t[0].xh.f.one.x;
    UNTIL(!xconn_wants_in(x));
    check("loop budget: paused at 32 MiB / 4096", 0, xconn_wants_in(x));
    check("loop budget: held at least 8192", 1, xc_held() >= 8192);
    gl_end();
}

static void t_paused_link_disarmed(void) {
    gl_begin(0);
    struct tr_node n = gl_node(g_p.port, "xmux.maxConnections=1\n");
    gl_attach(0, &n, g_key);
    UNTIL(gl_ready(0) && P_NSID(0) == 1);
    xc_budget_set(1024, 2048, 1536);
    static unsigned char msg[4000];
    memset(msg, 'm', sizeof msg);
    /* catches: a level-triggered paused socket spinning the loop */
    check("disarm: 4000 written", 0, transport_write(&g_t[0], msg, sizeof msg));
    struct xconn *x = g_t[0].xh.f.one.x;
    UNTIL(!xconn_wants_in(x));
    turns(3);
    int fd = x->link.fd;
    check("disarm: paused", 0, xconn_wants_in(x));
    check("disarm: crossed the ceiling", 1, xc_held() >= 2048);
    check("disarm: watched", 1, g_wev[fd] != 0);
    check("disarm: no EPOLLIN while paused", 0, (long)(g_wev[fd] & EPOLLIN));
    static unsigned char got[4000];
    size_t tot = 0;
    uint64_t dl = ms_now() + 3000;
    while (!xconn_wants_in(x) && ms_now() < dl) {
        size_t k = 0;
        if (transport_read(&g_t[0], got + tot, 100, &k) || !k) break;
        tot += k;
    }
    check("disarm: resumed under 1536", 1, xconn_wants_in(x) && xc_held() < 1536);
    tr_xmux_pass(g_now, MUXP_LATE);
    check("disarm: the LATE pass arms EPOLLIN", EPOLLIN, (long)(g_wev[fd] & EPOLLIN));
    dl = ms_now() + 3000;
    while (tot < sizeof got && ms_now() < dl) {
        size_t k = 0;
        turn();
        if (transport_read(&g_t[0], got + tot, sizeof got - tot, &k)) break;
        tot += k;
    }
    check("disarm: all 4000 echoed", 4000, (long)tot);
    check("disarm: the bytes", 0, memcmp(got, msg, sizeof msg));
    gl_end();
}

static void glue(void) {
    signal(SIGPIPE, SIG_IGN);
    g_now = 1000000;
    tr_xmux_rnd = rnd_zero;
    t_two_flows_one_accept();
    t_first_headers_before_ack();
    t_refused_before_settings_retried();
    t_refused_after_write_ends();
    t_refused_retry_fails();
    t_refused_stream_up_reads_again();
    t_refused_twice_ends();
    t_refused_post_resent();
    t_refused_get_reopened();
    t_refused_post_unkept();
    t_refused_post_bounded();
    t_refused_get_twice_ends();
    t_refused_get_waits();
    t_refused_post_past_window();
    t_redo_stack();
    t_refused_post_past_pend();
    t_refused_post_pend_busy();
    t_refused_post_waits_for_slot();
    t_refused_get_own_deadline();
    t_default_three();
    t_waiters_share_a_dial();
    t_dial_fail_retries_once();
    t_close_cancels();
    t_kill_resets_both();
    t_idle_redial();
    t_retire_after_requests();
    t_goaway_no_new_flow();
    t_goaway_none_refused();
    t_goaway_refused_orphan();
    t_goaway_after_answers_keeps_client();
    t_reset_before_headers();
    t_close_sends_fin();
    t_overflow_by_stream_cap();
    t_links_cap_closes_idle();
    t_links_cap_shares_busy();
    t_mgrs_cap();
    t_stale_node_closes();
    t_ping_wired();
    t_encryption_stays_private();
    t_stream_up_same_link();
    t_packet_up_posts_move();
    t_posts_keep_a_retired_link();
    t_post_reset_closes_client();
    t_post_400_keeps_client();
    t_streamup_post_fail_keeps_client();
    t_streamup_clean_end_keeps_flow();
    t_packet_window_across_links();
    t_writes_coalesce();
    t_posts_paced();
    t_room_budget_wake();
    t_room_batch_full_wake();
    t_budget_hard_many();
    t_uploaders_counted_exactly();
    t_idle_shrink_is_a_deadline();
    t_idle_due_is_the_nearest();
    t_reservation_ramps();
    t_idle_reservation_shrinks();
    t_share_among_uploaders();
    t_wake_after_all_flushes();
    t_paused_link_disarmed();
    t_budget_per_loop();
    t_close_frees_wakes();
    t_wake_no_double();
    t_partial_send_counts();
    t_post_one_frame();
    t_batch_holds_a_write_past_post_max();
    t_serve_skips_big_waiter();
    t_post_waits_for_window();
    t_post_waits_for_a_stream_slot();
    t_header_post_waits_for_a_stream_slot();
    t_stream_up_needs_two_slots();
    t_post_dial_fail();
    t_room_never_decides();
    t_post_goaway_redials();
    t_post_link_survives_lru();
    t_get_reset_closes_client();
    t_swept_post_client_kept();
    t_dead_post_link_redials();
    t_dl_two_pools();
    t_dl_waits_for_both();
    t_dl_waits_for_main();
    t_dl_defaults_per_block();
    t_dl_requests_per_side();
    t_dl_get_reset_fails_block_client();
    t_dl_post_redials_main();
    t_dl_posts_move_on_main();
    t_dl_mgr_slots();
    t_dl_no_link_gives_back();
    t_dl_stream_up_one_slot_each();
    t_dl_found_block_kept();
    t_dl_failed_flow_keeps_its_managers();
    t_dl_serve_keeps_its_link();
    t_dl_serve_frees_its_link();
    t_dl_place_keeps_its_main_link();
    t_dl_block_pinned_while_main_is_chosen();
    t_dl_cross_wait_no_deadlock();
    t_dl_wait_deadline();
    t_dl_held_block_dies();
    t_dl_held_block_slot_not_taken();
    t_dl_waiter_behind_a_hold();
    t_dl_held_block_goaway();
    t_dl_discard_credit_coalesced();
    t_waiter_beats_queued_posts();
    t_post_wait_deadline();
    t_late_serves_before_batched_posts();
    t_dead_stream_credit_per_frame();
    t_pin_is_released();
    t_dl_post_padding_discarded();
    t_dl_post_400_body_fails_the_write();
    t_dl_no_eviction_without_both_slots();
    t_dl_shared_block_outlives_one_stale_node();
    close(g_ep);
}

/* catches: the held-upload limit not split among loops like the other budgets */
static void t_pend_limit_per_loop(void) {
    struct mux_host h = GL_HOST;
    h.loops = 4;
    tr_xmux_host(&h, gl_stale);
    check("pend limit: 524288 / 4 loops", 131072, (long)xc_pend_limit());
    h.loops = 1;
    tr_xmux_host(&h, gl_stale);
    check("pend limit: one loop takes it all", 524288, (long)xc_pend_limit());
}

int main(void) {
    t_draw();
    t_pend_limit_per_loop();
    t_defaults_three_then_random();
    t_neither_set_one();
    t_concurrency();
    t_c_reuse();
    t_h_requests();
    t_h_secs_boundary();
    t_failed_retires();
    t_post_moves();
    t_refs_keep_conn();
    t_clients_cap();
    t_conn_new_fails();
    t_unbalanced_unref();
    t_retire_all();
    glue();
    return unit_done("xmuxmatch");
}
