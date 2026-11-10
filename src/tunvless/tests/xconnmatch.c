#define main vlessmatch_main
#include "vlessmatch.c"
#undef main

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include "xconn.h"
#include "trxmux.h"

ssize_t __real_send(int fd, const void *b, size_t n, int fl);
static long g_send_ok, g_send_again;

void *__real_malloc(size_t n);
static int g_chunk_fail;
static int g_hs_fail, g_hs_tries;

void *__wrap_malloc(size_t n) {
    if (g_hs_fail && n == 81920) {
        g_hs_tries++;
        errno = ENOMEM;
        return NULL;
    }
    if (g_chunk_fail && n >= XC_CHUNK) {
        g_chunk_fail = 0;
        errno = ENOMEM;
        return NULL;
    }
    return __real_malloc(n);
}

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

ssize_t __wrap_send(int fd, const void *b, size_t n, int fl) {
    ssize_t r = __real_send(fd, b, n, fl);
    if (r >= 0) g_send_ok++;
    else if (errno == EAGAIN || errno == EWOULDBLOCK) g_send_again++;
    return r;
}

struct wk { uint16_t owner; unsigned what; int rc; };
static struct wk g_wk[1024];
static int g_wk_n;

static void rec_wake(void *arg, uint16_t owner, unsigned what, int rc) {
    (void)arg;
    if (g_wk_n < (int)(sizeof g_wk / sizeof g_wk[0])) g_wk[g_wk_n++] = (struct wk){ owner, what, rc };
}

static const struct xc_host HOST = { rec_wake, NULL };

static int wakes(uint16_t owner, unsigned what) {
    int k = 0;
    for (int i = 0; i < g_wk_n; i++)
        if (g_wk[i].owner == owner && g_wk[i].what == what) k++;
    return k;
}

static int wake_rc(uint16_t owner, unsigned what) {
    for (int i = 0; i < g_wk_n; i++)
        if (g_wk[i].owner == owner && g_wk[i].what == what) return g_wk[i].rc;
    return 12345;
}

static uint64_t mono_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000u + (uint64_t)t.tv_nsec / 1000u;
}

static uint16_t g_port;

static int listen_lo(int rcvbuf) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (rcvbuf) setsockopt(l, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof a;
    if (bind(l, (struct sockaddr *)&a, sizeof a) || listen(l, 8) ||
        getsockname(l, (struct sockaddr *)&a, &al)) {
        close(l);
        return -1;
    }
    g_port = ntohs(a.sin_port);
    return l;
}

static struct tr_node plain_node(uint16_t port) {
    struct tr_node n;
    memset(&n, 0, sizeof n);
    n.host = "127.0.0.1";
    n.port = port;
    n.type = "xhttp";
    n.security = "none";
    n.sni = "";
    n.fp = "chrome";
    return n;
}

static char g_pbk[64];

static struct tr_node tls_node(uint16_t port) {
    struct tr_node n = plain_node(port);
    n.security = "reality";
    n.sni = "www.example.com";
    n.pbk = g_pbk;
    n.sid = "0123456789abcdef";
    return n;
}

static size_t peer_drain(int fd, unsigned char *b, size_t cap, int wait_ms) {
    size_t n = 0;
    while (n < cap) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        if (poll(&p, 1, wait_ms) <= 0) break;
        ssize_t r = read(fd, b + n, cap - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    return n;
}

static int fd_pending(int fd) {
    int v = -1;
    ioctl(fd, FIONREAD, &v);
    return v;
}

static size_t frame(unsigned char *o, uint32_t len, unsigned type, unsigned flags, uint32_t sid, const void *body) {
    o[0] = (unsigned char)(len >> 16);
    o[1] = (unsigned char)(len >> 8);
    o[2] = (unsigned char)len;
    o[3] = (unsigned char)type;
    o[4] = (unsigned char)flags;
    o[5] = (unsigned char)((sid >> 24) & 0x7f);
    o[6] = (unsigned char)(sid >> 16);
    o[7] = (unsigned char)(sid >> 8);
    o[8] = (unsigned char)sid;
    if (len && body) memcpy(o + 9, body, len);
    else if (len) memset(o + 9, 'q', len);
    return 9 + len;
}

static void pw(int fd, unsigned type, unsigned flags, uint32_t sid, const void *body, uint32_t len) {
    static unsigned char b[9 + 65536];
    size_t n = frame(b, len, type, flags, sid, body);
    wr_all(fd, b, n);
}

static void pw_u32(int fd, unsigned type, uint32_t sid, uint32_t v) {
    unsigned char b[4] = { (unsigned char)(v >> 24), (unsigned char)(v >> 16), (unsigned char)(v >> 8),
                           (unsigned char)v };
    pw(fd, type, 0, sid, b, 4);
}

static void pw_settings_win(int fd, uint32_t init) {
    unsigned char s[6] = { 0, 4, (unsigned char)(init >> 24), (unsigned char)(init >> 16),
                           (unsigned char)(init >> 8), (unsigned char)init };
    pw(fd, FR_SETTINGS, 0, 0, s, 6);
}

static const unsigned char ST200[1] = { 0x88 };

struct fv { unsigned type, flags; uint32_t sid, len; const unsigned char *p; };

static uint32_t be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int parse(const unsigned char *b, size_t n, struct fv *f, int max) {
    size_t i = 0;
    int k = 0;
    if (n >= 24 && !memcmp(b, "PRI * HTTP/2.0", 14)) i = 24;
    while (i + 9 <= n && k < max) {
        uint32_t len = ((uint32_t)b[i] << 16) | ((uint32_t)b[i + 1] << 8) | b[i + 2];
        if (i + 9 + len > n) break;
        f[k].len = len;
        f[k].type = b[i + 3];
        f[k].flags = b[i + 4];
        f[k].sid = be32(b + i + 5) & 0x7fffffffu;
        f[k].p = b + i + 9;
        k++;
        i += 9 + len;
    }
    return k;
}

static unsigned char g_pb[1 << 21];
static struct fv g_fv[8192];

static int peer_frames(int fd, int wait_ms) {
    size_t n = peer_drain(fd, g_pb, sizeof g_pb, wait_ms);
    return parse(g_pb, n, g_fv, (int)(sizeof g_fv / sizeof g_fv[0]));
}

static int count_type(int k, unsigned type, long sid) {
    int c = 0;
    for (int i = 0; i < k; i++)
        if (g_fv[i].type == type && (sid < 0 || g_fv[i].sid == (uint32_t)sid)) c++;
    return c;
}

static long wu_sum(int k, uint32_t sid, int *frames, uint32_t *min_inc) {
    long s = 0;
    int c = 0;
    uint32_t mn = UINT32_MAX;
    for (int i = 0; i < k; i++)
        if (g_fv[i].type == FR_WINDOW_UPDATE && g_fv[i].sid == sid && g_fv[i].len == 4) {
            uint32_t v = be32(g_fv[i].p) & 0x7fffffffu;
            s += v;
            c++;
            if (v < mn) mn = v;
        }
    if (frames) *frames = c;
    if (min_inc) *min_inc = mn;
    return s;
}

struct pl { struct xconn *x; int pfd; size_t pre_n; };

static int open_plain(struct pl *p, int shared, int64_t ka, int peer_rcvbuf, uint64_t now) {
    p->x = NULL;
    p->pfd = -1;
    int l = listen_lo(peer_rcvbuf);
    if (l < 0) return -1;
    struct tr_node n = plain_node(g_port);
    p->x = xconn_new(&n, ka, shared);
    if (!p->x) {
        close(l);
        return -1;
    }
    int rc = xconn_dial(p->x, 3);
    p->pfd = accept(l, NULL, NULL);
    close(l);
    unsigned char b[128];
    p->pre_n = p->pfd >= 0 ? peer_drain(p->pfd, b, sizeof b, 30) : 0;
    if (!rc && shared) rc = xconn_adopt(p->x, now);
    return rc;
}

static void close_plain(struct pl *p) {
    if (p->x) xconn_free(p->x);
    if (p->pfd >= 0) close(p->pfd);
    p->x = NULL;
    p->pfd = -1;
}

static int io_in(struct xconn *x, uint64_t now) {
    struct pollfd p = { .fd = x->link.fd, .events = POLLIN };
    poll(&p, 1, 200);
    return xconn_io(x, EPOLLIN, now);
}

static const struct h2_req RQ_GET = { .authority = "a.example", .path = "/d", .method = "GET", .end_stream = 1 };
static const struct h2_req RQ_POST = { .authority = "a.example", .path = "/u", .method = "POST" };

static unsigned char g_big[1 << 20];

struct bg { int fd; const unsigned char *b; size_t n; pthread_t th; };

static void *bg_run(void *a) {
    struct bg *g = a;
    wr_all(g->fd, g->b, g->n);
    return NULL;
}

static void bg_start(struct bg *g, int fd, const unsigned char *b, size_t n) {
    g->fd = fd;
    g->b = b;
    g->n = n;
    pthread_create(&g->th, NULL, bg_run, g);
}

static size_t read_all_of(const struct xs *s, unsigned char *out, size_t cap, int *end) {
    size_t tot = 0, got = 0;
    *end = 0;
    for (;;) {
        int rc = xs_read(s, out ? out + tot : g_pb, out ? cap - tot : sizeof g_pb, &got);
        if (rc) {
            *end = rc;
            break;
        }
        if (!got) break;
        tot += got;
    }
    return tot;
}

struct tp {
    struct srv s;
    struct plan pl;
    int lfd;
    pthread_t th;
    struct dir *cd, *sd;
};

static void *tp_run(void *a) {
    struct tp *p = a;
    p->s.fd = accept(p->lfd, NULL, NULL);
    if (p->s.fd < 0) return NULL;
    struct timeval tv = { .tv_sec = 3 };
    setsockopt(p->s.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return server_half(&p->s);
}

static int tp_start_rcv(struct tp *p, const char *alpn, int rcvbuf) {
    memset(p, 0, sizeof *p);
    p->pl.name = "xconn";
    p->pl.reality_ok = 1;
    p->pl.alpn = alpn;
    p->s.plan = &p->pl;
    p->s.fd = -1;
    p->lfd = listen_lo(rcvbuf);
    if (p->lfd < 0) return -1;
    return pthread_create(&p->th, NULL, tp_run, p);
}

static int tp_start(struct tp *p, const char *alpn) { return tp_start_rcv(p, alpn, 0); }

static int tp_finish(struct tp *p) {
    pthread_join(p->th, NULL);
    close(p->lfd);
    p->lfd = -1;
    if (p->s.rc || p->s.fd < 0) return -1;
    unsigned char zeros[HLEN] = { 0 }, empty[HLEN], derived[HLEN], master[HLEN], th[HLEN];
    unsigned char c_ap[HLEN], s_ap[HLEN];
    if (sc_hash(SC_SHA256, zeros, 0, empty)) return -1;
    if (xlabel(p->s.hs, "derived", empty, HLEN, derived, HLEN)) return -1;
    if (sc_hkdf_extract(SC_SHA256, derived, HLEN, zeros, HLEN, master)) return -1;
    tr_snapshot(&p->s.tr, th);
    if (xlabel(master, "c ap traffic", th, HLEN, c_ap, HLEN)) return -1;
    if (xlabel(master, "s ap traffic", th, HLEN, s_ap, HLEN)) return -1;
    p->cd = calloc(1, sizeof *p->cd);
    p->sd = calloc(1, sizeof *p->sd);
    if (!p->cd || !p->sd) return -1;
    if (client_finished(&p->s, p->cd) != 1) return -1;
    if (dir_set(p->cd, c_ap) || dir_set(p->sd, s_ap)) return -1;
    return 0;
}

static void tp_free(struct tp *p) {
    if (p->th && p->lfd >= 0) {
        pthread_join(p->th, NULL);
        close(p->lfd);
    }
    if (p->cd && p->cd->ready) sc_aead_free(&p->cd->g);
    if (p->sd && p->sd->ready) sc_aead_free(&p->sd->g);
    free(p->cd);
    free(p->sd);
    if (p->s.fd >= 0) close(p->s.fd);
    p->s.fd = -1;
}

static int tp_seal(struct dir *d, int fd, const unsigned char *msg, size_t n) {
    static unsigned char out[5 + 16384 + 17];
    if (n > 16384) return -1;
    size_t total = n + 1 + 16;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
    memcpy(out + 5, msg, n);
    out[5 + n] = 0x17;
    unsigned char nonce[12];
    dir_nonce(d, nonce);
    if (sc_aead_seal(&d->g, nonce, out, 5, out + 5, n + 1, out + 5 + n + 1)) return -1;
    d->seq++;
    return wr_all(fd, out, 5 + total);
}

static unsigned char g_rec[16384 + 256];

/* catches: two record formats, or a reused nonce */
static void t_seal_is_write(void) {
    struct tp p;
    check("seal: peer starts", 0, tp_start(&p, "h2"));
    struct tr_node n = tls_node(g_port);
    struct tr_link l;
    memset(&l, 0, sizeof l);
    int rc = tr_link_open(&l, &n, "h2", 3);
    check("seal: handshake", 0, rc);
    check("seal: peer keys", 0, tp_finish(&p));
    struct tls13 *b = calloc(1, sizeof *b);
    b->fd = -1;
    b->ready = 1;
    b->wr.aead = l.tls.wr.aead;
    b->wr.key_n = l.tls.wr.key_n;
    memcpy(b->wr.key, l.tls.wr.key, sizeof b->wr.key);
    memcpy(b->wr.iv, l.tls.wr.iv, sizeof b->wr.iv);
    b->wr_seq = l.tls.wr_seq;
    check("seal: copy keyed", 0, tls13_keys_setup(&b->wr));
    unsigned char msg[100];
    for (int i = 0; i < 100; i++) msg[i] = (unsigned char)(i * 7 + 1);
    unsigned char sealed[2][160];
    size_t sn[2] = { 0, 0 };
    check("seal: first record sealed", 0, tls13_seal(b, msg, 100, sealed[0], sizeof sealed[0], &sn[0]));
    check("seal: second record sealed", 0, tls13_seal(b, msg, 100, sealed[1], sizeof sealed[1], &sn[1]));
    check("seal: one record of 5 + 100 + 1 + 16 bytes", 122, (long)sn[0]);
    check("seal: room too small refused", TLS13_ETOOBIG, tls13_seal(b, msg, 100, g_rec, 121, &sn[1]));
    check("seal: write 1", 0, tls13_write(&l.tls, msg, 100));
    check("seal: write 2", 0, tls13_write(&l.tls, msg, 100));
    unsigned char wire[244];
    size_t got = 0;
    while (got < sizeof wire) {
        ssize_t r = recv(p.s.fd, wire + got, sizeof wire - got, MSG_PEEK);
        if (r <= 0) break;
        got = (size_t)r;
        if (got < sizeof wire) usleep(1000);
    }
    check("seal: two records on the wire", 244, (long)got);
    check("seal: first record equals tls13_write", 0, memcmp(wire, sealed[0], 122));
    check("seal: second record equals tls13_write", 0, memcmp(wire + 122, sealed[1], 122));
    size_t on = 0;
    unsigned char inner = 0;
    check("seal: peer opens record 0", 0, rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &on, &inner));
    check("seal: peer opens record 1 (fresh nonce)", 0, rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &on, &inner));
    check("seal: plaintext back", 0, on == 100 ? memcmp(g_rec, msg, 100) : -1);
    tls13_keys_free(&b->wr);
    free(b);
    tr_link_close(&l);
    tp_free(&p);
}

static int peer_lens(struct tp *p, size_t *lens, int max, int want) {
    int k = 0;
    while (k < max && k < want) {
        size_t n = 0;
        unsigned char inner = 0;
        if (rec_open(p->cd, p->s.fd, g_rec, sizeof g_rec, &n, &inner)) break;
        lens[k++] = n;
    }
    return k;
}

struct rw { struct tr_link *l; size_t n; int rc; pthread_t th; };

static void *rw_run(void *a) {
    struct rw *w = a;
    unsigned char *buf = calloc(1, w->n ? w->n : 1);
    w->rc = buf ? tls13_write(&w->l->tls, buf, w->n) : -1;
    free(buf);
    return NULL;
}

static int ramp_open(struct tp *p, struct tr_link *l, const char *what) {
    char nm[64];
    snprintf(nm, sizeof nm, "%s: peer starts", what);
    check(nm, 0, tp_start(p, "h2"));
    struct tr_node n = tls_node(g_port);
    memset(l, 0, sizeof *l);
    snprintf(nm, sizeof nm, "%s: handshake", what);
    check(nm, 0, tr_link_open(l, &n, "h2", 3));
    snprintf(nm, sizeof nm, "%s: peer keys", what);
    int rc = tp_finish(p);
    check(nm, 0, rc);
    return rc;
}

static void ramp_expect(const char *what, struct tp *p, const size_t *want, int n) {
    size_t got[128];
    int k = peer_lens(p, got, 128, n);
    check(what, n, k);
    for (int i = 0; i < k && i < n; i++) {
        if (got[i] != want[i]) {
            printf("  %s: record %d is %zu, want %zu\n", what, i + 1, got[i], want[i]);
            check(what, (long)want[i], (long)got[i]);
            return;
        }
    }
}

/* catches: a byte-count threshold in place of a record count, or a ramp that does not reach 16384 at the 14th record */
static void t_ramp_small_records(void) {
    struct tp p;
    struct tr_link l;
    if (ramp_open(&p, &l, "ramp small")) {
        tr_link_close(&l);
        tp_free(&p);
        return;
    }
    unsigned char one = 7;
    for (int i = 0; i < 13; i++) check("ramp small: 1 B write", 0, tls13_write(&l.tls, &one, 1));
    struct rw w = { .l = &l, .n = 40000 };
    int started = pthread_create(&w.th, NULL, rw_run, &w);
    check("ramp small: writer starts", 0, started);
    size_t want[16];
    for (int i = 0; i < 13; i++) want[i] = 1;
    want[13] = 16384; want[14] = 16384; want[15] = 7232;
    ramp_expect("ramp small: lengths", &p, want, 16);
    shutdown(l.fd, SHUT_RDWR);
    if (!started) pthread_join(w.th, NULL);
    check("ramp small: big write", 0, started ? -1 : w.rc);
    tr_link_close(&l);
    tp_free(&p);
}

/* catches: a write cut at 16384 whatever the count, or a step other than 1186 */
static void t_ramp_one_write(void) {
    struct tp p;
    struct tr_link l;
    if (ramp_open(&p, &l, "ramp one")) {
        tr_link_close(&l);
        tp_free(&p);
        return;
    }
    struct rw w = { .l = &l, .n = 1048576 };
    int started = pthread_create(&w.th, NULL, rw_run, &w);
    check("ramp one: writer starts", 0, started);
    size_t want[71] = { 1186, 2372, 3558, 4744, 5930, 7116, 8302, 9488, 10674, 11860, 13046, 14232, 15418 };
    for (int i = 13; i < 70; i++) want[i] = 16384;
    want[70] = 6762;
    ramp_expect("ramp one: lengths", &p, want, 71);
    shutdown(l.fd, SHUT_RDWR);
    if (!started) pthread_join(w.th, NULL);
    check("ramp one: write", 0, started ? -1 : w.rc);
    tr_link_close(&l);
    tp_free(&p);
}

/* catches: the count restarted per write */
static void t_ramp_across_writes(void) {
    struct tp p;
    struct tr_link l;
    if (ramp_open(&p, &l, "ramp across")) {
        tr_link_close(&l);
        tp_free(&p);
        return;
    }
    unsigned char *buf = calloc(1, 8192);
    for (int i = 0; i < 7; i++) check("ramp across: write", 0, tls13_write(&l.tls, buf, 8192));
    free(buf);
    size_t want[11] = { 1186, 2372, 3558, 1076, 5930, 2262, 8192, 8192, 8192, 8192, 8192 };
    ramp_expect("ramp across: lengths", &p, want, 11);
    tr_link_close(&l);
    tp_free(&p);
}

/* catches: an empty record sealed for a zero-length write, advancing the ramp */
static void t_ramp_zero_write(void) {
    struct tp p;
    struct tr_link l;
    if (ramp_open(&p, &l, "ramp zero")) {
        tr_link_close(&l);
        tp_free(&p);
        return;
    }
    unsigned char *buf = calloc(1, 2000);
    check("ramp zero: empty write", 0, tls13_write(&l.tls, NULL, 0));
    check("ramp zero: write", 0, tls13_write(&l.tls, buf, 2000));
    free(buf);
    size_t want[2] = { 1186, 814 };
    ramp_expect("ramp zero: lengths", &p, want, 2);
    size_t extra[1];
    struct timeval tv = { .tv_usec = 200000 };
    setsockopt(p.s.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    check("ramp zero: no third record", 0, peer_lens(&p, extra, 1, 1));
    tr_link_close(&l);
    tp_free(&p);
}

/* catches: the client Finished or handshake flight counted as application records */
static void t_ramp_after_handshake(void) {
    struct tp p;
    struct tr_link l;
    if (ramp_open(&p, &l, "ramp fresh")) {
        tr_link_close(&l);
        tp_free(&p);
        return;
    }
    unsigned char *buf = calloc(1, 2000);
    check("ramp fresh: write", 0, tls13_write(&l.tls, buf, 2000));
    free(buf);
    size_t want[2] = { 1186, 814 };
    ramp_expect("ramp fresh: lengths", &p, want, 2);
    tr_link_close(&l);
    tp_free(&p);
}

/* catches: room counted at 16384 per record, or wr_seq advanced by a refused seal */
static void t_seal_room_ramp(void) {
    struct tp p;
    struct tr_link l;
    if (ramp_open(&p, &l, "room ramp")) {
        tr_link_close(&l);
        tp_free(&p);
        return;
    }
    struct tls13 *b = calloc(1, sizeof *b);
    b->fd = -1;
    b->ready = 1;
    b->wr.aead = l.tls.wr.aead;
    b->wr.key_n = l.tls.wr.key_n;
    memcpy(b->wr.key, l.tls.wr.key, sizeof b->wr.key);
    memcpy(b->wr.iv, l.tls.wr.iv, sizeof b->wr.iv);
    check("room ramp: copy keyed", 0, tls13_keys_setup(&b->wr));
    static unsigned char msg[20000], out[20100];
    size_t on = 0;
    b->wr_seq = 0;
    check("room ramp: 5065 refused", TLS13_ETOOBIG, tls13_seal(b, msg, 5000, out, 5065, &on));
    check("room ramp: refusal keeps wr_seq", 0, (long)b->wr_seq);
    check("room ramp: 5066 fits", 0, tls13_seal(b, msg, 5000, out, 5066, &on));
    check("room ramp: 5066 bytes", 5066, (long)on);
    check("room ramp: three records", 3, (long)b->wr_seq);
    b->wr_seq = 13;
    check("room ramp: late ramp fits", 0, tls13_seal(b, msg, 20000, out, 20044, &on));
    check("room ramp: late ramp bytes", 20044, (long)on);
    check("room ramp: two records", 15, (long)b->wr_seq);
    check("room ramp: first late record", 16384 + 22, (long)(((out[3] << 8) | out[4]) + 5));
    tls13_keys_free(&b->wr);
    free(b);
    tr_link_close(&l);
    tp_free(&p);
}

static const unsigned char PREFACE70[70] = {
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

static size_t dial_on(struct xconn *x, int l, int *pfd) {
    int rc = xconn_dial(x, 3);
    if (!rc) rc = xconn_adopt(x, 0);
    *pfd = accept(l, NULL, NULL);
    close(l);
    unsigned char b[256];
    size_t n = peer_drain(*pfd, b, sizeof b, 30);
    if (rc) return 2000;
    if (n == 70 && memcmp(b, PREFACE70, 70)) return 1000;
    return n;
}

/* catches: a request sent at dial, or a leaked fd on refusal */
static void t_dial_preface(void) {
    int fd0 = fd_count();
    int l = listen_lo(0);
    struct tr_node n = plain_node(g_port);
    struct xconn *x = xconn_new(&n, 0, 0);
    check("dial: plain ok", 0, xconn_dial(x, 3));
    int pfd = accept(l, NULL, NULL);
    close(l);
    unsigned char b[256];
    size_t got = peer_drain(pfd, b, sizeof b, 30);
    check("dial: 70 preface bytes", 70, (long)got);
    check("dial: Go's preface", 0, got == 70 ? memcmp(b, PREFACE70, 70) : -1);
    xconn_free(x);
    check("dial: nothing after the preface", 0, (long)peer_drain(pfd, b, sizeof b, 30));
    close(pfd);
    l = listen_lo(0);
    n = plain_node(g_port);
    x = xconn_new(&n, 0, 1);
    check("dial: shared link, Go's 70 B preface", 70, (long)dial_on(x, l, &pfd));
    xconn_free(x);
    close(pfd);
    check("dial: descriptors back to the start", fd0, fd_count());
}

static void t_alpn_any(void) {
    int fd0 = fd_count();
    struct tp p;
    check("alpn any: peer starts", 0, tp_start(&p, "http/1.1"));
    struct tr_node n = tls_node(g_port);
    struct xconn *x = xconn_new(&n, 0, 1);
    /* catches: the TR_ENOH2 close kept */
    check("alpn any: http/1.1 dialled", 0, xconn_dial(x, 3));
    check("alpn any: peer keys", 0, tp_finish(&p));
    size_t got = 0;
    unsigned char inner = 0;
    check("alpn any: preface record opens", 0, rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &got, &inner));
    check("alpn any: 70 B preface", 70, (long)got);
    check("alpn any: Go's preface", 0, got == 70 ? memcmp(g_rec, PREFACE70, 70) : -1);
    xconn_free(x);
    tp_free(&p);
    check("alpn any: descriptors back to the start", fd0, fd_count());
}

static int fill_windows(struct pl *p) {
    pw_settings_win(p->pfd, 0x7fffffff);
    pw_u32(p->pfd, FR_WINDOW_UPDATE, 0, 0x7fffffff - 65535);
    int rc = io_in(p->x, 0);
    if (!rc) rc = xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
    return rc;
}

static void small_sndbuf(struct xconn *x) {
    int v = 4096;
    setsockopt(x->link.fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
}

/* catches: a blocking write on the shared socket */
static void t_send_never_blocks(void) {
    struct pl p;
    check("never blocks: link", 0, open_plain(&p, 1, 0, 4096, 0));
    small_sndbuf(p.x);
    check("never blocks: windows", 0, fill_windows(&p));
    struct xs s;
    check("never blocks: open", 0, xs_open(p.x, &RQ_POST, 1, &s));
    xconn_flush(p.x);
    int slow = 0, unforced = 0, bad = 0, it = 0;
    for (; it < 200 && xc_queued() < 262144; it++) {
        long r = xs_room(&s);
        uint64_t t0 = mono_us();
        if (xs_send(&s, g_big, (size_t)r, 0)) bad++;
        uint64_t t1 = mono_us();
        long ag = g_send_again;
        xconn_flush(p.x);
        uint64_t t2 = mono_us();
        if (t1 - t0 >= 5000 || t2 - t1 >= 5000) slow++;
        if (xc_queued() > 0 && g_send_again == ag) unforced++;
    }
    check("never blocks: queue reached 262144", 1, xc_queued() >= 262144);
    check("never blocks: every send accepted", 0, bad);
    check("never blocks: every call under 5 ms", 0, slow);
    check("never blocks: bytes stay queued only after EAGAIN", 0, unforced);
    check("never blocks: no room at a full queue", 0, xs_room(&s));
    check("never blocks: wants out", 1, xconn_wants_out(p.x));
    close_plain(&p);
    check("never blocks: queue released at free", 0, (long)xc_queued());
}

/* catches: rooms that together exceed what the queue and window admit */
static void t_room_sum_fits(void) {
    struct pl p;
    check("room sum: link", 0, open_plain(&p, 1, 0, 0, 0));
    pw_settings_win(p.pfd, 1048576);
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 1048576 - 65535);
    io_in(p.x, 0);
    struct xs s[3];
    for (int i = 0; i < 3; i++) xs_open(p.x, &RQ_POST, (uint16_t)(1 + i), &s[i]);
    for (int i = 0; i < 3; i++) xs_send(&s[i], g_big, 1, 0);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 3);
    io_in(p.x, 0);
    check("room sum: queue empty", 0, (long)xc_queued());
    check("room sum: connection window 1 MiB", 1048576, h2m_conn_room(&p.x->h2));
    long r[3];
    for (int i = 0; i < 3; i++) r[i] = xs_room(&s[i]);
    check("room sum: room A 262144/3", 87381, r[0]);
    check("room sum: room B 262144/3", 87381, r[1]);
    check("room sum: room C 262144/3", 87381, r[2]);
    int ok = 0;
    for (int i = 0; i < 3; i++) ok += xs_send(&s[i], g_big, (size_t)r[i], 0) == 0;
    check("room sum: three sends accepted", 3, ok);
    check("room sum: queue 262143", 262143, (long)xc_queued());
    close_plain(&p);
}

static void t_post_room_no_share(void) {
    struct pl p;
    check("post room: link", 0, open_plain(&p, 1, 0, 0, 0));
    pw_settings_win(p.pfd, 1048576);
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 1048576 - 65535);
    io_in(p.x, 0);
    struct xs s[3];
    xs_open(p.x, &RQ_POST, 1, &s[0]);
    xs_open(p.x, &RQ_POST, 1, &s[1]);
    xs_open(p.x, &RQ_POST, 2, &s[2]);
    for (int i = 0; i < 3; i++) xs_send(&s[i], g_big, 1, 0);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 3);
    io_in(p.x, 0);
    /* catches: the queue share, the uploaders split or the connection room kept in a new POST's size */
    check("post room: the stream window, 65535 + 983041 - 3 + 3", 1048576, xc_post_room(p.x, 2000000));
    check("post room: 200000 queued unflushed", 0, xs_send(&s[0], g_big, 200000, 0));
    check("post room: connection room 848576 left", 848576, h2m_conn_room(&p.x->h2) - (long)p.x->pend_n);
    check("post room: the connection room only guards", 1048576, xc_post_room(p.x, 2000000));
    close_plain(&p);
}

static void t_q_skip_across_chunks(void) {
    struct xc_q q = { 0 };
    static unsigned char got[40000];
    xc_q_push(&q, g_big, 40000);
    /* catches: a skip that stops at the first chunk, drops past the bytes asked, or miscounts what it dropped */
    check("skip: 20000 dropped across two chunks", 20000, (long)xc_q_skip(&q, 20000));
    check("skip: 20000 left", 20000, (long)q.n);
    check("skip: the rest starts after the skipped bytes", 20000, (long)xc_q_peek(&q, got, sizeof got));
    check("skip: the bytes", 0, memcmp(got, g_big + 20000, 20000));
    check("skip: past the end drops what is there", 20000, (long)xc_q_skip(&q, 50000));
    check("skip: empty", 0, (long)q.n);
    check("skip: no chunk kept", 1, q.head == NULL && q.tail == NULL);
    check("skip: nothing from an empty queue", 0, (long)xc_q_skip(&q, 1));
    xc_q_drop(&q);
}

/* catches: SEND_AGAIN for bytes the stack was told fit */
static void t_granted_room_is_accepted(void) {
    struct pl a, b, c;
    open_plain(&a, 1, 0, 0, 0);
    open_plain(&b, 1, 0, 0, 0);
    open_plain(&c, 1, 0, 0, 0);
    fill_windows(&a);
    fill_windows(&b);
    struct xs sa, sb, sc;
    xs_open(a.x, &RQ_POST, 1, &sa);
    xs_open(b.x, &RQ_POST, 2, &sb);
    xs_open(c.x, &RQ_POST, 3, &sc);
    check("granted: c sends to a 1000-byte window", 0, xs_send(&sc, g_big, 64535, 0));
    check("granted: c connection window", 1000, h2m_conn_room(&c.x->h2));
    long r = xs_room(&sc);
    check("granted: the window plus the send-ahead", 1000 + XC_PEND_STREAM, r);
    check("granted: window room accepted", 0, xs_send(&sc, g_big, (size_t)r, 0));
    int refused = 0, zero = 0, full = 0;
    for (int k = 0; k < 20; k++) {
        long level = (long)k * 300000 / 19;
        long need = level - (long)xc_queued();
        while (need > 0) {
            long m = need > (long)sizeof g_big ? (long)sizeof g_big : need;
            xs_send(&sb, g_big, (size_t)m, 0);
            need -= m;
        }
        int over = xc_queued() >= XC_OUT_HIGH;
        long ra = xs_room(&sa);
        if (over) full += ra == 0;
        else if (ra <= 0) zero++;
        else if (xs_send(&sa, g_big, (size_t)ra, 0) != 0) refused++;
    }
    check("granted: no room refused at 20 queue levels", 0, refused);
    check("granted: room never 0 below a full queue with open windows", 0, zero);
    check("granted: room 0 at every full level", 3, full);
    close_plain(&a);
    close_plain(&b);
    close_plain(&c);
}

/* catches: flows left with a closed window after the queue drained */
static void t_room_wakes_below_low(void) {
    struct pl p;
    open_plain(&p, 1, 0, 4096, 0);
    small_sndbuf(p.x);
    fill_windows(&p);
    struct xs s[3];
    for (int i = 0; i < 3; i++) xs_open(p.x, &RQ_POST, (uint16_t)(21 + i), &s[i]);
    xconn_flush(p.x);
    for (int it = 0; it < 400 && xc_queued() < XC_OUT_HIGH; it++) {
        xs_send(&s[it & 1], g_big, (size_t)xs_room(&s[it & 1]), 0);
        xconn_flush(p.x);
    }
    check("low: queue full", 1, xc_queued() >= XC_OUT_HIGH);
    check("low: no room A at a full queue", 0, xs_room(&s[0]));
    check("low: no room B at a full queue", 0, xs_room(&s[1]));
    g_wk_n = 0;
    int early = 0, late = 0, above = 0;
    uint64_t dl = mono_us() + 10000000;
    while (mono_us() < dl && (xc_queued() || xconn_wants_out(p.x))) {
        unsigned char b[4096];
        struct pollfd q = { .fd = p.pfd, .events = POLLIN };
        if (poll(&q, 1, 5) > 0 && read(p.pfd, b, sizeof b) <= 0) break;
        int before = g_wk_n;
        xconn_io(p.x, EPOLLOUT, 0);
        if (xc_queued() >= XC_OUT_LOW) above++;
        if (g_wk_n > before && xc_queued() >= XC_OUT_LOW) early++;
        if (!g_wk_n && xc_queued() < XC_OUT_LOW) late++;
    }
    check("low: the queue passed through high and low water", 1, above > 1);
    check("low: queue drained", 0, (long)xc_queued());
    check("low: no wake at or above low water", 0, early);
    check("low: wakes once below low water", 0, late);
    check("low: owner 21 woken once", 1, wakes(21, XW_ROOM));
    check("low: owner 22 woken once", 1, wakes(22, XW_ROOM));
    check("low: owner 23 never asked, not woken", 0, wakes(23, XW_ROOM));
    close_plain(&p);
}

static void link_end_wakes(int how) {
    struct pl a, b;
    open_plain(&a, 1, 0, 0, 0);
    open_plain(&b, 1, 0, 0, 0);
    fill_windows(&a);
    fill_windows(&b);
    struct xs sa, sb;
    xs_open(a.x, &RQ_POST, 31, &sa);
    xs_open(b.x, &RQ_POST, 32, &sb);
    xs_send(&sa, g_big, 300000, 0);
    check("link end: A holds the queue full", 1, xc_queued() >= XC_OUT_HIGH);
    check("link end: B starved", 0, xs_room(&sb));
    g_wk_n = 0;
    if (how) {
        xconn_free(a.x);
        a.x = NULL;
    } else {
        xconn_fail(a.x, H2_EIO);
    }
    check("link end: queue below low water", 1, xc_queued() < XC_OUT_LOW);
    check(how ? "link end: B woken by the free" : "link end: B woken by the failure", 1, wakes(32, XW_ROOM));
    check("link end: room for B", 1, xs_room(&sb) > 0);
    close_plain(&a);
    close_plain(&b);
}

/* catches: a starved stream left waiting a turn after its queue went with a failed or freed link */
static void t_link_end_wakes_starved(void) {
    link_end_wakes(0);
    link_end_wakes(1);
}

/* catches: PING ACK dropped at high water, or sent ahead of queued data */
static void t_control_ignores_high_water(void) {
    struct pl a, b;
    open_plain(&a, 1, 0, 0, 0);
    open_plain(&b, 1, 0, 0, 0);
    fill_windows(&a);
    fill_windows(&b);
    struct xs sa, sb;
    xs_open(a.x, &RQ_POST, 1, &sa);
    xs_open(b.x, &RQ_POST, 2, &sb);
    xconn_flush(b.x);
    peer_drain(b.pfd, g_pb, sizeof g_pb, 10);
    xs_send(&sa, g_big, 204800, 0);
    xs_send(&sb, g_big, 102400, 0);
    check("control: thread queue above high water", 1, xc_queued() > XC_OUT_HIGH);
    pw(b.pfd, FR_PING, 0, 0, "12345678", 8);
    check("control: ping read", 0, io_in(b.x, 0));
    size_t n = 0;
    uint64_t dl = mono_us() + 3000000;
    while (mono_us() < dl) {
        xconn_flush(b.x);
        n += peer_drain(b.pfd, g_pb + n, sizeof g_pb - n, 10);
        if (!xconn_wants_out(b.x) && n) break;
    }
    int k = parse(g_pb, n, g_fv, 8192);
    long before = 0, after = 0;
    int ack = -1;
    for (int i = 0; i < k; i++) {
        if (g_fv[i].type == FR_PING && (g_fv[i].flags & FLAG_ACK)) ack = i;
        else if (g_fv[i].type == FR_DATA) {
            if (ack < 0) before += g_fv[i].len;
            else after += g_fv[i].len;
        }
    }
    check("control: PING ACK sent", 1, ack >= 0);
    check("control: ACK carries the opaque data", 0, ack >= 0 ? memcmp(g_fv[ack].p, "12345678", 8) : -1);
    check("control: all DATA ahead of the ACK", 102400, before);
    check("control: no DATA after the ACK", 0, after);
    close_plain(&a);
    close_plain(&b);
}

static long g_flood_sent;

static long flood(unsigned type, unsigned flags, uint32_t len, int reads, long *peak) {
    struct pl p;
    open_plain(&p, 1, 0, 4096, 0);
    small_sndbuf(p.x);
    fcntl(p.pfd, F_SETFL, fcntl(p.pfd, F_GETFL) | O_NONBLOCK);
    static unsigned char b[64 * 17];
    size_t n = 0;
    for (int i = 0; i < 64; i++) n += frame(b + n, len, type, flags, 0, "12345678");
    long sent = 0;
    *peak = 0;
    uint64_t dl = mono_us() + 10000000;
    while (mono_us() < dl && sent < (4L << 20) && p.x->state == XC_LIVE) {
        ssize_t w = write(p.pfd, b, n);
        if (w > 0) sent += w;
        xconn_io(p.x, EPOLLIN | EPOLLOUT, 0);
        while (reads && read(p.pfd, g_pb, sizeof g_pb) > 0) {}
        long q = (long)p.x->out.n;
        if (q > *peak) *peak = q;
    }
    long st = p.x->state;
    g_flood_sent = sent;
    close_plain(&p);
    return st;
}

/* catches: control frames queued without a ceiling while the socket does not drain */
static void t_control_flood_closes(void) {
    long peak = 0;
    check("flood: PING flood closes the link", XC_DEAD, flood(FR_PING, 0, 8, 0, &peak));
    check("flood: PING ACKs held to 262144", 1, peak <= 262144);
    check("flood: SETTINGS flood closes the link", XC_DEAD, flood(FR_SETTINGS, 0, 0, 0, &peak));
    check("flood: SETTINGS ACKs held to 262144", 1, peak <= 262144);
    check("flood: a reading peer gets 4 MiB of PINGs answered", XC_LIVE, flood(FR_PING, 0, 8, 1, &peak));
    check("flood: all 4 MiB went in", 1, g_flood_sent >= (4L << 20));
}

/* catches: flush_in leaving a link live after its coalesced WINDOW_UPDATE crossed the control ceiling */
static void t_coalesced_credit_over_ceiling(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    xconn_discard(p.x);
    struct xs u;
    xs_open(p.x, &RQ_POST, 1, &u);
    p.x->q_ctl = XC_CTL_MAX - 4;
    p.x->st[u.slot].disc = 1u << 20;
    xconn_flush(p.x);
    check("ceiling: the link is dead in the same pass", XC_DEAD, p.x->state);
    close_plain(&p);
}

static int tls_link_rcv(struct tp *p, struct xconn **x, int rcvbuf) {
    if (tp_start_rcv(p, "h2", rcvbuf)) return -1;
    struct tr_node n = tls_node(g_port);
    *x = xconn_new(&n, 0, 1);
    int rc = xconn_dial(*x, 3);
    if (tp_finish(p)) return rc ? rc : -2;
    return rc;
}

static int tls_link(struct tp *p, struct xconn **x) { return tls_link_rcv(p, x, 0); }

/* catches: record overhead of control frames left out of the control ceiling on TLS */
static void t_control_flood_tls(void) {
    struct tp p;
    struct xconn *x;
    check("flood tls: link", 0, tls_link_rcv(&p, &x, 4096));
    xconn_adopt(x, 0);
    small_sndbuf(x);
    static unsigned char msg[16384];
    size_t m = 0;
    while (m + 9 <= sizeof msg) m += frame(msg + m, 0, FR_SETTINGS, 0, 0, NULL);
    long peak = 0, peak_ctl = 0, sent = 0;
    uint64_t dl = mono_us() + 10000000;
    while (mono_us() < dl && sent < (8L << 20) && x->state == XC_LIVE) {
        if (tp_seal(p.sd, p.s.fd, msg, m)) break;
        sent += (long)m;
        xconn_io(x, EPOLLIN | EPOLLOUT, 0);
        if ((long)x->out.n > peak) peak = (long)x->out.n;
        if ((long)x->q_ctl > peak_ctl) peak_ctl = (long)x->q_ctl;
    }
    check("flood tls: SETTINGS flood closes the link", XC_DEAD, x->state);
    check("flood tls: queued ACK records held to 262144", 1, peak <= 262144);
    check("flood tls: control count held to the ceiling", 1, peak_ctl <= XC_CTL_MAX);
    xconn_free(x);
    tp_free(&p);
}

/* catches: a control record charged as its plaintext on TLS, or a plain frame charged a record */
static void t_control_ceiling_counts_records(void) {
    static const unsigned char op[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    struct tp p;
    struct xconn *x;
    check("ceiling records: tls link", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    x->q_ctl = XC_CTL_MAX - 30;
    unsigned char msg[32];
    size_t m = frame(msg, 8, FR_PING, 0, 0, op);
    tp_seal(p.sd, p.s.fd, msg, m);
    io_in(x, 0);
    check("ceiling records: a 39 B PING ACK record past 30 B left fails the link", XC_DEAD, x->state);
    xconn_free(x);
    tp_free(&p);
    struct pl q;
    open_plain(&q, 1, 0, 0, 0);
    q.x->q_ctl = XC_CTL_MAX - 30;
    pw(q.pfd, FR_PING, 0, 0, op, 8);
    io_in(q.x, 0);
    check("ceiling records: a 17 B plain PING ACK within 30 B left is taken", XC_LIVE, q.x->state);
    xconn_flush(q.x);
    check("ceiling records: the plain PING ACK went out", 17, (long)peer_drain(q.pfd, g_pb, sizeof g_pb, 30));
    close_plain(&q);
}

/* catches: one staging buffer sealed with another link's keys */
static void t_staging_per_link(void) {
    struct tp p[2];
    struct xconn *x[2];
    for (int i = 0; i < 2; i++) {
        check("staging: tls link", 0, tls_link(&p[i], &x[i]));
        xconn_adopt(x[i], 0);
    }
    struct xs s[2];
    for (int i = 0; i < 2; i++) xs_open(x[i], &RQ_GET, (uint16_t)i, &s[i]);
    for (int i = 0; i < 2; i++) xconn_flush(x[i]);
    for (int i = 0; i < 2; i++) {
        size_t n = 0;
        unsigned char inner = 0;
        int rc = rec_open(p[i].cd, p[i].s.fd, g_rec, sizeof g_rec, &n, &inner);
        check("staging: preface record opens", 0, rc);
        check("staging: preface record holds the preface", 70, (long)n);
        rc = rec_open(p[i].cd, p[i].s.fd, g_rec, sizeof g_rec, &n, &inner);
        check("staging: frame record opens with this link's keys", 0, rc);
        struct fv f[4];
        int k = rc ? 0 : parse(g_rec, n, f, 4);
        check("staging: one frame in the record", 1, k);
        check("staging: it is this link's HEADERS", FR_HEADERS, k ? (long)f[0].type : -1);
        check("staging: the frame fills the record", (long)n, k ? (long)(9 + f[0].len) : -1);
        usleep(20000);
        check("staging: nothing more on this socket", 0, fd_pending(p[i].s.fd));
    }
    for (int i = 0; i < 2; i++) {
        xconn_free(x[i]);
        tp_free(&p[i]);
    }
}

static int next_rec(struct tp *p, struct fv *f, int max, size_t *n) {
    unsigned char inner = 0;
    *n = 0;
    if (rec_open(p->cd, p->s.fd, g_rec, sizeof g_rec, n, &inner)) return -1;
    return parse(g_rec, *n, f, max);
}

/* catches: ACK, HEADERS and DATA sealed together */
static void t_records_alone(void) {
    struct tp p;
    struct xconn *x;
    struct fv f[8];
    size_t n = 0;
    check("alone: tls link", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    struct xs g, u;
    check("alone: GET opened", 0, xs_open(x, &RQ_GET, 1, &g));
    xconn_flush(x);
    unsigned char inner = 0;
    check("alone: preface record opens", 0, rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &n, &inner));
    check("alone: preface record 70 B", 70, (long)n);
    int k = next_rec(&p, f, 8, &n);
    check("alone: HEADERS record one frame", 1, k);
    check("alone: HEADERS record is HEADERS", FR_HEADERS, k == 1 ? (long)f[0].type : -1);
    check("alone: HEADERS record holds only it", (long)n, k == 1 ? (long)(9 + f[0].len) : -1);
    static const unsigned char op[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    unsigned char msg[64];
    size_t m = frame(msg, 0, FR_SETTINGS, 0, 0, NULL);
    m += frame(msg + m, 8, FR_PING, 0, 0, op);
    check("alone: peer writes SETTINGS and PING", 0, tp_seal(p.sd, p.s.fd, msg, m));
    io_in(x, 0);
    xconn_flush(x);
    k = next_rec(&p, f, 8, &n);
    check("alone: SETTINGS ACK record 9 B", 9, (long)n);
    check("alone: SETTINGS ACK alone", 1, k == 1 && f[0].type == FR_SETTINGS && f[0].flags == FLAG_ACK);
    k = next_rec(&p, f, 8, &n);
    check("alone: PING ACK record 17 B", 17, (long)n);
    check("alone: PING ACK alone", 1, k == 1 && f[0].type == FR_PING && f[0].flags == FLAG_ACK);
    check("alone: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    check("alone: 100 B sent", 0, xs_send(&u, g_big, 100, 0));
    xconn_flush(x);
    k = next_rec(&p, f, 8, &n);
    check("alone: POST HEADERS record one frame", 1, k);
    check("alone: POST HEADERS record is HEADERS", FR_HEADERS, k == 1 ? (long)f[0].type : -1);
    check("alone: POST HEADERS record holds only it", (long)n, k == 1 ? (long)(9 + f[0].len) : -1);
    k = next_rec(&p, f, 8, &n);
    check("alone: DATA record 109 B", 109, (long)n);
    check("alone: DATA record is one DATA of 100", 1, k == 1 && f[0].type == FR_DATA && f[0].len == 100);
    usleep(20000);
    check("alone: nothing more", 0, fd_pending(p.s.fd));
    xconn_free(x);
    tp_free(&p);
}

static int rec_lens(struct tp *p, size_t *lens, unsigned char (*head)[9], int want) {
    int k = 0;
    while (k < want) {
        size_t n = 0;
        unsigned char inner = 0;
        if (rec_open(p->cd, p->s.fd, g_rec, sizeof g_rec, &n, &inner)) break;
        lens[k] = n;
        if (head) memcpy(head[k], g_rec, n < 9 ? n : 9);
        k++;
    }
    return k;
}

static void lens_expect(const char *what, const size_t *got, const size_t *want, int n) {
    for (int i = 0; i < n; i++) {
        if (got[i] == want[i]) continue;
        printf("  %s: record %d is %zu, want %zu; got", what, i + 1, got[i], want[i]);
        for (int j = 0; j < n; j++) printf(" %zu", got[j]);
        printf("\n");
        check(what, (long)want[i], (long)got[i]);
        return;
    }
    check(what, 0, 0);
}

static int is_data_head(const unsigned char *h, uint32_t len, uint32_t sid) {
    uint32_t l = ((uint32_t)h[0] << 16) | ((uint32_t)h[1] << 8) | h[2];
    return l == len && h[3] == FR_DATA && (be32(h + 5) & 0x7fffffffu) == sid;
}

static void get_flushed(struct tp *p, struct xconn *x, const char *what) {
    struct xs g;
    char nm[80];
    snprintf(nm, sizeof nm, "%s: GET opened", what);
    check(nm, 0, xs_open(x, &RQ_GET, 1, &g));
    xconn_flush(x);
    size_t lens[2];
    snprintf(nm, sizeof nm, "%s: preface and GET HEADERS records", what);
    check(nm, 2, rec_lens(p, lens, NULL, 2));
}

/* catches: the limit read once per x_out call (4744 4744 4744), or chunks filled to 16384 and then cut (4744 5930 5710 9) */
static void t_ramp_units(void) {
    struct tp p;
    struct xconn *x;
    check("ramp units: tls link", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    get_flushed(&p, x, "ramp units");
    struct xs u;
    check("ramp units: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    check("ramp units: 40000 B sent", 0, xs_send(&u, g_big, 40000, 0));
    xconn_flush(x);
    size_t got[7] = { 0 };
    unsigned char head[7][9];
    check("ramp units: POST HEADERS record", 1, rec_lens(&p, got, NULL, 1));
    check("ramp units: six DATA records", 6, rec_lens(&p, got, head, 6));
    static const size_t want[6] = { 4744, 5930, 5719, 8302, 8091, 7241 };
    lens_expect("ramp units: 4744 5930 5719 / 8302 8091 / 7241", got, want, 6);
    check("ramp units: unit 1 opens record 4", 1, is_data_head(head[0], 16384, u.sid));
    check("ramp units: unit 2 opens record 7", 1, is_data_head(head[3], 16384, u.sid));
    check("ramp units: unit 3 opens record 9", 1, is_data_head(head[5], 7232, u.sid));
    usleep(20000);
    check("ramp units: nothing more", 0, fd_pending(p.s.fd));
    xconn_free(x);
    tp_free(&p);
}

/* catches: control records left out of the count */
static void t_ramp_counts_control(void) {
    struct tp p;
    struct xconn *x;
    check("ramp control: tls link", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    get_flushed(&p, x, "ramp control");
    static const unsigned char op[8] = { 1, 1, 2, 3, 5, 8, 13, 21 };
    unsigned char msg[64];
    size_t m = frame(msg, 0, FR_SETTINGS, 0, 0, NULL);
    m += frame(msg + m, 8, FR_PING, 0, 0, op);
    check("ramp control: peer writes SETTINGS and PING", 0, tp_seal(p.sd, p.s.fd, msg, m));
    io_in(x, 0);
    xconn_flush(x);
    size_t got[6] = { 0 };
    check("ramp control: SETTINGS ACK and PING ACK records", 2, rec_lens(&p, got, NULL, 2));
    check("ramp control: SETTINGS ACK 9 B", 9, (long)got[0]);
    check("ramp control: PING ACK 17 B", 17, (long)got[1]);
    struct xs u;
    check("ramp control: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    check("ramp control: 16384 B sent", 0, xs_send(&u, g_big, 16384, 0));
    xconn_flush(x);
    check("ramp control: POST HEADERS record", 1, rec_lens(&p, got, NULL, 1));
    check("ramp control: three DATA records", 3, rec_lens(&p, got, NULL, 3));
    static const size_t want[3] = { 7116, 8302, 975 };
    lens_expect("ramp control: 7116 8302 975", got, want, 3);
    xconn_free(x);
    tp_free(&p);
}

/* catches: a limit that fell below the staged chunk copied past it instead of sealing the chunk first */
static void t_stage_over_limit(void) {
    struct tp p;
    struct xconn *x;
    check("stage over limit: tls link", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    get_flushed(&p, x, "stage over limit");
    check("stage over limit: nothing queued", 0, (long)x->out.n);
    uint64_t seq = x->link.tls.wr_seq;
    x->link.tls.wr_seq = 20;
    check("stage over limit: 5000 B staged", 0, x->h2.cb.out(x->h2.cb.ctx, g_big, 5000, H2M_PAY));
    check("stage over limit: still nothing queued", 0, (long)x->out.n);
    x->link.tls.wr_seq = 0;
    check("stage over limit: 100 B more", 0, x->h2.cb.out(x->h2.cb.ctx, g_big, 100, H2M_PAY));
    check("stage over limit: the 5000 B chunk sealed alone, as 1186 2372 1442", 5000 + 3 * 22, (long)x->out.n);
    check("stage over limit: three records", 3, (long)x->link.tls.wr_seq);
    x->link.tls.wr_seq = seq;
    xconn_free(x);
    tp_free(&p);
}

/* catches: a ramp per stream, or a counter shared between links */
static void t_ramp_once_per_link(void) {
    struct tp pa, pb;
    struct xconn *xa, *xb;
    size_t got[4] = { 0 };
    check("ramp link: link A", 0, tls_link(&pa, &xa));
    xconn_adopt(xa, 0);
    get_flushed(&pa, xa, "ramp link A");
    unsigned char msg[32];
    for (int i = 0; i < 11; i++) {
        unsigned char op[8] = { (unsigned char)i, 2, 3, 4, 5, 6, 7, 8 };
        size_t m = frame(msg, 8, FR_PING, 0, 0, op);
        check("ramp link: peer PING", 0, tp_seal(pa.sd, pa.s.fd, msg, m));
        io_in(xa, 0);
        xconn_flush(xa);
        check("ramp link: PING ACK record", 1, rec_lens(&pa, got, NULL, 1));
        check("ramp link: PING ACK 17 B", 17, (long)got[0]);
    }
    struct xs u;
    check("ramp link: POST on A", 0, xs_open(xa, &RQ_POST, 2, &u));
    check("ramp link: 16384 B on A", 0, xs_send(&u, g_big, 16384, 0));
    xconn_flush(xa);
    check("ramp link: POST HEADERS on A", 1, rec_lens(&pa, got, NULL, 1));
    check("ramp link: two DATA records on A", 2, rec_lens(&pa, got, NULL, 2));
    static const size_t want_a[2] = { 16384, 9 };
    lens_expect("ramp link: A at k15 cuts 16384 9", got, want_a, 2);
    check("ramp link: link B", 0, tls_link(&pb, &xb));
    xconn_adopt(xb, 0);
    struct xs v;
    check("ramp link: POST on B", 0, xs_open(xb, &RQ_POST, 2, &v));
    xconn_flush(xb);
    check("ramp link: preface and POST HEADERS on B", 2, rec_lens(&pb, got, NULL, 2));
    check("ramp link: 2000 B on B", 0, xs_send(&v, g_big, 2000, 0));
    xconn_flush(xb);
    check("ramp link: one DATA record on B", 1, rec_lens(&pb, got, NULL, 1));
    check("ramp link: B at k3 holds 2009 B", 2009, (long)got[0]);
    check("ramp link: 16384 B on B", 0, xs_send(&v, g_big, 16384, 0));
    xconn_flush(xb);
    check("ramp link: three DATA records on B", 3, rec_lens(&pb, got, NULL, 3));
    static const size_t want_b[3] = { 4744, 5930, 5719 };
    lens_expect("ramp link: B at k4 cuts 4744 5930 5719", got, want_b, 3);
    usleep(20000);
    check("ramp link: nothing more on B", 0, fd_pending(pb.s.fd));
    xconn_free(xb);
    tp_free(&pb);
    xconn_free(xa);
    tp_free(&pa);
}

/* catches: the flush pass sealing part of a unit */
static void t_flush_keeps_unit(void) {
    struct tp p;
    struct xconn *x;
    check("keep unit: tls link", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    struct xs u;
    check("keep unit: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    xconn_flush(x);
    size_t got[2] = { 0 };
    check("keep unit: preface and POST HEADERS", 2, rec_lens(&p, got, NULL, 2));
    uint16_t slot = x->st[u.slot].h2slot;
    check("keep unit: DATA of 3000 begun", 0, h2m_send_begin(&x->h2, slot, 3000, 0));
    check("keep unit: first 1000 B put", 0, h2m_send_put(&x->h2, g_big, 1000));
    xconn_flush(x);
    usleep(20000);
    check("keep unit: no record for part of the unit", 0, fd_pending(p.s.fd));
    check("keep unit: last 2000 B put", 0, h2m_send_put(&x->h2, g_big + 1000, 2000));
    xconn_flush(x);
    struct fv f[4];
    size_t n = 0;
    int k = next_rec(&p, f, 4, &n);
    check("keep unit: one record of 3009 B", 3009, (long)n);
    check("keep unit: it holds the whole DATA frame", 1, k == 1 && f[0].type == FR_DATA && f[0].len == 3000);
    usleep(20000);
    check("keep unit: nothing more", 0, fd_pending(p.s.fd));
    xconn_free(x);
    tp_free(&p);
}

/* catches: backpressure by not reading the shared socket, or a 1 MiB stream window */
static void t_slow_stream_does_not_stop_fast(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs a, b;
    xs_open(p.x, &RQ_GET, 1, &a);
    xs_open(p.x, &RQ_GET, 2, &b);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    unsigned char *buf = malloc(768 * (9 + 16384) + 64);
    size_t m = 0;
    m += frame(buf + m, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(buf + m, 1, FR_HEADERS, FLAG_END_HEADERS, 3, ST200);
    static unsigned char fa[16384], fb[16384];
    memset(fa, 'a', sizeof fa);
    memset(fb, 'b', sizeof fb);
    for (int i = 0; i < 512; i++) {
        if (i < 256) m += frame(buf + m, 16384, FR_DATA, 0, 1, fa);
        m += frame(buf + m, 16384, FR_DATA, 0, 3, fb);
    }
    struct bg g;
    bg_start(&g, p.pfd, buf, m);
    size_t bgot = 0;
    int bad = 0, rc = 0;
    uint64_t dl = mono_us() + 20000000;
    while (mono_us() < dl && bgot < 8388608) {
        struct pollfd q = { .fd = p.x->link.fd, .events = POLLIN };
        if (poll(&q, 1, 50) > 0) rc |= xconn_io(p.x, EPOLLIN, 0);
        xconn_flush(p.x);
        peer_drain(p.pfd, g_pb, sizeof g_pb, 0);
        size_t got;
        while (!xs_read(&b, g_pb, sizeof g_pb, &got) && got) {
            for (size_t i = 0; i < got; i++) bad += g_pb[i] != 'b';
            bgot += got;
        }
    }
    pthread_join(g.th, NULL);
    for (int i = 0; i < 20; i++) {
        struct pollfd q = { .fd = p.x->link.fd, .events = POLLIN };
        if (poll(&q, 1, 10) <= 0) break;
        rc |= xconn_io(p.x, EPOLLIN, 0);
    }
    check("slow: no link error", 0, rc);
    check("slow: B read all 8 MiB", 8388608, (long)bgot);
    check("slow: B bytes are B's", 0, bad);
    check("slow: the socket was read to empty", 0, fd_pending(p.x->link.fd));
    check("slow: A held its whole 4 MiB window", 4194304, (long)p.x->held_n);
    int end;
    check("slow: A held all 4194304", 4194304, (long)read_all_of(&a, NULL, 0, &end));
    free(buf);
    close_plain(&p);
}

/* catches: stream credit on arrival, which lets a slow client hold memory */
static void t_stream_credit_on_consumption(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs a;
    xs_open(p.x, &RQ_GET, 1, &a);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p.pfd, FR_DATA, 0, 1, NULL, 16384);
    pw(p.pfd, FR_DATA, 0, 1, NULL, 16384);
    pw(p.pfd, FR_DATA, 0, 1, NULL, 7232);
    for (int i = 0; i < 10; i++) {
        struct pollfd q = { .fd = p.x->link.fd, .events = POLLIN };
        if (poll(&q, 1, 20) <= 0) break;
        xconn_io(p.x, EPOLLIN, 0);
    }
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("consumption: no credit on arrival", 0, count_type(k, FR_WINDOW_UPDATE, -1));
    size_t got = 0;
    xs_read(&a, g_big, sizeof g_big, &got);
    check("consumption: 40000 read", 40000, (long)got);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    int nf = 0;
    uint32_t mn = 0;
    check("consumption: stream credit 40000", 40000, wu_sum(k, 1, &nf, &mn));
    check("consumption: in five reads of at most 8192", 5, nf);
    check("consumption: the last slice 7232", 7232, (long)mn);
    check("consumption: connection credit 40000", 40000, wu_sum(k, 0, NULL, NULL));
    check("consumption: connection first in each pair", 0, k >= 2 ? (long)g_fv[0].sid : -1);
    close_plain(&p);
}

/* catches: one credit per xs_read call instead of per 8 KiB read */
static void t_credit_go_reads(void) {
    struct tp p;
    struct xconn *x;
    struct fv f[8];
    size_t n = 0;
    check("go reads: tls link", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    struct xs g;
    check("go reads: GET opened", 0, xs_open(x, &RQ_GET, 1, &g));
    xconn_flush(x);
    unsigned char inner = 0;
    rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &n, &inner);
    rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &n, &inner);
    static unsigned char msg[16384];
    size_t m = frame(msg, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(msg + m, 10000, FR_DATA, 0, 1, NULL);
    tp_seal(p.sd, p.s.fd, msg, m);
    m = frame(msg, 10000, FR_DATA, 0, 1, NULL);
    tp_seal(p.sd, p.s.fd, msg, m);
    for (int i = 0; i < 10 && xs_status(&g) != 200; i++) io_in(x, 0);
    for (int i = 0; i < 10 && x->held_n < 20000; i++) io_in(x, 0);
    check("go reads: 20000 held", 20000, (long)x->held_n);
    size_t got = 0;
    check("go reads: one read of 20000", 0, xs_read(&g, g_big, 20000, &got));
    check("go reads: got 20000", 20000, (long)got);
    xconn_flush(x);
    int k = next_rec(&p, f, 8, &n);
    check("go reads: first record a pair", 2, k);
    check("go reads: WU(0, 8192)", 1, k == 2 && f[0].sid == 0 && be32(f[0].p) == 8192);
    check("go reads: WU(1, 8192)", 1, k == 2 && f[1].sid == 1 && be32(f[1].p) == 8192);
    k = next_rec(&p, f, 8, &n);
    check("go reads: second record a pair", 2, k);
    check("go reads: WU(0, 8192) again", 1, k == 2 && f[0].sid == 0 && be32(f[0].p) == 8192);
    check("go reads: WU(1, 8192) again", 1, k == 2 && f[1].sid == 1 && be32(f[1].p) == 8192);
    usleep(20000);
    check("go reads: 3616 kept", 0, fd_pending(p.s.fd));
    m = frame(msg, 1000, FR_DATA, 0, 1, NULL);
    tp_seal(p.sd, p.s.fd, msg, m);
    for (int i = 0; i < 10 && !x->held_n; i++) io_in(x, 0);
    check("go reads: 1000 read", 0, xs_read(&g, g_big, 1000, &got));
    xconn_flush(x);
    k = next_rec(&p, f, 8, &n);
    check("go reads: third record a pair", 2, k);
    check("go reads: WU(0, 4616)", 1, k == 2 && f[0].sid == 0 && be32(f[0].p) == 4616);
    check("go reads: WU(1, 4616)", 1, k == 2 && f[1].sid == 1 && be32(f[1].p) == 4616);
    usleep(20000);
    check("go reads: nothing more", 0, fd_pending(p.s.fd));
    xs_close(&g);
    xconn_free(x);
    tp_free(&p);
}

/* catches: an abandoned POST's answer eating the windows, or consumed inside the engine's callback */
static void t_nowner_credit(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs u;
    xs_open(p.x, &RQ_POST, 1, &u);
    xs_send(&u, g_big, 10, 1);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    xs_close(&u);
    check("nowner: the POST waits for its answer", 1, (long)xconn_streams(p.x));
    xconn_flush(p.x);
    check("nowner: nothing sent at the hand-off", 0, (long)peer_drain(p.pfd, g_pb, sizeof g_pb, 10));
    static const unsigned char op[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    static unsigned char msg[9 + 1 + 9 + 8192 + 9 + 8];
    size_t m = frame(msg, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(msg + m, 8192, FR_DATA, 0, 1, NULL);
    m += frame(msg + m, 8, FR_PING, 0, 0, op);
    wr_all(p.pfd, msg, m);
    for (int i = 0; i < 10 && !xconn_wants_out(p.x); i++) io_in(p.x, 0);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("nowner: three frames", 3, k);
    check("nowner: the PING ACK of the same read first", 1, k == 3 && g_fv[0].type == FR_PING);
    check("nowner: then WU(0, 8192)", 1, k == 3 && g_fv[1].sid == 0 && be32(g_fv[1].p) == 8192);
    check("nowner: then WU(1, 8192)", 1, k == 3 && g_fv[2].sid == 1 && be32(g_fv[2].p) == 8192);
    check("nowner: nothing held", 0, (long)p.x->held_n);
    pw(p.pfd, FR_DATA, FLAG_END_STREAM, 1, NULL, 8192);
    for (int i = 0; i < 10 && xconn_streams(p.x); i++) io_in(p.x, 0);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("nowner: the ended answer still credited, conn", 8192, wu_sum(k, 0, NULL, NULL));
    check("nowner: the ended answer still credited, stream", 8192, wu_sum(k, 1, NULL, NULL));
    check("nowner: the entry freed after", 0, (long)xconn_streams(p.x));
    close_plain(&p);
}

static void answer_20000(int fd, unsigned end) {
    static unsigned char msg[9 + 1 + 9 + 16384 + 9 + 3616];
    size_t m = frame(msg, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(msg + m, 16384, FR_DATA, 0, 1, NULL);
    m += frame(msg + m, 3616, FR_DATA, end, 1, NULL);
    wr_all(fd, msg, m);
}

/* catches: the connection window leaking the unread bytes of a closed stream */
static void t_close_refund_open(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs g;
    xs_open(p.x, &RQ_GET, 1, &g);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    answer_20000(p.pfd, 0);
    for (int i = 0; i < 10 && p.x->held_n < 20000; i++) io_in(p.x, 0);
    check("refund open: 20000 held", 20000, (long)p.x->held_n);
    xconn_flush(p.x);
    check("refund open: nothing sent on arrival", 0, (long)peer_drain(p.pfd, g_pb, sizeof g_pb, 10));
    xs_close(&g);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("refund open: two frames", 2, k);
    check("refund open: RST_STREAM(1, CANCEL) first", 1,
          k == 2 && g_fv[0].type == FR_RST_STREAM && g_fv[0].sid == 1 && be32(g_fv[0].p) == 8);
    check("refund open: then WU(0, 20000) alone", 1,
          k == 2 && g_fv[1].type == FR_WINDOW_UPDATE && g_fv[1].sid == 0 && be32(g_fv[1].p) == 20000);
    check("refund open: nothing held", 0, (long)p.x->held_n);
    close_plain(&p);
}

/* catches: the ent_free drop of an ended stream not refunded */
static void t_close_refund_ended(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs g;
    xs_open(p.x, &RQ_GET, 1, &g);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    answer_20000(p.pfd, FLAG_END_STREAM);
    for (int i = 0; i < 10 && !xs_ready(&g); i++) io_in(p.x, 0);
    for (int i = 0; i < 10 && p.x->held_n < 20000; i++) io_in(p.x, 0);
    check("refund ended: 20000 held", 20000, (long)p.x->held_n);
    check("refund ended: the stream ended", 1, (long)p.x->st[g.slot].ended);
    xs_close(&g);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("refund ended: one frame", 1, k);
    check("refund ended: WU(0, 20000) alone, no RST", 1,
          k == 1 && g_fv[0].type == FR_WINDOW_UPDATE && g_fv[0].sid == 0 && be32(g_fv[0].p) == 20000);
    check("refund ended: nothing held", 0, (long)p.x->held_n);
    check("refund ended: no stream left", 0, (long)xconn_streams(p.x));
    close_plain(&p);
}

/* catches: bytes queued before the hand-off dropped without credit */
static void t_close_refund_nowner(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs u;
    xs_open(p.x, &RQ_POST, 1, &u);
    xs_send(&u, g_big, 10, 1);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    pw(p.pfd, FR_DATA, 0, 1, NULL, 5000);
    for (int i = 0; i < 10 && p.x->held_n < 5000; i++) io_in(p.x, 0);
    check("refund nowner: 5000 held", 5000, (long)p.x->held_n);
    xs_close(&u);
    check("refund nowner: handed off", 1, (long)xconn_streams(p.x));
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("refund nowner: one frame", 1, k);
    check("refund nowner: WU(0, 5000) alone, no RST", 1,
          k == 1 && g_fv[0].type == FR_WINDOW_UPDATE && g_fv[0].sid == 0 && be32(g_fv[0].p) == 5000);
    check("refund nowner: nothing held", 0, (long)p.x->held_n);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p.pfd, FR_DATA, 0, 1, NULL, 8192);
    for (int i = 0; i < 10 && !xconn_wants_out(p.x); i++) io_in(p.x, 0);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("refund nowner: a later read two frames", 2, k);
    check("refund nowner: WU(0, 8192)", 1, k == 2 && g_fv[0].sid == 0 && be32(g_fv[0].p) == 8192);
    check("refund nowner: WU(1, 8192)", 1, k == 2 && g_fv[1].sid == 1 && be32(g_fv[1].p) == 8192);
    close_plain(&p);
}

/* catches: a refund written to a dead link, or its held bytes never subtracted */
static void t_dead_link_no_refund(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs g;
    xs_open(p.x, &RQ_GET, 1, &g);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    answer_20000(p.pfd, 0);
    shutdown(p.pfd, SHUT_WR);
    for (int i = 0; i < 10 && p.x->state == XC_LIVE; i++) io_in(p.x, 0);
    check("dead refund: the link died", XC_DEAD, p.x->state);
    check("dead refund: 20000 still held", 20000, (long)p.x->held_n);
    static unsigned char b[20000];
    size_t got = 0;
    check("dead refund: a read of 12000", 0, xs_read(&g, b, 12000, &got));
    check("dead refund: 12000 read", 12000, (long)got);
    check("dead refund: 8000 left", 8000, (long)p.x->held_n);
    uint64_t q = p.x->pt_q;
    xs_close(&g);
    check("dead refund: nothing written", 0, (long)(p.x->pt_q - q));
    check("dead refund: nothing queued", 0, (long)p.x->out.n);
    check("dead refund: held back to 0", 0, (long)p.x->held_n);
    xconn_flush(p.x);
    check("dead refund: nothing on the wire", 0, (long)peer_drain(p.pfd, g_pb, sizeof g_pb, 10));
    close_plain(&p);
}

/* catches: an ended ownerless answer left in the table when the link dies in the same read */
static void t_nowner_freed_on_fail(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs u;
    xs_open(p.x, &RQ_POST, 1, &u);
    xs_send(&u, g_big, 10, 1);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    xs_close(&u);
    unsigned char msg[256];
    size_t m = frame(msg, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(msg + m, 100, FR_DATA, FLAG_END_STREAM, 1, NULL);
    m += frame(msg + m, 1, FR_CONTINUATION, FLAG_END_HEADERS, 1, ST200);
    wr_all(p.pfd, msg, m);
    for (int i = 0; i < 10 && p.x->state == XC_LIVE; i++) io_in(p.x, 0);
    check("nowner fail: the link died", XC_DEAD, p.x->state);
    check("nowner fail: the ended answer freed", 0, (long)xconn_streams(p.x));
    close_plain(&p);
}

/* catches: discarded bytes still waiting for the link's pending update lost when the stream closes */
static void t_discard_close_credit(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    xconn_discard(p.x);
    struct xs u;
    xs_open(p.x, &RQ_POST, 1, &u);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    unsigned char msg[16384];
    size_t m = frame(msg, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(msg + m, 5000, FR_DATA, 0, 1, NULL);
    m += frame(msg + m, 5000, FR_DATA, 0, 1, NULL);
    wr_all(p.pfd, msg, m);
    for (int i = 0; i < 10 && !xconn_wants_out(p.x); i++) io_in(p.x, 0);
    xs_close(&u);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("discard close: four frames", 4, k);
    check("discard close: WU(0, 5000) for the first", 1, k == 4 && g_fv[0].sid == 0 && be32(g_fv[0].p) == 5000);
    check("discard close: WU(1, 5000) with it", 1, k == 4 && g_fv[1].sid == 1 && be32(g_fv[1].p) == 5000);
    check("discard close: RST_STREAM(1, CANCEL)", 1, k == 4 && g_fv[2].type == FR_RST_STREAM && be32(g_fv[2].p) == 8);
    check("discard close: the waiting 5000 on the connection", 1, k == 4 && g_fv[3].type == FR_WINDOW_UPDATE && g_fv[3].sid == 0 && be32(g_fv[3].p) == 5000);
    close_plain(&p);
}

/* catches: an ownerless POST on a discard link credited past the link's one pending update */
static void t_nowner_discard_gate(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    xconn_discard(p.x);
    struct xs u;
    xs_open(p.x, &RQ_POST, 1, &u);
    xs_send(&u, g_big, 10, 1);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    uint16_t idx = u.slot;
    xs_close(&u);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p.pfd, FR_DATA, 0, 1, NULL, 5000);
    for (int i = 0; i < 10 && !xconn_wants_out(p.x); i++) io_in(p.x, 0);
    check("nowner gate: one pair queued", 26, (long)(p.x->pt_q - p.x->pt_s));
    pw(p.pfd, FR_DATA, FLAG_END_STREAM, 1, NULL, 5000);
    for (int i = 0; i < 10 && !p.x->st[idx].ended; i++) io_in(p.x, 0);
    check("nowner gate: still one pair queued", 26, (long)(p.x->pt_q - p.x->pt_s));
    check("nowner gate: 5000 wait for it", 5000, (long)p.x->st[idx].disc);
    check("nowner gate: the ended entry kept for its credit", 1, (long)xconn_streams(p.x));
    xconn_flush(p.x);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("nowner gate: two pairs in all", 4, k);
    check("nowner gate: connection 10000", 10000, wu_sum(k, 0, NULL, NULL));
    check("nowner gate: stream 10000", 10000, wu_sum(k, 1, NULL, NULL));
    check("nowner gate: the entry freed once paid", 0, (long)xconn_streams(p.x));
    close_plain(&p);
}

/* catches: credit frames of honest downloads filling the control ceiling while the socket is blocked */
static void t_credit_held_while_blocked(void) {
    struct tp p;
    struct xconn *x;
    struct fv f[64];
    size_t n = 0;
    check("blocked: tls link", 0, tls_link_rcv(&p, &x, 4096));
    xconn_adopt(x, 0);
    struct xs s[16];
    for (int i = 0; i < 16; i++) xs_open(x, &RQ_GET, (uint16_t)i, &s[i]);
    xconn_flush(x);
    unsigned char inner = 0;
    usleep(20000);
    while (fd_pending(p.s.fd) > 0 && !rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &n, &inner)) {}
    small_sndbuf(x);
    static unsigned char msg[16384];
    size_t m = 0;
    for (int i = 0; i < 16; i++) m += frame(msg + m, 1, FR_HEADERS, FLAG_END_HEADERS, (uint32_t)(2 * i + 1), ST200);
    tp_seal(p.sd, p.s.fd, msg, m);
    long left[16], peak = 0, got = 0;
    for (int i = 0; i < 16; i++) left[i] = 4194304;
    for (int more = 1; more && x->state == XC_LIVE;) {
        more = 0;
        for (int i = 0; i < 16 && x->state == XC_LIVE; i++) {
            if (!left[i]) continue;
            uint32_t k = left[i] < 16375 ? (uint32_t)left[i] : 16375;
            left[i] -= k;
            more = 1;
            m = frame(msg, k, FR_DATA, left[i] ? 0 : FLAG_END_STREAM, (uint32_t)(2 * i + 1), NULL);
            if (tp_seal(p.sd, p.s.fd, msg, m)) break;
            xconn_io(x, EPOLLIN | EPOLLOUT, 0);
            for (int j = 0; j < 16; j++) {
                size_t r = 0;
                while (!xs_read(&s[j], g_big, sizeof g_big, &r) && r) got += (long)r;
            }
            if ((long)x->q_ctl > peak) peak = (long)x->q_ctl;
        }
    }
    for (int i = 0; i < 20 && got < 16L * 4194304; i++) {
        io_in(x, 0);
        for (int j = 0; j < 16; j++) {
            size_t r = 0;
            while (!xs_read(&s[j], g_big, sizeof g_big, &r) && r) got += (long)r;
        }
    }
    check("blocked: no link error", 0, x->rc);
    check("blocked: the link lives", XC_LIVE, x->state);
    check("blocked: all 64 MiB read", 16L * 4194304, got);
    check("blocked: the socket was blocked", 1, xconn_wants_out(x));
    check("blocked: control stayed under the ceiling", 1, peak <= XC_CTL_MAX);
    long sum[17] = { 0 };
    uint64_t dl = mono_us() + 20000000;
    while (mono_us() < dl && x->state == XC_LIVE) {
        xconn_flush(x);
        int all = sum[0] >= 16L * 4194304 - 4095;
        for (int i = 1; i <= 16; i++) all &= sum[i] >= 4194304 - 4095;
        if (all) break;
        struct pollfd q = { .fd = p.s.fd, .events = POLLIN };
        if (poll(&q, 1, 50) <= 0) continue;
        if (rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &n, &inner)) break;
        int k = parse(g_rec, n, f, 64);
        for (int i = 0; i < k; i++)
            if (f[i].type == FR_WINDOW_UPDATE && f[i].len == 4 && f[i].sid <= 31 && f[i].sid % 2 == (f[i].sid ? 1 : 0))
                sum[f[i].sid ? (f[i].sid + 1) / 2 : 0] += be32(f[i].p);
    }
    check("blocked: connection credit once drained", 1, sum[0] >= 16L * 4194304 - 4095 && sum[0] <= 16L * 4194304);
    int ok = 1;
    for (int i = 1; i <= 16; i++) ok &= sum[i] >= 4194304 - 4095 && sum[i] <= 4194304;
    check("blocked: every stream's credit once drained", 1, ok);
    for (int i = 0; i < 16; i++) xs_close(&s[i]);
    xconn_free(x);
    tp_free(&p);
}

static int pings(int k, unsigned char op[8]) {
    int c = 0;
    for (int i = 0; i < k; i++)
        if (g_fv[i].type == FR_PING && !(g_fv[i].flags & FLAG_ACK) && g_fv[i].len == 8) {
            c++;
            if (op) memcpy(op, g_fv[i].p, 8);
        }
    return c;
}

static int tick_pings(struct pl *p, uint64_t now, int *rc) {
    *rc = xconn_tick(p->x, now);
    xconn_flush(p->x);
    return pings(peer_frames(p->pfd, 5), NULL);
}

static void answered(struct pl *p, uint32_t sid) {
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
    pw(p->pfd, FR_HEADERS, FLAG_END_HEADERS, sid, ST200, 1);
    io_in(p->x, 0);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
}

/* catches: PING by write idle, no timeout, or off ignored */
static void t_keepalive(void) {
    struct pl p;
    struct xs s;
    int rc;
    open_plain(&p, 1, 0, 0, 0);
    xs_open(p.x, &RQ_GET, 5, &s);
    answered(&p, 1);
    g_wk_n = 0;
    check("keepalive: no PING at 44999", 0, tick_pings(&p, 44999, &rc));
    check("keepalive: PING at 45000", 1, tick_pings(&p, 45000, &rc));
    check("keepalive: tick 0 with the PING out", 0, rc);
    check("keepalive: 59999 still waits", 0, (tick_pings(&p, 59999, &rc), rc));
    check("keepalive: 60000 PING timeout", XC_EPING, xconn_tick(p.x, 60000));
    check("keepalive: owner woken with the timeout", 1, wakes(5, XW_READ));
    check("keepalive: wake carries XC_EPING", XC_EPING, wake_rc(5, XW_READ));
    size_t got;
    check("keepalive: the flow reads XC_EPING", XC_EPING, xs_read(&s, g_pb, 64, &got));
    xs_close(&s);
    close_plain(&p);

    open_plain(&p, 1, 0, 0, 0);
    xs_open(p.x, &RQ_GET, 5, &s);
    answered(&p, 1);
    xconn_tick(p.x, 45000);
    xconn_flush(p.x);
    unsigned char op[8] = { 0 };
    check("keepalive: PING to answer", 1, pings(peer_frames(p.pfd, 5), op));
    pw(p.pfd, FR_PING, FLAG_ACK, 0, op, 8);
    check("keepalive: ACK read at 59999", 0, io_in(p.x, 59999));
    check("keepalive: no error at 60000 after the ACK", 0, xconn_tick(p.x, 60000));
    check("keepalive: no PING at 104998", 0, tick_pings(&p, 104998, &rc));
    check("keepalive: next PING at 104999", 1, tick_pings(&p, 104999, &rc));
    xs_close(&s);
    close_plain(&p);

    open_plain(&p, 1, 2, 0, 0);
    xs_open(p.x, &RQ_GET, 5, &s);
    answered(&p, 1);
    check("keepalive 2: none at 1999", 0, tick_pings(&p, 1999, &rc));
    check("keepalive 2: PING at 2000", 1, tick_pings(&p, 2000, &rc));
    xs_close(&s);
    close_plain(&p);

    open_plain(&p, 1, -1, 0, 0);
    xs_open(p.x, &RQ_GET, 5, &s);
    answered(&p, 1);
    int n = 0, bad = 0;
    for (uint64_t t = 0; t <= 600000; t += 1000) {
        if (xconn_tick(p.x, t)) bad++;
        xconn_flush(p.x);
    }
    n = pings(peer_frames(p.pfd, 10), NULL);
    check("keepalive off: no PING in 10 min", 0, n);
    check("keepalive off: no tick error", 0, bad);
    xs_close(&s);
    close_plain(&p);
}

/* catches: no idle close, PINGs counted as use, or a stream not restarting the count */
static void t_idle_close(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    check("idle: 299999 open", 0, xconn_tick(p.x, 299999));
    check("idle: 300000 closes", XC_IDLE, xconn_tick(p.x, 300000));
    close_plain(&p);

    open_plain(&p, 1, 2, 0, 0);
    int bad = 0, seen = 0;
    for (uint64_t t = 1000; t < 300000; t += 1000) {
        if (xconn_tick(p.x, t)) bad++;
        xconn_flush(p.x);
        unsigned char op[8];
        if (pings(peer_frames(p.pfd, 1), op)) {
            seen++;
            pw(p.pfd, FR_PING, FLAG_ACK, 0, op, 8);
            io_in(p.x, t);
        }
    }
    check("idle: PINGs went out", 1, seen >= 100);
    check("idle: PINGs and ACKs change nothing", 0, bad);
    check("idle: 299999 with PINGs open", 0, xconn_tick(p.x, 299999));
    check("idle: 300000 with PINGs closes", XC_IDLE, xconn_tick(p.x, 300000));
    close_plain(&p);

    open_plain(&p, 1, -1, 0, 0);
    check("idle: open at 200000", 0, xconn_tick(p.x, 200000));
    struct xs s;
    xs_open(p.x, &RQ_GET, 8, &s);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p.pfd, FR_DATA, FLAG_END_STREAM, 1, "z", 1);
    io_in(p.x, 210000);
    int end;
    read_all_of(&s, NULL, 0, &end);
    xs_close(&s);
    g_wk_n = 0;
    check("idle: the count restarted at 210000", 0, xconn_tick(p.x, 300000));
    check("idle: 509999 open", 0, xconn_tick(p.x, 509999));
    check("idle: 510000 closes", XC_IDLE, xconn_tick(p.x, 510000));
    check("idle: no owner woken", 0, g_wk_n);
    close_plain(&p);
}

/* catches: an unanswered POST pinning a retired link forever */
static void t_orphan_post_times_out(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s, h;
    xs_open(p.x, &RQ_POST, 3, &s);
    xs_send(&s, (const unsigned char *)"x", 1, 1);
    xs_close(&s);
    xs_open(p.x, &RQ_POST, 4, &h);
    xs_send(&h, (const unsigned char *)"y", 1, 1);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("orphan: both counted", 2, xconn_streams(p.x));
    check("orphan: nothing at 29999", 0, xconn_tick(p.x, 29999));
    xconn_flush(p.x);
    check("orphan: no frame at 29999", 0, peer_frames(p.pfd, 10));
    g_wk_n = 0;
    xconn_tick(p.x, 30000);
    xconn_flush(p.x);
    unsigned char b[64];
    size_t n = peer_drain(p.pfd, b, sizeof b, 10);
    static const unsigned char want[26] = { 0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8,
                                            0, 0, 4, 3, 0, 0, 0, 0, 3, 0, 0, 0, 8 };
    static const unsigned char ping[9] = { 0, 0, 8, 6, 0, 0, 0, 0, 0 };
    check("orphan: RST_STREAM CANCEL on both, a PING after the first", 43, (long)n);
    check("orphan: first RST", 0, n == 43 ? memcmp(b, want, 13) : -1);
    check("orphan: PING", 0, n == 43 ? memcmp(b + 13, ping, 9) : -1);
    check("orphan: second RST", 0, n == 43 ? memcmp(b + 30, want + 13, 13) : -1);
    check("orphan: released one gone", 1, xconn_streams(p.x));
    check("orphan: held one's owner woken", 1, wakes(4, XW_READ));
    size_t got;
    check("orphan: held one reads a reset", H2_ERESET, xs_read(&h, b, sizeof b, &got));
    xs_close(&h);
    check("orphan: streams back to 0", 0, xconn_streams(p.x));
    close_plain(&p);
}

/* catches: an orphan POST answered 200 without END_STREAM pinning its link forever */
static void t_orphan_answered_open(void) {
    struct pl p;
    open_plain(&p, 1, -1, 0, 0);
    struct xs s, h;
    xs_open(p.x, &RQ_POST, 3, &s);
    xs_send(&s, (const unsigned char *)"x", 1, 1);
    xs_close(&s);
    xs_open(p.x, &RQ_POST, 4, &h);
    xs_send(&h, (const unsigned char *)"y", 1, 1);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 3, ST200, 1);
    check("orphan 200: answers read", 0, io_in(p.x, 1000));
    check("orphan 200: both counted", 2, xconn_streams(p.x));
    check("orphan 200: kept at 29999", 0, xconn_tick(p.x, 29999));
    check("orphan 200: both counted at 29999", 2, xconn_streams(p.x));
    xconn_tick(p.x, 30000);
    xconn_flush(p.x);
    unsigned char b[64];
    size_t n = peer_drain(p.pfd, b, sizeof b, 10);
    static const unsigned char want[13] = { 0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8 };
    check("orphan 200: RST_STREAM CANCEL at 30000", 13, (long)n);
    check("orphan 200: bytes", 0, n == 13 ? memcmp(b, want, 13) : -1);
    check("orphan 200: the orphan released, the owned one kept", 1, xconn_streams(p.x));
    xs_close(&h);
    check("orphan 200: streams back to 0", 0, xconn_streams(p.x));
    close_plain(&p);
}

/* catches: a flow forgotten, or buffered data lost on a connection error */
static void t_fail_fans_out(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s[3];
    static const uint16_t own[3] = { 7, 9, 11 };
    for (int i = 0; i < 3; i++) xs_open(p.x, &RQ_GET, own[i], &s[i]);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    for (int i = 0; i < 3; i++) {
        pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, (uint32_t)(1 + 2 * i), ST200, 1);
        pw(p.pfd, FR_DATA, 0, (uint32_t)(1 + 2 * i), "0123456789", 10);
    }
    io_in(p.x, 0);
    g_wk_n = 0;
    close(p.pfd);
    p.pfd = -1;
    check("fail: peer close", TR_ECLOSED, io_in(p.x, 0));
    check("fail: three wakes", 3, g_wk_n);
    for (int i = 0; i < 3; i++) {
        check("fail: one wake per owner", 1, wakes(own[i], XW_READ));
        check("fail: wake carries the error", TR_ECLOSED, wake_rc(own[i], XW_READ));
        unsigned char b[64];
        size_t got = 0;
        check("fail: buffered first", 0, xs_read(&s[i], b, sizeof b, &got));
        check("fail: its 10 bytes", 10, (long)got);
        check("fail: then the error", TR_ECLOSED, xs_read(&s[i], b, sizeof b, &got));
    }
    close_plain(&p);
}

static void goaway_case(uint32_t last, uint32_t code, int reset5) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s[3];
    for (int i = 0; i < 3; i++) xs_open(p.x, &RQ_GET, (uint16_t)(1 + 2 * i), &s[i]);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    unsigned char ga[8] = { (unsigned char)(last >> 24), (unsigned char)(last >> 16), (unsigned char)(last >> 8),
                            (unsigned char)last, (unsigned char)(code >> 24), (unsigned char)(code >> 16),
                            (unsigned char)(code >> 8), (unsigned char)code };
    g_wk_n = 0;
    pw(p.pfd, FR_GOAWAY, 0, 0, ga, 8);
    check("goaway: read", 0, io_in(p.x, 0));
    check("goaway: retired", 1, p.x->retired);
    struct xs t;
    check("goaway: no new stream", H2_ERESET, xs_open(p.x, &RQ_GET, 9, &t));
    unsigned char b[64];
    size_t got = 0;
    check("goaway: stream 5's owner woken", reset5, wakes(5, XW_READ));
    check("goaway: stream 5", reset5 ? XC_EGOAWAY : 0, xs_read(&s[2], b, sizeof b, &got));
    check("goaway: stream 1 untouched", 0, xs_read(&s[0], b, sizeof b, &got));
    for (int i = 0; i < 3 - reset5; i++) {
        uint32_t sid = (uint32_t)(1 + 2 * i);
        pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, sid, ST200, 1);
        pw(p.pfd, FR_DATA, 0, sid, "aa", 2);
    }
    io_in(p.x, 0);
    for (int i = 0; i < 3 - reset5; i++) {
        xs_read(&s[i], b, sizeof b, &got);
        check("goaway: below last keeps receiving", 2, (long)got);
    }
    if (reset5) xs_close(&s[2]);
    for (int i = 0; i < 3 - reset5; i++) {
        check("goaway: link stays while a stream is open", 0, xconn_tick(p.x, 1000));
        pw(p.pfd, FR_DATA, FLAG_END_STREAM, (uint32_t)(1 + 2 * i), "e", 1);
        io_in(p.x, 0);
        int end;
        check("goaway: stream ends on its END_STREAM", 1, (long)read_all_of(&s[i], b, sizeof b, &end));
        check("goaway: end code", H2_ERESET, end);
        xs_close(&s[i]);
    }
    check("goaway: closes after the last", XC_IDLE, xconn_tick(p.x, 1000));
    close_plain(&p);
}

/* catches: GOAWAY ending streams below last, or a GOAWAY link taking new flows */
static void t_goaway_above_resets(void) { goaway_case(3, 0, 1); }

/* catches: an error code in GOAWAY resetting streams within last */
static void t_goaway_error_code(void) { goaway_case(5, 2, 0); }

/* catches: a CANCEL that kills an in-flight chunk, or a GET left open */
static void t_close_maps_rst(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs g, q, e;
    xs_open(p.x, &RQ_GET, 1, &g);
    xs_open(p.x, &RQ_POST, 2, &q);
    xs_send(&q, (const unsigned char *)"x", 1, 1);
    xs_open(p.x, &RQ_GET, 3, &e);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p.pfd, FR_DATA, 0, 1, "hi", 2);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 5, ST200, 1);
    io_in(p.x, 0);
    xs_close(&g);
    xconn_flush(p.x);
    unsigned char b[64];
    size_t n = peer_drain(p.pfd, b, sizeof b, 10);
    static const unsigned char rst1[13] = { 0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8 };
    check("close: GET gets RST_STREAM CANCEL", 13, (long)n);
    check("close: RST bytes", 0, n == 13 ? memcmp(b, rst1, 13) : -1);
    xs_close(&q);
    xconn_flush(p.x);
    check("close: waiting POST sends nothing", 0, (long)peer_drain(p.pfd, b, sizeof b, 10));
    check("close: waiting POST still counted", 2, xconn_streams(p.x));
    xs_close(&e);
    xconn_flush(p.x);
    check("close: peer-ended stream sends nothing", 0, (long)peer_drain(p.pfd, b, sizeof b, 10));
    check("close: only the POST left", 1, xconn_streams(p.x));
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, ST200, 1);
    io_in(p.x, 0);
    check("close: POST released by its answer", 0, xconn_streams(p.x));
    xconn_flush(p.x);
    check("close: answer needs no frame", 0, (long)peer_drain(p.pfd, b, sizeof b, 10));
    close_plain(&p);
}

/* catches: a private link draining the socket ahead of its reader, or charged to the shared budget */
static void t_private_reads_on_demand(void) {
    struct tp p;
    tp_start(&p, "h2");
    struct tr_node n = tls_node(g_port);
    struct xconn *x = xconn_new(&n, 0, 0);
    check("private: dial", 0, xconn_dial(x, 3));
    check("private: peer", 0, tp_finish(&p));
    size_t rn;
    unsigned char inner;
    rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &rn, &inner);
    struct xs s;
    check("private: open", 0, xs_open(x, &RQ_GET, 1, &s));
    check("private: HEADERS sent at once", 0, rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &rn, &inner));
    static unsigned char msg[16384];
    size_t m = frame(msg, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(msg + m, 12000, FR_DATA, 0, 1, NULL);
    tp_seal(p.sd, p.s.fd, msg, m);
    m = frame(msg, 12000, FR_DATA, 0, 1, NULL);
    tp_seal(p.sd, p.s.fd, msg, m);
    tp_seal(p.sd, p.s.fd, msg, m);
    for (int i = 0; i < 200 && fd_pending(x->link.fd) < 12041 + 2 * 12031; i++) usleep(1000);
    check("private: three records waiting", 12041 + 2 * 12031, fd_pending(x->link.fd));
    for (int i = 0; i < 3; i++) {
        size_t got = 0;
        check("private: read", 0, xs_read(&s, g_big, 16384, &got));
        check("private: exactly one record's data", 12000, (long)got);
        check("private: nothing else buffered", 0, xs_ready(&s));
        if (i < 2) check("private: the socket holds the rest", 1, fd_pending(x->link.fd) > 0);
    }
    int k = 0, recs = 0;
    long sum0 = 0, sum1 = 0;
    usleep(20000);
    while (fd_pending(p.s.fd) > 0 && !rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &rn, &inner)) {
        struct fv f[16];
        k = parse(g_rec, rn, f, 16);
        recs++;
        for (int i = 0; i < k; i++)
            if (f[i].type == FR_WINDOW_UPDATE && f[i].len == 4) {
                if (f[i].sid == 0) sum0 += be32(f[i].p);
                if (f[i].sid == 1) sum1 += be32(f[i].p);
            }
    }
    check("private: connection credit on consumption, 8192 + 12000 + 12000", 32192, sum0);
    check("private: stream credit on consumption, the same", 32192, sum1);
    check("private: one record per credited slice", 3, recs);
    xs_close(&s);
    xconn_free(x);
    tp_free(&p);
}

struct drv { int fd; long body; int bad, end; };

static void *drv_peer(void *a) {
    struct drv *d = a;
    int v = 4096;
    setsockopt(d->fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
    pw_settings_win(d->fd, 16u << 20);
    pw_u32(d->fd, FR_WINDOW_UPDATE, 0, 16u << 20);
    pw(d->fd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    for (int i = 0; i < 32; i++) pw(d->fd, FR_DATA, 0, 1, NULL, 16384);
    static unsigned char in[1 << 21];
    size_t n = 0, at = 0;
    uint64_t dl = mono_us() + 20000000;
    while (!d->end && mono_us() < dl) {
        if (n == sizeof in) break;
        size_t want = sizeof in - n < 16384 ? sizeof in - n : 16384;
        ssize_t r = read(d->fd, in + n, want);
        if (r <= 0) break;
        n += (size_t)r;
        for (;;) {
            if (at < 24 && n >= 24 && !memcmp(in, "PRI ", 4)) at = 24;
            if (n - at < 9) break;
            uint32_t len = ((uint32_t)in[at] << 16) | ((uint32_t)in[at + 1] << 8) | in[at + 2];
            if (n - at < 9 + len) break;
            if (in[at + 3] == FR_DATA && (be32(in + at + 5) & 0x7fffffffu) == 1) {
                for (uint32_t i = 0; i < len; i++)
                    d->bad += in[at + 9 + i] != (unsigned char)((d->body + i) % 251);
                d->body += len;
                if (in[at + 4] & FLAG_END_STREAM) d->end = 1;
            }
            at += 9 + len;
        }
        usleep(10000);
    }
    pw(d->fd, FR_DATA, FLAG_END_STREAM, 1, "done", 4);
    return NULL;
}

/* catches: a deadlock between a queued large POST and a blocking read */
static void t_private_driver(void) {
    for (size_t i = 0; i < sizeof g_big; i++) g_big[i] = (unsigned char)(i % 251);
    int l = listen_lo(4096);
    struct tr_node n = plain_node(g_port);
    struct xconn *x = xconn_new(&n, 0, 0);
    check("driver: dial", 0, xconn_dial(x, 3));
    small_sndbuf(x);
    struct drv d = { .fd = accept(l, NULL, NULL) };
    close(l);
    struct xs s;
    xs_open(x, &RQ_POST, 1, &s);
    pthread_t th;
    pthread_create(&th, NULL, drv_peer, &d);
    size_t sent = 0, got = 0, tot = 0;
    int rc = 0, end = 0;
    uint64_t t0 = mono_us(), dl = t0 + 15000000;
    while (sent < sizeof g_big && !rc && mono_us() < dl) {
        long r = xs_room(&s);
        if (r > 0 && !xconn_wants_out(x)) {
            size_t k = sizeof g_big - sent < (size_t)r ? sizeof g_big - sent : (size_t)r;
            rc = xs_send(&s, g_big + sent, k, sent + k == sizeof g_big);
            if (!rc) sent += k;
        } else if (xs_wait(&s, 2000) > 0) {
            int r2;
            while (!(r2 = xs_read(&s, g_pb, sizeof g_pb, &got)) && got) tot += got;
            if (r2) end = r2;
        }
    }
    while (xconn_wants_out(x) && mono_us() < dl) xs_wait(&s, 2000);
    uint64_t t_post = mono_us() - t0;
    check("driver: 1 MiB POST written", (long)sizeof g_big, (long)sent);
    check("driver: POST done within 4 s", 1, t_post < 4000000);
    check("driver: no error", 0, rc);
    while (!end && mono_us() < dl) {
        if (xs_wait(&s, 2000) < 0) break;
        int r2;
        while (!(r2 = xs_read(&s, g_pb, sizeof g_pb, &got)) && got) tot += got;
        if (r2) end = r2;
    }
    pthread_join(th, NULL);
    check("driver: peer got the whole body", (long)sizeof g_big, d.body);
    check("driver: body intact", 0, d.bad);
    check("driver: answer read", 524288 + 4, (long)tot);
    check("driver: answer ended", H2_ERESET, end);
    check("driver: in time", 1, mono_us() < dl);
    xs_close(&s);
    xconn_free(x);
    close(d.fd);
}

/* catches: one wake per stream instead of per owner */
static void t_wake_dedup(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs a, b, c;
    xs_open(p.x, &RQ_GET, 31, &a);
    xs_open(p.x, &RQ_POST, 31, &b);
    xs_open(p.x, &RQ_GET, 32, &c);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p.pfd, FR_DATA, 0, 1, "aa", 2);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 3, ST200, 1);
    pw(p.pfd, FR_DATA, 0, 3, "bb", 2);
    pw(p.pfd, FR_DATA, 0, 1, "cc", 2);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 5, ST200, 1);
    pw(p.pfd, FR_DATA, 0, 5, "dd", 2);
    g_wk_n = 0;
    io_in(p.x, 0);
    check("dedup: one wake for an owner with two streams", 1, wakes(31, XW_READ));
    check("dedup: the other owner woken too", 1, wakes(32, XW_READ));
    check("dedup: two wakes in all", 2, g_wk_n);
    close_plain(&p);
}

/* catches: a non-200 answer read as data, or its status lost */
static void t_status_refusal(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s;
    xs_open(p.x, &RQ_GET, 4, &s);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    static const unsigned char st404[5] = { 0x48, 0x03, '4', '0', '4' };
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, st404, 5);
    pw(p.pfd, FR_DATA, 0, 1, "not found", 9);
    g_wk_n = 0;
    io_in(p.x, 0);
    xconn_flush(p.x);
    unsigned char b[64];
    size_t n = peer_drain(p.pfd, b, sizeof b, 10);
    static const unsigned char rst1[13] = { 0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8 };
    check("status: refusal reset with CANCEL", 0, n == 13 ? memcmp(b, rst1, 13) : -1);
    check("status: owner woken", 1, wakes(4, XW_READ));
    size_t got;
    check("status: the flow reads H2_ESTATUS", H2_ESTATUS, xs_read(&s, b, sizeof b, &got));
    check("status: the status kept", 404, xs_status(&s));
    xs_close(&s);
    check("status: nothing left", 0, xconn_streams(p.x));
    close_plain(&p);
}

/* catches: a flow left waiting after the connection window reopened */
static void t_window_wakes(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs a, b;
    xs_open(p.x, &RQ_POST, 41, &a);
    xs_open(p.x, &RQ_POST, 42, &b);
    check("window: leave 1000 of the connection window", 0, xs_send(&a, g_big, 64535, 0));
    check("window: room is the window and 64 KiB to hold", 66536, xs_room(&b));
    g_wk_n = 0;
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("window: low water does not wake a window wait", 0, wakes(42, XW_ROOM));
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 40000);
    io_in(p.x, 0);
    check("window: the waiting flow woken", 1, wakes(42, XW_ROOM));
    check("window: the flow that never asked, not woken", 0, wakes(41, XW_ROOM));
    check("window: room back, shared by two uploaders, and 64 KiB to hold", 86036, xs_room(&b));
    close_plain(&p);
}

/* catches: a private link holding a write until someone flushes it */
static void t_private_writes_at_once(void) {
    int l = listen_lo(0);
    struct tr_node n = plain_node(g_port);
    struct xconn *x = xconn_new(&n, 0, 0);
    xconn_dial(x, 3);
    int pfd = accept(l, NULL, NULL);
    close(l);
    peer_drain(pfd, g_pb, sizeof g_pb, 10);
    struct xs s;
    xs_open(x, &RQ_POST, 1, &s);
    check("private write: HEADERS out at once", 1, count_type(peer_frames(pfd, 10), FR_HEADERS, 1));
    check("private write: send", 0, xs_send(&s, (const unsigned char *)"abc", 3, 0));
    int k = peer_frames(pfd, 10);
    check("private write: DATA out at once", 1, count_type(k, FR_DATA, 1));
    check("private write: its bytes", 0, k == 1 && g_fv[0].len == 3 ? memcmp(g_fv[0].p, "abc", 3) : -1);
    check("private write: nothing left queued", 0, xconn_wants_out(x));
    xs_close(&s);
    xconn_free(x);
    close(pfd);
}

/* catches: a GET closed before its answer left open on the server */
static void t_get_closed_early(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs g;
    xs_open(p.x, &RQ_GET, 1, &g);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    xs_close(&g);
    xconn_flush(p.x);
    unsigned char b[64];
    size_t n = peer_drain(p.pfd, b, sizeof b, 10);
    static const unsigned char rst1[13] = { 0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8 };
    static const unsigned char ping[9] = { 0, 0, 8, 6, 0, 0, 0, 0, 0 };
    check("early GET: RST_STREAM CANCEL and PING at once", 30, (long)n);
    check("early GET: RST bytes", 0, n == 30 ? memcmp(b, rst1, 13) : -1);
    check("early GET: PING", 0, n == 30 ? memcmp(b + 13, ping, 9) : -1);
    check("early GET: no stream left", 0, xconn_streams(p.x));
    struct xs h;
    xs_open(p.x, &RQ_GET, 2, &h);
    pw(p.pfd, FR_HEADERS, FLAG_END_HEADERS, 3, ST200, 1);
    io_in(p.x, 0);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    xconn_tick(p.x, 30000);
    xconn_flush(p.x);
    check("early GET: an owned GET is not reset at 30 s", 0, (long)peer_drain(p.pfd, b, sizeof b, 10));
    size_t got;
    check("early GET: still open", 0, xs_read(&h, b, sizeof b, &got));
    xs_close(&h);
    close_plain(&p);
}

/* catches: payload of a frame ending on a chunk boundary counted as queued for ever */
static void t_chunk_boundary_pay(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s;
    xs_open(p.x, &RQ_POST, 1, &s);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("boundary: send 16375", 0, xs_send(&s, g_big, 16375, 0));
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 10);
    check("boundary: one 16384-byte frame read", 1, k == 1 && g_fv[0].len == 16375);
    check("boundary: nothing queued", 0, (long)xc_queued());
    check("boundary: nothing to send", 0, xconn_wants_out(p.x));
    close_plain(&p);
}

/* catches: a second flush in one turn forgetting who uploaded */
static void t_two_flushes_one_turn(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    fill_windows(&p);
    struct xs s[2];
    for (int i = 0; i < 2; i++) xs_open(p.x, &RQ_POST, (uint16_t)(51 + i), &s[i]);
    for (int i = 0; i < 2; i++) xs_send(&s[i], g_big, 1, 0);
    xconn_flush(p.x);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("turn: queue empty", 0, (long)xc_queued());
    check("turn: room still shared by two", XC_OUT_HIGH / 2, xs_room(&s[0]));
    close_plain(&p);
}

struct fl_run { uint16_t port; int open_rc; unsigned left; struct xconn *x; pthread_barrier_t made, freed; };

static void *fl_thread(void *arg) {
    struct fl_run *r = arg;
    struct tr_node n = plain_node(r->port);
    r->x = xconn_new(&n, 0, 0);
    struct xs s;
    r->open_rc = xconn_dial(r->x, 3) ? -1 : xs_open(r->x, &RQ_GET, 1, &s);
    pthread_barrier_wait(&r->made);
    pthread_barrier_wait(&r->freed);
    r->left = xc_free_n();
    return NULL;
}

/* catches: a connector thread keeping the chunks of the private links it opened for good */
static void t_private_thread_keeps_no_chunks(void) {
    int l = listen_lo(0);
    static struct fl_run r;
    r.port = g_port;
    r.open_rc = -1;
    r.left = 99;
    pthread_barrier_init(&r.made, NULL, 2);
    pthread_barrier_init(&r.freed, NULL, 2);
    pthread_t th;
    int made = pthread_create(&th, NULL, fl_thread, &r) == 0;
    int pfd = made ? accept(l, NULL, NULL) : -1;
    if (made) {
        pthread_barrier_wait(&r.made);
        xconn_free(r.x);
        pthread_barrier_wait(&r.freed);
        pthread_join(th, NULL);
    }
    check("free list: the request went out", 0, r.open_rc);
    check("free list: the opening thread keeps no chunk", 0, (long)r.left);
    pthread_barrier_destroy(&r.made);
    pthread_barrier_destroy(&r.freed);
    if (pfd >= 0) close(pfd);
    close(l);
}

static unsigned char g_pat[1 << 18];

static size_t data_of(int k, uint32_t sid, unsigned char *out, size_t cap, int *end) {
    size_t n = 0;
    *end = 0;
    for (int i = 0; i < k; i++) {
        if (g_fv[i].type != FR_DATA || g_fv[i].sid != sid) continue;
        if (n + g_fv[i].len <= cap) memcpy(out + n, g_fv[i].p, g_fv[i].len);
        n += g_fv[i].len;
        if (g_fv[i].flags & FLAG_END_STREAM) *end = g_fv[i].len ? 1 : 2;
    }
    return n;
}

static void pat_fill(void) {
    for (size_t i = 0; i < sizeof g_pat; i++) g_pat[i] = (unsigned char)(i * 7 + i / 251);
}

/* catches: a write past the window refused, or its held bytes never sent or sent out of order */
static void t_overshoot_held_then_sent(void) {
    pat_fill();
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s;
    xs_open(p.x, &RQ_POST, 51, &s);
    check("held: 64535 sent at once", 0, xs_send(&s, g_pat, 64535, 0));
    check("held: 1460 past a 1000-byte window taken", 0, xs_send(&s, g_pat + 64535, 1460, 0));
    check("held: room only to hold, less what is held", 65076, xs_room(&s));
    check("held: 460 bytes held", 460, (long)p.x->pend_n);
    xconn_flush(p.x);
    static unsigned char got[1 << 18];
    int end;
    size_t n = data_of(peer_frames(p.pfd, 20), 1, got, sizeof got, &end);
    check("held: the windows' worth went out", 65535, (long)n);
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 5000);
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 1, 5000);
    io_in(p.x, 0);
    xconn_flush(p.x);
    n += data_of(peer_frames(p.pfd, 20), 1, got + n, sizeof got - n, &end);
    check("held: the rest after the WINDOW_UPDATE", 65995, (long)n);
    check("held: bytes in order", 0, n == 65995 ? memcmp(got, g_pat, n) : -1);
    check("held: nothing queued after", 0, (long)xc_queued());
    check("held: nothing held after", 0, (long)p.x->pend_n);
    check("held: room back, and 64 KiB to hold", 70076, xs_room(&s));
    xs_close(&s);
    close_plain(&p);
}

/* catches: held bytes not counted against the room of other flows and new streams */
static void t_room_counts_held(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s, t;
    xs_open(p.x, &RQ_POST, 64, &s);
    xs_open(p.x, &RQ_POST, 65, &t);
    check("count held: the stream window and 3000 more", 0, xs_send(&s, g_big, 68535, 0));
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 20);
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 10000);
    io_in(p.x, 0);
    check("count held: still held behind the stream window", 3000, (long)p.x->pend_n);
    check("count held: room of another flow, (10000 - 3000) / 2 and 64 KiB to hold", 69036, xs_room(&t));
    check("count held: a 5000 POST, 10000 - 3000 held = 7000 >= min(5000, 16384)", 5000, xc_post_room(p.x, 5000));
    check("count held: a 100000 POST waits, 7000 < 16384", 0, xc_post_room(p.x, 100000));
    xs_close(&t);
    check("count held: past the window, 8000 more", 0, xs_send(&s, g_big, 8000, 0));
    check("count held: 11000 held against a 10000 window", 11000, (long)p.x->pend_n);
    check("count held: no new POST while 11000 held cover the 10000 window", 0, xc_post_room(p.x, 1));
    xs_close(&s);
    close_plain(&p);
}

/* catches: send-ahead room missing, not capped by the queue share, or held bytes leaked at free */
static void t_headroom_from_a_pool(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs o, s[5];
    xs_open(p.x, &RQ_POST, 80, &o);
    for (int i = 0; i < 5; i++) xs_open(p.x, &RQ_POST, (uint16_t)(81 + i), &s[i]);
    check("pool: fill the connection window", 0, xs_send(&o, g_big, 65535, 0));
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 20);
    static const long want[5] = { 65536, 65536, 65536, 32768, 16384 };
    long held = 0;
    int refused = 0;
    for (int i = 0; i < 5; i++) {
        long r = xs_room(&s[i]);
        check("pool: room shrinks with what is held", want[i], r);
        refused += xs_send(&s[i], g_big, (size_t)r, 0) != 0;
        held += r;
    }
    check("pool: every room taken", 0, refused);
    check("pool: all of it held", held, (long)p.x->pend_n);
    check("pool: within half the limit", 1, held <= XC_PEND_MAX / 2);
    for (int i = 0; i < 5; i++) xs_close(&s[i]);
    xs_close(&o);
    close_plain(&p);
}

static void t_pend_one_frame(void) {
    static const unsigned char mf[6] = { 0, 5, 0, 0x10, 0, 0 };
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    pw(p.pfd, FR_SETTINGS, 0, 0, mf, 6);
    io_in(p.x, 0);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    struct xs s;
    xs_open(p.x, &RQ_POST, 1, &s);
    /* catches: held bytes sent in 16 KiB pieces once the window opens */
    check("pend frame: 100,000 taken", 0, xs_send(&s, g_big, 100000, 0));
    check("pend frame: 34,465 held", 34465, (long)p.x->pend_n);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("pend frame: one DATA now", 1, count_type(k, FR_DATA, 1));
    check("pend frame: of 65,535", 65535, k > 1 ? (long)g_fv[k - 1].len : -1);
    static const unsigned char inc[4] = { 0, 0x01, 0x86, 0xa0 };
    unsigned char wu[26];
    size_t m = frame(wu, 4, FR_WINDOW_UPDATE, 0, 1, inc);
    m += frame(wu + m, 4, FR_WINDOW_UPDATE, 0, 0, inc);
    check("pend frame: both windows opened in one write", (long)m, (long)write(p.pfd, wu, m));
    io_in(p.x, 0);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("pend frame: the held bytes as one DATA", 1, count_type(k, FR_DATA, 1));
    long len = -1;
    for (int i = 0; i < k; i++)
        if (g_fv[i].type == FR_DATA) len = (long)g_fv[i].len;
    check("pend frame: of 34,465", 34465, len);
    check("pend frame: nothing held", 0, (long)p.x->pend_n);
    check("pend frame: the pool back", (long)xc_pend_limit(), (long)xc_pend_free());
    xs_close(&s);
    close_plain(&p);
}

/* catches: held bytes counted as sent when the write of their frame fails */
static void t_pend_flush_write_fails(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s, o;
    xs_open(p.x, &RQ_POST, 66, &o);
    xs_open(p.x, &RQ_POST, 67, &s);
    check("held write fails: fill the connection window", 0, xs_send(&o, g_big, 65535, 0));
    check("held write fails: 300000 held", 0, xs_send(&s, g_big, 300000, 0));
    check("held write fails: the pool spent", (long)(xc_pend_limit() - 300000), (long)xc_pend_free());
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 100000);
    g_chunk_fail = 1;
    io_in(p.x, 0);
    int armed = g_chunk_fail;
    g_chunk_fail = 0;
    check("held write fails: the frame's chunk refused", 0, armed);
    check("held write fails: the link dies", XC_DEAD, p.x->state);
    check("held write fails: nothing held", 0, (long)p.x->pend_n);
    check("held write fails: the pool whole again", (long)xc_pend_limit(), (long)xc_pend_free());
    xs_close(&s);
    xs_close(&o);
    close_plain(&p);
}

static void t_cancel_ping_ceiling(void) {
    struct tp p;
    struct xconn *x;
    struct xs s;
    check("cancel ceiling: tls link", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    xs_open(x, &RQ_GET, 1, &s);
    xconn_flush(x);
    x->q_ctl = XC_CTL_MAX - 52;
    /* catches: the cancel PING left out of the control ceiling, or charged a record of its own */
    xs_close(&s);
    check("cancel ceiling: RST + PING, one 52 B record, within 52 B left", XC_LIVE, x->state);
    xconn_free(x);
    tp_free(&p);
    check("cancel ceiling: tls link again", 0, tls_link(&p, &x));
    xconn_adopt(x, 0);
    xs_open(x, &RQ_GET, 1, &s);
    xconn_flush(x);
    x->q_ctl = XC_CTL_MAX - 51;
    xs_close(&s);
    check("cancel ceiling: past 51 B left fails the link", XC_DEAD, x->state);
    xconn_free(x);
    tp_free(&p);
}

/* catches: END_STREAM sent before the held bytes, or as an empty frame after them */
static void t_held_keeps_order_and_end(void) {
    pat_fill();
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s, o;
    xs_open(p.x, &RQ_POST, 52, &s);
    xs_open(p.x, &RQ_POST, 53, &o);
    check("order: fill the connection window", 0, xs_send(&o, g_big, 65535, 0));
    check("order: first write held whole", 0, xs_send(&s, g_pat, 3000, 0));
    check("order: second write held behind it", 0, xs_send(&s, g_pat + 3000, 2000, 0));
    check("order: the end held behind both", 0, xs_send(&s, NULL, 0, 1));
    xconn_flush(p.x);
    static unsigned char got[1 << 16];
    int end;
    size_t n = data_of(peer_frames(p.pfd, 20), 1, got, sizeof got, &end);
    check("order: nothing of the held stream yet", 0, (long)n);
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 10000);
    io_in(p.x, 0);
    xconn_flush(p.x);
    n = data_of(peer_frames(p.pfd, 20), 1, got, sizeof got, &end);
    check("order: all 5000 bytes went", 5000, (long)n);
    check("order: in the order written", 0, n == 5000 ? memcmp(got, g_pat, n) : -1);
    check("order: END_STREAM on the last data frame, not an empty one", 1, end);
    xs_close(&s);
    xs_close(&o);
    close_plain(&p);
}

/* catches: held bytes always flushed from slot 0, so one stream starves the rest */
static void t_held_flush_rotates(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs o, a, b;
    xs_open(p.x, &RQ_POST, 90, &o);
    xs_open(p.x, &RQ_POST, 91, &a);
    xs_open(p.x, &RQ_POST, 92, &b);
    check("rotate: fill the connection window", 0, xs_send(&o, g_big, 65535, 0));
    check("rotate: a holds 20000", 0, xs_send(&a, g_big, 20000, 0));
    check("rotate: b holds 20000", 0, xs_send(&b, g_big, 20000, 0));
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 20);
    static unsigned char got[1 << 16];
    int end;
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 10000);
    io_in(p.x, 0);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("rotate: first window to a", 10000, (long)data_of(k, 3, got, sizeof got, &end));
    pw_u32(p.pfd, FR_WINDOW_UPDATE, 0, 10000);
    io_in(p.x, 0);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("rotate: second window to b, not a again", 10000, (long)data_of(k, 5, got, sizeof got, &end));
    check("rotate: a waits its turn", 0, (long)data_of(k, 3, got, sizeof got, &end));
    xs_close(&o);
    xs_close(&a);
    xs_close(&b);
    close_plain(&p);
}

/* catches: held bytes past the hard limit taken, or not given back at close */
static void t_held_bounded(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs a, b, o;
    xs_open(p.x, &RQ_POST, 54, &a);
    xs_open(p.x, &RQ_POST, 55, &b);
    xs_open(p.x, &RQ_POST, 56, &o);
    check("bound: fill the connection window", 0, xs_send(&o, g_big, 65535, 0));
    check("bound: half the limit held for a", 0, xs_send(&a, g_big, XC_PEND_MAX / 2, 0));
    check("bound: the other half held for b", 0, xs_send(&b, g_big, XC_PEND_MAX / 2, 0));
    check("bound: one byte past the limit refused", H2_EWINDOW, xs_send(&a, g_big, 1, 0));
    xs_close(&a);
    xs_close(&b);
    xs_close(&o);
    xconn_flush(p.x);
    check("bound: closing frees the held bytes", 0, (long)p.x->pend_n);
    struct xs c;
    xs_open(p.x, &RQ_POST, 57, &c);
    check("bound: the limit is free again", 0, xs_send(&c, g_big, XC_PEND_MAX, 0));
    xs_close(&c);
    xc_pend_set(100000);
    xs_open(p.x, &RQ_POST, 63, &c);
    check("bound: a set limit of 100000 holds 100000", 0, xs_send(&c, g_big, 100000, 0));
    check("bound: one byte past the set limit refused", H2_EWINDOW, xs_send(&c, g_big, 1, 0));
    xs_close(&c);
    xc_pend_set(XC_PEND_MAX);
    close_plain(&p);
}

/* catches: send-ahead room promised past the held limit, so a granted write is refused */
static void t_room_within_held_limit(void) {
    xc_pend_set(40000);
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs a, b;
    xs_open(p.x, &RQ_POST, 64, &a);
    xs_open(p.x, &RQ_POST, 65, &b);
    xs_send(&a, g_big, 1, 0);
    xs_send(&b, g_big, 1, 0);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    long ra = xs_room(&a), rb = xs_room(&b);
    check("held room: a gets 32766 + 40000/2", 52766, ra);
    check("held room: b gets 32766 + 40000/2", 52766, rb);
    check("held room: a's room accepted", 0, xs_send(&a, g_big, (size_t)ra, 0));
    check("held room: b's room accepted", 0, xs_send(&b, g_big, (size_t)rb, 0));
    check("held room: b holds 52766 - 12767", 39999, (long)p.x->pend_n);
    check("held room: none once the limit is spent", 0, xs_room(&b));
    xs_close(&a);
    xs_close(&b);
    close_plain(&p);
    xc_pend_set(XC_PEND_MAX);
}

/* catches: a private link holding bytes past its window */
static void t_private_overshoot_refused(void) {
    struct pl p;
    open_plain(&p, 0, 0, 0, 0);
    struct xs s;
    xs_open(p.x, &RQ_POST, 58, &s);
    check("private: 65535 fits", 0, xs_send(&s, g_big, 65535, 0));
    check("private: past the window refused", H2_EWINDOW, xs_send(&s, g_big, 1, 0));
    xs_close(&s);
    close_plain(&p);
}

/* catches: held bytes kept counted after the link failed */
static void t_fail_drops_held(void) {
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs s, o;
    xs_open(p.x, &RQ_POST, 59, &s);
    xs_open(p.x, &RQ_POST, 60, &o);
    xs_send(&o, g_big, 65535, 0);
    check("fail: held", 0, xs_send(&s, g_big, 10000, 0));
    xconn_fail(p.x, TR_EIO);
    check("fail: held bytes released", 0, (long)p.x->pend_n);
    xs_close(&s);
    xs_close(&o);
    close_plain(&p);
    open_plain(&p, 1, 0, 0, 0);
    xs_open(p.x, &RQ_POST, 61, &o);
    xs_send(&o, g_big, 65535, 0);
    xs_open(p.x, &RQ_POST, 62, &s);
    check("fail: the whole limit after a failure", 0, xs_send(&s, g_big, XC_PEND_MAX, 0));
    xs_close(&s);
    xs_close(&o);
    close_plain(&p);
}

static struct xconn *g_bx[4];

static void held_ok(const char *what) {
    int64_t s = 0;
    for (int i = 0; i < 4; i++)
        if (g_bx[i]) s += g_bx[i]->held_n;
    check(what, (long)s, (long)xc_held());
}

static int wu_is(int k, int i, uint32_t sid, uint32_t v) {
    return i < k && g_fv[i].type == FR_WINDOW_UPDATE && g_fv[i].sid == sid && be32(g_fv[i].p) == v;
}

static int rst_is(int k, int i, uint32_t sid) {
    return i < k && g_fv[i].type == FR_RST_STREAM && g_fv[i].sid == sid && be32(g_fv[i].p) == 8;
}

static unsigned char g_pour[4][12 * (9 + 16384) + 64];

static size_t pour_frames(unsigned char *b, uint32_t sid, int n16k, uint32_t tail) {
    size_t m = 0;
    for (int i = 0; i < n16k; i++) m += frame(b + m, 16384, FR_DATA, 0, sid, NULL);
    if (tail) m += frame(b + m, tail, FR_DATA, 0, sid, NULL);
    return m;
}

static void budget_off(void) {
    xc_budget_set(XC_RX_BUDGET, XC_RX_HARD, XC_RX_RESUME);
    memset(g_bx, 0, sizeof g_bx);
}

static void io_until_held(struct pl *p, int64_t n, uint64_t now) {
    for (int i = 0; i < 100 && p->x->held_n < n; i++) io_in(p->x, now);
}

static void io_until_paused(struct xconn *w, struct pl *p, uint64_t now) {
    for (int i = 0; i < 100 && xconn_wants_in(w); i++) io_in(p->x, now);
}

static void wait_pending(int fd) {
    for (int i = 0; i < 100 && fd_pending(fd) <= 0; i++) usleep(2000);
}

static void soft3(struct pl *p, struct xs *a, struct xs *b, struct xs *c) {
    xc_budget_set(65536, 1048576, 917504);
    open_plain(p, 1, 0, 0, 0);
    g_bx[0] = p->x;
    xs_open(p->x, &RQ_GET, 1, a);
    xs_open(p->x, &RQ_GET, 2, b);
    xs_open(p->x, &RQ_GET, 3, c);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
    unsigned char *q = g_pour[0];
    size_t m = frame(q, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(q + m, 1, FR_HEADERS, FLAG_END_HEADERS, 3, ST200);
    m += frame(q + m, 1, FR_HEADERS, FLAG_END_HEADERS, 5, ST200);
    m += pour_frames(q + m, 1, 4, 4464);
    m += pour_frames(q + m, 3, 0, 8192);
    m += pour_frames(q + m, 5, 0, 8192);
    struct bg g;
    bg_start(&g, p->pfd, q, m);
    io_until_held(p, 86384, 0);
    pthread_join(g.th, NULL);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
}

/* catches: withholding every stream, or none, past the soft budget */
static void t_soft_withholds_holders(void) {
    struct pl p;
    struct xs a, b, c;
    soft3(&p, &a, &b, &c);
    check("soft: 86384 held", 86384, (long)p.x->held_n);
    held_ok("soft: xc_held is the links' sum");
    long s0 = g_send_ok;
    size_t got = 0;
    xs_read(&c, g_big, 8192, &got);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("soft: C read all it held, credited", 1, k == 2 && wu_is(k, 0, 0, 8192) && wu_is(k, 1, 5, 8192));
    held_ok("soft: sum after C");
    xs_read(&b, g_big, 4096, &got);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("soft: B still holds, WU(0, 4096) alone", 1, k == 1 && wu_is(k, 0, 0, 4096));
    held_ok("soft: sum after B");
    xs_read(&b, g_big, 4096, &got);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("soft: B emptied, WU(0, 4096) + WU(3, 8192)", 1, k == 2 && wu_is(k, 0, 0, 4096) && wu_is(k, 1, 3, 8192));
    xs_read(&a, g_big, 8192, &got);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("soft: under the budget A credited", 1, k == 2 && wu_is(k, 0, 0, 8192) && wu_is(k, 1, 1, 8192));
    check("soft: four sends", 4, g_send_ok - s0);
    held_ok("soft: sum at the end");
    close_plain(&p);
    budget_off();
}

/* catches: withheld credit released only by the stream's own read, or A's unread bytes not refunded */
static void t_release_on_close(void) {
    struct pl p;
    struct xs a, b, c;
    soft3(&p, &a, &b, &c);
    size_t got = 0;
    xs_read(&c, g_big, 8192, &got);
    xs_read(&b, g_big, 4096, &got);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 20);
    xs_close(&a);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("release: three frames", 3, k);
    check("release: RST_STREAM(1, CANCEL)", 1, rst_is(k, 0, 1));
    check("release: WU(0, 70000) alone", 1, wu_is(k, 1, 0, 70000));
    check("release: WU(3, 4096) alone", 1, wu_is(k, 2, 3, 4096));
    check("release: B holds its 4096", 4096, (long)p.x->held_n);
    held_ok("release: sum");
    close_plain(&p);
    budget_off();
}

static void ceiling_at(struct pl *p, int slot, struct xs *a, uint16_t owner, uint64_t now) {
    open_plain(p, 1, 0, 0, now);
    g_bx[slot] = p->x;
    xs_open(p->x, &RQ_GET, owner, a);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
}

static void ceiling_link(struct pl *p, int slot, struct xs *a, uint16_t owner) { ceiling_at(p, slot, a, owner, 0); }

static void pour_bg(struct pl *p, int slot, struct bg *g, uint32_t sid, int n16k, uint32_t tail, int hdr) {
    unsigned char *q = g_pour[slot];
    size_t m = hdr ? frame(q, 1, FR_HEADERS, FLAG_END_HEADERS, sid, ST200) : 0;
    m += pour_frames(q + m, sid, n16k, tail);
    bg_start(g, p->pfd, q, m);
}

/* catches: reading past the ceiling, or a paused link polled */
static void t_hard_ceiling_pauses(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p1, p2;
    struct xs a, b;
    struct bg g;
    ceiling_link(&p1, 0, &a, 1);
    pour_bg(&p1, 0, &g, 1, 9, 0, 1);
    io_until_paused(p1.x, &p1, 0);
    check("ceiling: L1 stopped at the ceiling", 1, p1.x->held_n >= 131072 && p1.x->held_n < 147456);
    check("ceiling: L1 paused", 0, xconn_wants_in(p1.x));
    held_ok("ceiling: sum after L1");
    pthread_join(g.th, NULL);
    ceiling_link(&p2, 1, &b, 2);
    pw(p2.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p2.pfd, FR_DATA, 0, 1, NULL, 1000);
    wait_pending(p2.x->link.fd);
    int pend = fd_pending(p2.x->link.fd);
    xconn_io(p2.x, EPOLLIN, 0);
    check("ceiling: L2 read nothing", 0, (long)p2.x->held_n);
    check("ceiling: L2's socket untouched", pend, fd_pending(p2.x->link.fd));
    check("ceiling: L2 paused", 0, xconn_wants_in(p2.x));
    size_t got = 0;
    xs_read(&a, g_big, 30000, &got);
    check("ceiling: 30000 read", 30000, (long)got);
    check("ceiling: held under resume", 1, xc_held() >= 101072 && xc_held() < 117456);
    check("ceiling: L1 resumed", 1, xconn_wants_in(p1.x));
    check("ceiling: L2 resumed", 1, xconn_wants_in(p2.x));
    held_ok("ceiling: sum after the read");
    xconn_io(p2.x, EPOLLIN, 0);
    check("ceiling: L2 delivers 1000", 1000, (long)p2.x->held_n);
    held_ok("ceiling: sum at the end");
    close_plain(&p1);
    close_plain(&p2);
    budget_off();
}

/* catches: only the reading link paused, or the largest not */
static void t_ceiling_reader_paused(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p3, p4;
    struct xs a, b;
    struct bg g;
    ceiling_link(&p3, 0, &a, 1);
    pour_bg(&p3, 0, &g, 1, 6, 1696, 1);
    io_until_held(&p3, 100000, 0);
    pthread_join(g.th, NULL);
    check("reader: L3 holds 100000", 100000, (long)p3.x->held_n);
    check("reader: L3 not paused under the ceiling", 1, xconn_wants_in(p3.x));
    ceiling_link(&p4, 1, &b, 2);
    pour_bg(&p4, 1, &g, 1, 4, 0, 1);
    io_until_paused(p3.x, &p4, 0);
    check("reader: the ceiling crossed", 1, xc_held() >= 131072);
    check("reader: L4 held at most one read past it", 1, p4.x->held_n >= 31072 && p4.x->held_n < 47456);
    check("reader: L3, the largest, paused", 0, xconn_wants_in(p3.x));
    check("reader: L4 not paused", 1, xconn_wants_in(p4.x));
    held_ok("reader: sum");
    pthread_join(g.th, NULL);
    wait_pending(p4.x->link.fd);
    int64_t h4 = p4.x->held_n;
    xconn_io(p4.x, EPOLLIN, 0);
    check("reader: L4's next pass reads nothing", (long)h4, (long)p4.x->held_n);
    check("reader: and pauses L4", 0, xconn_wants_in(p4.x));
    held_ok("reader: sum at the end");
    close_plain(&p3);
    close_plain(&p4);
    budget_off();
}

/* catches: a paused link waiting for the soft budget while stalled streams hold it */
static void t_resume_with_stalled_holders(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p0, p1;
    struct xs a, b;
    struct bg g;
    ceiling_link(&p0, 0, &a, 1);
    pour_bg(&p0, 0, &g, 1, 3, 10848, 1);
    io_until_held(&p0, 60000, 0);
    pthread_join(g.th, NULL);
    check("stalled: L0 holds 60000", 60000, (long)p0.x->held_n);
    ceiling_link(&p1, 1, &b, 2);
    pour_bg(&p1, 1, &g, 1, 5, 0, 1);
    io_until_paused(p1.x, &p1, 0);
    pthread_join(g.th, NULL);
    check("stalled: L1 holds more than L0", 1, p1.x->held_n > 60000);
    check("stalled: L1 paused", 0, xconn_wants_in(p1.x));
    check("stalled: L0 not paused", 1, xconn_wants_in(p0.x));
    size_t got = 0;
    xs_read(&b, g_big, 30000, &got);
    check("stalled: held under resume, over soft", 1, xc_held() >= 101072 && xc_held() < 117456);
    check("stalled: L1 resumed", 1, xconn_wants_in(p1.x));
    held_ok("stalled: sum");
    close_plain(&p0);
    close_plain(&p1);
    budget_off();
}

static void ab_link(struct pl *p, struct xs *a, struct xs *b) {
    xc_budget_set(65536, 131072, 122880);
    open_plain(p, 1, 0, 0, 0);
    g_bx[0] = p->x;
    xs_open(p->x, &RQ_GET, 1, a);
    xs_open(p->x, &RQ_GET, 2, b);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
    unsigned char *q = g_pour[0];
    size_t m = frame(q, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(q + m, 1, FR_HEADERS, FLAG_END_HEADERS, 3, ST200);
    m += pour_frames(q + m, 3, 0, 2000);
    m += pour_frames(q + m, 1, 9, 0);
    struct bg g;
    bg_start(&g, p->pfd, q, m);
    io_until_paused(p->x, p, 0);
    pthread_join(g.th, NULL);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
}

/* catches: a ceiling held by stalled streams hanging every flow forever, or a reset before 30 s */
static void t_ceiling_stall_reset(void) {
    struct pl p;
    struct xs a, b;
    ab_link(&p, &a, &b);
    check("stall: L1 paused", 0, xconn_wants_in(p.x));
    int64_t ha = p.x->held_n - 2000;
    check("stall: A crossed the ceiling", 1, p.x->held_n >= 131072);
    g_wk_n = 0;
    xconn_tick(p.x, 20000);
    size_t got = 0;
    xs_read(&b, g_big, 1000, &got);
    check("stall: B read 1000", 1000, (long)got);
    check("stall: 29999 nothing", 0, xconn_tick(p.x, 29999));
    xconn_flush(p.x);
    check("stall: nothing sent before 30000", 0, peer_frames(p.pfd, 20));
    check("stall: still paused", 0, xconn_wants_in(p.x));
    check("stall: 30000 ticks clean", 0, xconn_tick(p.x, 30000));
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    check("stall: two frames", 2, k);
    check("stall: RST_STREAM(1, CANCEL)", 1, rst_is(k, 0, 1));
    check("stall: WU(0, A's bytes + B's 1000) alone", 1, wu_is(k, 1, 0, (uint32_t)(ha + 1000)));
    check("stall: A's owner woken", 1, wakes(1, XW_READ));
    check("stall: with H2_ERESET", H2_ERESET, wake_rc(1, XW_READ));
    check("stall: A reads the reset", H2_ERESET, xs_read(&a, g_big, 100, &got));
    check("stall: B's 1000 held", 1000, (long)xc_held());
    check("stall: L1 resumed", 1, xconn_wants_in(p.x));
    held_ok("stall: sum");
    close_plain(&p);
    budget_off();
}

/* catches: held bytes of a dead or closed paused link never subtracted */
static void t_pause_stream_ends(void) {
    struct pl p;
    struct xs a, b;
    ab_link(&p, &a, &b);
    check("ends: paused", 0, xconn_wants_in(p.x));
    int64_t h = xc_held(), ha = p.x->held_n - 2000;
    xs_close(&a);
    check("ends: held less exactly A's bytes", (long)(h - ha), (long)xc_held());
    check("ends: B's 2000 left", 2000, (long)xc_held());
    check("ends: resumed", 1, xconn_wants_in(p.x));
    held_ok("ends: sum");
    close_plain(&p);
    budget_off();
}

/* catches: held bytes of a dead or closed paused link never subtracted */
static void t_pause_link_dies(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p1, p2;
    struct xs a, b;
    struct bg g;
    ceiling_link(&p1, 0, &a, 1);
    pour_bg(&p1, 0, &g, 1, 9, 0, 1);
    io_until_paused(p1.x, &p1, 0);
    pthread_join(g.th, NULL);
    int64_t ha = p1.x->held_n;
    ceiling_link(&p2, 1, &b, 2);
    pw(p2.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p2.pfd, FR_DATA, 0, 1, NULL, 1000);
    wait_pending(p2.x->link.fd);
    xconn_io(p2.x, EPOLLIN, 0);
    check("dies: L2 paused", 0, xconn_wants_in(p2.x));
    xconn_fail(p1.x, TR_EIO);
    held_ok("dies: sum after the failure");
    int end = 0;
    size_t n = read_all_of(&a, g_big, sizeof g_big, &end);
    check("dies: A reads its held bytes", (long)ha, (long)n);
    check("dies: then the error", TR_EIO, end);
    xs_close(&a);
    check("dies: nothing held", 0, (long)xc_held());
    check("dies: L2 resumed", 1, xconn_wants_in(p2.x));
    held_ok("dies: sum");
    xconn_io(p2.x, EPOLLIN, 0);
    check("dies: L2 delivers 1000", 1000, (long)p2.x->held_n);
    close_plain(&p1);
    close_plain(&p2);
    budget_off();
}

/* catches: a paused link killed by its own PING timeout */
static void t_pause_no_keepalive(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p;
    struct xs a;
    struct bg g;
    int rc;
    ceiling_link(&p, 0, &a, 1);
    pour_bg(&p, 0, &g, 1, 9, 0, 1);
    io_until_paused(p.x, &p, 0);
    pthread_join(g.th, NULL);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("no ping: paused", 0, xconn_wants_in(p.x));
    size_t got = 0;
    check("no ping: tick 29000", 0, tick_pings(&p, 29000, &rc));
    xs_read(&a, g_big, 1, &got);
    check("no ping: tick 58000", 0, tick_pings(&p, 58000, &rc));
    xs_read(&a, g_big, 1, &got);
    check("no ping: none at 60000", 0, tick_pings(&p, 60000, &rc));
    check("no ping: tick 60000 clean", 0, rc);
    check("no ping: link live", XC_LIVE, p.x->state);
    check("no ping: still paused", 0, xconn_wants_in(p.x));
    xs_read(&a, g_big, (size_t)(p.x->held_n - 122879), &got);
    check("no ping: under resume", 122879, (long)xc_held());
    check("no ping: resumed", 1, xconn_wants_in(p.x));
    check("no ping: none at 61000", 0, tick_pings(&p, 61000, &rc));
    check("no ping: none at 104999", 0, tick_pings(&p, 104999, &rc));
    check("no ping: PING at 105000", 1, tick_pings(&p, 105000, &rc));
    held_ok("no ping: sum");
    close_plain(&p);
    budget_off();
}


static void paused_at(struct pl *p, int slot, struct xs *a, uint64_t now) {
    struct bg g;
    ceiling_at(p, slot, a, (uint16_t)(slot + 1), now);
    pour_bg(p, slot, &g, 1, 9, 0, 1);
    io_until_paused(p->x, p, now);
    pthread_join(g.th, NULL);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
}

static int rst_after_tick(struct pl *p, uint64_t now) {
    xconn_tick(p->x, now);
    xconn_flush(p->x);
    int k = peer_frames(p->pfd, 20);
    return count_type(k, FR_RST_STREAM, -1);
}

/* catches: a dead or freed paused link still counted, so the next pause runs on an old stall clock */
static void t_pause_count_cleared(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p1, p2, p3, p4;
    struct xs a, b, c, d;
    int end = 0;
    paused_at(&p1, 0, &a, 0);
    check("count: L1 paused", 0, xconn_wants_in(p1.x));
    xconn_fail(p1.x, TR_EIO);
    read_all_of(&a, g_big, sizeof g_big, &end);
    xs_close(&a);
    check("count: nothing held after the dead link", 0, (long)xc_held());
    paused_at(&p2, 1, &b, 100000);
    check("count: L2 paused at 100000", 0, xconn_wants_in(p2.x));
    check("count: no reset at 129999", 0, rst_after_tick(&p2, 129999));
    check("count: reset at 130000", 1, rst_after_tick(&p2, 130000));
    xs_close(&b);
    close_plain(&p2);
    paused_at(&p3, 2, &c, 200000);
    check("count: L3 paused", 0, xconn_wants_in(p3.x));
    close_plain(&p3);
    g_bx[2] = NULL;
    check("count: nothing held after the free", 0, (long)xc_held());
    paused_at(&p4, 3, &d, 300000);
    check("count: L4 paused at 300000", 0, xconn_wants_in(p4.x));
    check("count: no reset at 329999", 0, rst_after_tick(&p4, 329999));
    check("count: reset at 330000", 1, rst_after_tick(&p4, 330000));
    xs_close(&d);
    close_plain(&p4);
    close_plain(&p1);
    budget_off();
}

/* catches: a stall reset leaving the clock, so every tick after it resets another stream */
static void t_stall_clock_restarts(void) {
    xc_budget_set(65536, 131072, 16384);
    struct pl p;
    struct xs a, b;
    open_plain(&p, 1, 0, 0, 0);
    g_bx[0] = p.x;
    xs_open(p.x, &RQ_GET, 1, &a);
    xs_open(p.x, &RQ_GET, 2, &b);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    unsigned char *q = g_pour[0];
    size_t m = frame(q, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(q + m, 1, FR_HEADERS, FLAG_END_HEADERS, 3, ST200);
    m += pour_frames(q + m, 1, 5, 0);
    m += pour_frames(q + m, 3, 4, 0);
    struct bg g;
    bg_start(&g, p.pfd, q, m);
    io_until_paused(p.x, &p, 0);
    pthread_join(g.th, NULL);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("clock: paused", 0, xconn_wants_in(p.x));
    check("clock: A's 81920 reset at 30000", 1, rst_after_tick(&p, 30000));
    check("clock: B still over resume, paused", 0, xconn_wants_in(p.x));
    check("clock: no second reset at 30001", 0, rst_after_tick(&p, 30001));
    check("clock: none at 30999", 0, rst_after_tick(&p, 30999));
    check("clock: B reset at 31000", 1, rst_after_tick(&p, 31000));
    check("clock: resumed", 1, xconn_wants_in(p.x));
    held_ok("clock: sum");
    close_plain(&p);
    budget_off();
}

/* catches: a paused link's hang-up ignored until it resumes */
static void t_paused_hangup_fails(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p;
    struct xs a;
    paused_at(&p, 0, &a, 0);
    int64_t h = p.x->held_n;
    check("hangup: paused", 0, xconn_wants_in(p.x));
    check("hangup: EPOLLHUP fails it", TR_EIO, xconn_io(p.x, EPOLLHUP, 0));
    check("hangup: dead", XC_DEAD, p.x->state);
    check("hangup: nothing read", (long)h, (long)p.x->held_n);
    held_ok("hangup: sum");
    close_plain(&p);
    budget_off();
}

/* catches: a paused link that died still counted, so the next pause runs on its stall clock */
static void t_dead_pause_uncounted(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p1, p2;
    struct xs a, b;
    paused_at(&p1, 0, &a, 0);
    int64_t h = xc_held();
    xconn_fail(p1.x, TR_EIO);
    ceiling_at(&p2, 1, &b, 2, 100000);
    pw(p2.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p2.pfd, FR_DATA, 0, 1, NULL, 1000);
    wait_pending(p2.x->link.fd);
    xconn_io(p2.x, EPOLLIN, 100000);
    check("dead pause: L2 paused at 100000", 0, xconn_wants_in(p2.x));
    xconn_tick(p2.x, 129999);
    check("dead pause: A kept at 129999", (long)h, (long)xc_held());
    xconn_tick(p2.x, 130000);
    check("dead pause: A dropped at 130000", 0, (long)xc_held());
    check("dead pause: L2 resumed", 1, xconn_wants_in(p2.x));
    held_ok("dead pause: sum");
    xs_close(&a);
    close_plain(&p1);
    close_plain(&p2);
    budget_off();
}

/* catches: a PING sent before the pause timing out while the link may not read its ACK */
static void t_pause_holds_ping_clock(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p;
    struct xs a;
    struct bg g;
    int rc;
    ceiling_at(&p, 0, &a, 1, 0);
    check("ping clock: PING at 45000", 1, tick_pings(&p, 45000, &rc));
    pour_bg(&p, 0, &g, 1, 9, 0, 1);
    io_until_paused(p.x, &p, 50000);
    pthread_join(g.th, NULL);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("ping clock: paused at 50000", 0, xconn_wants_in(p.x));
    check("ping clock: no timeout at 60000 while paused", 0, xconn_tick(p.x, 60000));
    check("ping clock: tick 70000", 0, xconn_tick(p.x, 70000));
    size_t got = 0;
    xs_read(&a, g_big, (size_t)(p.x->held_n - 122879), &got);
    check("ping clock: resumed at 70000", 1, xconn_wants_in(p.x));
    check("ping clock: no timeout at 84999", 0, xconn_tick(p.x, 84999));
    check("ping clock: timeout at 85000", XC_EPING, xconn_tick(p.x, 85000));
    xs_close(&a);
    close_plain(&p);
    budget_off();
}

/* catches: a private link's read rewinding the stall clock to its own stale time */
static void t_private_read_no_progress(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl pp, p1;
    struct xs b, a;
    open_plain(&pp, 0, 0, 0, 0);
    xs_open(pp.x, &RQ_GET, 2, &b);
    xconn_flush(pp.x);
    peer_drain(pp.pfd, g_pb, sizeof g_pb, 10);
    pw(pp.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(pp.pfd, FR_DATA, 0, 1, NULL, 1000);
    wait_pending(pp.x->link.fd);
    paused_at(&p1, 0, &a, 100000);
    check("private read: L1 paused at 100000", 0, xconn_wants_in(p1.x));
    check("private read: none at 110000", 0, rst_after_tick(&p1, 110000));
    size_t got = 0;
    for (int i = 0; i < 20 && !got; i++) xs_read(&b, g_big, 100, &got);
    check("private read: 100 read", 100, (long)got);
    g_wk_n = 0;
    check("private read: no reset at 110001", 0, rst_after_tick(&p1, 110001));
    check("private read: none at 129999", 0, rst_after_tick(&p1, 129999));
    check("private read: reset at 130000", 1, rst_after_tick(&p1, 130000));
    close_plain(&p1);
    xs_close(&b);
    close_plain(&pp);
    budget_off();
}

/* catches: a dead link's read rewinding the stall clock to the time it died */
static void t_dead_read_progress_now(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p2, p1;
    struct xs b, a;
    ceiling_at(&p2, 1, &b, 2, 0);
    pw(p2.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p2.pfd, FR_DATA, 0, 1, NULL, 1000);
    wait_pending(p2.x->link.fd);
    xconn_io(p2.x, EPOLLIN, 0);
    check("dead read: L2 holds 1000", 1000, (long)p2.x->held_n);
    xconn_fail(p2.x, TR_EIO);
    paused_at(&p1, 0, &a, 100000);
    check("dead read: L1 paused at 100000", 0, xconn_wants_in(p1.x));
    xconn_tick(p1.x, 105000);
    size_t got = 0;
    xs_read(&b, g_big, 100, &got);
    check("dead read: 100 read at 105000", 100, (long)got);
    check("dead read: no reset at 125000", 0, rst_after_tick(&p1, 125000));
    xs_read(&a, g_big, 1, &got);
    check("dead read: A read 1 at 125000", 1, (long)got);
    int64_t h = xc_held();
    xconn_tick(p1.x, 134999);
    check("dead read: B kept at 134999", (long)h, (long)xc_held());
    g_wk_n = 0;
    xconn_tick(p1.x, 135000);
    check("dead read: B reset at 135000", H2_ERESET, wake_rc(2, XW_READ));
    check("dead read: B's 900 dropped", (long)(h - 900), (long)xc_held());
    check("dead read: A still paused", 0, xconn_wants_in(p1.x));
    check("dead read: A reset at 155000", 1, rst_after_tick(&p1, 155000));
    xs_close(&a);
    xs_close(&b);
    close_plain(&p1);
    close_plain(&p2);
    budget_off();
}

static int rst_sid(struct pl *p, uint64_t now) {
    xconn_tick(p->x, now);
    xconn_flush(p->x);
    int k = peer_frames(p->pfd, 20), n = 0;
    uint32_t sid = 0;
    for (int i = 0; i < k; i++)
        if (g_fv[i].type == FR_RST_STREAM) {
            n++;
            sid = g_fv[i].sid;
        }
    return n == 1 ? (int)sid : -n;
}

/* catches: a stall episode freeing one stream per 30 s, or resetting past the resume threshold */
static void t_stall_steps(void) {
    xc_budget_set(65536, 131072, 40000);
    struct pl p;
    struct xs s[6];
    open_plain(&p, 1, 0, 0, 0);
    g_bx[0] = p.x;
    for (int i = 0; i < 6; i++) xs_open(p.x, &RQ_GET, (uint16_t)(i + 1), &s[i]);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    unsigned char *q = g_pour[0];
    size_t m = 0;
    for (int i = 0; i < 6; i++) m += frame(q + m, 1, FR_HEADERS, FLAG_END_HEADERS, (uint32_t)(2 * i + 1), ST200);
    for (int i = 0; i < 6; i++) m += pour_frames(q + m, (uint32_t)(2 * i + 1), 1, 5616);
    struct bg g;
    bg_start(&g, p.pfd, q, m);
    io_until_paused(p.x, &p, 0);
    pthread_join(g.th, NULL);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("steps: paused", 0, xconn_wants_in(p.x));
    check("steps: held in [131072, 132000]", 1, xc_held() >= 131072 && xc_held() <= 132000);
    check("steps: none at 29999", 0, rst_sid(&p, 29999));
    check("steps: sid 1 at 30000", 1, rst_sid(&p, 30000));
    check("steps: none at 30999", 0, rst_sid(&p, 30999));
    check("steps: sid 3 at 31000", 3, rst_sid(&p, 31000));
    check("steps: sid 5 at 32000", 5, rst_sid(&p, 32000));
    check("steps: sid 7 at 33000", 7, rst_sid(&p, 33000));
    check("steps: still paused over 40000", 0, xconn_wants_in(p.x));
    check("steps: sid 9 at 34000", 9, rst_sid(&p, 34000));
    check("steps: under resume, resumed", 1, xc_held() < 40000 && xconn_wants_in(p.x));
    check("steps: none at 35000", 0, rst_sid(&p, 35000));
    check("steps: none at 64000", 0, rst_sid(&p, 64000));
    check("steps: F keeps its bytes", 1, p.x->held_n > 21000);
    held_ok("steps: sum");
    m = pour_frames(q, 11, 7, 0);
    bg_start(&g, p.pfd, q, m);
    io_until_paused(p.x, &p, 40000);
    pthread_join(g.th, NULL);
    check("steps: a new episode paused at 40000", 0, xconn_wants_in(p.x));
    check("steps: the new episode waits, none at 41000", 0, rst_sid(&p, 41000));
    check("steps: none at 69999", 0, rst_sid(&p, 69999));
    check("steps: sid 11 at 70000", 11, rst_sid(&p, 70000));
    for (int i = 0; i < 6; i++) xs_close(&s[i]);
    close_plain(&p);
    budget_off();
}

static void steps_setup(struct pl *p, struct xs *s) {
    xc_budget_set(65536, 131072, 40000);
    open_plain(p, 1, 0, 0, 0);
    g_bx[0] = p->x;
    for (int i = 0; i < 6; i++) xs_open(p->x, &RQ_GET, (uint16_t)(i + 1), &s[i]);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
    unsigned char *q = g_pour[0];
    size_t m = 0;
    for (int i = 0; i < 6; i++) m += frame(q + m, 1, FR_HEADERS, FLAG_END_HEADERS, (uint32_t)(2 * i + 1), ST200);
    for (int i = 0; i < 6; i++) m += pour_frames(q + m, (uint32_t)(2 * i + 1), 1, 5616);
    struct bg g;
    bg_start(&g, p->pfd, q, m);
    io_until_paused(p->x, p, 0);
    pthread_join(g.th, NULL);
    xconn_flush(p->x);
    peer_drain(p->pfd, g_pb, sizeof g_pb, 10);
}

/* catches: a read between ticks stamped with the last tick, or a stream just read reset by the episode */
static void t_episode_read_between_ticks(void) {
    struct pl p;
    struct xs s[6];
    steps_setup(&p, s);
    xc_budget_set(65536, 131072, 10000);
    check("episode read: paused", 0, xconn_wants_in(p.x));
    check("episode read: sid 1 at 30000", 1, rst_sid(&p, 30000));
    size_t got = 0;
    p.x->now_ms = 30200;
    xs_read(&s[5], g_big, 100, &got);
    check("episode read: sid 11 read 100 at 30200", 100, (long)got);
    p.x->now_ms = 30500;
    xs_read(&s[2], g_big, 100, &got);
    check("episode read: sid 5 read 100 at 30500", 100, (long)got);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    check("episode read: sid 3 at 31000", 3, rst_sid(&p, 31000));
    check("episode read: sid 7 at 32000", 7, rst_sid(&p, 32000));
    check("episode read: sid 9 at 33000", 9, rst_sid(&p, 33000));
    check("episode read: readers over resume, paused", 0, xconn_wants_in(p.x));
    check("episode read: readers spared at 34000", 0, rst_sid(&p, 34000));
    check("episode read: spared at 60000, read 29800 ms ago", 0, rst_sid(&p, 60000));
    check("episode read: sid 11 at 60200", 11, rst_sid(&p, 60200));
    check("episode read: sid 5 waits a second, none at 60500", 0, rst_sid(&p, 60500));
    check("episode read: none at 61199", 0, rst_sid(&p, 61199));
    check("episode read: sid 5 at 61200", 5, rst_sid(&p, 61200));
    for (int i = 0; i < 6; i++) xs_close(&s[i]);
    close_plain(&p);
    budget_off();
}

/* catches: an episode resetting more than one stream per second */
static void t_storm_bound(void) {
    struct pl p;
    struct xs s[6];
    steps_setup(&p, s);
    check("storm: sid 1 at 30000", 1, rst_sid(&p, 30000));
    check("storm: same now again none", 0, rst_sid(&p, 30000));
    check("storm: none at 30999", 0, rst_sid(&p, 30999));
    check("storm: sid 3 at 31000", 3, rst_sid(&p, 31000));
    check("storm: none at 31999", 0, rst_sid(&p, 31999));
    for (int i = 0; i < 6; i++) xs_close(&s[i]);
    close_plain(&p);
    budget_off();
}

/* catches: a loop-wide progress clock, so a stalled holder is never reset while another flow reads */
static void t_stall_with_reader_elsewhere(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p2, p1;
    struct xs b, a;
    ceiling_at(&p2, 1, &b, 2, 0);
    pw(p2.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p2.pfd, FR_DATA, 0, 1, NULL, 1000);
    wait_pending(p2.x->link.fd);
    xconn_io(p2.x, EPOLLIN, 0);
    check("reader elsewhere: L2 holds 1000", 1000, (long)p2.x->held_n);
    paused_at(&p1, 0, &a, 0);
    check("reader elsewhere: L1 paused", 0, xconn_wants_in(p1.x));
    size_t got = 0;
    for (uint64_t t = 10000; t <= 20000; t += 10000) {
        xconn_tick(p2.x, t - 5000);
        xs_read(&b, g_big, 100, &got);
        check("reader elsewhere: L2 read 100", 100, (long)got);
        check("reader elsewhere: no reset before 30000", 0, rst_after_tick(&p1, t));
    }
    xconn_tick(p2.x, 25000);
    xs_read(&b, g_big, 100, &got);
    check("reader elsewhere: none at 29999", 0, rst_after_tick(&p1, 29999));
    check("reader elsewhere: A reset at 30000", 1, rst_after_tick(&p1, 30000));
    check("reader elsewhere: L1 resumed", 1, xconn_wants_in(p1.x));
    check("reader elsewhere: B keeps its 700", 700, (long)xc_held());
    xconn_tick(p2.x, 35000);
    xs_read(&b, g_big, 100, &got);
    check("reader elsewhere: B still reads", 100, (long)got);
    held_ok("reader elsewhere: sum");
    xs_close(&a);
    xs_close(&b);
    close_plain(&p1);
    close_plain(&p2);
    budget_off();
}

/* catches: a fruitless walk deferring the next one past a holder that fills after it */
static void t_stall_holder_fills_late(void) {
    xc_budget_set(65536, 131072, 122880);
    struct pl p2, p1;
    struct xs c, a;
    ceiling_at(&p2, 1, &c, 2, 0);
    paused_at(&p1, 0, &a, 0);
    xc_budget_set(65536, 131072, 40000);
    p1.x->now_ms = 1000;
    size_t got = 0;
    xs_read(&a, g_big, 50000, &got);
    check("fills late: A read 50000 at 1000", 50000, (long)got);
    check("fills late: L1 still paused", 0, xconn_wants_in(p1.x));
    check("fills late: none at 2000", 0, rst_after_tick(&p1, 2000));
    pw(p2.pfd, FR_HEADERS, FLAG_END_HEADERS, 1, ST200, 1);
    pw(p2.pfd, FR_DATA, 0, 1, NULL, 1000);
    wait_pending(p2.x->link.fd);
    xconn_io(p2.x, EPOLLIN, 5000);
    check("fills late: C holds 1000", 1000, (long)p2.x->held_n);
    for (uint64_t t = 10000; t < 30000; t += 10000) check("fills late: none", 0, rst_after_tick(&p1, t));
    check("fills late: none at 29999", 0, rst_after_tick(&p1, 29999));
    g_wk_n = 0;
    check("fills late: A spared at 30000", 0, rst_after_tick(&p1, 30000));
    check("fills late: C reset at 30000", H2_ERESET, wake_rc(2, XW_READ));
    check("fills late: C's 1000 dropped", 0, (long)p2.x->held_n);
    check("fills late: A reset at 31000", 1, rst_after_tick(&p1, 31000));
    held_ok("fills late: sum");
    xs_close(&a);
    xs_close(&c);
    close_plain(&p1);
    close_plain(&p2);
    budget_off();
}

static unsigned char g_fmx_peer[1 << 17];

static size_t fm_peer_post(int pfd, struct tp *tls, uint32_t sid, size_t want, int *same) {
    size_t have = 0, n = 0, sum = 0;
    *same = 1;
    for (int i = 0; i < 200 && sum < want; i++) {
        if (tls) {
            unsigned char inner = 0;
            size_t rn = 0;
            if (rec_open(tls->cd, tls->s.fd, g_fmx_peer + have, sizeof g_fmx_peer - have, &rn, &inner)) break;
            have += rn;
        } else {
            size_t k = peer_drain(pfd, g_fmx_peer + have, sizeof g_fmx_peer - have, 20);
            have += k;
        }
        struct fv f[256];
        int k = parse(g_fmx_peer, have, f, 256);
        sum = 0;
        n = 0;
        for (int j = 0; j < k; j++) {
            if (f[j].type != FR_DATA || f[j].sid != sid) continue;
            if (n + f[j].len > want || memcmp(f[j].p, g_big + n, f[j].len)) *same = 0;
            n += f[j].len;
            sum += f[j].len;
        }
    }
    if (sum != want) *same = 0;
    return sum;
}

static size_t fm_get_body(struct xconn *x, const struct xs *g, unsigned char *out, size_t cap) {
    size_t have = 0;
    for (int i = 0; i < 100 && have < 3; i++) {
        if (x->shared) io_in(x, 0);
        else usleep(2000);
        size_t got = 0;
        if (xs_read(g, out + have, cap - have, &got)) break;
        have += got;
    }
    return have;
}

static void x55_plain(int shared) {
    const char *nm = shared ? "x55 xconn plain shared" : "x55 xconn plain private";
    char what[96];
    int fd0 = fd_count();
    int l = listen_lo(0);
    uint16_t sp = g_port;
    int rl = listen_lo(0);
    struct fmrelay r;
    fmrelay_listen(&r, rl, sp);
    struct tr_node n = plain_node(g_port);
    fm_use(&FMT_X55, 0);
    struct xconn *x = xconn_new(&n, 0, shared);
    int rc = xconn_dial(x, 3);
    fm_use(NULL, 0);
    snprintf(what, sizeof what, "%s: dial", nm);
    check(what, 0, rc);
    int pfd = rc ? -1 : accept(l, NULL, NULL);
    close(l);
    if (pfd < 0) {
        xconn_free(x);
        fmrelay_join(&r);
        return;
    }
    if (shared) xconn_adopt(x, 0);
    unsigned char b[256];
    size_t got = peer_drain(pfd, b, sizeof b, 100);
    snprintf(what, sizeof what, "%s: Go's preface through the chain", nm);
    check(what, 1, got == 70 && !memcmp(b, PREFACE70, 70));
    struct xs g, u;
    snprintf(what, sizeof what, "%s: GET opened", nm);
    check(what, 0, xs_open(x, &RQ_GET, 1, &g));
    xconn_flush(x);
    int k = peer_frames(pfd, 100);
    snprintf(what, sizeof what, "%s: GET HEADERS at the peer", nm);
    check(what, 1, count_type(k, FR_HEADERS, g.sid));
    pw(pfd, FR_HEADERS, FLAG_END_HEADERS, g.sid, ST200, 1);
    pw(pfd, FR_DATA, FLAG_END_STREAM, g.sid, "abc", 3);
    unsigned char body[8];
    got = fm_get_body(x, &g, body, sizeof body);
    snprintf(what, sizeof what, "%s: GET body read", nm);
    check(what, 1, got == 3 && !memcmp(body, "abc", 3));
    snprintf(what, sizeof what, "%s: POST opened", nm);
    check(what, 0, xs_open(x, &RQ_POST, 2, &u));
    snprintf(what, sizeof what, "%s: 40000 B sent", nm);
    check(what, 0, xs_send(&u, g_big, 40000, 1));
    for (int i = 0; i < 50 && xconn_wants_out(x); i++) {
        xconn_flush(x);
        usleep(2000);
    }
    int same = 0;
    size_t sum = fm_peer_post(pfd, NULL, u.sid, 40000, &same);
    snprintf(what, sizeof what, "%s: the peer got 40000 B of POST body", nm);
    check(what, 40000, (long)sum);
    snprintf(what, sizeof what, "%s: the body is the bytes sent", nm);
    check(what, 1, same);
    xconn_free(x);
    close(pfd);
    fmrelay_join(&r);
    snprintf(what, sizeof what, "%s: descriptors back", nm);
    check(what, fd0, fd_count());
}

/* catches: xconn.c:717/762/809 on the bare fd */
static void t_fm_x55_xconn_plain(void) {
    x55_plain(0);
    x55_plain(1);
}

/* catches: xconn.c:809 or the TLS read of a shared xconn link on the bare fd */
static void t_fm_x55_xconn_tls(void) {
    int fd0 = fd_count();
    struct tp p;
    check("x55 xconn tls: peer starts", 0, tp_start(&p, "h2"));
    uint16_t sp = g_port;
    int rl = listen_lo(0);
    struct fmrelay r;
    fmrelay_listen(&r, rl, sp);
    struct tr_node n = tls_node(g_port);
    fm_use(&FMT_X55, 0);
    struct xconn *x = xconn_new(&n, 0, 1);
    int rc = xconn_dial(x, 3);
    fm_use(NULL, 0);
    check("x55 xconn tls: dial", 0, rc);
    int keys = tp_finish(&p);
    check("x55 xconn tls: peer keys", 0, keys);
    if (rc || keys) {
        xconn_free(x);
        tp_free(&p);
        fmrelay_join(&r);
        return;
    }
    xconn_adopt(x, 0);
    size_t rn = 0;
    unsigned char inner = 0;
    check("x55 xconn tls: preface record opens", 0, rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &rn, &inner));
    check("x55 xconn tls: Go's preface", 1, rn == 70 && !memcmp(g_rec, PREFACE70, 70));
    struct xs g, u;
    check("x55 xconn tls: GET opened", 0, xs_open(x, &RQ_GET, 1, &g));
    xconn_flush(x);
    struct fv f[8];
    int k = next_rec(&p, f, 8, &rn);
    check("x55 xconn tls: GET HEADERS at the peer", 1, k == 1 && f[0].type == FR_HEADERS);
    unsigned char msg[64];
    size_t m = frame(msg, 1, FR_HEADERS, FLAG_END_HEADERS, g.sid, ST200);
    m += frame(msg + m, 3, FR_DATA, FLAG_END_STREAM, g.sid, "abc");
    check("x55 xconn tls: peer answers", 0, tp_seal(p.sd, p.s.fd, msg, m));
    unsigned char body[8];
    size_t got = fm_get_body(x, &g, body, sizeof body);
    check("x55 xconn tls: GET body read", 1, got == 3 && !memcmp(body, "abc", 3));
    check("x55 xconn tls: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    check("x55 xconn tls: 40000 B sent", 0, xs_send(&u, g_big, 40000, 1));
    for (int i = 0; i < 50 && xconn_wants_out(x); i++) {
        xconn_flush(x);
        usleep(2000);
    }
    int same = 0;
    check("x55 xconn tls: the peer got 40000 B of POST body", 40000, (long)fm_peer_post(-1, &p, u.sid, 40000, &same));
    check("x55 xconn tls: the body is the bytes sent", 1, same);
    xconn_free(x);
    tp_free(&p);
    fmrelay_join(&r);
    check("x55 xconn tls: descriptors back", fd0, fd_count());
}

/* catches: CCS and Finished written separately (tls13.c:759, :774), which makes Xray's packets:"1-3" count differ */
static void t_ccs_fin_one_write(void) {
    struct tp p;
    check("ccs+fin: peer starts", 0, tp_start(&p, "h2"));
    struct tr_node n = tls_node(g_port);
    struct tr_link l;
    memset(&l, 0, sizeof l);
    g_fmt_rec_k = 0;
    fm_use(&FMT_REC, 0);
    int rc = tr_link_open(&l, &n, "h2", 3);
    fm_use(NULL, 0);
    check("ccs+fin: handshake", 0, rc);
    int keys = tp_finish(&p);
    check("ccs+fin: peer keys", 0, keys);
    if (rc || keys) {
        tr_link_close(&l);
        tp_free(&p);
        return;
    }
    check("ccs+fin: two writes for the handshake", 2, (long)g_fmt_rec_k);
    size_t hello = 5 + ((size_t)g_fmt_rec_head[0][3] << 8 | g_fmt_rec_head[0][4]);
    check("ccs+fin: write 1 is the whole ClientHello record", 1,
          g_fmt_rec_head[0][0] == 0x16 && g_fmt_rec_n[0] == hello);
    check("ccs+fin: write 2 is 6 + 5 + 4 + 32 + 1 + 16 = 64 B", 64, (long)g_fmt_rec_n[1]);
    check("ccs+fin: write 2 is CCS then a sealed record", 1,
          !memcmp(g_fmt_rec_head[1], "\x14\x03\x03\x00\x01\x01\x17\x03", 8));
    unsigned char buf[3000];
    memset(buf, 0x2a, sizeof buf);
    check("ccs+fin: 3000 B written", 0, tls13_write(&l.tls, buf, sizeof buf));
    check("ccs+fin: one write per record, two records", 4, (long)g_fmt_rec_k);
    check("ccs+fin: 1186 + 22 then 1814 + 22", 1, g_fmt_rec_n[2] == 1208 && g_fmt_rec_n[3] == 1836);
    check("ccs+fin: application records counted alone", 2, (long)l.tls.wr_seq);
    size_t lens[2];
    check("ccs+fin: the peer opens both", 2, peer_lens(&p, lens, 2, 2));
    check("ccs+fin: plaintext 1186 and 1814", 1, lens[0] == 1186 && lens[1] == 1814);
    tr_link_close(&l);
    tp_free(&p);
}

static size_t g_fcc_n[1024];
static size_t g_fcc_k;
static unsigned char g_fcc_h[5];

static int fcc_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    if (!g_fcc_k && n == 5) memcpy(g_fcc_h, d, 5);
    if (g_fcc_k < 1024) g_fcc_n[g_fcc_k] = n;
    g_fcc_k++;
    return emit(arg, d, n, 0);
}

static const struct fm_ops FMT_FCC = { .splice = 1, .wr = fcc_wr };
static const char g_fcc_json[] = "{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"packets\":\"1-3\",\"length\":5}}]}";

static struct fm_link *fcc_new(const struct tr_node *n) {
    (void)n;
    const struct fm_cfg *c = fm_cfg_get(g_fcc_json);
    if (!c) return NULL;
    const struct fm_ops *o[2] = { &fm_frag_ops, &FMT_FCC };
    const struct fm_mask *m[2] = { &c->m[0], &g_fmt_mask };
    return fm_link_new_ops(o, m, 2);
}

static size_t fcc_cut(size_t *at, size_t total) {
    size_t sum = 0, k = 0;
    while (*at < g_fcc_k && *at < 1024 && sum < total) {
        size_t n = g_fcc_n[(*at)++];
        if (sum + n < total && n != 5) return 0;
        if (n > 5) return 0;
        sum += n;
        k++;
    }
    return sum == total ? k : 0;
}

static void t_frag_ccs_count(void) {
    /* catches: the write count drifting by one through a separate CCS write */
    struct tp p;
    check("frag ccs: peer starts", 0, tp_start(&p, "h2"));
    struct tr_node n = tls_node(g_port);
    struct tr_link l;
    memset(&l, 0, sizeof l);
    g_fcc_k = 0;
    g_fm_new = fcc_new;
    int rc = tr_link_open(&l, &n, "h2", 3);
    g_fm_new = NULL;
    check("frag ccs: handshake", 0, rc);
    int keys = tp_finish(&p);
    check("frag ccs: peer keys", 0, keys);
    if (rc || keys) {
        tr_link_close(&l);
        tp_free(&p);
        return;
    }
    unsigned char buf[3000];
    memset(buf, 0x2a, sizeof buf);
    check("frag ccs: 3000 B written", 0, tls13_write(&l.tls, buf, sizeof buf));
    size_t at = 0, hello = 5 + ((size_t)g_fcc_h[3] << 8 | g_fcc_h[4]);
    check("frag ccs: the first piece is a hello header", 1, g_fcc_h[0] == 0x16 && hello > 5);
    size_t hk = fcc_cut(&at, hello);
    check("frag ccs: the hello in 5 B pieces", (long)((hello + 4) / 5), (long)hk);
    size_t ck = at;
    check("frag ccs: CCS + Finished as 12 x 5 + 4", 13, (long)fcc_cut(&at, 64));
    check("frag ccs: its last piece 4 B", 4, (long)g_fcc_n[ck + 12]);
    check("frag ccs: the first record in 5 B pieces, 241 x 5 + 3", 242, (long)fcc_cut(&at, 1208));
    check("frag ccs: the fourth write whole", 1, at + 1 == g_fcc_k && g_fcc_n[at] == 1836);
    size_t lens[2];
    check("frag ccs: the peer opens both", 2, peer_lens(&p, lens, 2, 2));
    check("frag ccs: plaintext 1186 and 1814", 1, lens[0] == 1186 && lens[1] == 1814);
    tr_link_close(&l);
    tp_free(&p);
}

static unsigned char g_gp[1 << 16];
static size_t g_gp_n;

static uint64_t gap_ms(void) { return mono_us() / 1000; }

static void gap_drain(int pfd) {
    for (;;) {
        ssize_t r = recv(pfd, g_gp + g_gp_n, sizeof g_gp - g_gp_n, MSG_DONTWAIT);
        if (r <= 0) return;
        g_gp_n += (size_t)r;
    }
}

static long gap_body(uint32_t sid, int *data_last) {
    struct fv f[256];
    int k = parse(g_gp, g_gp_n, f, 256);
    long sum = 0;
    *data_last = -1;
    for (int j = 0; j < k; j++) {
        if (f[j].type != FR_DATA || f[j].sid != sid) continue;
        if (memcmp(f[j].p, g_big + sum, f[j].len)) return -1;
        sum += f[j].len;
        *data_last = j;
    }
    return sum;
}

static int gap_ack(void) {
    struct fv f[256];
    int k = parse(g_gp, g_gp_n, f, 256);
    for (int j = 0; j < k; j++)
        if (f[j].type == FR_PING && (f[j].flags & FLAG_ACK)) return j;
    return -1;
}

static struct xconn *gap_dial(const struct fm_ops *o, int *pfd) {
    int l = listen_lo(0);
    struct tr_node n = plain_node(g_port);
    fm_use(o, 0);
    struct xconn *x = xconn_new(&n, 0, 0);
    int rc = x ? xconn_dial(x, 3) : -1;
    fm_use(NULL, 0);
    *pfd = rc ? -1 : accept(l, NULL, NULL);
    close(l);
    if (*pfd < 0) {
        xconn_free(x);
        return NULL;
    }
    g_gp_n = 0;
    peer_drain(*pfd, g_gp, sizeof g_gp, 50);
    g_gp_n = 0;
    return x;
}

static void gap_wait_in(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    poll(&p, 1, 200);
}

/* catches: the flush sending past a gap, or gaps blocking the read path */
static void t_xconn_gap(void) {
    int pfd;
    struct xconn *x = gap_dial(&FMT_GAP, &pfd);
    if (!x) {
        check("gap: dial", 0, 1);
        return;
    }
    struct xs u;
    uint64_t t0 = gap_ms(), tb = t0;
    check("gap: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    uint64_t ta = gap_ms();
    check("gap: 250 B sent", 0, xs_send(&u, g_big, 250, 1));
    int due = xconn_due(x, tb);
    check("gap: due 30 ms after the first flush", 1, due >= 30 && (uint64_t)due <= 30 + (ta - tb));
    check("gap: nothing to poll for while the gap runs", 0, xconn_wants_out(x));
    usleep(5000);
    gap_drain(pfd);
    int last = -1;
    check("gap: no body before the gap", 0, gap_body(u.sid, &last));
    pw(pfd, FR_PING, 0, 0, "12345678", 8);
    gap_wait_in(x->link.fd);
    check("gap: the PING is read during the gap", 0, xconn_io(x, EPOLLIN, gap_ms()));
    uint64_t body_at = 0, ack_at = 0;
    while (gap_ms() < t0 + 500 && !(body_at && ack_at)) {
        if (xconn_due(x, gap_ms()) == 0) xconn_flush(x);
        gap_drain(pfd);
        if (!body_at && gap_body(u.sid, &last) == 250) body_at = gap_ms();
        if (!ack_at && gap_ack() >= 0) ack_at = gap_ms();
        usleep(1000);
    }
    check("gap: the peer got the 250 B in order", 250, gap_body(u.sid, &last));
    check("gap: the last 50 not before 60 ms", 1, body_at >= t0 + 60);
    check("gap: the PING answered after the body", 1, ack_at && gap_ack() > last);
    xs_close(&u);
    xconn_free(x);
    close(pfd);
}

/* catches: the read-side flush sending past out_due */
static void t_xconn_gap_read_flush(void) {
    int pfd;
    struct xconn *x = gap_dial(&FMT_GAPZ, &pfd);
    if (!x) {
        check("gap read: dial", 0, 1);
        return;
    }
    struct xs u;
    uint64_t t0 = gap_ms();
    check("gap read: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    pw(pfd, FR_PING, 0, 0, "12345678", 8);
    gap_wait_in(x->link.fd);
    unsigned char b[16];
    size_t got = 0;
    check("gap read: read", 0, xs_read(&u, b, sizeof b, &got));
    usleep(5000);
    gap_drain(pfd);
    check("gap read: the PING ACK waits behind the gap", -1, gap_ack());
    check("gap read: a due time is reported", 1, xconn_due(x, gap_ms()) > 0);
    uint64_t ack_at = 0;
    while (gap_ms() < t0 + 300 && !ack_at) {
        if (xconn_due(x, gap_ms()) == 0) xconn_flush(x);
        gap_drain(pfd);
        if (gap_ack() >= 0) ack_at = gap_ms();
        usleep(1000);
    }
    check("gap read: the ACK leaves, not before its due time", 1, ack_at >= t0 + 30);
    xs_close(&u);
    xconn_free(x);
    close(pfd);
}

/* catches: a zero-length gap piece refused, or a layer that emits nothing leaving its bytes counted */
static void t_xconn_gap_empty(void) {
    int pfd;
    struct xconn *x = gap_dial(&FMT_GAPZ, &pfd);
    if (!x) {
        check("gap zero: dial", 0, 1);
        return;
    }
    struct xs u;
    uint64_t t0 = gap_ms();
    check("gap zero: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    check("gap zero: 250 B sent", 0, xs_send(&u, g_big, 250, 1));
    int last = -1;
    uint64_t body_at = 0;
    while (gap_ms() < t0 + 300 && !body_at) {
        if (xconn_due(x, gap_ms()) == 0) xconn_flush(x);
        gap_drain(pfd);
        if (gap_body(u.sid, &last) == 250) body_at = gap_ms();
        usleep(1000);
    }
    check("gap zero: the body after the HEADERS' gap", 1, body_at >= t0 + 30);
    xs_close(&u);
    xconn_free(x);
    close(pfd);
    x = gap_dial(&FMT_EAT, &pfd);
    if (!x) {
        check("gap eat: dial", 0, 1);
        return;
    }
    check("gap eat: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    check("gap eat: 250 B sent", 0, xs_send(&u, g_big, 250, 1));
    xconn_flush(x);
    check("gap eat: nothing left queued", 1, !xconn_wants_out(x) && !x->q_pay && !x->q_ctl && !x->out.head);
    xs_close(&u);
    xconn_free(x);
    close(pfd);
}

/* catches: transport_due not kicking the link's own chain, or room not taken from its queue */
static void t_transport_due(void) {
    static struct transport t;
    memset(&t, 0, sizeof t);
    check("transport due: no transport, nothing waits", 0, transport_due(&t, gap_ms(), &(int){ 0 }));
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp)) {
        check("transport due: socketpair", 0, 1);
        return;
    }
    t.fr = &tr_tcp;
    t.link.fd = sp[0];
    t.link.plain = 1;
    int next = 7;
    check("transport due: unmasked link, ok", 0, transport_due(&t, gap_ms(), &next));
    check("transport due: unmasked link, nothing waits", -1, next);
    check("transport due: unmasked link, no mask room", -1, transport_mask_room(&t));
    const struct fm_ops *o[1] = { &FMT_GAP };
    const struct fm_mask *m[1] = { &g_fmt_mask };
    t.link.tls.fm = fm_link_new_ops(o, m, 1);
    transport_set_loop(&t);
    uint64_t t0 = gap_ms(), tb = t0;
    check("transport due: 250 B written", 0, transport_write(&t, g_big, 250));
    uint64_t ta = gap_ms();
    g_gp_n = 0;
    gap_drain(sp[1]);
    check("transport due: the first piece leaves at once", 100, (long)g_gp_n);
    check("transport due: room is 65536 less 150 B and two pieces", 65536 - 150 - 16, transport_mask_room(&t));
    check("transport due: ok", 0, transport_due(&t, tb, &next));
    check("transport due: 30 ms to the next piece", 1, next >= 30 && (uint64_t)next <= 30 + (ta - tb));
    while (g_gp_n < 250 && gap_ms() < t0 + 300) {
        if (!transport_due(&t, gap_ms(), &next) && next > 0) usleep(1000);
        gap_drain(sp[1]);
    }
    check("transport due: all 250 B in order", 1, g_gp_n == 250 && !memcmp(g_gp, g_big, 250));
    check("transport due: not before 60 ms", 1, gap_ms() >= t0 + 60);
    check("transport due: room back to 65536", 65536, transport_mask_room(&t));
    tr_link_close(&t.link);
    close(sp[1]);
    int pfd;
    struct xconn *x = gap_dial(&FMT_GAP, &pfd);
    if (!x) {
        check("transport due xhttp: dial", 0, 1);
        return;
    }
    memset(&t, 0, sizeof t);
    t.fr = &tr_xhttp;
    t.xh.wait_ms = 1000;
    t.xh.priv[1] = x;
    struct xs u;
    t0 = tb = gap_ms();
    check("transport due xhttp: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    ta = gap_ms();
    check("transport due xhttp: 250 B sent", 0, xs_send(&u, g_big, 250, 1));
    check("transport due xhttp: ok", 0, transport_due(&t, tb, &next));
    check("transport due xhttp: the private link's gap reported", 1,
          next >= 30 && (uint64_t)next <= 30 + (ta - tb));
    int last = -1;
    uint64_t body_at = 0;
    while (gap_ms() < t0 + 500 && !body_at) {
        if (!transport_due(&t, gap_ms(), &next) && next > 0) usleep(1000);
        gap_drain(pfd);
        if (gap_body(u.sid, &last) == 250) body_at = gap_ms();
    }
    check("transport due xhttp: the body leaves through due alone", 250, gap_body(u.sid, &last));
    check("transport due xhttp: after the gaps", 1, body_at >= t0 + 60);
    xs_close(&u);
    xconn_free(x);
    close(pfd);
}

/* catches: tiny pieces held on a link without counting their chunks, so a masked link grows past every bound */
static void t_xconn_piece_cost(void) {
    int pfd;
    g_fmt_one_gap = 0;
    struct xconn *x = gap_dial(&FMT_ONE, &pfd);
    if (!x) {
        check("piece cost: dial", 0, 1);
        return;
    }
    g_fmt_one_gap = 1000;
    struct xs u;
    check("piece cost: POST opened", 0, xs_open(x, &RQ_POST, 2, &u));
    check("piece cost: 8 KiB sent", 0, xs_send(&u, g_big, 8192, 0));
    check("piece cost: each 1 B piece counted at 32 B or more", 1, x->q_pay >= 8192u * (1 + 32));
    check("piece cost: the room is down to its floor", 1, xs_room(&u) <= XC_MSS);
    int rc = 0;
    for (int i = 0; i < 4 && !rc; i++) rc = xs_send(&u, g_big, 8192, 0);
    check("piece cost: over the hard cap the link fails", TR_EIO, rc);
    check("piece cost: nothing counted after the failure", 0, (long)x->q_pay);
    xs_close(&u);
    xconn_free(x);
    close(pfd);
}

static void *g_gs_link;
static int *g_gs_done;

static int gs_submit(void *link, int *done) {
    g_gs_link = link;
    g_gs_done = done;
    return 0;
}

static int gs_watch(unsigned idx, int fd, unsigned ev) {
    (void)idx; (void)fd; (void)ev;
    return 0;
}

static const struct mux_host GS_HOST = { gs_submit, gs_watch, rec_wake, NULL, 1, 8000 };

/* catches: shared xmux links never woken for their delayed pieces */
static void t_xconn_gap_shared(void) {
    static struct transport t;
    static char key[4];
    memset(&t, 0, sizeof t);
    g_gs_link = NULL;
    tr_xmux_host(&GS_HOST, NULL);
    int l = listen_lo(0);
    struct tr_node n = plain_node(g_port);
    n.path = "/x";
    n.mode = "stream-one";
    n.xhx = "xmux.maxConnections=1\n";
    struct xc_ref ref = { key, 0, 0 };
    tr_xmux_pass(gap_ms(), MUXP_EARLY);
    check("gap shared: the flow waits for a link", XA_WAIT, tr_xmux_attach(&t, &n, key, NULL, 1, &ref));
    int rc = -1;
    if (g_gs_link) {
        fm_use(&FMT_GAP, 0);
        rc = tr_xmux_dial(g_gs_link, 3);
        fm_use(NULL, 0);
        __atomic_store_n(g_gs_done, 1, __ATOMIC_RELEASE);
    }
    check("gap shared: dial", 0, rc);
    int pfd = rc ? -1 : accept(l, NULL, NULL);
    close(l);
    if (pfd >= 0) {
        peer_drain(pfd, g_gp, sizeof g_gp, 50);
        g_gp_n = 0;
        tr_xmux_pass(gap_ms(), MUXP_EARLY);
        check("gap shared: the flow is on the link", 1, t.xh.f.one.x != NULL);
        check("gap shared: 250 B written", 0, t.xh.f.one.x ? transport_write(&t, g_big, 250) : -1);
        uint64_t t0 = gap_ms(), tb = t0;
        int due = tr_xmux_pass(t0, MUXP_LATE);
        uint64_t ta = gap_ms();
        int ld = xconn_due(t.xh.f.one.x, tb);
        check("gap shared: the link's gap is 30 ms from the pass", 1, ld >= 30 && (uint64_t)ld <= 30 + (ta - tb));
        check("gap shared: the pass asks to be woken within it", 1, due > 0 && due <= ld);
        int last = -1;
        uint64_t body_at = 0;
        while (gap_ms() < t0 + 500 && !body_at) {
            int d = tr_xmux_pass(gap_ms(), MUXP_LATE);
            gap_drain(pfd);
            if (gap_body(t.xh.f.one.sid, &last) == 250) body_at = gap_ms();
            usleep(d > 0 ? 1000 : 2000);
        }
        check("gap shared: the peer got the 250 B in order", 250, gap_body(t.xh.f.one.sid, &last));
        check("gap shared: after the gaps", 1, body_at >= t0 + 60);
    }
    if (t.fr) transport_close(&t);
    tr_xmux_pass(gap_ms(), MUXP_EXIT);
    if (pfd >= 0) close(pfd);
    tr_xmux_host(NULL, NULL);
    xc_set_host(&HOST);
}

/* catches: a handshake that runs on a NULL buffer or sends a Hello it cannot finish */
static void t_handshake_no_memory(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
        check("no memory: socketpair", 0, 1);
        return;
    }
    static const unsigned char alert[7] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50 };
    check("no memory: alert queued", 0, wr_all(sv[1], alert, sizeof alert));
    shutdown(sv[1], SHUT_WR);
    unsigned char hello[64] = { 0x16, 0x03, 0x01, 0x00, 59, 0x01 };
    unsigned char priv[32] = { 1 };
    struct tls13 *t = calloc(1, sizeof *t);
    if (!t) {
        check("no memory: tls13", 0, 1);
        close(sv[0]);
        close(sv[1]);
        return;
    }
    g_hs_tries = 0;
    g_hs_fail = 1;
    int rc = tls13_handshake(t, sv[0], hello, sizeof hello, priv);
    g_hs_fail = 0;
    int unread = -1;
    ioctl(sv[0], FIONREAD, &unread);
    unsigned char b, left[sizeof alert];
    while (recv(sv[0], left, sizeof left, MSG_DONTWAIT) > 0) {}
    close(sv[0]);
    struct timeval tv = { .tv_sec = 2 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ssize_t r = recv(sv[1], &b, 1, 0);
    check("no memory: TLS13_EIO", TLS13_EIO, rc);
    check("no memory: one block of 81920 asked for", 1, g_hs_tries);
    check("no memory: the server's record left unread", (long)sizeof alert, unread);
    check("no memory: EOF before any byte", 0, (long)r);
    close(sv[1]);
    free(t);
}

struct nsx { struct xconn *x; int rc, state, xrc, tries, again; };

static void nsx_fail(void) {
    g_cfail_tries = 0;
    g_cfail = sizeof(struct xconn_scratch);
}

static void *nsx_new(void *a) {
    struct nsx *s = a;
    nsx_fail();
    struct tr_node n = plain_node(g_port);
    s->x = xconn_new(&n, 0, 0);
    g_cfail = 0;
    s->tries = g_cfail_tries;
    struct xconn *y = xconn_new(&n, 0, 0);
    s->again = y != NULL;
    xconn_free(y);
    return NULL;
}

static void *nsx_dial(void *a) {
    struct nsx *s = a;
    nsx_fail();
    s->rc = xconn_dial(s->x, 3);
    g_cfail = 0;
    s->tries = g_cfail_tries;
    s->state = s->x->state;
    s->xrc = s->x->rc;
    return NULL;
}

static void *nsx_adopt(void *a) {
    struct nsx *s = a;
    nsx_fail();
    s->rc = xconn_adopt(s->x, 0);
    g_cfail = 0;
    s->tries = g_cfail_tries;
    s->state = s->x->state;
    s->xrc = s->x->rc;
    xconn_free(s->x);
    s->x = NULL;
    return NULL;
}

static int nsx_run(void *(*f)(void *), struct nsx *s) {
    pthread_t th;
    if (pthread_create(&th, NULL, f, s)) return 0;
    pthread_join(th, NULL);
    return 1;
}

/* catches: new, dial or adopt going on without a scratch, or a link left open and silent */
static void t_xconn_adopt_no_scratch(void) {
    struct nsx s;
    memset(&s, 0, sizeof s);
    int l = listen_lo(0);
    check("no scratch: listener", 1, l >= 0);
    if (l < 0) return;
    check("no scratch: new ran", 1, nsx_run(nsx_new, &s));
    check("no scratch: new asks for one scratch block", 1, s.tries);
    check("no scratch: new gives NULL", 1, s.x == NULL);
    check("no scratch: the next new succeeds", 1, s.again);

    struct tr_node n = plain_node(g_port);
    memset(&s, 0, sizeof s);
    s.x = xconn_new(&n, 0, 0);
    check("no scratch: dial ran", 1, s.x && nsx_run(nsx_dial, &s));
    struct pollfd pl = { .fd = l, .events = POLLIN };
    int pending = poll(&pl, 1, 300);
    check("no scratch: dial asks for one scratch block", 1, s.tries);
    check("no scratch: dial fails with H2_EIO", H2_EIO, s.rc);
    check("no scratch: dial leaves the link dead", XC_DEAD, s.state);
    check("no scratch: dial keeps the error", H2_EIO, s.xrc);
    check("no scratch: dial connects nowhere", 0, pending);
    if (s.x) xconn_free(s.x);

    memset(&s, 0, sizeof s);
    s.x = xconn_new(&n, 0, 1);
    int rc = s.x ? xconn_dial(s.x, 3) : -1;
    int pfd = accept(l, NULL, NULL);
    unsigned char b[128];
    if (pfd >= 0) peer_drain(pfd, b, sizeof b, 30);
    check("no scratch: shared link dialled", 0, rc);
    check("no scratch: adopt ran", 1, s.x && nsx_run(nsx_adopt, &s));
    check("no scratch: adopt asks for one scratch block", 1, s.tries);
    check("no scratch: adopt fails with H2_EIO", H2_EIO, s.rc);
    check("no scratch: adopt leaves the link dead", XC_DEAD, s.state);
    check("no scratch: adopt keeps the error", H2_EIO, s.xrc);
    long eof = -1;
    if (pfd >= 0) {
        struct timeval tv = { .tv_sec = 2 };
        setsockopt(pfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        eof = (long)recv(pfd, b, sizeof b, 0);
        close(pfd);
    }
    check("no scratch: the peer sees the link closed", 0, eof);
    close(l);
}

struct nsl { struct xconn *x; struct xs *s; int rc, state, xrc, tries; };

static void *nsl_seal(void *a) {
    struct nsl *s = a;
    nsx_fail();
    s->rc = xs_open(s->x, &RQ_GET, 1, s->s);
    g_cfail = 0;
    s->tries = g_cfail_tries;
    s->state = s->x->state;
    s->xrc = s->x->rc;
    return NULL;
}

static void *nsl_read_one(void *a) {
    struct nsl *s = a;
    unsigned char b[64];
    size_t got = 0;
    nsx_fail();
    s->rc = xs_read(s->s, b, sizeof b, &got);
    g_cfail = 0;
    s->tries = g_cfail_tries;
    s->state = s->x->state;
    s->xrc = s->x->rc;
    return NULL;
}

static void *nsl_read_pass(void *a) {
    struct nsl *s = a;
    nsx_fail();
    s->rc = xconn_io(s->x, EPOLLIN, 0);
    g_cfail = 0;
    s->tries = g_cfail_tries;
    s->state = s->x->state;
    s->xrc = s->x->rc;
    return NULL;
}

static int nsl_run(void *(*f)(void *), struct nsl *s) {
    pthread_t th;
    if (pthread_create(&th, NULL, f, s)) return 0;
    pthread_join(th, NULL);
    return 1;
}

/* catches: a TLS record sealed through a NULL scratch, or the failure swallowed so the stream opens */
static void t_xconn_seal_no_scratch(void) {
    struct tp p;
    tp_start(&p, "h2");
    struct tr_node n = tls_node(g_port);
    struct xconn *x = xconn_new(&n, 0, 0);
    struct xs st;
    check("seal no scratch: dial", 0, x ? xconn_dial(x, 3) : -1);
    check("seal no scratch: peer", 0, tp_finish(&p));
    struct nsl s = { x, &st, 1, 0, 0, 0 };
    check("seal no scratch: thread ran", 1, x && nsl_run(nsl_seal, &s));
    check("seal no scratch: one scratch block asked for", 1, s.tries);
    check("seal no scratch: open fails with H2_EIO", H2_EIO, s.rc);
    check("seal no scratch: the link is dead", XC_DEAD, s.state);
    check("seal no scratch: with H2_EIO", H2_EIO, s.xrc);
    if (x) xconn_free(x);
    tp_free(&p);
}

/* catches: a private link's read through a NULL scratch, or the failure swallowed so the reader waits on */
static void t_xconn_read_one_no_scratch(void) {
    struct pl p;
    check("read_one no scratch: private link", 0, open_plain(&p, 0, 0, 0, 0));
    struct xs st;
    check("read_one no scratch: stream", 0, p.x ? xs_open(p.x, &RQ_GET, 1, &st) : -1);
    struct nsl s = { p.x, &st, 1, 0, 0, 0 };
    check("read_one no scratch: thread ran", 1, p.x && nsl_run(nsl_read_one, &s));
    check("read_one no scratch: one scratch block asked for", 1, s.tries);
    check("read_one no scratch: the read fails with H2_EIO", H2_EIO, s.rc);
    check("read_one no scratch: the link is dead", XC_DEAD, s.state);
    check("read_one no scratch: with H2_EIO", H2_EIO, s.xrc);
    close_plain(&p);
}

/* catches: a shared link's read pass through a NULL scratch, or the failure swallowed so the link stays live */
static void t_xconn_read_pass_no_scratch(void) {
    struct pl p;
    check("read_pass no scratch: shared link", 0, open_plain(&p, 1, 0, 0, 0));
    struct nsl s = { p.x, NULL, 1, 0, 0, 0 };
    check("read_pass no scratch: thread ran", 1, p.x && nsl_run(nsl_read_pass, &s));
    check("read_pass no scratch: one scratch block asked for", 1, s.tries);
    check("read_pass no scratch: io fails with H2_EIO", H2_EIO, s.rc);
    check("read_pass no scratch: the link is dead", XC_DEAD, s.state);
    check("read_pass no scratch: with H2_EIO", H2_EIO, s.xrc);
    close_plain(&p);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    xc_set_host(&HOST);
    if (xc_x25519_keypair(g_rs_priv, g_rs_pub) != 0) return 1;
    b64url(g_rs_pub, 32, g_pbk);

    t_seal_is_write();
    t_ramp_small_records();
    t_ramp_one_write();
    t_ramp_across_writes();
    t_ramp_zero_write();
    t_ramp_after_handshake();
    t_seal_room_ramp();
    t_dial_preface();
    t_alpn_any();
    t_pend_one_frame();
    t_pend_flush_write_fails();
    t_cancel_ping_ceiling();
    t_send_never_blocks();
    t_room_sum_fits();
    t_post_room_no_share();
    t_q_skip_across_chunks();
    t_granted_room_is_accepted();
    t_room_wakes_below_low();
    t_link_end_wakes_starved();
    t_control_ignores_high_water();
    t_control_flood_closes();
    t_control_flood_tls();
    t_control_ceiling_counts_records();
    t_staging_per_link();
    t_records_alone();
    t_ramp_units();
    t_ramp_counts_control();
    t_ramp_once_per_link();
    t_stage_over_limit();
    t_flush_keeps_unit();
    t_slow_stream_does_not_stop_fast();
    t_stream_credit_on_consumption();
    t_credit_go_reads();
    t_nowner_credit();
    t_nowner_freed_on_fail();
    t_close_refund_open();
    t_close_refund_ended();
    t_close_refund_nowner();
    t_dead_link_no_refund();
    t_discard_close_credit();
    t_nowner_discard_gate();
    t_credit_held_while_blocked();
    t_keepalive();
    t_idle_close();
    t_orphan_post_times_out();
    t_orphan_answered_open();
    t_fail_fans_out();
    t_goaway_above_resets();
    t_goaway_error_code();
    t_close_maps_rst();
    t_private_reads_on_demand();
    t_private_driver();
    t_wake_dedup();
    t_status_refusal();
    t_window_wakes();
    t_private_writes_at_once();
    t_private_thread_keeps_no_chunks();
    t_get_closed_early();
    t_chunk_boundary_pay();
    t_two_flushes_one_turn();
    t_overshoot_held_then_sent();
    t_coalesced_credit_over_ceiling();
    t_room_counts_held();
    t_headroom_from_a_pool();
    t_held_keeps_order_and_end();
    t_held_flush_rotates();
    t_held_bounded();
    t_room_within_held_limit();
    t_private_overshoot_refused();
    t_fail_drops_held();
    t_soft_withholds_holders();
    t_release_on_close();
    t_hard_ceiling_pauses();
    t_ceiling_reader_paused();
    t_resume_with_stalled_holders();
    t_ceiling_stall_reset();
    t_pause_stream_ends();
    t_pause_link_dies();
    t_pause_no_keepalive();
    t_pause_count_cleared();
    t_stall_clock_restarts();
    t_paused_hangup_fails();
    t_dead_pause_uncounted();
    t_pause_holds_ping_clock();
    t_private_read_no_progress();
    t_dead_read_progress_now();
    t_stall_steps();
    t_episode_read_between_ticks();
    t_storm_bound();
    t_stall_with_reader_elsewhere();
    t_stall_holder_fills_late();
    t_fm_x55_xconn_plain();
    t_fm_x55_xconn_tls();
    t_ccs_fin_one_write();
    t_frag_ccs_count();
    t_xconn_gap();
    t_xconn_gap_read_flush();
    t_xconn_gap_empty();
    t_xconn_gap_shared();
    t_transport_due();
    t_xconn_piece_cost();
    t_handshake_no_memory();
    t_xconn_adopt_no_scratch();
    t_xconn_seal_no_scratch();
    t_xconn_read_one_no_scratch();
    t_xconn_read_pass_no_scratch();

    printf("\nxconnmatch: %s (%d failed)\n", fails ? "FAIL" : "ok", fails);
    return fails ? 1 : 0;
}
