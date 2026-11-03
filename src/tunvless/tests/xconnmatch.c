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

ssize_t __real_send(int fd, const void *b, size_t n, int fl);
static long g_send_ok, g_send_again;

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

static int tp_start(struct tp *p, const char *alpn) {
    memset(p, 0, sizeof *p);
    p->pl.name = "xconn";
    p->pl.reality_ok = 1;
    p->pl.alpn = alpn;
    p->s.plan = &p->pl;
    p->s.fd = -1;
    p->lfd = listen_lo(0);
    if (p->lfd < 0) return -1;
    return pthread_create(&p->th, NULL, tp_run, p);
}

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

static const unsigned char PREFACE58[58] = {
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n', '\r', '\n',
    'S', 'M', '\r', '\n', '\r', '\n',
    0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0f, 0x00, 0x01,
};

static size_t dial_on(struct xconn *x, int l, int *pfd) {
    int rc = xconn_dial(x, 3);
    if (!rc) rc = xconn_adopt(x, 0);
    *pfd = accept(l, NULL, NULL);
    close(l);
    unsigned char b[256];
    size_t n = peer_drain(*pfd, b, sizeof b, 30);
    if (rc) return 2000;
    if (n == 58 && memcmp(b, PREFACE58, 58)) return 1000;
    if (n == 45 && memcmp(b, PREFACE58, 45)) return 1001;
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
    check("dial: 58 preface bytes", 58, (long)got);
    check("dial: preface by RFC 9113", 0, got == 58 ? memcmp(b, PREFACE58, 58) : -1);
    xconn_free(x);
    check("dial: nothing after the preface", 0, (long)peer_drain(pfd, b, sizeof b, 30));
    close(pfd);

    struct tp p;
    tp_start(&p, "http/1.1");
    n = tls_node(g_port);
    x = xconn_new(&n, 0, 1);
    check("dial: ALPN http/1.1 refused", TR_ENOH2, xconn_dial(x, 3));
    check("dial: link dead", XC_DEAD, x->state);
    pthread_join(p.th, NULL);
    close(p.lfd);
    p.lfd = -1;
    xconn_free(x);
    tp_free(&p);
    check("dial: descriptors back to the start", fd0, fd_count());
}

/* catches: receive memory unbounded with many links, or today's preface lost for the first four */
static void t_preface_past_budget(void) {
    xc_budget_set(4u << 20);
    struct xconn *x[6];
    int l[6], pfd[6];
    for (int i = 0; i < 5; i++) {
        l[i] = listen_lo(0);
        struct tr_node n = plain_node(g_port);
        x[i] = xconn_new(&n, 0, 1);
    }
    static const long want[5] = { 58, 58, 58, 58, 45 };
    for (int i = 0; i < 5; i++) {
        char what[64];
        snprintf(what, sizeof what, "budget: link %d preface bytes", i + 1);
        check(what, want[i], (long)dial_on(x[i], l[i], &pfd[i]));
    }
    xconn_free(x[0]);
    close(pfd[0]);
    l[5] = listen_lo(0);
    struct tr_node n = plain_node(g_port);
    x[5] = xconn_new(&n, 0, 1);
    check("budget: sixth after the first freed sends 58", 58, (long)dial_on(x[5], l[5], &pfd[5]));
    for (int i = 1; i < 6; i++) {
        xconn_free(x[i]);
        close(pfd[i]);
    }
    xc_budget_set(XC_RX_BUDGET);
}

/* catches: a discard link made past the budget keeping the base of a link without a preface credit */
static void t_discard_past_budget(void) {
    xc_budget_set(0);
    int l = listen_lo(0), pfd = -1;
    struct tr_node n = plain_node(g_port);
    struct xconn *x = xconn_new(&n, 0, 1);
    check("discard past budget: made without the credit", 65535, (long)x->base);
    xconn_discard(x);
    check("discard past budget: base back to 0", 0, (long)x->base);
    check("discard past budget: full preface", 58, (long)dial_on(x, l, &pfd));
    check("discard past budget: connection window 1 MiB", 1048576, (long)x->h2.recv_win_conn);
    xconn_free(x);
    close(pfd);
    xc_budget_set(XC_RX_BUDGET);
}

/* catches: a new link's preface credit admitted against outstanding credit only, ignoring bytes held unread */
static void t_preface_counts_held(void) {
    xc_budget_set(2u << 20);
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    check("held preface: first link credited", 58, (long)p.pre_n);
    struct xs a;
    xs_open(p.x, &RQ_GET, 1, &a);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    unsigned char *buf = malloc(32 * (9 + 16384) + 16);
    size_t m = frame(buf, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    for (int i = 0; i < 32; i++) m += frame(buf + m, 16384, FR_DATA, 0, 1, NULL);
    struct bg g;
    bg_start(&g, p.pfd, buf, m);
    for (int i = 0; i < 200 && p.x->held_n < 524288; i++) {
        struct pollfd q = { .fd = p.x->link.fd, .events = POLLIN };
        if (poll(&q, 1, 30) <= 0) continue;
        xconn_io(p.x, EPOLLIN, 0);
    }
    pthread_join(g.th, NULL);
    check("held preface: 524288 held unread", 524288, (long)p.x->held_n);
    int l = listen_lo(0), pfd = -1;
    struct tr_node n = plain_node(g_port);
    struct xconn *b = xconn_new(&n, 0, 1);
    check("held preface: 524288 held + 1048576 out + 1048576 past 2 MiB, no credit", 45,
          (long)dial_on(b, l, &pfd));
    int end;
    check("held preface: the held bytes read", 524288, (long)read_all_of(&a, NULL, 0, &end));
    l = listen_lo(0);
    int cfd = -1;
    n = plain_node(g_port);
    struct xconn *c = xconn_new(&n, 0, 1);
    check("held preface: 0 held + 1048576 out + 1048576 fits 2 MiB exactly", 58, (long)dial_on(c, l, &cfd));
    xconn_free(c);
    close(cfd);
    xconn_free(b);
    close(pfd);
    xs_close(&a);
    free(buf);
    close_plain(&p);
    xc_budget_set(XC_RX_BUDGET);
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
    check("never blocks: room at the floor", XC_MSS, xs_room(&s));
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

static void t_new_room_counts_flows(void) {
    struct pl p;
    check("flows room: link", 0, open_plain(&p, 1, 0, 0, 0));
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
    /* catches: a flow's streams each counted as an uploader in the room of a new stream */
    check("flows room: a third flow gets 262144/3", 87381, xc_room_new(p.x, 3));
    check("flows room: the two-stream flow gets 262144/2", 131072, xc_room_new(p.x, 1));
    close_plain(&p);
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
    int refused = 0, zero = 0;
    for (int k = 0; k < 20; k++) {
        long level = (long)k * 300000 / 19;
        long need = level - (long)xc_queued();
        while (need > 0) {
            long m = need > (long)sizeof g_big ? (long)sizeof g_big : need;
            xs_send(&sb, g_big, (size_t)m, 0);
            need -= m;
        }
        long r = xs_room(&sa);
        if (r <= 0) zero++;
        else if (xs_send(&sa, g_big, (size_t)r, 0) != 0) refused++;
    }
    check("granted: no room refused at 20 queue levels", 0, refused);
    check("granted: room never 0 with open windows", 0, zero);
    check("granted: c sends to a 1000-byte window", 0, xs_send(&sc, g_big, 64535, 0));
    check("granted: c connection window", 1000, h2m_conn_room(&c.x->h2));
    long r = xs_room(&sc);
    check("granted: room capped by the window", 1000, r);
    check("granted: window room accepted", 0, xs_send(&sc, g_big, (size_t)r, 0));
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
    check("low: room A at the floor", XC_MSS, xs_room(&s[0]));
    check("low: room B at the floor", XC_MSS, xs_room(&s[1]));
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
    p.x->q_ctl = XC_CTL_MAX - 4;
    p.x->disc = 1u << 20;
    xconn_flush(p.x);
    check("ceiling: the link is dead in the same pass", XC_DEAD, p.x->state);
    close_plain(&p);
}

static int tls_link(struct tp *p, struct xconn **x) {
    if (tp_start(p, "h2")) return -1;
    struct tr_node n = tls_node(g_port);
    *x = xconn_new(&n, 0, 1);
    int rc = xconn_dial(*x, 3);
    if (tp_finish(p)) return rc ? rc : -2;
    return rc;
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
        check("staging: preface record holds the preface", 58, (long)n);
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

/* catches: backpressure by not reading the shared socket */
static void t_slow_stream_does_not_stop_fast(void) {
    xc_budget_set(4u << 20);
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    struct xs a, b;
    xs_open(p.x, &RQ_GET, 1, &a);
    xs_open(p.x, &RQ_GET, 2, &b);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    unsigned char *buf = malloc(64 * (9 + 16384) + 64);
    size_t m = 0;
    m += frame(buf + m, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    m += frame(buf + m, 1, FR_HEADERS, FLAG_END_HEADERS, 3, ST200);
    static unsigned char fa[16384], fb[16384];
    memset(fa, 'a', sizeof fa);
    memset(fb, 'b', sizeof fb);
    for (int i = 0; i < 32; i++) {
        m += frame(buf + m, 16384, FR_DATA, 0, 1, fa);
        m += frame(buf + m, 16384, FR_DATA, 0, 3, fb);
    }
    struct bg g;
    bg_start(&g, p.pfd, buf, m);
    size_t bgot = 0;
    int bad = 0, rc = 0;
    uint64_t dl = mono_us() + 10000000;
    while (mono_us() < dl && bgot < 524288) {
        struct pollfd q = { .fd = p.x->link.fd, .events = POLLIN };
        if (poll(&q, 1, 50) > 0) rc |= xconn_io(p.x, EPOLLIN, 0);
        xconn_flush(p.x);
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
    check("slow: B read all 524288", 524288, (long)bgot);
    check("slow: B bytes are B's", 0, bad);
    check("slow: the socket was read to empty", 0, fd_pending(p.x->link.fd));
    int end;
    check("slow: A held all 524288", 524288, (long)read_all_of(&a, NULL, 0, &end));
    free(buf);
    close_plain(&p);
}

/* catches: connection credit past the budget, or none under it */
static void t_budget_exact(void) {
    xc_budget_set(1179648);
    struct pl p;
    open_plain(&p, 1, 0, 0, 0);
    check("budget exact: full preface", 58, (long)p.pre_n);
    struct xs a;
    xs_open(p.x, &RQ_GET, 1, &a);
    xconn_flush(p.x);
    peer_drain(p.pfd, g_pb, sizeof g_pb, 10);
    unsigned char *buf = malloc(16 * (9 + 16384) + 16);
    size_t m = frame(buf, 1, FR_HEADERS, FLAG_END_HEADERS, 1, ST200);
    for (int i = 0; i < 16; i++) m += frame(buf + m, 16384, FR_DATA, 0, 1, NULL);
    struct bg g;
    bg_start(&g, p.pfd, buf, m);
    for (int i = 0; i < 200; i++) {
        struct pollfd q = { .fd = p.x->link.fd, .events = POLLIN };
        if (poll(&q, 1, 30) <= 0) break;
        xconn_io(p.x, EPOLLIN, 0);
    }
    pthread_join(g.th, NULL);
    xconn_io(p.x, EPOLLIN, 0);
    xconn_flush(p.x);
    int k = peer_frames(p.pfd, 20);
    int nf = 0;
    uint32_t mn = 0;
    check("budget exact: connection credit sums to 131072", 131072, wu_sum(k, 0, &nf, &mn));
    check("budget exact: in 4 updates", 4, nf);
    check("budget exact: of 32768 each", 32768, (long)mn);
    check("budget exact: no stream credit before reading", 0, count_type(k, FR_WINDOW_UPDATE, 1));
    size_t got = 0;
    check("budget exact: read 65536", 0, xs_read(&a, g_big, 65536, &got));
    check("budget exact: got 65536", 65536, (long)got);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("budget exact: two frames", 2, k);
    check("budget exact: stream credit 65536", 65536, wu_sum(k, 1, NULL, NULL));
    check("budget exact: connection credit 65536", 65536, wu_sum(k, 0, NULL, NULL));
    check("budget exact: stream credit first", 1, k == 2 ? (long)g_fv[0].sid : -1);
    free(buf);
    close_plain(&p);
    xc_budget_set(XC_RX_BUDGET);
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
    check("consumption: no stream credit on arrival", 0, count_type(k, FR_WINDOW_UPDATE, 1));
    size_t got = 0;
    xs_read(&a, g_big, sizeof g_big, &got);
    check("consumption: 40000 read", 40000, (long)got);
    xconn_flush(p.x);
    k = peer_frames(p.pfd, 20);
    check("consumption: stream credit 40000", 40000, wu_sum(k, 1, NULL, NULL));
    close_plain(&p);
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
    check("orphan: RST_STREAM CANCEL on both", 26, (long)n);
    check("orphan: bytes", 0, n == 26 ? memcmp(b, want, 26) : -1);
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
    xc_budget_set(0);
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
    int k = 0, found0 = 0, found1 = 0;
    usleep(20000);
    while (fd_pending(p.s.fd) > 0 && !rec_open(p.cd, p.s.fd, g_rec, sizeof g_rec, &rn, &inner)) {
        struct fv f[16];
        k = parse(g_rec, rn, f, 16);
        for (int i = 0; i < k; i++)
            if (f[i].type == FR_WINDOW_UPDATE && f[i].len == 4) {
                if (f[i].sid == 0) found0 = (int)be32(f[i].p);
                if (f[i].sid == 1) found1 = (int)be32(f[i].p);
            }
    }
    check("private: connection credit on arrival, outside the budget", 36000, found0);
    check("private: stream credit on consumption", 36000, found1);
    xs_close(&s);
    xconn_free(x);
    tp_free(&p);
    xc_budget_set(XC_RX_BUDGET);
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
    check("early GET: RST_STREAM CANCEL at once", 13, (long)n);
    check("early GET: RST bytes", 0, n == 13 ? memcmp(b, rst1, 13) : -1);
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
    check("count held: room of a new stream, (10000 - 3000) / 2", 3500, xc_room_new(p.x, 66));
    xs_close(&t);
    check("count held: past the window, 8000 more", 0, xs_send(&s, g_big, 8000, 0));
    check("count held: 11000 held against a 10000 window", 11000, (long)p.x->pend_n);
    check("count held: no room for a new stream while held bytes cover the window", 0, xc_room_new(p.x, 66));
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

static void feed_link(struct pl *p, uint32_t sid, size_t total) {
    size_t frames = total / 16384;
    unsigned char *buf = malloc(frames * (9 + 16384) + 16);
    size_t m = frame(buf, 1, FR_HEADERS, FLAG_END_HEADERS, sid, ST200);
    for (size_t i = 0; i < frames; i++) m += frame(buf + m, 16384, FR_DATA, 0, sid, NULL);
    struct bg g;
    bg_start(&g, p->pfd, buf, m);
    for (int i = 0; i < 400; i++) {
        struct pollfd q = { .fd = p->x->link.fd, .events = POLLIN };
        if (poll(&q, 1, 30) <= 0) break;
        xconn_io(p->x, EPOLLIN, 0);
    }
    pthread_join(g.th, NULL);
    xconn_io(p->x, EPOLLIN, 0);
    free(buf);
}

static size_t read_n(struct xs *s, size_t n) {
    size_t got = 0, k = 0;
    while (got < n && !xs_read(s, g_big, n - got < sizeof g_big ? n - got : sizeof g_big, &k) && k) got += k;
    return got;
}

/* catches: the reading link or an arrival paid before a link owed for bytes it read */
static void t_consumed_link_paid_first(void) {
    xc_budget_set((2u << 20) + 65536);
    struct pl a, b;
    open_plain(&a, 1, 0, 0, 0);
    open_plain(&b, 1, 0, 0, 0);
    struct xs sa, sb;
    xs_open(a.x, &RQ_GET, 1, &sa);
    xs_open(b.x, &RQ_GET, 2, &sb);
    xconn_flush(a.x);
    xconn_flush(b.x);
    peer_drain(a.pfd, g_pb, sizeof g_pb, 10);
    peer_drain(b.pfd, g_pb, sizeof g_pb, 10);
    feed_link(&a, 1, 1048576);
    xconn_flush(a.x);
    check("first: A paid on arrival what the budget had, 65536", 65536, wu_sum(peer_frames(a.pfd, 20), 0, NULL, NULL));
    xc_budget_set((1u << 20) + 65536);
    check("first: A read all 1 MiB", 1048576, (long)read_n(&sa, 1048576));
    xconn_flush(a.x);
    check("first: no room left for A's 983040", 0, wu_sum(peer_frames(a.pfd, 20), 0, NULL, NULL));
    feed_link(&b, 1, 65536);
    check("first: B read its 65536", 65536, (long)read_n(&sb, 65536));
    xconn_flush(a.x);
    xconn_flush(b.x);
    check("first: the freed 65536 go to A, which owes for what it read", 65536, wu_sum(peer_frames(a.pfd, 20), 0, NULL, NULL));
    check("first: none to B, which owes less", 0, wu_sum(peer_frames(b.pfd, 20), 0, NULL, NULL));
    xc_budget_set((2u << 20) + 65536);
    feed_link(&b, 1, 65536);
    xconn_flush(a.x);
    xconn_flush(b.x);
    check("first: the budget given back goes to A at B's next arrival", 917504, wu_sum(peer_frames(a.pfd, 20), 0, NULL, NULL));
    check("first: B gets what A leaves, its two 65536", 131072, wu_sum(peer_frames(b.pfd, 20), 0, NULL, NULL));
    xs_close(&sa);
    xs_close(&sb);
    close_plain(&b);
    close_plain(&a);
    xc_budget_set(XC_RX_BUDGET);
}

/* catches: credit by debt or without per-link held bytes, so unread data wins */
static void t_owed_not_debt(void) {
    xc_budget_set((2u << 20) + 65536);
    struct pl a, b;
    open_plain(&a, 1, 0, 0, 0);
    open_plain(&b, 1, 0, 0, 0);
    struct xs sa, sb;
    xs_open(a.x, &RQ_GET, 1, &sa);
    xs_open(b.x, &RQ_GET, 2, &sb);
    xconn_flush(a.x);
    xconn_flush(b.x);
    peer_drain(a.pfd, g_pb, sizeof g_pb, 10);
    peer_drain(b.pfd, g_pb, sizeof g_pb, 10);
    feed_link(&b, 1, 1048576);
    feed_link(&a, 1, 524288);
    xconn_flush(a.x);
    xconn_flush(b.x);
    check("owed: B paid on arrival 65536", 65536, wu_sum(peer_frames(b.pfd, 20), 0, NULL, NULL));
    check("owed: A paid nothing on arrival", 0, wu_sum(peer_frames(a.pfd, 20), 0, NULL, NULL));
    check("owed: A reads 131072", 131072, (long)read_n(&sa, 131072));
    xconn_flush(a.x);
    xconn_flush(b.x);
    check("owed: the 131072 go to A, which read them", 131072, wu_sum(peer_frames(a.pfd, 20), 0, NULL, NULL));
    check("owed: none to B, whose larger debt is unread", 0, wu_sum(peer_frames(b.pfd, 20), 0, NULL, NULL));
    xs_close(&sa);
    xs_close(&sb);
    close_plain(&b);
    close_plain(&a);
    xc_budget_set(XC_RX_BUDGET);
}

/* catches: credit paid to one link per pass while others still owe */
static void t_priority_pays_every_link(void) {
    xc_budget_set((3u << 20) + 524288);
    struct pl a, b, c;
    open_plain(&a, 1, 0, 0, 0);
    struct xs sa, sb, sc;
    xs_open(a.x, &RQ_GET, 1, &sa);
    xconn_flush(a.x);
    peer_drain(a.pfd, g_pb, sizeof g_pb, 10);
    feed_link(&a, 1, 524288);
    open_plain(&b, 1, 0, 0, 0);
    open_plain(&c, 1, 0, 0, 0);
    check("every: B took its preface", 58, (long)b.pre_n);
    check("every: C took its preface", 58, (long)c.pre_n);
    xc_budget_set(3u << 20);
    xs_open(b.x, &RQ_GET, 2, &sb);
    xs_open(c.x, &RQ_GET, 3, &sc);
    xconn_flush(b.x);
    xconn_flush(c.x);
    peer_drain(b.pfd, g_pb, sizeof g_pb, 10);
    peer_drain(c.pfd, g_pb, sizeof g_pb, 10);
    feed_link(&b, 1, 65536);
    feed_link(&c, 1, 65536);
    check("every: B read 65536", 65536, (long)read_n(&sb, 65536));
    check("every: C read 65536", 65536, (long)read_n(&sc, 65536));
    xconn_flush(a.x);
    peer_drain(a.pfd, g_pb, sizeof g_pb, 20);
    check("every: A read its 524288", 524288, (long)read_n(&sa, 524288));
    xconn_flush(b.x);
    xconn_flush(c.x);
    check("every: B paid 65536", 65536, wu_sum(peer_frames(b.pfd, 20), 0, NULL, NULL));
    check("every: C paid 65536", 65536, wu_sum(peer_frames(c.pfd, 20), 0, NULL, NULL));
    xs_close(&sa);
    xs_close(&sb);
    xs_close(&sc);
    close_plain(&c);
    close_plain(&b);
    close_plain(&a);
    xc_budget_set(XC_RX_BUDGET);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    xc_set_host(&HOST);
    if (xc_x25519_keypair(g_rs_priv, g_rs_pub) != 0) return 1;
    b64url(g_rs_pub, 32, g_pbk);

    t_seal_is_write();
    t_dial_preface();
    t_preface_past_budget();
    t_discard_past_budget();
    t_preface_counts_held();
    t_send_never_blocks();
    t_room_sum_fits();
    t_new_room_counts_flows();
    t_granted_room_is_accepted();
    t_room_wakes_below_low();
    t_control_ignores_high_water();
    t_control_flood_closes();
    t_staging_per_link();
    t_slow_stream_does_not_stop_fast();
    t_budget_exact();
    t_stream_credit_on_consumption();
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
    t_consumed_link_paid_first();
    t_owed_not_debt();
    t_priority_pays_every_link();
    t_coalesced_credit_over_ceiling();
    t_room_counts_held();
    t_headroom_from_a_pool();
    t_held_keeps_order_and_end();
    t_held_flush_rotates();
    t_held_bounded();
    t_room_within_held_limit();
    t_private_overshoot_refused();
    t_fail_drops_held();

    printf("\nxconnmatch: %s (%d failed)\n", fails ? "FAIL" : "ok", fails);
    return fails ? 1 : 0;
}
