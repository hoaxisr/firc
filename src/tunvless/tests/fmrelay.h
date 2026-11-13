#ifndef TUNVLESS_FMRELAY_H
#define TUNVLESS_FMRELAY_H
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <sys/socket.h>
#include "fmlink.h"
#include "transport.h"
#include "sdpeer.h"

enum { FMR_SD_PLAIN, FMR_SD_PAD, FMR_SD_DRIP };

static const struct sd_set *g_fmr_sd;
static int g_fmr_mode;
static int g_fmr_slow;

struct fmrelay {
    int fd[2], lfd;
    uint16_t to;
    int off[2];
    long n[2];
    int on;
    pthread_t th;
    const struct sd_set *sd;
    int sd_mode, sd_go, sd_padded, slow;
};

static uint64_t fmr_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

static int fmr_put(int fd, const unsigned char *b, size_t n) {
    while (n) {
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

static unsigned char fmr_pad(const struct sd_set *s) {
    for (size_t i = 0; i < s->lay[0].pool_n; i++)
        if (s->lay[0].pool[i] != s->lay[0].marker) return s->lay[0].pool[i];
    return 0;
}

static int fmr_drained(int fd, uint64_t dl) {
    for (;;) {
        int q = 0;
        if (ioctl(fd, SIOCOUTQ, &q)) return -1;
        if (!q) return 0;
        struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&p, 1, 0) > 0 && (p.revents & POLLIN)) return 0;
        if (fmr_ms() >= dl) return -1;
        sched_yield();
    }
}

static int fmr_sd_put(struct fmrelay *r, int fd, const unsigned char *w, size_t n, uint64_t dl) {
    unsigned char pad = fmr_pad(r->sd);
    int m = __atomic_load_n(&r->sd_mode, __ATOMIC_SEQ_CST);
    if (m == FMR_SD_PAD) {
        __atomic_store_n(&r->sd_mode, FMR_SD_PLAIN, __ATOMIC_SEQ_CST);
        if (fmr_put(fd, &pad, 1)) return -1;
        __atomic_store_n(&r->sd_padded, 1, __ATOMIC_SEQ_CST);
        while (!__atomic_load_n(&r->sd_go, __ATOMIC_SEQ_CST) && fmr_ms() < dl) poll(NULL, 0, 1);
        return fmr_put(fd, w, n);
    }
    if (m != FMR_SD_DRIP) return fmr_put(fd, w, n);
    for (size_t i = 0; i < n; i++)
        if (fmr_put(fd, w + i, 1) || fmr_drained(fd, dl) || fmr_put(fd, &pad, 1) || fmr_drained(fd, dl)) return -1;
    return 0;
}

static void fmr_loop(struct fmrelay *r) {
    int open[2] = { 1, 1 };
    uint64_t dl = fmr_ms() + 20000;
    static __thread unsigned char b[65536];
    struct tdec dec;
    memset(&dec, 0, sizeof dec);
    struct tpk pk = { r->sd, 0, 0, 1 };
    unsigned char *w = NULL;
    if (r->sd && (tdec_init(&dec, r->sd) || !(w = malloc(2 * sizeof b + 16)))) {
        tdec_free(&dec);
        open[0] = open[1] = 0;
    }
    while ((open[0] || open[1]) && fmr_ms() < dl) {
        struct pollfd p[2];
        for (int i = 0; i < 2; i++) {
            p[i].fd = open[i] ? r->fd[i] : -1;
            p[i].events = POLLIN;
            p[i].revents = 0;
        }
        if (poll(p, 2, 100) <= 0) continue;
        for (int i = 0; i < 2; i++) {
            if (!open[i] || !(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t got = recv(r->fd[i], b, r->slow && !i ? 4096 : sizeof b, 0);
            if (got <= 0) {
                open[i] = 0;
                shutdown(r->fd[1 - i], SHUT_WR);
                continue;
            }
            int bad;
            __atomic_add_fetch(&r->n[i], (long)got, __ATOMIC_SEQ_CST);
            if (r->sd && !i) {
                size_t k = tdec_run(&dec, b, (size_t)got, w);
                bad = dec.bad || fmr_put(r->fd[1], w, k);
            } else if (r->sd) {
                bad = fmr_sd_put(r, r->fd[0], w, tpk_pack(&pk, b, (size_t)got, w), dl);
            } else {
                if (!__atomic_load_n(&r->off[i], __ATOMIC_SEQ_CST))
                    for (ssize_t k = 0; k < got; k++) b[k] ^= 0x55;
                bad = fmr_put(r->fd[1 - i], b, (size_t)got);
            }
            if (bad) {
                open[i] = 0;
                shutdown(r->fd[i], SHUT_RD);
            }
            if (r->sd && !i && dec.bad) {
                shutdown(r->fd[0], SHUT_WR);
                shutdown(r->fd[1], SHUT_WR);
            }
            if (r->slow && !i) poll(NULL, 0, 1);
        }
    }
    if (r->sd) tdec_free(&dec);
    free(w);
    close(r->fd[0]);
    close(r->fd[1]);
}

static void *fmr_run(void *a) {
    fmr_loop(a);
    return NULL;
}

static void *fmr_listen_run(void *a) {
    struct fmrelay *r = a;
    struct pollfd p = { .fd = r->lfd, .events = POLLIN };
    int ok = poll(&p, 1, 5000) == 1;
    r->fd[0] = ok ? accept(r->lfd, NULL, NULL) : -1;
    close(r->lfd);
    if (r->fd[0] < 0) return NULL;
    r->fd[1] = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(r->to),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (r->fd[1] < 0 || connect(r->fd[1], (struct sockaddr *)&to, sizeof to)) {
        close(r->fd[0]);
        if (r->fd[1] >= 0) close(r->fd[1]);
        return NULL;
    }
    fmr_loop(r);
    return NULL;
}

static int fmrelay_wrap(struct fmrelay *r, int server_fd) {
    int q[2];
    memset(r, 0, sizeof *r);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, q)) return -1;
    r->fd[0] = q[1];
    r->fd[1] = server_fd;
    r->sd = g_fmr_sd;
    r->sd_mode = g_fmr_mode;
    r->slow = g_fmr_slow;
    if (pthread_create(&r->th, NULL, fmr_run, r)) {
        close(q[0]);
        close(q[1]);
        return -1;
    }
    r->on = 1;
    return q[0];
}

static int fmrelay_listen(struct fmrelay *r, int lfd, uint16_t to_port) {
    memset(r, 0, sizeof *r);
    r->lfd = lfd;
    r->to = to_port;
    r->sd = g_fmr_sd;
    r->sd_mode = g_fmr_mode;
    r->slow = g_fmr_slow;
    if (pthread_create(&r->th, NULL, fmr_listen_run, r)) return -1;
    r->on = 1;
    return 0;
}

static const struct sd_set *fmr_sd_of(const char *json) {
    const struct fm_cfg *cf = fm_cfg_get(json);
    return cf && cf->n == 1 && cf->m[0].kind == FM_SUDOKU ? sd_tables(&cf->m[0].u.sd) : NULL;
}

static void fmrelay_sd(struct fmrelay *r, int mode) {
    __atomic_store_n(&r->sd_go, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&r->sd_padded, 0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&r->sd_mode, mode, __ATOMIC_SEQ_CST);
}

static void fmrelay_go(struct fmrelay *r) {
    __atomic_store_n(&r->sd_go, 1, __ATOMIC_SEQ_CST);
}

static void fmrelay_off(struct fmrelay *r, int dir) {
    __atomic_store_n(&r->off[dir], 1, __ATOMIC_SEQ_CST);
}

static void fmrelay_join(struct fmrelay *r) {
    if (r->on) pthread_join(r->th, NULL);
    r->on = 0;
}

struct fmt_st { unsigned char held[16]; size_t nheld; };

static int fmt_x55_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    unsigned char *b = malloc(n ? n : 1);
    if (!b) return -1;
    for (size_t i = 0; i < n; i++) b[i] = d[i] ^ 0x55;
    int rc = emit(arg, b, n, 0);
    free(b);
    return rc;
}

static long fmt_x55_rd(struct fm_layer *me, unsigned char *d, size_t n, size_t cap) {
    (void)me; (void)cap;
    for (size_t i = 0; i < n; i++) d[i] ^= 0x55;
    return (long)n;
}

static size_t g_fmt_rec_n[64];
static unsigned char g_fmt_rec_head[64][8];
static size_t g_fmt_rec_k;

static int fmt_rec_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    if (g_fmt_rec_k < 64) {
        g_fmt_rec_n[g_fmt_rec_k] = n;
        memcpy(g_fmt_rec_head[g_fmt_rec_k], d, n < 8 ? n : 8);
        g_fmt_rec_k++;
    }
    return emit(arg, d, n, 0);
}

static long fmt_hold_rd(struct fm_layer *me, unsigned char *d, size_t n, size_t cap) {
    struct fmt_st *s = me->st;
    if (!n) {
        if (!s->nheld || cap < 1) return 0;
        d[0] = s->held[0];
        s->nheld = 0;
        return 1;
    }
    unsigned char last = d[n - 1];
    size_t out = n - 1;
    if (s->nheld) {
        memmove(d + 1, d, n - 1);
        d[0] = s->held[0];
        out = n;
    }
    s->held[0] = last;
    s->nheld = 1;
    return (long)out;
}

static int fmt_hold_pending(const struct fm_layer *me) {
    const struct fmt_st *s = me->st;
    return s->nheld > 0;
}

static long fmt_bad_rd(struct fm_layer *me, unsigned char *d, size_t n, size_t cap) {
    (void)me; (void)d; (void)n; (void)cap;
    return -1;
}

static const char *fmt_bad_why(const struct fm_layer *me) {
    (void)me;
    return "test: bad read";
}

static const struct fm_ops FMT_X55 = { .splice = 1, .wr = fmt_x55_wr, .rd = fmt_x55_rd };
static const struct fm_ops FMT_X55_NOSPLICE = { .splice = 0, .wr = fmt_x55_wr, .rd = fmt_x55_rd };
static const struct fm_ops FMT_REC = { .splice = 1, .wr = fmt_rec_wr };
static const struct fm_ops FMT_HOLD = { .splice = 1, .st_size = sizeof(struct fmt_st), .rd = fmt_hold_rd,
                                        .pending = fmt_hold_pending };

static int fmt_hs_fail(struct fm_layer *me, int fd) {
    (void)me; (void)fd;
    return TR_EMASK;
}

static const struct fm_ops FMT_HSFAIL = { .splice = 1, .hs = fmt_hs_fail, .why = fmt_bad_why };
static const struct fm_ops FMT_BAD = { .splice = 1, .rd = fmt_bad_rd, .why = fmt_bad_why };

static int fmt_gap_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    for (size_t off = 0; off < n; off += 100) {
        int rc = emit(arg, d + off, n - off < 100 ? n - off : 100, 30);
        if (rc) return rc;
    }
    return 0;
}

static int fmt_gapz_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    int rc = emit(arg, d, n, 0);
    return rc ? rc : emit(arg, d, 0, 30);
}

static int fmt_eat_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me; (void)d; (void)n; (void)emit; (void)arg;
    return 0;
}

static int64_t g_fmt_one_gap;

static int fmt_one_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    for (size_t i = 0; i < n; i++) {
        int rc = emit(arg, d + i, 1, g_fmt_one_gap);
        if (rc) return rc;
    }
    return 0;
}

static const struct fm_ops FMT_ONE = { .splice = 1, .wr = fmt_one_wr };
static const struct fm_ops FMT_GAP = { .splice = 1, .wr = fmt_gap_wr };
static const struct fm_ops FMT_GAPZ = { .splice = 1, .wr = fmt_gapz_wr };
static const struct fm_ops FMT_EAT = { .splice = 1, .wr = fmt_eat_wr };

static const struct fm_ops *g_fmt_ops;
static const struct fm_mask g_fmt_mask;

static struct fm_link *fmt_new(const struct tr_node *n) {
    (void)n;
    const struct fm_ops *o[1] = { g_fmt_ops };
    const struct fm_mask *m[1] = { &g_fmt_mask };
    return fm_link_new_ops(o, m, 1);
}

#endif
