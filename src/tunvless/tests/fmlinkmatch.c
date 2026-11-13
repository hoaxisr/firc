#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "unit.h"
#include "../src/proto/transport/fmlink.c"
#include "sdpeer.h"
#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/lsan_interface.h>
#endif

static size_t fm_queued(const struct fm_link *l) {
    return l ? l->qd_len : 0;
}

static const char *fm_why(const struct fm_link *l) {
    return l && l->why ? l->why : "";
}

#define TR_EIO_WANT (-33)
#define TR_ECLOSED_WANT (-34)

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void timeo(int fd, int rcv_ms, int snd_ms) {
    struct timeval r = { rcv_ms / 1000, (rcv_ms % 1000) * 1000 }, s = { snd_ms / 1000, (snd_ms % 1000) * 1000 };
    if (rcv_ms) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &r, sizeof r);
    if (snd_ms) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &s, sizeof s);
}

static void seqpair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv)) { perror("socketpair"); exit(2); }
    timeo(sv[0], 1000, 1000);
    timeo(sv[1], 1000, 1000);
}

static struct fm_mask mk(int64_t a, int64_t b) {
    struct fm_mask m;
    memset(&m, 0, sizeof m);
    m.kind = FM_FRAGMENT;
    m.u.frag.split.from = a;
    m.u.frag.split.to = b;
    return m;
}

struct tst { int64_t a, b; unsigned char held[16]; size_t nheld; int bad; };

static int t_init(void *st, const struct fm_mask *m) {
    struct tst *s = st;
    s->a = m->u.frag.split.from;
    s->b = m->u.frag.split.to;
    return 0;
}

static struct { int tag; size_t n; } g_log[64];
static size_t g_nlog;

static int rec_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    struct tst *s = me->st;
    if (g_nlog < 64) { g_log[g_nlog].tag = (int)s->a; g_log[g_nlog].n = n; g_nlog++; }
    return emit(arg, d, n, 0);
}

static int x55_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    unsigned char *b = malloc(n ? n : 1);
    for (size_t i = 0; i < n; i++) b[i] = d[i] ^ 0x55;
    int rc = emit(arg, b, n, 0);
    free(b);
    return rc;
}

static long x55_rd(struct fm_layer *me, unsigned char *d, size_t n, size_t cap) {
    (void)me; (void)cap;
    for (size_t i = 0; i < n; i++) d[i] ^= 0x55;
    return (long)n;
}

static long hold_rd(struct fm_layer *me, unsigned char *d, size_t n, size_t cap) {
    struct tst *s = me->st;
    unsigned char t[4096];
    size_t tot = s->nheld + n;
    if (tot > sizeof t || tot > cap + 1) return -1;
    memcpy(t, s->held, s->nheld);
    memcpy(t + s->nheld, d, n);
    if (n == 0) {
        memcpy(d, t, tot);
        s->nheld = 0;
        return (long)tot;
    }
    if (tot - 1 > cap) return -1;
    memcpy(d, t, tot - 1);
    s->held[0] = t[tot - 1];
    s->nheld = 1;
    return (long)(tot - 1);
}

static int hold_pending(const struct fm_layer *me) {
    const struct tst *s = me->st;
    return s->nheld > 0;
}

static int g_gapn;

static int gap_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    struct tst *s = me->st;
    g_gapn++;
    size_t k = (size_t)s->a;
    for (size_t off = 0; off < n; off += k) {
        int rc = emit(arg, d + off, n - off < k ? n - off : k, s->b);
        if (rc) return rc;
    }
    return 0;
}

static int hsx_hs(struct fm_layer *me, int fd) {
    struct tst *s = me->st;
    unsigned char hello[3] = { 'H', (unsigned char)s->a, 'X' }, r[2];
    int rc = fm_lower_write(me, hello, 3, 0);
    if (rc) return rc;
    rc = fm_lower_read_full(me, fd, r, 2);
    if (rc) return rc;
    s->bad = memcmp(r, "OK", 2) != 0;
    return s->bad ? -1 : 0;
}

static const char *hsx_why(const struct fm_layer *me) {
    const struct tst *s = me->st;
    return s->bad ? "hsx: bad reply" : NULL;
}

static int g_fail;

static int fail_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    struct tst *s = me->st;
    if (g_fail & 1) { s->bad = 1; return -7; }
    return emit(arg, d, n, 0);
}

static long fail_rd(struct fm_layer *me, unsigned char *d, size_t n, size_t cap) {
    struct tst *s = me->st;
    (void)d; (void)cap;
    if (g_fail & 2) { s->bad = 1; return -1; }
    return (long)n;
}

static const char *fail_why(const struct fm_layer *me) {
    const struct tst *s = me->st;
    return s->bad ? "fail: broken" : NULL;
}

static long part_rd(struct fm_layer *me, unsigned char *d, size_t n, size_t cap) {
    struct tst *s = me->st;
    (void)d; (void)cap;
    if (!n) return 0;
    s->nheld = 1;
    return (long)(n - 1);
}

static long grow_rd(struct fm_layer *me, unsigned char *d, size_t n, size_t cap) {
    (void)me; (void)d; (void)n;
    return (long)cap + 1;
}

static struct fm_layer *g_me;

static int stash_hs(struct fm_layer *me, int fd) {
    (void)fd;
    g_me = me;
    return 0;
}

static int alloc_init(void *st, const struct fm_mask *m) {
    (void)m;
    *(void **)st = malloc(100);
    return *(void **)st ? 0 : -1;
}

static void alloc_free(void *st) {
    free(*(void **)st);
}

static const struct fm_ops op_rec = { .splice = 1, .st_size = sizeof(struct tst), .init = t_init, .wr = rec_wr };
static const struct fm_ops op_x55s1 = { .splice = 1, .wr = x55_wr, .rd = x55_rd };
static const struct fm_ops op_x55s0 = { .splice = 0, .wr = x55_wr, .rd = x55_rd };
static const struct fm_ops op_hold = { .splice = 0, .st_size = sizeof(struct tst), .init = t_init, .rd = hold_rd,
                                       .pending = hold_pending };
static const struct fm_ops op_gap = { .splice = 1, .st_size = sizeof(struct tst), .init = t_init, .wr = gap_wr };
static const struct fm_ops op_hsx = { .splice = 1, .st_size = sizeof(struct tst), .init = t_init, .hs = hsx_hs,
                                      .why = hsx_why };

static const struct fm_ops op_fail = { .splice = 0, .st_size = sizeof(struct tst), .init = t_init, .wr = fail_wr,
                                       .rd = fail_rd, .why = fail_why };
static const struct fm_ops op_part = { .splice = 0, .st_size = sizeof(struct tst), .init = t_init, .rd = part_rd,
                                       .pending = hold_pending };
static const struct fm_ops op_grow = { .splice = 0, .rd = grow_rd };
static const struct fm_ops op_stash = { .splice = 1, .hs = stash_hs };
static const struct fm_ops op_alloc = { .splice = 1, .st_size = sizeof(void *), .init = alloc_init, .free = alloc_free };

static struct fm_link *chain(size_t n, const struct fm_ops *const *ops, const struct fm_mask *m) {
    const struct fm_mask *mp[8];
    for (size_t i = 0; i < n; i++) mp[i] = &m[i];
    return fm_link_new_ops(ops, mp, n);
}

static ssize_t peek_msg(int fd, unsigned char *b, size_t cap) {
    return recv(fd, b, cap, MSG_DONTWAIT);
}

struct hspeer { int fd; unsigned char h1[8], h2[8]; ssize_t n1, n2; int early; };

static void *hs_peer(void *p) {
    struct hspeer *h = p;
    unsigned char x[8];
    h->n1 = recv(h->fd, h->h1, sizeof h->h1, 0);
    poll(NULL, 0, 50);
    h->early = recv(h->fd, x, sizeof x, MSG_DONTWAIT) >= 0;
    send(h->fd, "OK", 2, MSG_NOSIGNAL);
    h->n2 = recv(h->fd, h->h2, sizeof h->h2, 0);
    send(h->fd, "OK", 2, MSG_NOSIGNAL);
    return NULL;
}

static void t_chain_order(void) {
    /* catches: the list applied in listed order next to the socket */
    int sv[2];
    seqpair(sv);
    const struct fm_ops *ops[2] = { &op_rec, &op_rec };
    struct fm_mask m[2] = { mk('a', 0), mk('b', 0) };
    struct fm_link *l = chain(2, ops, m);
    check("order: chain built", 1, l != NULL);
    unsigned char d[11] = "0123456789", got[32];
    g_nlog = 0;
    check("order: fm_send 10", 10, (long)fm_send(l, sv[0], d, 10, 0));
    check("order: two writes logged", 2, (long)g_nlog);
    check("order: rec_a first", 'a', g_log[0].tag);
    check("order: rec_a 10 B", 10, (long)g_log[0].n);
    check("order: rec_b second", 'b', g_log[1].tag);
    check("order: rec_b 10 B", 10, (long)g_log[1].n);
    check("order: peer got 10", 10, (long)peek_msg(sv[1], got, sizeof got));
    fm_link_free(l);

    const struct fm_ops *hops[2] = { &op_hsx, &op_hsx };
    struct fm_mask hm[2] = { mk('a', 0), mk('b', 0) };
    l = chain(2, hops, hm);
    struct hspeer h = { .fd = sv[1] };
    pthread_t th;
    pthread_create(&th, NULL, hs_peer, &h);
    check("order: hs ok", 0, fm_link_hs(l, sv[0], 0));
    pthread_join(th, NULL);
    check("order: first hello 3 B", 3, (long)h.n1);
    check_mem("order: first hello is hsx_b's", "HbX", h.h1, 3);
    check("order: no second hello before the answer", 0, h.early);
    check("order: second hello 3 B", 3, (long)h.n2);
    check_mem("order: second hello is hsx_a's", "HaX", h.h2, 3);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_hs_through_lower(void) {
    /* catches: an inner layer's handshake written straight to the socket */
    int sv[2];
    seqpair(sv);
    const struct fm_ops *ops[2] = { &op_hsx, &op_rec };
    struct fm_mask m[2] = { mk('h', 0), mk('r', 0) };
    struct fm_link *l = chain(2, ops, m);
    send(sv[1], "OK", 2, MSG_NOSIGNAL);
    g_nlog = 0;
    check("hs lower: hs ok", 0, fm_link_hs(l, sv[0], 0));
    check("hs lower: fm_send 5", 5, (long)fm_send(l, sv[0], "data!", 5, 0));
    check("hs lower: rec saw two writes", 2, (long)g_nlog);
    check("hs lower: first is the 3 B hello", 3, (long)g_log[0].n);
    check("hs lower: then the 5 B of data", 5, (long)g_log[1].n);
    unsigned char got[16];
    check("hs lower: peer hello", 3, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("hs lower: hello bytes", "HhX", got, 3);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_blocking_gap(void) {
    /* catches: gaps ignored by the blocking writer */
    int sv[2];
    seqpair(sv);
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(10, 20) };
    struct fm_link *l = chain(1, ops, m);
    unsigned char d[30], got[64];
    for (int i = 0; i < 30; i++) d[i] = (unsigned char)i;
    uint64_t t0 = mono_ms();
    check("blocking gap: fm_send 30", 30, (long)fm_send(l, sv[0], d, 30, 0));
    uint64_t el = mono_ms() - t0;
    check("blocking gap: elapsed >= 60 ms", 1, el >= 60);
    check("blocking gap: elapsed <= 1 s", 1, el <= 1000);
    for (int i = 0; i < 3; i++) {
        check("blocking gap: a message of 10", 10, (long)peek_msg(sv[1], got, sizeof got));
        check_mem("blocking gap: its bytes", d + 10 * i, got, 10);
    }
    check("blocking gap: no fourth", -1, (long)peek_msg(sv[1], got, sizeof got));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_loop_queue(void) {
    /* catches: a later write jumping the queue, or a sleep in loop mode */
    int sv[2], nx = 99;
    seqpair(sv);
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(10, 20) };
    struct fm_link *l = chain(1, ops, m);
    fm_set_loop(l, 1);
    unsigned char d[30], got[64];
    for (int i = 0; i < 30; i++) d[i] = (unsigned char)(0x40 + i);
    uint64_t t0 = mono_ms();
    check("loop queue: fm_send 30", 30, (long)fm_send(l, sv[0], d, 30, 0));
    check("loop queue: returned within 5 ms", 1, mono_ms() - t0 < 5);
    check("loop queue: one message out", 10, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("loop queue: first piece", d, got, 10);
    check("loop queue: no second yet", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("loop queue: 20 queued", 20, (long)fm_queued(l));
    check("loop queue: kick at +5", 0, fm_kick(l, sv[0], t0 + 5, &nx));
    check("loop queue: nothing sent at +5", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("loop queue: next_ms in 14..20", 1, nx >= 14 && nx <= 20);
    check("loop queue: kick at +21", 0, fm_kick(l, sv[0], t0 + 21, &nx));
    check("loop queue: second message", 10, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("loop queue: second piece", d + 10, got, 10);
    check("loop queue: no third yet", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("loop queue: next_ms 20", 20, nx);
    check("loop queue: later fm_send 4", 4, (long)fm_send(l, sv[0], "wxyz", 4, 0));
    check("loop queue: the 4 B waits", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("loop queue: 14 queued", 14, (long)fm_queued(l));
    check("loop queue: kick at +42", 0, fm_kick(l, sv[0], t0 + 42, &nx));
    check("loop queue: third message", 10, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("loop queue: third piece", d + 20, got, 10);
    check("loop queue: not the 4 B yet", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("loop queue: kick at +63", 0, fm_kick(l, sv[0], t0 + 63, &nx));
    check("loop queue: the 4 B last", 4, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("loop queue: its bytes", "wxyz", got, 4);
    check("loop queue: next_ms -1 when empty", -1, nx);
    check("loop queue: nothing queued", 0, (long)fm_queued(l));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_kick_stale_now(void) {
    /* catches: the gap after a kicked piece counted from the caller's stale clock, so it comes out short */
    int sv[2], nx = 99;
    seqpair(sv);
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(10, 20) };
    struct fm_link *l = chain(1, ops, m);
    fm_set_loop(l, 1);
    unsigned char d[30], got[64];
    memset(d, 0x61, sizeof d);
    check("stale kick: fm_send 30", 30, (long)fm_send(l, sv[0], d, 30, 0));
    check("stale kick: first piece out", 10, (long)peek_msg(sv[1], got, sizeof got));
    struct timespec ts = { 0, 60 * 1000000L };
    nanosleep(&ts, NULL);
    uint64_t stale = mono_ms() - 20;
    check("stale kick: kick 20 ms behind the clock", 0, fm_kick(l, sv[0], stale, &nx));
    check("stale kick: second piece out", 10, (long)peek_msg(sv[1], got, sizeof got));
    check("stale kick: the next gap is a full 20 ms of real time", 1, nx >= 40);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

#define BIG (4u << 20)

struct drain { int fd; unsigned char *b; size_t got; };

static void *drainer(void *p) {
    struct drain *dr = p;
    while (dr->got < BIG) {
        ssize_t r = recv(dr->fd, dr->b + dr->got, BIG - dr->got, 0);
        if (r <= 0) break;
        dr->got += (size_t)r;
    }
    return NULL;
}

static void t_loop_short_write(void) {
    /* catches: the rest of a short write dropped or sent out of order */
    int ls = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0), nx = 99, small = 32768;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof a;
    setsockopt(ls, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    bind(ls, (struct sockaddr *)&a, sizeof a);
    listen(ls, 1);
    getsockname(ls, (struct sockaddr *)&a, &al);
    setsockopt(c, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    check("short write: connect", 0, connect(c, (struct sockaddr *)&a, sizeof a));
    int s = accept(ls, NULL, NULL);
    timeo(c, 0, 100);
    timeo(s, 5000, 0);
    unsigned char *d = malloc(BIG), *rb = malloc(BIG);
    for (size_t i = 0; i < BIG; i++) d[i] = (unsigned char)(i ^ (i >> 8) ^ (i >> 16));
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(1 << 20, 1) };
    struct fm_link *l = chain(1, ops, m);
    fm_set_loop(l, 1);
    check("short write: fm_send returns 4 MiB", (long)BIG, (long)fm_send(l, c, d, BIG, 0));
    check("short write: the rest is queued", 1, fm_queued(l) > 0);
#if defined(__GLIBC__) && (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 33) && !defined(__SANITIZE_ADDRESS__)
    struct mallinfo2 mb = mallinfo2();
    size_t held_before = mb.uordblks + mb.hblkhd;
#endif
    check("short write: kick on a full buffer", 0, fm_kick(l, c, mono_ms(), &nx));
    check("short write: next_ms 0", 0, nx);
    struct drain dr = { .fd = s, .b = rb };
    pthread_t th;
    pthread_create(&th, NULL, drainer, &dr);
    uint64_t end = mono_ms() + 15000;
    int rc = 0;
    while (fm_queued(l) && mono_ms() < end) {
        rc = fm_kick(l, c, mono_ms(), &nx);
        if (rc) break;
        if (nx > 0) poll(NULL, 0, nx);
    }
    check("short write: kicks ok", 0, rc);
    check("short write: queue drained", 0, (long)fm_queued(l));
#if defined(__GLIBC__) && (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 33) && !defined(__SANITIZE_ADDRESS__)
    struct mallinfo2 mi = mallinfo2();
    check("short write: drained queue memory freed", 1, mi.uordblks + mi.hblkhd < held_before - (2u << 20));
#endif
    shutdown(c, SHUT_WR);
    pthread_join(th, NULL);
    check("short write: peer got 4 MiB", (long)BIG, (long)dr.got);
    check("short write: in order", 0, memcmp(d, rb, BIG));
    fm_link_free(l);
    free(d);
    free(rb);
    close(c);
    close(s);
    close(ls);
}

static void t_gap_through_lower(void) {
    /* catches: a layer's gap lost when the layer below cuts its piece */
    int sv[2], nx = 99;
    seqpair(sv);
    const struct fm_ops *ops[2] = { &op_gap, &op_gap };
    struct fm_mask m[2] = { mk(10, 20), mk(5, 0) };
    unsigned char d[20], got[32];
    for (int i = 0; i < 20; i++) d[i] = (unsigned char)(0x61 + i);
    struct fm_link *l = chain(2, ops, m);
    uint64_t t0 = mono_ms();
    check("gap lower: blocking fm_send 20", 20, (long)fm_send(l, sv[0], d, 20, 0));
    check("gap lower: blocking slept both gaps", 1, mono_ms() - t0 >= 40);
    for (int i = 0; i < 4; i++) {
        check("gap lower: blocking piece of 5", 5, (long)peek_msg(sv[1], got, sizeof got));
        check_mem("gap lower: blocking bytes", d + 5 * i, got, 5);
    }
    fm_link_free(l);
    l = chain(2, ops, m);
    fm_set_loop(l, 1);
    t0 = mono_ms();
    check("gap lower: loop fm_send 20", 20, (long)fm_send(l, sv[0], d, 20, 0));
    check("gap lower: loop first 5", 5, (long)peek_msg(sv[1], got, sizeof got));
    check("gap lower: loop second 5", 5, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("gap lower: loop second bytes", d + 5, got, 5);
    check("gap lower: loop held after the gap", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("gap lower: loop 10 queued", 10, (long)fm_queued(l));
    check("gap lower: kick at +5", 0, fm_kick(l, sv[0], t0 + 5, &nx));
    check("gap lower: nothing at +5", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("gap lower: next_ms in 14..20", 1, nx >= 14 && nx <= 20);
    check("gap lower: kick at +21", 0, fm_kick(l, sv[0], t0 + 21, &nx));
    check("gap lower: third 5", 5, (long)peek_msg(sv[1], got, sizeof got));
    check("gap lower: fourth 5", 5, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("gap lower: fourth bytes", d + 15, got, 5);
    check("gap lower: queue empty", -1, nx);
    check("gap lower: a later send waits the last gap", 1, (long)fm_send(l, sv[0], "z", 1, 0));
    check("gap lower: it is queued", 1, (long)fm_queued(l));
    check("gap lower: kick at +40 too early", 0, fm_kick(l, sv[0], t0 + 40, &nx));
    check("gap lower: next_ms > 0", 1, nx > 0);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_queue_cap(void) {
    /* catches: a delayed queue that grows without a bound */
    int sv[2], big = 4 << 20;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(2); }
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(1024, 1000) };
    struct fm_link *l = chain(1, ops, m);
    fm_set_loop(l, 1);
    size_t n = 100 * 1024;
    unsigned char *d = calloc(1, (size_t)FM_Q_HARD);
    check("queue cap: first send", (long)n, (long)fm_send(l, sv[0], d, n, 0));
    check("queue cap: over FM_Q_MAX queued", 1, fm_queued(l) > FM_Q_MAX);
    check("queue cap: still taken past FM_Q_MAX", (long)n, (long)fm_send(l, sv[0], d, n, 0));
    check("queue cap: a third send fills it", (long)n, (long)fm_send(l, sv[0], d, n, 0));
    check("queue cap: over FM_Q_HARD queued", 1, fm_queued(l) >= FM_Q_HARD - 1024);
    check("queue cap: refused when full", TR_EIO_WANT, (long)fm_send(l, sv[0], d, 10, 0));
    check_str("queue cap: why", "the send queue is full", fm_why(l));
    int nx;
    check("queue cap: kick reports the error", TR_EIO_WANT, fm_kick(l, sv[0], mono_ms() + 100000, &nx));
    free(d);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_hs_fail(void) {
    /* catches: a layer's handshake failure or its reason lost */
    int sv[2];
    seqpair(sv);
    const struct fm_ops *ops[2] = { &op_hsx, &op_rec };
    struct fm_mask m[2] = { mk('h', 0), mk('r', 0) };
    struct fm_link *l = chain(2, ops, m);
    send(sv[1], "NO", 2, MSG_NOSIGNAL);
    check("hs fail: bad reply fails", -1, fm_link_hs(l, sv[0], 0));
    check_str("hs fail: why from the layer", "hsx: bad reply", fm_why(l));
    fm_link_free(l);
    l = chain(2, ops, m);
    shutdown(sv[1], SHUT_WR);
    check("hs fail: peer closed before the reply", TR_ECLOSED_WANT, fm_link_hs(l, sv[0], 0));
    check_str("hs fail: no reason without one", "", fm_why(l));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static struct { size_t n; int64_t gap; unsigned char first; } g_pc[16];
static size_t g_npc;

static int rec_emit(void *arg, const unsigned char *d, size_t n, int64_t gap) {
    (void)arg;
    if (g_npc < 16) { g_pc[g_npc].n = n; g_pc[g_npc].gap = gap; g_pc[g_npc].first = n ? d[0] : 0; g_npc++; }
    return 0;
}

static void t_shape(void) {
    /* catches: fm_shape touching a socket, or a piece handed on without its gap */
    unsigned char d[25];
    for (int i = 0; i < 25; i++) d[i] = (unsigned char)i;
    const struct fm_ops *ops[2] = { &op_gap, &op_gap };
    struct fm_mask m[2] = { mk(10, 20), mk(5, 0) };
    struct fm_link *l = chain(1, ops, m);
    g_npc = 0;
    uint64_t t0 = mono_ms();
    check("shape: rc", 0, fm_shape(l, d, 25, rec_emit, NULL));
    check("shape: no sleep", 1, mono_ms() - t0 < 10);
    check("shape: three pieces", 3, (long)g_npc);
    check("shape: 10 then gap 20", 1, g_pc[0].n == 10 && g_pc[0].gap == 20 && g_pc[0].first == 0);
    check("shape: 10 then gap 20 again", 1, g_pc[1].n == 10 && g_pc[1].gap == 20 && g_pc[1].first == 10);
    check("shape: 5 then gap 20", 1, g_pc[2].n == 5 && g_pc[2].gap == 20 && g_pc[2].first == 20);
    fm_link_free(l);
    l = chain(2, ops, m);
    g_npc = 0;
    check("shape two: rc", 0, fm_shape(l, d, 10, rec_emit, NULL));
    check("shape two: three emits", 3, (long)g_npc);
    check("shape two: 5 no gap", 1, g_pc[0].n == 5 && g_pc[0].gap == 0);
    check("shape two: 5 no gap again", 1, g_pc[1].n == 5 && g_pc[1].gap == 0 && g_pc[1].first == 5);
    check("shape two: then the upper gap alone", 1, g_pc[2].n == 0 && g_pc[2].gap == 20);
    fm_link_free(l);
}

static void t_loop_after_due(void) {
    /* catches: a write sent past queued pieces whose gap is over but not yet kicked */
    int sv[2], nx;
    seqpair(sv);
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(10, 20) };
    struct fm_link *l = chain(1, ops, m);
    fm_set_loop(l, 1);
    unsigned char d[30], got[64];
    for (int i = 0; i < 30; i++) d[i] = (unsigned char)(0x30 + i);
    check("after due: fm_send 30", 30, (long)fm_send(l, sv[0], d, 30, 0));
    check("after due: first out", 10, (long)peek_msg(sv[1], got, sizeof got));
    poll(NULL, 0, 30);
    check("after due: fm_send 4 later", 4, (long)fm_send(l, sv[0], "wxyz", 4, 0));
    check("after due: the 4 B did not jump", -1, (long)peek_msg(sv[1], got, sizeof got));
    uint64_t end = mono_ms() + 2000;
    while (fm_queued(l) && mono_ms() < end) {
        if (fm_kick(l, sv[0], mono_ms(), &nx)) break;
        if (nx > 0) poll(NULL, 0, nx);
    }
    check("after due: second", 10, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("after due: second bytes", d + 10, got, 10);
    check("after due: third", 10, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("after due: third bytes", d + 20, got, 10);
    check("after due: the 4 B last", 4, (long)peek_msg(sv[1], got, sizeof got));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_errors(void) {
    /* catches: a write after a failed one, which leaves a hole in the stream, or a read error passed as data */
    int sv[2], nx;
    seqpair(sv);
    const struct fm_ops *ops[1] = { &op_fail };
    struct fm_mask m[1] = { mk(0, 0) };
    struct fm_link *l = chain(1, ops, m);
    unsigned char got[16];
    g_fail = 1;
    check("errors: failed write", -7, (long)fm_send(l, sv[0], "ab", 2, 0));
    check_str("errors: why", "fail: broken", fm_why(l));
    g_fail = 0;
    check("errors: later write still fails", -7, (long)fm_send(l, sv[0], "cd", 2, 0));
    check("errors: nothing reached the peer", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("errors: kick fails too", -7, fm_kick(l, sv[0], mono_ms(), &nx));
    fm_link_free(l);
    l = chain(1, ops, m);
    send(sv[1], "xy", 2, MSG_NOSIGNAL);
    g_fail = 2;
    errno = 0;
    check("errors: read error is -1", -1, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    check("errors: errno EPROTO", EPROTO, errno);
    check_str("errors: read why", "fail: broken", fm_why(l));
    g_fail = 0;
    fm_link_free(l);
    const struct fm_ops *gops[1] = { &op_grow };
    l = chain(1, gops, m);
    send(sv[1], "xy", 2, MSG_NOSIGNAL);
    errno = 0;
    check("errors: output over cap is -1", -1, (long)fm_recv(l, sv[0], got, 4, 0, 0));
    check("errors: over cap errno EPROTO", EPROTO, errno);
    fm_link_free(l);
    const struct fm_ops *hops[2] = { &op_hsx, &op_fail };
    struct fm_mask hm[2] = { mk('h', 0), mk(0, 0) };
    l = chain(2, hops, hm);
    send(sv[1], "OK", 2, MSG_NOSIGNAL);
    g_fail = 2;
    check("errors: hs read through a failed layer is TR_EMASK", -65, fm_link_hs(l, sv[0], 0));
    g_fail = 0;
    while (peek_msg(sv[1], got, sizeof got) > 0) {}
    fm_link_free(l);
    const struct fm_ops *sops[1] = { &op_stash };
    l = chain(1, sops, m);
    g_me = NULL;
    check("errors: stash hs", 0, fm_link_hs(l, sv[0], 0));
    check("errors: lower write outside hs/wr refused", -65, g_me ? fm_lower_write(g_me, (const unsigned char *)"q", 1, 0) : 0);
    check("errors: nothing sent by it", -1, (long)peek_msg(sv[1], got, sizeof got));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

struct slow { int fd; unsigned char *b; size_t got; };

static void *slow_drain(void *p) {
    struct slow *sd = p;
    while (sd->got < BIG) {
        size_t want = BIG - sd->got < 65536 ? BIG - sd->got : 65536;
        ssize_t r = recv(sd->fd, sd->b + sd->got, want, 0);
        if (r <= 0) break;
        sd->got += (size_t)r;
        poll(NULL, 0, 10);
    }
    return NULL;
}

static void t_blocking_short_write(void) {
    /* catches: the rest of a partial write dropped by the blocking writer */
    int ls = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0), small = 32768;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof a;
    setsockopt(ls, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    bind(ls, (struct sockaddr *)&a, sizeof a);
    listen(ls, 1);
    getsockname(ls, (struct sockaddr *)&a, &al);
    setsockopt(c, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    connect(c, (struct sockaddr *)&a, sizeof a);
    int s = accept(ls, NULL, NULL);
    timeo(c, 0, 200);
    timeo(s, 5000, 0);
    unsigned char *d = malloc(BIG), *rb = malloc(BIG);
    for (size_t i = 0; i < BIG; i++) d[i] = (unsigned char)(i * 7 + (i >> 12));
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(BIG, 0) };
    struct fm_link *l = chain(1, ops, m);
    struct slow sd = { .fd = s, .b = rb };
    pthread_t th;
    pthread_create(&th, NULL, slow_drain, &sd);
    check("blocking short: fm_send 4 MiB", (long)BIG, (long)fm_send(l, c, d, BIG, 0));
    shutdown(c, SHUT_WR);
    pthread_join(th, NULL);
    check("blocking short: peer got 4 MiB", (long)BIG, (long)sd.got);
    check("blocking short: in order", 0, memcmp(d, rb, BIG));
    fm_link_free(l);
    free(d);
    free(rb);
    close(c);
    close(s);
    close(ls);
}

static void t_room(void) {
    /* catches: room counted in data only, so delayed 1-byte pieces trip the hard cap */
    int sv[2], big = 4 << 20, refused = 0;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(2); }
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(1, 1000) };
    struct fm_link *l = chain(1, ops, m);
    fm_set_loop(l, 1);
    unsigned char d[1000];
    memset(d, 7, sizeof d);
    check("room: all of it at first", FM_Q_MAX, (long)fm_room(l));
    for (int i = 0; i < 10000 && fm_room(l) > 0; i++) {
        size_t k = fm_room(l) < sizeof d ? fm_room(l) : sizeof d;
        if (fm_send(l, sv[0], d, k, 0) != (ssize_t)k) refused = 1;
    }
    check("room: never refused while room > 0", 0, refused);
    check("room: reaches 0", 0, (long)fm_room(l));
    check("room: 9 B per 1-byte piece, at least 7282 queued", 1, fm_queued(l) >= 7282);
    check("room: and under 7282 + 1000", 1, fm_queued(l) < 7282 + 1000);
    check("room: a control write still taken", 3, (long)fm_send(l, sv[0], d, 3, 0));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_two_gaps(void) {
    /* catches: the upper gap overwriting the lower one, or counted from now instead of the pending due */
    int sv[2], nx = 99;
    seqpair(sv);
    const struct fm_ops *ops[2] = { &op_gap, &op_gap };
    struct fm_mask m[2] = { mk(10, 20), mk(5, 7) };
    unsigned char d[10], got[16];
    for (int i = 0; i < 10; i++) d[i] = (unsigned char)(0x41 + i);
    struct fm_link *l = chain(2, ops, m);
    fm_set_loop(l, 1);
    uint64_t t0 = mono_ms();
    check("two gaps queued: send 10", 10, (long)fm_send(l, sv[0], d, 10, 0));
    check("two gaps queued: first 5 out", 5, (long)peek_msg(sv[1], got, sizeof got));
    check("two gaps queued: 5 waiting", 5, (long)fm_queued(l));
    check("two gaps queued: kick at +8", 0, fm_kick(l, sv[0], t0 + 8, &nx));
    check("two gaps queued: second 5 out", 5, (long)peek_msg(sv[1], got, sizeof got));
    check("two gaps queued: later 1 B", 1, (long)fm_send(l, sv[0], "z", 1, 0));
    check("two gaps queued: kick at +34 too early", 0, fm_kick(l, sv[0], t0 + 34, &nx));
    check("two gaps queued: nothing at +34", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("two gaps queued: next 1", 1, nx);
    check("two gaps queued: kick at +35", 0, fm_kick(l, sv[0], t0 + 35, &nx));
    check("two gaps queued: 1 B after 7 + 20", 1, (long)peek_msg(sv[1], got, sizeof got));
    fm_link_free(l);
    l = chain(2, ops, m);
    fm_set_loop(l, 1);
    t0 = mono_ms();
    check("two gaps empty: send 5", 5, (long)fm_send(l, sv[0], d, 5, 0));
    check("two gaps empty: 5 out", 5, (long)peek_msg(sv[1], got, sizeof got));
    check("two gaps empty: nothing queued", 0, (long)fm_queued(l));
    check("two gaps empty: later 1 B", 1, (long)fm_send(l, sv[0], "z", 1, 0));
    check("two gaps empty: kick at +26 too early", 0, fm_kick(l, sv[0], t0 + 26, &nx));
    check("two gaps empty: nothing at +26", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("two gaps empty: next 1..2", 1, nx >= 1 && nx <= 2);
    check("two gaps empty: kick at +28", 0, fm_kick(l, sv[0], t0 + 28, &nx));
    check("two gaps empty: 1 B after 7 + 20", 1, (long)peek_msg(sv[1], got, sizeof got));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_loop_no_sleep(void) {
    /* catches: nanosleep reachable in loop mode */
    int sv[2];
    seqpair(sv);
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(1, 1000) };
    struct fm_link *l = chain(1, ops, m);
    fm_set_loop(l, 1);
    uint64_t t0 = mono_ms();
    check("no sleep: fm_send 3", 3, (long)fm_send(l, sv[0], "abc", 3, 0));
    check("no sleep: within 10 ms", 1, mono_ms() - t0 < 10);
    check("no sleep: 2 queued", 2, (long)fm_queued(l));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void direct_case(const char *what, const struct fm_ops *a, const struct fm_ops *b, size_t n,
                        const char *want_direct, const char *want_plain) {
    int sv[2];
    seqpair(sv);
    const struct fm_ops *ops[2] = { a, b };
    struct fm_mask m[2] = { mk(0, 0), mk(0, 0) };
    struct fm_link *l = chain(n, ops, m);
    unsigned char got[16];
    char w[96];
    send(sv[1], "\x01\x02", 2, MSG_NOSIGNAL);
    snprintf(w, sizeof w, "%s: direct read 2", what);
    check(w, 2, (long)fm_recv(l, sv[0], got, sizeof got, 0, 1));
    snprintf(w, sizeof w, "%s: direct bytes", what);
    check_hex(w, want_direct, got, 2);
    send(sv[1], "\x01\x02", 2, MSG_NOSIGNAL);
    snprintf(w, sizeof w, "%s: plain read 2", what);
    check(w, 2, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    snprintf(w, sizeof w, "%s: plain bytes", what);
    check_hex(w, want_plain, got, 2);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_direct_splice(void) {
    /* catches: direct reads through splice layers, or the walk from the wrong end */
    direct_case("direct [s1]", &op_x55s1, NULL, 1, "0102", "5457");
    direct_case("direct [s0]", &op_x55s0, NULL, 1, "5457", "5457");
    direct_case("direct [s0,s1]", &op_x55s0, &op_x55s1, 2, "0102", "0102");
    direct_case("direct [s1,s0]", &op_x55s1, &op_x55s0, 2, "5457", "0102");
}

static void send_case(const char *what, const struct fm_ops *a, const struct fm_ops *b, size_t n, int direct,
                      const char *want) {
    int sv[2];
    seqpair(sv);
    const struct fm_ops *ops[2] = { a, b };
    struct fm_link *l = fm_link_new_ops(ops, (const struct fm_mask *const[2]){ NULL, NULL }, n);
    unsigned char got[8];
    char w[96];
    snprintf(w, sizeof w, "%s: fm_send 3", what);
    check(w, 3, (long)fm_send(l, sv[0], "abc", 3, direct));
    snprintf(w, sizeof w, "%s: peer read 3", what);
    check(w, 3, (long)peek_msg(sv[1], got, sizeof got));
    snprintf(w, sizeof w, "%s: bytes", what);
    check_mem(w, want, got, 3);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_direct_send_splice(void) {
    /* catches: fm_send ignoring direct, lowering past a non-splice layer, or walking from the wrong end */
    send_case("send [s1] masked", &op_x55s1, NULL, 1, 0, "\x34\x37\x36");
    send_case("send [s1] direct", &op_x55s1, NULL, 1, 1, "abc");
    send_case("send [s0] direct", &op_x55s0, NULL, 1, 1, "\x34\x37\x36");
    send_case("send lay [s0,s1] direct", &op_x55s1, &op_x55s0, 2, 1, "\x34\x37\x36");
}

static void t_direct_send_behind_queue(void) {
    /* catches: a raw write sent ahead of queued outer pieces, or passed through the splice layer */
    int sv[2], nx = 99;
    seqpair(sv);
    const struct fm_ops *ops[1] = { &op_gap };
    struct fm_mask m[1] = { mk(10, 20) };
    struct fm_link *l = chain(1, ops, m);
    fm_set_loop(l, 1);
    unsigned char d[30], got[64];
    for (int i = 0; i < 30; i++) d[i] = (unsigned char)(0x40 + i);
    uint64_t t0 = mono_ms();
    g_gapn = 0;
    check("behind queue: outer send 30", 30, (long)fm_send(l, sv[0], d, 30, 0));
    check("behind queue: one gap write", 1, g_gapn);
    check("behind queue: first piece out", 10, (long)peek_msg(sv[1], got, sizeof got));
    check("behind queue: direct send 2", 2, (long)fm_send(l, sv[0], "BB", 2, 1));
    check("behind queue: gap layer not called", 1, g_gapn);
    check("behind queue: nothing new before the gap", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("behind queue: 22 queued", 22, (long)fm_queued(l));
    check("behind queue: kick at +21", 0, fm_kick(l, sv[0], t0 + 21, &nx));
    check("behind queue: kick at +42", 0, fm_kick(l, sv[0], t0 + 42, &nx));
    check("behind queue: kick at +63", 0, fm_kick(l, sv[0], t0 + 63, &nx));
    check("behind queue: second piece", 10, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("behind queue: second bytes", d + 10, got, 10);
    check("behind queue: third piece", 10, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("behind queue: third bytes", d + 20, got, 10);
    check("behind queue: then the raw 2 B", 2, (long)peek_msg(sv[1], got, sizeof got));
    check_mem("behind queue: raw bytes", "BB", got, 2);
    check("behind queue: nothing after", -1, (long)peek_msg(sv[1], got, sizeof got));
    check("behind queue: queue empty", 0, (long)fm_queued(l));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_pending(void) {
    /* catches: held bytes not reported, which stalls a flow until more data arrives */
    int sv[2];
    seqpair(sv);
    const struct fm_ops *ops[1] = { &op_hold };
    struct fm_mask m[1] = { mk(0, 0) };
    struct fm_link *l = chain(1, ops, m);
    unsigned char got[16];
    check("pending: none before", 0, fm_pending(l));
    send(sv[1], "abc", 3, MSG_NOSIGNAL);
    check("pending: first read 2", 2, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    check_mem("pending: ab", "ab", got, 2);
    check("pending: one held", 1, fm_pending(l));
    uint64_t t0 = mono_ms();
    check("pending: second read 1", 1, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    check("pending: did not block", 1, mono_ms() - t0 < 500);
    check_mem("pending: c", "c", got, 1);
    check("pending: none after", 0, fm_pending(l));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);

    seqpair(sv);
    l = chain(1, ops, m);
    send(sv[1], "abc", 3, MSG_NOSIGNAL);
    shutdown(sv[1], SHUT_WR);
    check("pending eof: ab", 2, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    check("pending eof: c", 1, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    check_mem("pending eof: c bytes", "c", got, 1);
    check("pending eof: then 0", 0, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);

    const struct fm_ops *pops[1] = { &op_part };
    seqpair(sv);
    l = chain(1, pops, m);
    send(sv[1], "abc", 3, MSG_NOSIGNAL);
    shutdown(sv[1], SHUT_WR);
    check("part eof: ab", 2, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    check("part eof: holding", 1, fm_pending(l));
    check("part eof: 0 at the end, not an error", 0, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);

    seqpair(sv);
    l = chain(1, pops, m);
    send(sv[1], "abc", 3, MSG_NOSIGNAL);
    check("part open: ab", 2, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    t0 = mono_ms();
    errno = 0;
    check("part open: nothing to emit is EAGAIN", -1, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    check("part open: errno EAGAIN", EAGAIN, errno);
    check("part open: did not wait", 1, mono_ms() - t0 < 500);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_rand_between(void) {
    /* catches: a closed interval, or the 0/1 shortcut missing */
    int ok10 = 1, ok11 = 1, ok5 = 1, lo = 0, hi = 0, out = 0;
    for (int i = 0; i < 200; i++) {
        if (fm_rand_between(10, 11) != 10) ok10 = 0;
        if (fm_rand_between(11, 10) != 10) ok11 = 0;
        if (fm_rand_between(5, 5) != 5) ok5 = 0;
    }
    for (int i = 0; i < 4000; i++) {
        int64_t v = fm_rand_between(10, 20);
        if (v == 10) lo = 1;
        if (v == 19) hi = 1;
        if (v < 10 || v >= 20) out = 1;
    }
    check("rand: (10,11) always 10", 1, ok10);
    check("rand: (11,10) always 10", 1, ok11);
    check("rand: (5,5) always 5", 1, ok5);
    check("rand: (10,20) hits 10", 1, lo);
    check("rand: (10,20) hits 19", 1, hi);
    check("rand: (10,20) never 20 or outside", 0, out);
    int sw = 1;
    for (int i = 0; i < 2000; i++) {
        int64_t v = fm_rand_between(20, 10);
        if (v < 10 || v >= 20) sw = 0;
    }
    check("rand: (20,10) swapped into [10,20)", 1, sw);
    unsigned char b[64];
    memset(b, 0, sizeof b);
    fm_rand_bytes(b, sizeof b, 0x2a, 0x2a);
    int all = 1, high = 0, range = 1, e30 = 0, e35 = 0;
    for (size_t i = 0; i < sizeof b; i++) if (b[i] != 0x2a) all = 0;
    check("rand bytes: from=to=2a gives 2a", 1, all);
    fm_rand_bytes(b, sizeof b, 0, 255);
    for (size_t i = 0; i < sizeof b; i++) if (b[i] >= 0x80) high = 1;
    check("rand bytes: (0,255) raw", 1, high);
    for (int k = 0; k < 20; k++) {
        fm_rand_bytes(b, sizeof b, 0x35, 0x30);
        for (size_t i = 0; i < sizeof b; i++) {
            if (b[i] < 0x30 || b[i] > 0x35) range = 0;
            if (b[i] == 0x30) e30 = 1;
            if (b[i] == 0x35) e35 = 1;
        }
    }
    check("rand bytes: (35,30) within [30,35]", 1, range);
    check("rand bytes: hits 30", 1, e30);
    check("rand bytes: hits 35", 1, e35);
}

static void t_open(void) {
    /* catches: an allocation for filter, or a config that fails to build dialed unmasked */
    static const char filt[] = "{\"tcp\":[{\"type\":\"filter\"}]}";
    static const char frag[] = "{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"length\":10}}]}";
    static const char bad[] = "{\"tcp\":[{\"type\":\"xmc\"}]}";
    static const char sd[] = "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\"}}]}";
    static const char marker[] = "!fm";
    struct fm_link *l = (struct fm_link *)1;
    check("open: no mask", 0, fm_link_open(NULL, &l));
    check("open: no mask, no link", 1, l == NULL);
    l = (struct fm_link *)1;
    check("open: filter only", 0, fm_link_open(filt, &l));
    check("open: filter only, no link", 1, l == NULL);
    const struct fm_cfg *c = fm_cfg_get(filt);
    check("open: config cached by pointer", 1, c != NULL && fm_cfg_get(filt) == c);
    check("open: fragment", 0, fm_link_open(frag, &l));
    check("open: fragment gets a link", 1, l != NULL);
    fm_link_free(l);
    check("open: sudoku", 0, fm_link_open(sd, &l));
    check("open: sudoku gets a link", 1, l != NULL);
    fm_link_free(l);
    l = (struct fm_link *)1;
    check("open: refused config", -65, fm_link_open(bad, &l));
    check("open: refused config, no link", 1, l == NULL);
    l = (struct fm_link *)1;
    check("open: the marker", -65, fm_link_open(marker, &l));
    check("open: the marker, no link", 1, l == NULL);
}

static void t_free(void) {
    /* catches: the queue not freed */
    int sv[2], ok = 1;
    seqpair(sv);
    const struct fm_ops *ops[3] = { &op_gap, &op_alloc, &op_hold };
    struct fm_mask m[3] = { mk(1, 1000), mk(0, 0), mk(0, 0) };
    unsigned char got[16];
    for (int i = 0; i < 1000; i++) {
        struct fm_link *l = chain(3, ops, m);
        fm_set_loop(l, 1);
        if (fm_send(l, sv[0], "abc", 3, 0) != 3 || fm_queued(l) != 2) ok = 0;
        while (peek_msg(sv[1], got, sizeof got) > 0) {}
        fm_link_free(l);
    }
    check("free: 1000 links with a queue", 1, ok);
    close(sv[0]);
    close(sv[1]);
}

#define FRAG(s) "{\"tcp\":[{\"type\":\"fragment\",\"settings\":" s "}]}"

static unsigned char g_hello[522];

static void hello_init(void) {
    static const unsigned char h[5] = { 0x16, 0x03, 0x01, 0x02, 0x05 };
    memcpy(g_hello, h, 5);
    for (int i = 0; i < 517; i++) g_hello[5 + i] = (unsigned char)i;
}

static struct fm_link *frag_open(const char *json) {
    struct fm_link *l = NULL;
    if (fm_link_open(json, &l) || !l) { fprintf(stderr, "frag_open failed: %s\n", json); exit(2); }
    return l;
}

static size_t g_fw[160];
static unsigned char g_fwd[8192];
static size_t g_nfw, g_fwn;

static void frag_take(int fd) {
    g_nfw = g_fwn = 0;
    for (;;) {
        ssize_t r = recv(fd, g_fwd + g_fwn, sizeof g_fwd - g_fwn, MSG_DONTWAIT);
        if (r < 0) return;
        if (g_nfw < 160) g_fw[g_nfw++] = (size_t)r;
        g_fwn += (size_t)r;
    }
}

static struct { size_t n; int64_t gap; } g_fs[160];
static size_t g_nfs;

static int frag_emit(void *arg, const unsigned char *d, size_t n, int64_t gap) {
    (void)arg; (void)d;
    if (g_nfs < 160) { g_fs[g_nfs].n = n; g_fs[g_nfs].gap = gap; g_nfs++; }
    return 0;
}

static int records_ok(const unsigned char *w, size_t n, size_t piece, size_t count, size_t last) {
    unsigned char body[517];
    size_t off = 0, got = 0;
    for (size_t i = 0; i < count; i++) {
        size_t want = i + 1 == count ? last : piece;
        if (off + 5 + want > n) return 0;
        if (w[off] != 0x16 || w[off + 1] != 0x03 || w[off + 2] != 0x01) return 0;
        if (w[off + 3] != (want >> 8) || w[off + 4] != (want & 0xff)) return 0;
        memcpy(body + got, w + off + 5, want);
        got += want;
        off += 5 + want;
    }
    return off == n && got == 517 && !memcmp(body, g_hello + 5, 517);
}

static void t_frag_hello_merged(void) {
    /* catches: records sent one per write when delays are zero, or a header other than d[0..2] + be16 */
    int sv[2];
    seqpair(sv);
    struct fm_link *l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10}"));
    check("hello merged: sent", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    frag_take(sv[1]);
    check("hello merged: one write", 1, (long)g_nfw);
    check("hello merged: 52 x 5 + 517 = 777 B", 777, (long)g_fw[0]);
    check("hello merged: 51 records of 10, one of 7", 1, records_ok(g_fwd, g_fwn, 10, 52, 7));
    fm_link_free(l);
    l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10}"));
    g_nfs = 0;
    check("hello merged shape: rc", 0, fm_shape(l, g_hello, 522, frag_emit, NULL));
    check("hello merged shape: one emit, gap 0", 1, g_nfs == 1 && g_fs[0].n == 777 && g_fs[0].gap == 0);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_frag_hello_delayed(void) {
    /* catches: the sleep left out after the last record */
    int sv[2];
    seqpair(sv);
    struct fm_link *l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delay\":\"5-6\"}"));
    uint64_t t0 = mono_ms();
    check("hello delayed: sent", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    uint64_t el = mono_ms() - t0;
    frag_take(sv[1]);
    check("hello delayed: 52 writes", 52, (long)g_nfw);
    int sz = 1;
    for (size_t i = 0; i < 51; i++) if (g_fw[i] != 15) sz = 0;
    check("hello delayed: 51 of 15 B", 1, sz);
    check("hello delayed: last 12 B", 12, (long)g_fw[51]);
    check("hello delayed: records intact", 1, records_ok(g_fwd, g_fwn, 10, 52, 7));
    check("hello delayed: elapsed >= 52 x 5 ms", 1, el >= 260);
    check("hello delayed: elapsed <= 2 s", 1, el <= 2000);
    fm_link_free(l);
    l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delay\":\"5-6\"}"));
    g_nfs = 0;
    check("hello delayed shape: rc", 0, fm_shape(l, g_hello, 522, frag_emit, NULL));
    int gaps = g_nfs == 52;
    for (size_t i = 0; i < g_nfs && i < 52; i++) if (g_fs[i].gap != 5) gaps = 0;
    check("hello delayed shape: 52 emits, each gap 5, the last too", 1, gaps);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_frag_hello_two_zero_delays(void) {
    /* catches: merging whenever every delay is zero */
    int sv[2];
    seqpair(sv);
    struct fm_link *l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delays\":[0,0]}"));
    uint64_t t0 = mono_ms();
    check("hello two zero: sent", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    check("hello two zero: no sleep", 1, mono_ms() - t0 < 200);
    frag_take(sv[1]);
    check("hello two zero: 52 writes", 52, (long)g_nfw);
    check("hello two zero: records intact", 1, records_ok(g_fwd, g_fwn, 10, 52, 7));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_frag_hello_maxsplit(void) {
    /* catches: maxSplit counted from 0 or ignored */
    int sv[2];
    seqpair(sv);
    struct fm_link *l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"maxSplit\":2}"));
    check("hello maxsplit: sent", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    frag_take(sv[1]);
    check("hello maxsplit: one write", 1, (long)g_nfw);
    check("hello maxsplit: 5 + 10 + 5 + 507 = 527 B", 527, (long)g_fw[0]);
    check("hello maxsplit: records of 10 and 507", 1, records_ok(g_fwd, g_fwn, 10, 2, 507));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_frag_hello_tail(void) {
    /* catches: the bytes after the record dropped, merged into the records, or given a gap */
    int sv[2];
    seqpair(sv);
    unsigned char d[525];
    memcpy(d, g_hello, 522);
    d[522] = 0xaa;
    d[523] = 0xbb;
    d[524] = 0xcc;
    struct fm_link *l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10}"));
    check("hello tail: sent", 525, (long)fm_send(l, sv[0], d, 525, 0));
    frag_take(sv[1]);
    check("hello tail: two writes", 2, (long)g_nfw);
    check("hello tail: records first", 1, g_fw[0] == 777 && records_ok(g_fwd, 777, 10, 52, 7));
    check("hello tail: then 3 B", 3, (long)g_fw[1]);
    check_mem("hello tail: aa bb cc", "\xaa\xbb\xcc", g_fwd + 777, 3);
    fm_link_free(l);
    l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delay\":\"5-6\"}"));
    g_nfs = 0;
    check("hello tail delayed shape: rc", 0, fm_shape(l, d, 525, frag_emit, NULL));
    check("hello tail delayed shape: 52 records, then 3 B with no gap", 1,
          g_nfs == 53 && g_fs[51].gap == 5 && g_fs[52].n == 3 && g_fs[52].gap == 0);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_frag_hello_only_first(void) {
    /* catches: tlshello acting on a later write or a partial record */
    int sv[2];
    seqpair(sv);
    static const char js[] = FRAG("{\"packets\":\"tlshello\",\"length\":10}");
    struct fm_link *l = frag_open(js);
    check("hello first: write 1 not 22", 6, (long)fm_send(l, sv[0], "\x17\x03\x03\x00\x01\x00", 6, 0));
    check("hello first: write 2 a hello", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    frag_take(sv[1]);
    check("hello first: two whole writes", 1, g_nfw == 2 && g_fw[0] == 6 && g_fw[1] == 522);
    check_mem("hello first: the hello as is", g_hello, g_fwd + 6, 522);
    fm_link_free(l);
    l = frag_open(js);
    check("hello first: 5 B record", 5, (long)fm_send(l, sv[0], "\x16\x03\x01\x00\x00", 5, 0));
    frag_take(sv[1]);
    check("hello first: 5 B whole", 1, g_nfw == 1 && g_fw[0] == 5);
    fm_link_free(l);
    l = frag_open(js);
    check("hello first: partial record", 105, (long)fm_send(l, sv[0], g_hello, 105, 0));
    frag_take(sv[1]);
    check("hello first: partial whole", 1, g_nfw == 1 && g_fw[0] == 105);
    fm_link_free(l);
    l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":1}"));
    check("hello first: 7 B record of 2", 7, (long)fm_send(l, sv[0], "\x16\x03\x01\x00\x02\x41\x42", 7, 0));
    frag_take(sv[1]);
    check("hello first: 7 B cut into two records of 1", 1, g_nfw == 1 && g_fw[0] == 12);
    check_mem("hello first: the two records", "\x16\x03\x01\x00\x01\x41\x16\x03\x01\x00\x01\x42", g_fwd, 12);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static int frag_sizes(const char *json, const size_t *wr, size_t nwr, const size_t *want, size_t nwant) {
    int sv[2];
    seqpair(sv);
    struct fm_link *l = frag_open(json);
    unsigned char d[300];
    for (int i = 0; i < 300; i++) d[i] = (unsigned char)i;
    size_t all = 0, tot = 0;
    unsigned char got[8192];
    int ok = 1;
    for (size_t i = 0; i < nwr; i++) {
        if (fm_send(l, sv[0], d, wr[i], 0) != (ssize_t)wr[i]) ok = 0;
        frag_take(sv[1]);
        memcpy(got + tot, g_fwd, g_fwn);
        tot += g_fwn;
        for (size_t k = 0; k < g_nfw; k++) {
            if (all >= nwant || g_fw[k] != want[all]) ok = 0;
            all++;
        }
        if (g_fwn != wr[i] || memcmp(g_fwd, d, wr[i])) ok = 0;
    }
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
    return ok && all == nwant;
}

static void t_frag_range(void) {
    /* catches: the window inclusive at one end only, compared signed, or the last length entry not repeated */
    size_t w4[4] = { 250, 250, 30, 250 }, w2[2] = { 250, 250 }, w45[1] = { 45 }, w3[3] = { 250, 250, 250 };
    size_t a[6] = { 250, 100, 100, 50, 30, 250 };
    check("range 2-3: 250 | 100 100 50 | 30 | 250", 1, frag_sizes(FRAG("{\"packets\":\"2-3\",\"length\":100}"), w4, 4, a, 6));
    check("range 3-1: nothing cut", 1, frag_sizes(FRAG("{\"packets\":\"3-1\",\"length\":100}"), w4, 4, w4, 4));
    size_t e6[6] = { 100, 100, 50, 100, 100, 50 };
    check("range 1--5: every write cut", 1, frag_sizes(FRAG("{\"packets\":\"1--5\",\"length\":100}"), w2, 2, e6, 6));
    check("range -5: nothing cut", 1, frag_sizes(FRAG("{\"packets\":\"-5\",\"length\":100}"), w2, 2, w2, 2));
    size_t e[9] = { 100, 100, 50, 100, 100, 50, 100, 100, 50 };
    check("range empty: every write cut", 1, frag_sizes(FRAG("{\"packets\":\"\",\"length\":100}"), w3, 3, e, 9));
    size_t l3[3] = { 10, 20, 15 };
    check("range lengths: 10 20 15", 1, frag_sizes(FRAG("{\"packets\":\"\",\"lengths\":[10,20]}"), w45, 1, l3, 3));
    size_t m2[2] = { 10, 35 };
    check("range maxsplit 2: 10 35", 1,
          frag_sizes(FRAG("{\"packets\":\"\",\"lengths\":[10,20],\"maxSplit\":2}"), w45, 1, m2, 2));
    struct fm_link *l = frag_open(FRAG("{\"packets\":\"\",\"length\":10,\"delay\":\"5-6\"}"));
    unsigned char d[25] = { 0 };
    g_nfs = 0;
    check("range delay shape: rc", 0, fm_shape(l, d, 25, frag_emit, NULL));
    check("range delay shape: 10 10 5, each gap 5, the last too", 1,
          g_nfs == 3 && g_fs[0].n == 10 && g_fs[1].n == 10 && g_fs[2].n == 5 && g_fs[0].gap == 5 &&
          g_fs[1].gap == 5 && g_fs[2].gap == 5);
    fm_link_free(l);
    l = frag_open(FRAG("{\"packets\":\"\",\"length\":10}"));
    g_nfs = 0;
    check("range no delay shape: rc", 0, fm_shape(l, d, 25, frag_emit, NULL));
    check("range no delay shape: gaps 0", 1,
          g_nfs == 3 && g_fs[0].gap == 0 && g_fs[1].gap == 0 && g_fs[2].gap == 0);
    fm_link_free(l);
    size_t r5[1] = { 300 };
    int sv[2], in = 1, cut = 0;
    seqpair(sv);
    l = frag_open(FRAG("{\"packets\":\"\",\"length\":\"5-9\"}"));
    for (int k = 0; k < 20; k++) {
        unsigned char x[300] = { 0 };
        fm_send(l, sv[0], x, r5[0], 0);
        frag_take(sv[1]);
        for (size_t i = 0; i + 1 < g_nfw; i++) {
            if (g_fw[i] < 5 || g_fw[i] > 8) in = 0;
            if (g_fw[i] == 8) cut = 1;
        }
    }
    check("range 5-9: pieces within [5,8]", 1, in);
    check("range 5-9: 8 is drawn", 1, cut);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_frag_range_zero_piece(void) {
    /* catches: a zero piece skipped, which shifts every later write number of an outer mask */
    static const char js[] = FRAG("{\"packets\":\"\",\"lengths\":[0,10]}");
    const struct fm_cfg *c = fm_cfg_get(js);
    check("zero piece: config", 1, c != NULL && c->n == 1);
    if (!c) return;
    struct fm_mask rm = mk('r', 0);
    const struct fm_ops *ops[2] = { &fm_frag_ops, &op_rec };
    const struct fm_mask *ms[2] = { &c->m[0], &rm };
    struct fm_link *l = fm_link_new_ops(ops, ms, 2);
    int sv[2];
    seqpair(sv);
    unsigned char d[25];
    for (int i = 0; i < 25; i++) d[i] = (unsigned char)i;
    g_nlog = 0;
    check("zero piece: sent", 25, (long)fm_send(l, sv[0], d, 25, 0));
    check("zero piece: rec saw 0 10 10 5", 1,
          g_nlog == 4 && g_log[0].n == 0 && g_log[1].n == 10 && g_log[2].n == 10 && g_log[3].n == 5);
    frag_take(sv[1]);
    check("zero piece: socket saw 10 10 5", 1, g_nfw == 3 && g_fw[0] == 10 && g_fw[1] == 10 && g_fw[2] == 5);
    check_mem("zero piece: bytes in order", d, g_fwd, 25);
    fm_link_free(l);
    l = frag_open(FRAG("{\"packets\":\"tlshello\",\"lengths\":[0,10]}"));
    check("zero piece hello: sent", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    frag_take(sv[1]);
    check("zero piece hello: 5 + 51 x 15 + 12 = 782 B", 1, g_nfw == 1 && g_fw[0] == 782);
    check_mem("zero piece hello: an empty record first", "\x16\x03\x01\x00\x00\x16\x03\x01\x00\x0a", g_fwd, 10);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

struct fwr { const unsigned char *d; size_t n; };

static int frag_seq(const char *json, const struct fwr *w, size_t nw, const size_t *want, size_t nwant) {
    int sv[2];
    seqpair(sv);
    struct fm_link *l = frag_open(json);
    size_t all = 0;
    int ok = 1;
    for (size_t i = 0; i < nw; i++) {
        if (fm_send(l, sv[0], w[i].d, w[i].n, 0) != (ssize_t)w[i].n) ok = 0;
        frag_take(sv[1]);
        for (size_t k = 0; k < g_nfw; k++) {
            if (all >= nwant || g_fw[k] != want[all]) ok = 0;
            all++;
        }
    }
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
    return ok && all == nwant;
}

static int gaps_zero(const char *json, const unsigned char *d, size_t n, size_t want) {
    struct fm_link *l = frag_open(json);
    g_nfs = 0;
    int ok = fm_shape(l, d, n, frag_emit, NULL) == 0 && g_nfs == want;
    for (size_t i = 0; i < g_nfs && i < 160; i++) if (g_fs[i].gap != 0) ok = 0;
    fm_link_free(l);
    return ok;
}

static void t_frag_xray_vectors(void) {
    /* catches: a hello split across writes cut, maxSplit off by one mid-write, the window over the hello, or merge read from more than delays[0].to */
    unsigned char f[300];
    for (int i = 0; i < 300; i++) f[i] = (unsigned char)i;
    struct fwr hs[2] = { { g_hello, 5 }, { g_hello + 5, 517 } }, h6[2] = { { g_hello, 6 }, { g_hello + 6, 516 } };
    size_t a[2] = { 5, 517 }, b[2] = { 6, 516 };
    check("xray hdrsplit: 5 | 517", 1, frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":10}"), hs, 2, a, 2));
    check("xray hdr6: 6 | 516", 1, frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":10}"), h6, 2, b, 2));
    struct fwr h1[1] = { { g_hello, 522 } }, h2[2] = { { g_hello, 522 }, { g_hello, 522 } };
    size_t c532[1] = { 532 }, c522[1] = { 522 };
    check("xray ms3hello: one write of 532", 1,
          frag_seq(FRAG("{\"packets\":\"tlshello\",\"lengths\":[3,5],\"maxSplit\":3}"), h1, 1, c532, 1));
    check("xray ms1hello: one record, 522", 1,
          frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":3,\"maxSplit\":1}"), h1, 1, c522, 1));
    struct fwr f20[1] = { { f, 20 } };
    size_t r3[3] = { 3, 5, 12 }, r1[1] = { 20 }, rn[5] = { 3, 5, 5, 5, 2 };
    check("xray ms3range: 3 5 12", 1, frag_seq(FRAG("{\"packets\":\"\",\"lengths\":[3,5],\"maxSplit\":3}"), f20, 1, r3, 3));
    check("xray ms1range: 20", 1, frag_seq(FRAG("{\"packets\":\"\",\"lengths\":[3,5],\"maxSplit\":1}"), f20, 1, r1, 1));
    check("xray msneg: 3 5 5 5 2", 1,
          frag_seq(FRAG("{\"packets\":\"\",\"lengths\":[3,5],\"maxSplit\":\"-2\"}"), f20, 1, rn, 5));
    struct fwr w4[4] = { { g_hello, 522 }, { f, 64 }, { f, 300 }, { f, 50 } };
    size_t w23[6] = { 522, 64, 100, 100, 100, 50 };
    check("xray win23: 522 | 64 | 100 100 100 | 50", 1, frag_seq(FRAG("{\"packets\":\"2-3\",\"length\":100}"), w4, 4, w23, 6));
    size_t w11[7] = { 100, 100, 100, 100, 100, 22, 522 };
    check("xray win11: the hello cut raw, the next whole", 1,
          frag_seq(FRAG("{\"packets\":\"1-1\",\"length\":100}"), h2, 2, w11, 7));
    size_t w12[3] = { 200, 200, 122 };
    check("xray win12: 200 200 122", 1, frag_seq(FRAG("{\"packets\":\"1-2\",\"length\":200}"), h1, 1, w12, 3));
    size_t m777[1] = { 777 }, s52[52];
    for (int i = 0; i < 52; i++) s52[i] = i < 51 ? 15 : 12;
    check("xray d00: merged", 1, frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delay\":\"0-0\"}"), h1, 1, m777, 1));
    check("xray d0a: merged", 1, frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delays\":[0]}"), h1, 1, m777, 1));
    check("xray dneg0: merged", 1,
          frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delays\":[\"-3-0\"]}"), h1, 1, m777, 1));
    check("xray d01: 52 writes", 1, frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delay\":\"0-1\"}"), h1, 1, s52, 52));
    check("xray d01: no gap", 1, gaps_zero(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delay\":\"0-1\"}"), g_hello, 522, 52));
    check("xray dnegneg: 52 writes", 1,
          frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delays\":[\"-3--1\"]}"), h1, 1, s52, 52));
    check("xray dnegneg: no gap", 1,
          gaps_zero(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delays\":[\"-3--1\"]}"), g_hello, 522, 52));
    static const unsigned char eb[6] = { 0x16, 0x03, 0x01, 0x00, 0x00, 0x16 };
    struct fwr e1[1] = { { eb, 6 } };
    size_t e51[2] = { 5, 1 };
    check("xray empty body + tail: 5 | 1", 1, frag_seq(FRAG("{\"packets\":\"tlshello\",\"length\":10}"), e1, 1, e51, 2));
    static const unsigned char zb[7] = { 0x16, 0x03, 0x01, 0x00, 0x02, 0x41, 0x42 };
    struct fwr z1[1] = { { zb, 7 } };
    size_t z27[1] = { 27 };
    check("xray zeros: one write of 27", 1, frag_seq(FRAG("{\"packets\":\"tlshello\",\"lengths\":[0,0,0,1]}"), z1, 1, z27, 1));
    check_mem("xray zeros: three empty records, then 41, then 42",
              "\x16\x03\x01\x00\x00\x16\x03\x01\x00\x00\x16\x03\x01\x00\x00\x16\x03\x01\x00\x01\x41\x16\x03\x01\x00\x01\x42",
              g_fwd, 27);
    struct fwr f10[1] = { { f, 10 } };
    size_t z442[3] = { 4, 4, 2 };
    check("xray zerosrange: 4 4 2", 1, frag_seq(FRAG("{\"packets\":\"\",\"lengths\":[0,0,4]}"), f10, 1, z442, 3));
    static const unsigned char fv[5] = { 0x16, 0x03, 0x01, 0x00, 0x00 };
    struct fm_link *l = frag_open(FRAG("{\"packets\":\"tlshello\",\"length\":10,\"delay\":\"5-6\"}"));
    g_nfs = 0;
    check("xray five_delay shape: rc", 0, fm_shape(l, fv, 5, frag_emit, NULL));
    check("xray five_delay: one emit of 5, gap 0", 1, g_nfs == 1 && g_fs[0].n == 5 && g_fs[0].gap == 0);
    fm_link_free(l);
}

#define HC1(s) "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":" s "}]}"
#define C ","
#define U(v) "{\"u64\":" #v "}"
#define S(v) "{\"type\":\"str\",\"bytes\":\"" v "\"}"
#define B(v) "{\"bytes\":" v "}"
#define TA(op, a) "{\"transform\":{\"op\":\"" op "\",\"args\":[" a "]}}"

#define HC_CAP(n) "{\"rand\":65536,\"capture\":\"" n "\"}"

static char g_hcout[600];

static const char *hc_eval(const char *items) {
    char js[2600], why[160];
    struct fm_cfg c;
    snprintf(js, sizeof js, HC1("{\"clients\":[[%s]]}"), items);
    if (fm_parse(js, strlen(js), &c, why, sizeof why)) {
        snprintf(g_hcout, sizeof g_hcout, "PARSE %s", why);
        return g_hcout;
    }
    struct fm_hc_env e;
    fm_hc_env_init(&e, -1);
    const struct fm_hc_seq *q = &c.m[0].u.hc.cl[0];
    unsigned char all[FM_HC_MAX + 16];
    size_t tot = 0;
    g_hcout[0] = 0;
    for (size_t i = 0; i < q->n; i++) {
        unsigned char *o = NULL;
        size_t n = 0;
        if (fm_hc_eval_item(&e, &q->it[i], &o, &n)) {
            snprintf(g_hcout, sizeof g_hcout, "ERR %s", e.why);
            free(o);
            tot = (size_t)-1;
            break;
        }
        if (tot + n <= sizeof all) memcpy(all + tot, o, n);
        tot += n;
        free(o);
    }
    if (tot != (size_t)-1) {
        if (tot > 200) snprintf(g_hcout, sizeof g_hcout, "LEN %zu", tot);
        else for (size_t i = 0; i < tot; i++) sprintf(g_hcout + 2 * i, "%02x", all[i]);
    }
    fm_hc_env_free(&e);
    fm_cfg_free(&c);
    return g_hcout;
}

static void t_hc_ops(void) {
    /* catches: an op off by its width or byte order, or a missing overflow check */
    static const struct { const char *it, *want; } v[] = {
        { TA("be16", TA("xor16", U(4660) C U(65535))), "edcb" },
        { TA("slice", B("[1,2,3,4]") C U(1) C U(2)), "0203" },
        { TA("slice", B("[1,2,3,4]") C U(3) C U(2)), "ERR slice out of bounds" },
        { TA("slice", B("[1,2,3,4]") C U(4) C U(0)), "" },
        { TA("slice", B("[1,2,3,4]") C U(18446744073709551615) C U(2)), "ERR slice out of bounds" },
        { TA("concat", S("ab") C S("cd") C S("ef")), "616263646566" },
        { TA("concat", TA("be16", U(1)) C TA("le32", U(2))), "000102000000" },
        { TA("pad", S("ab") C U(5) C S("xy")), "6162787978" },
        { TA("pad", S("ab") C U(7) C S("xyz")), "616278797a7879" },
        { TA("pad", S("ab") C U(2) C S("x")), "6162" },
        { TA("pad", S("abc") C U(2) C S("x")), "ERR pad target shorter than source" },
        { TA("pad", S("a") C U(3) C S("")), "ERR pad fill must not be empty" },
        { TA("pad", S("a") C U(65536) C S("x")), "LEN 65536" },
        { TA("pad", S("a") C U(65537) C S("x")), "ERR a value is longer than 65536 bytes" },
        { TA("truncate", S("abcdef") C U(3)), "616263" },
        { TA("truncate", S("abcdef") C U(7)), "ERR truncate out of bounds" },
        { TA("truncate", S("abc") C U(3)), "616263" },
        { TA("le16", U(258)), "0201" },
        { TA("le32", U(16909060)), "04030201" },
        { TA("be32", U(16909060)), "01020304" },
        { TA("le64", U(1)), "0100000000000000" },
        { TA("le64", U(18446744073709551615)), "ffffffffffffffff" },
        { TA("be16", U(65535)), "ffff" },
        { TA("be16", U(65536)), "ERR be16 overflow" },
        { TA("le16", U(65536)), "ERR le16 overflow" },
        { TA("be32", U(4294967296)), "ERR be32 overflow" },
        { TA("le32", U(4294967296)), "ERR le32 overflow" },
        { TA("be16", TA("add", U(18446744073709551615) C U(1))), "ERR add overflow" },
        { TA("le64", TA("add", U(18446744073709551614) C U(1))), "ffffffffffffffff" },
        { TA("be16", TA("add", U(2) C U(3))), "0005" },
        { TA("be16", TA("sub", U(1) C U(2))), "ERR sub underflow" },
        { TA("be16", TA("sub", U(5) C U(3))), "0002" },
        { TA("be16", TA("shl", U(1) C U(64))), "ERR shift out of range" },
        { TA("be16", TA("shl", U(9223372036854775808) C U(1))), "ERR shl overflow" },
        { TA("le64", TA("shl", U(1) C U(63))), "0000000000000080" },
        { TA("be16", TA("shr", U(256) C U(4))), "0010" },
        { TA("be16", TA("shr", U(1) C U(64))), "ERR shift out of range" },
        { TA("be16", TA("and", U(240) C U(60))), "0030" },
        { TA("be16", TA("or", U(240) C U(60))), "00fc" },
        { TA("be16", TA("xor16", U(65536) C U(1))), "ERR xor16 overflow" },
        { TA("be16", TA("xor16", U(1) C U(65536))), "ERR xor16 overflow" },
        { TA("be32", TA("xor32", U(4294967296) C U(1))), "ERR xor32 overflow" },
        { TA("be32", TA("xor32", U(305419896) C U(4294967295))), "edcba987" },
        { TA("add", U(1) C U(2)), "ERR expr value is not bytes" },
        { TA("shl", U(1) C U(1)), "ERR expr value is not bytes" },
        { TA("concat", S("a") C U(1)), "ERR expr value is not bytes" },
        { TA("slice", U(1) C U(0) C U(1)), "ERR expr value is not bytes" },
        { TA("slice", B("[1,2]") C S("a") C U(1)), "ERR expr value is not u64" },
        { TA("be16", S("a")), "ERR expr value is not u64" },
        { TA("be16", TA("be16", U(1))), "ERR expr value is not u64" },
        { TA("be16", U(1) C U(2)), "ERR be16 expects 1 arg" },
        { TA("le64", U(1) C U(2)), "ERR le64 expects 1 arg" },
        { TA("xor16", U(1)), "ERR xor expects 2 args" },
        { TA("add", U(1)), "ERR add expects 2 args" },
        { TA("shl", U(1)), "ERR shl expects 2 args" },
        { TA("pad", S("a") C U(3)), "ERR pad expects 3 args" },
        { TA("truncate", S("a")), "ERR truncate expects 2 args" },
        { TA("slice", S("a") C U(0)), "ERR slice expects 3 args" },
        { TA("concat", "{\"reuse\":\"nope\"}"), "ERR unknown variable: nope" },
        { TA("be16", "{\"metadata\":\"remote_port\"}"), "ERR unknown metadata: remote_port" },
        { "{\"reuse\":\"nope\"}", "ERR unknown variable: nope" },
        { "{\"delay\":\"5-6\"}", "" },
        { "{\"rand\":65536,\"randRange\":\"7-7\"}", "LEN 65536" },
        { "{\"rand\":65537}", "ERR a value is longer than 65536 bytes" },
        { HC_CAP("a") "," HC_CAP("b") "," HC_CAP("c") "," HC_CAP("d"), "LEN 262144" },
        { HC_CAP("a") "," HC_CAP("b") "," HC_CAP("c") "," HC_CAP("d") "," HC_CAP("a"), "LEN 327680" },
        { HC_CAP("a") "," HC_CAP("b") "," HC_CAP("c") "," HC_CAP("d") "," HC_CAP("e"),
          "ERR captured values are longer than 262144 bytes" },
        { "{\"packet\":[1,2],\"capture\":\"p\"}," TA("concat", "{\"reuse\":\"p\"}" C S("z")), "010201027a" },
        { "{\"packet\":[1,2],\"capture\":\"p\"}," TA("slice", "{\"reuse\":\"p\"}" C U(1) C U(1)), "010202" },
    };
    char name[80];
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        snprintf(name, sizeof name, "hc ops %zu: %.40s", i, v[i].want);
        check_str(name, v[i].want, hc_eval(v[i].it));
    }
}

static void t_hc_rand_capture(void) {
    /* catches: capture not stored, or randRange not applied */
    check_str("hc rand capture: 8 x 2a", "2a2a2a2a2a2a2a2a",
              hc_eval("{\"rand\":4,\"randRange\":\"42-42\",\"capture\":\"t\"},{\"reuse\":\"t\"}"));
    check_str("hc capture twice: the last kept", "0102020202",
              hc_eval("{\"packet\":[1],\"capture\":\"t\"},{\"packet\":[2,2],\"capture\":\"t\"},{\"reuse\":\"t\"}"));
    const char *r = hc_eval("{\"rand\":64,\"randRange\":\"7-8\"}");
    int in = strlen(r) == 128;
    for (size_t i = 0; in && i < 128; i += 2) in = r[i] == '0' && (r[i + 1] == '7' || r[i + 1] == '8');
    check("hc rand range 7-8: 64 bytes, each 07 or 08", 1, in);
}

struct hcstep { char op; size_t n; const char *d; };
struct hcres { ssize_t n; unsigned char b[64]; uint64_t at; };
struct hcpeer { int fd; const struct hcstep *st; size_t ns; struct hcres r[20]; int flag; };

static void *hc_peer(void *p) {
    struct hcpeer *h = p;
    for (size_t i = 0; i < h->ns; i++) {
        const struct hcstep *s = &h->st[i];
        struct hcres *r = &h->r[i];
        if (s->op == 'm') {
            r->n = recv(h->fd, r->b, s->n ? s->n : sizeof r->b, s->n ? MSG_WAITALL : 0);
        } else if (s->op == 's') {
            r->n = send(h->fd, s->d, s->n, MSG_NOSIGNAL);
        } else if (s->op == 'q') {
            struct pollfd pf = { h->fd, POLLIN, 0 };
            r->n = poll(&pf, 1, (int)s->n);
        } else if (s->op == 'w') {
            poll(NULL, 0, (int)s->n);
            __atomic_store_n(&h->flag, 1, __ATOMIC_SEQ_CST);
        } else if (s->op == 'x') {
            shutdown(h->fd, SHUT_WR);
        }
        r->at = mono_ms();
    }
    return NULL;
}

static void streampair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(2); }
    timeo(sv[0], 1000, 1000);
    timeo(sv[1], 1000, 1000);
}

static struct fm_link *hc_open(const char *json) {
    struct fm_link *l = NULL;
    if (fm_link_open(json, &l) || !l) { fprintf(stderr, "hc_open failed: %s\n", json); exit(2); }
    return l;
}

static int g_hc_ms;

static int hc_run(const char *json, int sv0, struct hcpeer *h, struct fm_link **keep) {
    pthread_t th;
    struct fm_link *l = hc_open(json);
    pthread_create(&th, NULL, hc_peer, h);
    int rc = fm_link_hs(l, sv0, g_hc_ms);
    if (keep) *keep = l;
    pthread_join(th, NULL);
    if (!keep) fm_link_free(l);
    return rc;
}

static void t_hc_conn(void) {
    /* catches: the reply not checked, or data altered after the exchange */
    static const char js[] = HC1("{\"clients\":[[{\"packet\":[1]},{\"rand\":1}]],\"servers\":[[{\"packet\":[2]},{\"rand\":1}]]}");
    int sv[2];
    streampair(sv);
    static const struct hcstep ok[] = { { 'm', 2, NULL }, { 's', 6, "\x02\x7f" "back" }, { 'm', 4, NULL } };
    struct hcpeer h = { .fd = sv[1], .st = ok, .ns = 3 };
    pthread_t th;
    struct fm_link *l = hc_open(js);
    pthread_create(&th, NULL, hc_peer, &h);
    check("hc conn: hs ok", 0, fm_link_hs(l, sv[0], 0));
    check("hc conn: send data", 4, (long)fm_send(l, sv[0], "data", 4, 0));
    unsigned char got[16];
    check("hc conn: answer's tail read upward", 4, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    check_mem("hc conn: tail unchanged", "back", got, 4);
    pthread_join(th, NULL);
    check("hc conn: peer read the 2 B header", 1, h.r[0].n == 2 && h.r[0].b[0] == 1);
    check("hc conn: peer read data unchanged", 1, h.r[2].n == 4 && !memcmp(h.r[2].b, "data", 4));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);

    streampair(sv);
    static const struct hcstep bad[] = { { 'm', 2, NULL }, { 's', 2, "\x03\x7f" } };
    struct hcpeer hb = { .fd = sv[1], .st = bad, .ns = 2 };
    l = NULL;
    check("hc conn: bad answer fails", -65, hc_run(js, sv[0], &hb, &l));
    check_str("hc conn: why", "header-custom: the server's answer did not match", fm_why(l));
    check_str("hc conn: last why", "header-custom: the server's answer did not match", fm_last_why());
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
    streampair(sv);
    struct hcpeer hg = { .fd = sv[1], .st = ok, .ns = 3 };
    l = hc_open(js);
    pthread_create(&th, NULL, hc_peer, &hg);
    check("hc conn: a later exchange ok", 0, fm_link_hs(l, sv[0], 2000));
    check_str("hc conn: last why cleared", "", fm_last_why());
    check("hc conn: data again", 4, (long)fm_send(l, sv[0], "data", 4, 0));
    check("hc conn: tail again", 4, (long)fm_recv(l, sv[0], got, sizeof got, 0, 0));
    pthread_join(th, NULL);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);

    streampair(sv);
    static const struct hcstep shut[] = { { 'm', 2, NULL }, { 's', 1, "\x02" }, { 'x', 0, NULL } };
    struct hcpeer hs = { .fd = sv[1], .st = shut, .ns = 3 };
    check("hc conn: closed mid-answer", -34, hc_run(js, sv[0], &hs, NULL));
    close(sv[0]);
    close(sv[1]);
}

static void t_hc_read_kinds(void) {
    /* catches: a reuse or transform item in the answer not compared, or an answer error without its text */
    static const char js[] = HC1("{\"clients\":[[{\"packet\":[1,2],\"capture\":\"a\"}],[{\"reuse\":\"r\"}]],"
                                 "\"servers\":[[{\"reuse\":\"a\"}," TA("be16", U(258)) ",{\"rand\":2,\"capture\":\"r\"}]]}");
    static const char ms[] = HC1("{\"clients\":[[{\"packet\":[1,2],\"capture\":\"a\"}]],\"servers\":[["
                                 TA("concat", "{\"reuse\":\"a\"}" C S("z")) "," TA("slice", B("[1,2,3,4]") C U(1) C U(2)) "]]}");
    static const char ev[] = HC1("{\"clients\":[[{\"packet\":[1]}]],\"servers\":[[" TA("slice", B("[1]") C U(0) C U(2)) "]]}");
    int sv[2];
    streampair(sv);
    static const struct hcstep ok[] = { { 'm', 0, NULL }, { 's', 6, "\x01\x02\x01\x02\xaa\xbb" }, { 'm', 0, NULL } };
    struct hcpeer h = { .fd = sv[1], .st = ok, .ns = 3 };
    check("hc read kinds: hs ok", 0, hc_run(js, sv[0], &h, NULL));
    close(sv[0]);
    close(sv[1]);
    check("hc read kinds: c0 is 01 02", 1, h.r[0].n == 2 && h.r[0].b[0] == 1 && h.r[0].b[1] == 2);
    check("hc read kinds: c1 is the rand read back", 1, h.r[2].n == 2 && h.r[2].b[0] == 0xaa && h.r[2].b[1] == 0xbb);
    streampair(sv);
    static const struct hcstep r1[] = { { 'm', 0, NULL }, { 's', 6, "\x01\x03\x01\x02\xaa\xbb" } };
    struct hcpeer h1 = { .fd = sv[1], .st = r1, .ns = 2 };
    check("hc read kinds: reuse mismatch", -65, hc_run(js, sv[0], &h1, NULL));
    close(sv[0]);
    close(sv[1]);
    streampair(sv);
    static const struct hcstep r2[] = { { 'm', 0, NULL }, { 's', 6, "\x01\x02\x01\x03\xaa\xbb" } };
    struct hcpeer h2 = { .fd = sv[1], .st = r2, .ns = 2 };
    check("hc read kinds: transform mismatch", -65, hc_run(js, sv[0], &h2, NULL));
    close(sv[0]);
    close(sv[1]);
    streampair(sv);
    static const struct hcstep r4[] = { { 'm', 0, NULL }, { 's', 5, "\x01\x02z\x02\x03" } };
    struct hcpeer h4 = { .fd = sv[1], .st = r4, .ns = 2 };
    check("hc read kinds: answer lengths from concat and slice", 0, hc_run(ms, sv[0], &h4, NULL));
    close(sv[0]);
    close(sv[1]);
    streampair(sv);
    static const struct hcstep r3[] = { { 'm', 0, NULL }, { 's', 2, "\x01\x00" } };
    struct hcpeer h3 = { .fd = sv[1], .st = r3, .ns = 2 };
    struct fm_link *l = NULL;
    check("hc read kinds: answer eval error", -65, hc_run(ev, sv[0], &h3, &l));
    close(sv[0]);
    close(sv[1]);
    check_str("hc read kinds: its why", "header-custom: slice out of bounds", fm_why(l));
    fm_link_free(l);
}

static void t_hc_carry_vars(void) {
    /* catches: variables reset between sequences */
    static const char js[] = HC1("{\"clients\":[[{\"packet\":[1]}],[{\"reuse\":\"tok\"}]],"
                                 "\"servers\":[[{\"rand\":4,\"capture\":\"tok\"}]]}");
    int sv[2];
    seqpair(sv);
    static const struct hcstep st[] = { { 'm', 0, NULL }, { 's', 4, "\xde\xad\xbe\xef" }, { 'm', 0, NULL } };
    struct hcpeer h = { .fd = sv[1], .st = st, .ns = 3 };
    check("hc carry: hs ok", 0, hc_run(js, sv[0], &h, NULL));
    check("hc carry: c0 01", 1, h.r[0].n == 1 && h.r[0].b[0] == 1);
    check("hc carry: c1 is the captured token", 1, h.r[2].n == 4 && !memcmp(h.r[2].b, "\xde\xad\xbe\xef", 4));
    close(sv[0]);
    close(sv[1]);
}

static void t_hc_order(void) {
    /* catches: trailing server sequences never read */
    static const char js[] = HC1("{\"clients\":[[{\"packet\":[16]}],[{\"packet\":[17]}]],"
                                 "\"servers\":[[{\"packet\":[32]}],[{\"packet\":[33]}],[{\"packet\":[34]}]]}");
    int sv[2];
    seqpair(sv);
    static const struct hcstep st[] = { { 'm', 0, NULL }, { 'q', 50, NULL }, { 's', 1, "\x20" }, { 'm', 0, NULL },
                                        { 'q', 50, NULL }, { 's', 1, "\x21" }, { 'w', 50, NULL }, { 's', 1, "\x22" } };
    struct hcpeer h = { .fd = sv[1], .st = st, .ns = 8 };
    pthread_t th;
    struct fm_link *l = hc_open(js);
    pthread_create(&th, NULL, hc_peer, &h);
    check("hc order: hs ok", 0, fm_link_hs(l, sv[0], 0));
    check("hc order: hs returned after s2 was sent", 1, __atomic_load_n(&h.flag, __ATOMIC_SEQ_CST));
    pthread_join(th, NULL);
    check("hc order: c0 first", 1, h.r[0].n == 1 && h.r[0].b[0] == 16);
    check("hc order: nothing before s0", 0, (long)h.r[1].n);
    check("hc order: c1 after s0", 1, h.r[3].n == 1 && h.r[3].b[0] == 17);
    check("hc order: nothing before s1", 0, (long)h.r[4].n);
    unsigned char x[4];
    check("hc order: s2 consumed", -1, (long)recv(sv[0], x, sizeof x, MSG_DONTWAIT));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static void t_hc_delay(void) {
    /* catches: the merged buffer not flushed before a delay */
    static const char js[] = HC1("{\"clients\":[[{\"packet\":[1]},{\"delay\":\"30-31\",\"packet\":[2]}]]}");
    int sv[2];
    seqpair(sv);
    static const struct hcstep st[] = { { 'm', 0, NULL }, { 'm', 0, NULL } };
    struct hcpeer h = { .fd = sv[1], .st = st, .ns = 2 };
    uint64_t t0 = mono_ms();
    check("hc delay: hs ok", 0, hc_run(js, sv[0], &h, NULL));
    uint64_t el = mono_ms() - t0;
    check("hc delay: 01 alone", 1, h.r[0].n == 1 && h.r[0].b[0] == 1);
    check("hc delay: then 02 alone", 1, h.r[1].n == 1 && h.r[1].b[0] == 2);
    check("hc delay: 02 not before 30 ms", 1, h.r[1].at - t0 >= 30);
    check("hc delay: elapsed <= 2 s", 1, el <= 2000);
    close(sv[0]);
    close(sv[1]);
}

static void t_hc_empty_seq(void) {
    /* catches: a zero-length write sent */
    static const char js[] = HC1("{\"clients\":[[{\"delay\":\"5-6\"}]],\"servers\":[[{\"packet\":[9]}]]}");
    static const char jf[] = "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":{\"clients\":[[{\"delay\":\"5-6\"}]]}},"
                             "{\"type\":\"fragment\",\"settings\":{\"packets\":\"tlshello\",\"length\":10}}]}";
    int sv[2];
    seqpair(sv);
    static const struct hcstep st[] = { { 'q', 100, NULL }, { 's', 1, "\x09" }, { 'm', 0, NULL } };
    struct hcpeer h = { .fd = sv[1], .st = st, .ns = 3 };
    pthread_t th;
    struct fm_link *l = hc_open(js);
    pthread_create(&th, NULL, hc_peer, &h);
    uint64_t t0 = mono_ms();
    check("hc empty: hs ok", 0, fm_link_hs(l, sv[0], 0));
    check("hc empty: the delay slept", 1, mono_ms() - t0 >= 5);
    check("hc empty: data", 1, (long)fm_send(l, sv[0], "x", 1, 0));
    pthread_join(th, NULL);
    check("hc empty: nothing before the answer", 0, (long)h.r[0].n);
    check("hc empty: the first message is the data", 1, h.r[2].n == 1 && h.r[2].b[0] == 'x');
    fm_link_free(l);
    l = hc_open(jf);
    t0 = mono_ms();
    check("hc empty chain: hs ok", 0, fm_link_hs(l, sv[0], 0));
    check("hc empty chain: the delay slept", 1, mono_ms() - t0 >= 5);
    check("hc empty chain: hello sent", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    frag_take(sv[1]);
    check("hc empty chain: the hello is fragment's write 1", 1, g_nfw == 1 && g_fw[0] == 777);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static int tcp_conn(int fam, const char *lis, const char *dial, int *cfd, int *sfd, unsigned *sport, unsigned *cport) {
    struct sockaddr_storage a;
    socklen_t al;
    memset(&a, 0, sizeof a);
    int one = 1, zero = 0, ls = socket(fam, SOCK_STREAM, 0);
    if (ls < 0) return -1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (fam == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&a;
        s4->sin_family = AF_INET;
        inet_pton(AF_INET, lis, &s4->sin_addr);
        al = sizeof *s4;
    } else {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&a;
        setsockopt(ls, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        s6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, lis, &s6->sin6_addr);
        al = sizeof *s6;
    }
    if (bind(ls, (struct sockaddr *)&a, al) || listen(ls, 1) || getsockname(ls, (struct sockaddr *)&a, &al)) {
        close(ls);
        return -1;
    }
    if (fam == AF_INET) {
        *sport = ntohs(((struct sockaddr_in *)&a)->sin_port);
    } else {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&a;
        *sport = ntohs(s6->sin6_port);
        inet_pton(AF_INET6, dial, &s6->sin6_addr);
    }
    *cfd = socket(fam, SOCK_STREAM, 0);
    if (connect(*cfd, (struct sockaddr *)&a, al)) {
        close(*cfd);
        close(ls);
        return -1;
    }
    *sfd = accept(ls, NULL, NULL);
    close(ls);
    al = sizeof a;
    getsockname(*cfd, (struct sockaddr *)&a, &al);
    *cport = fam == AF_INET ? ntohs(((struct sockaddr_in *)&a)->sin_port) : ntohs(((struct sockaddr_in6 *)&a)->sin6_port);
    timeo(*cfd, 1000, 1000);
    timeo(*sfd, 1000, 1000);
    return 0;
}

static void t_hc_metadata(void) {
    /* catches: src and dst aliases swapped, or host-order ports */
#define MD(op, name) TA(op, "{\"metadata\":\"" name "\"}")
    static const char j4[] = HC1("{\"clients\":[[" MD("be16", "remote_port") C MD("be16", "src_port_u16") C
                                 MD("be16", "dst_port_u16") C MD("be32", "remote_ip4_u32") "]]}");
    static const char j8[] = HC1("{\"clients\":[[" MD("be16", "local_port") C MD("be32", "local_ip4_u32") C
                                 MD("be32", "src_ip4_u32") C MD("be32", "dst_ip4_u32") "]]}");
    int c, s;
    unsigned sp, cp;
    unsigned char got[16], want[16];
    struct fm_link *l;
    check("hc meta: v4 connection", 0, tcp_conn(AF_INET, "127.0.0.1", NULL, &c, &s, &sp, &cp));
    l = hc_open(j4);
    check("hc meta v4: hs ok", 0, fm_link_hs(l, c, 0));
    unsigned char w4[10] = { (unsigned char)(sp >> 8), (unsigned char)sp, (unsigned char)(sp >> 8), (unsigned char)sp,
                             (unsigned char)(cp >> 8), (unsigned char)cp, 0x7f, 0, 0, 1 };
    check("hc meta v4: 10 B", 10, (long)recv(s, got, 10, MSG_WAITALL));
    check_mem("hc meta v4: remote, src, dst, remote ip", w4, got, 10);
    fm_link_free(l);
    l = hc_open(j8);
    check("hc meta v4 rest: hs ok", 0, fm_link_hs(l, c, 0));
    unsigned char w8[14] = { (unsigned char)(cp >> 8), (unsigned char)cp, 0x7f, 0, 0, 1, 0x7f, 0, 0, 1, 0x7f, 0, 0, 1 };
    check("hc meta v4 rest: 14 B", 14, (long)recv(s, got, 14, MSG_WAITALL));
    check_mem("hc meta v4 rest: local port, local, src, dst ip", w8, got, 14);
    fm_link_free(l);
    close(c);
    close(s);

    check("hc meta: v4-mapped connection", 0, tcp_conn(AF_INET6, "::", "::ffff:127.0.0.1", &c, &s, &sp, &cp));
    l = hc_open(j4);
    check("hc meta mapped: hs ok", 0, fm_link_hs(l, c, 0));
    memcpy(want, (unsigned char[10]){ (unsigned char)(sp >> 8), (unsigned char)sp, (unsigned char)(sp >> 8),
                                      (unsigned char)sp, (unsigned char)(cp >> 8), (unsigned char)cp, 0x7f, 0, 0, 1 }, 10);
    check("hc meta mapped: 10 B", 10, (long)recv(s, got, 10, MSG_WAITALL));
    check_mem("hc meta mapped: the v4 address", want, got, 10);
    fm_link_free(l);
    close(c);
    close(s);

    check("hc meta: v6 connection", 0, tcp_conn(AF_INET6, "::1", "::1", &c, &s, &sp, &cp));
    l = hc_open(j4);
    check("hc meta v6: hs fails", -65, fm_link_hs(l, c, 0));
    check_str("hc meta v6: why", "header-custom: unknown metadata: remote_ip4_u32", fm_why(l));
    check("hc meta v6: nothing written", -1, (long)recv(s, got, sizeof got, MSG_DONTWAIT));
    fm_link_free(l);
    close(c);
    close(s);
#undef MD
}

static void t_hc_through_fragment(void) {
    /* catches: header bytes written below an outer mask */
#define HDR "{\"type\":\"header-custom\",\"settings\":{\"clients\":[[{\"type\":\"str\",\"packet\":\"GET / HTTP/1.1\\r\\n\\r\\n\"}]]}}"
#define FRG "{\"type\":\"fragment\",\"settings\":{\"packets\":\"tlshello\",\"length\":10}}"
    static const char hf[] = "{\"tcp\":[" HDR "," FRG "]}";
    static const char fh[] = "{\"tcp\":[" FRG "," HDR "]}";
    int sv[2];
    seqpair(sv);
    struct fm_link *l = hc_open(hf);
    check("hc+frag: hs ok", 0, fm_link_hs(l, sv[0], 0));
    check("hc+frag: hello sent", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    frag_take(sv[1]);
    check("hc+frag: header then the uncut hello", 1, g_nfw == 2 && g_fw[0] == 18 && g_fw[1] == 522);
    check_mem("hc+frag: header bytes", "GET / HTTP/1.1\r\n\r\n", g_fwd, 18);
    check_mem("hc+frag: hello bytes", g_hello, g_fwd + 18, 522);
    fm_link_free(l);
    l = hc_open(fh);
    check("frag+hc: hs ok", 0, fm_link_hs(l, sv[0], 0));
    check("frag+hc: hello sent", 522, (long)fm_send(l, sv[0], g_hello, 522, 0));
    frag_take(sv[1]);
    check("frag+hc: header whole, then the cut hello", 1, g_nfw == 2 && g_fw[0] == 18 && g_fw[1] == 777);
    check_mem("frag+hc: header bytes", "GET / HTTP/1.1\r\n\r\n", g_fwd, 18);
    check("frag+hc: 52 records", 1, records_ok(g_fwd + 18, 777, 10, 52, 7));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
#undef HDR
#undef FRG
}

static void t_hc_deadline(void) {
    /* catches: an exchange held past the link's timeout by a silent or trickling server, or by a long delay */
    static const char js[] = HC1("{\"clients\":[[{\"packet\":[1]}]],\"servers\":[[{\"packet\":[2,2,2,2,2,2,2,2]}]]}");
    static const char jd[] = HC1("{\"clients\":[[{\"packet\":[1]},{\"delay\":\"5000-5001\",\"packet\":[2]}]]}");
    static const char jk[] = HC1("{\"clients\":[[{\"packet\":[1]},{\"delay\":\"30-31\",\"packet\":[2]}]]}");
    static const char je[] = HC1("{\"clients\":[[{\"delay\":\"5000-5001\"}]]}");
    static const char jf[] = "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":{\"clients\":[[{\"packet\":[1,2]}]]}},"
                             "{\"type\":\"fragment\",\"settings\":{\"packets\":\"1-1\",\"length\":1,\"delay\":\"5000-5001\"}}]}";
    static const char *nans = "header-custom: no answer from the server";
    static const char *ndel = "header-custom: a delay would pass the deadline of the exchange";
    int sv[2];
    struct fm_link *l;
    uint64_t t0, el;
    static const struct hcstep silent[] = { { 'm', 1, NULL }, { 'w', 800, NULL } };
    pthread_t th;
    streampair(sv);
    struct hcpeer hq = { .fd = sv[1], .st = silent, .ns = 2 };
    l = hc_open(js);
    pthread_create(&th, NULL, hc_peer, &hq);
    t0 = mono_ms();
    int rc = fm_link_hs(l, sv[0], 200);
    el = mono_ms() - t0;
    pthread_join(th, NULL);
    check("hc deadline silent: -56", -56, rc);
    check("hc deadline silent: not before 190 ms", 1, el >= 190);
    check("hc deadline silent: not past 600 ms", 1, el <= 600);
    check_str("hc deadline silent: why", nans, fm_why(l));
    check("hc deadline silent: peer saw the header", 1, (long)hq.r[0].n);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);

    streampair(sv);
    static const struct hcstep none[] = { { 'm', 1, NULL }, { 'w', 1300, NULL } };
    struct hcpeer hn = { .fd = sv[1], .st = none, .ns = 2 };
    g_hc_ms = 0;
    check("hc no deadline, socket timeout: -56", -56, hc_run(js, sv[0], &hn, &l));
    check_str("hc no deadline, socket timeout: why", nans, fm_why(l));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);

    streampair(sv);
    static const struct hcstep tr[] = { { 'm', 1, NULL }, { 's', 1, "\x02" }, { 'w', 100, NULL }, { 's', 1, "\x02" },
                                        { 'w', 100, NULL }, { 's', 1, "\x02" }, { 'w', 100, NULL }, { 's', 1, "\x02" },
                                        { 'w', 100, NULL }, { 's', 1, "\x02" }, { 'w', 100, NULL }, { 's', 1, "\x02" },
                                        { 'w', 100, NULL }, { 's', 1, "\x02" }, { 'w', 100, NULL }, { 's', 1, "\x02" } };
    struct hcpeer ht = { .fd = sv[1], .st = tr, .ns = 16 };
    l = hc_open(js);
    pthread_create(&th, NULL, hc_peer, &ht);
    t0 = mono_ms();
    rc = fm_link_hs(l, sv[0], 350);
    el = mono_ms() - t0;
    pthread_join(th, NULL);
    check("hc deadline trickle: -56", -56, rc);
    check("hc deadline trickle: not past 600 ms", 1, el <= 600);
    check_str("hc deadline trickle: why", nans, fm_why(l));
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);

    seqpair(sv);
    const char *dl[3] = { jd, je, jf };
    for (int i = 0; i < 3; i++) {
        l = hc_open(dl[i]);
        t0 = mono_ms();
        check("hc deadline delay: refused", -56, fm_link_hs(l, sv[0], 300));
        check("hc deadline delay: at once", 1, mono_ms() - t0 < 200);
        check_str("hc deadline delay: why", ndel, fm_why(l));
        fm_link_free(l);
        frag_take(sv[1]);
    }
    l = hc_open(jk);
    check("hc deadline delay inside it: ok", 0, fm_link_hs(l, sv[0], 2000));
    fm_link_free(l);
    frag_take(sv[1]);
    close(sv[0]);
    close(sv[1]);
    g_hc_ms = 0;
}

#define SD_JS "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\",\"paddingMin\":5,\"paddingMax\":20}}]}"
#define SD_JS0 "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\",\"paddingMin\":0,\"paddingMax\":0}}]}"
#define SD_JS100 "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\",\"paddingMax\":100}}]}"

static const struct fm_mask *sd_mask_of(const char *json) {
    const struct fm_cfg *c = fm_cfg_get(json);
    return c && c->n == 1 && c->m[0].kind == FM_SUDOKU ? &c->m[0] : NULL;
}

static const struct sd_set *sd_set_of(const char *json) {
    const struct fm_mask *m = sd_mask_of(json);
    return m ? sd_tables(&m->u.sd) : NULL;
}

static unsigned char *sd_pattern(size_t n, unsigned seed) {
    unsigned char *b = malloc(n);
    if (!b) exit(2);
    for (size_t i = 0; i < n; i++) b[i] = (unsigned char)((i * 131 + seed) ^ (i >> 7));
    return b;
}

struct sdrx { int fd; const struct sd_set *s; size_t want, got; unsigned char *out; int bad; };

static void *sd_rx(void *p) {
    struct sdrx *r = p;
    struct tdec d;
    unsigned char *raw = malloc(1 << 16), *tmp = malloc(1 << 16);
    if (!raw || !tmp || tdec_init(&d, r->s)) {
        r->bad = 1;
        free(raw);
        free(tmp);
        return NULL;
    }
    uint64_t end = mono_ms() + 5000;
    while (r->got < r->want && mono_ms() < end && !d.bad) {
        struct pollfd q = { r->fd, POLLIN, 0 };
        if (poll(&q, 1, 100) <= 0) continue;
        ssize_t k = recv(r->fd, raw, 1 << 16, MSG_DONTWAIT);
        if (k <= 0) continue;
        size_t m = tdec_run(&d, raw, (size_t)k, tmp);
        if (m > r->want - r->got) {
            r->bad = 1;
            break;
        }
        memcpy(r->out + r->got, tmp, m);
        r->got += m;
    }
    r->bad |= d.bad;
    tdec_free(&d);
    free(raw);
    free(tmp);
    return NULL;
}

struct sdtx { int fd; const unsigned char *b; size_t n; };

static void *sd_tx(void *p) {
    struct sdtx *w = p;
    size_t off = 0;
    while (off < w->n) {
        ssize_t k = send(w->fd, w->b + off, w->n - off, MSG_NOSIGNAL);
        if (k <= 0) break;
        off += (size_t)k;
    }
    return NULL;
}

static size_t sd_read_all(struct fm_link *l, int fd, unsigned char *out, size_t want, int flags) {
    size_t got = 0;
    uint64_t end = mono_ms() + 5000;
    while (got < want && mono_ms() < end) {
        if (flags & MSG_DONTWAIT) {
            struct pollfd q = { fd, POLLIN, 0 };
            poll(&q, 1, 50);
        }
        ssize_t r = fm_recv(l, fd, out + got, want - got, flags, 0);
        if (r > 0) got += (size_t)r;
        else if (r == 0) break;
    }
    return got;
}

static void sd_roundtrip(int loop) {
    char what[96];
    const char *mode = loop ? "loop" : "blocking";
    enum { N = 65536 };
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(2); }
    timeo(sv[0], 2000, 2000);
    struct fm_link *l = NULL;
    snprintf(what, sizeof what, "sd roundtrip %s: link", mode);
    check(what, 0, fm_link_open(SD_JS, &l));
    const struct sd_set *s = sd_set_of(SD_JS);
    if (!l || !s) {
        fm_link_free(l);
        close(sv[0]);
        close(sv[1]);
        return;
    }
    if (loop) {
        fm_set_loop(l, 1);
        fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    }
    unsigned char *up = sd_pattern(N, 3), *got = calloc(1, N), *down = sd_pattern(N, 77);
    struct sdrx rx = { sv[1], s, N, 0, got, 0 };
    pthread_t th;
    pthread_create(&th, NULL, sd_rx, &rx);
    snprintf(what, sizeof what, "sd roundtrip %s: 64 KiB written", mode);
    check(what, N, (long)fm_send(l, sv[0], up, N, 0));
    int nx = 0, rc = 0;
    uint64_t end = mono_ms() + 5000;
    while (loop && fm_queued(l) && mono_ms() < end && !rc) {
        rc = fm_kick(l, sv[0], mono_ms(), &nx);
        poll(NULL, 0, 1);
    }
    pthread_join(th, NULL);
    snprintf(what, sizeof what, "sd roundtrip %s: the peer decodes 64 KiB", mode);
    check(what, N, (long)rx.got);
    snprintf(what, sizeof what, "sd roundtrip %s: the bytes sent", mode);
    check(what, 1, !rx.bad && !memcmp(up, got, N));
    struct tpk p = { s, 0, 30, 0x2545f4914f6cdd1du };
    unsigned char *wire = malloc(2 * N + 16);
    struct sdtx tx = { sv[1], wire, wire ? tpk_pack(&p, down, N, wire) : 0 };
    pthread_t wt;
    pthread_create(&wt, NULL, sd_tx, &tx);
    memset(got, 0, N);
    size_t rn = sd_read_all(l, sv[0], got, N, loop ? MSG_DONTWAIT : 0);
    pthread_join(wt, NULL);
    snprintf(what, sizeof what, "sd roundtrip %s: 64 KiB read back", mode);
    check(what, N, (long)rn);
    snprintf(what, sizeof what, "sd roundtrip %s: the bytes the peer packed", mode);
    check(what, 0, memcmp(down, got, N));
    fm_link_free(l);
    free(up);
    free(got);
    free(down);
    free(wire);
    close(sv[0]);
    close(sv[1]);
}

static void t_sd_layer_roundtrip(void) {
    /* catches: wr or rd not wired */
    sd_roundtrip(0);
    sd_roundtrip(1);
}

static size_t g_cnt_n[16], g_cnt_k;

static int cnt_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    if (g_cnt_k < 16) g_cnt_n[g_cnt_k] = n;
    g_cnt_k++;
    return emit(arg, d, n, 0);
}

static int cut_wr(struct fm_layer *me, const unsigned char *d, size_t n, fm_emit_fn emit, void *arg) {
    (void)me;
    size_t a = n / 3, b = 2 * n / 3;
    int rc = emit(arg, d, a, 0);
    if (!rc) rc = emit(arg, d + a, b - a, 0);
    if (!rc) rc = emit(arg, d + b, n - b, 0);
    return rc;
}

static const struct fm_ops op_cnt = { .splice = 1, .wr = cnt_wr };
static const struct fm_ops op_cut = { .splice = 1, .wr = cut_wr };

static void t_sd_one_emit_per_write(void) {
    /* catches: the encoder emitting in chunks */
    const struct fm_mask *m0 = sd_mask_of(SD_JS0), *m = sd_mask_of(SD_JS);
    const struct sd_set *s = sd_set_of(SD_JS);
    struct fm_mask none;
    memset(&none, 0, sizeof none);
    if (!m0 || !m || !s) {
        check("sd one emit: configs", 1, 0);
        return;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(2); }
    int big = 1 << 20;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    timeo(sv[0], 2000, 2000);
    timeo(sv[1], 2000, 0);
    const struct fm_ops *o1[2] = { &fm_sd_ops, &op_cnt };
    const struct fm_mask *ms1[2] = { m0, &none };
    struct fm_link *l = fm_link_new_ops(o1, ms1, 2);
    check("sd one emit: [sudoku, counter] link", 1, l != NULL);
    if (!l) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    unsigned char *d = sd_pattern(20000, 9);
    g_cnt_k = 0;
    static const size_t len[3] = { 1, 1000, 20000 };
    unsigned char *raw = malloc(1 << 17);
    for (int i = 0; i < 3; i++) {
        fm_send(l, sv[0], d, len[i], 0);
        size_t k = 0;
        while (k < 4 * len[i]) {
            ssize_t r = recv(sv[1], raw, 1 << 17, 0);
            if (r <= 0) break;
            k += (size_t)r;
        }
    }
    check("sd one emit: three writes below sudoku", 3, (long)g_cnt_k);
    check("sd one emit: 4 B for 1 B at chance 0", 4, (long)g_cnt_n[0]);
    check("sd one emit: 4,000 B for 1,000 B", 4000, (long)g_cnt_n[1]);
    check("sd one emit: 80,000 B for 20,000 B", 80000, (long)g_cnt_n[2]);
    fm_link_free(l);
    const struct fm_ops *o2[2] = { &op_cut, &fm_sd_ops };
    const struct fm_mask *ms2[2] = { &none, m };
    l = fm_link_new_ops(o2, ms2, 2);
    check("sd one emit: [cutter, sudoku] link", 1, l != NULL);
    if (l) {
        unsigned char *got = calloc(1, 21001);
        struct sdrx rx = { sv[1], s, 21001, 0, got, 0 };
        pthread_t th;
        pthread_create(&th, NULL, sd_rx, &rx);
        for (int i = 0; i < 3; i++) fm_send(l, sv[0], d, len[i], 0);
        pthread_join(th, NULL);
        int same = rx.got == 21001 && !memcmp(got, d, 1) && !memcmp(got + 1, d, 1000) &&
                   !memcmp(got + 1001, d, 20000);
        check("sd one emit: three pieces per write decode intact", 1, !rx.bad && same);
        free(got);
        fm_link_free(l);
    }
    free(raw);
    free(d);
    close(sv[0]);
    close(sv[1]);
}

static void t_sd_room_grows(void) {
    /* catches: room in wire bytes, which trips FM_Q_HARD on the next call */
    struct fm_link *z = NULL;
    check("sd room: chance 0 link", 0, fm_link_open(SD_JS0, &z));
    check("sd room: chance 0, empty queue 65,536 / 4", 16384, (long)fm_room(z));
    fm_link_free(z);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(2); }
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    unsigned char fill[4096];
    memset(fill, 'f', sizeof fill);
    while (send(sv[0], fill, sizeof fill, MSG_DONTWAIT) > 0) {}
    while (send(sv[0], fill, 1, MSG_DONTWAIT) > 0) {}
    struct fm_link *l = NULL;
    check("sd room: link", 0, fm_link_open(SD_JS100, &l));
    if (!l) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    fm_set_loop(l, 1);
    check("sd room: empty queue 65,536 / 9", 7281, (long)fm_room(l));
    unsigned char *d = sd_pattern(FM_Q_MAX, 5);
    int eio = 0, over = 0;
    size_t worst = 0;
    for (int i = 0; i < 10; i++) {
        size_t r = fm_room(l);
        if (fm_send(l, sv[0], d, r, 0) < 0) eio = 1;
        if (q_mem(l) > 65545) over = 1;
        if (q_mem(l) > worst) worst = q_mem(l);
    }
    check("sd room: ten writes of the room, never TR_EIO", 0, eio);
    check("sd room: queue at most 65,545 after each", 0, over);
    check("sd room: the first write queued", 1, worst >= 4 * 7281);
    free(d);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

static int sd_sink(void *arg, const unsigned char *d, size_t n, int64_t gap) {
    (void)d;
    (void)gap;
    *(size_t *)arg += n;
    return 0;
}

struct sdth { struct fm_link *l; size_t wire; int rc; };

static void *sd_thread(void *p) {
    struct sdth *t = p;
    unsigned char *d = sd_pattern(20000, 1);
    t->rc = fm_shape(t->l, d, 20000, sd_sink, &t->wire);
    free(d);
    return NULL;
}

static void t_sd_scratch_thread(void) {
    /* catches: the thread scratch never released */
    static const char js[] = "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\",\"paddingMin\":100,"
                             "\"paddingMax\":100}}]}";
    struct sdth t = { NULL, 0, -1 };
    check("sd scratch: link", 0, fm_link_open(js, &t.l));
    if (!t.l) return;
#if defined(__GLIBC__) && (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 33) && !defined(__SANITIZE_ADDRESS__)
    struct mallinfo2 mb = mallinfo2();
    size_t before = mb.uordblks + mb.hblkhd;
#endif
    pthread_t th;
    pthread_create(&th, NULL, sd_thread, &t);
    pthread_join(th, NULL);
    check("sd scratch: the thread's write", 0, t.rc);
    check("sd scratch: 9 x 20,000 + 1 B of wire", 180001, (long)t.wire);
#if defined(__SANITIZE_ADDRESS__)
    check("sd scratch: nothing left on the heap", 0, __lsan_do_recoverable_leak_check());
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 33)
    struct mallinfo2 ma = mallinfo2();
    size_t after = ma.uordblks + ma.hblkhd;
    check("sd scratch: the joined thread's buffer freed", 1, after < before + 65536);
#endif
    fm_link_free(t.l);
}

static void t_sd_init_refused(void) {
    /* catches: a missing table set taken as a link */
    struct fm_mask bad;
    memset(&bad, 0, sizeof bad);
    static char pat[1][9] = { "zzzzzzzz" };
    bad.kind = FM_SUDOKU;
    bad.u.sd.pw = (unsigned char *)"p";
    bad.u.sd.pw_n = 1;
    bad.u.sd.n_pat = 1;
    bad.u.sd.pat = pat;
    check("sd init: no table set", 1, sd_tables(&bad.u.sd) == NULL);
    const struct fm_ops *o[1] = { &fm_sd_ops };
    const struct fm_mask *m[1] = { &bad };
    struct fm_link *l = fm_link_new_ops(o, m, 1);
    check("sd init: the link refused", 1, l == NULL);
    fm_link_free(l);
}

static long sd_inq(int fd) {
    int n = -1;
    return ioctl(fd, FIONREAD, &n) ? -1 : n;
}

static void t_sd_zero_yield(void) {
    /* catches: a second recv in the same call after a zero-yield read */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(2); }
    timeo(sv[0], 3000, 1000);
    struct fm_link *l = NULL;
    check("sd zero yield: link", 0, fm_link_open(SD_JS0, &l));
    if (!l) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    unsigned char b[16];
    check("sd zero yield: pad sent", 1, (long)send(sv[1], "\x10", 1, MSG_NOSIGNAL));
    errno = 0;
    uint64_t t0 = mono_ms();
    ssize_t r = fm_recv(l, sv[0], b, sizeof b, 0, 0);
    int e = errno;
    uint64_t el = mono_ms() - t0;
    check("sd zero yield, flags 0: -1", -1, (long)r);
    check("sd zero yield, flags 0: EINTR", EINTR, e);
    check("sd zero yield, flags 0: within 100 ms", 1, el < 100);
    check("sd zero yield, flags 0: the pad was read", 0, sd_inq(sv[0]));
    check("sd zero yield: second pad sent", 1, (long)send(sv[1], "\x10", 1, MSG_NOSIGNAL));
    errno = 0;
    r = fm_recv(l, sv[0], b, sizeof b, MSG_DONTWAIT, 0);
    e = errno;
    check("sd zero yield, MSG_DONTWAIT: -1", -1, (long)r);
    check("sd zero yield, MSG_DONTWAIT: EAGAIN", EAGAIN, e);
    check("sd zero yield, MSG_DONTWAIT: the pad was read", 0, sd_inq(sv[0]));
    check("sd zero yield: hints sent", 3, (long)send(sv[1], "\x20\x20\x80", 3, MSG_NOSIGNAL));
    r = fm_recv(l, sv[0], b, sizeof b, 0, 0);
    check("sd zero yield: then one byte", 1, (long)r);
    check("sd zero yield: 41", 0x41, r == 1 ? b[0] : -1);
    fm_link_free(l);
    close(sv[0]);
    close(sv[1]);
}

#define SD_HC "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":{\"clients\":[[{\"packet\":[1]}]],\"servers\":[[{\"packet\":[2,2,2,2]}]]}}," \
              "{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\",\"paddingMin\":0,\"paddingMax\":0}}]}"

struct sdhs { int fd, silent; const struct sd_set *s; long head; };

static void *sd_hs_peer(void *p) {
    struct sdhs *h = p;
    unsigned char b[64], w[64];
    struct pollfd q = { h->fd, POLLIN, 0 };
    h->head = poll(&q, 1, 2000) == 1 ? (long)recv(h->fd, b, sizeof b, 0) : -1;
    if (h->silent) {
        send(h->fd, "\x10", 1, MSG_NOSIGNAL);
        poll(NULL, 0, 800);
        return NULL;
    }
    struct tpk k = { h->s, 0, 0, 1 };
    static const unsigned char ans[4] = { 2, 2, 2, 2 };
    size_t n = tpk_pack(&k, ans, 4, w);
    for (size_t i = 0; i < n; i++) {
        send(h->fd, "\x10", 1, MSG_NOSIGNAL);
        poll(NULL, 0, 50);
        send(h->fd, w + i, 1, MSG_NOSIGNAL);
        poll(NULL, 0, 50);
    }
    return NULL;
}

static void t_sd_hs_zero_yield(void) {
    /* catches: fm_lower_read_full treating EINTR as an error or a timeout */
    const struct sd_set *s = sd_set_of(SD_JS0);
    for (int silent = 0; silent < 2; silent++) {
        const char *nm = silent ? "sd hs zero yield, silent" : "sd hs zero yield, drip";
        char what[96];
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) { perror("socketpair"); exit(2); }
        timeo(sv[0], 3000, 1000);
        timeo(sv[1], 3000, 1000);
        struct fm_link *l = NULL;
        snprintf(what, sizeof what, "%s: link", nm);
        check(what, 0, fm_link_open(SD_HC, &l));
        if (!l || !s) {
            fm_link_free(l);
            close(sv[0]);
            close(sv[1]);
            continue;
        }
        struct sdhs h = { sv[1], silent, s, 0 };
        pthread_t th;
        pthread_create(&th, NULL, sd_hs_peer, &h);
        uint64_t t0 = mono_ms();
        int rc = fm_link_hs(l, sv[0], silent ? 300 : 3000);
        uint64_t el = mono_ms() - t0;
        pthread_join(th, NULL);
        snprintf(what, sizeof what, "%s: the peer got the header", nm);
        check(what, 1, h.head > 0);
        if (silent) {
            snprintf(what, sizeof what, "%s: TR_ECONNTIMEOUT", nm);
            check(what, TR_ECONNTIMEOUT, rc);
            snprintf(what, sizeof what, "%s: not before 290 ms", nm);
            check(what, 1, el >= 290);
            snprintf(what, sizeof what, "%s: not past 400 ms", nm);
            check(what, 1, el <= 400);
        } else {
            snprintf(what, sizeof what, "%s: the exchange completes", nm);
            check(what, 0, rc);
            snprintf(what, sizeof what, "%s: why empty", nm);
            check_str(what, "", fm_why(l));
        }
        fm_link_free(l);
        close(sv[0]);
        close(sv[1]);
    }
}

int main(void) {
    t_chain_order();
    t_hs_through_lower();
    t_blocking_gap();
    t_loop_queue();
    t_loop_short_write();
    t_loop_no_sleep();
    t_shape();
    t_loop_after_due();
    t_errors();
    t_blocking_short_write();
    t_gap_through_lower();
    t_queue_cap();
    t_hs_fail();
    t_direct_splice();
    t_direct_send_splice();
    t_direct_send_behind_queue();
    t_pending();
    t_rand_between();
    t_open();
    t_room();
    t_two_gaps();
    t_kick_stale_now();
    t_free();
    hello_init();
    t_frag_hello_merged();
    t_frag_hello_delayed();
    t_frag_hello_two_zero_delays();
    t_frag_hello_maxsplit();
    t_frag_hello_tail();
    t_frag_hello_only_first();
    t_frag_range();
    t_frag_range_zero_piece();
    t_frag_xray_vectors();
    t_hc_ops();
    t_hc_rand_capture();
    t_hc_conn();
    t_hc_read_kinds();
    t_hc_carry_vars();
    t_hc_order();
    t_hc_delay();
    t_hc_empty_seq();
    t_hc_metadata();
    t_hc_through_fragment();
    t_hc_deadline();
    t_sd_layer_roundtrip();
    t_sd_one_emit_per_write();
    t_sd_room_grows();
    t_sd_scratch_thread();
    t_sd_init_refused();
    t_sd_zero_yield();
    t_sd_hs_zero_yield();
    return unit_done("fmlinkmatch");
}
