/* Node pool: `active` nodes work at once, new connections are spread over them, each node is
 * health checked, and a dead one is replaced by the next free candidate without restarting.
 *
 * The pool wraps the protocol's dialer (dialer.h). The protocol does not know about it: the ctx of
 * its table is still a node, but each connection has its own node, kept in the pool's session
 * header. The stack asks the pool the four optional questions of the table (peer_of, match, stale,
 * lost) and knows nothing about nodes.
 *
 * SLOTS. A slot is the place of one active node: the node (or none), whether it is alive, and a
 * generation. The generation changes when the slot's node is declared dead or replaced, and the
 * stack resets the connections of older generations (stale: RST to the client) while those of
 * live slots are left alone. A candidate is taken if it is the node of any slot: two slots never
 * hold the same node.
 *
 * SPREADING (`by`). connection — every new connection to a random live slot; site — the slot by a
 * hash of the destination address (if that slot is dead, the next live one round the circle, so
 * the sites of live slots do not move); site_client — by a hash of client and destination.
 *
 * SPARE CONNECTIONS of the stack (DC_PRECONNECT) are opened to live slots in turn. A connection
 * takes a spare that suits its node (match): with connection, any — the connection moves to the
 * spare's node; with site, only its own slot's. A spare to a node no longer active is dropped.
 *
 * HEALTH. The measure is the protocol's probe (for VLESS: connect, TLS/Reality, a request through
 * the node and the first byte of the answer), the same check that chose the node at startup.
 * Outcomes of live traffic are not a verdict, they only bring the check forward: a burst of SYNs
 * fails together on one packet loss, and a good handshake does not prove the node passes traffic.
 *   - a live node is checked every `interval` (60 s); a failure is retried after 3 s, two in a
 *     row and the node is dead (after a stall the first failure is enough: the node has already
 *     been silent longer than the threshold);
 *   - checks come early after three failed connects in a row and after a live connection is cut
 *     by the kernel for silence (lost: stack.c, node_sock_silence);
 *   - a dead node: its connections are reset (generation) and a replacement is searched at once
 *     among the free candidates in order of preference. None answers — another round after 15 s
 *     (own node first, then the free candidates), doubling up to 5 minutes. An empty slot (fewer
 *     candidates answered at startup than `active`) searches the same way.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "pool.h"
#include "../control.h"
#include "transport.h"
#include "osrand.h"

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif

#define PL_LOG_W "tunvless[warn]: "
#define PL_LOG_I "tunvless[info]: "

#define PL_CONFIRM_S   3
#define PL_RETRY_S     15
#define PL_RETRY_MAX_S 300
#define PL_STREAK      3
#define PL_TIMEOUT_S   8
/* A cut connection brings a check forward at most this often: the connections of a dead node are
 * cut together, and one check is enough. */
#define PL_LOST_GAP_MS 5000
#define PL_DRAINED 8

/* The pool's session header; the protocol's session follows at PL_HDR. */
struct pl_sess {
    const void *node;           /* the connection's node; NULL — a spare not yet anybody's */
    unsigned gen;               /* the slot's generation when the node was chosen */
    int slot;                   /* -1 — none */
    uint8_t udp, opened;        /* flow_open was called with k */
    struct flow_key k;
};
#define PL_HDR 64
_Static_assert(sizeof(struct pl_sess) <= PL_HDR, "pool session header larger than PL_HDR");
#define INNER(s) ((void *)((unsigned char *)(s) + PL_HDR))
#define CINNER(s) ((const void *)((const unsigned char *)(s) + PL_HDR))

struct pl_slot {
    int node;                   /* node index; -1 — empty */
    int up;                     /* alive: new connections come here */
    unsigned gen;
    int fails;                  /* failed checks in a row */
    int streak;                 /* failed connects in a row */
    int kick;                   /* check now */
    int lost;                   /* a stall brought the check: one failure is enough */
    uint64_t due;               /* next check, ms of CLOCK_MONOTONIC */
    uint64_t retry;             /* pause between rounds of a dead or empty slot, s */
    uint64_t checked_at;
    unsigned drained[PL_DRAINED];
    unsigned drained_n;
};

struct pl_sel { struct pl_sel *old; size_t n; int c[]; };

static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct pool_cfg cf;
    const struct dialer_ops *in;
    struct pl_slot *slot;
    struct pl_sel *sel;
    int n;                      /* slots: active, but no more than candidates */
    unsigned rr;                /* round robin of spare connections */
    int said_up;                /* the last state logged: some node alive */
    int pub;
    char why[256];              /* reason of the last failed check */
    char sig[1024];             /* the last active set logged */
} g_pl = { .mu = PTHREAD_MUTEX_INITIALIZER };

static const void *pl_node(int i) {
    return g_pl.cf.node(i);
}

static uint64_t pl_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

int pool_by_parse(const char *s) {
    if (!strcmp(s, "connection")) return POOL_BY_CONNECTION;
    if (!strcmp(s, "site")) return POOL_BY_SITE;
    if (!strcmp(s, "site-client") || !strcmp(s, "site_client")) return POOL_BY_SITE_CLIENT;
    return -1;
}

const char *pool_by_name(int by) {
    switch (by) {
    case POOL_BY_SITE: return "site";
    case POOL_BY_SITE_CLIENT: return "site-client";
    default: return "connection";
    }
}

/* ---- spreading ------------------------------------------------------------------------- */

static uint32_t pl_mix(uint32_t h) {
    h ^= h >> 16;
    h *= 0x7feb352du;
    h ^= h >> 15;
    h *= 0x846ca68bu;
    h ^= h >> 16;
    return h;
}

/* Per loop thread; spreading evenly needs no cryptographic strength. */
static unsigned pl_rand(void) {
    static __thread uint32_t x;
    if (!x) {
        if (os_getrandom(&x, sizeof x, GRND_NONBLOCK) != (ssize_t)sizeof x || !x)
            x = (uint32_t)pl_now_ms() ^ (uint32_t)getpid() ^ 0x9e3779b9u;
        if (!x) x = 1;
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

/* The slot for a new connection. Under the lock. -1 — no slot has a node. With no live slot, a
 * dead one that has a node: the connection fails fast (RST). */
static int pl_pick(const struct flow_key *k) {
    int live[64], nl = 0, any = -1;
    for (int i = 0; i < g_pl.n; i++) {
        if (g_pl.slot[i].node < 0) continue;
        if (any < 0) any = i;
        if (g_pl.slot[i].up && nl < (int)(sizeof live / sizeof live[0])) live[nl++] = i;
    }
    if (!nl) return any;
    if (g_pl.cf.by == POOL_BY_CONNECTION || !k) return live[pl_rand() % (unsigned)nl];
    uint32_t h = g_pl.cf.by == POOL_BY_SITE_CLIENT ? pl_mix(k->src * 0x9e3779b1u) ^ k->dst : k->dst;
    int at = (int)(pl_mix(h) % (uint32_t)g_pl.n);
    for (int d = 0; d < g_pl.n; d++) {
        const struct pl_slot *sl = &g_pl.slot[(at + d) % g_pl.n];
        if (sl->node >= 0 && sl->up) return (at + d) % g_pl.n;
    }
    return any;
}

static void pl_bind(struct pl_sess *s, int slot) {
    s->slot = slot;
    s->node = slot >= 0 ? pl_node(g_pl.slot[slot].node) : NULL;
    s->gen = slot >= 0 ? g_pl.slot[slot].gen : 0;
}

/* ---- health: state in the log ----------------------------------------------------------- */

/* Log the pool's state when it changes: the active nodes, and the moment no node answers (with the
 * reason of the last failed check) or one answers again. Takes the lock itself. */
static void pl_publish(void) {
    char names[1024] = "";
    const char *plain[64];
    int idx[64];
    size_t w = 0, np = 0;
    int any = 0;
    pthread_mutex_lock(&g_pl.mu);
    for (int i = 0; i < g_pl.n; i++) {
        if (g_pl.slot[i].node < 0 || !g_pl.slot[i].up) continue;
        any = 1;
        const char *nm = g_pl.cf.proto->name(pl_node(g_pl.slot[i].node));
        if (np < 64) {
            idx[np] = g_pl.slot[i].node;
            plain[np++] = nm;
        }
        if (w + 2 < sizeof names)
            w += (size_t)snprintf(names + w, sizeof names - w, "%s%s (#%d)", w ? ", " : "", nm,
                                  g_pl.slot[i].node);
    }
    pthread_mutex_unlock(&g_pl.mu);

    if (any && !g_pl.said_up) {
        g_pl.said_up = 1;
    } else if (!any && g_pl.said_up) {
        g_pl.said_up = 0;
        fprintf(stderr, PL_LOG_W "no active node answers (%s) — new connections are refused "
                        "until one does\n", g_pl.why[0] ? g_pl.why : "no answer");
    }
    if (w >= sizeof names - 2) w = sizeof names - 1;
    if (!strcmp(names, g_pl.sig)) return;
    snprintf(g_pl.sig, sizeof g_pl.sig, "%s", names);
    if (any) fprintf(stderr, PL_LOG_I "active: %s\n", names);
    ctl_emit_active(plain, idx, np);
}

/* ---- health: checks --------------------------------------------------------------------- */

static int pl_probe(int node, char *why, size_t n) {
    return g_pl.cf.proto->probe(pl_node(node), PL_TIMEOUT_S, why, n);
}

/* Whether candidate c is the node of another slot (live, or dead and waiting for it). Under the
 * lock. */
static int pl_taken(int c, int except) {
    for (int i = 0; i < g_pl.n; i++)
        if (i != except && g_pl.slot[i].node == c) return 1;
    return 0;
}

static void pl_slot_alive(struct pl_slot *sl) {
    sl->up = 1;
    sl->fails = sl->streak = sl->kick = sl->lost = 0;
    sl->retry = PL_RETRY_S;
    sl->checked_at = pl_now_ms();
    sl->due = sl->checked_at + (uint64_t)g_pl.cf.interval_s * 1000ull;
}

static int pl_in(const struct pl_sel *sel, int c) {
    for (size_t k = 0; k < sel->n; k++)
        if (sel->c[k] == c) return 1;
    return 0;
}

/* Give slot i a live node: its own previous one (if own), then the free candidates in order.
 * 1 — found. Probes run without the lock (up to eight seconds each); the state is logged after
 * every failure, so "no node answers" is said at once, not after the whole round. */
static int pl_refill(int i, int own) {
    char why[256];
    pthread_mutex_lock(&g_pl.mu);
    int prev = g_pl.slot[i].node;
    unsigned gen = g_pl.slot[i].gen;
    const struct pl_sel *sel = g_pl.sel;
    pthread_mutex_unlock(&g_pl.mu);
    if (own && prev >= 0) {
        if (pl_probe(prev, why, sizeof why) == 0) {
            pthread_mutex_lock(&g_pl.mu);
            if (g_pl.slot[i].gen != gen) { pthread_mutex_unlock(&g_pl.mu); return 0; }
            pl_slot_alive(&g_pl.slot[i]);
            pthread_mutex_unlock(&g_pl.mu);
            fprintf(stderr, PL_LOG_I "node %s answers again\n", g_pl.cf.proto->name(pl_node(prev)));
            ctl_emit_node_up(g_pl.cf.proto->name(pl_node(prev)), prev);
            pl_publish();
            return 1;
        }
        snprintf(g_pl.why, sizeof g_pl.why, "%s", why);
        pl_publish();
    }
    for (size_t k = 0; k < sel->n; k++) {
        int c = sel->c[k];
        pthread_mutex_lock(&g_pl.mu);
        int moved = g_pl.slot[i].gen != gen;
        int busy = c == prev || pl_taken(c, i);
        pthread_mutex_unlock(&g_pl.mu);
        if (moved) return 0;
        if (busy) continue;
        if (pl_probe(c, why, sizeof why) != 0) {
            if (!g_pl.why[0]) snprintf(g_pl.why, sizeof g_pl.why, "%s", why);
            pl_publish();
            continue;
        }
        pthread_mutex_lock(&g_pl.mu);
        if (g_pl.slot[i].gen != gen) { pthread_mutex_unlock(&g_pl.mu); return 0; }
        if (pl_taken(c, i) || !pl_in(g_pl.sel, c)) { pthread_mutex_unlock(&g_pl.mu); continue; }
        struct pl_slot *sl = &g_pl.slot[i];
        sl->node = c;
        __atomic_add_fetch(&sl->gen, 1, __ATOMIC_RELEASE);  /* pl_stale reads it without the lock */
        pl_slot_alive(sl);
        int n = g_pl.n;
        pthread_mutex_unlock(&g_pl.mu);
        if (prev >= 0)
            fprintf(stderr, PL_LOG_W "node %s does not answer — %s takes its place\n",
                    g_pl.cf.proto->name(pl_node(prev)), g_pl.cf.proto->name(pl_node(c)));
        else
            fprintf(stderr, PL_LOG_I "active node %d of %d: %s\n", i + 1, n,
                    g_pl.cf.proto->name(pl_node(c)));
        stack_nodes_changed();
        pl_publish();
        return 1;
    }
    pthread_mutex_lock(&g_pl.mu);
    struct pl_slot *sl = &g_pl.slot[i];
    if (sl->gen != gen || g_pl.sel != sel) { pthread_mutex_unlock(&g_pl.mu); return 0; }
    int retry_s = (int)sl->retry;
    sl->due = pl_now_ms() + sl->retry * 1000ull;
    sl->retry = sl->retry * 2 > PL_RETRY_MAX_S ? PL_RETRY_MAX_S : sl->retry * 2;
    int none_up = 1;
    for (int k = 0; k < g_pl.n; k++)
        if (g_pl.slot[k].node >= 0 && g_pl.slot[k].up) none_up = 0;
    pthread_mutex_unlock(&g_pl.mu);
    pl_publish();
    if (none_up) ctl_emit_no_node(retry_s);
    return 0;
}

/* One check of slot i: a live slot gets its regular check, a dead or empty one a search round. */
static void pl_check(int i) {
    pthread_mutex_lock(&g_pl.mu);
    struct pl_slot *sl = &g_pl.slot[i];
    int node = sl->node, up = sl->up, lost = sl->lost;
    unsigned gen = sl->gen;
    sl->kick = sl->lost = 0;
    pthread_mutex_unlock(&g_pl.mu);
    if (node < 0 || !up) { pl_refill(i, 1); return; }

    char why[256];
    int rc = pl_probe(node, why, sizeof why);
    pthread_mutex_lock(&g_pl.mu);
    if (sl->gen != gen) { pthread_mutex_unlock(&g_pl.mu); return; }
    sl->checked_at = pl_now_ms();
    if (rc == 0) {
        sl->fails = sl->streak = 0;
        sl->due = sl->checked_at + (uint64_t)g_pl.cf.interval_s * 1000ull;
        pthread_mutex_unlock(&g_pl.mu);
        return;
    }
    /* Two failures in a row, against a single loss on a radio link; one is enough when a stall
     * brought the check. */
    if (++sl->fails < 2 && !lost) {
        sl->due = sl->checked_at + PL_CONFIRM_S * 1000ull;
        pthread_mutex_unlock(&g_pl.mu);
        return;
    }
    /* Dead: its connections are reset now (generation), without waiting for a replacement. */
    sl->up = 0;
    sl->fails = 0;
    __atomic_add_fetch(&sl->gen, 1, __ATOMIC_RELEASE);
    sl->retry = PL_RETRY_S;
    pthread_mutex_unlock(&g_pl.mu);
    snprintf(g_pl.why, sizeof g_pl.why, "%s", why);
    fprintf(stderr, PL_LOG_W "node %s does not answer: %s — looking for a replacement\n",
            g_pl.cf.proto->name(pl_node(node)), why);
    ctl_emit_node_down(g_pl.cf.proto->name(pl_node(node)), node, why);
    stack_nodes_changed();
    /* Its own node has just failed twice: only the free candidates now; it waits for the next
     * round. */
    pl_refill(i, 0);
}

/* The slot to check next: one asked to be checked now first, otherwise the earliest due. Under the
 * lock; waits until it is due. */
static int pl_next(void) {
    for (;;) {
        if (g_pl.pub) {
            g_pl.pub = 0;
            return -1;
        }
        uint64_t now = pl_now_ms(), due = UINT64_MAX;
        int best = -1;
        for (int i = 0; i < g_pl.n; i++) {
            const struct pl_slot *sl = &g_pl.slot[i];
            if (sl->kick && sl->up && sl->node >= 0) return i;
            if (sl->due < due) { due = sl->due; best = i; }
        }
        if (best >= 0 && due <= now) return best;
        struct timespec ts = { .tv_sec = (time_t)(due / 1000), .tv_nsec = (long)(due % 1000) * 1000000L };
        pthread_cond_timedwait(&g_pl.cv, &g_pl.mu, &ts);
    }
}

static void *pl_thread(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_pl.mu);
        int i = pl_next();
        pthread_mutex_unlock(&g_pl.mu);
        if (i < 0) pl_publish();
        else pl_check(i);
    }
    return NULL;
}

/* Under the lock. */
static void pl_kick(int i) {
    g_pl.slot[i].kick = 1;
    pthread_cond_signal(&g_pl.cv);
}

/* ---- the pool's dialer ------------------------------------------------------------------ */

static const char *pl_peer(const void *ctx) {
    (void)ctx;
    const char *r = "?";
    pthread_mutex_lock(&g_pl.mu);
    for (int i = 0; i < g_pl.n; i++)
        if (g_pl.slot[i].node >= 0) { r = g_pl.in->peer(pl_node(g_pl.slot[i].node)); break; }
    pthread_mutex_unlock(&g_pl.mu);
    return r;
}

static const char *pl_peer_of(const void *ctx, const void *sess) {
    const struct pl_sess *s = sess;
    return s->node ? g_pl.in->peer(s->node) : pl_peer(ctx);
}

static void pl_describe(const void *ctx, char *out, size_t n) {
    (void)ctx;
    size_t w = 0;
    out[0] = '\0';
    pthread_mutex_lock(&g_pl.mu);
    for (int i = 0; i < g_pl.n && w + 2 < n; i++) {
        if (g_pl.slot[i].node < 0) continue;
        if (w) w += (size_t)snprintf(out + w, n - w, ", ");
        if (w < n) {
            g_pl.in->describe(pl_node(g_pl.slot[i].node), out + w, n - w);
            w += strlen(out + w);
        }
    }
    pthread_mutex_unlock(&g_pl.mu);
    if (g_pl.cf.active > 1 && w < n)
        snprintf(out + w, n - w, " — %d active, spread by %s", g_pl.cf.active, pool_by_name(g_pl.cf.by));
}

static const char *pl_strerror(int rc) { return g_pl.in->strerror(rc); }

/* A connect outcome for the slot's health: a streak of failures brings its check forward. */
static void pl_seen(const struct pl_sess *s, int rc) {
    if (s->slot < 0) return;
    pthread_mutex_lock(&g_pl.mu);
    struct pl_slot *sl = &g_pl.slot[s->slot];
    if (sl->gen == s->gen) {
        if (rc == 0) sl->streak = 0;
        else if (++sl->streak >= PL_STREAK) pl_kick(s->slot);
    }
    pthread_mutex_unlock(&g_pl.mu);
}

static int pl_connect(const void *ctx, void *sess, int timeout_s) {
    (void)ctx;
    struct pl_sess *s = sess;
    if (!s->node) {
        /* A spare: to the live slots in turn. */
        pthread_mutex_lock(&g_pl.mu);
        int pick = -1;
        for (int d = 0; d < g_pl.n && pick < 0; d++) {
            int i = (int)((g_pl.rr + (unsigned)d) % (unsigned)g_pl.n);
            if (g_pl.slot[i].node >= 0 && g_pl.slot[i].up) pick = i;
        }
        if (pick >= 0) {
            g_pl.rr = (unsigned)pick + 1;
            pl_bind(s, pick);
        }
        pthread_mutex_unlock(&g_pl.mu);
        if (pick < 0) return TR_ECONNECT;
    }
    int rc = g_pl.in->connect(s->node, INNER(s), timeout_s);
    pl_seen(s, rc);
    return rc;
}

/* A spare connection to a client's connection. If the spare's node is another one (by connection),
 * the connection moves to it: the protocol's flow state is set up again for the new node (VLESS:
 * UUID and Vision), then the link is moved. */
static void pl_take(void *dst, void *src) {
    struct pl_sess *d = dst, *s = src;
    if (d->node != s->node) {
        d->node = s->node;
        d->slot = s->slot;
        d->gen = s->gen;
        if (d->opened) g_pl.in->flow_open(d->node, INNER(d), &d->k, d->udp);
    }
    g_pl.in->take(INNER(d), INNER(s));
    s->node = NULL;
    s->slot = -1;
}

static void pl_close(void *sess) { g_pl.in->close(INNER(sess)); }

static void pl_clear(void *sess) {
    struct pl_sess *s = sess;
    s->node = NULL;
    s->slot = -1;
    s->opened = 0;
    g_pl.in->clear(INNER(s));
}

static int pl_fd(const void *sess) { return g_pl.in->fd(CINNER(sess)); }
static int pl_has_data(const void *sess) { return g_pl.in->has_data(CINNER(sess)); }

static int pl_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)ctx;
    struct pl_sess *s = sess;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, pl_pick(k));
    pthread_mutex_unlock(&g_pl.mu);
    if (!s->node) return -1;
    s->k = *k;
    s->udp = (uint8_t)udp;
    s->opened = 1;
    return g_pl.in->flow_open(s->node, INNER(s), k, udp);
}

static int pl_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *d, size_t n) {
    (void)ctx;
    struct pl_sess *s = sess;
    return g_pl.in->send(s->node, INNER(s), k, udp, d, n);
}

static long pl_room(const void *ctx, void *sess) {
    (void)ctx;
    struct pl_sess *s = sess;
    if (!g_pl.in->room || !s->node) return -1;
    return g_pl.in->room(s->node, INNER(s));
}

static size_t pl_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    return g_pl.in->dgram_frame(p, n, out, cap);
}

static int pl_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    return g_pl.in->read(INNER(sess), buf, cap, data, got);
}

static int pl_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                      dialer_emit_fn emit, void *arg) {
    (void)ctx;
    struct pl_sess *s = sess;
    return g_pl.in->deliver(s->node, INNER(s), udp, d, n, emit, arg);
}

static int pl_match(const void *ctx, const void *dst, const void *src) {
    (void)ctx;
    const struct pl_sess *d = dst, *s = src;
    if (!s->node || s->slot < 0) return -1;
    pthread_mutex_lock(&g_pl.mu);
    const struct pl_slot *sl = &g_pl.slot[s->slot];
    int live = sl->gen == s->gen && sl->up;
    pthread_mutex_unlock(&g_pl.mu);
    if (!live) return -1;
    if (g_pl.cf.by == POOL_BY_CONNECTION) return 1;
    return d->slot == s->slot;
}

static int pl_stale(const void *ctx, const void *sess) {
    (void)ctx;
    const struct pl_sess *s = sess;
    if (s->slot < 0 || !s->node) return 0;
    const struct pl_slot *sl = &g_pl.slot[s->slot];
    if (__atomic_load_n(&sl->gen, __ATOMIC_ACQUIRE) == s->gen) return 0;
    for (int k = 0; k < PL_DRAINED; k++)
        if (__atomic_load_n(&sl->drained[k], __ATOMIC_RELAXED) == s->gen + 1) {
            ((struct pl_sess *)sess)->slot = -1;
            return 0;
        }
    return 1;
}

static void pl_lost(const void *ctx, const void *sess) {
    (void)ctx;
    const struct pl_sess *s = sess;
    if (s->slot < 0) return;
    pthread_mutex_lock(&g_pl.mu);
    struct pl_slot *sl = &g_pl.slot[s->slot];
    if (sl->gen == s->gen && sl->up && pl_now_ms() - sl->checked_at >= PL_LOST_GAP_MS) {
        sl->lost = 1;
        pl_kick(s->slot);
    }
    pthread_mutex_unlock(&g_pl.mu);
}

static struct dialer_ops g_pl_ops;

/* ---- start ------------------------------------------------------------------------------ */

struct pl_ready { stack_ready_fn ready; void *arg; };

/* The device is up: health checks start. A node named on the command line was not probed at
 * startup, so its first check runs at once. */
static void pl_ready_cb(void *arg, const char *dev) {
    const struct pl_ready *r = arg;
    pl_publish();
    pthread_attr_t a;
    pthread_attr_init(&a);
    /* A check holds a connection (struct transport, ~40 KB) on its stack. */
    pthread_attr_setstacksize(&a, 512 * 1024);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    int err = pthread_create(&t, &a, pl_thread, NULL);
    pthread_attr_destroy(&a);
    if (err)
        fprintf(stderr, PL_LOG_W "no health check thread (%s) — a dead node will not be noticed\n",
                strerror(err));
    if (r->ready) r->ready(r->arg, dev);
}

static struct pl_sel *pl_sel_new(const int *c, size_t n) {
    struct pl_sel *s = malloc(sizeof *s + n * sizeof s->c[0]);
    if (!s) return NULL;
    s->old = NULL;
    s->n = n;
    if (n) memcpy(s->c, c, n * sizeof s->c[0]);
    return s;
}

/* Slots and the pool's dialer for configuration pc, or NULL — out of memory. Separate from pool_run
 * for the tests, which set the pool up without a device. */
static const struct dialer *pool_setup(const struct pool_cfg *pc) {
    /* CLOCK_MONOTONIC: deadlines must not move with the wall clock (NTP steps it after boot). */
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&g_pl.cv, &ca);
    pthread_condattr_destroy(&ca);
    g_pl.cf = *pc;
    g_pl.in = pc->proto->ops;
    if (g_pl.cf.interval_s <= 0) g_pl.cf.interval_s = POOL_INTERVAL_S;
    if (g_pl.cf.active < 1) g_pl.cf.active = 1;
    g_pl.n = g_pl.cf.active;
    if ((size_t)g_pl.n > pc->sel_n) {
        fprintf(stderr, PL_LOG_W "%d active nodes asked, %zu candidates — all of them are active\n",
                g_pl.cf.active, pc->sel_n);
        g_pl.n = (int)pc->sel_n;
    }
    if (g_pl.n < 1) g_pl.n = 1;
    struct pl_sel *sel = pl_sel_new(pc->sel, pc->sel_n);
    g_pl.slot = calloc((size_t)g_pl.cf.active, sizeof *g_pl.slot);
    if (!g_pl.slot || !sel) {
        free(sel);
        fprintf(stderr, PL_LOG_W "out of memory for node slots\n");
        return NULL;
    }
    sel->old = g_pl.sel;
    g_pl.sel = sel;
    uint64_t now = pl_now_ms();
    for (int i = 0; i < g_pl.cf.active; i++) {
        g_pl.slot[i].node = -1;
        g_pl.slot[i].retry = PL_RETRY_S;
        g_pl.slot[i].due = now;            /* an empty slot searches at once */
    }
    g_pl.slot[0].node = pc->first;
    g_pl.slot[0].up = 1;
    g_pl.slot[0].checked_at = now;
    g_pl.slot[0].due = pc->checked ? now + (uint64_t)g_pl.cf.interval_s * 1000ull : now;

    g_pl_ops = *g_pl.in;
    g_pl_ops.sess_size = PL_HDR + g_pl.in->sess_size;
    g_pl_ops.peer = pl_peer;
    g_pl_ops.describe = pl_describe;
    g_pl_ops.strerror = pl_strerror;
    g_pl_ops.connect = pl_connect;
    g_pl_ops.take = pl_take;
    g_pl_ops.close = pl_close;
    g_pl_ops.clear = pl_clear;
    g_pl_ops.fd = pl_fd;
    g_pl_ops.has_data = pl_has_data;
    g_pl_ops.flow_open = pl_flow_open;
    g_pl_ops.send = pl_send;
    g_pl_ops.room = pl_room;
    g_pl_ops.dgram_frame = pl_dgram_frame;
    g_pl_ops.read = pl_read;
    g_pl_ops.deliver = pl_deliver;
    g_pl_ops.peer_of = pl_peer_of;
    g_pl_ops.match = pl_match;
    g_pl_ops.stale = pl_stale;
    g_pl_ops.lost = pl_lost;

    /* The stack keeps the pointer until the process ends. */
    static struct dialer d;
    d.ops = &g_pl_ops;
    d.ctx = &g_pl;
    d.silence_s = pc->silence_s;
    return &d;
}

int pool_run(const struct tun_cfg *tc, const struct pool_cfg *pc, stack_ready_fn ready, void *arg) {
    const struct dialer *d = pool_setup(pc);
    if (!d) return 1;
    static struct pl_ready r;
    r.ready = ready;
    r.arg = arg;
    return stack_run(tc, d, pl_ready_cb, &r);
}

int pool_select(const int *c, size_t n) {
    struct pl_sel *sel = pl_sel_new(c, n);
    if (!sel) return -1;
    const char *gone[64];
    int ng = 0, drained = 0;
    uint64_t now = pl_now_ms();
    pthread_mutex_lock(&g_pl.mu);
    sel->old = g_pl.sel;
    g_pl.sel = sel;
    int want = (size_t)g_pl.cf.active < n ? g_pl.cf.active : (int)n;
    if (want > g_pl.n) g_pl.n = want;
    for (int i = 0; i < g_pl.n; i++) {
        struct pl_slot *sl = &g_pl.slot[i];
        if (sl->node >= 0 && !pl_in(sel, sl->node)) {
            if (ng < 64) gone[ng++] = g_pl.cf.proto->name(pl_node(sl->node));
            __atomic_store_n(&sl->drained[sl->drained_n++ % PL_DRAINED], sl->gen + 1, __ATOMIC_RELAXED);
            sl->node = -1;
            sl->up = 0;
            sl->fails = sl->streak = sl->kick = sl->lost = 0;
            __atomic_add_fetch(&sl->gen, 1, __ATOMIC_RELEASE);
            drained++;
        }
        if (sl->node < 0 || !sl->up) {
            sl->retry = PL_RETRY_S;
            sl->due = now;
        }
    }
    if (drained) g_pl.pub = 1;
    pthread_cond_signal(&g_pl.cv);
    pthread_mutex_unlock(&g_pl.mu);
    for (int k = 0; k < ng; k++)
        fprintf(stderr, PL_LOG_I "node %s left the list — its connections stay on it until they end\n",
                gone[k]);
    if (drained) stack_nodes_changed();
    return drained;
}
