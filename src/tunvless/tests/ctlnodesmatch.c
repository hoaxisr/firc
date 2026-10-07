#define _GNU_SOURCE
#include "unit.h"
#include "../src/proto/transport/trdial.c"
#include "../src/ctlnodes.h"
#include "nodes.h"
#include "vless.h"
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#define UUID "b831381d-6324-4d53-ad4f-8cda48b30811"

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_release[8], g_holding[8];

static unsigned fake_resolve(const char *host, struct in_addr out[ADDR_MAX]) {
    if (!strncmp(host, "bad", 3)) return 0;
    if (!strncmp(host, "hold", 4)) {
        int k = host[4] - '0';
        pthread_mutex_lock(&g_mu);
        g_holding[k] = 1;
        pthread_cond_broadcast(&g_cv);
        while (!g_release[k]) pthread_cond_wait(&g_cv, &g_mu);
        pthread_mutex_unlock(&g_mu);
    }
    out[0].s_addr = htonl(0x0a000001u);
    return 1;
}

static void release(int k) {
    pthread_mutex_lock(&g_mu);
    g_release[k] = 1;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

struct pub { int n; int c[8]; };
static struct pub g_pub[32];
static int g_pub_n, g_acks[16], g_ack_n, g_full;
static int64_t g_ack_ms[16];

static int64_t ms_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int on_select(const int *sel, size_t n) {
    pthread_mutex_lock(&g_mu);
    if (g_pub_n < 32) {
        g_pub[g_pub_n].n = (int)n;
        for (size_t i = 0; i < n && i < 8; i++) g_pub[g_pub_n].c[i] = sel[i];
        g_pub_n++;
    }
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
    return 0;
}

static void on_ack(int count) {
    pthread_mutex_lock(&g_mu);
    if (g_ack_n < 16) { g_ack_ms[g_ack_n] = ms_now(); g_acks[g_ack_n++] = count; }
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static void on_full(void) {
    pthread_mutex_lock(&g_mu);
    g_full++;
    pthread_mutex_unlock(&g_mu);
}

static int wait_for(int *counter, int want, int ms) {
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += ms / 1000;
    dl.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&g_mu);
    while (*counter < want)
        if (pthread_cond_timedwait(&g_cv, &g_mu, &dl) != 0) break;
    int got = *counter;
    pthread_mutex_unlock(&g_mu);
    return got;
}

static void settle(void) {
    struct timespec ts = { 0, 300000000 };
    nanosleep(&ts, NULL);
}

static int g_wfd = -1;
static void *reader(void *arg) {
    ctln_read(arg);
    return NULL;
}

static void put(const char *s) {
    if (write(g_wfd, s, strlen(s)) != (ssize_t)strlen(s)) abort();
}

static void link_of(char *out, size_t n, const char *host, const char *name) {
    snprintf(out, n, "vless://" UUID "@%s:443?security=none&type=tcp#%s\n", host, name);
}

static void cmd(const char *const *hosts, int n) {
    char buf[4096] = "nodes\n", l[256];
    for (int i = 0; i < n; i++) {
        link_of(l, sizeof l, hosts[i], hosts[i]);
        strcat(buf, l);
    }
    strcat(buf, "\n");
    put(buf);
}

static int idx_of(const char *host) {
    char l[256];
    link_of(l, sizeof l, host, host);
    l[strlen(l) - 1] = 0;
    return nodes_find(l);
}

static int pub_is(int k, int n, const int *c) {
    pthread_mutex_lock(&g_mu);
    int ok = k < g_pub_n && g_pub[k].n == n;
    for (int i = 0; ok && i < n; i++) ok = g_pub[k].c[i] == c[i];
    pthread_mutex_unlock(&g_mu);
    return ok;
}

int main(void) {
    g_resolve = fake_resolve;
    nodes_init(sizeof(struct vless_node));
    transport_pin_host("pinned1");
    transport_pin_host("pinned2");
    static const struct ctln_hooks h = { on_select, on_ack, on_full, 2000 };
    check("resolver thread started", 0, ctln_start(&h));
    int p[2];
    if (pipe(p) != 0) return 2;
    g_wfd = p[1];
    FILE *in = fdopen(p[0], "r");
    pthread_t rt;
    pthread_create(&rt, NULL, reader, in);

    cmd((const char *[]){ "hold1", "bad1" }, 2);
    check("ack: one per command, with the usable count", 2, wait_for(&g_ack_n, 1, 1000) == 1 ? g_acks[0] : -1);
    settle();
    /* catches: an empty or partial set published before any of its nodes resolves */
    check("nothing pinned yet: nothing published", 0, g_pub_n);
    release(1);
    wait_for(&g_pub_n, 1, 2000);
    settle();
    int a1 = idx_of("hold1");
    /* catches: the resolved node not published, or published twice */
    check("published once the node resolves", 1, g_pub_n == 1 && pub_is(0, 1, &a1));

    cmd((const char *[]){ "bad2", "bad3" }, 2);
    wait_for(&g_pub_n, 2, 2000);
    /* catches: a command whose names all fail leaving the old set active */
    check("nothing resolves: the empty set is published", 1, pub_is(1, 0, NULL));

    cmd((const char *[]){ "pinned1", "hold2", "hold3" }, 3);
    wait_for(&g_pub_n, 3, 2000);
    int p1 = idx_of("pinned1"), h2 = idx_of("hold2"), h3 = idx_of("hold3");
    /* catches: pinned nodes waiting for the new names */
    check("pinned nodes are published first", 1, pub_is(2, 1, &p1));
    release(3);
    wait_for(&g_pub_n, 4, 2000);
    release(2);
    wait_for(&g_pub_n, 5, 2000);
    /* catches: a resolved host not republished, or the order taken from resolution */
    check("each resolved host republishes, in command order", 1,
          pub_is(3, 2, (int[]){ p1, h3 }) && pub_is(4, 3, (int[]){ p1, h2, h3 }));

    int pubs = g_pub_n, acks = g_ack_n;
    int64_t t0 = ms_now();
    cmd((const char *[]){ "hold4" }, 1);
    wait_for(&g_holding[4], 1, 1000);
    cmd((const char *[]){ "pinned2" }, 1);
    wait_for(&g_ack_n, acks + 2, 1000);
    /* catches: an ack waiting behind the previous command's resolution */
    check("two commands back to back: both acks at once", 1,
          g_ack_n == acks + 2 && g_ack_ms[acks + 1] - t0 < 500);
    wait_for(&g_pub_n, pubs + 1, 1500);
    int pp2 = idx_of("pinned2");
    /* catches: the newer set waiting for the older one's names */
    check("the newer set is published while the older one resolves", 1, pub_is(pubs, 1, &pp2));
    release(4);
    settle();
    /* catches: a superseded command published after the newer one */
    check("the superseded set is never published", pubs + 1, g_pub_n);

    pubs = g_pub_n;
    acks = g_ack_n;
    char l[256];
    link_of(l, sizeof l, "pinned1", "eof");
    put("nodes\n");
    put(l);
    for (int i = 0; i < PIN_MAX; i++) {
        char hh[16];
        snprintf(hh, sizeof hh, "fill%d", i);
        transport_pin_host(hh);
    }
    close(g_wfd);
    pthread_join(rt, NULL);
    settle();
    /* catches: a command cut by EOF applied as if complete */
    check("a command cut by EOF: no ack, nothing published", 1, g_ack_n == acks && g_pub_n == pubs);

    if (pipe(p) != 0) return 2;
    g_wfd = p[1];
    in = fdopen(p[0], "r");
    pthread_create(&rt, NULL, reader, in);
    cmd((const char *[]){ "new1", "new2" }, 2);
    wait_for(&g_pub_n, pubs + 1, 2000);
    cmd((const char *[]){ "new3" }, 1);
    wait_for(&g_pub_n, pubs + 2, 2000);
    /* catches: a full pin table reported as names that do not resolve, or reported every time */
    check("pin table full: reported once", 1, g_full);
    check("pin table full: the node is left out", 1, pub_is(pubs, 0, NULL));
    close(g_wfd);
    pthread_join(rt, NULL);
    return unit_done("ctlnodesmatch");
}
