#define _GNU_SOURCE
#include "unit.h"
#include "sub-pq-samples.h"
#include "../src/proto/transport/trdial.c"
#include "../src/ctlnodes.h"
#include "../src/ctlmap.h"
#include "nodes.h"
#include "vless.h"
#include "vlink.h"
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#define UUID "b831381d-6324-4d53-ad4f-8cda48b30811"
#define PBK "K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng"

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_release[8], g_holding[8];

static int g_six_resolves, g_dlpin_resolves;

static unsigned fake_resolve(const char *host, struct tr_ip out[ADDR_MAX]) {
    if (!strncmp(host, "bad", 3)) return 0;
    if (!strncmp(host, "dlpin", 5)) __atomic_add_fetch(&g_dlpin_resolves, 1, __ATOMIC_RELAXED);
    if (!strncmp(host, "six", 3)) {
        __atomic_add_fetch(&g_six_resolves, 1, __ATOMIC_RELAXED);
        memset(&out[0], 0, sizeof out[0]);
        out[0].b[0] = 0x20;
        out[0].b[1] = 0x01;
        out[0].b[2] = 0x0d;
        out[0].b[3] = 0xb8;
        out[0].b[15] = 0x01;
        out[0].v6 = 1;
        return 1;
    }
    if (!strncmp(host, "hold", 4)) {
        int k = host[4] - '0';
        pthread_mutex_lock(&g_mu);
        g_holding[k] = 1;
        pthread_cond_broadcast(&g_cv);
        while (!g_release[k]) pthread_cond_wait(&g_cv, &g_mu);
        pthread_mutex_unlock(&g_mu);
    }
    memset(&out[0], 0, sizeof out[0]);
    out[0].b[0] = 0x0a;
    out[0].b[3] = 0x01;
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
static int g_pub_n, g_acks[16], g_ack_n, g_full, g_map_acks[4], g_map_ack_n;
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

static void on_map_ack(int count) {
    pthread_mutex_lock(&g_mu);
    if (g_map_ack_n < 4) g_map_acks[g_map_ack_n++] = count;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static int g_wake_calls, g_wake_idx[8];
static size_t g_wake_n;
static int on_wake(const int *idx, size_t n) {
    pthread_mutex_lock(&g_mu);
    g_wake_calls++;
    g_wake_n = n;
    for (size_t i = 0; i < n && i < 8; i++) g_wake_idx[i] = idx[i];
    pthread_mutex_unlock(&g_mu);
    return 0;
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

static void link_dl(char *out, size_t n, const char *host, const char *dl_host) {
    snprintf(out, n,
             "vless://" UUID "@%s:443?security=none&type=xhttp&path=%%2Fx&extra=%%7B%%22downloadSettings%%22%%3A%%7B"
             "%%22address%%22%%3A%%22%s%%22%%2C%%22port%%22%%3A443%%2C%%22network%%22%%3A%%22xhttp%%22%%7D%%7D#%s\n",
             host, dl_host, dl_host);
}

static void cmd_dl(const char *host, const char *dl_host) {
    char l[512], buf[600] = "nodes\n";
    link_dl(l, sizeof l, host, dl_host);
    strcat(buf, l);
    strcat(buf, "\n");
    put(buf);
}

static int idx_dl(const char *host, const char *dl_host) {
    char l[512];
    link_dl(l, sizeof l, host, dl_host);
    l[strlen(l) - 1] = 0;
    return nodes_find(l);
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
    transport_pin_host("six1");
    transport_pin_host("dlpin1");
    ctlmap_init(htonl(0xc6120000u), 15);
    static const struct ctln_hooks h = { on_select, on_ack, on_full, 2000, on_map_ack, on_wake };
    check("resolver thread started", 0, ctln_start(&h));
    int p[2];
    if (pipe(p) != 0) return 2;
    g_wfd = p[1];
    FILE *in = fdopen(p[0], "r");
    pthread_t rt;
    pthread_create(&rt, NULL, reader, in);

    put("map\n198.18.0.1 1.2.3.4\n198.18.0.2 -\n\nclose\n198.18.0.0/24\n\nmapall\n198.18.0.3 1.2.3.4\n\n");
    cmd((const char *[]){ "hold1", "bad1" }, 2);
    check("ack: one per command, with the usable count", 2, wait_for(&g_ack_n, 1, 1000) == 1 ? g_acks[0] : -1);
    uint32_t cb[2];
    uint8_t cl[2];
    /* catches: map and close lines read as nodes, or a nodes command read as map lines */
    check("map and mapall acked apart from nodes", 1,
          wait_for(&g_map_ack_n, 2, 1000) == 2 && g_map_acks[0] == 2 && g_map_acks[1] == 1);
    struct cm_real real;
    check("mapall read as mapall", 1, ctlmap_lookup(htonl(0xc6120001u), &real) == CM_NONE &&
          ctlmap_lookup(htonl(0xc6120003u), &real) == CM_REAL);
    check("close posted, not acked", 1,
          ctlmap_take_closes(cb, cl, 2, NULL) == 1 && cb[0] == htonl(0xc6120000u) && cl[0] == 24);
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
    int six_before = g_six_resolves;
    cmd((const char *[]){ "pinned1", "six1", "hold5" }, 3);
    wait_for(&g_pub_n, pubs + 1, 2000);
    settle();
    int s1 = idx_of("six1"), h5 = idx_of("hold5");
    check("an IPv6-only pin is published with the other pinned nodes", 1,
          g_pub_n == pubs + 1 && pub_is(pubs, 2, (int[]){ p1, s1 }));
    release(5);
    wait_for(&g_pub_n, pubs + 2, 2000);
    check("an IPv6-only pin then the resolved node", 1, pub_is(pubs + 1, 3, (int[]){ p1, s1, h5 }));
    check("an IPv6-only pin is not resolved again", six_before, g_six_resolves);

    pubs = g_pub_n;
    char ep[] = "/tmp/ctlnodese-XXXXXX";
    int efd = mkstemp(ep), se = dup(2);
    unlink(ep);
    dup2(efd, 2);
    cmd_dl("pinned2", "bad5");
    wait_for(&g_pub_n, pubs + 1, 2000);
    fflush(stderr);
    dup2(se, 2);
    close(se);
    char err[1024];
    ssize_t ek = pread(efd, err, sizeof err - 1, 0);
    err[ek > 0 ? ek : 0] = 0;
    close(efd);
    /* catches: the download host never pinned, or a node published when only its main host resolves */
    check("a download host that does not resolve: the empty set", 1, pub_is(pubs, 0, NULL));
    check("a download host that does not resolve: named", 1,
          strstr(err, "bad5 does not resolve — left out of the candidates") != NULL);

    pubs = g_pub_n;
    cmd_dl("pinned2", "hold6");
    settle();
    /* catches: the download host never pinned, or a node published when only its main host resolves */
    check("a download host resolving: nothing published", pubs, g_pub_n);
    release(6);
    wait_for(&g_pub_n, pubs + 1, 2000);
    int d6 = idx_dl("pinned2", "hold6");
    check("a download host resolved: the node published", 1, d6 >= 0 && pub_is(pubs, 1, &d6));

    pubs = g_pub_n;
    int dl_before = g_dlpin_resolves;
    cmd_dl("pinned2", "dlpin1");
    wait_for(&g_pub_n, pubs + 1, 1000);
    settle();
    int d1 = idx_dl("pinned2", "dlpin1");
    /* catches: the download host never pinned, or a node published when only its main host resolves */
    check("a pinned download host: published at once", 1, d1 >= 0 && g_pub_n == pubs + 1 && pub_is(pubs, 1, &d1));
    check("a pinned download host: not resolved again", dl_before, g_dlpin_resolves);

    acks = g_ack_n;
    pubs = g_pub_n;
    size_t bcap = 256 * 8192;
    char *big = malloc(bcap);
    size_t bo = (size_t)snprintf(big, bcap, "nodes\n");
    for (int i = 0; i < 256; i++)
        bo += (size_t)snprintf(big + bo, bcap - bo,
                               "vless://" UUID "@pinned1:443?type=xhttp&security=reality&pbk=" PBK "&sid=01&sni=m.example"
                               "&path=%%2Fxp&pqv=%s&encryption=%s&extra=%%7B%%22downloadSettings%%22%%3A%%7B%%22address%%22"
                               "%%3A%%22pinned2%%22%%2C%%22port%%22%%3A443%%2C%%22network%%22%%3A%%22xhttp%%22%%2C%%22security"
                               "%%22%%3A%%22reality%%22%%2C%%22realitySettings%%22%%3A%%7B%%22serverName%%22%%3A%%22rs.example"
                               "%%22%%2C%%22fingerprint%%22%%3A%%22chrome%%22%%2C%%22publicKey%%22%%3A%%22" PBK "%%22%%2C"
                               "%%22shortId%%22%%3A%%22ab%%22%%2C%%22mldsa65Verify%%22%%3A%%22%s%%22%%7D%%7D%%7D#pq%d\n",
                               PQV_KEY, ENC_MLKEM, PQV_KEY, i);
    bo += (size_t)snprintf(big + bo, bcap - bo, "\n");
    put(big);
    free(big);
    wait_for(&g_ack_n, acks + 1, 20000);
    wait_for(&g_pub_n, pubs + 1, 5000);
    /* catches: the nodes command still cut at 1 MiB */
    check("nodes_with_two_pqv_fit: 256 lines over 1 MiB, all taken", 1,
          bo > (1u << 20) && g_ack_n == acks + 1 && g_acks[acks] == 256 && g_pub_n == pubs + 1 && g_pub[pubs].n == 256);

    acks = g_ack_n;
    char w0[256], w1[256], wx[256], wbuf[2048];
    link_of(w0, sizeof w0, "pinned1", "wake0");
    link_of(w1, sizeof w1, "pinned1", "wake1");
    link_of(wx, sizeof wx, "pinned1", "wakex");
    snprintf(wbuf, sizeof wbuf, "nodes\n%s%s\nwake\n%s%s\nnodes\n%s\n", w0, w1, w1, wx, w0);
    put(wbuf);
    wait_for(&g_ack_n, acks + 2, 2000);
    w1[strlen(w1) - 1] = 0;
    int i1 = nodes_find(w1);
    w1[strlen(w1)] = '\n';
    /* catches: a wake read as a node list or the other way round, an unknown link passed as -1, or the empty line not ending it */
    check("t_wake_reads_links", 1,
          i1 >= 0 && g_ack_n == acks + 2 && g_acks[acks] == 2 && g_acks[acks + 1] == 1 && g_wake_calls == 1 &&
              g_wake_n == 1 && g_wake_idx[0] == i1);
    settle();

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

    if (pipe(p) != 0) return 2;
    g_wfd = p[1];
    in = fdopen(p[0], "r");
    pthread_create(&rt, NULL, reader, in);
    acks = g_ack_n;
    int wakes0 = g_wake_calls;
    size_t ocap = VLESS_CTL_NODES_MAX + 8192;
    char *over = malloc(ocap);
    size_t oo = (size_t)snprintf(over, ocap, "wake\n");
    while (oo < VLESS_CTL_NODES_MAX + 1) oo += (size_t)snprintf(over + oo, ocap - oo, "%s", wx);
    oo += (size_t)snprintf(over + oo, ocap - oo, "%s\nnodes\n%s\n", w1, w0);
    char ep2[] = "/tmp/ctlnodeso-XXXXXX";
    int eo = mkstemp(ep2);
    unlink(ep2);
    int se2 = dup(2);
    dup2(eo, 2);
    put(over);
    free(over);
    wait_for(&g_ack_n, acks + 1, 20000);
    fflush(stderr);
    dup2(se2, 2);
    close(se2);
    char oe[4096];
    ssize_t ok2 = pread(eo, oe, sizeof oe - 1, 0);
    oe[ok2 > 0 ? ok2 : 0] = 0;
    close(eo);
    int warned = 0;
    for (const char *q = oe; (q = strstr(q, "wake over")) != NULL; q++) warned++;
    /* catches: a wake read without the size cap, its lines past the cap taken, or the warning repeated */
    check("t_wake_over_cap", 1,
          g_ack_n == acks + 1 && g_wake_calls == wakes0 + 1 && g_wake_n == 0 && warned == 1);
    settle();
    int wakes = g_wake_calls;
    snprintf(wbuf, sizeof wbuf, "wake\n%s", w1);
    put(wbuf);
    close(g_wfd);
    pthread_join(rt, NULL);
    /* catches: a wake cut by EOF applied as if complete */
    check("t_wake_cut_by_eof", wakes, g_wake_calls);
    return unit_done("ctlnodesmatch");
}
