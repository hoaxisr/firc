#define _GNU_SOURCE
#include "unit.h"
#include "../src/proto/transport/trdial.c"
#include "nodes.h"
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

struct tn { char name[16]; int v; };

static unsigned g_resolves;
static int g_now_in, g_max_in, g_delay_ms;
static unsigned fake_resolve(const char *host, struct in_addr out[ADDR_MAX]) {
    __atomic_add_fetch(&g_resolves, 1, __ATOMIC_RELAXED);
    if (host[0] == 'd') {
        int in = __atomic_add_fetch(&g_now_in, 1, __ATOMIC_ACQ_REL);
        int m = __atomic_load_n(&g_max_in, __ATOMIC_ACQUIRE);
        while (in > m && !__atomic_compare_exchange_n(&g_max_in, &m, in, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) { }
        struct timespec ts = { 0, (long)__atomic_load_n(&g_delay_ms, __ATOMIC_ACQUIRE) * 1000000L };
        nanosleep(&ts, NULL);
        __atomic_sub_fetch(&g_now_in, 1, __ATOMIC_ACQ_REL);
        out[0].s_addr = htonl(0x0b000001u);
        return 1;
    }
    if (!strcmp(host, "bad")) return 0;
    if (!strcmp(host, "slow")) {
        struct timespec ts = { 0, 600000000 };
        nanosleep(&ts, NULL);
        out[0].s_addr = htonl(0x0a0000feu);
        return 1;
    }
    out[0].s_addr = htonl(0x0a000000u + (uint32_t)atoi(host + 1));
    return 1;
}

static int64_t ms_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

struct seen { char host[32][16]; int ok[32]; int n; };
static void on_pin(void *ud, const char *host, int ok) {
    struct seen *s = ud;
    if (s->n >= 32) return;
    snprintf(s->host[s->n], sizeof s->host[0], "%s", host);
    s->ok[s->n++] = ok;
}
static int seen_ok(const struct seen *s, const char *host) {
    for (int i = 0; i < s->n; i++)
        if (!strcmp(s->host[i], host)) return s->ok[i];
    return -1;
}

static int g_stop_after;
static int stop_once(void *ud) {
    const struct seen *s = ud;
    return s->n >= g_stop_after;
}

static volatile int g_stop;
static int g_torn;
static void *pin_reader(void *arg) {
    (void)arg;
    char h[16];
    unsigned k = 0;
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) {
        snprintf(h, sizeof h, "h%u", k++ % 400);
        uint32_t a[4];
        int n = transport_pinned_addrs(h, a, 4);
        if (n && (n != 1 || a[0] != htonl(0x0a000000u + (uint32_t)atoi(h + 1)))) g_torn = 1;
    }
    return NULL;
}

static int g_store_torn, g_base;
static void *store_reader(void *arg) {
    (void)arg;
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) {
        int n = nodes_count();
        if (n <= g_base) continue;
        const struct tn *t = node_at(n - 1);
        if (t->v != n - 1) g_store_torn = 1;
    }
    return NULL;
}

int main(void) {
    nodes_init(sizeof(struct tn));
    struct tn a = { "a", 0 }, b = { "b", 1 };
    int ia = nodes_add(&a, "link-a");
    int ib = nodes_add(&b, "link-b");
    int ia2 = nodes_add(&a, "link-a");
    /* catches: a link seen again stored as a new node */
    check("store: same link, same index", 1, ia == 0 && ib == 1 && ia2 == 0);
    check("store: a repeated link does not grow it", 2, nodes_count());
    /* catches: identity taken from the node's content instead of the link */
    check("store: another link with equal content is a new node", 2, nodes_add(&a, "link-a2"));
    /* catches: nodes without a link merged into one */
    check("store: nodes without a link never merge", 1, nodes_add(&a, NULL) != nodes_add(&a, NULL));
    check("store: find by link", 1, nodes_find("link-b") == 1 && nodes_find("nope") == -1);
    const struct tn *p0 = node_at(0);
    g_base = nodes_count();
    pthread_t rt;
    __atomic_store_n(&g_stop, 0, __ATOMIC_RELEASE);
    pthread_create(&rt, NULL, store_reader, NULL);
    int ok = 1;
    for (int i = nodes_count(); i < 1000; i++) {
        struct tn t = { "x", i };
        if (nodes_add(&t, NULL) != i) ok = 0;
    }
    __atomic_store_n(&g_stop, 1, __ATOMIC_RELEASE);
    pthread_join(rt, NULL);
    /* catches: a store that moves its nodes as it grows */
    check("store: node 0 stays where it was after 1000 more", 1, ok && node_at(0) == p0 && p0->v == 0);
    /* catches: a node published before its content is written */
    check("store: a reader never sees a node half written", 0, g_store_torn);
    check("store: node 999 readable", 999, ((const struct tn *)node_at(999))->v);
    const char *s1 = nodes_intern("abc", 3), *s2 = nodes_intern("abcd", 3), *s3 = nodes_intern("abd", 3);
    /* catches: equal values stored twice, or different ones merged */
    check("intern: equal values share one copy", 1, s1 && s1 == s2 && !strcmp(s1, "abc"));
    check("intern: a different value is another copy", 1, s3 && s3 != s1 && !strcmp(s3, "abd"));

    g_resolve = fake_resolve;
    __atomic_store_n(&g_stop, 0, __ATOMIC_RELEASE);
    pthread_create(&rt, NULL, pin_reader, NULL);
    char h[16];
    for (int i = 0; i < 400; i++) {
        snprintf(h, sizeof h, "h%d", i);
        transport_pin_host(h);
    }
    __atomic_store_n(&g_stop, 1, __ATOMIC_RELEASE);
    pthread_join(rt, NULL);
    /* catches: a pin entry seen by a reader before it is complete */
    check("pin: a concurrent reader never sees a torn entry", 0, g_torn);
    uint32_t addr[4];
    check("pin: h399 pinned", 1, transport_pinned_addrs("h399", addr, 4) == 1 && addr[0] == htonl(0x0a00018fu));

    struct seen sn;
    memset(&sn, 0, sizeof sn);
    unsigned before = g_resolves;
    const char *hosts[] = { "h400", "slow", "bad", "h7", "h401" };
    int64_t t0 = ms_now();
    transport_pin_hosts(hosts, 5, 200, on_pin, NULL, &sn);
    int64_t took = ms_now() - t0;
    /* catches: a slow name holding the whole command past its timeout */
    check("pin hosts: a slow name times out", 1, took < 500 && seen_ok(&sn, "slow") == 0);
    check("pin hosts: every host answered once", 5, sn.n);
    /* catches: an unresolvable name reported as pinned */
    check("pin hosts: resolved names ok, a failed one not", 1,
          seen_ok(&sn, "h400") == 1 && seen_ok(&sn, "h401") == 1 && seen_ok(&sn, "bad") == 0);
    /* catches: an already pinned name resolved again */
    check("pin hosts: a pinned name is not resolved again", 1, seen_ok(&sn, "h7") == 1 && g_resolves - before == 4);
    check("pin hosts: new names are pinned", 1,
          transport_pinned_addrs("h401", addr, 4) == 1 && addr[0] == htonl(0x0a000191u));
    check("pin hosts: the timed out name is not", 0, transport_pinned_addrs("slow", addr, 4));
    const char *twice[] = { "h500", "h500" };
    unsigned pins = g_pin_n;
    memset(&sn, 0, sizeof sn);
    transport_pin_hosts(twice, 2, 200, on_pin, NULL, &sn);
    /* catches: one name pinned twice when it comes twice */
    check("pin hosts: a name given twice is pinned once", 1, g_pin_n - pins == 1 && sn.n == 2 && sn.ok[0] && sn.ok[1]);
    struct timespec ts = { 0, 700000000 };
    nanosleep(&ts, NULL);
    check("pin hosts: a late answer is dropped", 0, transport_pinned_addrs("slow", addr, 4));

    const char *wave[20];
    char wn[20][8];
    for (int i = 0; i < 20; i++) { snprintf(wn[i], sizeof wn[i], "d%d", i); wave[i] = wn[i]; }
    __atomic_store_n(&g_delay_ms, 100, __ATOMIC_RELEASE);
    memset(&sn, 0, sizeof sn);
    t0 = ms_now();
    transport_pin_hosts(wave, 20, 1000, on_pin, NULL, &sn);
    took = ms_now() - t0;
    int okn = 0;
    for (int i = 0; i < sn.n; i++) okn += sn.ok[i] > 0;
    /* catches: one thread per name without bound, or one name at a time */
    check("pin wave: at most 16 names at once, more than one", 1, g_max_in <= 16 && g_max_in > 1);
    check("pin wave: twenty names in two rounds", 1, okn == 20 && took < 450);
    for (int i = 0; i < 20; i++) { snprintf(wn[i], sizeof wn[i], "d%d", 100 + i); wave[i] = wn[i]; }
    __atomic_store_n(&g_delay_ms, 300, __ATOMIC_RELEASE);
    memset(&sn, 0, sizeof sn);
    t0 = ms_now();
    transport_pin_hosts(wave, 20, 500, on_pin, NULL, &sn);
    took = ms_now() - t0;
    okn = 0;
    for (int i = 0; i < sn.n; i++) okn += sn.ok[i] > 0;
    /* catches: queued names given a deadline of their own */
    check("pin wave: queued names share the one deadline", 1, okn == 16 && sn.n == 20 && took < 700);
    nanosleep(&(struct timespec){ 0, 400000000 }, NULL);
    for (int i = 0; i < 3; i++) { snprintf(wn[i], sizeof wn[i], "d%d", 200 + i); wave[i] = wn[i]; }
    __atomic_store_n(&g_delay_ms, 50, __ATOMIC_RELEASE);
    memset(&sn, 0, sizeof sn);
    g_stop_after = 1;
    transport_pin_hosts(wave, 3, 1000, on_pin, stop_once, &sn);
    /* catches: a wave going on after its caller lost interest */
    check("pin wave: a stop ends it without more answers", 1, sn.n == 1);
    nanosleep(&(struct timespec){ 0, 200000000 }, NULL);

    for (int i = 900; g_pin_n < PIN_MAX - 1; i++) {
        snprintf(h, sizeof h, "h%d", i);
        transport_pin_host(h);
    }
    const char *last2[] = { "h3001", "h3002" };
    memset(&sn, 0, sizeof sn);
    transport_pin_hosts(last2, 2, 500, on_pin, NULL, &sn);
    /* catches: the name that found the table full told as one that does not resolve */
    check("pin hosts: the one name past the last place answers full", 1,
          sn.n == 2 && ((sn.ok[0] > 0 && sn.ok[1] == TR_EPINFULL) || (sn.ok[1] > 0 && sn.ok[0] == TR_EPINFULL)));
    int full = 0, other = 0;
    for (int i = 1000; i < 1600; i++) {
        snprintf(h, sizeof h, "h%d", i);
        int rc = transport_pin_host(h);
        if (rc == TR_EPINFULL) full++;
        else if (rc < 0) other++;
    }
    /* catches: pins written past the table, or a full table told as a failed name */
    check("pin: past the table, names are refused as full", 1, full == 600 && !other);
    unsigned rs = g_resolves;
    /* catches: a name resolved for nothing when there is no room to pin it */
    check("pin: a full table does not resolve", 1, transport_pin_host("h2999") == TR_EPINFULL && g_resolves == rs);
    memset(&sn, 0, sizeof sn);
    const char *more[] = { "h2000" };
    transport_pin_hosts(more, 1, 200, on_pin, NULL, &sn);
    /* catches: names still resolved, or told as unresolvable, with no room to pin them */
    check("pin hosts: a full table answers full without resolving", 1,
          sn.n == 1 && sn.ok[0] == TR_EPINFULL && g_resolves == rs);
    return unit_done("nodesmatch");
}
