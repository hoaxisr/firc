#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "unit.h"
#include "tscratch.h"

void *__real_calloc(size_t k, size_t n);
void __real_free(void *p);
int __real_pthread_key_create(pthread_key_t *k, void (*d)(void *));
int __real_pthread_setspecific(pthread_key_t k, const void *v);

static size_t g_watch, g_fail;
#define FT 64
static pthread_mutex_t g_fm = PTHREAD_MUTEX_INITIALIZER;
static void *g_got[FT][TS_N];
static int g_seen[FT][TS_N];
static int g_freed;
static void *g_one;
static int g_one_freed;
static int g_watched, g_key_fails, g_set_fails;

void *__wrap_calloc(size_t k, size_t n) {
    if (g_fail && k * n == g_fail) return NULL;
    void *p = __real_calloc(k, n);
    if (g_watch && k * n == g_watch) {
        __atomic_fetch_add(&g_watched, 1, __ATOMIC_SEQ_CST);
        pthread_mutex_lock(&g_fm);
        g_one = p;
        pthread_mutex_unlock(&g_fm);
    }
    return p;
}

int __wrap_pthread_key_create(pthread_key_t *k, void (*d)(void *)) {
    if (!g_key_fails) return __real_pthread_key_create(k, d);
    __real_pthread_key_create(k, d);
    return EAGAIN;
}

int __wrap_pthread_setspecific(pthread_key_t k, const void *v) {
    return g_set_fails ? ENOMEM : __real_pthread_setspecific(k, v);
}

void __wrap_free(void *p) {
    if (p) {
        pthread_mutex_lock(&g_fm);
        if (p == g_one) g_one_freed++;
        for (int t = 0; t < FT; t++)
            for (int s = 0; s < TS_N; s++)
                if (g_got[t][s] == p && !g_seen[t][s]) { g_seen[t][s] = 1; g_freed++; goto done; }
done:
        pthread_mutex_unlock(&g_fm);
    }
    __real_free(p);
}

static void run(void *(*f)(void *), void *a) {
    pthread_t t;
    if (pthread_create(&t, NULL, f, a) == 0) pthread_join(t, NULL);
}

static void *same_one(void *a) {
    void **r = a;
    r[0] = ts_get(TS_H2, 64);
    r[1] = ts_get(TS_H2, 64);
    return NULL;
}

static void t_ts_same_on_one_thread(void) {
    /* catches: a fresh block per call (a leak and lost state) */
    void *r[2] = { NULL, NULL };
    run(same_one, r);
    check("one thread: a block", 1, r[0] != NULL);
    check("one thread: the same block twice", 1, r[0] != NULL && r[0] == r[1]);
}

#define PT 8
#define PN 4096
static pthread_barrier_t g_bar;
struct per { int k; unsigned char *p; int whole; };

static void *per_one(void *a) {
    struct per *w = a;
    w->p = ts_get(TS_H2MUX, PN);
    if (w->p) memset(w->p, w->k + 1, PN);
    pthread_barrier_wait(&g_bar);
    w->whole = w->p != NULL;
    for (int i = 0; w->p && i < PN; i++)
        if (w->p[i] != w->k + 1) { w->whole = 0; break; }
    pthread_barrier_wait(&g_bar);
    return NULL;
}

static void t_ts_per_thread(void) {
    /* catches: a plain static instead of __thread: threads share one scratch */
    struct per w[PT];
    pthread_t t[PT];
    int up = 0, whole = 0, distinct = 1;
    pthread_barrier_init(&g_bar, NULL, PT);
    for (int i = 0; i < PT; i++) {
        w[i] = (struct per){ .k = i };
        if (pthread_create(&t[i], NULL, per_one, &w[i]) == 0) up++;
    }
    for (int i = 0; i < up; i++) pthread_join(t[i], NULL);
    pthread_barrier_destroy(&g_bar);
    for (int i = 0; i < PT; i++) {
        whole += w[i].whole;
        for (int j = 0; j < i; j++)
            if (w[i].p == w[j].p) distinct = 0;
    }
    check("per thread: 8 threads ran", PT, up);
    check("per thread: each block still holds its own index", PT, whole);
    check("per thread: 8 distinct blocks", 1, distinct);
}

#define ZN 65536
struct zero { int fill; int zero; int calls; };

static void *zero_one(void *a) {
    struct zero *z = a;
    int before = __atomic_load_n(&g_watched, __ATOMIC_SEQ_CST);
    unsigned char *p = ts_get(TS_XCONN, ZN);
    z->calls = __atomic_load_n(&g_watched, __ATOMIC_SEQ_CST) - before;
    z->zero = p != NULL;
    for (int i = 0; p && i < ZN; i++)
        if (p[i]) { z->zero = 0; break; }
    if (p && z->fill) memset(p, 0xff, ZN);
    return NULL;
}

static void t_ts_zeroed(void) {
    /* catches: malloc instead of calloc: state that relied on zeroed TLS starts as garbage */
    struct zero a = { 0 }, b = { .fill = 1 }, c = { 0 };
    g_watch = ZN;
    run(zero_one, &a);
    run(zero_one, &b);
    run(zero_one, &c);
    g_watch = 0;
    check("zeroed: one calloc of the slot's size", 1, a.calls);
    check("zeroed: the block reads all zero", 1, a.zero);
    check("zeroed: after a thread wrote 0xff and exited, still zero", 1, c.zero);
}

static void *nokey_one(void *a) {
    void **r = a;
    r[0] = ts_get(TS_WS, 512);
    return NULL;
}

static void t_ts_no_key_no_block(void) {
    /* catches: a block kept without a destructor (a leak per thread) */
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        void *r[1] = { NULL };
        g_key_fails = 1;
        g_watch = 512;
        run(nokey_one, r);
        pthread_mutex_lock(&g_fm);
        int code = (r[0] != NULL) | (g_watched == 1 ? 0 : 2) | (g_one && g_one_freed == 1 ? 0 : 4);
        pthread_mutex_unlock(&g_fm);
        _exit(code);
    }
    int st = 0;
    int code = pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st) ? WEXITSTATUS(st) : 0xff;
    check("no key: ts_get gives NULL", 0, code & 1);
    check("no key: the block was allocated", 0, code & 2);
    check("no key: the block was freed", 0, code & 4);
}

static void *every_slot(void *a) {
    int t = (int)(intptr_t)a;
    for (int s = 0; s < TS_N; s++) {
        void *p = ts_get((enum ts_slot)s, (size_t)(s + 1) * 1024);
        pthread_mutex_lock(&g_fm);
        g_got[t][s] = p;
        pthread_mutex_unlock(&g_fm);
    }
    return NULL;
}

static void t_ts_freed_at_exit(void) {
    /* catches: no destructor, or one that frees the array but not the blocks */
    pthread_t th[FT];
    int up = 0, got = 0;
    for (int t = 0; t < FT; t++)
        if (pthread_create(&th[t], NULL, every_slot, (void *)(intptr_t)t) == 0) up++;
    for (int t = 0; t < up; t++) pthread_join(th[t], NULL);
    pthread_mutex_lock(&g_fm);
    for (int t = 0; t < FT; t++)
        for (int s = 0; s < TS_N; s++) got += g_got[t][s] != NULL;
    int freed = g_freed;
    memset(g_got, 0, sizeof g_got);
    pthread_mutex_unlock(&g_fm);
    check("at exit: 64 threads ran", FT, up);
    check("at exit: every slot of every thread got a block", FT * TS_N, got);
    check("at exit: every block freed once", FT * TS_N, freed);
}

static void *retry_one(void *a) {
    void **r = a;
    g_fail = 128;
    r[0] = ts_get(TS_GRPC, 128);
    g_fail = 0;
    r[1] = ts_get(TS_GRPC, 128);
    r[2] = ts_get(TS_GRPC, 128);
    return NULL;
}

static void t_ts_failure_retries(void) {
    /* catches: a cached failure (the thread loses the transport for good) or a crash on NULL */
    void *r[3] = { (void *)1, NULL, NULL };
    run(retry_one, r);
    check("retry: a failed allocation gives NULL", 1, r[0] == NULL);
    check("retry: the next call gets a block", 1, r[1] != NULL);
    check("retry: the third call the same block", 1, r[1] != NULL && r[1] == r[2]);
}

static void *noset_one(void *a) {
    void **r = a;
    g_set_fails = 1;
    r[0] = ts_get(TS_VENC, 768);
    g_set_fails = 0;
    r[1] = ts_get(TS_VENC, 768);
    return NULL;
}

static void t_ts_setspecific_fails(void) {
    /* catches: a block kept, or handed out, when its destructor could not be registered */
    void *r[2] = { (void *)1, NULL };
    pthread_mutex_lock(&g_fm);
    g_one = NULL;
    g_one_freed = 0;
    pthread_mutex_unlock(&g_fm);
    int before = __atomic_load_n(&g_watched, __ATOMIC_SEQ_CST);
    g_watch = 768;
    run(noset_one, r);
    g_watch = 0;
    pthread_mutex_lock(&g_fm);
    int freed = g_one_freed;
    pthread_mutex_unlock(&g_fm);
    check("no setspecific: ts_get gives NULL", 1, r[0] == NULL);
    check("no setspecific: two blocks asked for", 2, __atomic_load_n(&g_watched, __ATOMIC_SEQ_CST) - before);
    check("no setspecific: the first freed, then the second at thread exit", 2, freed);
    check("no setspecific: the next call gets a block", 1, r[1] != NULL);
}

int main(void) {
    t_ts_no_key_no_block();
    t_ts_same_on_one_thread();
    t_ts_per_thread();
    t_ts_zeroed();
    t_ts_freed_at_exit();
    t_ts_failure_retries();
    t_ts_setspecific_fails();
    return unit_done("tscratchmatch");
}
