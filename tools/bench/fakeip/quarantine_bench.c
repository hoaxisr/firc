#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "firc/fakeip.h"

static firc_fakeip_cfg_t cfg(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.base.b[2] = 0x9a;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = 400000;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    return c;
}

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Steady state: every name already mapped, so the sticky-mapping fast path answers. */
static void bench_repeat(firc_fakeip_t *f, int n) {
    firc_ip_t a, b;
    char name[64];
    double t0 = now_s();
    for (int i = 0; i < n; i++) {
        snprintf(name, sizeof(name), "a%d.example.com", i);
        (void)firc_fakeip_get(f, name, "g1", 2000, &a, &b);
    }
    double dt = now_s() - t0;
    printf("repeat N=%-7d %8.3f s  %7.2f us/query\n", n, dt, dt * 1e6 / n);
}

int main(int argc, char **argv) {
    int n = (argc > 1) ? atoi(argv[1]) : 10000;
    bool repeat = (argc > 2 && argv[2][0] == 'r');
    firc_fakeip_cfg_t c = cfg();
    firc_fakeip_t *f = NULL;
    firc_ip_t a, b;
    char name[64];

    if (firc_fakeip_new(&c, &f) != FIRC_OK) {
        fprintf(stderr, "firc_fakeip_new failed\n");
        return 1;
    }
    for (int i = 0; i < n; i++) {
        snprintf(name, sizeof(name), "a%d.example.com", i);
        (void)firc_fakeip_get(f, name, "g1", 1000, &a, &b);
    }
    if (repeat) {
        bench_repeat(f, n);
        firc_fakeip_free(f);
        return 0;
    }
    firc_fakeip_reclaim(f, 1000 + 86400 + 1); /* n addresses now parked */

    /* Past 129794 names the pool refuses, and refusals skip the quarantine: count them. */
    int refused = 0;
    double t0 = now_s();
    for (int i = 0; i < n; i++) {
        snprintf(name, sizeof(name), "b%d.example.com", i);
        if (firc_fakeip_get(f, name, "g1", 1000 + 86400 + 1, &a, &b) != FIRC_OK) { refused++; }
    }
    double dt = now_s() - t0;

    printf("N=%-7d %8.3f s  %7.1f us/query  refused=%d\n", n, dt, dt * 1e6 / n, refused);
    firc_fakeip_free(f);
    return 0;
}
