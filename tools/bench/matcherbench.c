#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "firc/match.h"

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    size_t n = argc > 1 ? strtoul(argv[1], NULL, 10) : 10000;
    int wide = argc > 2 ? atoi(argv[2]) : 0; /* 1: spread over many suffixes */
    int borrow = argc > 3 ? atoi(argv[3]) : 0; /* 1: borrowed names, as lists add them */

    char **names = malloc(n * sizeof(char *));
    for (size_t i = 0; i < n; i++) {
        char buf[128];
        if (wide) {
            snprintf(buf, sizeof(buf), "n%zu.ads%zu.example%zu.com", i, i % 13, i % 4096);
        } else {
            snprintf(buf, sizeof(buf), "n%zu.ads%zu.example.com", i, i % 13);
        }
        names[i] = strdup(buf);
    }

    double t0 = now();
    firc_matcher_t *m = firc_matcher_new();
    for (size_t i = 0; i < n; i++) {
        firc_err_t (*add_fn)(firc_matcher_t *, const char *, const char *) =
            borrow ? firc_matcher_add_borrowed : firc_matcher_add;
        if (add_fn(m, "namespace", names[i]) != FIRC_OK) { return 1; }
    }
    double t1 = now();

    size_t hits = 0;
    for (size_t i = 0; i < n && i < 20000; i++) {
        if (firc_matcher_match(m, names[i])) { hits++; }
    }
    double t2 = now();

    printf("n=%-8zu wide=%d borrow=%d  build=%7.3f s  match=%7.3f s (%zu lookups)\n",
           n, wide, borrow, t1 - t0, t2 - t1, n < 20000 ? n : 20000);
    (void)hits;
    firc_matcher_free(m);
    return 0;
}
