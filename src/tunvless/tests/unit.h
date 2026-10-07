/* Shared frame of the unit tests: counters, check()/check_str()/check_mem()/check_hex() and one
 * summary line. A test includes "unit.h", checks with these and ends main() with
 * `return unit_done("test_name");`.
 *
 * A test whose check() differs in any way (column width, wording, argument order, substring
 * instead of equality) keeps its own copy: it is a different check under the same name.
 *
 * Prefer linking the module under test as a separate .c over #include "../src/....c": including
 * merges two translation units, so static names leak between them, and an undefined reference
 * the real build would hit goes unnoticed. */
#ifndef STEER_TESTS_UNIT_H
#define STEER_TESTS_UNIT_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int unit_pass, unit_fail;

static inline void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "FAIL");
    if (want == got) { unit_pass++; return; }
    unit_fail++;
    printf("     want: %ld\n     got:  %ld\n", want, got);
}

static inline void check_str(const char *what, const char *want, const char *got) {
    printf("%-62s %s\n", what, strcmp(want, got) == 0 ? "ok" : "FAIL");
    if (strcmp(want, got) == 0) { unit_pass++; return; }
    unit_fail++;
    printf("     want: \"%s\"\n     got:  \"%s\"\n", want, got);
}

static inline void check_mem(const char *what, const void *want, const void *got, size_t n) {
    int eq = memcmp(want, got, n) == 0;
    printf("%-62s %s\n", what, eq ? "ok" : "FAIL");
    if (eq) { unit_pass++; return; }
    unit_fail++;
    printf("     want:");
    for (size_t i = 0; i < n; i++) printf(" %02x", ((const uint8_t *)want)[i]);
    printf("\n     got: ");
    for (size_t i = 0; i < n; i++) printf(" %02x", ((const uint8_t *)got)[i]);
    printf("\n");
}

/* want — a hex string (lower case, no separators); b/n — raw bytes. */
static inline void check_hex(const char *what, const char *want, const uint8_t *b, size_t n) {
    char got[160];
    for (size_t i = 0; i < n; i++) sprintf(got + i * 2, "%02x", b[i]);
    printf("%-62s %s\n", what, strcmp(want, got) == 0 ? "ok" : "FAIL");
    if (strcmp(want, got) == 0) { unit_pass++; return; }
    unit_fail++;
    printf("     want: %s\n     got:  %s\n", want, got);
}

static inline int unit_done(const char *name) {
    printf("\n%s: %d passed, %d failed\n", name, unit_pass, unit_fail);
    return unit_fail ? 1 : 0;
}

#endif
