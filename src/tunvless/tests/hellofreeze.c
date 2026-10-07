/* Byte-for-byte stability of the ClientHello: a guard for changes to reality.c.
 *
 * The Chrome fingerprint is what lets a Reality server tell us from a stranger, and a deliberate
 * change to it is checked by a capture next to a real browser. A capture needs a network, a
 * server and eyes; this test needs only a compiler. It does not replace the capture: it catches
 * an UNINTENDED change, an edit "nearby" that leaked into the built Hello unnoticed.
 *
 * The Hello is a function of randomness, time and the cipher order. Randomness comes from a
 * deterministic generator (os_getrandom is redefined by a macro BEFORE the source is included, so
 * the key pair, the extension shuffle and all the noise are covered), time is fixed, and the
 * cipher order, which depends on the CPU, is pinned with STEER_CIPHER.
 *
 * The Hello is really built (X25519 and the authenticator's AES-GCM go through src/lib/scrypto.h),
 * so the test needs the crypto library and runs in `make crypto-test`:
 *
 *     make crypto-test                   # builds it and compares with tests/chello-frozen.h
 *     ./out/tests/hellofreeze --emit > tests/chello-frozen.h   # refreeze
 *
 * Refreeze ONLY together with a capture next to a browser: a freeze records whatever is there and
 * would silently legitimize a broken fingerprint. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
/* The declaration first: the macro below would otherwise rewrite it too. */
#include "osrand.h"

/* Deterministic getrandom. Changing the generator changes the reference, i.e. needs a refreeze. */
static uint64_t prng = 0x123456789ABCDEFull;
static unsigned g_calls;
static void prng_step(void) { prng = prng * 6364136223846793005ull + 1442695040888963407ull; }

/* Why the generator skips 128 bytes.
 *
 * The frozen Hello was made with mbedtls, which blinded each X25519 multiplication (randomized
 * projective coordinates) with bytes from the same source as the rest of the Hello: 64 per
 * multiplication, and building a Hello takes two (the public key, and the secret with the
 * server's pbk). wolfCrypt behind scrypto blinds (where it does: portable C,
 * WOLFSSL_CURVE25519_BLINDING) from ITS OWN generator, so none of that reaches this stream. In
 * real use this changes nothing, but the test's deterministic stream would be 128 bytes off, and
 * every Hello byte after the key (random, GREASE, ECH padding, extension shuffle) would differ
 * though the builder had not changed.
 *
 * So the generator skips those 128 bytes where they were drawn: right after the first call (the
 * 32-byte private key, x25519_keypair), before the second. With the skip the current code gives
 * the frozen Hello byte for byte. If the calls in reality.c move, the test turns red, and it
 * should: such a change needs the same analysis. */
#define MBEDTLS_BLINDING_BYTES 128
static ssize_t det_getrandom(void *buf, size_t n, unsigned int flags) {
    (void)flags;
    if (++g_calls == 2)
        for (int i = 0; i < MBEDTLS_BLINDING_BYTES; i++) prng_step();
    unsigned char *p = buf;
    for (size_t i = 0; i < n; i++) {
        prng_step();
        p[i] = (unsigned char)(prng >> 33);
    }
    return (ssize_t)n;
}
static time_t det_time(time_t *p) { (void)p; return (time_t)1700000000; }

#define os_getrandom(b, n, f) det_getrandom((b), (n), (f))
#define time(p) det_time(p)
#include "../src/proto/tls/reality.c"
#undef os_getrandom
#undef time

#include "chello-frozen.h"
#include "chello-frozen-pq.h"

static const struct reality_cfg CFG = {
    .sni = "www.example.com",
    .pbk = "xNlHRs0RY8mJhMhOVWRxg8ykpZmqHrjKQqm3-1lQF3E",
    .sid = "0123456789abcdef",
    .fp  = "chrome",
    .alpn = "h2",
};

/* The same with the real X25519MLKEM768 hybrid (reality_cfg.pq), as Chrome 131+ sends it. The
 * ML-KEM key is made from a seed drawn from the same deterministic source, so the bytes are
 * reproducible. */
static const struct reality_cfg CFG_PQ = {
    .sni = "www.example.com",
    .pbk = "xNlHRs0RY8mJhMhOVWRxg8ykpZmqHrjKQqm3-1lQF3E",
    .sid = "0123456789abcdef",
    .fp  = "chrome",
    .alpn = "h2",
    .pq = 1,
};

static size_t build_seeded(const struct reality_cfg *cfg, const char *cipher, uint64_t seed,
                           unsigned char *out, size_t cap) {
    setenv("STEER_CIPHER", cipher, 1);
    prng = seed;
    g_calls = 0;
    struct reality_state st;
    size_t n = 0;
    if (reality_build_hello(cfg, &st, out, cap, &n) != 0) return 0;
    return n;
}
static size_t build_cfg(const struct reality_cfg *cfg, const char *cipher,
                        unsigned char *out, size_t cap) {
    return build_seeded(cfg, cipher, 0x123456789ABCDEFull, out, cap);
}
static size_t build(const char *cipher, unsigned char *out, size_t cap) {
    return build_cfg(&CFG, cipher, out, cap);
}

/* The extension types of a built Hello (a whole record), in order; returns their number. */
static size_t ext_types(const unsigned char *h, size_t n, unsigned *t, size_t cap) {
    size_t p = 5 + 4 + 2 + 32, k = 0;
    p += 1 + h[p];                                          /* session_id */
    p += 2 + ((size_t)h[p] << 8 | h[p + 1]);                /* cipher suites */
    p += 1 + h[p];                                          /* compression */
    size_t end = p + 2 + ((size_t)h[p] << 8 | h[p + 1]);
    for (p += 2; p + 4 <= end && end <= n && k < cap; p += 4 + ((size_t)h[p + 2] << 8 | h[p + 3]))
        t[k++] = (unsigned)h[p] << 8 | h[p + 1];
    return k;
}
static int is_grease(unsigned v) { return (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF); }

static void emit(const char *name, const unsigned char *b, size_t n) {
    printf("static const char %s[] =\n    \"", name);
    for (size_t i = 0; i < n; i++) {
        printf("\\x%02x", b[i]);
        if ((i + 1) % 16 == 0 && i + 1 < n) printf("\"\n    \"");
    }
    printf("\";\n\n");
}

int main(int argc, char **argv) {
    unsigned char a[4096], c[4096];
    if (argc > 2 && !strcmp(argv[1], "--raw-pq")) {           /* for tests/hello-diff.py (uTLS) */
        size_t n = build_cfg(&CFG_PQ, "aes", a, sizeof(a));
        FILE *f = fopen(argv[2], "wb");
        if (!n || !f) return 2;
        fwrite(a, 1, n, f);
        fclose(f);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--emit-pq")) {
        size_t pa = build_cfg(&CFG_PQ, "aes", a, sizeof(a)), pc = build_cfg(&CFG_PQ, "chacha", c, sizeof(c));
        if (!pa || !pc) { puts("building the hybrid Hello failed"); return 2; }
        puts("/* Generated by tests/hellofreeze.c --emit-pq: the Hello with X25519MLKEM768. */");
        puts("#ifndef STEER_CHELLO_FROZEN_PQ_H\n#define STEER_CHELLO_FROZEN_PQ_H\n");
        emit("FROZEN_PQ_AES", a, pa);
        emit("FROZEN_PQ_CHACHA", c, pc);
        printf("#define FROZEN_PQ_N %zu\n\n#endif\n", pa);
        return 0;
    }
    size_t an = build("aes", a, sizeof(a));
    size_t cn = build("chacha", c, sizeof(c));
    if (!an || !cn) { puts("building the Hello failed"); return 2; }

    if (argc > 1 && !strcmp(argv[1], "--emit")) {
        puts("/* Generated by tests/hellofreeze.c --emit; see that file's header. */");
        puts("#ifndef STEER_CHELLO_FROZEN_H\n#define STEER_CHELLO_FROZEN_H\n");
        emit("FROZEN_AES", a, an);
        emit("FROZEN_CHACHA", c, cn);
        printf("#define FROZEN_N %zu\n\n#endif\n", an);
        return 0;
    }

    int fails = 0;
    if (an != FROZEN_N || memcmp(a, FROZEN_AES, an) != 0) {
        printf("FAIL: Hello (aes) differs from the frozen copy (%zu vs %d bytes)\n",
               an, FROZEN_N);
        for (size_t i = 0; i < an && i < FROZEN_N; i++)
            if (a[i] != (unsigned char)FROZEN_AES[i]) {
                printf("  first difference at byte %zu: %02x vs %02x\n",
                       i, a[i], (unsigned char)FROZEN_AES[i]);
                break;
            }
        fails++;
    } else {
        printf("%-62s ok\n", "Hello (aes): byte for byte as frozen");
    }
    if (cn != FROZEN_N || memcmp(c, FROZEN_CHACHA, cn) != 0) {
        printf("FAIL: Hello (chacha) differs from the frozen copy\n");
        fails++;
    } else {
        printf("%-62s ok\n", "Hello (chacha): byte for byte as frozen");
    }
    {
        unsigned char pa[4096], pc[4096];
        size_t pan = build_cfg(&CFG_PQ, "aes", pa, sizeof(pa)), pcn = build_cfg(&CFG_PQ, "chacha", pc, sizeof(pc));
        if (pan != FROZEN_PQ_N || memcmp(pa, FROZEN_PQ_AES, pan) != 0) {
            printf("FAIL: hybrid Hello (aes) differs from the frozen copy (%zu vs %d bytes)\n", pan, FROZEN_PQ_N);
            fails++;
        } else printf("%-62s ok\n", "hybrid Hello (aes): byte for byte as frozen");
        if (pcn != FROZEN_PQ_N || memcmp(pc, FROZEN_PQ_CHACHA, pcn) != 0) {
            printf("FAIL: hybrid Hello (chacha) differs from the frozen copy\n");
            fails++;
        } else printf("%-62s ok\n", "hybrid Hello (chacha): byte for byte as frozen");
        /* The hybrid adds exactly 4 (group header in key_share) + 1216 (its key share) + 2
         * (supported_groups). */
        if (pan != an + 4 + 1216 + 2) {
            printf("FAIL: hybrid Hello is %zu bytes, expected %zu\n", pan, an + 4 + 1216 + 2);
            fails++;
        } else printf("%-62s ok\n", "hybrid adds exactly its key share (1216) and its group");
    }
    /* The suite orders MUST differ: if they match, cpu_has_aes no longer affects the Hello, and
     * a MIPS router would get a cipher six times slower. */
    if (memcmp(a, c, an) == 0) {
        printf("FAIL: aes and chacha gave the same Hello: the cipher order has no effect\n");
        fails++;
    } else {
        printf("%-62s ok\n", "cipher suite order follows the CPU (aes and chacha differ)");
    }
    /* GREASE is drawn per connection, and the frozen Hello holds one draw: a rule that matters in
     * one draw of sixteen (the two GREASE extensions must not share a type) needs many. Over 256
     * draws: GREASE comes first and last, and no extension type repeats (a server refuses a Hello
     * with a repeated extension). */
    {
        int bad = 0;
        for (uint64_t s = 1; s <= 256; s++) {
            unsigned char h[4096];
            unsigned t[32];
            size_t n = build_seeded(&CFG, "aes", s, h, sizeof(h));
            size_t k = n ? ext_types(h, n, t, 32) : 0;
            if (k < 3 || !is_grease(t[0]) || !is_grease(t[k - 1])) bad++;
            for (size_t i = 0; i < k; i++)
                for (size_t j = i + 1; j < k; j++) bad += t[i] == t[j];
        }
        if (bad) {
            printf("FAIL: %d faults in the extension types of 256 random Hellos\n", bad);
            fails++;
        } else {
            printf("%-62s ok\n", "256 random Hellos: GREASE first and last, no type repeats");
        }
    }
    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed");
    return fails ? 1 : 0;
}
