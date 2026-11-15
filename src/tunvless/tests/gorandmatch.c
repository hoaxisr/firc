#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "unit.h"
#include "../src/lib/gorand.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

struct sha { uint32_t h[8]; uint8_t buf[64]; size_t n; uint64_t total; };

static uint32_t ror(uint32_t x, int k) { return (x >> k) | (x << (32 - k)); }

static void sha_block(struct sha *s, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t a = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t b = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + a + w[i - 7] + b;
    }
    uint32_t v[8];
    memcpy(v, s->h, sizeof v);
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = v[7] + (ror(v[4], 6) ^ ror(v[4], 11) ^ ror(v[4], 25)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + K[i] + w[i];
        uint32_t t2 = (ror(v[0], 2) ^ ror(v[0], 13) ^ ror(v[0], 22)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        memmove(v + 1, v, 7 * sizeof v[0]);
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) s->h[i] += v[i];
}

static void sha_init(struct sha *s) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof iv);
    s->n = 0;
    s->total = 0;
}

static void sha_add(struct sha *s, const uint8_t *p, size_t n) {
    s->total += n;
    while (n--) {
        s->buf[s->n++] = *p++;
        if (s->n == 64) { sha_block(s, s->buf); s->n = 0; }
    }
}

static void sha_hex(struct sha *s, char out[65]) {
    uint64_t bits = s->total * 8;
    uint8_t pad = 0x80;
    sha_add(s, &pad, 1);
    pad = 0;
    while (s->n != 56) sha_add(s, &pad, 1);
    for (int i = 7; i >= 0; i--) { uint8_t b = (uint8_t)(bits >> (8 * i)); sha_add(s, &b, 1); }
    for (int i = 0; i < 8; i++) sprintf(out + 8 * i, "%08x", s->h[i]);
}

static void hash10k(int64_t seed, char out[65]) {
    static struct go_rand r;
    struct sha s;
    go_rand_seed(&r, seed);
    sha_init(&s);
    for (int i = 0; i < 10000; i++) {
        uint64_t v = (uint64_t)go_rand_int63(&r);
        uint8_t b[8];
        for (int k = 0; k < 8; k++) b[k] = (uint8_t)(v >> (56 - 8 * k));
        sha_add(&s, b, 8);
    }
    sha_hex(&s, out);
}

static struct go_rand g_r, g_q;

static void first3(const char *what, int64_t seed, const char *want, const char *hash) {
    char got[96], hx[65], name[96];
    long long a, b, c;
    go_rand_seed(&g_r, seed);
    a = go_rand_int63(&g_r);
    b = go_rand_int63(&g_r);
    c = go_rand_int63(&g_r);
    snprintf(got, sizeof got, "%lld %lld %lld", a, b, c);
    snprintf(name, sizeof name, "%s first three", what);
    check_str(name, want, got);
    hash10k(seed, hx);
    snprintf(name, sizeof name, "%s hash of 10000", what);
    check_str(name, hash, hx);
}

static void t_sha_known(void) {
    /* catches: a broken test SHA-256 that would make every hash check meaningless */
    struct sha s;
    char got[65];
    sha_init(&s);
    sha_add(&s, (const uint8_t *)"abc", 3);
    sha_hex(&s, got);
    check_str("sha256 abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", got);
}

static void t_go_seed1(void) {
    /* catches: a wrong tap/feed start, a dropped rngCooked xor, or the u32 shift */
    char got[96];
    first3("seed 1", 1, "5577006791947779410 8674665223082153551 6129484611666145821",
           "952b5aa496983110713a3b90b99982031e11ce9e8eaef13440178f7b50c91261");
    go_rand_seed(&g_r, 1);
    unsigned long a = go_rand_u32(&g_r), b = go_rand_u32(&g_r), c = go_rand_u32(&g_r);
    snprintf(got, sizeof got, "%lu %lu %lu", a, b, c);
    check_str("seed 1 u32 x3", "2596996162 4039455774 2854263694", got);
}

static void t_go_seed_folds(void) {
    /* catches: the 0 -> 89482311 branch or the modulo */
    const char *h0 = "19370450e8e511a16970bc569dfcaae5ee277fc4cbcda54fff49d2baec6e5de6";
    const char *w0 = "8717895732742165505 2259404117704393152 6050128673802995827";
    const char *hn = "727088f492dd557728ad0497d5d27f5405258f513fdb2d3f9ec9fcd8cabbca85";
    const char *wn = "3644962268338389676 550171362161912239 3094056749125766625";
    first3("seed 0", 0, w0, h0);
    first3("seed 89482311", 89482311, w0, h0);
    first3("seed 2147483647", 2147483647, w0, h0);
    first3("seed -1", -1, wn, hn);
    first3("seed 2147483646", 2147483646, wn, hn);
    first3("seed INT64_MAX", INT64_MAX, "5577006791947779410 8674665223082153551 6129484611666145821",
           "952b5aa496983110713a3b90b99982031e11ce9e8eaef13440178f7b50c91261");
    first3("seed INT64_MIN", INT64_MIN, "7681445645332086223 6777158040660201103 8748006033234207912",
           "4cf319b24750e2bfcef425c8be466e80d973aa38b3bee31538e331c18b106590");
    first3("seed -2039914840885289964", -INT64_C(2039914840885289964),
           "1734826076916981736 2086822802163261076 7972771334260658883",
           "f980315123bfbee137cb4b65fee9d4ef06027d239b55a8857dd809ad899b4e4a");
}

static void t_go_int31n_reject(void) {
    /* catches: the rejection loop missing or thresh = 0 */
    static const long want[12] = {1009863944, 469992029, 455951040, 737470659, 70477212, 323101650,
                                  553205347, 873639256, 230064081, 341512364, 503466637, 303905605};
    go_rand_seed(&g_r, 1);
    go_rand_seed(&g_q, 1);
    for (int i = 0; i < 12; i++) check("int31n(0x40000001)", want[i], go_rand_int31n(&g_r, 0x40000001));
    for (int i = 0; i < 17; i++) go_rand_u32(&g_q);
    check("exactly 17 u32 consumed", (long)go_rand_u32(&g_q), (long)go_rand_u32(&g_r));
}

static void t_go_shuffle(void) {
    /* catches: the walk from 0 up, or j drawn from [0, i) */
    static const uint16_t w2[2] = {0, 1}, w5[5] = {2, 0, 1, 4, 3}, w10[10] = {1, 7, 4, 0, 9, 2, 3, 5, 8, 6};
    uint16_t v[10];
    for (int i = 0; i < 2; i++) v[i] = (uint16_t)i;
    go_rand_seed(&g_r, 1);
    go_rand_shuffle_u16(&g_r, v, 2);
    check_mem("shuffle n=2", w2, v, sizeof w2);
    for (int i = 0; i < 5; i++) v[i] = (uint16_t)i;
    go_rand_seed(&g_r, 1);
    go_rand_shuffle_u16(&g_r, v, 5);
    check_mem("shuffle n=5", w5, v, sizeof w5);
    for (int i = 0; i < 10; i++) v[i] = (uint16_t)i;
    go_rand_seed(&g_r, 1);
    go_rand_shuffle_u16(&g_r, v, 10);
    check_mem("shuffle n=10", w10, v, sizeof w10);
}

int main(void) {
    t_sha_known();
    t_go_seed1();
    t_go_seed_folds();
    t_go_int31n_reject();
    t_go_shuffle();
    return unit_done("gorandmatch");
}
