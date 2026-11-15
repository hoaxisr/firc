#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "unit.h"
#include "../src/lib/scrypto.h"
#include "../src/proto/transport/fmask.h"
#include "../src/lib/gorand.h"
#include "../src/proto/transport/fmsd.h"
#include "sdpeer.h"

struct hbuf { unsigned char *b; size_t n, cap; };

static void hput(struct hbuf *h, const void *p, size_t n) {
    if (h->n + n > h->cap) {
        h->cap = (h->n + n) * 2;
        h->b = realloc(h->b, h->cap);
        if (!h->b) abort();
    }
    memcpy(h->b + h->n, p, n);
    h->n += n;
}

static void hbe16(struct hbuf *h, unsigned v) {
    unsigned char b[2] = {(unsigned char)(v >> 8), (unsigned char)v};
    hput(h, b, 2);
}

static void hcheck(const char *what, const char *want, struct hbuf *h) {
    unsigned char d[32];
    sc_hash(SC_SHA256, h->b, h->n, d);
    check_hex(what, want, d, 32);
    free(h->b);
    memset(h, 0, sizeof *h);
}

static struct fm_cfg cfgs[96];
static size_t ncfg;

static const struct fm_sd *sd_cfg(const char *settings) {
    char j[512], why[256];
    snprintf(j, sizeof j, "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":%s}]}", settings);
    if (ncfg == sizeof cfgs / sizeof cfgs[0]) abort();
    struct fm_cfg *c = &cfgs[ncfg++];
    if (fm_parse(j, strlen(j), c, why, sizeof why) || c->n != 1 || c->m[0].kind != FM_SUDOKU) {
        printf("parse %s: %s\n", settings, why);
        abort();
    }
    return &c->m[0].u.sd;
}

static void t_sd_grids(void) {
    /* catches: a column-major walk or no box check */
    const struct sd_base *b = sd_base();
    check("grids: base built", 1, b != NULL);
    if (!b) return;
    uint8_t grid[SD_GRIDS][16];
    int whole = 1;
    struct hbuf h = {0};
    memset(grid, 0, sizeof grid);
    for (int i = 0; i < SD_GRIDS; i++) {
        for (uint32_t s = b->off[i]; s < b->off[i + 1]; s++)
            for (int k = 0; k < 4; k++) {
                uint8_t g = b->g[s][k], v = (uint8_t)((g >> 4) + 1);
                if (grid[i][g & 15] && grid[i][g & 15] != v) whole = 0;
                grid[i][g & 15] = v;
            }
        for (int p = 0; p < 16; p++)
            if (!grid[i][p]) whole = 0;
        hput(&h, grid[i], 16);
    }
    static const uint8_t g0[16] = {1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1};
    static const uint8_t g287[16] = {4, 3, 2, 1, 2, 1, 4, 3, 3, 4, 1, 2, 1, 2, 3, 4};
    check("grids: every cell named once by its clue sets", 1, whole);
    check_mem("grids: grid 0", g0, grid[0], 16);
    check_mem("grids: grid 287", g287, grid[287], 16);
    hcheck("grids: sha256 of 288 x 16", "2865b433b40cedd051916982f14f4d4bb26680b65070b1d1354cc54e7f778b67", &h);
}

static void t_sd_base(void) {
    /* catches: positions out of order, unsorted groups, or uniqueness per grid */
    const struct sd_base *b = sd_base();
    check("base: built", 1, b != NULL);
    if (!b) return;
    uint32_t lo = UINT32_MAX, hi = 0;
    struct hbuf h = {0};
    for (unsigned i = 0; i < SD_GRIDS; i++) {
        uint32_t n = b->off[i + 1] - b->off[i];
        if (n < lo) lo = n;
        if (n > hi) hi = n;
        hbe16(&h, i);
        hbe16(&h, n);
        hput(&h, b->g[b->off[i]], 4 * (size_t)n);
    }
    static const uint8_t first[4] = {0x00, 0x1e, 0x2d, 0x33};
    check("base: off[0]", 0, b->off[0]);
    check("base: 25,728 sets", 25728, b->off[SD_GRIDS]);
    check("base: fewest sets per grid", 12, lo);
    check("base: most sets per grid", 128, hi);
    check_mem("base: grid 0 first set", first, b->g[0], 4);
    hcheck("base: sha256", "e7f816eb3aa2ef3906372c8afa7b3a80b1b71125f850341e6a60e68f60165a4d", &h);
}

static void hex_of(const uint8_t *p, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", p[i]);
}

static void t_sd_layouts(void) {
    /* catches: bit order swapped, p bits swapped, or the pool unsorted */
    struct sd_layout l;
    char hx[89];
    check("layout entropy: made", 0, sd_layout_make(&l, 0, ""));
    check("layout entropy: marker", 0x80, l.marker);
    check("layout entropy: pool_n", 16, l.pool_n);
    hex_of(l.pool, l.pool_n, hx);
    check_str("layout entropy: pool", "80108111821283138414851586168717", hx);
    check("layout entropy: hint[0x3f]", 0x6f, l.hint[0x3f]);
    check("layout entropy: cls[0x6f]", 0x3f, l.cls[0x6f]);
    check("layout entropy: cls[0x80] mark", SD_MARK, l.cls[0x80]);
    check("layout entropy: cls[0x10] pad", SD_PAD, l.cls[0x10]);

    check("layout ascii: made", 0, sd_layout_make(&l, 1, ""));
    check("layout ascii: marker", 0x3f, l.marker);
    check("layout ascii: pool_n", 32, l.pool_n);
    int run = 1;
    for (int i = 0; i < 32; i++)
        if (l.pool[i] != 0x20 + i) run = 0;
    check("layout ascii: pool 20..3f", 1, run);
    check("layout ascii: hint[0x3f]", 0x0a, l.hint[0x3f]);
    check("layout ascii: cls['\\n']", 0x3f, l.cls['\n']);
    check("layout ascii: cls[0x7f]", 0x3f, l.cls[0x7f]);
    check("layout ascii: cls[0x3f] mark", SD_MARK, l.cls[0x3f]);

    check("layout xpxvvpvv: made", 0, sd_layout_make(&l, 0, "xpxvvpvv"));
    check("layout xpxvvpvv: hint[0]", 0xa0, l.hint[0]);
    check("layout xpxvvpvv: hint[0x20]", 0xe0, l.hint[0x20]);
    check("layout xpxvvpvv: hint[0x10]", 0xa4, l.hint[0x10]);
    check("layout xpxvvpvv: hint[0x08]", 0xb0, l.hint[0x08]);
    check("layout xpxvvpvv: hint[0x01]", 0xa1, l.hint[0x01]);
    check("layout xpxvvpvv: marker", 0x2f, l.marker);
    check("layout xpxvvpvv: cls[0x2f] mark", SD_MARK, l.cls[0x2f]);
    check("layout xpxvvpvv: pool_n", 44, l.pool_n);
    hex_of(l.pool, l.pool_n, hx);
    check_str("layout xpxvvpvv: pool",
              "2f373b3d3e3f676b6d6e6f73757677797a7b7c7d7e7f8f979b9d9e9fc7cbcdcecfd3d5d6d7d9dadbdcdddedf", hx);

    check("layout vxpvxvvp: made", 0, sd_layout_make(&l, 0, "vxpvxvvp"));
    check("layout vxpvxvvp: marker", 0x1f, l.marker);
    check("layout vxpvxvvp: pool_n", 44, l.pool_n);
    hex_of(l.pool, l.pool_n, hx);
    check_str("layout vxpvxvvp: pool",
              "1f2f3b3d3e3f5767737576778f9b9d9e9fabadaeafb9babbbcbdbebfc7d3d5d6d7e3e5e6e7f1f2f3f4f5f6f7", hx);

    int pats = 0, all44 = 1;
    for (unsigned m = 0; m < 6561; m++) {
        char p[9];
        int nx = 0, np = 0, nv = 0;
        unsigned v = m;
        for (int i = 0; i < 8; i++, v /= 3) {
            p[i] = "xpv"[v % 3];
            nx += p[i] == 'x';
            np += p[i] == 'p';
            nv += p[i] == 'v';
        }
        p[8] = '\0';
        if (nx != 2 || np != 2 || nv != 4) continue;
        pats++;
        if (sd_layout_make(&l, 0, p) || l.pool_n != 44) all44 = 0;
    }
    check("layout: 420 patterns", 420, pats);
    check("layout: every pattern gives a 44-byte pool", 1, all44);
}

static void order_case(const char *name, const unsigned char *pw, size_t n, int64_t want_seed, const char *want) {
    uint16_t o[SD_GRIDS];
    int64_t seed = 0;
    char what[96];
    struct hbuf h = {0};
    snprintf(what, sizeof what, "order %s: made", name);
    check(what, 0, sd_order(pw, n, o, &seed));
    snprintf(what, sizeof what, "order %s: seed", name);
    check(what, 1, want_seed == seed);
    if (want_seed != seed) printf("     want: %lld\n     got:  %lld\n", (long long)want_seed, (long long)seed);
    for (int i = 0; i < SD_GRIDS; i++) hbe16(&h, o[i]);
    snprintf(what, sizeof what, "order %s: sha256", name);
    hcheck(what, want, &h);
}

static void t_sd_order(void) {
    /* catches: a little-endian seed, or the password cut at NUL */
    uint16_t o[SD_GRIDS];
    int64_t seed;
    static const uint16_t e0[8] = {284, 28, 251, 47, 72, 127, 147, 81};
    static const uint16_t e280[8] = {212, 166, 253, 14, 250, 247, 64, 54};
    static const uint16_t t0[8] = {251, 175, 275, 249, 202, 8, 226, 269};
    order_case("\"\"", (const unsigned char *)"", 0, -2039914840885289964LL,
               "371cdb27e720fdf495ace12b789255bffe9ce7a8528c186db8828f4421ecd7f1");
    sd_order((const unsigned char *)"", 0, o, &seed);
    check_mem("order \"\": [0:8]", e0, o, sizeof e0);
    check_mem("order \"\": [280:]", e280, o + 280, sizeof e280);
    order_case("test", (const unsigned char *)"test", 4, -6951639720043709083LL,
               "536cc087f68d7e8f469987c3d8099a89798d8cd961895136c9bb44279c74ca7f");
    sd_order((const unsigned char *)"test", 4, o, &seed);
    check_mem("order test: [0:8]", t0, o, sizeof t0);
    order_case("p", (const unsigned char *)"p", 1, 1481096887605153049LL,
               "4e58fbc953deae576429232fba52b773b8c1422beeef22f2b91e90223b30b490");
    order_case("\\0", (const unsigned char *)"", 1, 7940984811893783192LL,
               "91e64c35ad4539bfa46a52b2a3e6824930108455b7c6bb479d98231c3d1d28b0");

    const struct sd_set *s = sd_tables(sd_cfg("{\"password\":\"\\u0000\"}"));
    check("order \\0: set built", 1, s != NULL);
    sd_order((const unsigned char *)"", 1, o, &seed);
    if (s) check_mem("order \\0: the set holds the first 256", o, s->order, 256 * sizeof o[0]);
    s = sd_tables(sd_cfg("{\"password\":\"test\"}"));
    check("order test: set built", 1, s != NULL);
    if (s) check_mem("order test: set [0:8]", t0, s->order, sizeof t0);
}

static void lists_hash(const char *what, const struct sd_set *s, size_t t, const char *want) {
    const struct sd_base *b = sd_base();
    struct hbuf h = {0};
    for (int x = 0; x < 256; x++) {
        unsigned o = s->order[x];
        hbe16(&h, b->off[o + 1] - b->off[o]);
        for (uint32_t k = b->off[o]; k < b->off[o + 1]; k++)
            for (int j = 0; j < 4; j++) hput(&h, &s->lay[t].hint[b->g[k][j]], 1);
    }
    hcheck(what, want, &h);
}

static void t_sd_enc_lists(void) {
    /* catches: a table built from the wrong layout, or the tables of a set not sharing the password's order */
    const struct sd_base *b = sd_base();
    const struct sd_set *s = sd_tables(sd_cfg("{}"));
    check("enc lists {}: built", 1, b && s);
    if (!b || !s) return;
    check("enc lists {}: one table", 1, (long)s->n);
    lists_hash("enc lists {}", s, 0, "bf89940defc58da3feb19fcc3eaec20ac80d78d367f796f7d33d7a298210ff7e");
    uint8_t e[48] = {0};
    unsigned o = s->order[0];
    size_t n = b->off[o + 1] - b->off[o];
    check("enc lists {}: enc[0] has 12 sets", 12, (long)n);
    if (n == 12)
        for (size_t k = 0; k < 12; k++)
            for (int j = 0; j < 4; j++) e[4 * k + j] = s->lay[0].hint[b->g[b->off[o] + k][j]];
    check_hex("enc lists {}: enc[0]",
              "03294a60082f47600e2947600822416b082f41660e29416605224a6d05224c6b03244a6d03244c6b0e24476d052f4c66",
              e, 48);

    s = sd_tables(sd_cfg("{\"password\":\"test\"}"));
    check("enc lists test: built", 1, s != NULL);
    if (s) lists_hash("enc lists test", s, 0, "123e9669c7f7f9ba7de728e795acb7153812f39987d7ac63cc42afa2bcc2796e");
    s = sd_tables(sd_cfg("{\"password\":\"test\",\"ascii\":\"prefer_ascii\"}"));
    check("enc lists test ascii: built", 1, s != NULL);
    if (s) lists_hash("enc lists test ascii", s, 0, "1c6f945f9dc13650e389d07279e6a41fe716eef8f9328d4af2d92d625a5fe6b1");
    s = sd_tables(sd_cfg("{\"password\":\"test\",\"customTables\":[\"xpxvvpvv\",\"vxpvxvvp\"]}"));
    check("enc lists test two: two tables", 2, s ? (long)s->n : -1);
    if (s && s->n == 2) {
        lists_hash("enc lists test two: table 0", s, 0, "39e76bbf8b6c91769a2f7fd00dd99f24eded64201394e25808026a40f3dbb3ef");
        lists_hash("enc lists test two: table 1", s, 1, "2658323721cac27980be680012f6aa1822ee93c9ac5f1976ed96b51fb03db6b1");
    }
    s = sd_tables(sd_cfg("{\"password\":\"p\"}"));
    check("enc lists p: built", 1, s != NULL);
    if (s) lists_hash("enc lists p", s, 0, "8b472ce86da3ed401adb88eeaf9543953e850ef8739f280cf2531432f7beff4e");
}

static const struct fm_sd *race_cfg;
static const struct sd_set *race_got[8];
static pthread_barrier_t race_bar;

static void *race(void *arg) {
    size_t i = (size_t)arg;
    pthread_barrier_wait(&race_bar);
    race_got[i] = sd_tables(race_cfg);
    return NULL;
}

void __real_go_rand_seed(struct go_rand *r, int64_t seed);
void __wrap_go_rand_seed(struct go_rand *r, int64_t seed);
static unsigned sd_builds;

void __wrap_go_rand_seed(struct go_rand *r, int64_t seed) {
    __atomic_add_fetch(&sd_builds, 1, __ATOMIC_SEQ_CST);
    __real_go_rand_seed(r, seed);
}

static void t_sd_cache(void) {
    /* catches: a cache keyed by the fm string, or a racy publish */
    unsigned b0 = sd_builds;
    const struct sd_set *a = sd_tables(sd_cfg("{\"password\":\"cache-a\",\"paddingMin\":5}"));
    const struct sd_set *a2 = sd_tables(sd_cfg("{\"password\":\"cache-a\",\"paddingMin\":10,\"paddingMax\":30}"));
    check("cache: built", 1, a != NULL);
    check("cache: padding is not in the key", 1, a == a2);
    check("cache: one build", (long)b0 + 1, sd_builds);
    const struct sd_set *c = sd_tables(sd_cfg("{\"password\":\"cache-b\"}"));
    check("cache: another password is another set", 1, c && c != a);
    check("cache: two builds", (long)b0 + 2, sd_builds);
    const struct sd_set *x1 = sd_tables(sd_cfg("{\"password\":\"cache-c\",\"ascii\":\"ascii\",\"customTables\":[\"xpxvvpvv\"]}"));
    const struct sd_set *x2 = sd_tables(sd_cfg("{\"password\":\"cache-c\",\"ascii\":\"ascii\",\"customTables\":[\"vxpvxvvp\"]}"));
    check("cache: ascii ignores customTables", 1, x1 && x1 == x2);
    check("cache: three builds", (long)b0 + 3, sd_builds);
    const struct sd_set *en = sd_tables(sd_cfg("{\"password\":\"cache-c\"}"));
    check("cache: the mode is in the key", 1, en && en != x1);
    check("cache: entropy set marker", 0x80, en ? en->lay[0].marker : -1);
    check("cache: ascii set marker", 0x3f, x1 ? x1->lay[0].marker : -1);
    const struct sd_set *t1 = sd_tables(sd_cfg("{\"password\":\"cache-c\",\"customTables\":[\"xpxvvpvv\"]}"));
    const struct sd_set *t2 = sd_tables(sd_cfg("{\"password\":\"cache-c\",\"customTables\":[\"vxpvxvvp\"]}"));
    check("cache: patterns are in the key", 1, t1 && t2 && t1 != t2 && t1 != en);
    check("cache: six builds", (long)b0 + 6, sd_builds);

    pthread_t th[8];
    int same = 1, once = 1;
    for (int round = 0; round < 32; round++) {
        char js[64];
        snprintf(js, sizeof js, "{\"password\":\"cache-race-%d\"}", round);
        race_cfg = sd_cfg(js);
        unsigned b1 = sd_builds;
        pthread_barrier_init(&race_bar, NULL, 8);
        for (size_t i = 0; i < 8; i++) pthread_create(&th[i], NULL, race, (void *)i);
        for (size_t i = 0; i < 8; i++) pthread_join(th[i], NULL);
        pthread_barrier_destroy(&race_bar);
        same &= race_got[0] != NULL;
        for (size_t i = 1; i < 8; i++) same &= race_got[i] == race_got[0];
        once &= sd_builds == b1 + 1;
    }
    check("cache: 8 threads get one set, 32 keys", 1, same);
    check("cache: 8 threads build once, 32 keys", 1, once);
}

static size_t unhex(const char *h, unsigned char *out) {
    size_t n = 0;
    for (; h[0] && h[1]; h += 2) {
        unsigned v;
        if (sscanf(h, "%2x", &v) != 1) abort();
        out[n++] = (unsigned char)v;
    }
    return n;
}

static const char *two_js = "{\"password\":\"test\",\"customTables\":[\"xpxvvpvv\",\"vxpvxvvp\"]}";
static const char *three_js = "{\"password\":\"test\",\"customTables\":[\"xpxvvpvv\",\"vxpvxvvp\",\"pvxvxpvv\"]}";

static int in_pool(const struct sd_layout *l, uint8_t b) {
    for (unsigned i = 0; i < l->pool_n; i++)
        if (l->pool[i] == b) return 1;
    return 0;
}

static void sort4u(uint8_t *a) {
    for (int i = 1; i < 4; i++)
        for (int j = i; j > 0 && a[j - 1] > a[j]; j--) {
            uint8_t t = a[j];
            a[j] = a[j - 1];
            a[j - 1] = t;
        }
}

static int in_list(const struct sd_set *s, size_t t, uint8_t byte, const uint8_t *h) {
    const struct sd_base *b = sd_base();
    unsigned o = s->order[byte];
    uint8_t got[4];
    memcpy(got, h, 4);
    sort4u(got);
    for (uint32_t k = b->off[o]; k < b->off[o + 1]; k++) {
        uint8_t w[4];
        for (int j = 0; j < 4; j++) w[j] = s->lay[t].hint[b->g[k][j]];
        sort4u(w);
        if (!memcmp(w, got, 4)) return 1;
    }
    return 0;
}

static void t_sd_enc_nopad(void) {
    /* catches: a fixed set or order, or the hints sorted before writing */
    const struct sd_set *s = sd_tables(sd_cfg("{}"));
    unsigned char e0[48], out[16];
    unhex("03294a60082f47600e2947600822416b082f41660e29416605224a6d05224c6b03244a6d03244c6b0e24476d052f4c66", e0);
    struct sd_enc e;
    check("enc nopad: init", 0, s ? sd_enc_init(&e, s, 0, 0) : -1);
    if (!s) return;
    check("enc nopad: chance 0", 0, e.chance);
    int sets[12] = {0}, perms[256] = {0}, len_ok = 1, member = 1;
    for (int r = 0; r < 5000; r++) {
        unsigned char z = 0;
        size_t n = sd_encode(&e, &z, 1, out);
        if (n != 4) {
            len_ok = 0;
            continue;
        }
        int found = -1;
        for (int k = 0; k < 12 && found < 0; k++) {
            uint8_t a[4], b[4];
            memcpy(a, e0 + 4 * k, 4);
            memcpy(b, out, 4);
            sort4u(a);
            sort4u(b);
            if (!memcmp(a, b, 4)) found = k;
        }
        if (found < 0) {
            member = 0;
            continue;
        }
        sets[found]++;
        unsigned id = 0;
        for (int i = 0; i < 4; i++)
            for (unsigned j = 0; j < 4; j++)
                if (e0[4 * found + j] == out[i]) id = id * 4 + j;
        perms[id]++;
    }
    int nsets = 0, nperms = 0;
    for (int k = 0; k < 12; k++) nsets += sets[k] > 0;
    for (int k = 0; k < 256; k++) nperms += perms[k] > 0;
    check("enc nopad: 4 bytes per byte, 5,000 runs", 1, len_ok);
    check("enc nopad: every output is an enc[0] set", 1, member);
    check("enc nopad: all 12 sets occur", 12, nsets);
    check("enc nopad: all 24 orders occur", 24, nperms);
    check("enc nopad: bound 4n", 40, (long)sd_enc_bound(&e, 10));
    check("enc nopad: empty input writes nothing", 0, (long)sd_encode(&e, out, 0, out));
}

static void t_sd_enc_fullpad_rotation(void) {
    /* catches: the trailing pad from the last byte's table, ti reset per write, or one pool for all tables */
    const struct sd_set *s = sd_tables(sd_cfg(two_js));
    if (!s || s->n != 2) {
        check("enc fullpad: two tables", 2, s ? (long)s->n : -1);
        return;
    }
    check("enc fullpad: 0x7f is in pool 0", 1, in_pool(&s->lay[0], 0x7f));
    check("enc fullpad: 0x7f is a hint of table 1", 1, s->lay[1].cls[0x7f] < 64);
    int len_ok = 1, shape = 1, pools = 1, lists = 1, trail = 1, next = 1;
    unsigned char out[64];
    static const unsigned char in[3] = {0, 1, 2};
    for (int r = 0; r < 300; r++) {
        struct sd_enc e;
        if (sd_enc_init(&e, s, 100, 100)) {
            len_ok = 0;
            break;
        }
        size_t n = sd_encode(&e, in, 3, out);
        if (n != 28) {
            len_ok = 0;
            continue;
        }
        for (int i = 0; i < 3; i++) {
            const unsigned char *p = out + 9 * i;
            const struct sd_layout *l = &s->lay[i % 2];
            uint8_t h[4];
            if (!in_pool(l, p[0])) pools = 0;
            for (int k = 0; k < 4; k++) {
                if (!in_pool(l, p[1 + 2 * k])) pools = 0;
                if (l->cls[p[2 + 2 * k]] >= 64) shape = 0;
                h[k] = p[2 + 2 * k];
            }
            if (!in_list(s, i % 2, in[i], h)) lists = 0;
        }
        if (!in_pool(&s->lay[1], out[27])) trail = 0;
        if (sd_encode(&e, in, 0, out)) len_ok = 0;
        unsigned char three = 3;
        n = sd_encode(&e, &three, 1, out);
        if (n != 10) {
            next = 0;
            continue;
        }
        uint8_t h[4] = {out[2], out[4], out[6], out[8]};
        if (!in_list(s, 1, 3, h)) next = 0;
        for (int k = 0; k < 9; k += k ? 2 : 1)
            if (!in_pool(&s->lay[1], out[k])) next = 0;
        if (!in_pool(&s->lay[0], out[9])) next = 0;
    }
    check("enc fullpad: length 28 for 3 bytes, 0 for none, 300 runs", 1, len_ok);
    check("enc fullpad: P (P H) x4 shape", 1, shape);
    check("enc fullpad: byte i pads in pool i % 2", 1, pools);
    check("enc fullpad: byte i set in table i % 2's list", 1, lists);
    check("enc fullpad: trailing pad in pool 1", 1, trail);
    check("enc fullpad: the next call starts at table 1", 1, next);
}

static void t_sd_enc_rate(void) {
    /* catches: a biased draw or a decision skipped */
    const struct sd_set *s = sd_tables(sd_cfg("{}"));
    struct sd_enc e;
    size_t n = 200000;
    check("enc rate: init", 0, s ? sd_enc_init(&e, s, 50, 50) : -1);
    if (!s) return;
    check("enc rate: bound 9n + 1", (long)(9 * n + 1), (long)sd_enc_bound(&e, n));
    unsigned char *in = calloc(n, 1), *out = malloc(9 * n + 1);
    if (!in || !out) abort();
    for (size_t i = 0; i < n; i++) in[i] = (unsigned char)(i * 131 + 7);
    size_t w = sd_encode(&e, in, n, out);
    double share = (double)(w - 4 * n) / 1000001.0;
    printf("     pad share %.5f\n", share);
    check("enc rate: pad share 0.5 +- 0.005", 1, w >= 4 * n && share > 0.495 && share < 0.505);
    free(in);
    free(out);
}

static void t_sd_chance(void) {
    /* catches: IntN(max - min) without the +1, or a chance per write */
    const struct sd_set *s = sd_tables(sd_cfg("{}"));
    int c36 = 0, c37 = 0, other = 0, fixed37 = 1, kept = 1;
    if (!s) return;
    for (int r = 0; r < 200; r++) {
        struct sd_enc e;
        if (sd_enc_init(&e, s, 36, 37)) other++;
        if (e.chance == 36) c36++;
        else if (e.chance == 37) c37++;
        else other++;
        if (sd_enc_init(&e, s, 37, 37) || e.chance != 37) fixed37 = 0;
    }
    check("chance: 36 occurs", 1, c36 > 0);
    check("chance: 37 occurs", 1, c37 > 0);
    check("chance: nothing else", 0, other);
    check("chance: 37/37 is 37", 1, fixed37);
    struct sd_enc e;
    unsigned char out[64], in[4] = {1, 2, 3, 4};
    check("chance: 0..100 init", 0, sd_enc_init(&e, s, 0, 100));
    unsigned c = e.chance;
    for (int r = 0; r < 1000; r++) {
        sd_encode(&e, in, 4, out);
        if (e.chance != c) kept = 0;
    }
    check("chance: fixed over 1,000 calls", 1, kept);
}

static void t_sd_below(void) {
    /* catches: modulo bias or an off-by-one range */
    struct sd_rng r;
    long cnt[25] = {0};
    check("below: init", 0, sd_rng_init(&r));
    for (int i = 0; i < 240000; i++) {
        unsigned v = sd_rng_below(&r, 24);
        cnt[v < 24 ? v : 24]++;
    }
    int ok = 1;
    for (int v = 0; v < 24; v++)
        if (cnt[v] < 9400 || cnt[v] > 10600) {
            ok = 0;
            printf("     below(24) = %d: %ld\n", v, cnt[v]);
        }
    check("below: nothing at or above 24", 0, cnt[24]);
    check("below: each of 24 counts 10,000 +- 600", 1, ok);
}

static void t_sd_below_bias(void) {
    /* catches: a draw below 256 without rejection, or a rejection bound off by one */
    struct sd_rng r;
    static long cnt[193];
    check("below 192: init", 0, sd_rng_init(&r));
    for (int i = 0; i < 192000; i++) {
        unsigned v = sd_rng_below(&r, 192);
        cnt[v < 192 ? v : 192]++;
    }
    int ok = 1;
    for (int v = 0; v < 192; v++)
        if (cnt[v] < 800 || cnt[v] > 1200) {
            ok = 0;
            printf("     below(192) = %d: %ld\n", v, cnt[v]);
        }
    check("below 192: nothing at or above 192", 0, cnt[192]);
    check("below 192: each of 192 counts 1,000 +- 200", 1, ok);
}

static int unpack_case(const char *what, const struct sd_set *s, size_t gi, const char *in_hex, const char *want_hex) {
    unsigned char in[64], want[64], buf[64], got[64];
    char w[128];
    size_t n = unhex(in_hex, in), wn = unhex(want_hex, want), gn;
    int ok = 1;
    struct sd_dec d = {s, gi, 0, 0};
    memcpy(buf, in, n);
    gn = sd_unpack(&d, buf, n);
    snprintf(w, sizeof w, "%s: whole", what);
    check(w, (long)wn, (long)gn);
    if (gn == wn) check_mem(w, want, buf, wn);
    for (size_t cut = 0; cut <= n; cut++) {
        struct sd_dec c = {s, gi, 0, 0};
        gn = 0;
        if (cut == 0) {
            for (size_t i = 0; i < n; i++) {
                buf[0] = in[i];
                if (sd_unpack(&c, buf, 1)) got[gn++] = buf[0];
                if (c.nbits >= 8 || c.bits >> c.nbits) ok = 0;
            }
        } else {
            memcpy(buf, in, cut);
            size_t a = sd_unpack(&c, buf, cut);
            memcpy(got, buf, a);
            memcpy(buf, in + cut, n - cut);
            size_t b = sd_unpack(&c, buf, n - cut);
            memcpy(got + a, buf, b);
            gn = a + b;
        }
        if (gn != wn || memcmp(got, want, wn) || c.gi != d.gi) ok = 0;
    }
    snprintf(w, sizeof w, "%s: bytewise, every split", what);
    check(w, 1, ok);
    return (int)d.gi;
}

static void t_sd_unpack_vectors(void) {
    /* catches: the marker reset missing, a pad taken for the marker, or bits lost between calls */
    const struct sd_set *en = sd_tables(sd_cfg("{}"));
    const struct sd_set *as = sd_tables(sd_cfg("{\"ascii\":\"prefer_ascii\"}"));
    check("unpack vectors: sets", 1, en && as);
    if (!en || !as) return;
    unpack_case("unpack entropy 202080", en, 0, "202080", "41");
    unpack_case("unpack entropy hello", en, 0, "2a06254c2b066c80", "68656c6c6f");
    unpack_case("unpack entropy 000f6c20", en, 0, "000f6c20", "00ff10");
    unpack_case("unpack ascii hello", as, 0, "5a46556c5b467c3f", "68656c6c6f");
    unpack_case("unpack ascii 0a0a0a0a", as, 0, "0a0a0a0a", "ffffff");
    unpack_case("unpack ascii 50503f", as, 0, "50503f", "41");
    unpack_case("unpack entropy 202080202080", en, 0, "202080202080", "4141");
    unpack_case("unpack entropy 20202020", en, 0, "20202020", "410410");
    unpack_case("unpack entropy 2010208010", en, 0, "2010208010", "41");
}

static void t_sd_unpack_rotation(void) {
    /* catches: the layout from a byte counter, or the marker of the current layout */
    const struct sd_set *s = sd_tables(sd_cfg(two_js));
    check("unpack rotation: two tables", 2, s ? (long)s->n : -1);
    if (!s || s->n != 2) return;
    unpack_case("unpack two hello", s, 0, "b65cadf8b75cfc1f", "68656c6c6f");
    unpack_case("unpack two 7f after the first", s, 0, "b67f5cadf8b75cfc1f", "6b756c6c6f");
    unpack_case("unpack two 2f after the first", s, 0, "b62f5cadf8b75cfc1f", "68656c6c6f");
    unpack_case("unpack two 1f after the first", s, 0, "b61f5cadf8b75cfc1f", "195b1b1b");
    unpack_case("unpack two a4492f", s, 0, "a4492f", "41");
}

static void t_sd_index_wrap(void) {
    /* catches: an unreduced index that wraps at 2^32 on 32-bit */
    const struct sd_set *s = sd_tables(sd_cfg(three_js));
    check("index wrap: three tables", 3, s ? (long)s->n : -1);
    if (!s || s->n != 3) return;
    unsigned char out[64];
    struct tpk p = {s, 2, 0, 1};
    size_t n = tpk_pack(&p, (const unsigned char *)"hello", 5, out);
    check_hex("index wrap: test packer at 2 is Go's at 4294967294", "6eaa5bf8b75cfc2f", out, n);
    check("index wrap: gi after", 0, unpack_case("index wrap: unpack at 2", s, 4294967294u % 3, "6eaa5bf8b75cfc2f", "68656c6c6f"));
    unpack_case("index wrap: Go's at 2^32 unpacks at 1", s, 1, "cd3aadf86faaf91f", "68656c6c6f");

    size_t total = 1 << 20, done = 0;
    unsigned char *in = malloc(4096), *buf = malloc(9 * 4096 + 1);
    struct sd_enc e;
    struct sd_dec d = {s, 0, 0, 0};
    struct tpk q = {s, 0, 30, 0x9e3779b97f4a7c15u};
    int ti_ok = sd_enc_init(&e, s, 30, 30) == 0, gi_ok = 1;
    if (!in || !buf) abort();
    for (size_t i = 0; i < 4096; i++) in[i] = (unsigned char)(i * 7 + 3);
    while (done < total) {
        size_t k = 1 + (done * 2654435761u >> 7) % 4096;
        sd_encode(&e, in, k, buf);
        if (e.ti >= 3) ti_ok = 0;
        size_t m = tpk_pack(&q, in, k, buf);
        sd_unpack(&d, buf, m);
        if (d.gi >= 3) gi_ok = 0;
        done += k;
    }
    check("index wrap: ti < 3 after every call, 1 MiB", 1, ti_ok);
    check("index wrap: gi < 3 after every call, 1 MiB", 1, gi_ok);
    free(in);
    free(buf);
}

static void t_sd_unpack_inplace(void) {
    /* catches: output overrunning the input, or a byte held back */
    const struct sd_set *en = sd_tables(sd_cfg("{}"));
    const struct sd_set *s = sd_tables(sd_cfg(two_js));
    check("unpack inplace: sets", 1, en && s && s->n == 2);
    if (!en || !s || s->n != 2) return;
    unsigned char out[64];
    struct tpk p = {en, 0, 0, 1};
    size_t n = tpk_pack(&p, (const unsigned char *)"hello", 5, out);
    check_hex("unpack inplace: test packer entropy hello", "2a06254c2b066c80", out, n);
    p = (struct tpk){s, 0, 0, 1};
    n = tpk_pack(&p, (const unsigned char *)"hello", 5, out);
    check_hex("unpack inplace: test packer two tables hello", "b65cadf8b75cfc1f", out, n);

    size_t total = 64 << 10, wn = 0, got = 0;
    unsigned char *in = malloc(total), *wire = malloc(3 * total + 4096), *res = malloc(total + 16);
    struct tpk q = {s, 0, 30, 0x243f6a8885a308d3u};
    struct sd_rng r;
    if (!in || !wire || !res || sd_rng_init(&r)) abort();
    for (size_t i = 0; i < total; i++) in[i] = (unsigned char)sd_rng_below(&r, 256);
    for (size_t i = 0; i < total;) {
        size_t k = 1 + tpk_below(&q, 1000);
        if (k > total - i) k = total - i;
        wn += tpk_pack(&q, in + i, k, wire + wn);
        i += k;
    }
    struct sd_dec d = {s, 0, 0, 0};
    int le = 1, nb = 1, over = 0;
    for (size_t i = 0; i < wn;) {
        size_t k = 1 + tpk_below(&q, 300);
        if (k > wn - i) k = wn - i;
        unsigned char *cut = malloc(k);
        if (!cut) abort();
        memcpy(cut, wire + i, k);
        size_t m = sd_unpack(&d, cut, k);
        if (m > k) le = 0;
        if (d.nbits >= 8 || d.bits >> d.nbits) nb = 0;
        if (got + m > total) over = 1;
        else memcpy(res + got, cut, m);
        free(cut);
        got += m;
        i += k;
    }
    check("unpack inplace: output <= input per call", 1, le);
    check("unpack inplace: nbits < 8, bits < 2^nbits after each", 1, nb);
    check("unpack inplace: 64 KiB back", (long)total, (long)got);
    check("unpack inplace: the input back", 1, !over && got == total && !memcmp(res, in, total));
    free(in);
    free(wire);
    free(res);
}

static void rng_blocks(const char *what, struct sd_rng *r, const char *want) {
    unsigned char got[256];
    char name[96];
    r->pos = sizeof r->buf;
    for (size_t i = 0; i < sizeof got; i++) got[i] = (unsigned char)sd_rng_below(r, 256);
    for (int i = 0; i < 4; i++) {
        char w[129];
        memcpy(w, want + 128 * i, 128);
        w[128] = 0;
        snprintf(name, sizeof name, "%s, block %d", what, i);
        check_hex(name, w, got + 64 * i, 64);
    }
}

static void t_sd_chacha8_block(void) {
    /* catches: a wrong round count, rotation, or little-endian store */
    struct sd_rng r;
    check("chacha8: init", 0, sd_rng_init(&r));
    memset(r.key, 0, sizeof r.key);
    r.ctr = 0;
    rng_blocks("chacha8: zero key, ctr 0..3", &r,
        "3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e984ce172b9216f419f445367456d5619314a42a3da86b001387bfdb80e0cfe42"
        "d2aefa0deaa5c151bf0adb6c01f2a5adc0fd581259f9a2aadcf20f8fd566a26b5032ec38bbc5da98ee0c6f568b872a65a08abf251deb21bb4b56e5d8821e68aa"
        "7fe7b1ff12cffd9d7e21f517501ecaff43cea3e8e3eb28cbd8d1001f68b5c68755b970d3b7dafc64d3e59bdeaadc8f82a975a481df31b52870aa5fa2ba340af9"
        "2ba037cdb63cb5a7277dc5d6dc549e4e28a15c70670f0e97787c170485829264ecbf14bddeb68410f423e8849e0ce35c10d20a802bbc3d9a6ca01c386279bf01");
    check("chacha8: zero key, ctr after 4 blocks", 4, (long)r.ctr);
    for (int i = 0; i < 32; i++) r.key[i] = (unsigned char)(i + 1);
    r.ctr = 0;
    rng_blocks("chacha8: key 01..20, ctr 0..3", &r,
        "3a18a8af6f9cdc014941edb1be09504e9cf39c73ed8734b57a7888da2cd5cd67e44b6563c28edcc0428d5b93eda865d65532657a0a46d70c4b2006cdfbfad4f7"
        "662fc8736782a6ad2cdcd5a9b9cad0a4c040684f62b009c04ad5c11fcb5aeb79d6823f4a3892ccde242c2b8ed2531d05711d7d6512d02bd61bacb4f344176e19"
        "1b787f0b866c140a478119e7934d958b89ad34b9fec132af9bfc1902b5fc82aadcc5e96ea21deced249d59465625cae28b2bba601d017dcdb5299eca30c95667"
        "a09461cb692b7ff0d108fdb9b03d4de33861d71b06c89e53cdff9d7d7f2ea79d17c06d74bdad933c0f95106c57341506b3a0448ab4e929403b8b558543a72f67");
}

static void t_sd_rng_rekey(void) {
    /* catches: a block counter that wraps into reused keystream, the rekey bound moved, or a key not from the stream */
    struct sd_rng r;
    unsigned char k0[32], k1[32];
    check("rng rekey: init", 0, sd_rng_init(&r));
    for (int i = 0; i < 32; i++) k0[i] = (unsigned char)(i + 1);
    memcpy(r.key, k0, 32);
    r.ctr = UINT32_MAX - 4;
    rng_blocks("rng rekey: at 2^32 - 5 the old key", &r,
        "a574a91ffc5cbad220e607fe36e03a89f9c1fc9af7fae430b3730d588895549e1d29bdaa89a7239b5f65a2e2da325e9b07c03658743aa3af52a8c5087c5b7ebf"
        "0d5d27014ad6b9f4c7e88b9a13bd866c0af1f85947b96e165284114ba72b7bfd5dae2fbfa8c9c282fea7f7638e556be34bd72486fddc5416232872fd21e4e97a"
        "61318cd82367e98d1f87ae2cf0d43b20a67e2727418b1e7dd433f1b2e53997b01e800a068bfcba78c67e7a6441fdd2cc4026553f84baf125c16890dc807802ba"
        "39cfd5cd685a81170cb3c24d9c07c6129d39dce6736d9100877446f6f49afcc3e2073df2667c1c583a094c6e599ad573c1472003839d2f83dbd2c0ff91b4fd97");
    check("rng rekey: at 2^32 - 5 no rekey", 1, !memcmp(r.key, k0, 32));
    check("rng rekey: at 2^32 - 5 ctr ends at 2^32 - 1", (long)UINT32_MAX, (long)r.ctr);
    r.ctr = UINT32_MAX - 3;
    rng_blocks("rng rekey: at 2^32 - 4 the new key", &r,
        "2ef08cc1ffc599a680eb76f837b7808b2eca46f38b3fe819f7d79467b0d3f732f8c2fa538e6a46fdbc1dfacb172f08467b380f6c65e8a4e723846e43269e06de"
        "e67adf68711ea8e0cfe969dde205231586c0d7fa50b5bbaf228962b5ed30615c93ab4c3f003afdc438565bc44e265082a5149fd69e713d7849b941d64e5fb347"
        "845d58821a39f4fa391b8e378d2c7ddb12bc9a1d89b36c30855fd0fbe18055ec19aae73e8f99db0f615522b1840aeeae287db557b19fc48e7a1856719e37046a"
        "cea81cd71865b54b287705c1e3b26c4bd2de48bb87071eccccb35f75563ae8094ac8c86a90a46edd33c295573fadc6a5eeccc4e3b18b12f9646a957b3ca393d9");
    unhex("0d5d27014ad6b9f4c7e88b9a13bd866c0af1f85947b96e165284114ba72b7bfd", k1);
    check_mem("rng rekey: at 2^32 - 4 the key is block 2^32 - 4", k1, r.key, 32);
    check("rng rekey: at 2^32 - 4 ctr restarts, 4 blocks", 4, (long)r.ctr);
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static int bench(void) {
    int rc = 1;
    unsigned char *in = NULL, *out = NULL, *wire = NULL;
    double t = now_ms();
    if (!sd_base()) goto out;
    printf("sd_base %.1f ms\n", now_ms() - t);
    t = now_ms();
    const struct sd_set *s = sd_tables(sd_cfg("{\"password\":\"bench\"}"));
    if (!s) goto out;
    printf("table set %.1f ms\n", now_ms() - t);
    size_t n = 16 << 10, rounds = 512;
    struct sd_rng r;
    in = malloc(n);
    out = malloc(9 * n + 1);
    if (!in || !out || sd_rng_init(&r)) goto out;
    for (size_t i = 0; i < n; i++) in[i] = (unsigned char)sd_rng_below(&r, 256);
    static const unsigned chances[3] = {0, 20, 100};
    for (int c = 0; c < 3; c++) {
        struct sd_enc e;
        if (sd_enc_init(&e, s, chances[c], chances[c])) goto out;
        t = now_ms();
        for (size_t k = 0; k < rounds; k++) sd_encode(&e, in, n, out);
        printf("encode chance %u: %.1f MB/s\n", chances[c], n * rounds / 1e3 / (now_ms() - t));
    }
    struct tpk p = {s, 0, 20, 1};
    size_t wn = tpk_pack(&p, in, n, out);
    if (!(wire = malloc(wn))) goto out;
    struct sd_dec d = {s, 0, 0, 0};
    t = now_ms();
    for (size_t k = 0; k < rounds; k++) {
        memcpy(wire, out, wn);
        sd_unpack(&d, wire, wn);
    }
    printf("sd_unpack: %.1f MB/s of wire\n", wn * rounds / 1e3 / (now_ms() - t));
    size_t draws = 64 << 20;
    unsigned sink = 0;
    t = now_ms();
    for (size_t k = 0; k < draws; k++) sink += sd_rng_below(&r, 256);
    printf("keystream: %.1f MB/s (%u)\n", draws / 1e3 / (now_ms() - t), sink & 1);
    rc = 0;
out:
    free(in);
    free(out);
    free(wire);
    return rc;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--bench")) {
        int rc = bench();
        for (size_t i = 0; i < ncfg; i++) fm_cfg_free(&cfgs[i]);
        return rc;
    }
    t_sd_grids();
    t_sd_base();
    t_sd_layouts();
    t_sd_order();
    t_sd_enc_lists();
    t_sd_cache();
    t_sd_enc_nopad();
    t_sd_enc_fullpad_rotation();
    t_sd_enc_rate();
    t_sd_chance();
    t_sd_below();
    t_sd_below_bias();
    t_sd_unpack_vectors();
    t_sd_unpack_rotation();
    t_sd_index_wrap();
    t_sd_unpack_inplace();
    t_sd_chacha8_block();
    t_sd_rng_rekey();
    for (size_t i = 0; i < ncfg; i++) fm_cfg_free(&cfgs[i]);
    return unit_done("fmsdmatch");
}
