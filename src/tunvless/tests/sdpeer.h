#ifndef STEER_TESTS_SDPEER_H
#define STEER_TESTS_SDPEER_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../src/proto/transport/fmsd.h"

struct tpk { const struct sd_set *s; size_t gi; unsigned chance; uint64_t r; };

static unsigned tpk_below(struct tpk *p, unsigned n) {
    p->r ^= p->r << 13;
    p->r ^= p->r >> 7;
    p->r ^= p->r << 17;
    return (unsigned)((p->r >> 16) % n);
}

static size_t tpk_pad(struct tpk *p, const struct sd_layout *l, unsigned char *w) {
    if (!p->chance || (p->chance < 100 && tpk_below(p, 100) >= p->chance)) return 0;
    for (;;) {
        uint8_t b = l->pool[tpk_below(p, l->pool_n)];
        if (b != l->marker) {
            *w = b;
            return 1;
        }
    }
}

static size_t tpk_pack(struct tpk *p, const unsigned char *in, size_t n, unsigned char *out) {
    uint64_t buf = 0;
    unsigned cnt = 0;
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        buf = buf << 8 | in[i];
        cnt += 8;
        while (cnt >= 6) {
            cnt -= 6;
            const struct sd_layout *l = &p->s->lay[p->gi % p->s->n];
            w += tpk_pad(p, l, out + w);
            out[w++] = l->hint[(buf >> cnt) & 0x3f];
            p->gi++;
            buf &= (UINT64_C(1) << cnt) - 1;
        }
    }
    if (cnt) {
        const struct sd_layout *l = &p->s->lay[p->gi % p->s->n];
        w += tpk_pad(p, l, out + w);
        out[w++] = l->hint[(buf << (6 - cnt)) & 0x3f];
        p->gi++;
        out[w++] = p->s->lay[p->gi % p->s->n].marker;
    }
    w += tpk_pad(p, &p->s->lay[p->gi % p->s->n], out + w);
    return w;
}

struct tdk { uint32_t key; uint8_t byte; };
struct tdec { const struct sd_set *s; struct tdk *map[8]; size_t map_n[8]; size_t ti; uint8_t h[4]; unsigned hn; int bad; };

static uint32_t tdec_key(const uint8_t *h) {
    uint8_t a[4];
    memcpy(a, h, 4);
    for (int i = 1; i < 4; i++)
        for (int j = i; j > 0 && a[j - 1] > a[j]; j--) {
            uint8_t t = a[j];
            a[j] = a[j - 1];
            a[j - 1] = t;
        }
    return (uint32_t)a[0] << 24 | (uint32_t)a[1] << 16 | (uint32_t)a[2] << 8 | a[3];
}

static int tdk_cmp(const void *a, const void *b) {
    uint32_t x = ((const struct tdk *)a)->key, y = ((const struct tdk *)b)->key;
    return x < y ? -1 : x > y;
}

static int tdec_init(struct tdec *d, const struct sd_set *s) {
    memset(d, 0, sizeof *d);
    d->s = s;
    const struct sd_base *b = sd_base();
    if (!s || !b || s->n > 8) return -1;
    for (size_t t = 0; t < s->n; t++) {
        size_t n = 0;
        for (unsigned v = 0; v < 256; v++) n += b->off[s->order[v] + 1] - b->off[s->order[v]];
        d->map[t] = malloc(n * sizeof *d->map[t]);
        if (!d->map[t]) return -1;
        for (unsigned v = 0; v < 256; v++)
            for (uint32_t k = b->off[s->order[v]]; k < b->off[s->order[v] + 1]; k++) {
                uint8_t h[4];
                for (int j = 0; j < 4; j++) h[j] = s->lay[t].hint[b->g[k][j]];
                d->map[t][d->map_n[t]].key = tdec_key(h);
                d->map[t][d->map_n[t]++].byte = (uint8_t)v;
            }
        qsort(d->map[t], d->map_n[t], sizeof *d->map[t], tdk_cmp);
    }
    return 0;
}

static void tdec_free(struct tdec *d) {
    for (size_t t = 0; t < 8; t++) free(d->map[t]);
    memset(d, 0, sizeof *d);
}

static size_t tdec_run(struct tdec *d, const unsigned char *in, size_t n, unsigned char *out) {
    size_t w = 0;
    for (size_t i = 0; i < n && !d->bad; i++) {
        size_t t = d->ti % d->s->n;
        if (d->s->lay[t].cls[in[i]] >= 64) continue;
        d->h[d->hn++] = in[i];
        if (d->hn < 4) continue;
        d->hn = 0;
        struct tdk k = { tdec_key(d->h), 0 };
        const struct tdk *f = bsearch(&k, d->map[t], d->map_n[t], sizeof k, tdk_cmp);
        if (!f) {
            d->bad = 1;
            break;
        }
        out[w++] = f->byte;
        d->ti++;
    }
    return w;
}

#endif
