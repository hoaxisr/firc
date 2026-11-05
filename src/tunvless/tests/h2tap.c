#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scrypto.h"
#include "hpackread.h"

static const unsigned char go_preface[70] = {
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
    0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
    0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00,
    0x00, 0x05, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0xa0, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
};

struct rec { size_t off, len; };
struct frm { size_t off; uint32_t len, sid; uint8_t type, flags; };
struct unit { size_t off, end, frame; };
struct blk {
    size_t rec, frame_last;
    size_t nupd;
    uint32_t upd0;
    unsigned char hb[3];
    int pseudo_ok;
    char method[16];
    char *names;
    char *fields;
};

static unsigned char *st;
static size_t st_n, st_cap;
static struct rec *rv;
static size_t rn, rcap;
static struct frm *fv;
static size_t fn, fcap;
static struct unit *uv;
static size_t un, ucap;
static struct blk *bv;
static size_t bn, bcap;
static size_t ack_rec = SIZE_MAX, open_rec = SIZE_MAX;
static const char *g_cmd = "";
static struct hr_ctx hctx;
static struct hr_block hblk;
static unsigned char hbuf[1 << 17];

static void *grow(void *p, size_t *cap, size_t need, size_t sz) {
    if (need <= *cap) return p;
    size_t c = *cap ? *cap * 2 : 64;
    while (c < need) c *= 2;
    void *q = realloc(p, c * sz);
    if (!q) { fprintf(stderr, "h2tap: out of memory\n"); exit(2); }
    *cap = c;
    return q;
}

static unsigned char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "h2tap: cannot open %s\n", path); exit(2); }
    unsigned char *b = NULL;
    size_t cap = 0, k;
    *n = 0;
    for (;;) {
        b = grow(b, &cap, *n + 65536, 1);
        k = fread(b + *n, 1, 65536, f);
        *n += k;
        if (k < 65536) break;
    }
    fclose(f);
    return b;
}

static uint32_t get16(const unsigned char *p) { return ((uint32_t)p[0] << 8) | p[1]; }
static uint32_t get24(const unsigned char *p) { return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2]; }
static uint32_t get32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t unhex(const char *s, unsigned char *out, size_t cap) {
    size_t n = 0;
    while (s[0] && s[1] && n < cap) {
        int a = hexval(s[0]), b = hexval(s[1]);
        if (a < 0 || b < 0) break;
        out[n++] = (unsigned char)(a << 4 | b);
        s += 2;
    }
    return n;
}

static size_t find_secret(const char *keylog, const unsigned char rnd[32], unsigned char *sec) {
    size_t n;
    unsigned char *d = slurp(keylog, &n);
    size_t got = 0;
    char *s = realloc(d, n + 1);
    if (!s) { fprintf(stderr, "h2tap: out of memory\n"); exit(2); }
    s[n] = '\0';
    char *save = NULL;
    for (char *line = strtok_r(s, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char lab[64], r[80], x[160];
        unsigned char rb[32];
        if (sscanf(line, "%63s %79s %159s", lab, r, x) != 3) continue;
        if (strcmp(lab, "CLIENT_TRAFFIC_SECRET_0") || unhex(r, rb, 32) != 32 || memcmp(rb, rnd, 32)) continue;
        got = unhex(x, sec, 64);
        break;
    }
    free(s);
    return got;
}

static int expand_label(enum sc_hash h, const unsigned char *sec, size_t sn, const char *lb,
                        unsigned char *out, size_t on) {
    unsigned char info[32];
    size_t ll = strlen(lb), i = 0;
    info[i++] = (unsigned char)(on >> 8);
    info[i++] = (unsigned char)on;
    info[i++] = (unsigned char)(6 + ll);
    memcpy(info + i, "tls13 ", 6);
    i += 6;
    memcpy(info + i, lb, ll);
    i += ll;
    info[i++] = 0;
    return sc_hkdf_expand(h, sec, sn, info, i, out, on);
}

static int server_suite(const unsigned char *d, size_t n) {
    if (n < 5 || d[0] != 22) return -1;
    size_t len = get16(d + 3);
    const unsigned char *b = d + 5;
    if (len > n - 5 || len < 40 || b[0] != 2) return -1;
    size_t sid = b[38];
    if (39 + sid + 2 > len) return -1;
    return (int)get16(b + 39 + sid);
}

static void decrypt(const char *keylog, const unsigned char *c, size_t cn, const unsigned char *s, size_t sn) {
    if (cn < 5 + 38 || c[0] != 22 || c[5] != 1) { fprintf(stderr, "h2tap: no ClientHello\n"); exit(2); }
    const unsigned char *rnd = c + 5 + 6;
    int suite = server_suite(s, sn);
    enum sc_hash h;
    enum sc_aead_alg a;
    switch (suite) {
    case 0x1301: h = SC_SHA256; a = SC_AES128_GCM; break;
    case 0x1302: h = SC_SHA384; a = SC_AES256_GCM; break;
    case 0x1303: h = SC_SHA256; a = SC_CHACHA20_POLY1305; break;
    default: fprintf(stderr, "h2tap: suite %#x not handled\n", (unsigned)suite); exit(3);
    }
    unsigned char sec[64], key[32], iv[12];
    size_t secn = find_secret(keylog, rnd, sec);
    if (secn != sc_hash_len(h)) { fprintf(stderr, "h2tap: no CLIENT_TRAFFIC_SECRET_0 for this client random\n"); exit(3); }
    size_t kn = sc_aead_key_len(a);
    struct sc_aead k;
    if (expand_label(h, sec, secn, "key", key, kn) || expand_label(h, sec, secn, "iv", iv, 12) ||
        sc_aead_setkey(&k, a, key)) { fprintf(stderr, "h2tap: key setup failed\n"); exit(2); }
    static unsigned char tmp[16384 + 512];
    int fin = 0;
    uint64_t seq = 0;
    size_t p = 0;
    while (p + 5 <= cn) {
        size_t len = get16(c + p + 3);
        if (p + 5 + len > cn) break;
        const unsigned char *body = c + p + 5;
        if (c[p] == 23 && !fin) fin = 1;
        else if (c[p] == 23) {
            if (len < 17 || len > sizeof tmp) { fprintf(stderr, "h2tap: bad record length %zu\n", len); exit(2); }
            memcpy(tmp, body, len);
            unsigned char nonce[12];
            memcpy(nonce, iv, 12);
            for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(seq >> (8 * i));
            if (sc_aead_open(&k, nonce, c + p, 5, tmp, len - 16, tmp + len - 16)) {
                fprintf(stderr, "h2tap: record %llu does not decrypt\n", (unsigned long long)seq);
                exit(2);
            }
            seq++;
            size_t m = len - 16;
            while (m && tmp[m - 1] == 0) m--;
            if (!m) { fprintf(stderr, "h2tap: record without content type\n"); exit(2); }
            unsigned char ct = tmp[--m];
            if (ct == 23) {
                st = grow(st, &st_cap, st_n + m, 1);
                memcpy(st + st_n, tmp, m);
                rv = grow(rv, &rcap, rn + 1, sizeof *rv);
                rv[rn].off = st_n;
                rv[rn].len = m;
                rn++;
                st_n += m;
            } else if (ct != 21) {
                fprintf(stderr, "h2tap: inner content type %u not handled\n", ct);
                exit(2);
            }
        }
        p += 5 + len;
    }
    sc_aead_free(&k);
}

static size_t rec_of(size_t off) {
    size_t lo = 0, hi = rn;
    while (hi - lo > 1) {
        size_t m = (lo + hi) / 2;
        if (rv[m].off <= off) lo = m;
        else hi = m;
    }
    return lo;
}

static int mid(size_t off) { return off < st_n && rv[rec_of(off)].off != off; }

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void block_done(size_t first, size_t last, size_t n) {
    bv = grow(bv, &bcap, bn + 1, sizeof *bv);
    struct blk *b = &bv[bn++];
    memset(b, 0, sizeof *b);
    b->rec = rec_of(fv[first].off);
    b->frame_last = last;
    memcpy(b->hb, hbuf, n < 3 ? n : 3);
    if (hr_decode_ctx(&hctx, hbuf, n, &hblk)) {
        fprintf(stderr, "h2tap: header block at record %zu does not decode\n", b->rec);
        exit(2);
    }
    b->nupd = hblk.nupd;
    b->upd0 = hblk.nupd ? hblk.upd[0] : 0;
    static const char *const want[4] = { ":authority", ":method", ":path", ":scheme" };
    size_t np = 0;
    int ok = 1;
    const char *nm[HR_MAX];
    size_t tot = 1;
    for (size_t i = 0; i < hblk.n; i++) {
        nm[i] = hblk.f[i].name;
        tot += strlen(hblk.f[i].name) + 1;
        if (hblk.f[i].name[0] != ':') continue;
        if (np >= 4 || np != i || strcmp(hblk.f[i].name, want[np])) ok = 0;
        np++;
        if (!strcmp(hblk.f[i].name, ":method"))
            snprintf(b->method, sizeof b->method, "%s", hblk.f[i].value);
    }
    b->pseudo_ok = ok && np == 4;
    qsort(nm, hblk.n, sizeof nm[0], cmp_str);
    size_t ft = 1;
    for (size_t i = 0; i < hblk.n; i++) ft += strlen(hblk.f[i].name) + strlen(hblk.f[i].value) + 3;
    b->fields = malloc(ft);
    if (!b->fields) { fprintf(stderr, "h2tap: out of memory\n"); exit(2); }
    char *fp = b->fields;
    for (size_t i = 0; i < hblk.n; i++) fp += sprintf(fp, "%s: %s\n", hblk.f[i].name, hblk.f[i].value);
    *fp = '\0';
    b->names = malloc(tot);
    if (!b->names) { fprintf(stderr, "h2tap: out of memory\n"); exit(2); }
    b->names[0] = '\0';
    for (size_t i = 0; i < hblk.n; i++) {
        if (i) strcat(b->names, " ");
        strcat(b->names, nm[i]);
    }
}

static void parse_fail(const char *why) {
    fprintf(strcmp(g_cmd, "check") ? stderr : stdout, "FAIL rec 0: %s\n", why);
    exit(1);
}

static void parse(void) {
    if (!rn) parse_fail("no application record");
    if (st_n < 24 || memcmp(st, go_preface, 24)) parse_fail("no h2 preface");
    size_t p = 24;
    while (p + 9 <= st_n) {
        uint32_t len = get24(st + p);
        if (p + 9 + len > st_n) break;
        fv = grow(fv, &fcap, fn + 1, sizeof *fv);
        fv[fn].off = p;
        fv[fn].len = len;
        fv[fn].type = st[p + 3];
        fv[fn].flags = st[p + 4];
        fv[fn].sid = get32(st + p + 5) & 0x7fffffffu;
        if (fv[fn].type == 4 && (fv[fn].flags & 1) && ack_rec == SIZE_MAX) ack_rec = rec_of(p);
        fn++;
        p += 9 + len;
    }
    hr_ctx_init(&hctx, 4096);
    size_t i = 0;
    while (i < fn) {
        uv = grow(uv, &ucap, un + 1, sizeof *uv);
        struct unit *u = &uv[un++];
        u->off = i == 0 ? 0 : fv[i].off;
        u->frame = i;
        size_t j = i + 1;
        const struct frm *f = &fv[i];
        if (i == 0) {
            if (j < fn && fv[j].type == 8 && fv[j].sid == 0 && mid(fv[j].off)) j++;
        } else if (f->type == 1) {
            size_t n = 0, last = i;
            int end = f->flags & 4;
            for (size_t k = i;; k++) {
                if (k > i && (k >= fn || fv[k].type != 9)) break;
                const unsigned char *pl = st + fv[k].off + 9;
                uint32_t pl_n = fv[k].len;
                if (k == i && (f->flags & 8)) {
                    if (!pl_n || pl[0] >= pl_n) { fprintf(stderr, "h2tap: bad padding\n"); exit(2); }
                    pl_n -= 1u + pl[0];
                    pl++;
                }
                if (k == i && (f->flags & 0x20)) {
                    if (pl_n < 5) { fprintf(stderr, "h2tap: HEADERS priority field cut short\n"); exit(2); }
                    pl += 5;
                    pl_n -= 5;
                }
                if (n + pl_n > sizeof hbuf) { fprintf(stderr, "h2tap: header block too large\n"); exit(2); }
                memcpy(hbuf + n, pl, pl_n);
                n += pl_n;
                last = k;
                j = k + 1;
                if (k > i) end = fv[k].flags & 4;
                if (end) break;
            }
            if (end) block_done(i, last, n);
            else if (open_rec == SIZE_MAX) open_rec = rec_of(f->off);
        } else if (f->type == 3) {
            if (j < fn && fv[j].type == 6 && !(fv[j].flags & 1) && mid(fv[j].off)) j++;
        } else if (f->type == 8 && f->sid == 0) {
            if (j < fn && fv[j].type == 8 && fv[j].sid != 0 && mid(fv[j].off)) j++;
        }
        u->end = j < fn ? fv[j].off : fv[j - 1].off + 9 + fv[j - 1].len;
        i = j;
    }
}

static const char *tname(uint8_t t) {
    static const char *const n[10] = { "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
                                       "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION" };
    return t < 10 ? n[t] : "UNKNOWN";
}

static const char *ukind(size_t u) {
    const struct frm *f = &fv[uv[u].frame];
    if (uv[u].frame == 0) return "preface";
    return tname(f->type);
}

static int cmd_check(void) {
    if (rv[0].len != sizeof go_preface || memcmp(st, go_preface, sizeof go_preface)) {
        printf("FAIL rec 0: not the 70 B preface (%zu B)\n", rv[0].len);
        return 1;
    }
    for (size_t u = 0; u + 1 < un; u++) {
        if (!mid(uv[u].end)) continue;
        printf("FAIL rec %zu: holds bytes of two units (%s, %s)\n", rec_of(uv[u].end), ukind(u), ukind(u + 1));
        return 1;
    }
    if (open_rec != SIZE_MAX) {
        printf("FAIL rec %zu: header block not ended\n", open_rec);
        return 1;
    }
    size_t first_after = SIZE_MAX;
    for (size_t b = 0; b < bn && first_after == SIZE_MAX; b++)
        if (ack_rec != SIZE_MAX && bv[b].rec > ack_rec) first_after = b;
    for (size_t b = 0; b < bn; b++) {
        if (bv[b].nupd && bv[b].rec > ack_rec && b != first_after) {
            printf("FAIL rec %zu: a size update in a block after the first one after the SETTINGS ACK record\n", bv[b].rec);
            return 1;
        }
        if (!bv[b].pseudo_ok) {
            printf("FAIL rec %zu: pseudo order is not :authority :method :path :scheme (%s)\n", bv[b].rec, bv[b].names);
            return 1;
        }
        if (bv[b].nupd && bv[b].rec < ack_rec) {
            printf("FAIL rec %zu: a size update in a block before the SETTINGS ACK record\n", bv[b].rec);
            return 1;
        }
    }
    printf("ok records %zu frames %zu units %zu blocks %zu\n", rn, fn, un, bn);
    return 0;
}

static int cmd_first(void) {
    size_t h = SIZE_MAX;
    for (size_t i = 0; i < fn; i++)
        if (fv[i].type == 1) { h = rec_of(fv[i].off); break; }
    if (h == SIZE_MAX && ack_rec == SIZE_MAX) printf("none\n");
    else printf(h < ack_rec ? "headers-first\n" : "ack-first\n");
    return 0;
}

static int cmd_afterack(void) {
    for (size_t b = 0; b < bn; b++)
        if (ack_rec != SIZE_MAX && bv[b].rec > ack_rec) {
            printf("%02x%02x%02x\n", bv[b].hb[0], bv[b].hb[1], bv[b].hb[2]);
            return 0;
        }
    printf("none\n");
    return 0;
}

static int cmd_names(const char *method) {
    for (size_t b = 0; b < bn; b++)
        if (!strcmp(bv[b].method, method)) { printf("%s\n", bv[b].names); return 0; }
    return 1;
}

static int cmd_fields(const char *method) {
    for (size_t b = 0; b < bn; b++)
        if (!strcmp(bv[b].method, method)) { fputs(bv[b].fields, stdout); return 0; }
    return 1;
}

static const char *field_of(const char *fields, const char *name, size_t *n) {
    size_t k = strlen(name);
    for (const char *l = fields; *l; l = strchr(l, '\n') + 1) {
        if (!strncmp(l, name, k) && l[k] == ':' && l[k + 1] == ' ') {
            *n = strcspn(l + k + 2, "\n");
            return l + k + 2;
        }
        if (!strchr(l, '\n')) break;
    }
    return NULL;
}

static int cmd_posts(void) {
    for (size_t b = 0; b < bn; b++) {
        if (strcmp(bv[b].method, "POST")) continue;
        size_t pn = 0, cn = 0;
        const char *p = field_of(bv[b].fields, ":path", &pn), *c = field_of(bv[b].fields, "content-length", &cn);
        printf("%.*s %.*s\n", (int)(p ? pn : 1), p ? p : "-", (int)(c ? cn : 1), c ? c : "-");
    }
    return 0;
}

static int cmd_wu(void) {
    size_t pairs = 0, lone0 = 0, lones = 0;
    for (size_t u = 0; u < un; u++) {
        const struct frm *f = &fv[uv[u].frame];
        if (uv[u].frame == 0 || f->type != 8) continue;
        if (f->sid) lones++;
        else if (uv[u].end > f->off + 13) pairs++;
        else lone0++;
    }
    printf("pairs %zu lone0 %zu lonestream %zu\n", pairs, lone0, lones);
    return 0;
}

static int cmd_dump(void) {
    printf("hex0 ");
    for (size_t i = 0; i < rv[0].len; i++) printf("%02x", st[i]);
    printf("\n");
    size_t f = 0, b = 0;
    for (size_t r = 0; r < rn; r++) {
        printf("rec %zu %zu", r, rv[r].len);
        if (f && f <= fn && fv[f - 1].off + 9 + fv[f - 1].len > rv[r].off && fv[f - 1].off < rv[r].off) printf(" ..");
        while (f < fn && fv[f].off < rv[r].off + rv[r].len) {
            const struct frm *x = &fv[f];
            const unsigned char *pl = st + x->off + 9;
            printf(" %s/%u/%u/%u", tname(x->type), x->flags, x->sid, x->len);
            if (x->type == 4 && !(x->flags & 1)) {
                printf("[");
                for (uint32_t k = 0; k + 6 <= x->len; k += 6) printf("%s%u=%u", k ? "," : "", get16(pl + k), get32(pl + k + 2));
                printf("]");
            } else if (x->type == 8 && x->len == 4) {
                printf("+%u", get32(pl) & 0x7fffffffu);
            } else if (x->type == 3 && x->len == 4) {
                printf("=%u", get32(pl));
            }
            while (b < bn && bv[b].frame_last == f) {
                printf("[hb=%02x%02x%02x", bv[b].hb[0], bv[b].hb[1], bv[b].hb[2]);
                if (bv[b].nupd) printf(",upd=%u", bv[b].upd0);
                printf(",");
                for (const char *s = bv[b].names; *s; s++) putchar(*s == ' ' ? ',' : *s);
                printf("]");
                b++;
            }
            f++;
        }
        printf("\n");
    }
    return 0;
}

static size_t ramp_cap(size_t i) { return i < 13 ? 1186 * (i + 1) : 16384; }

static int ramp_over(void) {
    for (size_t i = 0; i < rn; i++)
        if (rv[i].len > ramp_cap(i)) {
            printf("FAIL rec %zu: %zu over %zu\n", i, rv[i].len, ramp_cap(i));
            return 1;
        }
    return 0;
}

static int cmd_lens(size_t n) {
    if (!n || n > rn) n = rn;
    for (size_t i = 0; i < n; i++) printf(i ? " %zu" : "%zu", rv[i].len);
    printf("\n");
    return 0;
}

static int cmd_ramp(void) {
    if (ramp_over()) return 1;
    printf("ok records %zu\n", rn);
    return 0;
}

static int cmd_ramp_units(void) {
    if (ramp_over()) return 1;
    for (size_t u = 0; u < un; u++)
        for (size_t r = rec_of(uv[u].off); r + 1 < rn && rv[r].off + rv[r].len < uv[u].end; r++)
            if (rv[r].len != ramp_cap(r)) {
                printf("FAIL rec %zu: cut inside a unit at %zu, cap %zu\n", r, rv[r].len, ramp_cap(r));
                return 1;
            }
    printf("ok records %zu units %zu\n", rn, un);
    return 0;
}

static int cmd_has(const char *needle) {
    size_t k = strlen(needle);
    for (size_t i = 0; k && i + k <= st_n; i++)
        if (!memcmp(st + i, needle, k)) return 0;
    return 1;
}

static int count_arg(const char *a, size_t *out) {
    if (*a < '0' || *a > '9') return -1;
    char *e;
    errno = 0;
    unsigned long v = strtoul(a, &e, 10);
    if (*e || errno) return -1;
    *out = v;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 5 || ((!strcmp(argv[1], "names") || !strcmp(argv[1], "has") || !strcmp(argv[1], "fields")) && argc < 6)) {
        fprintf(stderr, "usage: h2tap dump|check|first|wu|posts|afterack|names|fields|lens|ramp|ramp-units|has KEYLOG C2S S2C [METHOD|N|TEXT]\n");
        return 2;
    }
    size_t lens_n = 0;
    if (!strcmp(argv[1], "lens") && argc > 5 && count_arg(argv[5], &lens_n)) {
        fprintf(stderr, "h2tap: lens N: %s is not a record count\n", argv[5]);
        return 2;
    }
    size_t cn, sn;
    unsigned char *c = slurp(argv[3], &cn), *s = slurp(argv[4], &sn);
    g_cmd = argv[1];
    decrypt(argv[2], c, cn, s, sn);
    free(c);
    free(s);
    if (!strcmp(argv[1], "lens")) return cmd_lens(lens_n);
    if (!strcmp(argv[1], "ramp")) return cmd_ramp();
    if (!strcmp(argv[1], "has")) return cmd_has(argv[5]);
    parse();
    if (!strcmp(argv[1], "ramp-units")) return cmd_ramp_units();
    if (!strcmp(argv[1], "check")) return cmd_check();
    if (!strcmp(argv[1], "first")) return cmd_first();
    if (!strcmp(argv[1], "names")) return cmd_names(argv[5]);
    if (!strcmp(argv[1], "fields")) return cmd_fields(argv[5]);
    if (!strcmp(argv[1], "wu")) return cmd_wu();
    if (!strcmp(argv[1], "posts")) return cmd_posts();
    if (!strcmp(argv[1], "afterack")) return cmd_afterack();
    if (!strcmp(argv[1], "dump")) return cmd_dump();
    fprintf(stderr, "h2tap: unknown command %s\n", argv[1]);
    return 2;
}
