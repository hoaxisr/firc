#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int seq;

static int dry(void) {
    const char *d = getenv("XTC_DRY");
    return d != NULL && strcmp(d, "1") == 0;
}

static uint32_t u32(const unsigned char *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static unsigned char *load(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    unsigned char *buf = NULL;
    size_t cap = 0, n = 0, got;
    do {
        if (n == cap) {
            cap = cap ? cap * 2 : 65536;
            unsigned char *nb = realloc(buf, cap);
            if (nb == NULL) { free(buf); fclose(f); return NULL; }
            buf = nb;
        }
        got = fread(buf + n, 1, cap - n, f);
        n += got;
    } while (got > 0);
    fclose(f);
    *len = n;
    return buf;
}

static int seed_view(const unsigned char *s, size_t n, unsigned char info[84], size_t *blob_at) {
    if (n >= 96 && n == 96u + u32(s + 40)) {
        memcpy(info, s, 32);
        memcpy(info + 32, s + 32, 4);
        memcpy(info + 36, s + 44, 40);
        memcpy(info + 76, s + 36, 8);
        *blob_at = 96;
        return 0;
    }
    if (n >= 84 && n == 84u + u32(s + 80)) {
        memcpy(info, s, 84);
        *blob_at = 84;
        return 0;
    }
    return -1;
}

static int zero_counters(unsigned char *blob, size_t size, int v6) {
    size_t at_next = v6 ? 142 : 90, at_cnt = v6 ? 152 : 96, min = v6 ? 168 : 112;
    size_t off = 0;
    while (off < size) {
        if (size - off < min) { return -1; }
        uint16_t next;
        memcpy(&next, blob + off + at_next, sizeof(next));
        if (next < min || next > size - off) { return -1; }
        memset(blob + off + at_cnt, 0, 16);
        off += next;
    }
    return 0;
}

static void mark(const char *what) {
    const char *dir = getenv("XTCAPTURE_DIR");
    if (dir == NULL) { return; }
    char path[1024];
    snprintf(path, sizeof(path), "%s/dry-%s", dir, what);
    FILE *f = fopen(path, "w");
    if (f != NULL) { fclose(f); }
}

int getsockopt(int fd, int level, int opt, void *val, socklen_t *len) {
    int (*real)(int, int, int, void *, socklen_t *);
    *(void **)(&real) = dlsym(RTLD_NEXT, "getsockopt");
    if (!dry() || (level != 0 && level != 41) || (opt != 64 && opt != 65) || val == NULL || len == NULL || *len < 40) {
        return real(fd, level, opt, val, len);
    }
    const char *path = getenv("XTC_SEED");
    size_t n = 0, blob_at = 0;
    unsigned char info[84];
    unsigned char *seed = path != NULL ? load(path, &n) : NULL;
    if (seed == NULL || seed_view(seed, n, info, &blob_at) != 0) {
        free(seed);
        errno = EIO;
        return -1;
    }
    if (strncmp((const char *)val, (const char *)info, 32) != 0) {
        free(seed);
        return real(fd, level, opt, val, len);
    }
    uint32_t size = u32(info + 80);
    int rc = 0;
    if (opt == 64) {
        if (*len != 84) {
            rc = -1;
        } else {
            memcpy(val, info, 84);
            mark("answered");
        }
    } else {
        unsigned char *out = val;
        if (*len != 40u + size || u32(out + 32) != size) {
            rc = -1;
        } else {
            memcpy(out + 40, seed + blob_at, size);
            if (zero_counters(out + 40, size, level == 41) != 0) { rc = -1; }
        }
    }
    free(seed);
    if (rc != 0) { errno = EINVAL; }
    return rc;
}

int setsockopt(int fd, int level, int opt, const void *val, socklen_t len) {
    int (*real)(int, int, int, const void *, socklen_t);
    *(void **)(&real) = dlsym(RTLD_NEXT, "setsockopt");
    if ((level != 0 && level != 41) || (opt != 64 && opt != 65)) {
        return real(fd, level, opt, val, len);
    }
    const char *dir = getenv("XTCAPTURE_DIR");
    if (dir != NULL) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/%03d-%s.bin", dir, seq++, opt == 64 ? "replace" : "counters");
        FILE *f = fopen(path, "w");
        if (f != NULL) {
            fwrite(val, 1, len, f);
            fclose(f);
        }
    }
    if (!dry()) {
        return real(fd, level, opt, val, len);
    }
    if (opt == 64 && len >= 96) {
        void *counters;
        memcpy(&counters, (const unsigned char *)val + 88, sizeof(counters));
        uint32_t num = u32((const unsigned char *)val + 84);
        if (counters != NULL && num > 0) { memset(counters, 0, (size_t)num * 16u); }
    }
    return 0;
}
