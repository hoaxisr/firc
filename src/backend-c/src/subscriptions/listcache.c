#include "firc/listcache.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <zlib.h>

#include "firc/atomic_write.h"
#include "firc/hash.h"
#include "firc/sub_fetch.h"

#define HEX_LEN 16
#define NAME_LEN (2 * HEX_LEN + 1)
#define TMP_MID ".tmp."
#define TMP_LEN (NAME_LEN + 5 + 6)
#define RESERVE_MIN ((uint64_t)8 * 1024 * 1024)
#define PATH_CAP 512
#define MAX_BODY FIRC_SUB_FETCH_MAX_BODY_BYTES

firc_listcache_room_fn firc_listcache_room_hook_for_test;

static void hex8(const uint8_t *h, char out[HEX_LEN + 1])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < HEX_LEN / 2; i++) {
        out[2 * i] = digits[(unsigned)h[i] >> 4U];
        out[2 * i + 1] = digits[(unsigned)h[i] & 15U];
    }
    out[HEX_LEN] = 0;
}

static bool is_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool is_cache_prefix(const char *name)
{
    return is_hex(name, HEX_LEN) && name[HEX_LEN] == '-' && is_hex(name + HEX_LEN + 1, HEX_LEN);
}

static bool is_cache_name(const char *name)
{
    return strlen(name) == NAME_LEN && is_cache_prefix(name);
}

static bool is_temp_name(const char *name)
{
    return strlen(name) == TMP_LEN && is_cache_prefix(name) &&
           memcmp(name + NAME_LEN, TMP_MID, 5) == 0;
}

static bool of_key(const char *name, const char *key)
{
    return strncmp(name, key, HEX_LEN) == 0 && name[HEX_LEN] == '-';
}

void firc_listcache_key(const char *url, char out[17])
{
    uint8_t h[FIRC_SHA256_DIGEST_LEN];
    firc_sha256((const uint8_t *)url, strlen(url), h);
    hex8(h, out);
}

bool firc_listcache_room(uint64_t fs_total, uint64_t fs_free, uint64_t held, uint64_t size)
{
    uint64_t reserve = fs_total / 10 > RESERVE_MIN ? fs_total / 10 : RESERVE_MIN;
    if (size > fs_free || fs_free - size < reserve) {
        return false;
    }
    return held + size <= (fs_free + held) / 2;
}

static firc_err_t make_dirs(const char *dir)
{
    char p[PATH_CAP];
    int n = snprintf(p, sizeof p, "%s", dir);
    if (n < 0 || (size_t)n >= sizeof p) {
        return FIRC_ERR_INVAL;
    }
    for (char *q = p + 1; *q != 0; q++) {
        if (*q == '/') {
            *q = 0;
            (void)mkdir(p, 0700);
            *q = '/';
        }
    }
    if (mkdir(p, 0700) == 0) {
        return FIRC_OK;
    }
    struct stat st;
    if (errno == EEXIST && stat(p, &st) == 0 && S_ISDIR(st.st_mode)) {
        return FIRC_OK;
    }
    return FIRC_ERR_IO;
}

static firc_err_t gzip_body(const uint8_t *body, size_t len, uint8_t **out, size_t *out_len)
{
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (deflateInit2(&zs, 9, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return FIRC_ERR_NOMEM;
    }
    uLong cap = deflateBound(&zs, (uLong)len);
    uint8_t *buf = malloc(cap);
    if (buf == NULL) {
        deflateEnd(&zs);
        return FIRC_ERR_NOMEM;
    }
    zs.next_in = (Bytef *)body;
    zs.avail_in = (uInt)len;
    zs.next_out = buf;
    zs.avail_out = (uInt)cap;
    int rc = deflate(&zs, Z_FINISH);
    size_t got = (size_t)zs.total_out;
    deflateEnd(&zs);
    if (rc != Z_STREAM_END) {
        free(buf);
        return FIRC_ERR_IO;
    }
    *out = buf;
    *out_len = got;
    return FIRC_OK;
}

static firc_err_t held_sizes(const char *dir, const char *key, uint64_t *others, uint64_t *own)
{
    DIR *d = opendir(dir);
    if (d == NULL) {
        return firc_err_from_errno(errno);
    }
    int dfd = dirfd(d);
    if (dfd < 0) {
        closedir(d);
        return FIRC_ERR_IO;
    }
    uint64_t sum = 0;
    uint64_t mine = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 ||
            fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        if (!of_key(e->d_name, key)) {
            sum += (uint64_t)st.st_size;
        } else if (is_cache_name(e->d_name)) {
            mine += (uint64_t)st.st_size;
        }
    }
    closedir(d);
    *others = sum;
    *own = mine;
    return FIRC_OK;
}

static void remove_others(const char *dir, const char *key, const char *keep)
{
    DIR *d = opendir(dir);
    if (d == NULL) {
        return;
    }
    int dfd = dirfd(d);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (is_cache_name(e->d_name) && of_key(e->d_name, key) && strcmp(e->d_name, keep) != 0 && dfd >= 0) {
            (void)unlinkat(dfd, e->d_name, 0);
        }
    }
    closedir(d);
}

firc_err_t firc_listcache_write(const char *dir, const char *key, const uint8_t *body, size_t len,
                                const uint8_t hash[32])
{
    if (dir == NULL || key == NULL || (body == NULL && len > 0) || hash == NULL ||
        strlen(key) != HEX_LEN || !is_hex(key, HEX_LEN) || len > MAX_BODY) {
        return FIRC_ERR_INVAL;
    }
    char hx[HEX_LEN + 1];
    hex8(hash, hx);
    char name[NAME_LEN + 1];
    snprintf(name, sizeof name, "%s-%s", key, hx);
    char path[PATH_CAP];
    int n = snprintf(path, sizeof path, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof path) {
        return FIRC_ERR_INVAL;
    }
    struct stat st;
    if (stat(path, &st) == 0) {
        remove_others(dir, key, name);
        return FIRC_OK;
    }
    firc_err_t rc = make_dirs(dir);
    if (rc != FIRC_OK) {
        return rc;
    }

    uint8_t *packed = NULL;
    const uint8_t *data = body;
    size_t data_len = len;
    if (!(len >= 3 && memcmp(body, "SRS", 3) == 0)) {
        rc = gzip_body(body, len, &packed, &data_len);
        if (rc != FIRC_OK) {
            return rc;
        }
        data = packed;
    }

    struct statvfs vfs;
    uint64_t held = 0;
    uint64_t own = 0;
    if (statvfs(dir, &vfs) != 0) {
        rc = firc_err_from_errno(errno);
    } else {
        rc = held_sizes(dir, key, &held, &own);
    }
    if (rc == FIRC_OK) {
        firc_listcache_room_fn room =
            firc_listcache_room_hook_for_test != NULL ? firc_listcache_room_hook_for_test
                                                      : firc_listcache_room;
        uint64_t total = (uint64_t)vfs.f_blocks * (uint64_t)vfs.f_frsize;
        uint64_t avail = (uint64_t)vfs.f_bavail * (uint64_t)vfs.f_frsize;
        if (!room(total, avail + own, held, (uint64_t)data_len)) {
            rc = FIRC_ERR_LIMIT;
        } else {
            rc = firc_atomic_write(path, (const char *)data, data_len);
        }
    }
    free(packed);
    if (rc == FIRC_OK) {
        remove_others(dir, key, name);
    }
    return rc;
}

static firc_err_t inflate_body(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit2(&zs, 32 + 15) != Z_OK) {
        return FIRC_ERR_NOMEM;
    }
    size_t cap = in_len > MAX_BODY / 4 ? MAX_BODY + 1 : in_len * 4 + 4096;
    if (cap > MAX_BODY + 1) {
        cap = MAX_BODY + 1;
    }
    uint8_t *buf = malloc(cap);
    firc_err_t err = buf == NULL ? FIRC_ERR_NOMEM : FIRC_ERR_PROTO;
    size_t have = 0;
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)in_len;
    while (buf != NULL) {
        zs.next_out = buf + have;
        zs.avail_out = (uInt)(cap - have);
        int rc = inflate(&zs, Z_NO_FLUSH);
        have = (size_t)(zs.next_out - buf);
        if (rc == Z_STREAM_END) {
            err = have <= MAX_BODY ? FIRC_OK : FIRC_ERR_PROTO;
            break;
        }
        if (rc == Z_MEM_ERROR) {
            err = FIRC_ERR_NOMEM;
            break;
        }
        if ((rc != Z_OK && rc != Z_BUF_ERROR) || zs.avail_out != 0 || cap > MAX_BODY) {
            break;
        }
        size_t grown = cap * 2 > MAX_BODY + 1 ? MAX_BODY + 1 : cap * 2;
        uint8_t *nb = realloc(buf, grown);
        if (nb == NULL) {
            err = FIRC_ERR_NOMEM;
            break;
        }
        buf = nb;
        cap = grown;
    }
    inflateEnd(&zs);
    if (err != FIRC_OK) {
        free(buf);
        return err;
    }
    *out = buf;
    *out_len = have;
    return FIRC_OK;
}

static firc_err_t load_file(int fd, uint8_t **buf, size_t *len, time_t *mtime)
{
    struct stat st;
    if (fstat(fd, &st) != 0) {
        return firc_err_from_errno(errno);
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size > (uint64_t)MAX_BODY * 2) {
        return FIRC_ERR_PROTO;
    }
    size_t size = (size_t)st.st_size;
    uint8_t *b = malloc(size > 0 ? size : 1);
    if (b == NULL) {
        return FIRC_ERR_NOMEM;
    }
    size_t got = 0;
    while (got < size) {
        ssize_t r = read(fd, b + got, size - got);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            free(b);
            return r == 0 ? FIRC_ERR_PROTO : firc_err_from_errno(errno);
        }
        got += (size_t)r;
    }
    *buf = b;
    *len = size;
    *mtime = st.st_mtime;
    return FIRC_OK;
}

static firc_err_t read_one(const char *path, const char *name, uint8_t **body, size_t *len,
                           uint8_t digest[FIRC_SHA256_DIGEST_LEN], time_t *mtime)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? FIRC_ERR_NOENT : firc_err_from_errno(errno);
    }
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    firc_err_t err = load_file(fd, &raw, &raw_len, mtime);
    close(fd);
    if (err != FIRC_OK) {
        return err;
    }
    uint8_t *out = raw;
    size_t out_len = raw_len;
    if (raw_len >= 2 && raw[0] == 0x1f && raw[1] == 0x8b) {
        out = NULL;
        err = inflate_body(raw, raw_len, &out, &out_len);
        free(raw);
    } else if (raw_len > MAX_BODY) {
        err = FIRC_ERR_PROTO;
    }
    if (err == FIRC_OK) {
        firc_sha256(out, out_len, digest);
        char hx[HEX_LEN + 1];
        hex8(digest, hx);
        if (memcmp(hx, name + HEX_LEN + 1, HEX_LEN) != 0) {
            err = FIRC_ERR_PROTO;
        }
    }
    if (err != FIRC_OK) {
        free(out);
        return err;
    }
    *body = out;
    *len = out_len;
    return FIRC_OK;
}

#define READ_TRIES 8

static size_t newest_names(DIR *d, const char *key, char names[READ_TRIES][NAME_LEN + 1])
{
    int dfd = dirfd(d);
    time_t when[READ_TRIES];
    size_t n = 0;
    struct dirent *e;
    while (dfd >= 0 && (e = readdir(d)) != NULL) {
        struct stat st;
        if (!is_cache_name(e->d_name) || !of_key(e->d_name, key) ||
            fstatat(dfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }
        size_t at = n;
        while (at > 0 && st.st_mtime > when[at - 1]) {
            at--;
        }
        if (at >= READ_TRIES) {
            continue;
        }
        size_t last = n < READ_TRIES ? n : READ_TRIES - 1;
        for (size_t i = last; i > at; i--) {
            memcpy(names[i], names[i - 1], NAME_LEN + 1);
            when[i] = when[i - 1];
        }
        memcpy(names[at], e->d_name, NAME_LEN + 1);
        when[at] = st.st_mtime;
        if (n < READ_TRIES) {
            n++;
        }
    }
    return n;
}

firc_err_t firc_listcache_read(const char *dir, const char *key, uint8_t **body, size_t *len,
                               uint8_t hash[32], time_t *mtime)
{
    if (dir == NULL || key == NULL || body == NULL || len == NULL || hash == NULL ||
        mtime == NULL || strlen(key) != HEX_LEN) {
        return FIRC_ERR_INVAL;
    }
    *body = NULL;
    *len = 0;
    DIR *d = opendir(dir);
    if (d == NULL) {
        return errno == ENOENT ? FIRC_ERR_NOENT : firc_err_from_errno(errno);
    }
    char names[READ_TRIES][NAME_LEN + 1];
    size_t n = newest_names(d, key, names);
    closedir(d);
    for (size_t i = 0; i < n; i++) {
        char path[PATH_CAP];
        int w = snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        if (w < 0 || (size_t)w >= sizeof path) {
            return FIRC_ERR_INVAL;
        }
        uint8_t digest[FIRC_SHA256_DIGEST_LEN] = {0};
        time_t when = 0;
        firc_err_t err = read_one(path, names[i], body, len, digest, &when);
        if (err == FIRC_OK) {
            remove_others(dir, key, names[i]);
            memcpy(hash, digest, sizeof digest);
            *mtime = when;
            return FIRC_OK;
        }
        if (err == FIRC_ERR_PROTO) {
            (void)unlink(path);
        } else if (err != FIRC_ERR_NOENT) {
            return err;
        }
    }
    return FIRC_ERR_NOENT;
}

firc_err_t firc_listcache_remove(const char *dir, const char *key, const uint8_t hash[32])
{
    if (dir == NULL || key == NULL || hash == NULL || strlen(key) != HEX_LEN) {
        return FIRC_ERR_INVAL;
    }
    char hx[HEX_LEN + 1];
    hex8(hash, hx);
    char path[PATH_CAP];
    int n = snprintf(path, sizeof path, "%s/%s-%s", dir, key, hx);
    if (n < 0 || (size_t)n >= sizeof path) {
        return FIRC_ERR_INVAL;
    }
    if (unlink(path) != 0 && errno != ENOENT) {
        return firc_err_from_errno(errno);
    }
    return FIRC_OK;
}

static bool listed(const char *name, const char *const *keys, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (keys[i] != NULL && of_key(name, keys[i])) {
            return true;
        }
    }
    return false;
}

firc_err_t firc_listcache_sweep(const char *dir, const char *const *keys, size_t n)
{
    if (dir == NULL) {
        return FIRC_ERR_INVAL;
    }
    DIR *d = opendir(dir);
    if (d == NULL) {
        return errno == ENOENT ? FIRC_OK : firc_err_from_errno(errno);
    }
    int dfd = dirfd(d);
    if (dfd < 0) {
        closedir(d);
        return FIRC_ERR_IO;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        bool drop = (keys == NULL && is_temp_name(e->d_name)) ||
                    (keys != NULL && is_cache_name(e->d_name) && !listed(e->d_name, keys, n));
        if (drop) {
            (void)unlinkat(dfd, e->d_name, 0);
        }
    }
    closedir(d);
    return FIRC_OK;
}
