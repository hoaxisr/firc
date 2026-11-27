#include "greatest.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <zlib.h>

#include "firc/hash.h"
#include "firc/listcache.h"
#include "firc/sub_fetch.h"

#define MIB ((uint64_t)1024 * 1024)
#define GIB (MIB * 1024)
#define MAX_BODY FIRC_SUB_FETCH_MAX_BODY_BYTES

void *__wrap_malloc(size_t n);
void *__wrap_realloc(void *p, size_t n);
ssize_t __wrap_read(int fd, void *buf, size_t n);
ssize_t __wrap___read_chk(int fd, void *buf, size_t n, size_t buflen);
int __wrap_statvfs(const char *path, struct statvfs *out);
extern void *__real_malloc(size_t n);
extern void *__real_realloc(void *p, size_t n);
extern ssize_t __real_read(int fd, void *buf, size_t n);
extern ssize_t __real___read_chk(int fd, void *buf, size_t n, size_t buflen);
extern int __real_statvfs(const char *path, struct statvfs *out);

static int g_mallocs_left = -1;
static bool g_realloc_fails;
static bool g_read_eio;
static bool g_fake_fs;

void *__wrap_malloc(size_t n)
{
    if (g_mallocs_left == 0) {
        return NULL;
    }
    if (g_mallocs_left > 0) {
        g_mallocs_left--;
    }
    return __real_malloc(n);
}

void *__wrap_realloc(void *p, size_t n)
{
    return g_realloc_fails ? NULL : __real_realloc(p, n);
}

ssize_t __wrap_read(int fd, void *buf, size_t n)
{
    if (g_read_eio) {
        errno = EIO;
        return -1;
    }
    return __real_read(fd, buf, n);
}

ssize_t __wrap___read_chk(int fd, void *buf, size_t n, size_t buflen)
{
    if (g_read_eio) {
        errno = EIO;
        return -1;
    }
    return __real___read_chk(fd, buf, n, buflen);
}

#define FAKE_FRSIZE 4096U
#define FAKE_BLOCKS 262144U
#define FAKE_BAVAIL 131072U

int __wrap_statvfs(const char *path, struct statvfs *out)
{
    if (!g_fake_fs) {
        return __real_statvfs(path, out);
    }
    memset(out, 0, sizeof *out);
    out->f_frsize = FAKE_FRSIZE;
    out->f_bsize = FAKE_FRSIZE;
    out->f_blocks = FAKE_BLOCKS;
    out->f_bavail = FAKE_BAVAIL;
    out->f_bfree = FAKE_BAVAIL;
    return 0;
}

static char g_dir[64];

static void make_dir(void)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/firc_lc_XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        g_dir[0] = 0;
    }
}

static void remove_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (d != NULL) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
                continue;
            }
            char p[512];
            snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

static void hex16(const uint8_t *h, char out[17])
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[2 * i] = digits[h[i] >> 4];
        out[2 * i + 1] = digits[h[i] & 15];
    }
    out[16] = 0;
}

static void file_of(const char *dir, const char *key, const uint8_t *body, size_t len,
                    char *out, size_t cap)
{
    uint8_t h[32];
    firc_sha256(body, len, h);
    char hx[17];
    hex16(h, hx);
    snprintf(out, cap, "%s/%s-%s", dir, key, hx);
}

static int entries(const char *dir)
{
    int n = 0;
    DIR *d = opendir(dir);
    if (d == NULL) {
        return -1;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0) {
            n++;
        }
    }
    closedir(d);
    return n;
}

static int put(const char *dir, const char *name, const char *text)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "w");
    if (f == NULL) {
        return -1;
    }
    fputs(text, f);
    fclose(f);
    return 0;
}

static int exists(const char *dir, const char *name)
{
    char p[512];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    struct stat st;
    return stat(p, &st) == 0;
}

static firc_err_t store(const char *key, const uint8_t *body, size_t len)
{
    uint8_t h[32];
    firc_sha256(body, len, h);
    return firc_listcache_write(g_dir, key, body, len, h);
}

static const char TEXT[] = "example.com\nfoo.example.org\n*.bar.example.net\nexample.com\n";
static const uint8_t SRS1[] = {'S', 'R', 'S', 1, 0, 0, 0, 9, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'};
static const uint8_t SRS2[] = {'S', 'R', 'S', 1, 0, 0, 0, 4, 'w', 'x', 'y', 'z'};
static const char KEY_A[] = "0123456789abcdef";
static const char KEY_B[] = "fedcba9876543210";

static uint64_t g_seen_held;
static uint64_t g_seen_size;
static uint64_t g_seen_total;
static int g_calls;

static bool room_yes(uint64_t total, uint64_t free_, uint64_t held, uint64_t size)
{
    (void)free_;
    g_seen_total = total;
    g_seen_held = held;
    g_seen_size = size;
    g_calls++;
    return true;
}

static bool room_no(uint64_t total, uint64_t free_, uint64_t held, uint64_t size)
{
    (void)total;
    (void)free_;
    (void)held;
    (void)size;
    g_calls++;
    return false;
}

/* Catches: a key from another digest, from uppercase hex, or of the wrong length. */
TEST key_is_the_first_16_hex_of_the_url_sha256(void)
{
    char k[17];
    firc_listcache_key("abc", k);
    ASSERT_STR_EQ("ba7816bf8f01cfea", k);
    PASS();
}

/* Catches: the 8 MiB floor of the reserve dropped or compared with > instead of >=. */
TEST room_the_8mib_reserve_decides_on_a_small_partition(void)
{
    uint64_t total = 30 * MIB;
    uint64_t free_ = 96 * MIB / 10;
    ASSERT(firc_listcache_room(total, free_, 0, 15 * MIB / 10));
    ASSERT_FALSE(firc_listcache_room(total, free_, 0, 17 * MIB / 10));
    ASSERT(firc_listcache_room(total, 9 * MIB, 0, MIB));
    ASSERT_FALSE(firc_listcache_room(total, 9 * MIB, 0, MIB + 1));
    PASS();
}

/* Catches: the 10 % reserve dropped, or a size larger than the free space wrapping around. */
TEST room_the_tenth_reserve_decides_on_a_large_filesystem(void)
{
    ASSERT(firc_listcache_room(16 * GIB, 12 * GIB, 0, 100 * MIB));
    ASSERT_FALSE(firc_listcache_room(16 * GIB, 1700 * MIB, 0, 100 * MIB));
    ASSERT(firc_listcache_room(16 * GIB, 1800 * MIB, 0, 100 * MIB));
    ASSERT_FALSE(firc_listcache_room(16 * GIB, 50 * MIB, 0, 100 * MIB));
    PASS();
}

/* Catches: the half rule dropped, held left out of either side, or rounded the wrong way. */
TEST room_the_half_rule_decides_when_the_cache_holds_much(void)
{
    ASSERT(firc_listcache_room(64 * MIB, 30 * MIB, 10 * MIB, 10 * MIB));
    ASSERT_FALSE(firc_listcache_room(64 * MIB, 30 * MIB, 10 * MIB, 11 * MIB));
    ASSERT_FALSE(firc_listcache_room(64 * MIB, 30 * MIB, 10 * MIB, 10 * MIB + 1));
    PASS();
}

/* Catches: text stored raw, or a round trip that changes the bytes, the hash or the mtime. */
TEST text_round_trip_is_stored_gzipped(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1));
    char p[512];
    file_of(g_dir, KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1, p, sizeof p);
    FILE *f = fopen(p, "rb");
    ASSERT(f != NULL);
    uint8_t head[2] = {0};
    size_t got = fread(head, 1, 2, f);
    fclose(f);
    ASSERT_EQ(2, (int)got);
    ASSERT_EQ(0x1f, head[0]);
    ASSERT_EQ(0x8b, head[1]);
    struct stat st;
    ASSERT_EQ(0, stat(p, &st));
    ASSERT_EQ(0600, (int)(st.st_mode & 0777));

    uint8_t *body = NULL;
    size_t len = 0;
    uint8_t h[32];
    uint8_t want[32];
    time_t mtime = 0;
    ASSERT_EQ(FIRC_OK, firc_listcache_read(g_dir, KEY_A, &body, &len, h, &mtime));
    ASSERT_EQ(sizeof TEXT - 1, len);
    ASSERT_MEM_EQ(TEXT, body, len);
    firc_sha256((const uint8_t *)TEXT, sizeof TEXT - 1, want);
    ASSERT_MEM_EQ(want, h, 32);
    ASSERT_EQ(st.st_mtime, mtime);
    free(body);
    remove_dir(g_dir);
    PASS();
}

/* Catches: an srs body gzipped, or its raw read cut short. */
TEST srs_round_trip_is_stored_raw(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, SRS1, sizeof SRS1));
    char p[512];
    file_of(g_dir, KEY_A, SRS1, sizeof SRS1, p, sizeof p);
    struct stat st;
    ASSERT_EQ(0, stat(p, &st));
    ASSERT_EQ((off_t)sizeof SRS1, st.st_size);
    FILE *f = fopen(p, "rb");
    ASSERT(f != NULL);
    uint8_t head[3] = {0};
    size_t got = fread(head, 1, 3, f);
    fclose(f);
    ASSERT_EQ(3, (int)got);
    ASSERT_MEM_EQ("SRS", head, 3);

    uint8_t *body = NULL;
    size_t len = 0;
    uint8_t h[32];
    time_t mtime = 0;
    ASSERT_EQ(FIRC_OK, firc_listcache_read(g_dir, KEY_A, &body, &len, h, &mtime));
    ASSERT_EQ(sizeof SRS1, len);
    ASSERT_MEM_EQ(SRS1, body, len);
    free(body);
    remove_dir(g_dir);
    PASS();
}

/* Catches: an existing file rewritten instead of left as it is. */
TEST the_same_body_twice_keeps_the_same_inode(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1));
    char p[512];
    file_of(g_dir, KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1, p, sizeof p);
    struct stat a;
    struct stat b;
    ASSERT_EQ(0, stat(p, &a));
    g_calls = 0;
    firc_listcache_room_hook_for_test = room_yes;
    firc_err_t rc = store(KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1);
    firc_listcache_room_hook_for_test = NULL;
    ASSERT_EQ(FIRC_OK, rc);
    ASSERT_EQ(0, g_calls);
    ASSERT_EQ(0, stat(p, &b));
    ASSERT_EQ(a.st_ino, b.st_ino);
    ASSERT_EQ(1, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

/* Catches: the key's old file kept, or another key's file removed with it. */
TEST a_new_body_replaces_only_its_own_keys_file(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, SRS1, sizeof SRS1));
    ASSERT_EQ(FIRC_OK, store(KEY_B, SRS1, sizeof SRS1));
    ASSERT_EQ(FIRC_OK, store(KEY_A, SRS2, sizeof SRS2));
    char old_a[512];
    char new_a[512];
    char b[512];
    file_of(g_dir, KEY_A, SRS1, sizeof SRS1, old_a, sizeof old_a);
    file_of(g_dir, KEY_A, SRS2, sizeof SRS2, new_a, sizeof new_a);
    file_of(g_dir, KEY_B, SRS1, sizeof SRS1, b, sizeof b);
    struct stat st;
    ASSERT(stat(old_a, &st) != 0);
    ASSERT_EQ(0, stat(new_a, &st));
    ASSERT_EQ(0, stat(b, &st));
    ASSERT_EQ(2, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a refused write that still writes, or removes the key's old file. */
TEST a_refusal_keeps_the_old_file_and_writes_nothing(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, SRS1, sizeof SRS1));
    g_calls = 0;
    firc_listcache_room_hook_for_test = room_no;
    firc_err_t rc = store(KEY_A, SRS2, sizeof SRS2);
    firc_listcache_room_hook_for_test = NULL;
    ASSERT_EQ(FIRC_ERR_LIMIT, rc);
    ASSERT_EQ(1, g_calls);
    char old_a[512];
    file_of(g_dir, KEY_A, SRS1, sizeof SRS1, old_a, sizeof old_a);
    struct stat st;
    ASSERT_EQ(0, stat(old_a, &st));
    ASSERT_EQ(1, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

/* Catches: the key's own old file counted as held, or the filesystem size read from the wrong field. */
TEST held_counts_other_keys_files_only(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    firc_listcache_room_hook_for_test = room_yes;
    g_calls = 0;
    firc_err_t r1 = store(KEY_A, SRS1, sizeof SRS1);
    uint64_t held1 = g_seen_held;
    uint64_t size1 = g_seen_size;
    firc_err_t r2 = store(KEY_B, SRS2, sizeof SRS2);
    uint64_t held2 = g_seen_held;
    firc_err_t r3 = store(KEY_A, SRS2, sizeof SRS2);
    uint64_t held3 = g_seen_held;
    uint64_t size3 = g_seen_size;
    firc_listcache_room_hook_for_test = NULL;
    ASSERT_EQ(FIRC_OK, r1);
    ASSERT_EQ(FIRC_OK, r2);
    ASSERT_EQ(FIRC_OK, r3);
    ASSERT_EQ(3, g_calls);
    ASSERT_EQ(0, held1);
    ASSERT_EQ(sizeof SRS1, size1);
    ASSERT_EQ(sizeof SRS1, held2);
    ASSERT_EQ(sizeof SRS2, held3);
    ASSERT_EQ(sizeof SRS2, size3);
    struct statvfs vfs;
    ASSERT_EQ(0, statvfs(g_dir, &vfs));
    ASSERT_EQ((uint64_t)vfs.f_blocks * vfs.f_frsize, g_seen_total);
    remove_dir(g_dir);
    PASS();
}

/* Catches: a missing cache directory left uncreated or created open to others. */
TEST write_creates_the_directory_private(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    char sub[128];
    snprintf(sub, sizeof sub, "%s/lists", g_dir);
    uint8_t h[32];
    firc_sha256(SRS1, sizeof SRS1, h);
    ASSERT_EQ(FIRC_OK, firc_listcache_write(sub, KEY_A, SRS1, sizeof SRS1, h));
    struct stat st;
    ASSERT_EQ(0, stat(sub, &st));
    ASSERT_EQ(0700, (int)(st.st_mode & 0777));
    ASSERT_EQ(1, entries(sub));
    remove_dir(sub);
    remove_dir(g_dir);
    PASS();
}

static int put_body(const char *path, const uint8_t *body, size_t len, time_t mtime)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    size_t n = fwrite(body, 1, len, f);
    fclose(f);
    if (n != len) {
        return -1;
    }
    struct timespec ts[2];
    ts[0].tv_sec = mtime;
    ts[0].tv_nsec = 0;
    ts[1] = ts[0];
    return utimensat(AT_FDCWD, path, ts, 0);
}

static int read_newest_case(const uint8_t *old_body, size_t old_len, const uint8_t *new_body,
                            size_t new_len)
{
    char old_p[512];
    char new_p[512];
    file_of(g_dir, KEY_A, old_body, old_len, old_p, sizeof old_p);
    file_of(g_dir, KEY_A, new_body, new_len, new_p, sizeof new_p);
    if (put_body(old_p, old_body, old_len, 1000000000) != 0 ||
        put_body(new_p, new_body, new_len, 2000000000) != 0) {
        return -1;
    }
    uint8_t *body = NULL;
    size_t len = 0;
    uint8_t h[32];
    time_t mtime = 0;
    firc_err_t rc = firc_listcache_read(g_dir, KEY_A, &body, &len, h, &mtime);
    int ok = rc == FIRC_OK && len == new_len && memcmp(body, new_body, len) == 0 &&
             mtime == 2000000000 && !exists(g_dir, strrchr(old_p, '/') + 1) &&
             exists(g_dir, strrchr(new_p, '/') + 1) && entries(g_dir) == 1;
    free(body);
    unlink(new_p);
    unlink(old_p);
    return ok ? 0 : 1;
}

/* Catches: a read after a crash that serves whichever of two files readdir lists first, or keeps the older one. */
TEST read_takes_the_newest_file_and_removes_the_rest(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(0, read_newest_case(SRS1, sizeof SRS1, SRS2, sizeof SRS2));
    ASSERT_EQ(0, read_newest_case(SRS2, sizeof SRS2, SRS1, sizeof SRS1));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a write of a body already on disk that leaves a second file of the same key behind. */
TEST a_write_of_a_present_body_removes_the_keys_other_file(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    char p1[512];
    char p2[512];
    file_of(g_dir, KEY_A, SRS1, sizeof SRS1, p1, sizeof p1);
    file_of(g_dir, KEY_A, SRS2, sizeof SRS2, p2, sizeof p2);
    ASSERT_EQ(0, put_body(p1, SRS1, sizeof SRS1, 1000000000));
    ASSERT_EQ(0, put_body(p2, SRS2, sizeof SRS2, 2000000000));
    ASSERT_EQ(FIRC_OK, store(KEY_B, SRS1, sizeof SRS1));
    ASSERT_EQ(FIRC_OK, store(KEY_A, SRS2, sizeof SRS2));
    struct stat st;
    ASSERT(stat(p1, &st) != 0);
    ASSERT_EQ(0, stat(p2, &st));
    ASSERT_EQ(2, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a truncated gzip accepted as a shorter body, or left on disk. */
TEST a_truncated_gzip_is_removed(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1));
    char p[512];
    file_of(g_dir, KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1, p, sizeof p);
    struct stat st;
    ASSERT_EQ(0, stat(p, &st));
    ASSERT_EQ(0, truncate(p, st.st_size - 6));
    uint8_t *body = NULL;
    size_t len = 0;
    uint8_t h[32];
    time_t mtime = 0;
    ASSERT_EQ(FIRC_ERR_NOENT, firc_listcache_read(g_dir, KEY_A, &body, &len, h, &mtime));
    ASSERT(body == NULL);
    ASSERT(stat(p, &st) != 0);
    ASSERT_EQ(0, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a raw file trusted without checking its hash against the name. */
TEST a_truncated_srs_is_removed(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, SRS1, sizeof SRS1));
    char p[512];
    file_of(g_dir, KEY_A, SRS1, sizeof SRS1, p, sizeof p);
    ASSERT_EQ(0, truncate(p, sizeof SRS1 - 2));
    uint8_t *body = NULL;
    size_t len = 0;
    uint8_t h[32];
    time_t mtime = 0;
    ASSERT_EQ(FIRC_ERR_NOENT, firc_listcache_read(g_dir, KEY_A, &body, &len, h, &mtime));
    ASSERT(body == NULL);
    struct stat st;
    ASSERT(stat(p, &st) != 0);
    remove_dir(g_dir);
    PASS();
}

/* Catches: a read that finds another key's file, or fails on a missing directory with another code. */
TEST a_missing_key_is_noent(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_B, SRS1, sizeof SRS1));
    uint8_t *body = NULL;
    size_t len = 0;
    uint8_t h[32];
    time_t mtime = 0;
    ASSERT_EQ(FIRC_ERR_NOENT, firc_listcache_read(g_dir, KEY_A, &body, &len, h, &mtime));
    ASSERT(body == NULL);
    ASSERT_EQ(1, entries(g_dir));
    char sub[128];
    snprintf(sub, sizeof sub, "%s/none", g_dir);
    ASSERT_EQ(FIRC_ERR_NOENT, firc_listcache_read(sub, KEY_A, &body, &len, h, &mtime));
    remove_dir(g_dir);
    PASS();
}

static const char NAME_A[] = "0123456789abcdef-1111111111111111";
static const char NAME_B[] = "fedcba9876543210-2222222222222222";
static const char NAME_TMP[] = "fedcba9876543210-2222222222222222.tmp.Ab3dEf";
static const char NAME_TMP_A[] = "0123456789abcdef-1111111111111111.tmp.zzzzzz";
static const char NAME_FOREIGN[] = "notes.txt";
static const char NAME_NEAR[] = "0123456789abcdef-1111";
static const char NAME_UPPER[] = "0123456789ABCDEF-1111111111111111";

static int fill_sweep_dir(void)
{
    const char *names[] = {NAME_A, NAME_B, NAME_TMP, NAME_TMP_A, NAME_FOREIGN, NAME_NEAR, NAME_UPPER};
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (put(g_dir, names[i], "x") != 0) {
            return -1;
        }
    }
    return 0;
}

/* Catches: a listed key removed, an unlisted one kept, a temp file removed, or a foreign name removed. */
TEST sweep_keeps_listed_keys_and_foreign_names(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(0, fill_sweep_dir());
    const char *keys[] = {"aaaaaaaaaaaaaaaa", KEY_A};
    ASSERT_EQ(FIRC_OK, firc_listcache_sweep(g_dir, keys, 2));
    ASSERT(exists(g_dir, NAME_A));
    ASSERT_FALSE(exists(g_dir, NAME_B));
    ASSERT(exists(g_dir, NAME_TMP));
    ASSERT(exists(g_dir, NAME_TMP_A));
    ASSERT(exists(g_dir, NAME_FOREIGN));
    ASSERT(exists(g_dir, NAME_NEAR));
    ASSERT(exists(g_dir, NAME_UPPER));
    ASSERT_EQ(6, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a sweep without keys that removes cache files instead of temp files only. */
TEST sweep_without_keys_removes_temp_files_only(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(0, fill_sweep_dir());
    ASSERT_EQ(FIRC_OK, firc_listcache_sweep(g_dir, NULL, 0));
    ASSERT(exists(g_dir, NAME_A));
    ASSERT(exists(g_dir, NAME_B));
    ASSERT_FALSE(exists(g_dir, NAME_TMP));
    ASSERT_FALSE(exists(g_dir, NAME_TMP_A));
    ASSERT_EQ(5, entries(g_dir));
    char sub[128];
    snprintf(sub, sizeof sub, "%s/none", g_dir);
    ASSERT_EQ(FIRC_OK, firc_listcache_sweep(sub, NULL, 0));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a sweep after a save that removes the temp file a worker is writing. */
TEST a_keyed_sweep_leaves_a_write_in_flight(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(0, put(g_dir, NAME_TMP, "x"));
    static const char *const none[1] = {NULL};
    ASSERT_EQ(FIRC_OK, firc_listcache_sweep(g_dir, none, 0));
    ASSERT(exists(g_dir, NAME_TMP));
    ASSERT_EQ(FIRC_OK, firc_listcache_sweep(g_dir, NULL, 0));
    ASSERT_FALSE(exists(g_dir, NAME_TMP));
    remove_dir(g_dir);
    PASS();
}

static firc_err_t read_key(const char *key, uint8_t **body, size_t *len)
{
    uint8_t h[32];
    time_t mtime = 0;
    return firc_listcache_read(g_dir, key, body, len, h, &mtime);
}

/* Catches: a file of a good body removed because its buffer could not be allocated. */
TEST a_failed_file_allocation_keeps_the_file(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, SRS1, sizeof SRS1));
    uint8_t *body = NULL;
    size_t len = 0;
    g_mallocs_left = 0;
    firc_err_t rc = read_key(KEY_A, &body, &len);
    g_mallocs_left = -1;
    ASSERT_EQ(FIRC_ERR_NOMEM, rc);
    ASSERT(body == NULL);
    char p[512];
    file_of(g_dir, KEY_A, SRS1, sizeof SRS1, p, sizeof p);
    struct stat st;
    ASSERT_EQ(0, stat(p, &st));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a gzip file removed because its inflate buffer could not be allocated. */
TEST a_failed_inflate_allocation_keeps_the_file(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1));
    uint8_t *body = NULL;
    size_t len = 0;
    g_mallocs_left = 1;
    firc_err_t rc = read_key(KEY_A, &body, &len);
    g_mallocs_left = -1;
    ASSERT_EQ(FIRC_ERR_NOMEM, rc);
    ASSERT(body == NULL);
    char p[512];
    file_of(g_dir, KEY_A, (const uint8_t *)TEXT, sizeof TEXT - 1, p, sizeof p);
    struct stat st;
    ASSERT_EQ(0, stat(p, &st));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a gzip file removed because its inflate buffer could not grow. */
TEST a_failed_inflate_growth_keeps_the_file(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    size_t n = (size_t)MIB;
    uint8_t *zeros = calloc(1, n);
    ASSERT(zeros != NULL);
    ASSERT_EQ(FIRC_OK, store(KEY_A, zeros, n));
    char p[512];
    file_of(g_dir, KEY_A, zeros, n, p, sizeof p);
    free(zeros);
    uint8_t *body = NULL;
    size_t len = 0;
    g_realloc_fails = true;
    firc_err_t rc = read_key(KEY_A, &body, &len);
    g_realloc_fails = false;
    ASSERT_EQ(FIRC_ERR_NOMEM, rc);
    ASSERT(body == NULL);
    struct stat st;
    ASSERT_EQ(0, stat(p, &st));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a file removed because reading it failed with an I/O error. */
TEST a_read_error_keeps_the_file(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    ASSERT_EQ(FIRC_OK, store(KEY_A, SRS1, sizeof SRS1));
    uint8_t *body = NULL;
    size_t len = 0;
    g_read_eio = true;
    firc_err_t rc = read_key(KEY_A, &body, &len);
    g_read_eio = false;
    ASSERT_EQ(FIRC_ERR_IO, rc);
    ASSERT(body == NULL);
    char p[512];
    file_of(g_dir, KEY_A, SRS1, sizeof SRS1, p, sizeof p);
    struct stat st;
    ASSERT_EQ(0, stat(p, &st));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a damaged newest file taking the valid older copy with it, or itself left behind. */
TEST a_damaged_newest_file_falls_back_to_the_older_one(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    char old_p[512];
    char new_p[512];
    file_of(g_dir, KEY_A, SRS1, sizeof SRS1, old_p, sizeof old_p);
    file_of(g_dir, KEY_A, SRS2, sizeof SRS2, new_p, sizeof new_p);
    ASSERT_EQ(0, put_body(old_p, SRS1, sizeof SRS1, 1000000000));
    ASSERT_EQ(0, put_body(new_p, SRS2, sizeof SRS2 - 1, 2000000000));
    uint8_t *body = NULL;
    size_t len = 0;
    uint8_t h[32];
    time_t mtime = 0;
    ASSERT_EQ(FIRC_OK, firc_listcache_read(g_dir, KEY_A, &body, &len, h, &mtime));
    ASSERT_EQ(sizeof SRS1, len);
    ASSERT_MEM_EQ(SRS1, body, len);
    ASSERT_EQ((time_t)1000000000, mtime);
    free(body);
    struct stat st;
    ASSERT(stat(new_p, &st) != 0);
    ASSERT_EQ(0, stat(old_p, &st));
    ASSERT_EQ(1, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

static int gzip_file(const char *path, const uint8_t *body, size_t len)
{
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (deflateInit2(&zs, 9, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    uLong cap = deflateBound(&zs, (uLong)len);
    uint8_t *out = malloc(cap);
    if (out == NULL) {
        deflateEnd(&zs);
        return -1;
    }
    zs.next_in = (Bytef *)body;
    zs.avail_in = (uInt)len;
    zs.next_out = out;
    zs.avail_out = (uInt)cap;
    int rc = deflate(&zs, Z_FINISH);
    size_t got = (size_t)zs.total_out;
    deflateEnd(&zs);
    int res = rc == Z_STREAM_END ? put_body(path, out, got, 1000000000) : -1;
    free(out);
    return res;
}

/* Catches: an inflated body over the fetch cap accepted from the cache, or left on disk. */
TEST a_gzip_body_over_the_cap_is_removed(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    size_t n = MAX_BODY + 1;
    uint8_t *zeros = calloc(1, n);
    ASSERT(zeros != NULL);
    char p[512];
    file_of(g_dir, KEY_A, zeros, n, p, sizeof p);
    int put_rc = gzip_file(p, zeros, n);
    free(zeros);
    ASSERT_EQ(0, put_rc);
    uint8_t *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_NOENT, read_key(KEY_A, &body, &len));
    ASSERT(body == NULL);
    ASSERT_EQ(0, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a raw body over the fetch cap accepted from the cache, or left on disk. */
TEST a_raw_body_over_the_cap_is_removed(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    size_t n = MAX_BODY + 1;
    uint8_t *raw = calloc(1, n);
    ASSERT(raw != NULL);
    memcpy(raw, "SRS", 3);
    char p[512];
    file_of(g_dir, KEY_A, raw, n, p, sizeof p);
    int put_rc = put_body(p, raw, n, 1000000000);
    free(raw);
    ASSERT_EQ(0, put_rc);
    uint8_t *body = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_ERR_NOENT, read_key(KEY_A, &body, &len));
    ASSERT(body == NULL);
    ASSERT_EQ(0, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

/* Catches: a body over the fetch cap written to the cache. */
TEST a_write_over_the_cap_is_refused(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    size_t n = MAX_BODY + 1;
    uint8_t *zeros = calloc(1, n);
    ASSERT(zeros != NULL);
    firc_err_t rc = store(KEY_A, zeros, n);
    free(zeros);
    ASSERT_EQ(FIRC_ERR_INVAL, rc);
    ASSERT_EQ(0, entries(g_dir));
    remove_dir(g_dir);
    PASS();
}

static uint64_t g_seen_free;

static bool room_free_seen(uint64_t total, uint64_t free_, uint64_t held, uint64_t size)
{
    g_seen_total = total;
    g_seen_free = free_;
    g_seen_held = held;
    g_seen_size = size;
    return true;
}

/* Catches: the key's own old file, about to be replaced, not counted as free space. */
TEST the_keys_old_file_counts_as_free_space(void)
{
    make_dir();
    ASSERT(g_dir[0] != 0);
    size_t n = 4 * (size_t)MIB;
    uint8_t *old_body = calloc(1, n);
    ASSERT(old_body != NULL);
    memcpy(old_body, "SRS", 3);
    char old_p[512];
    file_of(g_dir, KEY_A, old_body, n, old_p, sizeof old_p);
    int put_rc = put_body(old_p, old_body, n, 1000000000);
    free(old_body);
    ASSERT_EQ(0, put_rc);
    ASSERT_EQ(0, put(g_dir, "fedcba9876543210-3333333333333333", "12345"));
    g_fake_fs = true;
    firc_listcache_room_hook_for_test = room_free_seen;
    firc_err_t rc = store(KEY_A, SRS2, sizeof SRS2);
    firc_listcache_room_hook_for_test = NULL;
    g_fake_fs = false;
    ASSERT_EQ(FIRC_OK, rc);
    ASSERT_EQ((uint64_t)GIB, g_seen_total);
    ASSERT_EQ((uint64_t)512 * MIB + 4 * MIB, g_seen_free);
    ASSERT_EQ((uint64_t)5, g_seen_held);
    ASSERT_EQ((uint64_t)sizeof SRS2, g_seen_size);
    remove_dir(g_dir);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(key_is_the_first_16_hex_of_the_url_sha256);
    RUN_TEST(room_the_8mib_reserve_decides_on_a_small_partition);
    RUN_TEST(room_the_tenth_reserve_decides_on_a_large_filesystem);
    RUN_TEST(room_the_half_rule_decides_when_the_cache_holds_much);
    RUN_TEST(text_round_trip_is_stored_gzipped);
    RUN_TEST(srs_round_trip_is_stored_raw);
    RUN_TEST(the_same_body_twice_keeps_the_same_inode);
    RUN_TEST(a_new_body_replaces_only_its_own_keys_file);
    RUN_TEST(a_refusal_keeps_the_old_file_and_writes_nothing);
    RUN_TEST(held_counts_other_keys_files_only);
    RUN_TEST(write_creates_the_directory_private);
    RUN_TEST(read_takes_the_newest_file_and_removes_the_rest);
    RUN_TEST(a_write_of_a_present_body_removes_the_keys_other_file);
    RUN_TEST(a_truncated_gzip_is_removed);
    RUN_TEST(a_truncated_srs_is_removed);
    RUN_TEST(a_missing_key_is_noent);
    RUN_TEST(sweep_keeps_listed_keys_and_foreign_names);
    RUN_TEST(sweep_without_keys_removes_temp_files_only);
    RUN_TEST(a_keyed_sweep_leaves_a_write_in_flight);
    RUN_TEST(a_failed_file_allocation_keeps_the_file);
    RUN_TEST(a_failed_inflate_allocation_keeps_the_file);
    RUN_TEST(a_failed_inflate_growth_keeps_the_file);
    RUN_TEST(a_read_error_keeps_the_file);
    RUN_TEST(a_damaged_newest_file_falls_back_to_the_older_one);
    RUN_TEST(a_gzip_body_over_the_cap_is_removed);
    RUN_TEST(a_raw_body_over_the_cap_is_removed);
    RUN_TEST(a_write_over_the_cap_is_refused);
    RUN_TEST(the_keys_old_file_counts_as_free_space);
    GREATEST_MAIN_END();
}
