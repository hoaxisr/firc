#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "firc/fakeip_ula.h"

static char g_dir[128];

static const char *pathfor(const char *name, char *buf, size_t n) {
    snprintf(buf, n, "%s/%s", g_dir, name);
    return buf;
}

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (f == NULL) { return; }
    fputs(text, f);
    fclose(f);
}

static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) { return NULL; }
    static char buf[256];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* Catches: a generated ULA prefix not read back from its file on the next start. */
TEST a_generated_prefix_survives_a_restart(void) {
    char p[192];
    pathfor("survives", p, sizeof(p));
    unlink(p);

    firc_ip_t first = {{0}, 0}, second = {{0}, 0};
    uint8_t len1 = 0, len2 = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &first, &len1));
    ASSERT_EQ_FMTm("the generated pool is a /48", 48, (int)len1, "%d");
    ASSERT_EQ_FMT(16, (int)first.len, "%d");
    ASSERT_EQ_FMTm("RFC 4193: a ULA begins fd", 0xfd, (int)first.b[0], "%02x");

    for (int i = 6; i < 16; i++) {
        ASSERT_EQ_FMTm("bits below the prefix must be clear", 0, (int)first.b[i], "%d");
    }

    ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &second, &len2));
    ASSERT_EQ_FMT(48, (int)len2, "%d");
    ASSERT_MEM_EQm("the second start must reuse the first start's prefix", &first, &second,
                   sizeof(first));

    unlink(p);
    PASS();
}

/* Catches: a constant or all-zero Global ID. */
TEST the_global_id_is_actually_random(void) {
    firc_ip_t seen[16];
    char p[192];
    bool any_different = false;

    for (int i = 0; i < 16; i++) {
        char name[32];
        snprintf(name, sizeof(name), "rand%d", i);
        pathfor(name, p, sizeof(p));
        unlink(p);
        uint8_t len = 0;
        ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &seen[i], &len));
        unlink(p);

        int nonzero = 0;
        for (int j = 1; j < 6; j++) { nonzero += (seen[i].b[j] != 0); }
        ASSERTm("an all-zero Global ID means the random bytes never arrived", nonzero > 0);

        if (i > 0 && memcmp(&seen[i], &seen[0], sizeof(seen[0])) != 0) { any_different = true; }
    }
    ASSERTm("sixteen identical prefixes is a constant, not a generated id", any_different);

    for (int j = 1; j < 6; j++) {
        bool moved = false;
        for (int i = 1; i < 16 && !moved; i++) { moved = (seen[i].b[j] != seen[0].b[j]); }
        ASSERT_EQ_FMTm("this byte of the Global ID never changed", true, moved, "%d");
    }
    PASS();
}

/* Catches: the prefix file written as anything but readable CIDR text. */
TEST the_prefix_is_written_as_readable_cidr_text(void) {
    char p[192];
    pathfor("text", p, sizeof(p));
    unlink(p);

    firc_ip_t base = {{0}, 0};
    uint8_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &base, &len));

    const char *body = read_file(p);
    ASSERT(body != NULL);
    ASSERT_EQm("the file must start with the ULA nibble", 'f', body[0]);
    ASSERTm("and name a /48", strstr(body, "/48") != NULL);

    char pinned[192];
    pathfor("text_copy", pinned, sizeof(pinned));
    write_file(pinned, body);
    firc_ip_t reread = {{0}, 0};
    uint8_t rlen = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(pinned, &reread, &rlen));
    ASSERT_MEM_EQ(&base, &reread, sizeof(base));
    ASSERT_EQ_FMT(48, (int)rlen, "%d");

    unlink(p);
    unlink(pinned);
    PASS();
}

/* Catches: a prefix file that is not a ULA /48 obeyed, or treated as fatal. */
TEST a_file_that_is_not_a_ula_48_is_replaced(void) {
    static const struct {
        const char *why;
        const char *body;
    } bad[] = {
        {"not an address at all", "garbage\n"},
        {"empty", ""},
        {"a global prefix, not a ULA", "2001:db8:1234::/48\n"},
        {"link-local, not a ULA", "fe80::/48\n"},
        {"a v4 prefix", "198.18.0.0/15\n"},
        {"the right family and nibble but the wrong width", "fd37:9a5c:be10::/64\n"},
        {"bits set below the prefix", "fd37:9a5c:be10:1::/48\n"},
        {"no prefix length", "fd37:9a5c:be10::\n"},
        {"reserved, not locally assigned", "fc37:9a5c:be10::/48\n"},
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char p[192];
        pathfor("bad", p, sizeof(p));
        unlink(p);
        write_file(p, bad[i].body);

        firc_ip_t base = {{0}, 0};
        uint8_t len = 0;
        if (firc_fakeip_ula_load(p, &base, &len) != FIRC_OK) { FAILm(bad[i].why); }
        if (len != 48 || base.b[0] != 0xfd) { FAILm(bad[i].why); }
        for (int j = 6; j < 16; j++) {
            if (base.b[j] != 0) { FAILm(bad[i].why); }
        }
        {
            const char *now = read_file(p);
            if (now == NULL || strcmp(now, bad[i].body) == 0) { FAILm(bad[i].why); }
        }

        firc_ip_t again = {{0}, 0};
        uint8_t alen = 0;
        ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &again, &alen));
        if (memcmp(&base, &again, sizeof(base)) != 0) { FAILm(bad[i].why); }
        unlink(p);
    }
    PASS();
}

/* Catches: a generated prefix in fc00::/8 instead of fd00::/8. */
TEST the_generated_prefix_is_locally_assigned(void) {
    char p[192];
    pathfor("lbit", p, sizeof(p));
    for (int i = 0; i < 8; i++) {
        unlink(p);
        firc_ip_t base = {{0}, 0};
        uint8_t len = 0;
        ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &base, &len));
        ASSERT_EQ_FMTm("fc00::/8 is reserved; only fd00::/8 is locally assigned", 0xfd,
                       (int)base.b[0], "%02x");
    }
    unlink(p);
    PASS();
}

/* Catches: a symlink at the temp file's name followed instead of refused. */
TEST a_symlink_at_the_temp_name_is_refused(void) {
    char p[192], tmp[224], victim[192];
    pathfor("symlink_state", p, sizeof(p));
    pathfor("symlink_victim", victim, sizeof(victim));
    snprintf(tmp, sizeof(tmp), "%s.tmp", p);
    unlink(p);
    unlink(tmp);
    write_file(victim, "do not touch\n");
    ASSERT_EQ(0, symlink(victim, tmp));

    firc_ip_t base = {{0}, 0};
    uint8_t len = 0;
    firc_err_t err = firc_fakeip_ula_load(p, &base, &len);

    const char *body = read_file(victim);
    ASSERT(body != NULL);
    ASSERT_STR_EQm("the file the link pointed at must be untouched", "do not touch\n", body);

    struct stat st;
    if (lstat(p, &st) == 0) {
        ASSERT_FALSEm("the state file must not have become a symlink", S_ISLNK(st.st_mode));
    }
    if (err == FIRC_OK) {
        ASSERT_EQ_FMT(48, (int)len, "%d");
        ASSERT_EQ_FMT(0xfd, (int)base.b[0], "%02x");
        firc_ip_t again = {{0}, 0};
        uint8_t alen = 0;
        ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &again, &alen));
        ASSERT_MEM_EQm("what it returned is what it persisted", &base, &again, sizeof(base));
    } else {
        ASSERT_EQ_FMT((int)FIRC_ERR_SYS, (int)err, "%d");
    }

    unlink(tmp);
    unlink(p);
    unlink(victim);
    PASS();
}

/* Catches: the losing instance of two concurrent starts keeping its own prefix. */
TEST concurrent_starts_agree_on_one_prefix(void) {
    char p[192];
    pathfor("concurrent", p, sizeof(p));

    for (int round = 0; round < 40; round++) {
        unlink(p);
        pid_t kids[4];
        int fds[4][2];
        for (int i = 0; i < 4; i++) {
            ASSERT_EQ(0, pipe(fds[i]));
            kids[i] = fork();
            if (kids[i] == 0) {
                close(fds[i][0]);
                firc_ip_t b = {{0}, 0};
                uint8_t l = 0;
                if (firc_fakeip_ula_load(p, &b, &l) != FIRC_OK) { _exit(1); }
                ssize_t w = write(fds[i][1], b.b, 16);
                _exit(w == 16 ? 0 : 1);
            }
            close(fds[i][1]);
        }
        uint8_t got[4][16];
        int ok = 0;
        for (int i = 0; i < 4; i++) {
            if (read(fds[i][0], got[i], 16) == 16) { ok++; }
            close(fds[i][0]);
            int st = 0;
            waitpid(kids[i], &st, 0);
        }
        ASSERT_EQ_FMT(4, ok, "%d");
        for (int i = 1; i < 4; i++) {
            if (memcmp(got[0], got[i], 16) != 0) {
                FAILm("two concurrent starts disagreed about the generated prefix");
            }
        }
        firc_ip_t onDisk = {{0}, 0};
        uint8_t l = 0;
        ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &onDisk, &l));
        ASSERT_MEM_EQ(got[0], onDisk.b, 16);
    }
    unlink(p);
    PASS();
}

/* Catches: a prefix file created with any group or other permission bits. */
TEST the_state_file_is_not_world_writable(void) {
    char p[192];
    pathfor("perms", p, sizeof(p));
    unlink(p);
    firc_ip_t b = {{0}, 0};
    uint8_t l = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_ula_load(p, &b, &l));

    struct stat st;
    ASSERT_EQ(0, stat(p, &st));
    ASSERT_EQ_FMTm("no group or other bits", 0, (int)(st.st_mode & (mode_t)0077), "%o");
    unlink(p);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    const char *base = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    snprintf(g_dir, sizeof(g_dir), "%s/firc-ula-%ld", base, (long)getpid());
    if (mkdir(g_dir, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "cannot create %s\n", g_dir);
        return 1;
    }
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_generated_prefix_survives_a_restart);
    RUN_TEST(the_global_id_is_actually_random);
    RUN_TEST(the_prefix_is_written_as_readable_cidr_text);
    RUN_TEST(a_file_that_is_not_a_ula_48_is_replaced);
    RUN_TEST(the_generated_prefix_is_locally_assigned);
    RUN_TEST(a_symlink_at_the_temp_name_is_refused);
    RUN_TEST(concurrent_starts_agree_on_one_prefix);
    RUN_TEST(the_state_file_is_not_world_writable);
    int rc = greatest_all_passed() ? 0 : 1;
    GREATEST_PRINT_REPORT();
    rmdir(g_dir);
    return rc;
}
