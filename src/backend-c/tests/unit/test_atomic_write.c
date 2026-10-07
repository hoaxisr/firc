#include "greatest.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "firc/atomic_write.h"

TEST mkstemp_cloexec_fd_is_cloexec_from_the_start(void) {
    /* catches: a temp file fd created without O_CLOEXEC, or an unfilled template */
    char tmpl[] = "/tmp/firc_aw_XXXXXX";
    int fd = firc_mkstemp_cloexec(tmpl);
    ASSERT(fd >= 0);
    ASSERT(strstr(tmpl, "XXXXXX") == NULL);
    ASSERT((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    struct stat st;
    ASSERT_EQ(0, fstat(fd, &st));
    ASSERT_EQ(0600, (int)(st.st_mode & 0777));
    close(fd);
    unlink(tmpl);
    PASS();
}

TEST atomic_write_replaces_the_content(void) {
    /* catches: a write that leaves the old content or a partial file */
    char dir[] = "/tmp/firc_aw_dir_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char path[64];
    snprintf(path, sizeof path, "%s/f", dir);
    ASSERT_EQ(FIRC_OK, firc_atomic_write(path, "old\n", 4));
    ASSERT_EQ(FIRC_OK, firc_atomic_write(path, "new!\n", 5));
    char buf[16] = {0};
    FILE *f = fopen(path, "r");
    ASSERT(f != NULL);
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    ASSERT_EQ(5, (int)n);
    ASSERT_STR_EQ("new!\n", buf);
    unlink(path);
    rmdir(dir);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(mkstemp_cloexec_fd_is_cloexec_from_the_start);
    RUN_TEST(atomic_write_replaces_the_content);
    GREATEST_MAIN_END();
}
