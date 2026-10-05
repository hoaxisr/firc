#include "greatest.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "firc/instance_lock.h"

static void temp_path(char *buf, size_t n) {
    char dir[] = "/tmp/firc-lock-XXXXXX";
    if (mkdtemp(dir) == NULL) { abort(); }
    snprintf(buf, n, "%s/fircd.lock", dir);
}

static void drop(const char *path) {
    char dir[256];
    snprintf(dir, sizeof(dir), "%s", path);
    *strrchr(dir, '/') = '\0';
    unlink(path);
    rmdir(dir);
}

TEST a_second_holder_is_refused_until_the_first_lets_go(void) {
    char path[256];
    temp_path(path, sizeof(path));
    int first = -1, second = -1;
    ASSERT_EQ(FIRC_OK, firc_instance_lock(path, &first));
    ASSERT(first >= 0);
    ASSERT_EQ(FIRC_ERR_EXIST, firc_instance_lock(path, &second));
    ASSERT_EQ(-1, second);
    firc_instance_unlock(first);
    ASSERT_EQ(FIRC_OK, firc_instance_lock(path, &second));
    firc_instance_unlock(second);
    drop(path);
    PASS();
}

/* Catches: a second process taking the lock while this one holds it. */
TEST another_process_is_refused_while_this_one_holds_it(void) {
    char path[256];
    temp_path(path, sizeof(path));
    int held = -1;
    ASSERT_EQ(FIRC_OK, firc_instance_lock(path, &held));
    pid_t pid = fork();
    ASSERT(pid >= 0);
    if (pid == 0) {
        int fd = -1;
        _exit(firc_instance_lock(path, &fd) == FIRC_ERR_EXIST ? 3 : 4);
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT_EQ_FMTm("the child was refused", 3, WEXITSTATUS(status), "%d");
    firc_instance_unlock(held);
    pid = fork();
    ASSERT(pid >= 0);
    if (pid == 0) {
        int fd = -1;
        _exit(firc_instance_lock(path, &fd) == FIRC_OK ? 5 : 6);
    }
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_EQ_FMTm("released: the child takes it", 5, WEXITSTATUS(status), "%d");
    drop(path);
    PASS();
}

/* Catches: an unwritable lock file failing instead of being locked read-only. */
TEST a_lock_file_that_cannot_be_opened_for_writing_is_taken_read_only(void) {
    if (geteuid() == 0) { SKIPm("permissions do not bind root"); }
    char path[256];
    temp_path(path, sizeof(path));
    int held = -1;
    ASSERT_EQ(FIRC_OK, firc_instance_lock(path, &held));
    firc_instance_unlock(held);
    char dir[256];
    snprintf(dir, sizeof(dir), "%s", path);
    *strrchr(dir, '/') = '\0';
    ASSERT_EQ(0, chmod(path, 0444));
    ASSERT_EQ(0, chmod(dir, 0555));
    int first = -1, second = -1;
    ASSERT_EQ(FIRC_OK, firc_instance_lock(path, &first));
    ASSERT(first >= 0);
    ASSERT_EQ_FMTm("taken read-only", O_RDONLY, fcntl(first, F_GETFL) & O_ACCMODE, "%d");
    ASSERT_EQ_FMTm("still exclusive", FIRC_ERR_EXIST, firc_instance_lock(path, &second), "%d");
    firc_instance_unlock(first);
    chmod(dir, 0700);
    chmod(path, 0600);
    drop(path);
    PASS();
}

TEST a_directory_that_cannot_be_written_is_an_error_not_a_lock(void) {
    int fd = -1;
    ASSERT_EQ(FIRC_ERR_NOENT, firc_instance_lock("/nonexistent-dir-for-firc/fircd.lock", &fd));
    ASSERT_EQ(-1, fd);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_second_holder_is_refused_until_the_first_lets_go);
    RUN_TEST(another_process_is_refused_while_this_one_holds_it);
    RUN_TEST(a_lock_file_that_cannot_be_opened_for_writing_is_taken_read_only);
    RUN_TEST(a_directory_that_cannot_be_written_is_an_error_not_a_lock);
    GREATEST_MAIN_END();
}
