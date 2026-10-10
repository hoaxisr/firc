#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */
#include "greatest.h"

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "../../src/xtables/xt_internal.h"

static int bind_xtables(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path + 1, "xtables", 7);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 8)) != 0) {
        if (fd >= 0) { close(fd); }
        return -1;
    }
    return fd;
}

static bool in_own_netns;

static long ms_since(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (long)(t1.tv_sec - t0->tv_sec) * 1000L + (t1.tv_nsec - t0->tv_nsec) / 1000000L;
}

/* Catches: a lock on another name or address length than iptables 1.4.21's, so the two writers never meet. */
TEST the_lock_is_iptables_lock(void) {
    if (!in_own_netns) { SKIPm("no user namespace: @xtables would be the host's"); }
    int holder = bind_xtables();
    ASSERT(holder >= 0);
    int fd = -1;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ASSERT_EQ(EAGAIN, firc_xt_sock_lock(&fd, 200));
    long waited = ms_since(&t0);
    ASSERT_EQ(-1, fd);
    ASSERTm("waited the whole 200 ms", waited >= 200);
    ASSERTm("and not much longer", waited < 1000);
    close(holder);
    ASSERT_EQ(0, firc_xt_sock_lock(&fd, 200));
    ASSERT(fd >= 0);
    ASSERT_EQm("iptables cannot take it now", -1, bind_xtables());
    firc_xt_sock_unlock(&fd);
    ASSERT_EQ(-1, fd);
    int again = bind_xtables();
    ASSERTm("and can once firc lets go", again >= 0);
    close(again);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    in_own_netns = unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0;
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_lock_is_iptables_lock);
    GREATEST_MAIN_END();
}
