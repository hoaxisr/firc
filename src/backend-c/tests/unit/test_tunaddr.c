#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier): unshare() */
#include "greatest.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "firc/tunaddr.h"
#include "ifcfg.h"

static firc_tun_ifaddr_t entry(const char *name, const char *text)
{
    firc_tun_ifaddr_t e;
    memset(&e, 0, sizeof e);
    snprintf(e.name, sizeof e.name, "%s", name);
    e.family = strchr(text, ':') != NULL ? AF_INET6 : AF_INET;
    inet_pton(e.family, text, e.addr);
    return e;
}

TEST n3_is_dot_4(void)
{
    /* catches: 1+n lost, or the old 198.51.100 bytes c6 33 64 */
    static const uint8_t want[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xcb, 0x00, 0x71, 0x04};
    char v4[20];
    uint8_t v6[16];
    firc_tun_addr(3, v4, v6);
    ASSERT_STR_EQ("203.0.113.4/32", v4);
    ASSERT_MEM_EQ(want, v6, 16);
    PASS();
}

TEST n99_is_dot_100(void)
{
    /* catches: a last byte that is not 1+n past one digit */
    static const uint8_t want[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xcb, 0x00, 0x71, 0x64};
    char v4[20];
    uint8_t v6[16];
    firc_tun_addr(99, v4, v6);
    ASSERT_STR_EQ("203.0.113.100/32", v4);
    ASSERT_MEM_EQ(want, v6, 16);
    PASS();
}

TEST a_holder_elsewhere_is_named(void)
{
    /* catches: the holder lookup removed, or the v4 not compared */
    firc_tun_ifaddr_t v[] = {entry("br0", "192.168.1.1"), entry("ezcfg0", "203.0.113.4")};
    firc_tun_addr_set_ifaddrs_for_test(v, 2);
    char out[16] = "x";
    int held = firc_tun_addr_holder(3, "tunvless3", out);
    firc_tun_addr_set_ifaddrs_for_test(NULL, 0);
    ASSERT_EQ(AF_INET, held);
    ASSERT_STR_EQ("ezcfg0", out);
    PASS();
}

TEST the_v6_is_checked_too(void)
{
    /* catches: an address held only in IPv6 let through */
    firc_tun_ifaddr_t v[] = {entry("br0", "2001:db8::cb00:7104")};
    firc_tun_addr_set_ifaddrs_for_test(v, 1);
    char out[16] = "x";
    int held = firc_tun_addr_holder(3, "tunvless3", out);
    firc_tun_addr_set_ifaddrs_for_test(NULL, 0);
    ASSERT_EQ(AF_INET6, held);
    ASSERT_STR_EQ("br0", out);
    PASS();
}

TEST the_own_device_is_no_holder(void)
{
    /* catches: a tunnel refused for the address its own device already holds */
    firc_tun_ifaddr_t v[] = {entry("tunvless3", "203.0.113.4"), entry("tunvless3", "2001:db8::cb00:7104")};
    firc_tun_addr_set_ifaddrs_for_test(v, 2);
    char out[16] = "x";
    int held = firc_tun_addr_holder(3, "tunvless3", out);
    firc_tun_addr_set_ifaddrs_for_test(NULL, 0);
    ASSERT_EQ(0, held);
    PASS();
}

TEST another_tunnels_address_is_no_holder(void)
{
    /* catches: a holder found by prefix or by any address in the range instead of the exact one */
    firc_tun_ifaddr_t v[] = {entry("tunvless4", "203.0.113.5"), entry("br0", "2001:db8::cb00:7105"),
                             entry("ezcfg0", "198.51.100.4")};
    firc_tun_addr_set_ifaddrs_for_test(v, 3);
    char out[16] = "x";
    int held = firc_tun_addr_holder(3, "tunvless3", out);
    firc_tun_addr_set_ifaddrs_for_test(NULL, 0);
    ASSERT_EQ(0, held);
    PASS();
}

TEST an_unreadable_address_list_is_told_apart(void)
{
    /* catches: a failed read of the interface addresses reported as no holder */
    firc_tun_addr_fail_ifaddrs_for_test(true);
    char out[16] = "x";
    int held = firc_tun_addr_holder(3, "tunvless3", out);
    firc_tun_addr_set_ifaddrs_for_test(NULL, 0);
    ASSERT_EQ(-1, held);
    PASS();
}

TEST the_system_read_is_used_again_after_a_failure(void)
{
    /* catches: the failure seam left on after the seam is reset */
    firc_tun_addr_fail_ifaddrs_for_test(true);
    firc_tun_addr_set_ifaddrs_for_test(NULL, 0);
    char out[16] = "x";
    ASSERT(firc_tun_addr_holder(3, "tunvless3", out) >= 0);
    PASS();
}

static bool put(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return false;
    }
    bool ok = write(fd, text, strlen(text)) == (ssize_t)strlen(text);
    close(fd);
    return ok;
}

static int real_read_steps(void)
{
    char map[64];
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        return 10;
    }
    snprintf(map, sizeof map, "0 %u 1", (unsigned)uid);
    if (!put("/proc/self/uid_map", map) || !put("/proc/self/setgroups", "deny")) {
        return 11;
    }
    snprintf(map, sizeof map, "0 %u 1", (unsigned)gid);
    if (!put("/proc/self/gid_map", map)) {
        return 11;
    }
    char out[16];
    if (system("ip link set lo up && ip addr add 203.0.113.4/32 dev lo") != 0) {
        return 12;
    }
    memset(out, 0, sizeof out);
    if (firc_tun_addr_holder(3, "tunvless3", out) != AF_INET || strcmp(out, "lo") != 0) {
        return 13;
    }
    if (firc_tun_addr_holder(3, "lo", out) != 0) {
        return 14;
    }
    if (system("ip addr del 203.0.113.4/32 dev lo && ip -6 addr add 2001:db8::cb00:7104/128 dev lo nodad") != 0) {
        return 15;
    }
    memset(out, 0, sizeof out);
    if (firc_tun_addr_holder(3, "tunvless3", out) != AF_INET6 || strcmp(out, "lo") != 0) {
        return 16;
    }
    if (system("ip -6 addr del 2001:db8::cb00:7104/128 dev lo") != 0) {
        return 17;
    }
    if (firc_tun_addr_holder(3, "tunvless3", out) != 0) {
        return 18;
    }
    return 0;
}

TEST the_system_read_finds_each_family_on_lo(void)
{
    /* catches: the getifaddrs loop skipping v6, reading the wrong sockaddr, or naming no interface */
    firc_tun_addr_set_ifaddrs_for_test(NULL, 0);
    fflush(NULL);
    pid_t pid = fork();
    ASSERT(pid >= 0);
    if (pid == 0) {
        _exit(real_read_steps());
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT(WIFEXITED(status));
    ASSERT_EQ_FMT(0, WEXITSTATUS(status), "%d");
    PASS();
}

TEST fircd_and_tunvless_derive_the_same_v6(void)
{
    /* catches: fircd checking a v6 address tunvless never adds */
    static const uint8_t want[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xcb, 0x00, 0x71, 0x04};
    char v4[20];
    uint8_t ours[16];
    firc_tun_addr(3, v4, ours);
    struct in_addr a;
    ASSERT_EQ(1, inet_pton(AF_INET, "203.0.113.4", &a));
    unsigned char theirs[16];
    ifcfg_addr6_of(a.s_addr, theirs);
    ASSERT_MEM_EQ(want, ours, 16);
    ASSERT_MEM_EQ(want, theirs, 16);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(n3_is_dot_4);
    RUN_TEST(n99_is_dot_100);
    RUN_TEST(a_holder_elsewhere_is_named);
    RUN_TEST(the_v6_is_checked_too);
    RUN_TEST(the_own_device_is_no_holder);
    RUN_TEST(another_tunnels_address_is_no_holder);
    RUN_TEST(an_unreadable_address_list_is_told_apart);
    RUN_TEST(the_system_read_is_used_again_after_a_failure);
    RUN_TEST(the_system_read_finds_each_family_on_lo);
    RUN_TEST(fircd_and_tunvless_derive_the_same_v6);
    GREATEST_MAIN_END();
}
