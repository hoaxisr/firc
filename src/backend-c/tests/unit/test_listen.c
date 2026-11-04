#include "greatest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "firc/listen.h"
#include "firc/log.h"

static bool g_no_ipv6;

int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol) {
    if (g_no_ipv6 && domain == AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

static void reset(void *ud) {
    (void)ud;
    g_no_ipv6 = false;
    firc_log_set_fd(STDERR_FILENO);
}

static FILE *capture_log(void) {
    FILE *f = tmpfile();
    if (f != NULL) { firc_log_set_fd(fileno(f)); }
    return f;
}

static void read_log(FILE *f, char *text, size_t cap) {
    firc_log_set_fd(STDERR_FILENO);
    rewind(f);
    size_t got = fread(text, 1, cap - 1, f);
    text[got] = '\0';
    fclose(f);
}

static uint16_t free_port(int type) {
    int fd = __real_socket(AF_INET, type, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET};
    socklen_t len = sizeof(sa);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, len) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        if (fd >= 0) { close(fd); }
        return 0;
    }
    close(fd);
    return ntohs(sa.sin_port);
}

static sa_family_t family_of(int fd, uint16_t *port) {
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) { return AF_UNSPEC; }
    *port = ntohs(((struct sockaddr_in *)&sa)->sin_port);
    return sa.ss_family;
}

/* Catches: no fallback to 0.0.0.0 when the kernel has no IPv6, the port changed on the way, or the WARN missing or unnamed. */
TEST the_any_address_falls_back_to_ipv4_without_ipv6(void) {
    uint16_t port = free_port(SOCK_DGRAM);
    ASSERT(port != 0);
    struct sockaddr_storage sa;
    socklen_t len = 0;
    ASSERT(firc_listen_addr("[::]", port, true, &sa, &len));
    g_no_ipv6 = true;
    FILE *log = capture_log();
    ASSERT(log != NULL);
    int fd = firc_listen_open("DNS proxy", SOCK_DGRAM, &sa, len, FIRC_DNS_UDP_LISTEN, NULL, 0);
    char text[1024];
    read_log(log, text, sizeof(text));
    ASSERT(fd >= 0);
    uint16_t bound = 0;
    ASSERT_EQ(AF_INET, family_of(fd, &bound));
    ASSERT_EQ(port, bound);
    char name[64];
    firc_listen_name(fd, SOCK_DGRAM, name, sizeof(name));
    char want_name[64];
    snprintf(want_name, sizeof(want_name), "0.0.0.0:%u/udp", port);
    ASSERT_STR_EQ(want_name, name);
    close(fd);
    char want[200];
    snprintf(want, sizeof(want),
             "DNS proxy: IPv6 is not available on this router; listening on 0.0.0.0:%u/udp instead of [::]:%u",
             port, port);
    ASSERTm(text, strstr(text, want) != NULL);
    PASS();
}

/* Catches: an explicit IPv6 address quietly moved to IPv4, which would listen somewhere nobody asked for. */
TEST an_explicit_ipv6_address_does_not_fall_back(void) {
    struct sockaddr_storage sa;
    socklen_t len = 0;
    ASSERT(firc_listen_addr("fd00::1", 3553, true, &sa, &len));
    g_no_ipv6 = true;
    ASSERT_EQ(-EAFNOSUPPORT, firc_listen_open("DNS proxy", SOCK_DGRAM, &sa, len, FIRC_DNS_UDP_LISTEN, NULL, 0));
    PASS();
}

/* Catches: a [::] port held by another program taken over on IPv4 instead of failing with the reason. */
TEST an_any_address_port_in_use_does_not_fall_back(void) {
    uint16_t port = free_port(SOCK_STREAM);
    ASSERT(port != 0);
    int held = __real_socket(AF_INET6, SOCK_STREAM, 0);
    ASSERT(held >= 0);
    struct sockaddr_in6 h6 = {.sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_ANY_INIT};
    if (bind(held, (struct sockaddr *)&h6, sizeof(h6)) != 0 || listen(held, 1) != 0) {
        close(held);
        SKIPm("no IPv6 in this namespace");
    }
    struct sockaddr_storage sa;
    socklen_t len = 0;
    ASSERT(firc_listen_addr("[::]", port, true, &sa, &len));
    FILE *log = capture_log();
    ASSERT(log != NULL);
    int fd = firc_listen_open("WebUI", SOCK_STREAM, &sa, len, FIRC_WEB_LISTEN, NULL, 0);
    char text[1024];
    read_log(log, text, sizeof(text));
    close(held);
    ASSERT_EQ(-EADDRINUSE, fd);
    ASSERT_EQ(NULL, strstr(text, "instead of"));
    PASS();
}

/* Catches: the address, port, protocol or reason missing, or the in-use case without its hint. */
TEST a_port_in_use_is_named_with_a_hint(void) {
    char out[200];
    firc_listen_describe(out, sizeof(out), "127.0.0.1", 3553, SOCK_DGRAM, EADDRINUSE, NULL);
    ASSERT_STR_EQ("127.0.0.1:3553/udp: address already in use (is another program using this port?)", out);
    firc_listen_describe(out, sizeof(out), "[::]", 666, SOCK_STREAM, EADDRINUSE, NULL);
    ASSERT_STR_EQ("[::]:666/tcp: address already in use (is another program using this port?)", out);
    PASS();
}

/* Catches: a bare IPv6 address printed without brackets, so its port reads as part of it. */
TEST a_bare_ipv6_address_gets_brackets(void) {
    char out[200];
    firc_listen_describe(out, sizeof(out), "fd00::1", 53, SOCK_STREAM, EADDRNOTAVAIL, NULL);
    ASSERT_STR_EQ("[fd00::1]:53/tcp: address not available (not an address of this router)", out);
    PASS();
}

/* Catches: no IPv6 on the router told as a bare system error, or another errno losing its own text. */
TEST other_reasons_keep_their_own_text(void) {
    char out[200];
    firc_listen_describe(out, sizeof(out), "[::]", 3553, SOCK_DGRAM, EAFNOSUPPORT, NULL);
    ASSERT_STR_EQ("[::]:3553/udp: address family not supported (is IPv6 off on this router?)", out);
    firc_listen_describe(out, sizeof(out), "0.0.0.0", 80, SOCK_STREAM, EACCES, NULL);
    ASSERT_STR_EQ("0.0.0.0:80/tcp: permission denied", out);
    PASS();
}

static int hold4(int type, uint16_t port) {
    int fd = __real_socket(AF_INET, type, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        (type == SOCK_STREAM && listen(fd, 1) != 0)) {
        if (fd >= 0) { close(fd); }
        return -1;
    }
    return fd;
}

/* Catches: a known holder dropped from the line, or a reason other than in use given one. */
TEST a_holder_replaces_the_hint(void) {
    char out[200];
    firc_listen_describe(out, sizeof(out), "[::]", 3553, SOCK_DGRAM, EADDRINUSE, "socat (pid 812)");
    ASSERT_STR_EQ("[::]:3553/udp: address already in use by socat (pid 812)", out);
    firc_listen_describe(out, sizeof(out), "fd00::1", 53, SOCK_STREAM, EADDRNOTAVAIL, "socat (pid 812)");
    ASSERT_STR_EQ("[fd00::1]:53/tcp: address not available (not an address of this router)", out);
    PASS();
}

static void self_holder(char *out, size_t cap) {
    char comm[64] = "";
    FILE *f = fopen("/proc/self/comm", "r");
    if (f != NULL) {
        if (fgets(comm, sizeof(comm), f) == NULL) { comm[0] = '\0'; }
        fclose(f);
    }
    comm[strcspn(comm, "\n")] = '\0';
    snprintf(out, cap, "%s (pid %ld)", comm, (long)getpid());
}

/* Catches: a failed open not described, or the UDP holder not found in /proc/net/udp or named wrong. */
TEST a_failed_open_names_what_it_tried(void) {
    uint16_t port = free_port(SOCK_DGRAM);
    int held = hold4(SOCK_DGRAM, port);
    ASSERT(held >= 0);
    struct sockaddr_storage sa;
    socklen_t len = 0;
    ASSERT(firc_listen_addr("127.0.0.1", port, false, &sa, &len));
    char why[200] = "";
    ASSERT_EQ(-EADDRINUSE, firc_listen_open("DNS proxy", SOCK_DGRAM, &sa, len, 0, why, sizeof(why)));
    char holder[100];
    self_holder(holder, sizeof(holder));
    char want[300];
    snprintf(want, sizeof(want), "127.0.0.1:%u/udp: address already in use by %s", port, holder);
    ASSERT_STR_EQ(want, why);
    close(held);
    PASS();
}

static int hold6(int type, uint16_t port) {
    int fd = __real_socket(AF_INET6, type, 0);
    struct sockaddr_in6 sa = {.sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_ANY_INIT};
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        (type == SOCK_STREAM && listen(fd, 1) != 0)) {
        if (fd >= 0) { close(fd); }
        return -1;
    }
    return fd;
}

static enum greatest_test_res ipv6_holder_named(int type, const char *proto) {
    uint16_t port = free_port(type);
    ASSERT(port != 0);
    int held = hold6(type, port);
    if (held < 0) { SKIPm("no IPv6 in this namespace"); }
    struct sockaddr_storage sa;
    socklen_t len = 0;
    ASSERT(firc_listen_addr("127.0.0.1", port, false, &sa, &len));
    char why[300] = "";
    int fd = firc_listen_open("DNS proxy", type, &sa, len, 0, why, sizeof(why));
    close(held);
    char holder[100];
    self_holder(holder, sizeof(holder));
    char want[300];
    snprintf(want, sizeof(want), "127.0.0.1:%u/%s: address already in use by %s", port, proto, holder);
    ASSERT_EQ(-EADDRINUSE, fd);
    ASSERT_STR_EQ(want, why);
    PASS();
}

/* Catches: tcp6 never read, or a TCP port looked up in the UDP tables. */
TEST a_tcp_listener_on_ipv6_is_named(void) {
    CHECK_CALL(ipv6_holder_named(SOCK_STREAM, "tcp"));
    PASS();
}

/* Catches: udp6 never read, the table where the DNS proxy's usual holders sit. */
TEST a_udp_socket_on_ipv6_is_named(void) {
    CHECK_CALL(ipv6_holder_named(SOCK_DGRAM, "udp"));
    PASS();
}

/* Catches: /proc walked again for the same failure, a new failure not walked, or a success that keeps the old one. */
TEST the_same_failure_reuses_its_holder(void) {
    uint16_t port = free_port(SOCK_DGRAM);
    int held = hold4(SOCK_DGRAM, port);
    ASSERT(held >= 0);
    struct sockaddr_storage sa;
    socklen_t len = 0;
    ASSERT(firc_listen_addr("127.0.0.1", port, false, &sa, &len));
    firc_listen_seen_t seen = {.err = EADDRINUSE, .held = true, .holder = {.pid = 1, .name = "cached"}};
    char why[300] = "";
    ASSERT_EQ(-EADDRINUSE, firc_listen_open_seen(NULL, SOCK_DGRAM, &sa, len, 0, why, sizeof(why), &seen));
    char want[300];
    snprintf(want, sizeof(want), "127.0.0.1:%u/udp: address already in use by cached (pid 1)", port);
    ASSERT_STR_EQ(want, why);

    seen.err = EACCES;
    ASSERT_EQ(-EADDRINUSE, firc_listen_open_seen(NULL, SOCK_DGRAM, &sa, len, 0, why, sizeof(why), &seen));
    ASSERT_EQ(EADDRINUSE, seen.err);
    ASSERT(seen.held);
    ASSERT_EQ((long)getpid(), seen.holder.pid);

    close(held);
    int fd = firc_listen_open_seen(NULL, SOCK_DGRAM, &sa, len, 0, why, sizeof(why), &seen);
    ASSERT(fd >= 0);
    close(fd);
    ASSERT_EQ(0, seen.err);
    ASSERT_FALSE(seen.held);
    PASS();
}

/* Catches: a fallback that also fails described as [::], an address it never bound. */
TEST a_failed_fallback_names_0_0_0_0(void) {
    uint16_t port = free_port(SOCK_STREAM);
    int held = hold4(SOCK_STREAM, port);
    ASSERT(held >= 0);
    struct sockaddr_storage sa;
    socklen_t len = 0;
    ASSERT(firc_listen_addr("", port, true, &sa, &len));
    g_no_ipv6 = true;
    char why[200] = "";
    ASSERT_EQ(-EADDRINUSE, firc_listen_open("WebUI", SOCK_STREAM, &sa, len, FIRC_WEB_LISTEN, why, sizeof(why)));
    char holder[100];
    self_holder(holder, sizeof(holder));
    char want[300];
    snprintf(want, sizeof(want), "0.0.0.0:%u/tcp: address already in use by %s", port, holder);
    ASSERT_STR_EQ(want, why);
    close(held);
    PASS();
}

/* Catches: the WebUI's fallback WARN not naming the WebUI, or an empty address shown as nothing. */
TEST the_webui_fallback_is_named_and_the_any_address_readable(void) {
    uint16_t port = free_port(SOCK_STREAM);
    ASSERT(port != 0);
    struct sockaddr_storage sa;
    socklen_t len = 0;
    ASSERT(firc_listen_addr("", port, true, &sa, &len));
    g_no_ipv6 = true;
    FILE *log = capture_log();
    ASSERT(log != NULL);
    int fd = firc_listen_open("WebUI", SOCK_STREAM, &sa, len, FIRC_WEB_LISTEN, NULL, 0);
    char text[1024];
    read_log(log, text, sizeof(text));
    ASSERT(fd >= 0);
    close(fd);
    char want[200];
    snprintf(want, sizeof(want),
             "WebUI: IPv6 is not available on this router; listening on 0.0.0.0:%u/tcp instead of [::]:%u", port,
             port);
    ASSERTm(text, strstr(text, want) != NULL);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(reset, NULL);
    RUN_TEST(a_port_in_use_is_named_with_a_hint);
    RUN_TEST(a_holder_replaces_the_hint);
    RUN_TEST(a_tcp_listener_on_ipv6_is_named);
    RUN_TEST(a_udp_socket_on_ipv6_is_named);
    RUN_TEST(a_bare_ipv6_address_gets_brackets);
    RUN_TEST(other_reasons_keep_their_own_text);
    RUN_TEST(the_any_address_falls_back_to_ipv4_without_ipv6);
    RUN_TEST(an_explicit_ipv6_address_does_not_fall_back);
    RUN_TEST(an_any_address_port_in_use_does_not_fall_back);
    RUN_TEST(a_failed_open_names_what_it_tried);
    RUN_TEST(the_same_failure_reuses_its_holder);
    RUN_TEST(a_failed_fallback_names_0_0_0_0);
    RUN_TEST(the_webui_fallback_is_named_and_the_any_address_readable);
    GREATEST_MAIN_END();
}
