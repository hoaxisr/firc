#include "greatest.h"

#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <unistd.h>

#include "firc/log.h"
#include <string.h>
#include <sys/socket.h>

#include "firc/loop.h"
#include "firc/netlink_watcher.h"
#include "firc/rtnl.h"

/* The one interface a message names, 0 for none, -1 for more than one. */
static int one_oif(const struct nlmsghdr *h) {
    int oifs[FIRC_NL_WATCHER_MAX_NEXTHOPS];
    size_t n = firc_nl_watcher_default_route_oifs(h, oifs, sizeof(oifs) / sizeof(oifs[0]));
    return n == 1 ? oifs[0] : n == 0 ? 0 : -1;
}

/* One route message as the kernel would send it. */
static struct nlmsghdr *route_msg(uint8_t *buf, uint16_t type, uint8_t dst_len, uint8_t rtm_type,
                                  uint8_t protocol, uint32_t oif) {
    memset(buf, 0, 256);
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = type;
    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = dst_len;
    rtm->rtm_type = rtm_type;
    rtm->rtm_protocol = protocol;
    rtm->rtm_table = RT_TABLE_MAIN;
    if (oif != 0) { mnl_attr_put_u32(nlh, RTA_OIF, oif); }
    return nlh;
}

TEST a_default_route_names_its_interface(void) {
    uint8_t buf[256];
    ASSERT_EQ_FMT(7, one_oif(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 7)), "%d");
    ASSERT_EQ_FMTm("a default going away just as much", 7,
                   one_oif(route_msg(buf, RTM_DELROUTE, 0, RTN_UNICAST, RTPROT_DHCP, 7)), "%d");
    PASS();
}

/* Catches: a route firc wrote itself naming an interface, so every write triggers another. */
TEST a_route_of_firc_s_own_names_nothing(void) {
    uint8_t buf[256];
    ASSERT_EQ_FMT(0, one_oif(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, FIRC_RTPROT, 7)), "%d");
    PASS();
}

TEST only_default_routes_of_a_forwarding_type_name_an_interface(void) {
    uint8_t buf[256];
    ASSERT_EQ_FMTm("a more-specific route is not the interface's gateway", 0,
                   one_oif(route_msg(buf, RTM_NEWROUTE, 24, RTN_UNICAST, RTPROT_BOOT, 7)), "%d");
    ASSERT_EQ_FMTm("nor is a reject route at /0", 0,
                   one_oif(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNREACHABLE, RTPROT_BOOT, 7)), "%d");
    ASSERT_EQ_FMTm("nor an address or link message", 0,
                   one_oif(route_msg(buf, RTM_NEWADDR, 0, RTN_UNICAST, RTPROT_BOOT, 7)), "%d");
    ASSERT_EQ_FMTm("a default with no device names none", 0,
                   one_oif(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 0)), "%d");
    PASS();
}

/* Catches: only the first leg of an ECMP default named. */
TEST a_multipath_default_names_every_one_of_its_legs(void) {
    uint8_t buf[256];
    struct nlmsghdr *nlh = route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 0);
    uint8_t nhbuf[64];
    memset(nhbuf, 0, sizeof(nhbuf));
    size_t off = 0;
    for (int k = 0; k < 2; k++) {
        struct rtnexthop *nh = (struct rtnexthop *)(void *)(nhbuf + off);
        nh->rtnh_len = (unsigned short)sizeof(*nh);
        nh->rtnh_ifindex = 8 + k;
        off += sizeof(*nh);
    }
    struct rtnexthop *again = (struct rtnexthop *)(void *)(nhbuf + off);
    again->rtnh_len = (unsigned short)sizeof(*again);
    again->rtnh_ifindex = 8;
    off += sizeof(*again);
    mnl_attr_put(nlh, RTA_MULTIPATH, (uint16_t)off, nhbuf);
    int oifs[FIRC_NL_WATCHER_MAX_NEXTHOPS];
    size_t n = firc_nl_watcher_default_route_oifs(nlh, oifs, sizeof(oifs) / sizeof(oifs[0]));
    ASSERT_EQ_FMTm("both legs, each once", (size_t)2, n, "%zu");
    ASSERT_EQ_FMT(8, oifs[0], "%d");
    ASSERT_EQ_FMTm("the second leg is named too", 9, oifs[1], "%d");
    PASS();
}

/* What the watcher logged while `body` ran. */
static void log_of(void (*body)(void), char *out, size_t cap) {
    out[0] = '\0';
    char path[] = "/tmp/firc-watcher-log.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { return; }
    firc_log_set_fd(fd);
    body();
    firc_log_set_fd(2);
    lseek(fd, 0, SEEK_SET);
    ssize_t n = read(fd, out, cap - 1);
    out[n > 0 ? (size_t)n : 0] = '\0';
    close(fd);
    unlink(path);
}

/* How many interfaces come back from one ECMP default with `legs` devices. */
static size_t legs_named(int legs, int *oifs, size_t cap) {
    uint8_t buf[1024];
    struct nlmsghdr *nlh = route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 0);
    uint8_t nhbuf[256];
    memset(nhbuf, 0, sizeof(nhbuf));
    size_t off = 0;
    for (int k = 0; k < legs; k++) {
        struct rtnexthop *nh = (struct rtnexthop *)(void *)(nhbuf + off);
        nh->rtnh_len = (unsigned short)sizeof(*nh);
        nh->rtnh_ifindex = 20 + k;
        off += sizeof(*nh);
    }
    mnl_attr_put(nlh, RTA_MULTIPATH, (uint16_t)off, nhbuf);
    return firc_nl_watcher_default_route_oifs(nlh, oifs, cap);
}

static size_t probe_legs;
static size_t probe_named;
static void name_legs(void) {
    int oifs[FIRC_NL_WATCHER_MAX_NEXTHOPS];
    probe_named = legs_named((int)probe_legs, oifs, sizeof(oifs) / sizeof(oifs[0]));
}

/* Catches: a route that exactly fills the room warned about as dropped legs. */
TEST a_default_with_exactly_as_many_legs_as_there_is_room_for_keeps_them_all(void) {
    char log[512];
    probe_legs = FIRC_NL_WATCHER_MAX_NEXTHOPS;
    log_of(name_legs, log, sizeof(log));
    ASSERT_EQ_FMTm("every leg", (size_t)FIRC_NL_WATCHER_MAX_NEXTHOPS, probe_named, "%zu");
    ASSERTm("nothing was dropped, so nothing is said about dropping", strstr(log, "the rest are not looked at") == NULL);
    PASS();
}

/* Catches: a dropped leg past the room left unsaid. */
TEST a_default_with_more_legs_than_there_is_room_for_says_so(void) {
    char log[512];
    probe_legs = FIRC_NL_WATCHER_MAX_NEXTHOPS + 1;
    log_of(name_legs, log, sizeof(log));
    ASSERT_EQ_FMTm("what fits", (size_t)FIRC_NL_WATCHER_MAX_NEXTHOPS, probe_named, "%zu");
    ASSERTm("the dropped leg is reported", strstr(log, "the rest are not looked at") != NULL);
    PASS();
}

/* Catches: a truncated last message read past the buffer (seen only under sanitize). */
TEST a_truncated_route_message_at_the_end_of_the_buffer_is_not_read(void) {
    struct nlmsghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.nlmsg_len = sizeof(hdr);
    hdr.nlmsg_type = RTM_NEWROUTE;
    struct nlmsghdr *exact = malloc(sizeof(hdr));
    ASSERT(exact != NULL);
    memcpy(exact, &hdr, sizeof(hdr));
    ASSERT_EQ_FMT(0, one_oif(exact), "%d");
    free(exact);
    PASS();
}

TEST a_truncated_route_message_names_nothing(void) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_NEWROUTE;
    struct nlmsghdr *next = mnl_nlmsg_put_header(buf + nlh->nlmsg_len);
    next->nlmsg_type = RTM_NEWROUTE;
    struct rtmsg *rtm2 = mnl_nlmsg_put_extra_header(next, sizeof(*rtm2));
    rtm2->rtm_family = AF_INET;
    rtm2->rtm_type = RTN_UNICAST;
    rtm2->rtm_protocol = RTPROT_BOOT;
    mnl_attr_put_u32(next, RTA_OIF, 7);
    ASSERT_EQ_FMTm("nothing of the message that follows is read as this one's", 0, one_oif(nlh), "%d");
    PASS();
}

/* Catches: the watcher not joining the route groups, missing a reconnected WAN's gateway. */
TEST the_watcher_listens_for_route_changes_as_well_as_links_and_addresses(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_nl_watcher_t *w = NULL;
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(loop, NULL, NULL, NULL, NULL, NULL, NULL, &w));
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    socklen_t len = sizeof(sa);
    ASSERT_EQ(0, getsockname(firc_nl_watcher_fd(w), (struct sockaddr *)&sa, &len));
    ASSERTm("link", (sa.nl_groups & RTMGRP_LINK) != 0);
    ASSERTm("ipv4 addresses", (sa.nl_groups & RTMGRP_IPV4_IFADDR) != 0);
    ASSERTm("ipv6 addresses", (sa.nl_groups & RTMGRP_IPV6_IFADDR) != 0);
    ASSERTm("ipv4 routes", (sa.nl_groups & RTMGRP_IPV4_ROUTE) != 0);
    ASSERTm("ipv6 routes", (sa.nl_groups & RTMGRP_IPV6_ROUTE) != 0);
    firc_nl_watcher_destroy(w);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: ENOBUFS read as a dead socket or as nothing, instead of lost state. */
TEST an_overrun_buffer_means_lost_state_not_a_dead_socket(void) {
    ASSERT_EQ_FMT(FIRC_NL_RECV_LOST, firc_nl_watcher_recv_verdict(ENOBUFS), "%d");
    ASSERT_EQ_FMTm("nothing more to read, for now", FIRC_NL_RECV_DRAINED, firc_nl_watcher_recv_verdict(EAGAIN),
                   "%d");
    ASSERT_EQ_FMTm("interrupted, not over", FIRC_NL_RECV_RETRY, firc_nl_watcher_recv_verdict(EINTR), "%d");
    ASSERT_EQ_FMTm("a socket that is no use any more", FIRC_NL_RECV_FATAL, firc_nl_watcher_recv_verdict(EBADF),
                   "%d");
    PASS();
}

static void count_lost(void *ud) { (*(int *)ud)++; }

/* Catches: a lost message not reported to the listener, or reading stopped after it. */
TEST a_lost_message_tells_the_listener_and_reading_goes_on(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    int lost = 0;
    firc_nl_watcher_t *w = NULL;
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(loop, NULL, NULL, NULL, NULL, count_lost, &lost, &w));
    ASSERTm("read on: the socket is fine", firc_nl_watcher_handle_recv_error(w, ENOBUFS));
    ASSERT_EQ_FMTm("the listener was told", 1, lost, "%d");
    ASSERTm("a datagram that did not fit is lost too", firc_nl_watcher_handle_recv_error(w, ENOSPC));
    ASSERT_EQ_FMT(2, lost, "%d");
    ASSERTm("interrupted: read again", firc_nl_watcher_handle_recv_error(w, EINTR));
    ASSERT_EQ_FMTm("...and nothing was lost", 2, lost, "%d");
    ASSERT_FALSEm("nothing more to read, for now", firc_nl_watcher_handle_recv_error(w, EAGAIN));
    ASSERT_FALSEm("a socket that is no use any more", firc_nl_watcher_handle_recv_error(w, EBADF));
    ASSERT_EQ_FMTm("neither of those is a loss", 2, lost, "%d");
    firc_nl_watcher_destroy(w);
    firc_loop_destroy(loop);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_default_route_names_its_interface);
    RUN_TEST(a_route_of_firc_s_own_names_nothing);
    RUN_TEST(only_default_routes_of_a_forwarding_type_name_an_interface);
    RUN_TEST(a_multipath_default_names_every_one_of_its_legs);
    RUN_TEST(a_default_with_exactly_as_many_legs_as_there_is_room_for_keeps_them_all);
    RUN_TEST(a_default_with_more_legs_than_there_is_room_for_says_so);
    RUN_TEST(a_truncated_route_message_names_nothing);
    RUN_TEST(a_truncated_route_message_at_the_end_of_the_buffer_is_not_read);
    RUN_TEST(the_watcher_listens_for_route_changes_as_well_as_links_and_addresses);
    RUN_TEST(an_overrun_buffer_means_lost_state_not_a_dead_socket);
    RUN_TEST(a_lost_message_tells_the_listener_and_reading_goes_on);
    GREATEST_MAIN_END();
}
