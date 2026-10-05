#include "firc/netlink_watcher.h"
#include "firc/log.h"
#include "firc/nlattr_iter.h"
#include "firc/rtnl.h"

#include <errno.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define FIRC_NL_WATCHER_RECVBUF 8192

struct firc_nl_watcher {
    struct mnl_socket *nl;
    firc_loop_t *loop;
    firc_nl_link_cb link_cb;
    void *link_ud;
    firc_nl_addr_cb addr_cb;
    void *addr_ud;
    firc_nl_lost_cb lost_cb;
    void *lost_ud;
};

static void handle_link_msg(firc_nl_watcher_t *w, const struct nlmsghdr *h) {
    if (h->nlmsg_type != RTM_NEWLINK || !w->link_cb) { return; }

    const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(h);
    bool up = (ifi->ifi_flags & IFF_UP) != 0;
    if (!up) { return; }

    char name[IFNAMSIZ] = {0};
    firc_nlattr_iter_t attr_it;
    const struct nlattr *attr;
    if (!firc_nlattr_iter_init_nlmsg(&attr_it, h, sizeof(struct ifinfomsg))) { return; }
    while (firc_nlattr_iter_next(&attr_it, &attr)) {
        if (mnl_attr_get_type(attr) == IFLA_IFNAME) {
            const char *v = mnl_attr_get_str(attr);
            snprintf(name, sizeof(name), "%s", v);
        }
    }
    if (name[0] == '\0') { return; }

    w->link_cb(name, true, w->link_ud);
}

static void handle_addr_msg(firc_nl_watcher_t *w, const struct nlmsghdr *h) {
    if (h->nlmsg_type != RTM_NEWADDR || !w->addr_cb) {
        return;
    }
    const struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(h);
    char name[IFNAMSIZ] = {0};
    if (!if_indextoname(ifa->ifa_index, name)) { return; }
    w->addr_cb(name, w->addr_ud);
}

firc_nl_recv_verdict_t firc_nl_watcher_recv_verdict(int err) {
    switch (err) {
    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
        return FIRC_NL_RECV_DRAINED;
    case EINTR:
        return FIRC_NL_RECV_RETRY;
    case ENOBUFS:
    case ENOSPC:
        /* Messages were dropped but the socket is fine: read on. */
        return FIRC_NL_RECV_LOST;
    default:
        return FIRC_NL_RECV_FATAL;
    }
}

/* False only when a device was dropped for want of room. */
static bool add_oif(int *out, size_t max, size_t *n, int oif) {
    if (oif <= 0) { return true; }
    for (size_t i = 0; i < *n; i++) {
        if (out[i] == oif) { return true; }
    }
    if (*n == max) { return false; }
    out[(*n)++] = oif;
    return true;
}

size_t firc_nl_watcher_default_route_oifs(const struct nlmsghdr *h, int *out, size_t max) {
    size_t n = 0;
    bool dropped = false;
    if (out == NULL || max == 0) { return 0; }
    if (h->nlmsg_type != RTM_NEWROUTE && h->nlmsg_type != RTM_DELROUTE) { return 0; }
    if (mnl_nlmsg_get_payload_len(h) < sizeof(struct rtmsg)) { return 0; }
    const struct rtmsg *rtm = mnl_nlmsg_get_payload(h);
    if (rtm->rtm_dst_len != 0 || rtm->rtm_type != RTN_UNICAST) { return 0; }
    if (rtm->rtm_protocol == FIRC_RTPROT) { return 0; }

    firc_nlattr_iter_t it;
    const struct nlattr *a;
    if (!firc_nlattr_iter_init_nlmsg(&it, h, sizeof(struct rtmsg))) { return 0; }
    while (firc_nlattr_iter_next(&it, &a)) {
        uint16_t t = mnl_attr_get_type(a);
        if (t == RTA_OIF && mnl_attr_get_payload_len(a) == 4) {
            dropped = !add_oif(out, max, &n, (int)mnl_attr_get_u32(a)) || dropped;
        } else if (t == RTA_MULTIPATH) {
            /* ECMP: one device per leg, none at the top level; name every leg. */
            const void *p = mnl_attr_get_payload(a);
            size_t left = mnl_attr_get_payload_len(a);
            const struct rtnexthop *nh = p;
            while (left >= sizeof(*nh) && nh->rtnh_len >= sizeof(*nh) && (size_t)nh->rtnh_len <= left) {
                dropped = !add_oif(out, max, &n, nh->rtnh_ifindex) || dropped;
                size_t step = (size_t)RTNH_ALIGN(nh->rtnh_len);
                if (step == 0 || step > left) { break; }
                left -= step;
                nh = (const struct rtnexthop *)(const void *)((const char *)nh + step);
            }
        }
    }
    if (dropped) {
        FIRC_WARN("a default route names more than %d devices; the rest are not looked at", (int)max);
    }
    return n;
}

static void handle_route_msg(firc_nl_watcher_t *w, const struct nlmsghdr *h) {
    if (!w->addr_cb) { return; }
    int oifs[FIRC_NL_WATCHER_MAX_NEXTHOPS];
    size_t n = firc_nl_watcher_default_route_oifs(h, oifs, sizeof(oifs) / sizeof(oifs[0]));
    for (size_t i = 0; i < n; i++) {
        char name[IFNAMSIZ] = {0};
        if (!if_indextoname((unsigned)oifs[i], name)) { continue; }
        w->addr_cb(name, w->addr_ud);
    }
}

bool firc_nl_watcher_handle_recv_error(firc_nl_watcher_t *w, int err) {
    switch (firc_nl_watcher_recv_verdict(err)) {
    case FIRC_NL_RECV_RETRY:
        return true;
    case FIRC_NL_RECV_LOST:
        FIRC_WARN("netlink watcher lost messages (%s); every interface is re-read",
                  err == ENOBUFS ? "its buffer overran" : "a message did not fit the read buffer");
        if (w->lost_cb) { w->lost_cb(w->lost_ud); }
        return true;
    case FIRC_NL_RECV_FATAL:
        FIRC_WARN("netlink watcher recv error: %s", strerror(err));
        return false;
    case FIRC_NL_RECV_DRAINED:
    default:
        return false;
    }
}

static void on_readable(firc_loop_t *loop, int fd, uint32_t events, void *ud) {
    (void)loop;
    (void)fd;
    (void)events;
    firc_nl_watcher_t *w = ud;
    uint8_t buf[FIRC_NL_WATCHER_RECVBUF];

    for (;;) {
        ssize_t ret = mnl_socket_recvfrom(w->nl, buf, sizeof(buf));
        if (ret < 0) {
            if (!firc_nl_watcher_handle_recv_error(w, errno)) { return; }
            continue;
        }
        if (ret == 0) { break; }

        int len = (int)ret;
        struct nlmsghdr *nh = (struct nlmsghdr *)buf;
        while (mnl_nlmsg_ok(nh, len)) {
            switch (nh->nlmsg_type) {
            case RTM_NEWLINK:
                handle_link_msg(w, nh);
                break;
            case RTM_NEWADDR:
                handle_addr_msg(w, nh);
                break;
            case RTM_NEWROUTE:
            case RTM_DELROUTE:
                handle_route_msg(w, nh);
                break;
            default:
                break;
            }
            nh = mnl_nlmsg_next(nh, &len);
        }
    }
}

firc_err_t firc_nl_watcher_create(firc_loop_t *loop, firc_nl_link_cb link_cb, void *link_ud,
                                  firc_nl_addr_cb addr_cb, void *addr_ud, firc_nl_lost_cb lost_cb,
                                  void *lost_ud, firc_nl_watcher_t **out) {
    *out = NULL;
    firc_nl_watcher_t *w = calloc(1, sizeof(*w));
    if (!w) { return FIRC_ERR_NOMEM; }
    w->loop = loop;
    w->link_cb = link_cb;
    w->link_ud = link_ud;
    w->addr_cb = addr_cb;
    w->addr_ud = addr_ud;
    w->lost_cb = lost_cb;
    w->lost_ud = lost_ud;

    w->nl = mnl_socket_open(NETLINK_ROUTE);
    if (!w->nl) {
        firc_err_t err = firc_err_from_errno(errno);
        free(w);
        return err;
    }

    /* Room for route-multicast bursts; SO_RCVBUFFORCE passes rmem_max with CAP_NET_ADMIN. */
    int rcvbuf = 512 * 1024;
    int wfd = mnl_socket_get_fd(w->nl);
    bool got = false;
#ifdef SO_RCVBUFFORCE
    got = setsockopt(wfd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) == 0;
#endif
    if (!got && setsockopt(wfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0) {
        FIRC_DEBUG("netlink watcher keeps the default receive buffer: %s", strerror(errno));
    }

    unsigned int groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE |
                          RTMGRP_IPV6_ROUTE;
    if (mnl_socket_bind(w->nl, groups, MNL_SOCKET_AUTOPID) < 0) {
        firc_err_t err = firc_err_from_errno(errno);
        mnl_socket_close(w->nl);
        free(w);
        return err;
    }

    int flags = fcntl(wfd, F_GETFL, 0);
    if (flags < 0 || fcntl(wfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        firc_err_t err = firc_err_from_errno(errno);
        mnl_socket_close(w->nl);
        free(w);
        return err;
    }

    firc_err_t err = firc_loop_add_fd(loop, wfd, EPOLLIN, on_readable, w);
    if (err != FIRC_OK) {
        mnl_socket_close(w->nl);
        free(w);
        return err;
    }

    *out = w;
    return FIRC_OK;
}

int firc_nl_watcher_fd(const firc_nl_watcher_t *w) {
    return w == NULL || w->nl == NULL ? -1 : mnl_socket_get_fd(w->nl);
}

void firc_nl_watcher_destroy(firc_nl_watcher_t *w) {
    if (!w) { return; }
    firc_loop_del_fd(w->loop, mnl_socket_get_fd(w->nl));
    mnl_socket_close(w->nl);
    free(w);
}
