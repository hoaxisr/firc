#include "firc/mark.h"
#include "firc/rtnl.h"
#include "firc/log.h"
#include "firc/nlattr_iter.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <libmnl/libmnl.h>
#include <linux/fib_rules.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define FIRC_RTNL_RECVBUF 8192

typedef struct {
    char owner[48];
    uint32_t field;
} field_hint_t;

struct firc_rtnl {
    struct mnl_socket *nl; /* NULL when opened over a caller's fd */
    int fd;
    uint32_t seq;
    field_hint_t hints[FIRC_MARK_MAX_GROUPS];
    size_t n_hints;
    firc_rtnl_fields_fn on_fields;
    void *on_fields_ud;
};

static uint32_t hint_for(const firc_rtnl_t *r, const char *owner) {
    if (owner == NULL) { return 0; }
    for (size_t i = 0; i < r->n_hints; i++) {
        if (strcmp(r->hints[i].owner, owner) == 0) { return r->hints[i].field; }
    }
    return 0;
}

static bool remember_hint(firc_rtnl_t *r, const char *owner, uint32_t field) {
    if (owner == NULL || strlen(owner) >= sizeof(r->hints[0].owner)) { return false; }
    for (size_t i = 0; i < r->n_hints; i++) {
        if (strcmp(r->hints[i].owner, owner) == 0) {
            bool changed = r->hints[i].field != field;
            r->hints[i].field = field;
            return changed;
        }
    }
    if (r->n_hints == FIRC_MARK_MAX_GROUPS) { return false; }
    snprintf(r->hints[r->n_hints].owner, sizeof(r->hints[0].owner), "%s", owner);
    r->hints[r->n_hints].field = field;
    r->n_hints++;
    return true;
}

static void hand_fields(const firc_rtnl_t *r, firc_rtnl_fields_fn fn, void *ud) {
    if (fn == NULL) { return; }
    firc_rtnl_field_t v[FIRC_MARK_MAX_GROUPS];
    for (size_t i = 0; i < r->n_hints; i++) {
        v[i].owner = r->hints[i].owner;
        v[i].field = r->hints[i].field;
    }
    fn(ud, v, r->n_hints);
}

static void notify_fields(const firc_rtnl_t *r) {
    hand_fields(r, r->on_fields, r->on_fields_ud);
}

firc_rtnl_t *firc_rtnl_open(void) {
    firc_rtnl_t *r = calloc(1, sizeof(*r));
    if (!r) { return NULL; }
    r->nl = mnl_socket_open(NETLINK_ROUTE);
    if (!r->nl) {
        free(r);
        return NULL;
    }
    if (mnl_socket_bind(r->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(r->nl);
        free(r);
        return NULL;
    }
    r->fd = mnl_socket_get_fd(r->nl);
    return r;
}

firc_rtnl_t *firc_rtnl_open_fd(int fd) {
    firc_rtnl_t *r = calloc(1, sizeof(*r));
    if (!r) { return NULL; }
    r->fd = fd;
    return r;
}

void firc_rtnl_close(firc_rtnl_t *r) {
    if (!r) { return; }
    if (r->nl) {
        mnl_socket_close(r->nl);
    } else {
        close(r->fd);
    }
    free(r);
}

static bool payload_at_least(const struct nlmsghdr *h, size_t n) {
    return mnl_nlmsg_get_payload_len(h) >= n;
}

/* An abandoned dump blocks the socket's next dump until its DONE is read. */
static void drain_dump(firc_rtnl_t *r, uint32_t seq) {
    uint8_t buf[FIRC_RTNL_RECVBUF];
    for (int guard = 0; guard < 65536; guard++) {
        struct pollfd pfd = {.fd = r->fd, .events = POLLIN};
        if (poll(&pfd, 1, 200) <= 0) { return; }
        ssize_t ret = recv(r->fd, buf, sizeof(buf), MSG_TRUNC | MSG_DONTWAIT);
        if (ret <= 0) { return; }
        int len = (int)ret;
        if ((size_t)ret > sizeof(buf)) { len = (int)sizeof(buf); }
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        while (mnl_nlmsg_ok(h, len)) {
            if (h->nlmsg_seq == seq && (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)) { return; }
            h = mnl_nlmsg_next(h, &len);
        }
    }
}

static firc_err_t nl_execute(firc_rtnl_t *r, struct nlmsghdr *nlh, int *out_code,
                          void (*msg_cb)(const struct nlmsghdr *, void *), void *cb_ud) {
    *out_code = 0;
    if (send(r->fd, nlh, nlh->nlmsg_len, 0) < 0) { return firc_err_from_errno(errno); }

    const uint32_t seq = nlh->nlmsg_seq;
    const bool dump = (nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
    const bool acked = dump || (nlh->nlmsg_flags & NLM_F_ACK) != 0;
    uint8_t buf[FIRC_RTNL_RECVBUF];
    for (;;) {
        /* MSG_TRUNC: an oversized reply is an error, never a shortened dump. */
        ssize_t ret = recv(r->fd, buf, sizeof(buf), MSG_TRUNC);
        if (ret < 0) { return firc_err_from_errno(errno); }
        if ((size_t)ret > sizeof(buf)) {
            if (dump) { drain_dump(r, seq); }
            return FIRC_ERR_LIMIT;
        }
        /* EOF (only a test peer sends one) must not read as success. */
        if (ret == 0) { return FIRC_ERR_IO; }

        int len = (int)ret;
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        bool done = false, ours = false;
        while (mnl_nlmsg_ok(h, len)) {
            /* Other seqs are leftovers; an ACKed request or a dump ends at our error or DONE. */
            if (h->nlmsg_seq != seq) {
                h = mnl_nlmsg_next(h, &len);
                continue;
            }
            ours = true;
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (!payload_at_least(h, sizeof(struct nlmsgerr))) {
                    if (dump) { drain_dump(r, seq); }
                    return FIRC_ERR_PROTO;
                }
                struct nlmsgerr *e = (struct nlmsgerr *)mnl_nlmsg_get_payload(h);
                *out_code = e->error < 0 ? -e->error : e->error;
                done = true;
                break;
            }
            if (h->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (msg_cb) { msg_cb(h, cb_ud); }
            h = mnl_nlmsg_next(h, &len);
        }
        if (done) { break; }
        if (!acked && ours) { break; }
    }
    return FIRC_OK;
}

static struct nlmsghdr *put_rule_header(uint8_t *buf, uint16_t type, uint16_t flags, uint32_t seq,
                                        int family, uint32_t table) {
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = seq;

    struct fib_rule_hdr *frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
    memset(frh, 0, sizeof(*frh));
    frh->family = (uint8_t)family;
    frh->table = table < 256 ? (uint8_t)table : RT_TABLE_UNSPEC;
    frh->action = (type == RTM_NEWRULE) ? FR_ACT_TO_TBL : FR_ACT_UNSPEC;
    return nlh;
}

struct nlmsghdr *firc_rtnl_build_rule(void *buf, bool add, uint32_t seq, int family, uint32_t mark,
                                      uint32_t mask, uint32_t table, uint32_t priority) {
    if (buf == NULL) { return NULL; }
    uint16_t flags = add ? (uint16_t)(NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)
                         : (uint16_t)(NLM_F_REQUEST | NLM_F_ACK);
    struct nlmsghdr *nlh = put_rule_header((uint8_t *)buf, add ? RTM_NEWRULE : RTM_DELRULE, flags,
                                           seq, family, table);
    mnl_attr_put_u32(nlh, FRA_FWMARK, mark);
    mnl_attr_put_u32(nlh, FRA_FWMASK, mask);
    mnl_attr_put_u32(nlh, FRA_PRIORITY, priority);
    if (table >= 256) { mnl_attr_put_u32(nlh, FRA_TABLE, table); }
    return nlh;
}

static firc_err_t rule_add(firc_rtnl_t *r, int family, uint32_t mark, uint32_t mask,
                           uint32_t table, uint32_t priority, const char *reply_iif) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh =
        firc_rtnl_build_rule(buf, true, ++r->seq, family, mark, mask, table, priority);
    if (reply_iif != NULL) {
        mnl_attr_put_strz(nlh, FRA_IIFNAME, reply_iif);
        mnl_attr_put_u32(nlh, FIRC_FRA_SUPPRESS_PREFIXLEN, 0);
    }

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == 0) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

firc_err_t firc_rtnl_rule_add(firc_rtnl_t *r, int family, uint32_t mark, uint32_t mask,
                              uint32_t table, uint32_t priority) {
    return rule_add(r, family, mark, mask, table, priority, NULL);
}

firc_err_t firc_rtnl_rule_add_reply(firc_rtnl_t *r, int family, uint32_t mark, uint32_t mask,
                                    const char *iif, uint32_t table, uint32_t priority) {
    if (iif == NULL || iif[0] == '\0' || strlen(iif) >= IFNAMSIZ) { return FIRC_ERR_INVAL; }
    return rule_add(r, family, mark, mask, table, priority, iif);
}

firc_err_t firc_rtnl_rule_del(firc_rtnl_t *r, int family, uint32_t mark, uint32_t mask,
                              uint32_t table, uint32_t priority) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh =
        firc_rtnl_build_rule(buf, false, ++r->seq, family, mark, mask, table, priority);

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == 0 || code == ENOENT) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

static firc_err_t occupant_of(firc_rtnl_t *r, int family, uint32_t table, uint32_t priority, const uint8_t *dst,
                              uint8_t prefix_len, bool *found, bool *ours, uint8_t *rtm_type);

static struct nlmsghdr *put_route_header(uint8_t *buf, uint16_t type, uint16_t flags, uint32_t seq,
                                         int family, uint32_t table, uint8_t rtm_type) {
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = seq;

    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
    memset(rtm, 0, sizeof(*rtm));
    rtm->rtm_family = (uint8_t)family;
    rtm->rtm_table = table < 256 ? (uint8_t)table : RT_TABLE_UNSPEC;
    rtm->rtm_protocol = FIRC_RTPROT;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = rtm_type;
    return nlh;
}

firc_err_t firc_rtnl_route_add_blackhole(firc_rtnl_t *r, int family, uint32_t table, uint32_t priority) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = put_route_header(
        buf, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK, ++r->seq, family,
        table, RTN_BLACKHOLE);
    if (table >= 256) { mnl_attr_put_u32(nlh, RTA_TABLE, table); }
    mnl_attr_put_u32(nlh, RTA_PRIORITY, priority);

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == 0) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

firc_err_t firc_rtnl_route_del_blackhole(firc_rtnl_t *r, int family, uint32_t table, uint32_t priority) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = put_route_header(buf, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, ++r->seq,
                                            family, table, RTN_BLACKHOLE);
    if (table >= 256) { mnl_attr_put_u32(nlh, RTA_TABLE, table); }
    mnl_attr_put_u32(nlh, RTA_PRIORITY, priority);

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == 0 || code == ESRCH) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

struct nlmsghdr *firc_rtnl_build_unreachable(void *buf, bool add, uint32_t seq, int family,
                                             uint32_t table, uint32_t priority,
                                             const uint8_t *dst, uint8_t prefix_len) {
    if (buf == NULL || dst == NULL) { return NULL; }
    size_t addr_len = (family == AF_INET) ? 4u : (family == AF_INET6 ? 16u : 0u);
    if (addr_len == 0 || prefix_len > addr_len * 8u) { return NULL; }

    uint16_t flags = add ? (uint16_t)(NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)
                         : (uint16_t)(NLM_F_REQUEST | NLM_F_ACK);
    struct nlmsghdr *nlh = put_route_header((uint8_t *)buf, add ? RTM_NEWROUTE : RTM_DELROUTE,
                                            flags, seq, family, table, RTN_UNREACHABLE);
    /* Without dst_len and RTA_DST the request names the table's default route. */
    struct rtmsg *rtm = (struct rtmsg *)mnl_nlmsg_get_payload(nlh);
    rtm->rtm_dst_len = prefix_len;
    if (table >= 256) { mnl_attr_put_u32(nlh, RTA_TABLE, table); }
    mnl_attr_put_u32(nlh, RTA_PRIORITY, priority);
    mnl_attr_put(nlh, RTA_DST, addr_len, dst);
    return nlh;
}

firc_err_t firc_rtnl_route_add_unreachable(firc_rtnl_t *r, int family, uint32_t table,
                                           uint32_t priority, const uint8_t *dst,
                                           uint8_t prefix_len) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh =
        firc_rtnl_build_unreachable(buf, true, ++r->seq, family, table, priority, dst, prefix_len);
    if (nlh == NULL) { return FIRC_ERR_INVAL; }

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == 0) { return FIRC_OK; }
    if (code == EEXIST) {
        /* EEXIST: ours is adopted, an untagged reject replaced, a forwarding route refused. */
        bool found = false, ours = false;
        uint8_t type = RTN_UNSPEC;
        firc_err_t oerr = occupant_of(r, family, table, priority, dst, prefix_len, &found, &ours, &type);
        if (oerr != FIRC_OK) { return oerr; }
        bool rejecting = type == RTN_UNREACHABLE || type == RTN_BLACKHOLE || type == RTN_PROHIBIT;
        if (found && rejecting && ours) { return FIRC_OK; }
        if (found && !rejecting) {
            FIRC_WARN("a forwarding route holds the pool prefix at metric %u in table %u: the pool would be "
                      "routed, not rejected", priority, table);
            return FIRC_ERR_EXIST;
        }
        /* Gone in between: one more exclusive try; a second EEXIST fails. */
        memset(buf, 0, sizeof(buf));
        nlh = firc_rtnl_build_unreachable(buf, true, ++r->seq, family, table, priority, dst, prefix_len);
        if (nlh == NULL) { return FIRC_ERR_INVAL; }
        if (found) { nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK; }
        err = nl_execute(r, nlh, &code, NULL, NULL);
        if (err != FIRC_OK) { return err; }
        if (code == 0) { return FIRC_OK; }
        if (code == EEXIST) {
            if (found) {
                FIRC_WARN("the reject route at the pool prefix, metric %u, table %u could not be replaced", priority,
                          table);
            } else {
                FIRC_WARN("the pool prefix at metric %u in table %u is held by a route the dump does not show; not "
                          "taken as ours", priority, table);
            }
            return FIRC_ERR_EXIST;
        }
        return firc_err_from_errno(code);
    }
    return firc_err_from_errno(code);
}

firc_err_t firc_rtnl_route_del_unreachable(firc_rtnl_t *r, int family, uint32_t table,
                                           uint32_t priority, const uint8_t *dst,
                                           uint8_t prefix_len) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh =
        firc_rtnl_build_unreachable(buf, false, ++r->seq, family, table, priority, dst, prefix_len);
    if (nlh == NULL) { return FIRC_ERR_INVAL; }

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == 0 || code == ESRCH || code == ENOENT) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

firc_err_t firc_rtnl_route_add_iface(firc_rtnl_t *r, int family, uint32_t table, uint32_t priority,
                                 int oif, const uint8_t *gw, uint8_t gw_len, bool *enodev) {
    *enodev = false;
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = put_route_header(
        buf, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK, ++r->seq, family,
        table, RTN_UNICAST);
    if (table >= 256) { mnl_attr_put_u32(nlh, RTA_TABLE, table); }
    mnl_attr_put_u32(nlh, RTA_PRIORITY, priority);
    mnl_attr_put_u32(nlh, RTA_OIF, (uint32_t)oif);
    if (gw && gw_len > 0) { mnl_attr_put(nlh, RTA_GATEWAY, gw_len, gw); }

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == ENODEV) {
        *enodev = true;
        return FIRC_OK;
    }
    if (code == 0) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

firc_err_t firc_rtnl_route_del_iface(firc_rtnl_t *r, int family, uint32_t table, uint32_t priority,
                                 int oif, const uint8_t *gw, uint8_t gw_len) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = put_route_header(buf, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, ++r->seq,
                                            family, table, RTN_UNICAST);
    if (table >= 256) { mnl_attr_put_u32(nlh, RTA_TABLE, table); }
    mnl_attr_put_u32(nlh, RTA_PRIORITY, priority);
    mnl_attr_put_u32(nlh, RTA_OIF, (uint32_t)oif);
    if (gw && gw_len > 0) { mnl_attr_put(nlh, RTA_GATEWAY, gw_len, gw); }

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == 0 || code == ESRCH) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

typedef struct link_ctx {
    bool found;
    unsigned flags;
} link_ctx_t;

static void link_msg_cb(const struct nlmsghdr *h, void *ud) {
    link_ctx_t *ctx = ud;
    if (h->nlmsg_type != RTM_NEWLINK || !payload_at_least(h, sizeof(struct ifinfomsg))) { return; }
    const struct ifinfomsg *ifi = mnl_nlmsg_get_payload(h);
    ctx->found = true;
    ctx->flags = ifi->ifi_flags;
}

firc_err_t firc_rtnl_link_by_name(firc_rtnl_t *r, const char *name, firc_link_info_t *out, bool *found) {
    *found = false;
    memset(out, 0, sizeof(*out));

    unsigned idx = if_nametoindex(name);
    if (idx == 0) { return FIRC_OK; }

    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    /* No NLM_F_ACK: this single-reply path would leave the ACK queued for the next request. */
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++r->seq;
    struct ifinfomsg *ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
    memset(ifi, 0, sizeof(*ifi));
    ifi->ifi_index = (int)idx;

    link_ctx_t ctx = {0};
    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, link_msg_cb, &ctx);
    if (err != FIRC_OK) { return err; }
    if (code != 0 && code != ENODEV) { return firc_err_from_errno(code); }
    if (!ctx.found) { return FIRC_OK; }

    out->ifindex = (int)idx;
    out->up = (ctx.flags & IFF_UP) != 0;
    out->point_to_point = (ctx.flags & IFF_POINTOPOINT) != 0;
    *found = true;
    return FIRC_OK;
}

typedef struct gw_ctx {
    int want_oif;
    bool found;
    bool saw_gatewayless;
    bool in_main;
    uint32_t priority; /* metric */
    uint8_t gw[16];
    uint8_t gw_len;
} gw_ctx_t;

/* IPv4 ECMP keeps next hops only in RTA_MULTIPATH, none at the top level. */
static bool multipath_gw(const struct nlattr *attr, int want_oif, uint8_t *gw, uint8_t *gw_len) {
    const void *p = mnl_attr_get_payload(attr);
    size_t left = mnl_attr_get_payload_len(attr);
    const struct rtnexthop *nh = p;
    while (left >= sizeof(*nh) && nh->rtnh_len >= sizeof(*nh) && (size_t)nh->rtnh_len <= left) {
        if (nh->rtnh_ifindex == want_oif) {
            const struct nlattr *a = (const struct nlattr *)(const void *)((const char *)nh + sizeof(*nh));
            int alen = (int)(nh->rtnh_len - sizeof(*nh));
            while (mnl_attr_ok(a, alen)) {
                uint16_t len = mnl_attr_get_payload_len(a);
                if (mnl_attr_get_type(a) == RTA_GATEWAY && (len == 4 || len == 16)) {
                    memcpy(gw, mnl_attr_get_payload(a), len);
                    *gw_len = (uint8_t)len;
                    return true;
                }
                int step = (int)MNL_ALIGN(a->nla_len);
                if (step <= 0) { break; }
                alen -= step;
                a = (const struct nlattr *)(const void *)((const char *)a + step);
            }
        }
        size_t step = (size_t)RTNH_ALIGN(nh->rtnh_len);
        if (step == 0 || step > left) { break; }
        left -= step;
        nh = (const struct rtnexthop *)(const void *)((const char *)nh + step);
    }
    return false;
}

/* Dump order is no ranking: every default is compared, main first, then lowest metric; ours are skipped. */
static void gw_msg_cb(const struct nlmsghdr *h, void *ud) {
    gw_ctx_t *ctx = ud;
    if (h->nlmsg_type != RTM_NEWROUTE) { return; }
    if (!payload_at_least(h, sizeof(struct rtmsg))) { return; }
    const struct rtmsg *rtm = mnl_nlmsg_get_payload(h);
    if (rtm->rtm_protocol == FIRC_RTPROT) { return; }
    if (rtm->rtm_dst_len != 0 || rtm->rtm_type != RTN_UNICAST) { return; }

    int oif = -1;
    uint8_t gw[16] = {0};
    uint8_t gwlen = 0;
    uint32_t table = rtm->rtm_table, priority = 0;

    firc_nlattr_iter_t attr_it;
    const struct nlattr *attr;
    if (!firc_nlattr_iter_init_nlmsg(&attr_it, h, sizeof(struct rtmsg))) { return; }
    while (firc_nlattr_iter_next(&attr_it, &attr)) {
        switch (mnl_attr_get_type(attr)) {
        case RTA_OIF:
            if (mnl_attr_get_payload_len(attr) == 4) {
                oif = (int)*(const uint32_t *)mnl_attr_get_payload(attr);
            }
            break;
        case RTA_GATEWAY: {
            uint16_t len = mnl_attr_get_payload_len(attr);
            if (len == 4 || len == 16) {
                memcpy(gw, mnl_attr_get_payload(attr), len);
                gwlen = (uint8_t)len;
            }
            break;
        }
        case RTA_TABLE:
            if (mnl_attr_get_payload_len(attr) == 4) { table = *(const uint32_t *)mnl_attr_get_payload(attr); }
            break;
        case RTA_PRIORITY:
            if (mnl_attr_get_payload_len(attr) == 4) { priority = *(const uint32_t *)mnl_attr_get_payload(attr); }
            break;
        case RTA_MULTIPATH:
            if (multipath_gw(attr, ctx->want_oif, gw, &gwlen)) { oif = ctx->want_oif; }
            break;
        default:
            break;
        }
    }
    if (oif != ctx->want_oif) { return; }
    if (gwlen == 0) {
        ctx->saw_gatewayless = true;
        return;
    }

    bool in_main = table == RT_TABLE_MAIN;
    bool better = !ctx->found || (in_main && !ctx->in_main) || (in_main == ctx->in_main && priority < ctx->priority);
    if (!better) { return; }
    memcpy(ctx->gw, gw, gwlen);
    ctx->gw_len = gwlen;
    ctx->in_main = in_main;
    ctx->priority = priority;
    ctx->found = true;
}

firc_err_t firc_rtnl_gateway_for_iface(firc_rtnl_t *r, int family, int ifindex, bool *found, uint8_t *gw,
                                       uint8_t *gw_len) {
    bool ignored = false;
    return firc_rtnl_gateway_for_iface2(r, family, ifindex, found, gw, gw_len, &ignored);
}

firc_err_t firc_rtnl_gateway_for_iface2(firc_rtnl_t *r, int family, int ifindex, bool *found, uint8_t *gw,
                                        uint8_t *gw_len, bool *gatewayless) {
    *found = false;
    *gatewayless = false;
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = ++r->seq;
    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
    memset(rtm, 0, sizeof(*rtm));
    rtm->rtm_family = (uint8_t)family;

    gw_ctx_t ctx = {0};
    ctx.want_oif = ifindex;

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, gw_msg_cb, &ctx);
    if (err != FIRC_OK) { return err; }
    if (code != 0) { return firc_err_from_errno(code); }

    if (ctx.found) {
        memcpy(gw, ctx.gw, ctx.gw_len);
        *gw_len = ctx.gw_len;
        *found = true;
    } else {
        *gatewayless = ctx.saw_gatewayless;
    }
    return FIRC_OK;
}

typedef struct used_set {
    uint32_t *vals;
    size_t n, cap;
} used_set_t;

static bool used_set_contains(const used_set_t *s, uint32_t v) {
    for (size_t i = 0; i < s->n; i++) {
        if (s->vals[i] == v) { return true; }
    }
    return false;
}

static void used_set_add(used_set_t *s, uint32_t v) {
    if (used_set_contains(s, v)) { return; }
    if (s->n + 1 > s->cap) {
        size_t newcap = s->cap == 0 ? 32 : s->cap * 2;
        uint32_t *tmp = realloc(s->vals, newcap * sizeof(*tmp));
        if (!tmp) { return; }
        s->vals = tmp;
        s->cap = newcap;
    }
    s->vals[s->n++] = v;
}

typedef struct scan_ctx {
    used_set_t marks;
    used_set_t tables;
} scan_ctx_t;

static void rule_scan_cb(const struct nlmsghdr *h, void *ud) {
    scan_ctx_t *ctx = ud;
    if (h->nlmsg_type != RTM_NEWRULE || !payload_at_least(h, sizeof(struct fib_rule_hdr))) { return; }
    const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(h);
    used_set_add(&ctx->tables, frh->table);

    firc_nlattr_iter_t attr_it;
    const struct nlattr *attr;
    if (!firc_nlattr_iter_init_nlmsg(&attr_it, h, sizeof(struct fib_rule_hdr))) { return; }
    while (firc_nlattr_iter_next(&attr_it, &attr)) {
        uint16_t type = mnl_attr_get_type(attr);
        if (type == FRA_FWMARK && mnl_attr_get_payload_len(attr) == 4) {
            used_set_add(&ctx->marks, *(const uint32_t *)mnl_attr_get_payload(attr));
        } else if (type == FRA_TABLE && mnl_attr_get_payload_len(attr) == 4) {
            used_set_add(&ctx->tables, *(const uint32_t *)mnl_attr_get_payload(attr));
        }
    }
}

static void route_scan_cb(const struct nlmsghdr *h, void *ud) {
    scan_ctx_t *ctx = ud;
    if (h->nlmsg_type != RTM_NEWROUTE || !payload_at_least(h, sizeof(struct rtmsg))) { return; }
    const struct rtmsg *rtm = mnl_nlmsg_get_payload(h);
    used_set_add(&ctx->tables, rtm->rtm_table);

    firc_nlattr_iter_t attr_it;
    const struct nlattr *attr;
    if (!firc_nlattr_iter_init_nlmsg(&attr_it, h, sizeof(struct rtmsg))) { return; }
    while (firc_nlattr_iter_next(&attr_it, &attr)) {
        if (mnl_attr_get_type(attr) == RTA_TABLE && mnl_attr_get_payload_len(attr) == 4) {
            used_set_add(&ctx->tables, *(const uint32_t *)mnl_attr_get_payload(attr));
        }
    }
}

static firc_err_t dump_family(firc_rtnl_t *r, uint16_t msg_type, int family,
                            void (*cb)(const struct nlmsghdr *, void *), void *ud) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = msg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
    nlh->nlmsg_seq = ++r->seq;

    if (msg_type == RTM_GETRULE) {
        struct fib_rule_hdr *frh = mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
        memset(frh, 0, sizeof(*frh));
        frh->family = (uint8_t)family;
    } else {
        struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
        memset(rtm, 0, sizeof(*rtm));
        rtm->rtm_family = (uint8_t)family;
    }

    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, cb, ud);
    if (err != FIRC_OK) { return err; }
    if (code != 0) { return firc_err_from_errno(code); }
    return FIRC_OK;
}

typedef struct stale_rule {
    int family;
    uint32_t mark, mask, table, priority;
} stale_rule_t;

typedef struct stale_ctx {
    stale_rule_t *v;
    size_t n, cap;
    int family;
    bool oom;
} stale_ctx_t;

static void stale_scan_cb(const struct nlmsghdr *h, void *ud) {
    stale_ctx_t *ctx = ud;
    if (h->nlmsg_type != RTM_NEWRULE || !payload_at_least(h, sizeof(struct fib_rule_hdr))) { return; }
    const struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(h);

    uint32_t mark = 0, mask = 0, priority = 0, table = frh->table;
    bool have_mask = false, have_priority = false;

    firc_nlattr_iter_t it;
    const struct nlattr *a;
    if (!firc_nlattr_iter_init_nlmsg(&it, h, sizeof(struct fib_rule_hdr))) { return; }
    while (firc_nlattr_iter_next(&it, &a)) {
        uint16_t t = mnl_attr_get_type(a);
        if (mnl_attr_get_payload_len(a) != 4) { continue; }
        uint32_t v = *(const uint32_t *)mnl_attr_get_payload(a);
        if (t == FRA_FWMARK) {
            mark = v;
        } else if (t == FRA_FWMASK) {
            mask = v;
            have_mask = true;
        } else if (t == FRA_PRIORITY) {
            priority = v;
            have_priority = true;
        } else if (t == FRA_TABLE) {
            table = v;
        }
    }

    /* Mask and priority together: either alone could claim a foreign rule. */
    if (!have_mask || !have_priority) { return; }
    if (mask != FIRC_MARK_GROUP_MASK) { return; }
    if (priority != FIRC_RULE_PRIORITY && priority != FIRC_RULE_PRIORITY_REPLY) { return; }

    if (ctx->n == ctx->cap) {
        size_t cap = ctx->cap ? ctx->cap * 2 : 8;
        stale_rule_t *v = realloc(ctx->v, cap * sizeof(*v));
        if (v == NULL) {
            ctx->oom = true;
            return;
        }
        ctx->v = v;
        ctx->cap = cap;
    }
    ctx->v[ctx->n++] = (stale_rule_t){ctx->family, mark, mask, table, priority};
}

firc_err_t firc_rtnl_clean_stale_rules(firc_rtnl_t *r, size_t *removed) {
    if (removed != NULL) { *removed = 0; }
    if (r == NULL) { return FIRC_ERR_INVAL; }

    stale_ctx_t ctx = {0};
    firc_err_t err = FIRC_OK;
    const int fams[2] = {AF_INET, AF_INET6};
    for (size_t i = 0; i < 2 && err == FIRC_OK; i++) {
        ctx.family = fams[i];
        err = dump_family(r, RTM_GETRULE, fams[i], stale_scan_cb, &ctx);
    }
    if (err == FIRC_OK && ctx.oom) { err = FIRC_ERR_NOMEM; }

    if (err == FIRC_OK) {
        for (size_t i = 0; i < ctx.n; i++) {
            const stale_rule_t *sr = &ctx.v[i];
            firc_err_t e = firc_rtnl_rule_del(r, sr->family, sr->mark, sr->mask, sr->table,
                                              sr->priority);
            if (e != FIRC_OK) {
                err = e;
            } else if (removed != NULL) {
                (*removed)++;
            }
        }
    }
    free(ctx.v);
    return err;
}

typedef struct {
    int family;
    uint32_t table, priority, oif; /* oif 0: none reported */
    uint8_t rtm_type, protocol, scope, dst_len;
    uint8_t dst[16];
    uint8_t gw_len; /* 0: no gateway */
    uint8_t gw[16];
} seen_route_t;

typedef struct {
    seen_route_t *v;
    size_t n, cap;
    bool oom;
} routes_ctx_t;

static void routes_scan_cb(const struct nlmsghdr *h, void *ud) {
    routes_ctx_t *ctx = ud;
    if (h->nlmsg_type != RTM_NEWROUTE || !payload_at_least(h, sizeof(struct rtmsg))) { return; }
    const struct rtmsg *rtm = mnl_nlmsg_get_payload(h);
    size_t addr_len = rtm->rtm_family == AF_INET ? 4 : rtm->rtm_family == AF_INET6 ? 16 : 0;
    if (addr_len == 0) { return; }

    seen_route_t o;
    memset(&o, 0, sizeof(o));
    o.family = rtm->rtm_family;
    o.table = rtm->rtm_table;
    o.rtm_type = rtm->rtm_type;
    o.protocol = rtm->rtm_protocol;
    o.scope = rtm->rtm_scope;
    o.dst_len = rtm->rtm_dst_len;
    firc_nlattr_iter_t it;
    const struct nlattr *a;
    if (!firc_nlattr_iter_init_nlmsg(&it, h, sizeof(struct rtmsg))) { return; }
    while (firc_nlattr_iter_next(&it, &a)) {
        uint16_t t = mnl_attr_get_type(a);
        uint16_t len = mnl_attr_get_payload_len(a);
        if (t == RTA_TABLE && len == 4) {
            o.table = *(const uint32_t *)mnl_attr_get_payload(a);
        } else if (t == RTA_PRIORITY && len == 4) {
            o.priority = *(const uint32_t *)mnl_attr_get_payload(a);
        } else if (t == RTA_DST && len == addr_len) {
            memcpy(o.dst, mnl_attr_get_payload(a), addr_len);
        } else if (t == RTA_OIF && len == 4) {
            o.oif = *(const uint32_t *)mnl_attr_get_payload(a);
        } else if (t == RTA_GATEWAY && len == addr_len) {
            memcpy(o.gw, mnl_attr_get_payload(a), addr_len);
            o.gw_len = (uint8_t)addr_len;
        }
    }
    if (ctx->n == ctx->cap) {
        size_t cap = ctx->cap ? ctx->cap * 2 : 16;
        seen_route_t *v = realloc(ctx->v, cap * sizeof(*v));
        if (v == NULL) {
            ctx->oom = true;
            return;
        }
        ctx->v = v;
        ctx->cap = cap;
    }
    ctx->v[ctx->n++] = o;
}

static firc_err_t dump_routes(firc_rtnl_t *r, routes_ctx_t *ctx) {
    firc_err_t err = dump_family(r, RTM_GETROUTE, AF_INET, routes_scan_cb, ctx);
    if (err == FIRC_OK) { err = dump_family(r, RTM_GETROUTE, AF_INET6, routes_scan_cb, ctx); }
    if (err == FIRC_OK && ctx->oom) { err = FIRC_ERR_NOMEM; }
    return err;
}

/* Names type, scope and next hop: an IPv6 delete otherwise takes the first route at the key. */
static firc_err_t del_seen_route(firc_rtnl_t *r, const seen_route_t *o, bool *deleted) {
    *deleted = false;
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = put_route_header(buf, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, ++r->seq, o->family,
                                            o->table, o->rtm_type);
    struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
    rtm->rtm_dst_len = o->dst_len;
    rtm->rtm_scope = o->scope; /* IPv4 matches the scope on a delete: as dumped, or nothing matches */
    if (o->table >= 256) { mnl_attr_put_u32(nlh, RTA_TABLE, o->table); }
    mnl_attr_put_u32(nlh, RTA_PRIORITY, o->priority);
    if (o->dst_len != 0) { mnl_attr_put(nlh, RTA_DST, o->family == AF_INET ? 4 : 16, o->dst); }
    if (o->oif != 0) { mnl_attr_put_u32(nlh, RTA_OIF, o->oif); }
    if (o->gw_len != 0) { mnl_attr_put(nlh, RTA_GATEWAY, o->gw_len, o->gw); }
    int code = 0;
    firc_err_t err = nl_execute(r, nlh, &code, NULL, NULL);
    if (err != FIRC_OK) { return err; }
    if (code == 0) {
        *deleted = true;
        return FIRC_OK;
    }
    if (code == ESRCH || code == ENOENT) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

firc_err_t firc_rtnl_purge_tagged_routes(firc_rtnl_t *r, size_t *removed, size_t *left) {
    if (removed != NULL) { *removed = 0; }
    if (left != NULL) { *left = 0; }
    if (r == NULL) { return FIRC_ERR_INVAL; }
    routes_ctx_t ctx = {0};
    firc_err_t err = dump_routes(r, &ctx);
    if (err == FIRC_OK) {
        for (size_t i = 0; i < ctx.n; i++) {
            if (ctx.v[i].protocol != FIRC_RTPROT) { continue; }
            bool deleted = false;
            firc_err_t e = del_seen_route(r, &ctx.v[i], &deleted);
            if (e != FIRC_OK) {
                err = e;
            } else if (deleted && removed != NULL) {
                (*removed)++;
            }
        }
    }
    free(ctx.v);
    routes_ctx_t after = {0};
    firc_err_t e = dump_routes(r, &after);
    if (e == FIRC_OK) {
        for (size_t i = 0; i < after.n; i++) {
            if (after.v[i].protocol == FIRC_RTPROT && left != NULL) { (*left)++; }
        }
    } else if (err == FIRC_OK) {
        err = e;
    }
    free(after.v);
    return err;
}

/* Any tagged route makes the key ours; any forwarding route makes it forwarding. */
static firc_err_t occupant_of(firc_rtnl_t *r, int family, uint32_t table, uint32_t priority, const uint8_t *dst,
                              uint8_t prefix_len, bool *found, bool *ours, uint8_t *rtm_type) {
    *found = false;
    *ours = false;
    *rtm_type = RTN_UNSPEC;
    routes_ctx_t ctx = {0};
    firc_err_t err = dump_family(r, RTM_GETROUTE, family, routes_scan_cb, &ctx);
    if (err == FIRC_OK && ctx.oom) { err = FIRC_ERR_NOMEM; }
    if (err == FIRC_OK) {
        size_t addr_len = family == AF_INET ? 4 : 16;
        for (size_t i = 0; i < ctx.n; i++) {
            const seen_route_t *o = &ctx.v[i];
            if (o->table != table || o->priority != priority || o->dst_len != prefix_len ||
                memcmp(o->dst, dst, addr_len) != 0) {
                continue;
            }
            bool forwards = o->rtm_type != RTN_UNREACHABLE && o->rtm_type != RTN_BLACKHOLE &&
                            o->rtm_type != RTN_PROHIBIT;
            if (!*found || forwards) { *rtm_type = o->rtm_type; }
            *found = true;
            if (o->protocol == FIRC_RTPROT) { *ours = true; }
        }
    }
    free(ctx.v);
    return err;
}

void firc_rtnl_forget_mark_field(firc_rtnl_t *r, const char *owner) {
    if (r == NULL || owner == NULL) { return; }
    for (size_t i = 0; i < r->n_hints; i++) {
        if (strcmp(r->hints[i].owner, owner) != 0) { continue; }
        r->hints[i] = r->hints[--r->n_hints];
        notify_fields(r);
        return;
    }
}

firc_err_t firc_rtnl_alloc_mark_field(firc_rtnl_t *r, uint32_t *out_field) {
    return firc_rtnl_alloc_mark_field_for(r, NULL, out_field);
}

firc_err_t firc_rtnl_alloc_mark_field_for(firc_rtnl_t *r, const char *owner, uint32_t *out_field) {
    scan_ctx_t ctx = {0};

    firc_err_t err = dump_family(r, RTM_GETRULE, AF_INET, rule_scan_cb, &ctx);
    if (err == FIRC_OK) { err = dump_family(r, RTM_GETRULE, AF_INET6, rule_scan_cb, &ctx); }

    if (err == FIRC_OK) {
        /* Only the group field of an existing rule's mark counts. */
        bool taken[FIRC_MARK_MAX_GROUPS + 1] = {false};
        for (size_t i = 0; i < ctx.marks.n; i++) {
            uint32_t f = (ctx.marks.vals[i] & FIRC_MARK_GROUP_MASK) >> FIRC_MARK_GROUP_SHIFT;
            if (f >= 1 && f <= FIRC_MARK_MAX_GROUPS) { taken[f] = true; }
        }
        /* Every other owner's field is reserved, live or not, so an added group cannot take it. */
        for (size_t i = 0; i < r->n_hints; i++) {
            uint32_t h = r->hints[i].field;
            if (owner != NULL && strcmp(r->hints[i].owner, owner) == 0) { continue; }
            if (h >= 1 && h <= FIRC_MARK_MAX_GROUPS) { taken[h] = true; }
        }

        uint32_t f = 0;
        uint32_t want = hint_for(r, owner);
        if (want >= 1 && want <= FIRC_MARK_MAX_GROUPS && !taken[want]) {
            f = want;
        } else {
            for (f = 1; f <= FIRC_MARK_MAX_GROUPS; f++) {
                if (!taken[f]) { break; }
            }
        }
        /* Refused, never wrapped: a wrapped field shares another group's interface. */
        if (f > FIRC_MARK_MAX_GROUPS) {
            err = FIRC_ERR_LIMIT;
        } else {
            *out_field = f;
            if (remember_hint(r, owner, f)) { notify_fields(r); }
        }
    }

    free(ctx.marks.vals);
    free(ctx.tables.vals);
    return err;
}

firc_err_t firc_rtnl_alloc_mark_table(firc_rtnl_t *r, uint32_t start_idx, uint32_t *out_idx) {
    scan_ctx_t ctx = {0};
    used_set_add(&ctx.tables, RT_TABLE_UNSPEC);
    used_set_add(&ctx.tables, 253);
    used_set_add(&ctx.tables, 254);
    used_set_add(&ctx.tables, 255);

    firc_err_t err = dump_family(r, RTM_GETRULE, AF_INET, rule_scan_cb, &ctx);
    if (err == FIRC_OK) { err = dump_family(r, RTM_GETRULE, AF_INET6, rule_scan_cb, &ctx); }
    if (err == FIRC_OK) { err = dump_family(r, RTM_GETROUTE, AF_INET, route_scan_cb, &ctx); }
    if (err == FIRC_OK) { err = dump_family(r, RTM_GETROUTE, AF_INET6, route_scan_cb, &ctx); }

    if (err == FIRC_OK) {
        uint32_t idx;
        for (idx = start_idx; idx < FIRC_RTNL_TABLE_END; idx++) {
            if (!used_set_contains(&ctx.tables, idx) && !used_set_contains(&ctx.marks, idx)) {
                break;
            }
        }
        *out_idx = idx;
    }

    free(ctx.marks.vals);
    free(ctx.tables.vals);
    return err;
}

firc_err_t firc_rtnl_seed_mark_field(firc_rtnl_t *r, const char *owner, uint32_t field) {
    if (r == NULL || owner == NULL || strlen(owner) >= sizeof(r->hints[0].owner)) { return FIRC_ERR_INVAL; }
    if (field < 1 || field > FIRC_MARK_MAX_GROUPS) { return FIRC_ERR_INVAL; }
    for (size_t i = 0; i < r->n_hints; i++) {
        if (r->hints[i].field == field || strcmp(r->hints[i].owner, owner) == 0) { return FIRC_ERR_EXIST; }
    }
    if (r->n_hints == FIRC_MARK_MAX_GROUPS) { return FIRC_ERR_LIMIT; }
    snprintf(r->hints[r->n_hints].owner, sizeof(r->hints[0].owner), "%s", owner);
    r->hints[r->n_hints].field = field;
    r->n_hints++;
    return FIRC_OK;
}

void firc_rtnl_watch_mark_fields(firc_rtnl_t *r, firc_rtnl_fields_fn fn, void *ud) {
    if (r == NULL) { return; }
    r->on_fields = fn;
    r->on_fields_ud = ud;
}

void firc_rtnl_fields_now(const firc_rtnl_t *r, firc_rtnl_fields_fn fn, void *ud) {
    if (r != NULL) { hand_fields(r, fn, ud); }
}
