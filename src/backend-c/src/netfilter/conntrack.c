#include "firc/conntrack.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "firc/log.h"
#include "firc/mark.h"
#include "firc/nlattr_iter.h"

/* Fits one dump datagram: up to ~4 KB on 3.10, 16 KB on 4.9. */
#define FIRC_CT_RECVBUF 32768
#define FIRC_CT_REQBUF 1024
/* Hits per family per flush; more returns FIRC_ERR_AGAIN. */
#define FIRC_CT_MAX_HITS 4096
/* Liveness bound: the socket blocks, and flushes run on the DNS thread. */
#define FIRC_CT_FLUSH_BUDGET_MS 1000
/* Separate budget to read an abandoned dump off the socket, or later dumps get EBUSY. */
#define FIRC_CT_DRAIN_BUDGET_MS 500

struct firc_ct {
    int fd;
    uint32_t seq;
    /* Set once a filtered dump fails and the unfiltered one works; see dump_family. */
    bool filter_refused;
    /* ms, monotonic; NULL is CLOCK_MONOTONIC. */
    int64_t (*clock_ms)(void);
};

/* The original tuple is kept verbatim: re-encoding it misses protocols like ICMP. */
#define FIRC_CT_TUPLE_MAX 128

typedef struct {
    uint8_t family;
    bool have_id;
    uint32_t id; /* CTA_ID: the kernel's handle for this entry */
    uint16_t tuple_len;
    uint8_t tuple[FIRC_CT_TUPLE_MAX]; /* a whole CTA_TUPLE_ORIG attribute */
} ct_hit_t;

typedef enum {
    SCAN_BY_MARK,
    SCAN_POOL_REPLIES,
    SCAN_STALE_MARKS,
    SCAN_CHUNK_FLOWS,
} scan_mode_t;

typedef struct {
    ct_hit_t *v;
    size_t n, cap;
    bool too_many;
    bool no_memory;
    bool tuple_too_big;
    scan_mode_t mode;
    uint32_t mark_value, mark_mask;
    const uint8_t *v4;
    uint8_t v4_len;
    const uint8_t *v6;
    uint8_t v6_len;
    const firc_ct_chunk_t *chunks;
    size_t n_chunks;
    /* Kernel-side filter: narrows what arrives; wanted() still decides. */
    bool filter_mark;
    uint32_t filter_value, filter_mask;
} scan_t;

firc_ct_t *firc_ct_open_fd(int fd) {
    firc_ct_t *ct = calloc(1, sizeof(*ct));
    if (ct == NULL) {
        close(fd);
        return NULL;
    }
    ct->fd = fd;
    return ct;
}

void firc_ct_set_clock(firc_ct_t *ct, int64_t (*clock_ms)(void)) {
    if (ct != NULL) { ct->clock_ms = clock_ms; }
}

firc_ct_t *firc_ct_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) { return NULL; }
    /* A dump is the whole table: room for it, or the kernel drops the rest. */
    int rcvbuf = 1024 * 1024;
    bool got = false;
#ifdef SO_RCVBUFFORCE /* the whole amount, past net.core.rmem_max; root only */
    got = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) == 0;
#endif
    if (!got) { (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)); }
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return NULL;
    }
    return firc_ct_open_fd(fd);
}

void firc_ct_close(firc_ct_t *ct) {
    if (ct == NULL) { return; }
    if (ct->fd >= 0) { close(ct->fd); }
    free(ct);
}

/* len 0 matches nothing: a family without a pool covers none of it. */
static bool prefix_eq(const uint8_t *a, const uint8_t *b, uint8_t len) {
    if (len == 0) { return false; }
    size_t whole = len / 8u;
    if (memcmp(a, b, whole) != 0) { return false; }
    uint8_t rest = len % 8u;
    if (rest == 0) { return true; }
    uint8_t mask = (uint8_t)(0xffu << (8u - rest));
    return (a[whole] & mask) == (b[whole] & mask);
}

static bool tuple_src(const struct nlattr *tuple, int family, uint8_t *src) {
    size_t alen = family == AF_INET ? 4u : 16u;
    uint16_t want = family == AF_INET ? CTA_IP_V4_SRC : CTA_IP_V6_SRC;
    firc_nlattr_iter_t it;
    const struct nlattr *a;
    if (!firc_nlattr_iter_init_nested(&it, tuple)) { return false; }
    while (firc_nlattr_iter_next(&it, &a)) {
        if (mnl_attr_get_type(a) != CTA_TUPLE_IP) { continue; }
        firc_nlattr_iter_t in;
        const struct nlattr *b;
        if (!firc_nlattr_iter_init_nested(&in, a)) { continue; }
        while (firc_nlattr_iter_next(&in, &b)) {
            if (mnl_attr_get_type(b) == want && mnl_attr_get_payload_len(b) == alen) {
                memcpy(src, mnl_attr_get_payload(b), alen);
                return true;
            }
        }
    }
    return false;
}

static bool tuple_dst(const struct nlattr *tuple, int family, uint8_t *dst) {
    size_t alen = family == AF_INET ? 4u : 16u;
    uint16_t want = family == AF_INET ? CTA_IP_V4_DST : CTA_IP_V6_DST;
    firc_nlattr_iter_t it;
    const struct nlattr *a;
    if (!firc_nlattr_iter_init_nested(&it, tuple)) { return false; }
    while (firc_nlattr_iter_next(&it, &a)) {
        if (mnl_attr_get_type(a) != CTA_TUPLE_IP) { continue; }
        firc_nlattr_iter_t in;
        const struct nlattr *b;
        if (!firc_nlattr_iter_init_nested(&in, a)) { continue; }
        while (firc_nlattr_iter_next(&in, &b)) {
            if (mnl_attr_get_type(b) == want && mnl_attr_get_payload_len(b) == alen) {
                memcpy(dst, mnl_attr_get_payload(b), alen);
                return true;
            }
        }
    }
    return false;
}

static bool in_pool(const scan_t *s, int family, const uint8_t *dst) {
    if (family == AF_INET) { return s->v4_len > 0 && prefix_eq(dst, s->v4, s->v4_len); }
    return s->v6_len > 0 && prefix_eq(dst, s->v6, s->v6_len);
}

static bool chunk_owner_field(const scan_t *s, int family, const uint8_t *dst, uint32_t *out, bool *inexact) {
    for (size_t i = 0; i < s->n_chunks; i++) {
        const firc_ct_chunk_t *c = &s->chunks[i];
        if (c->is_subnet || (int)c->family != family) { continue; }
        if (prefix_eq(dst, c->base, c->prefix)) {
            *out = c->field & s->mark_mask;
            *inexact = c->inexact;
            return true;
        }
    }
    return false;
}

/* Errs towards keeping: a live group with no prefix yet is invisible here. */
static bool anyone_holds(const scan_t *s, uint32_t field) {
    for (size_t i = 0; i < s->n_chunks; i++) {
        if ((s->chunks[i].field & s->mark_mask) == field) { return true; }
    }
    return false;
}

static bool holder_routes_to(const scan_t *s, int family, const uint8_t *dst, uint32_t field) {
    for (size_t i = 0; i < s->n_chunks; i++) {
        const firc_ct_chunk_t *c = &s->chunks[i];
        if (!c->is_subnet || (c->field & s->mark_mask) != field) { continue; }
        if ((int)c->family != family) { continue; }
        /* Prefix 0 covers the family; prefix_eq reads 0 as "no pool". */
        if (c->prefix == 0 || prefix_eq(dst, c->base, c->prefix)) { return true; }
    }
    return false;
}

/* True when the entry is stale; *why (optional) names the deciding branch. */
static bool mark_is_left_over(const scan_t *s, int family, const uint8_t *dst, uint32_t field,
                              const char **why) {
    const char *ignored = NULL;
    if (why == NULL) { why = &ignored; }
    if (in_pool(s, family, dst)) {
        uint32_t owner = 0;
        bool inexact = false;
        if (!chunk_owner_field(s, family, dst, &owner, &inexact)) {
            *why = "an address firc issued that no live chunk covers";
            return true;
        }
        if (owner == field) { return false; }
        if (!inexact) {
            *why = "the chunk it is addressed to belongs to a group holding another field";
            return true;
        }
        *why = "the chunk belongs to a group with a selector, and the group holding the flow's field routes "
               "nothing that covers it";
        return !holder_routes_to(s, family, dst, field);
    }
    /* Outside the pool a field nobody holds proves nothing: keep the stranger's flow. */
    if (!anyone_holds(s, field)) { return false; }
    *why = "the group holding its field routes nothing that covers it";
    return !holder_routes_to(s, family, dst, field);
}

static bool wanted(const struct nlmsghdr *h, scan_t *s, ct_hit_t *out) {
    if (mnl_nlmsg_get_payload_len(h) < sizeof(struct nfgenmsg)) { return false; }
    const struct nfgenmsg *nfg = mnl_nlmsg_get_payload(h);
    int family = nfg->nfgen_family;
    if (family != AF_INET && family != AF_INET6) { return false; }

    memset(out, 0, sizeof(*out));
    out->family = (uint8_t)family;
    bool have_mark = false;
    uint32_t mark = 0;
    const struct nlattr *reply = NULL;
    const struct nlattr *orig = NULL;
    const char *stale_why = NULL;
    uint8_t stale_dst[16] = {0};

    firc_nlattr_iter_t it;
    const struct nlattr *a;
    if (!firc_nlattr_iter_init_nlmsg(&it, h, sizeof(struct nfgenmsg))) { return false; }
    while (firc_nlattr_iter_next(&it, &a)) {
        uint16_t t = mnl_attr_get_type(a);
        if (t == CTA_MARK && mnl_attr_get_payload_len(a) == 4) {
            mark = ntohl(mnl_attr_get_u32(a));
            have_mark = true;
        } else if (t == CTA_ID && mnl_attr_get_payload_len(a) == 4) {
            out->id = ntohl(mnl_attr_get_u32(a));
            out->have_id = true;
        } else if (t == CTA_TUPLE_REPLY) {
            reply = a;
        } else if (t == CTA_TUPLE_ORIG) {
            orig = a;
        }
    }
    if ((s->mode == SCAN_BY_MARK || s->mode == SCAN_CHUNK_FLOWS) &&
        (!have_mark || (mark & s->mark_mask) != (s->mark_value & s->mark_mask))) {
        return false;
    }
    if (orig == NULL) { return false; }

    if (s->mode == SCAN_CHUNK_FLOWS) {
        uint8_t orig_dst[16] = {0};
        if (!tuple_dst(orig, family, orig_dst) || !in_pool(s, family, orig_dst)) { return false; }
    } else if (s->mode == SCAN_POOL_REPLIES) {
        /* An unbound flow replies from the fake address it was given. */
        uint8_t reply_src[16] = {0};
        if (reply == NULL || !tuple_src(reply, family, reply_src)) { return false; }
        const uint8_t *pool = family == AF_INET ? s->v4 : s->v6;
        uint8_t len = family == AF_INET ? s->v4_len : s->v6_len;
        if (pool == NULL || !prefix_eq(reply_src, pool, len)) { return false; }
    } else if (s->mode == SCAN_STALE_MARKS) {
        uint32_t field = mark & s->mark_mask;
        if (!have_mark || field == 0) { return false; }
        /* No handled bit: not ours. This keeps firmware policy marks out; the converse does not hold. */
        if ((mark & FIRC_MARK_HANDLED) == 0) { return false; }
        uint8_t orig_dst[16] = {0};
        if (!tuple_dst(orig, family, orig_dst)) { return false; }
        const char *why = "stale";
        if (!mark_is_left_over(s, family, orig_dst, field, &why)) { return false; }
        stale_why = why;
        memcpy(stale_dst, orig_dst, sizeof(stale_dst));
    }

    size_t whole = MNL_ALIGN(mnl_attr_get_len(orig));
    if (whole > FIRC_CT_TUPLE_MAX) {
        /* An overflow, not "not ours": skipping silently would leave a flow misrouted. */
        s->tuple_too_big = true;
        return false;
    }
    memcpy(out->tuple, orig, whole);
    out->tuple_len = (uint16_t)whole;
    /* Logged after the size check, so only deletions that happen are announced. */
    if (stale_why != NULL && firc_log_level() <= FIRC_LOG_DEBUG) {
        char where[INET6_ADDRSTRLEN] = "?";
        inet_ntop(family, stale_dst, where, sizeof(where));
        FIRC_DEBUG("stale mark: %s carries group field %u -- %s; deleting", where,
                   (unsigned)(mark & s->mark_mask) >> FIRC_MARK_GROUP_SHIFT, stale_why);
    }
    return true;
}

static void scan_cb(const struct nlmsghdr *h, void *ud) {
    scan_t *s = ud;
    /* CT_NEW is 0: check the subsystem too. */
    if (NFNL_SUBSYS_ID(h->nlmsg_type) != NFNL_SUBSYS_CTNETLINK) { return; }
    if ((h->nlmsg_type & 0xff) != IPCTNL_MSG_CT_NEW) { return; }
    ct_hit_t hit;
    if (!wanted(h, s, &hit)) { return; }
    if (s->n == s->cap) {
        if (s->cap >= FIRC_CT_MAX_HITS) {
            s->too_many = true;
            return;
        }
        size_t cap = s->cap ? s->cap * 2 : 32;
        ct_hit_t *v = realloc(s->v, cap * sizeof(*v));
        if (v == NULL) {
            s->no_memory = true;
            return;
        }
        s->v = v;
        s->cap = cap;
    }
    s->v[s->n++] = hit;
}

static int64_t now_ms(const firc_ct_t *ct) {
    if (ct->clock_ms != NULL) { return ct->clock_ms(); }
    struct timespec ts = {0, 0};
    /* 0 reads as "budget spent", never as an indeterminate deadline. */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int left_ms(const firc_ct_t *ct, int64_t deadline) {
    int64_t d = deadline - now_ms(ct);
    if (d <= 0) { return 0; }
    /* The clamp, not now_ms's zero, keeps a failing clock from blocking for weeks. */
    const int64_t most = FIRC_CT_FLUSH_BUDGET_MS + FIRC_CT_DRAIN_BUDGET_MS;
    if (d > most) { d = most; }
    return (int)d;
}

/* An abandoned dump blocks later dumps (EBUSY) until read to its end. */
static void drain_dump(firc_ct_t *ct, uint32_t seq) {
    uint8_t buf[FIRC_CT_RECVBUF];
    const int64_t deadline = now_ms(ct) + FIRC_CT_DRAIN_BUDGET_MS;
    for (int guard = 0; guard < 65536; guard++) {
        int wait = left_ms(ct, deadline);
        if (wait == 0) { return; }
        if (wait > 200) { wait = 200; }
        struct pollfd pfd = {.fd = ct->fd, .events = POLLIN};
        if (poll(&pfd, 1, wait) <= 0) { return; }
        ssize_t ret = recv(ct->fd, buf, sizeof(buf), MSG_TRUNC | MSG_DONTWAIT);
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

static firc_err_t ct_execute(firc_ct_t *ct, struct nlmsghdr *nlh, int *out_code,
                             void (*msg_cb)(const struct nlmsghdr *, void *), void *ud,
                             int64_t deadline) {
    *out_code = 0;
    /* Nothing is sent once the budget is spent: the dump would be left running. */
    if (left_ms(ct, deadline) == 0) { return FIRC_ERR_AGAIN; }
    if (send(ct->fd, nlh, nlh->nlmsg_len, 0) < 0) { return firc_err_from_errno(errno); }
    const uint32_t seq = nlh->nlmsg_seq;
    const bool dump = (nlh->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
    uint8_t buf[FIRC_CT_RECVBUF];
    for (;;) {
        struct pollfd pfd = {.fd = ct->fd, .events = POLLIN};
        int waited = left_ms(ct, deadline);
        int pr = poll(&pfd, 1, waited);
        if (pr == 0) {
            FIRC_WARN("conntrack did not answer within %d ms of the %d ms this flush had; what "
                      "was not read is not flushed",
                      waited, FIRC_CT_FLUSH_BUDGET_MS);
            if (dump) { drain_dump(ct, seq); }
            return FIRC_ERR_AGAIN;
        }
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            return firc_err_from_errno(errno);
        }
        ssize_t ret = recv(ct->fd, buf, sizeof(buf), MSG_TRUNC | MSG_DONTWAIT);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { continue; }
            if (errno == ENOBUFS) {
                /* The dump is still running and must be read off before the next. */
                FIRC_WARN("the conntrack table overran this socket; some flows were not looked at");
                if (dump) { drain_dump(ct, seq); }
                return FIRC_ERR_AGAIN;
            }
            return firc_err_from_errno(errno);
        }
        if ((size_t)ret > sizeof(buf)) {
            if (dump) { drain_dump(ct, seq); }
            return FIRC_ERR_LIMIT;
        }
        if (ret == 0) { return FIRC_ERR_IO; }
        int len = (int)ret;
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        bool done = false, ours = false;
        while (mnl_nlmsg_ok(h, len)) {
            if (h->nlmsg_seq != seq) {
                h = mnl_nlmsg_next(h, &len);
                continue;
            }
            ours = true;
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (mnl_nlmsg_get_payload_len(h) < sizeof(struct nlmsgerr)) { return FIRC_ERR_PROTO; }
                const struct nlmsgerr *e = mnl_nlmsg_get_payload(h);
                *out_code = e->error < 0 ? -e->error : e->error;
                done = true;
                break;
            }
            if (h->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (msg_cb) { msg_cb(h, ud); }
            h = mnl_nlmsg_next(h, &len);
        }
        if (done) { break; }
        if (!dump && ours) { break; }
    }
    return FIRC_OK;
}

static firc_err_t dump_family(firc_ct_t *ct, int family, scan_t *s, int64_t deadline) {
    /* Bounded by the loop, not the flag: a missed flag must not recurse. */
    bool retried_unfiltered = false;
    for (int attempt = 0; attempt < 2; attempt++) {
        bool asked = s->filter_mark && !ct->filter_refused && !retried_unfiltered;

        uint8_t buf[FIRC_CT_REQBUF];
        memset(buf, 0, sizeof(buf));
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
        nlh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET);
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        nlh->nlmsg_seq = ++ct->seq;
        struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
        nfg->nfgen_family = (uint8_t)family;
        nfg->version = NFNETLINK_V0;
        nfg->res_id = 0;
        if (asked) {
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(s->filter_value));
            mnl_attr_put_u32(nlh, CTA_MARK_MASK, htonl(s->filter_mask));
        }

        int code = 0;
        firc_err_t err = ct_execute(ct, nlh, &code, scan_cb, s, deadline);
        if (err != FIRC_OK) { return err; }
        if (code == 0) {
            /* Armed only after the unfiltered read worked. */
            if (retried_unfiltered) { ct->filter_refused = true; }
            return FIRC_OK;
        }
        if (!asked) { return firc_err_from_errno(code); }
        /* EOPNOTSUPP only: EINVAL means the module is not loaded yet on 3.4/3.10; others are refusals. */
        if (code != EOPNOTSUPP) {
            return firc_err_from_errno(code);
        }

        /* Filter refused: drop what arrived and read unfiltered, or a refusal reads as an empty table. */
        FIRC_WARN("this kernel refuses a conntrack dump filtered by mark (%s); reading the whole "
                  "table instead",
                  strerror(code));
        s->n = 0;
        s->too_many = false;
        s->no_memory = false;
        s->tuple_too_big = false;
        retried_unfiltered = true;
    }
    /* Unreachable: the second pass has `asked` false. */
    return FIRC_ERR_IO;
}

/* Named by the verbatim original tuple plus CTA_ID, so a new flow on the same tuple is spared. */
static firc_err_t delete_hit(firc_ct_t *ct, const ct_hit_t *hit, bool *deleted,
                             int64_t deadline) {
    *deleted = false;
    uint8_t buf[FIRC_CT_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++ct->seq;
    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = hit->family;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;
    if (nlh->nlmsg_len + hit->tuple_len > FIRC_CT_REQBUF) { return FIRC_ERR_LIMIT; }
    memcpy(mnl_nlmsg_get_payload_tail(nlh), hit->tuple, hit->tuple_len);
    nlh->nlmsg_len += hit->tuple_len;
    if (hit->have_id) { mnl_attr_put_u32(nlh, CTA_ID, htonl(hit->id)); }

    int code = 0;
    firc_err_t err = ct_execute(ct, nlh, &code, NULL, NULL, deadline);
    if (err != FIRC_OK) { return err; }
    if (code == 0) {
        *deleted = true;
        return FIRC_OK;
    }
    if (code == ENOENT || code == ESRCH) { return FIRC_OK; }
    return firc_err_from_errno(code);
}

/* A refusal never discards work: other entries and families go on; the first error is returned. */
static firc_err_t flush(firc_ct_t *ct, scan_t *s, size_t *deleted) {
    if (deleted != NULL) { *deleted = 0; }
    if (ct == NULL) { return FIRC_ERR_INVAL; }
    /* One budget for the whole flush, not per dump. */
    const int64_t deadline = now_ms(ct) + FIRC_CT_FLUSH_BUDGET_MS;
    firc_err_t err = FIRC_OK;
    size_t gone = 0;
    /* Repair each family before dumping the next, so a flush out of time has done work. */
    size_t found = 0;
    const int families[2] = {AF_INET, AF_INET6};
    for (int fi = 0; fi < 2; fi++) {
        firc_err_t e = dump_family(ct, families[fi], s, deadline);
        if (e != FIRC_OK && err == FIRC_OK) { err = e; }
        for (size_t i = 0; i < s->n; i++) {
            bool one = false;
            firc_err_t de = delete_hit(ct, &s->v[i], &one, deadline);
            if (de != FIRC_OK) {
                if (err == FIRC_OK) { err = de; }
            } else if (one) {
                gone++;
            }
        }
        found += s->n;
        /* Emptied per family, or a full array rejects the next family's hits. */
        s->n = 0;
    }
    if (deleted != NULL) { *deleted = gone; }
    if (s->tuple_too_big) {
        FIRC_WARN("a conntrack entry's original tuple was larger than %d bytes and could not be "
                  "named back to the kernel; that flow is left steering as it was",
                  FIRC_CT_TUPLE_MAX);
    }
    if (s->too_many) {
        FIRC_WARN("more than %d conntrack entries matched at once; the rest are left for another "
                  "pass", FIRC_CT_MAX_HITS);
    }
    if (s->no_memory) {
        FIRC_WARN("not enough memory to hold what matched in conntrack; the rest are left for "
                  "another pass");
    }
    /* Stopping early is AGAIN; an oversized tuple is not, since it stays unnameable. */
    if ((s->too_many || s->no_memory) && err == FIRC_OK) { err = FIRC_ERR_AGAIN; }
    if (gone != found) {
        FIRC_DEBUG("conntrack flush: %zu entries matched, %zu deleted", found, gone);
    }
    free(s->v);
    return err;
}

firc_err_t firc_ct_flush_by_mark(firc_ct_t *ct, uint32_t value, uint32_t mask, size_t *deleted) {
    scan_t s = {0};
    s.mode = SCAN_BY_MARK;
    s.mark_value = value;
    s.mark_mask = mask;
    s.filter_mark = true;
    /* Masked here: the kernel tests (ct->mark & mask) == value without masking value. */
    s.filter_value = value & mask;
    s.filter_mask = mask;
    return flush(ct, &s, deleted);
}

firc_err_t firc_ct_flush_pool_replies(firc_ct_t *ct, const uint8_t v4[4], uint8_t v4_len, const uint8_t v6[16],
                                      uint8_t v6_len, size_t *deleted) {
    scan_t s = {0};
    s.mode = SCAN_POOL_REPLIES;
    /* No mark filter: flows born while a full pass has our chains down carry no mark. */
    s.v4 = v4;
    s.v4_len = v4_len;
    s.v6 = v6;
    s.v6_len = v6_len;
    return flush(ct, &s, deleted);
}

firc_err_t firc_ct_flush_group_chunk_flows(firc_ct_t *ct, uint32_t value, const uint8_t v4[4], uint8_t v4_len,
                                           const uint8_t v6[16], uint8_t v6_len, size_t *deleted) {
    scan_t s = {0};
    s.mode = SCAN_CHUNK_FLOWS;
    /* Handled bit in value and mask: the field alone would take firmware-policy flows. */
    s.mark_value = value | FIRC_MARK_HANDLED;
    s.mark_mask = FIRC_MARK_GROUP_MASK | FIRC_MARK_HANDLED;
    s.filter_mark = true;
    s.filter_value = s.mark_value & s.mark_mask;
    s.filter_mask = s.mark_mask;
    s.v4 = v4;
    s.v4_len = v4_len;
    s.v6 = v6;
    s.v6_len = v6_len;
    return flush(ct, &s, deleted);
}

firc_err_t firc_ct_flush_stale_group_marks(firc_ct_t *ct, const uint8_t v4[4], uint8_t v4_len,
                                           const uint8_t v6[16], uint8_t v6_len,
                                           const firc_ct_chunk_t *chunks, size_t n_chunks,
                                           uint32_t mask, size_t *deleted) {
    scan_t s = {0};
    s.mode = SCAN_STALE_MARKS;
    s.mark_mask = mask;
    /* The handled bit as value and mask: this also keeps firmware policy marks out. */
    s.filter_mark = true;
    s.filter_value = FIRC_MARK_HANDLED;
    s.filter_mask = FIRC_MARK_HANDLED;
    s.v4 = v4;
    s.v4_len = v4_len;
    s.v6 = v6;
    s.v6_len = v6_len;
    s.chunks = chunks;
    s.n_chunks = n_chunks;
    return flush(ct, &s, deleted);
}
