#include "fake_conntrack.h"

#include <assert.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>

#include "firc/nlattr_iter.h"
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/sockios.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#define FAKE_CT_MAX 4200

typedef struct {
    int family;
    uint8_t orig_src[16], orig_dst[16], reply_src[16];
    uint32_t mark;
    bool icmp;
    bool gone;
    uint32_t id;
} fake_entry_t;

struct fake_ct {
    int fd;
    int peer_fd;
    pthread_t th;
    pthread_mutex_t mu;
    fake_entry_t v[FAKE_CT_MAX];
    size_t n;
    size_t deletes;
    size_t dumps;
    bool silent;
    int dump_delay_ms;
    bool saw_mark_filter;
    bool ignore_filter;
    int reject_filter_err;
    uint32_t filter_mark, filter_mask;
    bool silent_deletes;
    uint8_t deleted_reply[FAKE_CT_MAX][16];
    size_t n_deleted;
    int dump_err;
    int dump_err_family;
    int dump_err_of;
    int delete_err;
    size_t dump_padding;
    uint32_t next_id;
    bool recreate_on_delete;
};

static size_t addr_len(int family) { return family == AF_INET ? 4u : 16u; }

/* One entry as ctnetlink reports it: the two tuples nested, the mark beside them. */
static void put_entry(struct nlmsghdr *nlh, const fake_entry_t *e) {
    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = (uint8_t)e->family;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;
    size_t alen = addr_len(e->family);
    uint16_t ipa = e->family == AF_INET ? CTA_IP_V4_SRC : CTA_IP_V6_SRC;
    uint16_t ipb = e->family == AF_INET ? CTA_IP_V4_DST : CTA_IP_V6_DST;

    struct nlattr *orig = mnl_attr_nest_start(nlh, CTA_TUPLE_ORIG);
    struct nlattr *oip = mnl_attr_nest_start(nlh, CTA_TUPLE_IP);
    mnl_attr_put(nlh, ipa, (uint16_t)alen, e->orig_src);
    mnl_attr_put(nlh, ipb, (uint16_t)alen, e->orig_dst);
    mnl_attr_nest_end(nlh, oip);
    struct nlattr *op = mnl_attr_nest_start(nlh, CTA_TUPLE_PROTO);
    if (e->icmp) {
        mnl_attr_put_u8(nlh, CTA_PROTO_NUM, IPPROTO_ICMP);
        mnl_attr_put_u16(nlh, CTA_PROTO_ICMP_ID, htons((uint16_t)4242));
        mnl_attr_put_u8(nlh, CTA_PROTO_ICMP_TYPE, 8);
        mnl_attr_put_u8(nlh, CTA_PROTO_ICMP_CODE, 0);
    } else {
        mnl_attr_put_u8(nlh, CTA_PROTO_NUM, IPPROTO_TCP);
        mnl_attr_put_u16(nlh, CTA_PROTO_SRC_PORT, htons((uint16_t)12345));
        mnl_attr_put_u16(nlh, CTA_PROTO_DST_PORT, htons((uint16_t)443));
    }
    mnl_attr_nest_end(nlh, op);
    mnl_attr_nest_end(nlh, orig);

    struct nlattr *rep = mnl_attr_nest_start(nlh, CTA_TUPLE_REPLY);
    struct nlattr *rip = mnl_attr_nest_start(nlh, CTA_TUPLE_IP);
    mnl_attr_put(nlh, ipa, (uint16_t)alen, e->reply_src);
    mnl_attr_put(nlh, ipb, (uint16_t)alen, e->orig_src);
    mnl_attr_nest_end(nlh, rip);
    struct nlattr *rp = mnl_attr_nest_start(nlh, CTA_TUPLE_PROTO);
    mnl_attr_put_u8(nlh, CTA_PROTO_NUM, IPPROTO_TCP);
    mnl_attr_put_u16(nlh, CTA_PROTO_SRC_PORT, htons((uint16_t)443));
    mnl_attr_put_u16(nlh, CTA_PROTO_DST_PORT, htons((uint16_t)12345));
    mnl_attr_nest_end(nlh, rp);
    mnl_attr_nest_end(nlh, rep);

    mnl_attr_put_u32(nlh, CTA_MARK, htonl(e->mark));
    mnl_attr_put_u32(nlh, CTA_ID, htonl(e->id));
}

static void reply_to(struct fake_ct *f, const void *buf, size_t len) {
    (void)send(f->fd, buf, len, MSG_NOSIGNAL);
}

static void put_ack(struct fake_ct *f, const struct nlmsghdr *req, int err) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = NLMSG_ERROR;
    nlh->nlmsg_seq = req->nlmsg_seq;
    struct nlmsgerr *e = mnl_nlmsg_put_extra_header(nlh, sizeof(*e));
    e->error = -err;
    e->msg = *req;
    reply_to(f, buf, nlh->nlmsg_len);
}

/* The stored entry a delete names, matched on either tuple as the kernel does. */
static fake_entry_t *entry_named_by(struct fake_ct *f, const struct nlmsghdr *h, uint8_t *reply_out) {
    const struct nfgenmsg *nfg = mnl_nlmsg_get_payload(h);
    int family = nfg->nfgen_family;
    size_t alen = addr_len(family);
    uint16_t want_src = family == AF_INET ? CTA_IP_V4_SRC : CTA_IP_V6_SRC;
    uint16_t want_dst = family == AF_INET ? CTA_IP_V4_DST : CTA_IP_V6_DST;
    uint8_t src[16] = {0}, dst[16] = {0};
    bool reply_side = false, have = false;

    firc_nlattr_iter_t it;
    const struct nlattr *a;
    if (!firc_nlattr_iter_init_nlmsg(&it, h, sizeof(struct nfgenmsg))) { return NULL; }
    while (firc_nlattr_iter_next(&it, &a)) {
        uint16_t t = mnl_attr_get_type(a);
        if (t != CTA_TUPLE_ORIG && t != CTA_TUPLE_REPLY) { continue; }
        reply_side = t == CTA_TUPLE_REPLY;
        firc_nlattr_iter_t t1;
        const struct nlattr *b;
        if (!firc_nlattr_iter_init_nested(&t1, a)) { continue; }
        while (firc_nlattr_iter_next(&t1, &b)) {
            if (mnl_attr_get_type(b) != CTA_TUPLE_IP) { continue; }
            firc_nlattr_iter_t t2;
            const struct nlattr *c;
            if (!firc_nlattr_iter_init_nested(&t2, b)) { continue; }
            while (firc_nlattr_iter_next(&t2, &c)) {
                uint16_t ct = mnl_attr_get_type(c);
                if (mnl_attr_get_payload_len(c) != alen) { continue; }
                if (ct == want_src) {
                    memcpy(src, mnl_attr_get_payload(c), alen);
                    have = true;
                } else if (ct == want_dst) {
                    memcpy(dst, mnl_attr_get_payload(c), alen);
                }
            }
        }
    }
    uint32_t want_id = 0;
    bool have_id = false;
    firc_nlattr_iter_t top;
    const struct nlattr *ta;
    if (firc_nlattr_iter_init_nlmsg(&top, h, sizeof(struct nfgenmsg))) {
        while (firc_nlattr_iter_next(&top, &ta)) {
            if (mnl_attr_get_type(ta) == CTA_ID && mnl_attr_get_payload_len(ta) == 4) {
                want_id = ntohl(mnl_attr_get_u32(ta));
                have_id = true;
            }
        }
    }
    if (!have) { return NULL; }
    bool req_icmp = false;
    firc_nlattr_iter_t pit;
    const struct nlattr *pa;
    if (firc_nlattr_iter_init_nlmsg(&pit, h, sizeof(struct nfgenmsg))) {
        while (firc_nlattr_iter_next(&pit, &pa)) {
            uint16_t t = mnl_attr_get_type(pa);
            if (t != CTA_TUPLE_ORIG && t != CTA_TUPLE_REPLY) { continue; }
            firc_nlattr_iter_t t1;
            const struct nlattr *b;
            if (!firc_nlattr_iter_init_nested(&t1, pa)) { continue; }
            while (firc_nlattr_iter_next(&t1, &b)) {
                if (mnl_attr_get_type(b) != CTA_TUPLE_PROTO) { continue; }
                firc_nlattr_iter_t t2;
                const struct nlattr *c;
                if (!firc_nlattr_iter_init_nested(&t2, b)) { continue; }
                while (firc_nlattr_iter_next(&t2, &c)) {
                    if (mnl_attr_get_type(c) == CTA_PROTO_ICMP_ID) { req_icmp = true; }
                }
            }
        }
    }
    for (size_t i = 0; i < f->n; i++) {
        fake_entry_t *e = &f->v[i];
        if (e->gone || e->family != family) { continue; }
        const uint8_t *want_a = reply_side ? e->reply_src : e->orig_src;
        const uint8_t *want_b = reply_side ? e->orig_src : e->orig_dst;
        if (e->icmp != req_icmp) { continue; }
        if (memcmp(want_a, src, alen) == 0 && memcmp(want_b, dst, alen) == 0) {
            if (have_id && want_id != e->id) { continue; }
            if (reply_out != NULL) { memcpy(reply_out, e->reply_src, 16); }
            return e;
        }
    }
    return NULL;
}

static void answer(struct fake_ct *f, const struct nlmsghdr *req) {
    uint8_t type = (uint8_t)(req->nlmsg_type & 0xff);
    if ((req->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP) {
        pthread_mutex_lock(&f->mu);
        f->dumps++;
        bool silent = f->silent;
        int delay = f->dump_delay_ms;
        pthread_mutex_unlock(&f->mu);
        if (delay > 0) {
            struct timespec ts = {.tv_sec = delay / 1000, .tv_nsec = (long)(delay % 1000) * 1000000L};
            nanosleep(&ts, NULL);
        }
        if (silent) { return; }
        int want_family = AF_UNSPEC;
        if (mnl_nlmsg_get_payload_len(req) >= sizeof(struct nfgenmsg)) {
            const struct nfgenmsg *want = mnl_nlmsg_get_payload(req);
            want_family = want->nfgen_family;
        }
        bool f_mark = false;
        uint32_t f_val = 0, f_mask = 0;
        {
            const struct nlattr *a = mnl_nlmsg_get_payload_offset(req, sizeof(struct nfgenmsg));
            const char *tail = (const char *)mnl_nlmsg_get_payload_tail(req);
            while (mnl_attr_ok(a, (int)(tail - (const char *)a))) {
                uint16_t t = mnl_attr_get_type(a);
                if (t == CTA_MARK && mnl_attr_get_payload_len(a) == 4) {
                    f_val = ntohl(mnl_attr_get_u32(a));
                    f_mark = true;
                } else if (t == CTA_MARK_MASK && mnl_attr_get_payload_len(a) == 4) {
                    f_mask = ntohl(mnl_attr_get_u32(a));
                }
                a = mnl_attr_next(a);
            }
        }
        pthread_mutex_lock(&f->mu);
        f->saw_mark_filter = f_mark;
        f->filter_mark = f_val;
        f->filter_mask = f_mask;
        bool ignoring = f->ignore_filter;
        int reject = f->reject_filter_err;
        pthread_mutex_unlock(&f->mu);
        if (f_mark && reject != 0) {
            put_ack(f, req, reject);
            return;
        }
        pthread_mutex_lock(&f->mu);
        if (f->dump_err != 0) {
            int err = f->dump_err;
            f->dump_err = 0;
            pthread_mutex_unlock(&f->mu);
            put_ack(f, req, err);
            return;
        }
        if (f->dump_err_of != 0 && f->dump_err_family == want_family) {
            int err = f->dump_err_of;
            f->dump_err_of = 0;
            pthread_mutex_unlock(&f->mu);
            put_ack(f, req, err);
            return;
        }
        static uint8_t buf[131072];
        static uint8_t pad[49152];
        bool first = true;
        for (size_t i = 0; i < f->n; i++) {
            if (f->v[i].gone) { continue; }
            if (want_family != AF_UNSPEC && f->v[i].family != want_family) { continue; }
            if (f_mark && !ignoring && (f->v[i].mark & f_mask) != f_val) { continue; }
            memset(buf, 0, sizeof(buf));
            struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
            nlh->nlmsg_type = (uint16_t)((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW);
            nlh->nlmsg_flags = NLM_F_MULTI;
            nlh->nlmsg_seq = req->nlmsg_seq;
            put_entry(nlh, &f->v[i]);
            if (first && f->dump_padding > 0 && f->dump_padding <= sizeof(pad)) {
                memset(pad, 0, f->dump_padding);
                mnl_attr_put(nlh, CTA_UNSPEC, f->dump_padding, pad);
            }
            first = false;
            reply_to(f, buf, nlh->nlmsg_len);
        }
        pthread_mutex_unlock(&f->mu);
        uint8_t dbuf[128];
        memset(dbuf, 0, sizeof(dbuf));
        struct nlmsghdr *done = mnl_nlmsg_put_header(dbuf);
        done->nlmsg_type = NLMSG_DONE;
        done->nlmsg_flags = NLM_F_MULTI;
        done->nlmsg_seq = req->nlmsg_seq;
        mnl_nlmsg_put_extra_header(done, sizeof(int));
        reply_to(f, dbuf, done->nlmsg_len);
        return;
    }
    if (type == IPCTNL_MSG_CT_DELETE) {
        pthread_mutex_lock(&f->mu);
        if (f->silent_deletes) {
            f->deletes++;
            pthread_mutex_unlock(&f->mu);
            return;
        }
        if (f->recreate_on_delete) {
            f->recreate_on_delete = false;
            for (size_t i = 0; i < f->n; i++) { f->v[i].id = ++f->next_id; }
        }
        f->deletes++;
        uint8_t reply[16] = {0};
        fake_entry_t *e = entry_named_by(f, req, reply);
        int err = f->delete_err;
        if (err != 0) {
            f->delete_err = 0;
        } else if (e != NULL) {
            e->gone = true;
            if (f->n_deleted < FAKE_CT_MAX) { memcpy(f->deleted_reply[f->n_deleted++], reply, 16); }
        } else {
            err = ENOENT;
        }
        pthread_mutex_unlock(&f->mu);
        put_ack(f, req, err);
        return;
    }
    put_ack(f, req, EOPNOTSUPP);
}

static void *kernel_main(void *ud) {
    struct fake_ct *f = ud;
    uint8_t buf[8192];
    for (;;) {
        ssize_t got = recv(f->fd, buf, sizeof(buf), 0);
        if (got <= 0) { break; }
        int len = (int)got;
        const struct nlmsghdr *h = (const struct nlmsghdr *)buf;
        while (mnl_nlmsg_ok(h, len)) {
            answer(f, h);
            h = mnl_nlmsg_next(h, &len);
        }
    }
    return NULL;
}

fake_ct_t *fake_ct_start(firc_ct_t **out) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) { return NULL; }
    struct fake_ct *f = calloc(1, sizeof(*f));
    if (f == NULL) {
        close(sv[0]);
        close(sv[1]);
        return NULL;
    }
    f->fd = sv[0];
    f->peer_fd = sv[1];
    pthread_mutex_init(&f->mu, NULL);
    *out = firc_ct_open_fd(sv[1]);
    if (*out == NULL || pthread_create(&f->th, NULL, kernel_main, f) != 0) {
        firc_ct_close(*out);
        *out = NULL;
        close(sv[0]);
        free(f);
        return NULL;
    }
    return f;
}

void fake_ct_stop(fake_ct_t *f) {
    if (f == NULL) { return; }
    shutdown(f->fd, SHUT_RDWR);
    pthread_join(f->th, NULL);
    close(f->fd);
    pthread_mutex_destroy(&f->mu);
    free(f);
}

void fake_ct_add(fake_ct_t *f, int family, const uint8_t *orig_src, const uint8_t *orig_dst,
                 const uint8_t *reply_src, uint32_t mark) {
    pthread_mutex_lock(&f->mu);
    assert(f->n < FAKE_CT_MAX);
    fake_entry_t *e = &f->v[f->n++];
    memset(e, 0, sizeof(*e));
    e->family = family;
    size_t alen = addr_len(family);
    memcpy(e->orig_src, orig_src, alen);
    memcpy(e->orig_dst, orig_dst, alen);
    memcpy(e->reply_src, reply_src, alen);
    e->mark = mark;
    e->id = ++f->next_id;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_last_is_icmp(fake_ct_t *f) {
    pthread_mutex_lock(&f->mu);
    if (f->n > 0) { f->v[f->n - 1].icmp = true; }
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_recreate_on_next_delete(fake_ct_t *f) {
    pthread_mutex_lock(&f->mu);
    f->recreate_on_delete = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_fail_dump_of(fake_ct_t *f, int family, int err) {
    pthread_mutex_lock(&f->mu);
    f->dump_err_family = family;
    f->dump_err_of = err;
    pthread_mutex_unlock(&f->mu);
}

size_t fake_ct_unread(fake_ct_t *f) {
    int n = 0;
    if (ioctl(f->peer_fd, SIOCINQ, &n) != 0 || n < 0) { return 0; }
    return (size_t)n;
}

void fake_ct_set_dump_padding(fake_ct_t *f, size_t bytes) {
    pthread_mutex_lock(&f->mu);
    f->dump_padding = bytes;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_fail_next_dump(fake_ct_t *f, int err) {
    pthread_mutex_lock(&f->mu);
    f->dump_err = err;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_fail_next_delete(fake_ct_t *f, int err) {
    pthread_mutex_lock(&f->mu);
    f->delete_err = err;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_never_answer_deletes(fake_ct_t *f) {
    pthread_mutex_lock(&f->mu);
    f->silent_deletes = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_delay_dumps(fake_ct_t *f, int ms) {
    pthread_mutex_lock(&f->mu);
    f->dump_delay_ms = ms;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_reject_mark_filter(fake_ct_t *f, int err) {
    pthread_mutex_lock(&f->mu);
    f->reject_filter_err = err;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_ignore_mark_filter(fake_ct_t *f) {
    pthread_mutex_lock(&f->mu);
    f->ignore_filter = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_ct_never_answer_dumps(fake_ct_t *f) {
    pthread_mutex_lock(&f->mu);
    f->silent = true;
    pthread_mutex_unlock(&f->mu);
}

bool fake_ct_dump_filtered_on_mark(fake_ct_t *f, uint32_t *value, uint32_t *mask) {
    pthread_mutex_lock(&f->mu);
    bool saw = f->saw_mark_filter;
    if (value != NULL) { *value = f->filter_mark; }
    if (mask != NULL) { *mask = f->filter_mask; }
    pthread_mutex_unlock(&f->mu);
    return saw;
}

size_t fake_ct_dumps(fake_ct_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->dumps;
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t fake_ct_deletes(fake_ct_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->deletes;
    pthread_mutex_unlock(&f->mu);
    return n;
}

bool fake_ct_deleted(fake_ct_t *f, const uint8_t *reply_src, size_t len) {
    pthread_mutex_lock(&f->mu);
    bool found = false;
    for (size_t i = 0; i < f->n_deleted && !found; i++) {
        found = memcmp(f->deleted_reply[i], reply_src, len) == 0;
    }
    pthread_mutex_unlock(&f->mu);
    return found;
}

size_t fake_ct_remaining(fake_ct_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = 0;
    for (size_t i = 0; i < f->n; i++) {
        if (!f->v[i].gone) { n++; }
    }
    pthread_mutex_unlock(&f->mu);
    return n;
}
