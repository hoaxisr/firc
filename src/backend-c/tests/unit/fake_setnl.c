#include "fake_setnl.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_hash.h>
#include <linux/netfilter/nfnetlink.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define FAKE_SETNL_MAX_SETS 64
#define FAKE_SETNL_RECV 65536
#define FAKE_SETNL_GATE_MS 5000

typedef struct {
    uint8_t cidr;
    uint8_t addr[16];
} member_t;

typedef struct {
    bool used;
    char name[IPSET_MAXNAMELEN];
    char type[IPSET_MAXNAMELEN];
    uint8_t family;
    uint8_t revision;
    uint32_t maxelem;
    uint32_t hashsize;
    bool referenced;
    member_t *m;
    size_t n, cap;
    uint32_t *slots;
    size_t n_slots;
} set_t;

typedef struct {
    uint8_t *data;
    size_t len;
} datagram_t;

struct fake_setnl {
    int fd;
    pthread_t th;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    set_t sets[FAKE_SETNL_MAX_SETS];
    uint8_t rev4, rev6;
    bool no_type;
    bool no_subsystem;
    bool silent;
    bool hold;
    bool stopping;
    size_t fail_nth;
    int fail_err;
    size_t fail_nth2;
    int fail_err2;
    size_t adds_seen;
    void (*step)(const char *, const char *, void *);
    void *step_ud;
    size_t messages, sends, largest;
    datagram_t last[16];
    uint8_t **old;
    size_t n_old, cap_old;
    bool inject;
    uint8_t inject_cmd;
    int inject_err;
    bool inject_apply;
    uint8_t *rbuf;
    uint8_t lbuf[16384];
};

static size_t alen_of(uint8_t nfproto) { return nfproto == NFPROTO_IPV4 ? 4u : 16u; }

static uint8_t nfproto_of(uint8_t family) { return family == 4 ? NFPROTO_IPV4 : NFPROTO_IPV6; }

static void mask(member_t *m, uint8_t nfproto) {
    size_t alen = alen_of(nfproto);
    for (size_t i = 0; i < 16; i++) {
        size_t bit = i * 8;
        if (i >= alen || bit >= m->cidr) {
            m->addr[i] = 0;
        } else if (m->cidr - bit < 8) {
            m->addr[i] &= (uint8_t)(0xffu << (8u - (m->cidr - bit)));
        }
    }
}

static uint32_t hash_of(const member_t *m) {
    uint32_t h = 2166136261u ^ m->cidr;
    for (size_t i = 0; i < 16; i++) { h = (h ^ m->addr[i]) * 16777619u; }
    return h;
}

static set_t *find(struct fake_setnl *f, const char *name) {
    for (size_t i = 0; i < FAKE_SETNL_MAX_SETS; i++) {
        if (f->sets[i].used && strcmp(f->sets[i].name, name) == 0) { return &f->sets[i]; }
    }
    return NULL;
}

static void drop(set_t *s) {
    free(s->m);
    free(s->slots);
    memset(s, 0, sizeof(*s));
}

static set_t *make(struct fake_setnl *f, const char *name) {
    for (size_t i = 0; i < FAKE_SETNL_MAX_SETS; i++) {
        if (!f->sets[i].used) {
            memset(&f->sets[i], 0, sizeof(f->sets[i]));
            f->sets[i].used = true;
            snprintf(f->sets[i].name, sizeof(f->sets[i].name), "%s", name);
            return &f->sets[i];
        }
    }
    return NULL;
}

static long slot_of(const set_t *s, const member_t *m) {
    if (s->n_slots == 0) { return -1; }
    size_t i = hash_of(m) & (s->n_slots - 1);
    for (;;) {
        uint32_t v = s->slots[i];
        if (v == 0) { return -(long)i - 2; }
        const member_t *o = &s->m[v - 1];
        if (o->cidr == m->cidr && memcmp(o->addr, m->addr, 16) == 0) { return (long)i; }
        i = (i + 1) & (s->n_slots - 1);
    }
}

static void reindex(set_t *s, size_t want) {
    free(s->slots);
    s->n_slots = want;
    s->slots = calloc(want, sizeof(*s->slots));
    for (size_t k = 0; k < s->n; k++) {
        long r = slot_of(s, &s->m[k]);
        s->slots[-r - 2] = (uint32_t)(k + 1);
    }
}

static int insert(set_t *s, const member_t *m) {
    if (slot_of(s, m) >= 0) { return 0; }
    if (s->n >= s->maxelem) { return IPSET_ERR_HASH_FULL; }
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 64;
        member_t *m2 = realloc(s->m, s->cap * sizeof(*s->m));
        if (m2 == NULL) { abort(); }
        s->m = m2;
    }
    s->m[s->n++] = *m;
    if (s->n * 2 > s->n_slots) {
        reindex(s, s->n_slots ? s->n_slots * 4 : 256);
    } else {
        long r = slot_of(s, m);
        s->slots[-r - 2] = (uint32_t)s->n;
    }
    return 0;
}

static void reply(struct fake_setnl *f, const void *buf, size_t len) { (void)send(f->fd, buf, len, MSG_NOSIGNAL); }

static void ack(struct fake_setnl *f, const struct nlmsghdr *req, int err) {
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = NLMSG_ERROR;
    nlh->nlmsg_seq = req->nlmsg_seq;
    struct nlmsgerr *e = mnl_nlmsg_put_extra_header(nlh, sizeof(*e));
    e->error = -err;
    e->msg = *req;
    reply(f, buf, nlh->nlmsg_len);
}

static struct nlmsghdr *start_msg(uint8_t *buf, const struct nlmsghdr *req, uint8_t cmd, uint16_t flags) {
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (uint16_t)((unsigned)(NFNL_SUBSYS_IPSET << 8) | (unsigned)cmd);
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = req->nlmsg_seq;
    struct nfgenmsg *g = mnl_nlmsg_put_extra_header(nlh, sizeof(*g));
    g->nfgen_family = NFPROTO_IPV4;
    g->version = NFNETLINK_V0;
    mnl_attr_put_u8(nlh, IPSET_ATTR_PROTOCOL, 6);
    return nlh;
}

static bool parse(const struct nlattr *nest, const struct nlmsghdr *h, const struct nlattr **tb, size_t max) {
    for (size_t i = 0; i <= max; i++) { tb[i] = NULL; }
    const struct nlattr *a;
    int left;
    if (nest != NULL) {
        a = mnl_attr_get_payload(nest);
        left = (int)mnl_attr_get_payload_len(nest);
    } else {
        a = mnl_nlmsg_get_payload_offset(h, sizeof(struct nfgenmsg));
        left = (int)((const char *)mnl_nlmsg_get_payload_tail(h) - (const char *)a);
    }
    while (left > 0) {
        if (!mnl_attr_ok(a, left)) { return false; }
        uint16_t t = mnl_attr_get_type(a);
        if (t <= max) { tb[t] = a; }
        left -= (int)MNL_ALIGN(a->nla_len);
        a = (const struct nlattr *)((const uint8_t *)a + MNL_ALIGN(a->nla_len));
    }
    return true;
}

static bool net(const struct nlattr *a, size_t len) {
    return a == NULL || ((a->nla_type & NLA_F_NET_BYTEORDER) && mnl_attr_get_payload_len(a) == len);
}

static bool nested(const struct nlattr *a) { return a == NULL || (a->nla_type & NLA_F_NESTED); }

static uint32_t be32(const struct nlattr *a) {
    uint32_t v;
    memcpy(&v, mnl_attr_get_payload(a), 4);
    return ntohl(v);
}

static bool str(const struct nlattr *a, char *out) {
    if (a == NULL) { return false; }
    size_t len = mnl_attr_get_payload_len(a);
    const char *p = mnl_attr_get_payload(a);
    size_t sl = strnlen(p, len);
    if (sl == len || sl >= IPSET_MAXNAMELEN) { return false; }
    memcpy(out, p, sl + 1);
    return true;
}

static bool u8(const struct nlattr *a, uint8_t *out) {
    if (a == NULL || mnl_attr_get_payload_len(a) != 1 || (a->nla_type & NLA_F_NET_BYTEORDER)) { return false; }
    *out = mnl_attr_get_u8(a);
    return true;
}

static void put_set_name(struct nlmsghdr *nlh, const char *name) { mnl_attr_put_strz(nlh, IPSET_ATTR_SETNAME, name); }

static int do_create(struct fake_setnl *f, const char *name, const struct nlattr **tb) {
    char type[IPSET_MAXNAMELEN];
    uint8_t rev, fam;
    if (!str(tb[IPSET_ATTR_TYPENAME], type) || !u8(tb[IPSET_ATTR_REVISION], &rev) ||
        !u8(tb[IPSET_ATTR_FAMILY], &fam) || !nested(tb[IPSET_ATTR_DATA])) {
        return IPSET_ERR_PROTOCOL;
    }
    if (fam != NFPROTO_IPV4 && fam != NFPROTO_IPV6) { return IPSET_ERR_INVALID_FAMILY; }
    if (f->no_type || strcmp(type, "hash:net") != 0 || rev > (fam == NFPROTO_IPV4 ? f->rev4 : f->rev6)) {
        return IPSET_ERR_FIND_TYPE;
    }
    uint32_t hashsize = 1024, maxelem = 65536;
    if (tb[IPSET_ATTR_DATA] != NULL) {
        const struct nlattr *d[IPSET_ATTR_CREATE_MAX + 1];
        if (!parse(tb[IPSET_ATTR_DATA], NULL, d, IPSET_ATTR_CREATE_MAX)) { return IPSET_ERR_PROTOCOL; }
        if (!net(d[IPSET_ATTR_HASHSIZE], 4) || !net(d[IPSET_ATTR_MAXELEM], 4)) { return IPSET_ERR_PROTOCOL; }
        if (d[IPSET_ATTR_HASHSIZE]) { hashsize = be32(d[IPSET_ATTR_HASHSIZE]); }
        if (d[IPSET_ATTR_MAXELEM]) { maxelem = be32(d[IPSET_ATTR_MAXELEM]); }
    }
    if (find(f, name) != NULL) { return EEXIST; }
    set_t *s = make(f, name);
    if (s == NULL) { return IPSET_ERR_MAX_SETS; }
    snprintf(s->type, sizeof(s->type), "%s", type);
    s->family = fam;
    s->revision = rev;
    s->hashsize = hashsize;
    s->maxelem = maxelem;
    return 0;
}

static int do_add(struct fake_setnl *f, const char *name, const struct nlattr **tb) {
    set_t *s = find(f, name);
    if (s == NULL) { return ENOENT; }
    if (tb[IPSET_ATTR_DATA] == NULL || !nested(tb[IPSET_ATTR_DATA])) { return IPSET_ERR_PROTOCOL; }
    const struct nlattr *d[IPSET_ATTR_ADT_MAX + 1];
    if (!parse(tb[IPSET_ATTR_DATA], NULL, d, IPSET_ATTR_ADT_MAX)) { return IPSET_ERR_PROTOCOL; }
    if (d[IPSET_ATTR_IP] == NULL || !nested(d[IPSET_ATTR_IP]) || !net(d[IPSET_ATTR_LINENO], 4)) {
        return IPSET_ERR_PROTOCOL;
    }
    const struct nlattr *ip[IPSET_ATTR_IPADDR_MAX + 1];
    if (!parse(d[IPSET_ATTR_IP], NULL, ip, IPSET_ATTR_IPADDR_MAX)) { return IPSET_ERR_PROTOCOL; }
    size_t alen = alen_of(s->family);
    const struct nlattr *addr = ip[s->family == NFPROTO_IPV4 ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6];
    if (addr == NULL || !net(addr, alen)) {
        return s->family == NFPROTO_IPV4 ? IPSET_ERR_IPADDR_IPV4 : IPSET_ERR_IPADDR_IPV6;
    }
    member_t m;
    memset(&m, 0, sizeof(m));
    memcpy(m.addr, mnl_attr_get_payload(addr), alen);
    m.cidr = (uint8_t)(alen * 8);
    if (d[IPSET_ATTR_CIDR] != NULL) {
        if (!u8(d[IPSET_ATTR_CIDR], &m.cidr)) { return IPSET_ERR_PROTOCOL; }
        if (m.cidr == 0 || m.cidr > alen * 8) { return IPSET_ERR_INVALID_CIDR; }
    }
    mask(&m, s->family);
    return insert(s, &m);
}

static int do_destroy(struct fake_setnl *f, const struct nlattr **tb) {
    if (tb[IPSET_ATTR_SETNAME] == NULL) {
        for (size_t i = 0; i < FAKE_SETNL_MAX_SETS; i++) {
            if (f->sets[i].used && f->sets[i].referenced) { return IPSET_ERR_BUSY; }
        }
        for (size_t i = 0; i < FAKE_SETNL_MAX_SETS; i++) {
            if (f->sets[i].used) { drop(&f->sets[i]); }
        }
        return 0;
    }
    char name[IPSET_MAXNAMELEN];
    if (!str(tb[IPSET_ATTR_SETNAME], name)) { return IPSET_ERR_PROTOCOL; }
    set_t *s = find(f, name);
    if (s == NULL) { return ENOENT; }
    if (s->referenced) { return IPSET_ERR_BUSY; }
    drop(s);
    return 0;
}

static int do_rename(struct fake_setnl *f, const char *name, const struct nlattr **tb) {
    char to[IPSET_MAXNAMELEN];
    if (!str(tb[IPSET_ATTR_SETNAME2], to)) { return IPSET_ERR_PROTOCOL; }
    set_t *s = find(f, name);
    if (s == NULL) { return ENOENT; }
    if (s->referenced) { return IPSET_ERR_REFERENCED; }
    if (find(f, to) != NULL) { return IPSET_ERR_EXIST_SETNAME2; }
    snprintf(s->name, sizeof(s->name), "%s", to);
    return 0;
}

static int do_swap(struct fake_setnl *f, const char *name, const struct nlattr **tb) {
    char to[IPSET_MAXNAMELEN];
    if (!str(tb[IPSET_ATTR_SETNAME2], to)) { return IPSET_ERR_PROTOCOL; }
    set_t *a = find(f, name);
    if (a == NULL) { return ENOENT; }
    set_t *b = find(f, to);
    if (b == NULL) { return IPSET_ERR_EXIST_SETNAME2; }
    if (strcmp(a->type, b->type) != 0 || a->family != b->family) { return IPSET_ERR_TYPE_MISMATCH; }
    set_t t = *a;
    *a = *b;
    *b = t;
    memcpy(b->name, a->name, sizeof(b->name));
    memcpy(a->name, t.name, sizeof(a->name));
    bool r = a->referenced;
    a->referenced = b->referenced;
    b->referenced = r;
    return 0;
}

static void do_list(struct fake_setnl *f, const struct nlmsghdr *req) {
    uint8_t *buf = f->lbuf;
    memset(buf, 0, sizeof(f->lbuf));
    size_t off = 0;
    for (size_t i = 0; i < FAKE_SETNL_MAX_SETS; i++) {
        if (!f->sets[i].used) { continue; }
        struct nlmsghdr *nlh = start_msg(buf + off, req, IPSET_CMD_LIST, NLM_F_MULTI);
        put_set_name(nlh, f->sets[i].name);
        off += (nlh->nlmsg_len + 3u) & ~3u;
    }
    struct nlmsghdr *done = mnl_nlmsg_put_header(buf + off);
    done->nlmsg_type = NLMSG_DONE;
    done->nlmsg_flags = NLM_F_MULTI;
    done->nlmsg_seq = req->nlmsg_seq;
    mnl_nlmsg_put_extra_header(done, sizeof(int));
    off += done->nlmsg_len;
    reply(f, buf, off);
}

static void do_type(struct fake_setnl *f, const struct nlmsghdr *req, const struct nlattr **tb, int *err) {
    char type[IPSET_MAXNAMELEN];
    uint8_t fam;
    if (!str(tb[IPSET_ATTR_TYPENAME], type) || !u8(tb[IPSET_ATTR_FAMILY], &fam)) {
        *err = IPSET_ERR_PROTOCOL;
        return;
    }
    if (f->no_type || strcmp(type, "hash:net") != 0) {
        *err = IPSET_ERR_FIND_TYPE;
        return;
    }
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = start_msg(buf, req, IPSET_CMD_TYPE, 0);
    mnl_attr_put_strz(nlh, IPSET_ATTR_TYPENAME, type);
    mnl_attr_put_u8(nlh, IPSET_ATTR_FAMILY, fam);
    mnl_attr_put_u8(nlh, IPSET_ATTR_REVISION, fam == NFPROTO_IPV4 ? f->rev4 : f->rev6);
    mnl_attr_put_u8(nlh, IPSET_ATTR_REVISION_MIN, 0);
    reply(f, buf, nlh->nlmsg_len);
}

static const char *what_of(uint8_t cmd) {
    switch (cmd) {
    case IPSET_CMD_PROTOCOL: return "protocol";
    case IPSET_CMD_TYPE: return "type";
    case IPSET_CMD_CREATE: return "create";
    case IPSET_CMD_DESTROY: return "destroy";
    case IPSET_CMD_RENAME: return "rename";
    case IPSET_CMD_SWAP: return "swap";
    case IPSET_CMD_ADD: return "add";
    case IPSET_CMD_LIST: return "list";
    default: return "other";
    }
}

static void gate(struct fake_setnl *f) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += FAKE_SETNL_GATE_MS / 1000;
    while (f->hold && !f->stopping) {
        if (pthread_cond_timedwait(&f->cv, &f->mu, &until) == ETIMEDOUT) { break; }
    }
}

static void handle(struct fake_setnl *f, const struct nlmsghdr *h) {
    pthread_mutex_lock(&f->mu);
    f->messages++;
    bool silent = f->silent, nosys = f->no_subsystem;
    void (*step)(const char *, const char *, void *) = f->step;
    void *step_ud = f->step_ud;
    pthread_mutex_unlock(&f->mu);
    if (silent) { return; }
    if (nosys || (h->nlmsg_type >> 8) != NFNL_SUBSYS_IPSET ||
        mnl_nlmsg_get_payload_len(h) < sizeof(struct nfgenmsg)) {
        ack(f, h, EINVAL);
        return;
    }
    uint8_t cmd = (uint8_t)(h->nlmsg_type & 0xff);
    const struct nlattr *tb[IPSET_ATTR_CMD_MAX + 1];
    int err = 0;
    uint8_t proto = 0;
    char name[IPSET_MAXNAMELEN] = "";
    if (!parse(NULL, h, tb, IPSET_ATTR_CMD_MAX) || !u8(tb[IPSET_ATTR_PROTOCOL], &proto) || proto != 6 ||
        !net(tb[IPSET_ATTR_FLAGS], 4) || !net(tb[IPSET_ATTR_LINENO], 4) || !nested(tb[IPSET_ATTR_DATA])) {
        err = IPSET_ERR_PROTOCOL;
    }
    bool has_name = err == 0 && str(tb[IPSET_ATTR_SETNAME], name);
    if (step != NULL) { step(what_of(cmd), name, step_ud); }
    bool dump = (h->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
    pthread_mutex_lock(&f->mu);
    bool injected = err == 0 && f->inject && f->inject_cmd == cmd;
    bool run = !injected || f->inject_apply;
    int inject_err = f->inject_err;
    if (injected) { f->inject = false; }
    if (err == 0 && run) {
        switch (cmd) {
        case IPSET_CMD_PROTOCOL: {
            uint8_t buf[128];
            memset(buf, 0, sizeof(buf));
            struct nlmsghdr *nlh = start_msg(buf, h, IPSET_CMD_PROTOCOL, 0);
            reply(f, buf, nlh->nlmsg_len);
            break;
        }
        case IPSET_CMD_TYPE: do_type(f, h, tb, &err); break;
        case IPSET_CMD_CREATE: err = has_name ? do_create(f, name, tb) : IPSET_ERR_PROTOCOL; break;
        case IPSET_CMD_DESTROY: err = do_destroy(f, tb); break;
        case IPSET_CMD_RENAME: err = has_name ? do_rename(f, name, tb) : IPSET_ERR_PROTOCOL; break;
        case IPSET_CMD_SWAP: err = has_name ? do_swap(f, name, tb) : IPSET_ERR_PROTOCOL; break;
        case IPSET_CMD_ADD:
            gate(f);
            f->adds_seen++;
            if (f->fail_nth != 0 && f->adds_seen == f->fail_nth) {
                err = f->fail_err;
                f->fail_nth = 0;
            } else if (f->fail_nth2 != 0 && f->adds_seen == f->fail_nth2) {
                err = f->fail_err2;
                f->fail_nth2 = 0;
            } else {
                err = has_name ? do_add(f, name, tb) : IPSET_ERR_PROTOCOL;
            }
            break;
        case IPSET_CMD_LIST:
            if (dump) {
                do_list(f, h);
            } else {
                err = EOPNOTSUPP;
            }
            break;
        default: err = EOPNOTSUPP; break;
        }
    }
    pthread_mutex_unlock(&f->mu);
    if (injected) {
        if (inject_err != 0) { ack(f, h, inject_err); }
        return;
    }
    if (err != 0) {
        ack(f, h, err);
    } else if (!dump && (h->nlmsg_flags & NLM_F_ACK)) {
        ack(f, h, 0);
    }
}

static void *kernel_main(void *ud) {
    struct fake_setnl *f = ud;
    for (;;) {
        ssize_t got = recv(f->fd, f->rbuf, FAKE_SETNL_RECV, 0);
        if (got <= 0) { break; }
        pthread_mutex_lock(&f->mu);
        f->sends++;
        if ((size_t)got > f->largest) { f->largest = (size_t)got; }
        const struct nlmsghdr *first = (const struct nlmsghdr *)f->rbuf;
        if (mnl_nlmsg_ok(first, (int)got)) {
            datagram_t *d = &f->last[first->nlmsg_type & 0x0f];
            if (d->data != NULL) {
                if (f->n_old == f->cap_old) {
                    f->cap_old = f->cap_old ? f->cap_old * 2 : 64;
                    uint8_t **o = realloc(f->old, f->cap_old * sizeof(*o));
                    if (o == NULL) { abort(); }
                    f->old = o;
                }
                f->old[f->n_old++] = d->data;
            }
            d->data = malloc((size_t)got);
            memcpy(d->data, f->rbuf, (size_t)got);
            d->len = (size_t)got;
        }
        pthread_mutex_unlock(&f->mu);
        int len = (int)got;
        const struct nlmsghdr *h = first;
        while (mnl_nlmsg_ok(h, len)) {
            handle(f, h);
            h = mnl_nlmsg_next(h, &len);
        }
    }
    return NULL;
}

fake_setnl_t *fake_setnl_start(firc_setnl_t **out) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) { return NULL; }
    struct fake_setnl *f = calloc(1, sizeof(*f));
    if (f == NULL) {
        close(sv[0]);
        close(sv[1]);
        return NULL;
    }
    f->rbuf = malloc(FAKE_SETNL_RECV);
    f->fd = sv[0];
    f->rev4 = 6;
    f->rev6 = 6;
    pthread_mutex_init(&f->mu, NULL);
    pthread_cond_init(&f->cv, NULL);
    *out = firc_setnl_new_fd(sv[1]);
    if (*out == NULL || f->rbuf == NULL || pthread_create(&f->th, NULL, kernel_main, f) != 0) {
        firc_setnl_free(*out);
        *out = NULL;
        close(sv[0]);
        free(f->rbuf);
        free(f);
        return NULL;
    }
    return f;
}

void fake_setnl_stop(fake_setnl_t *f) {
    if (f == NULL) { return; }
    pthread_mutex_lock(&f->mu);
    f->stopping = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    shutdown(f->fd, SHUT_RDWR);
    pthread_join(f->th, NULL);
    close(f->fd);
    for (size_t i = 0; i < FAKE_SETNL_MAX_SETS; i++) {
        if (f->sets[i].used) { drop(&f->sets[i]); }
    }
    for (size_t i = 0; i < 16; i++) { free(f->last[i].data); }
    for (size_t i = 0; i < f->n_old; i++) { free(f->old[i]); }
    free(f->old);
    pthread_cond_destroy(&f->cv);
    pthread_mutex_destroy(&f->mu);
    free(f->rbuf);
    free(f);
}

void fake_setnl_set_revision(fake_setnl_t *f, uint8_t family, uint8_t rev) {
    pthread_mutex_lock(&f->mu);
    if (family == 4) {
        f->rev4 = rev;
    } else {
        f->rev6 = rev;
    }
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_no_type(fake_setnl_t *f) {
    pthread_mutex_lock(&f->mu);
    f->no_type = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_no_subsystem(fake_setnl_t *f) {
    pthread_mutex_lock(&f->mu);
    f->no_subsystem = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_reference(fake_setnl_t *f, const char *name, bool on) {
    pthread_mutex_lock(&f->mu);
    set_t *s = find(f, name);
    if (s != NULL) { s->referenced = on; }
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_fail_add_at(fake_setnl_t *f, size_t nth, int err) {
    pthread_mutex_lock(&f->mu);
    f->adds_seen = 0;
    f->fail_nth = nth;
    f->fail_err = err;
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_fail_add_also(fake_setnl_t *f, size_t nth, int err) {
    pthread_mutex_lock(&f->mu);
    f->fail_nth2 = nth;
    f->fail_err2 = err;
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_fail_next(fake_setnl_t *f, uint8_t cmd, int err, bool apply) {
    pthread_mutex_lock(&f->mu);
    f->inject = true;
    f->inject_cmd = cmd;
    f->inject_err = err;
    f->inject_apply = apply;
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_never_answer(fake_setnl_t *f) {
    pthread_mutex_lock(&f->mu);
    f->silent = true;
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_plant(fake_setnl_t *f, const char *name, uint8_t family) {
    pthread_mutex_lock(&f->mu);
    set_t *s = make(f, name);
    if (s != NULL) {
        snprintf(s->type, sizeof(s->type), "hash:net");
        s->family = nfproto_of(family);
        s->revision = family == 4 ? f->rev4 : f->rev6;
        s->hashsize = 1024;
        s->maxelem = 65536;
    }
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_hold_adds(fake_setnl_t *f, bool on) {
    pthread_mutex_lock(&f->mu);
    f->hold = on;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
}

void fake_setnl_on_step(fake_setnl_t *f, void (*fn)(const char *what, const char *name, void *ud), void *ud) {
    pthread_mutex_lock(&f->mu);
    f->step = fn;
    f->step_ud = ud;
    pthread_mutex_unlock(&f->mu);
}

bool fake_setnl_has(fake_setnl_t *f, const char *name) {
    pthread_mutex_lock(&f->mu);
    bool r = find(f, name) != NULL;
    pthread_mutex_unlock(&f->mu);
    return r;
}

size_t fake_setnl_count(fake_setnl_t *f, const char *name) {
    pthread_mutex_lock(&f->mu);
    set_t *s = find(f, name);
    size_t n = s != NULL ? s->n : 0;
    pthread_mutex_unlock(&f->mu);
    return n;
}

bool fake_setnl_contains(fake_setnl_t *f, const char *name, const firc_nf_prefix_t *p) {
    pthread_mutex_lock(&f->mu);
    set_t *s = find(f, name);
    bool r = false;
    if (s != NULL && s->family == nfproto_of(p->family)) {
        member_t m;
        memset(&m, 0, sizeof(m));
        m.cidr = p->cidr;
        memcpy(m.addr, p->addr, alen_of(s->family));
        mask(&m, s->family);
        r = slot_of(s, &m) >= 0;
    }
    pthread_mutex_unlock(&f->mu);
    return r;
}

bool fake_setnl_meta(fake_setnl_t *f, const char *name, fake_setnl_meta_t *out) {
    pthread_mutex_lock(&f->mu);
    set_t *s = find(f, name);
    if (s != NULL) {
        memcpy(out->type, s->type, sizeof(out->type));
        out->family = s->family;
        out->revision = s->revision;
        out->maxelem = s->maxelem;
        out->hashsize = s->hashsize;
        out->referenced = s->referenced;
    }
    pthread_mutex_unlock(&f->mu);
    return s != NULL;
}

size_t fake_setnl_sets(fake_setnl_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = 0;
    for (size_t i = 0; i < FAKE_SETNL_MAX_SETS; i++) { n += f->sets[i].used ? 1u : 0u; }
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t fake_setnl_messages(fake_setnl_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->messages;
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t fake_setnl_sends(fake_setnl_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->sends;
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t fake_setnl_largest_send(fake_setnl_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->largest;
    pthread_mutex_unlock(&f->mu);
    return n;
}

bool fake_setnl_last_datagram(fake_setnl_t *f, uint8_t cmd, const uint8_t **data, size_t *len) {
    pthread_mutex_lock(&f->mu);
    datagram_t *d = &f->last[cmd & 0x0f];
    *data = d->data;
    *len = d->len;
    pthread_mutex_unlock(&f->mu);
    return *data != NULL;
}
