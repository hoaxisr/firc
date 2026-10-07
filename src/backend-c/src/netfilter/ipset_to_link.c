#include "firc/ipset_to_link.h"
#include "firc/log.h"
#include "firc/mark.h"

#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include "firc/pool_reject.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

typedef struct family_state {
    bool rule_added;
    bool reply_rule_added; /* IPv4 only */
    bool blackhole_added;
    bool iface_route_present;
    bool iface_has_gw;
    uint8_t gw[16];
    uint8_t gw_len;
} family_state_t;

struct firc_ipset_to_link {
    char *chain_name;
    char *iface_name;
    firc_ipt_t *ipt4;
    firc_ipt_t *ipt6;
    firc_rtnl_t *rtnl;
    const firc_fakeip_t *pool; /* loop thread only */
    const firc_fakeip_snapshot_t *(*snap)(void *ud);
    void *snap_ud;
    char *group_id;
    firc_ipv4_subnet_t *sub4;
    size_t n_sub4;
    firc_ipv6_subnet_t *sub6;
    size_t n_sub6;
    firc_nf_devices_t dev;
    bool pool_rejected;
    uint32_t start_idx;

    bool enabled;
    uint32_t mark;       /* what the MARK rule writes: group field + handled bit */
    uint32_t mark_field; /* 1..FIRC_MARK_MAX_GROUPS; 0 until enable */
    firc_ct_t *ct;
    uint32_t table;
    family_state_t v4, v6;
};

firc_ipset_to_link_t *firc_ipset_to_link_new(const char *chain_name, const char *iface_name,
                                         firc_ipt_t *ipt4, firc_ipt_t *ipt6,
                                         firc_rtnl_t *rtnl, uint32_t start_idx,
                                         const firc_fakeip_t *pool, const char *group_id,
                                         const firc_fakeip_snapshot_t *(*snap)(void *ud),
                                         void *snap_ud) {
    firc_ipset_to_link_t *l = calloc(1, sizeof(*l));
    if (!l) { return NULL; }
    l->chain_name = strdup(chain_name);
    l->iface_name = strdup(iface_name);
    if (!l->chain_name || !l->iface_name) {
        free(l->chain_name);
        free(l->iface_name);
        free(l);
        return NULL;
    }
    l->ipt4 = ipt4;
    l->ipt6 = ipt6;
    l->rtnl = rtnl;
    l->pool = pool;
    l->snap = snap;
    l->snap_ud = snap_ud;
    l->group_id = group_id ? strdup(group_id) : NULL;
    if (group_id && !l->group_id) {
        free(l->chain_name);
        free(l->iface_name);
        free(l);
        return NULL;
    }
    l->start_idx = start_idx;
    return l;
}

void firc_ipset_to_link_free(firc_ipset_to_link_t *l) {
    if (!l) { return; }
    free(l->chain_name);
    free(l->iface_name);
    free(l->group_id);
    free(l->sub4);
    free(l->sub6);
    firc_nf_devices_clear(&l->dev);
    free(l);
}

typedef struct {
    firc_ipt_t *ipt;
    const char *chain;
    const char *mark_str;
    const char *jump; /* the devices chain, for a selector group; else NULL */
    unsigned want_family;
    firc_err_t err;
} chunk_emit_t;

static void emit_chunk_rule(void *ud, const char *group_id, unsigned family,
                            const firc_ip_t *base, uint8_t prefix) {
    chunk_emit_t *e = ud;
    (void)group_id;
    if (family != e->want_family || e->err != FIRC_OK) { return; }

    char cidr[64];
    char addr[INET6_ADDRSTRLEN];
    if (inet_ntop(base->len == 4 ? AF_INET : AF_INET6, base->b, addr, sizeof(addr)) == NULL) {
        e->err = FIRC_ERR_INVAL;
        return;
    }
    if (snprintf(cidr, sizeof(cidr), "%s/%u", addr, prefix) >= (int)sizeof(cidr)) {
        e->err = FIRC_ERR_INVAL;
        return;
    }

    if (e->jump != NULL) {
        const char *j[] = {"-d", cidr, "-j", e->jump};
        e->err = firc_ipt_append(e->ipt, "mangle", e->chain, j, 4);
        return;
    }

    const char *mk[] = {"-d", cidr, "-j", "MARK", "--set-xmark", e->mark_str};
    e->err = firc_ipt_append(e->ipt, "mangle", e->chain, mk, 6);
    if (e->err != FIRC_OK) { return; }
    /* Masks spelled out as iptables-save echoes them; only firc's bits reach ctmark. */
    const char *cm[] = {"-d", cidr, "-j", "CONNMARK", "--save-mark", "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    e->err = firc_ipt_append(e->ipt, "mangle", e->chain, cm, 9);
}

firc_err_t firc_ipset_to_link_devices_chain_of(const char *chain, char *out, size_t cap) {
    int n = snprintf(out, cap, "%s%s", chain, FIRC_DEVICES_CHAIN_SUFFIX);
    return n < 0 || (size_t)n >= cap ? FIRC_ERR_INVAL : FIRC_OK;
}

/* Parts in iptables-save order, none for a /0; false for the other family. */
static bool source_match(const firc_nf_source_t *s, bool is6, char *text, size_t cap, const char **parts,
                         size_t *n) {
    *n = 0;
    switch (s->kind) {
    case FIRC_NF_SRC_ADDR: {
        if ((s->family == 6) != is6) { return false; }
        if (s->prefix == 0) { return true; } /* iptables-save never echoes -s 0.0.0.0/0 */
        char a[INET6_ADDRSTRLEN];
        if (inet_ntop(is6 ? AF_INET6 : AF_INET, s->addr, a, sizeof(a)) == NULL) { return false; }
        snprintf(text, cap, "%s/%u", a, s->prefix);
        parts[(*n)++] = "-s";
        parts[(*n)++] = text;
        return true;
    }
    case FIRC_NF_SRC_MAC:
        /* %02X as libxt_mac echoes it, or the chain is rewritten every pass. */
        snprintf(text, cap, "%02X:%02X:%02X:%02X:%02X:%02X", s->mac[0], s->mac[1], s->mac[2], s->mac[3],
                 s->mac[4], s->mac[5]);
        parts[(*n)++] = "-m";
        parts[(*n)++] = "mac";
        parts[(*n)++] = "--mac-source";
        parts[(*n)++] = text;
        return true;
    case FIRC_NF_SRC_MARK:
        /* Every bit but firc's: an earlier firc chain may have written ours. */
        snprintf(text, cap, "0x%x/0x%x", s->mark & FIRC_MARK_POLICY_MASK, FIRC_MARK_POLICY_MASK);
        parts[(*n)++] = "-m";
        parts[(*n)++] = "mark";
        parts[(*n)++] = "--mark";
        parts[(*n)++] = text;
        return true;
    default:
        return false;
    }
}

/* Deny RETURNs, allow MARKs, then CONNMARK only on packets this chain marked. */
static firc_err_t emit_devices_chain(firc_ipt_t *ipt, const char *dchain, const char *mark_str,
                                     const firc_nf_devices_t *dev) {
    bool is6 = firc_ipt_proto(ipt) == FIRC_IPT_PROTO_IPV6;
    firc_err_t err = firc_ipt_register_chain_override(ipt, "mangle", dchain);
    if (err != FIRC_OK) { return err; }
    char text[64];
    const char *r[12];
    size_t n = 0;
    for (size_t i = 0; i < dev->n_deny; i++) {
        if (!source_match(&dev->deny[i], is6, text, sizeof(text), r, &n)) { continue; }
        r[n++] = "-j";
        r[n++] = "RETURN";
        err = firc_ipt_append(ipt, "mangle", dchain, r, n);
        if (err != FIRC_OK) { return err; }
    }
    if (dev->allow_all) {
        const char *all[] = {"-j", "MARK", "--set-xmark", mark_str};
        err = firc_ipt_append(ipt, "mangle", dchain, all, 4);
        if (err != FIRC_OK) { return err; }
    } else {
        for (size_t i = 0; i < dev->n_allow; i++) {
            if (!source_match(&dev->allow[i], is6, text, sizeof(text), r, &n)) { continue; }
            r[n++] = "-j";
            r[n++] = "MARK";
            r[n++] = "--set-xmark";
            r[n++] = mark_str;
            err = firc_ipt_append(ipt, "mangle", dchain, r, n);
            if (err != FIRC_OK) { return err; }
        }
    }
    const char *cm[] = {"-m", "mark", "--mark", mark_str, "-j", "CONNMARK", "--save-mark",
                        "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    return firc_ipt_append(ipt, "mangle", dchain, cm, 11);
}

firc_err_t firc_ipset_to_link_build_rules_dev(firc_ipt_t *ipt, const char *chain_name, const char *iface_name,
                                              uint32_t mark, uint32_t mark_field,
                                              const firc_fakeip_snapshot_t *snap, const char *group_id,
                                              const firc_nf_devices_t *dev) {
    if (!ipt) { return FIRC_OK; }
    bool with_dev = dev != NULL && dev->active;
    char dchain[128];
    if (with_dev && firc_ipset_to_link_devices_chain_of(chain_name, dchain, sizeof(dchain)) != FIRC_OK) {
        return FIRC_ERR_INVAL;
    }

    firc_err_t err = firc_ipt_register_chain_override(ipt, "filter", chain_name);
    if (err != FIRC_OK) { return err; }

    /* Masked on both sides: bits outside FIRC_MARK_WRITE_MASK are not ours. */
    char mark_str[32], match_str[32];
    snprintf(mark_str, sizeof(mark_str), "0x%x/0x%x", mark, FIRC_MARK_WRITE_MASK);
    snprintf(match_str, sizeof(match_str), "0x%x/0x%x", firc_mark_group_value(mark_field),
             FIRC_MARK_GROUP_MASK);

    if (strcmp(iface_name, FIRC_IPSET_TO_LINK_BLACKHOLE) != 0) {
        /* FORWARD sees the real address, so match the mark, not the chunk. */
        const char *acc[] = {"-o", iface_name, "-m", "mark", "--mark", match_str, "-j", "ACCEPT"};
        err = firc_ipt_append(ipt, "filter", chain_name, acc, 8);
        if (err != FIRC_OK) { return err; }
    }
    const char *fwd_args[] = {"-j", chain_name};
    err = firc_ipt_append(ipt, "filter", "FORWARD", fwd_args, 2);
    if (err != FIRC_OK) { return err; }

    err = firc_ipt_register_chain_override(ipt, "mangle", chain_name);
    if (err != FIRC_OK) { return err; }
    const char *mangle1[] = {"-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"};
    err = firc_ipt_append(ipt, "mangle", chain_name, mangle1, 6);
    if (err != FIRC_OK) { return err; }
    const char *pre_args[] = {"-j", chain_name};
    err = firc_ipt_append(ipt, "mangle", "PREROUTING", pre_args, 2);
    if (err != FIRC_OK) { return err; }

    err = firc_ipt_register_chain_override(ipt, "nat", chain_name);
    if (err != FIRC_OK) { return err; }
    /* POSTROUTING sees the real address: match the mark and the output interface. */
    if (strcmp(iface_name, FIRC_IPSET_TO_LINK_BLACKHOLE) != 0) {
        const char *nat1[] = {"-o", iface_name, "-m",          "mark",
                              "--mark", match_str, "-j", "MASQUERADE"};
        err = firc_ipt_append(ipt, "nat", chain_name, nat1, 8);
        if (err != FIRC_OK) { return err; }
    }
    const char *post_args[] = {"-j", chain_name};
    err = firc_ipt_append(ipt, "nat", "POSTROUTING", post_args, 2);
    if (err != FIRC_OK) { return err; }

    if (snap != NULL && group_id != NULL) {
        chunk_emit_t e = {
            .ipt = ipt,
            .chain = chain_name,
            .mark_str = mark_str,
            .jump = with_dev ? dchain : NULL,
            .want_family = firc_ipt_proto(ipt) == FIRC_IPT_PROTO_IPV6 ? FIRC_FAM_V6 : FIRC_FAM_V4,
            .err = FIRC_OK,
        };
        /* Snapshot only: the loop thread frees live chunks without a lock. */
        firc_fakeip_snapshot_walk_chunks(snap, group_id, emit_chunk_rule, &e);
        if (e.err != FIRC_OK) { return e.err; }
    }

    if (with_dev) { return emit_devices_chain(ipt, dchain, mark_str, dev); }
    return FIRC_OK;
}

firc_err_t firc_ipset_to_link_build_rules(firc_ipt_t *ipt, const char *chain_name, const char *iface_name,
                                          uint32_t mark, uint32_t mark_field,
                                          const firc_fakeip_snapshot_t *snap, const char *group_id) {
    return firc_ipset_to_link_build_rules_dev(ipt, chain_name, iface_name, mark, mark_field, snap, group_id,
                                              NULL);
}

static firc_err_t build_iptables_rules(firc_ipset_to_link_t *l, firc_ipt_t *ipt) {
    firc_err_t err = firc_ipset_to_link_build_rules_dev(ipt, l->chain_name, l->iface_name,
                                                        l->mark, l->mark_field,
                                                        l->snap ? l->snap(l->snap_ud) : NULL,
                                                        l->group_id, &l->dev);
    if (err != FIRC_OK) { return err; }
    return firc_ipset_to_link_build_subnet_rules_dev(ipt, l->chain_name, l->mark, l->sub4, l->n_sub4,
                                                     l->sub6, l->n_sub6, &l->dev);
}

firc_err_t firc_ipset_to_link_set_subnets(firc_ipset_to_link_t *l, const firc_ipv4_subnet_t *v4,
                                          size_t n4, const firc_ipv6_subnet_t *v6, size_t n6,
                                          bool *changed) {
    if (!l) { return FIRC_ERR_INVAL; }
    bool same = n4 == l->n_sub4 && n6 == l->n_sub6 &&
                (n4 == 0 || memcmp(v4, l->sub4, n4 * sizeof(*v4)) == 0) &&
                (n6 == 0 || memcmp(v6, l->sub6, n6 * sizeof(*v6)) == 0);
    if (changed) { *changed = !same; }
    if (same) { return FIRC_OK; }
    firc_ipv4_subnet_t *c4 = n4 ? malloc(n4 * sizeof(*c4)) : NULL;
    firc_ipv6_subnet_t *c6 = n6 ? malloc(n6 * sizeof(*c6)) : NULL;
    if ((n4 && !c4) || (n6 && !c6)) {
        free(c4);
        free(c6);
        return FIRC_ERR_NOMEM;
    }
    if (n4) { memcpy(c4, v4, n4 * sizeof(*c4)); }
    if (n6) { memcpy(c6, v6, n6 * sizeof(*c6)); }
    free(l->sub4);
    free(l->sub6);
    l->sub4 = c4;
    l->n_sub4 = n4;
    l->sub6 = c6;
    l->n_sub6 = n6;
    return FIRC_OK;
}

void firc_nf_devices_clear(firc_nf_devices_t *d) {
    if (d == NULL) { return; }
    free(d->deny);
    free(d->allow);
    memset(d, 0, sizeof(*d));
}

/* Only the fields of the source's kind, never memcmp: the padding is garbage. */
static bool source_equal(const firc_nf_source_t *a, const firc_nf_source_t *b) {
    if (a->kind != b->kind) { return false; }
    switch (a->kind) {
    case FIRC_NF_SRC_ADDR:
        return a->family == b->family && a->prefix == b->prefix &&
               memcmp(a->addr, b->addr, a->family == 6 ? 16 : 4) == 0;
    case FIRC_NF_SRC_MAC:
        return memcmp(a->mac, b->mac, sizeof(a->mac)) == 0;
    case FIRC_NF_SRC_MARK:
        return ((a->mark ^ b->mark) & FIRC_MARK_POLICY_MASK) == 0;
    default:
        return true;
    }
}

static bool sources_equal(const firc_nf_source_t *a, const firc_nf_source_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!source_equal(&a[i], &b[i])) { return false; }
    }
    return true;
}

firc_err_t firc_nf_devices_push(firc_nf_devices_t *d, bool deny, const firc_nf_source_t *s) {
    firc_nf_source_t **v = deny ? &d->deny : &d->allow;
    size_t *n = deny ? &d->n_deny : &d->n_allow;
    size_t *cap = deny ? &d->cap_deny : &d->cap_allow;
    for (size_t i = 0; i < *n; i++) {
        if (source_equal(&(*v)[i], s)) { return FIRC_OK; }
    }
    if (*n >= *cap) {
        size_t room = *n != 0 ? *n * 2 : 4;
        firc_nf_source_t *grown = realloc(*v, room * sizeof(*grown));
        if (grown == NULL) { return FIRC_ERR_NOMEM; }
        *v = grown;
        *cap = room;
    }
    (*v)[(*n)++] = *s;
    return FIRC_OK;
}

bool firc_nf_devices_equal(const firc_nf_devices_t *a, const firc_nf_devices_t *b) {
    return a->active == b->active && a->allow_all == b->allow_all && a->n_deny == b->n_deny &&
           a->n_allow == b->n_allow && sources_equal(a->deny, b->deny, a->n_deny) &&
           sources_equal(a->allow, b->allow, a->n_allow);
}

static bool source_in(const firc_nf_source_t *s, const firc_nf_source_t *v, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (source_equal(s, &v[i])) { return true; }
    }
    return false;
}

/* An inactive chain counts as marking every device. */
bool firc_nf_devices_narrows(const firc_nf_devices_t *was, const firc_nf_devices_t *now) {
    if (was->active && !was->allow_all && was->n_allow == 0) { return false; }
    bool was_all = !was->active || was->allow_all;
    bool now_all = !now->active || now->allow_all;
    size_t was_deny = was->active ? was->n_deny : 0;
    size_t now_deny = now->active ? now->n_deny : 0;
    for (size_t i = 0; i < now_deny; i++) {
        if (!source_in(&now->deny[i], was->deny, was_deny)) { return true; }
    }
    if (now_all) { return false; }
    if (was_all) { return true; }
    for (size_t i = 0; i < was->n_allow; i++) {
        if (!source_in(&was->allow[i], now->allow, now->n_allow)) { return true; }
    }
    return false;
}

static firc_err_t sources_copy(const firc_nf_source_t *src, size_t n, firc_nf_source_t **out) {
    *out = NULL;
    if (n == 0) { return FIRC_OK; }
    *out = malloc(n * sizeof(**out));
    if (*out == NULL) { return FIRC_ERR_NOMEM; }
    memcpy(*out, src, n * sizeof(**out));
    return FIRC_OK;
}

firc_err_t firc_nf_devices_copy(firc_nf_devices_t *dst, const firc_nf_devices_t *src) {
    firc_nf_devices_t c = {.active = src->active, .allow_all = src->allow_all, .n_deny = src->n_deny,
                           .n_allow = src->n_allow, .cap_deny = src->n_deny, .cap_allow = src->n_allow};
    firc_err_t err = sources_copy(src->deny, src->n_deny, &c.deny);
    if (err == FIRC_OK) { err = sources_copy(src->allow, src->n_allow, &c.allow); }
    if (err != FIRC_OK) {
        firc_nf_devices_clear(&c);
        memset(dst, 0, sizeof(*dst));
        return err;
    }
    *dst = c;
    return FIRC_OK;
}

firc_err_t firc_ipset_to_link_set_devices(firc_ipset_to_link_t *l, const firc_nf_devices_t *d, bool *changed) {
    if (l == NULL || d == NULL) { return FIRC_ERR_INVAL; }
    bool same = firc_nf_devices_equal(&l->dev, d);
    if (changed) { *changed = !same; }
    if (same) { return FIRC_OK; }
    firc_nf_devices_t c;
    firc_err_t err = firc_nf_devices_copy(&c, d);
    if (err != FIRC_OK) { return err; }
    firc_nf_devices_clear(&l->dev);
    l->dev = c;
    return FIRC_OK;
}

const firc_nf_devices_t *firc_ipset_to_link_devices(const firc_ipset_to_link_t *l) { return &l->dev; }

/* Real prefixes: original direction and not yet handled; parts in iptables-save order, no -d for /0. */
static const char *proto_name(uint8_t proto) {
    return proto == IPPROTO_TCP ? "tcp" : proto == IPPROTO_UDP ? "udp" : NULL;
}

static firc_err_t emit_subnet_rule(firc_ipt_t *ipt, const char *chain, const char *cidr,
                                   unsigned prefix, uint8_t proto, const char *ports,
                                   const char *mark_str, const char *jump) {
    char handled[32];
    snprintf(handled, sizeof(handled), "0x%x/0x%x", FIRC_MARK_HANDLED, FIRC_MARK_HANDLED);
    const char *pn = proto_name(proto);
    const char *head[8];
    size_t nh = 0;
    if (prefix != 0) { head[nh++] = "-d"; head[nh++] = cidr; }
    if (pn != NULL) { head[nh++] = "-p"; head[nh++] = pn; }
    const char *pm[4];
    size_t np = 0;
    if (pn != NULL && ports[0] != '\0') {
        bool list = strchr(ports, ',') != NULL;
        pm[np++] = "-m";
        pm[np++] = list ? "multiport" : pn;
        pm[np++] = list ? "--dports" : "--dport";
        pm[np++] = ports;
    }
    const char *mk[32], *cm[32];
    size_t nm = 0, nc = 0;
    for (size_t i = 0; i < nh; i++) { mk[nm++] = head[i]; cm[nc++] = head[i]; }
    const char *dir[] = {"-m", "conntrack", "--ctdir", "ORIGINAL"};
    for (size_t i = 0; i < 4; i++) { mk[nm++] = dir[i]; cm[nc++] = dir[i]; }
    const char *unm[] = {"-m", "mark", "!", "--mark", handled};
    for (size_t i = 0; i < 5; i++) { mk[nm++] = unm[i]; }
    for (size_t i = 0; i < np; i++) { mk[nm++] = pm[i]; cm[nc++] = pm[i]; }
    if (jump != NULL) {
        mk[nm++] = "-j";
        mk[nm++] = jump;
        return firc_ipt_append(ipt, "mangle", chain, mk, nm);
    }
    const char *tgt[] = {"-j", "MARK", "--set-xmark", mark_str};
    for (size_t i = 0; i < 4; i++) { mk[nm++] = tgt[i]; }
    firc_err_t err = firc_ipt_append(ipt, "mangle", chain, mk, nm);
    if (err != FIRC_OK) { return err; }
    const char *save[] = {"-j", "CONNMARK", "--save-mark", "--nfmask", "0x40ff0000", "--ctmask", "0x40ff0000"};
    for (size_t i = 0; i < 7; i++) { cm[nc++] = save[i]; }
    return firc_ipt_append(ipt, "mangle", chain, cm, nc);
}

firc_err_t firc_ipset_to_link_build_subnet_rules_dev(firc_ipt_t *ipt, const char *chain_name, uint32_t mark,
                                                     const firc_ipv4_subnet_t *v4, size_t n4,
                                                     const firc_ipv6_subnet_t *v6, size_t n6,
                                                     const firc_nf_devices_t *dev) {
    if (!ipt) { return FIRC_OK; }
    bool with_dev = dev != NULL && dev->active;
    char dchain[128];
    if (with_dev && firc_ipset_to_link_devices_chain_of(chain_name, dchain, sizeof(dchain)) != FIRC_OK) {
        return FIRC_ERR_INVAL;
    }
    char mark_str[32];
    snprintf(mark_str, sizeof(mark_str), "0x%x/0x%x", mark, FIRC_MARK_WRITE_MASK);
    bool is6 = firc_ipt_proto(ipt) == FIRC_IPT_PROTO_IPV6;
    char addr[INET6_ADDRSTRLEN], cidr[64];
    for (size_t i = 0; i < (is6 ? n6 : n4); i++) {
        const void *raw = is6 ? (const void *)v6[i].addr : (const void *)v4[i].addr;
        unsigned prefix = is6 ? v6[i].cidr : v4[i].cidr;
        if (inet_ntop(is6 ? AF_INET6 : AF_INET, raw, addr, sizeof(addr)) == NULL) {
            return FIRC_ERR_INVAL;
        }
        snprintf(cidr, sizeof(cidr), "%s/%u", addr, prefix);
        uint8_t proto = is6 ? v6[i].proto : v4[i].proto;
        const char *ports = is6 ? v6[i].ports : v4[i].ports;
        /* Ports without a protocol would mark every port. */
        if (proto == 0 && ports[0] != '\0') { return FIRC_ERR_INVAL; }
        firc_err_t err = emit_subnet_rule(ipt, chain_name, cidr, prefix, proto, ports, mark_str,
                                          with_dev ? dchain : NULL);
        if (err != FIRC_OK) { return err; }
    }
    return FIRC_OK;
}

firc_err_t firc_ipset_to_link_build_subnet_rules(firc_ipt_t *ipt, const char *chain_name,
                                                 uint32_t mark, const firc_ipv4_subnet_t *v4,
                                                 size_t n4, const firc_ipv6_subnet_t *v6,
                                                 size_t n6) {
    return firc_ipset_to_link_build_subnet_rules_dev(ipt, chain_name, mark, v4, n4, v6, n6, NULL);
}

static firc_err_t insert_iptables_rules(firc_ipset_to_link_t *l, firc_ipt_t *ipt) {
    if (!ipt) { return FIRC_OK; }

    firc_err_t err = build_iptables_rules(l, ipt);
    if (err != FIRC_OK) { return err; }
    return firc_ipt_commit(ipt);
}

firc_err_t firc_ipset_to_link_rewrite_chains(firc_ipset_to_link_t *l) {
    if (!l || !l->enabled) { return FIRC_OK; }
    firc_err_t e4 = insert_iptables_rules(l, l->ipt4);
    firc_err_t e6 = insert_iptables_rules(l, l->ipt6);
    return e4 != FIRC_OK ? e4 : e6;
}

firc_err_t firc_ipset_to_link_stage_for_test(firc_ipset_to_link_t *l) {
    if (!l) { return FIRC_ERR_INVAL; }
    firc_err_t e4 = build_iptables_rules(l, l->ipt4);
    firc_err_t e6 = build_iptables_rules(l, l->ipt6);
    return e4 != FIRC_OK ? e4 : e6;
}

firc_err_t firc_ipset_to_link_prepare_iptables(firc_ipset_to_link_t *l) {
    if (!l || !l->enabled) { return FIRC_OK; }

    firc_err_t e4 = build_iptables_rules(l, l->ipt4);
    firc_err_t e6 = build_iptables_rules(l, l->ipt6);
    return e4 != FIRC_OK ? e4 : e6;
}

firc_err_t firc_ipset_to_link_stage_delete(firc_ipt_t *ipt, const char *chain_name) {
    if (!ipt) { return FIRC_OK; }
    static const struct {
        const char *table;
        const char *base;
    } k_where[] = {{"filter", "FORWARD"}, {"mangle", "PREROUTING"}, {"nat", "POSTROUTING"}};
    firc_err_t first_err = FIRC_OK;
    for (size_t i = 0; i < sizeof(k_where) / sizeof(k_where[0]); i++) {
        firc_err_t err = firc_ipt_register_chain_delete(ipt, k_where[i].table, chain_name);
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        const char *jump[] = {"-j", chain_name};
        err = firc_ipt_delete(ipt, k_where[i].table, k_where[i].base, jump, 2);
        if (err != FIRC_OK && err != FIRC_ERR_NOENT && first_err == FIRC_OK) { first_err = err; }
    }
    /* -X order is safe: the group chain is flushed at its declaration. */
    char dchain[128];
    firc_err_t derr = firc_ipset_to_link_devices_chain_of(chain_name, dchain, sizeof(dchain));
    if (derr == FIRC_OK) { derr = firc_ipt_register_chain_delete(ipt, "mangle", dchain); }
    if (derr != FIRC_OK && first_err == FIRC_OK) { first_err = derr; }
    return first_err;
}

firc_err_t firc_ipset_to_link_stage_delete_devices(firc_ipt_t *ipt, const char *devices_chain) {
    if (!ipt) { return FIRC_OK; }
    return firc_ipt_register_chain_delete(ipt, "mangle", devices_chain);
}

static firc_err_t delete_iptables_rules(firc_ipset_to_link_t *l, firc_ipt_t *ipt) {
    if (!ipt) { return FIRC_OK; }
    firc_err_t first_err = firc_ipset_to_link_stage_delete(ipt, l->chain_name);
    firc_err_t err = firc_ipt_commit(ipt);
    if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
    return first_err;
}

static firc_err_t insert_ip_rule(firc_ipset_to_link_t *l, const char **failed) {
    /* Reject routes before the rule: a marked packet must never take the group's default. */
    if (l->pool != NULL) {
        l->pool_rejected = true; /* set first: rollback removes a half-installed pair */
        firc_err_t err = firc_pool_reject_install(l->rtnl, l->pool, l->table,
                                                  FIRC_POOL_REJECT_METRIC_GROUP);
        if (err != FIRC_OK) { *failed = "pool reject route"; return err; }
    } else {
        FIRC_WARN("no address pool for chain %s: its table cannot reject pool traffic",
                  l->chain_name);
    }
    /* The reply twin goes in before the rule it guards. */
    if (l->ipt4 && strcmp(l->iface_name, FIRC_IPSET_TO_LINK_BLACKHOLE) != 0) {
        (void)firc_rtnl_rule_del(l->rtnl, AF_INET, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, RT_TABLE_MAIN, FIRC_RULE_PRIORITY_REPLY);
        firc_err_t rerr = firc_rtnl_rule_add_reply(l->rtnl, AF_INET, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, l->iface_name, RT_TABLE_MAIN, FIRC_RULE_PRIORITY_REPLY);
        if (rerr != FIRC_OK) { *failed = "ip rule"; return rerr; }
        l->v4.reply_rule_added = true;
    }
    if (l->ipt4) {
        (void)firc_rtnl_rule_del(l->rtnl, AF_INET, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, l->table, firc_rule_priority_for_field(l->mark_field));
        firc_err_t err = firc_rtnl_rule_add(l->rtnl, AF_INET, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, l->table, firc_rule_priority_for_field(l->mark_field));
        if (err != FIRC_OK) { *failed = "ip rule"; return err; }
        l->v4.rule_added = true;
    }
    if (l->ipt6) {
        (void)firc_rtnl_rule_del(l->rtnl, AF_INET6, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, l->table, firc_rule_priority_for_field(l->mark_field));
        firc_err_t err = firc_rtnl_rule_add(l->rtnl, AF_INET6, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, l->table, firc_rule_priority_for_field(l->mark_field));
        if (err != FIRC_OK) { *failed = "ip rule"; return err; }
        l->v6.rule_added = true;
    }

    return FIRC_OK;
}

static firc_err_t delete_ip_rule(firc_ipset_to_link_t *l) {
    firc_err_t first_err = FIRC_OK;
    /* Rules out before reject routes, or a marked packet takes the default. */
    if (l->v4.rule_added) {
        firc_err_t err = firc_rtnl_rule_del(l->rtnl, AF_INET, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, l->table, firc_rule_priority_for_field(l->mark_field));
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        l->v4.rule_added = false;
    }
    if (l->v4.reply_rule_added) {
        firc_err_t err = firc_rtnl_rule_del(l->rtnl, AF_INET, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, RT_TABLE_MAIN, FIRC_RULE_PRIORITY_REPLY);
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        l->v4.reply_rule_added = false;
    }
    if (l->v6.rule_added) {
        firc_err_t err = firc_rtnl_rule_del(l->rtnl, AF_INET6, firc_mark_group_value(l->mark_field), FIRC_MARK_GROUP_MASK, l->table, firc_rule_priority_for_field(l->mark_field));
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        l->v6.rule_added = false;
    }
    if (l->pool_rejected && l->pool != NULL) {
        firc_err_t err = firc_pool_reject_remove(l->rtnl, l->pool, l->table,
                                                 FIRC_POOL_REJECT_METRIC_GROUP);
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        l->pool_rejected = false;
    }
    return first_err;
}

static firc_err_t update_iface_route(firc_ipset_to_link_t *l, int family, int ifindex,
                                   bool point_to_point, family_state_t *fs) {
    bool has_gw = false;
    uint8_t gw[16] = {0};
    uint8_t gw_len = 0;

    if (!point_to_point) {
        bool found;
        bool gatewayless = false;
        firc_err_t err =
            firc_rtnl_gateway_for_iface2(l->rtnl, family, ifindex, &found, gw, &gw_len, &gatewayless);
        if (err == FIRC_OK && !found && gatewayless) {
            /* On-link default: drop the learnt gateway, or a dead one stays forever. */
            FIRC_DEBUG("%s has a default route with no gateway; the group's default follows it", l->iface_name);
        } else if (err != FIRC_OK || !found) {
            /* No default found is not "no gateway": keep the last one rather than write a dev-only route. */
            if (err != FIRC_OK) {
                FIRC_WARN("gateway lookup failed for %s: %s; keeping the gateway last written", l->iface_name,
                          firc_err_str(err));
            } else if (fs->iface_has_gw) {
                FIRC_DEBUG("no default route on %s yet; keeping the gateway last written", l->iface_name);
            }
            if (fs->iface_has_gw) {
                has_gw = true;
                gw_len = fs->gw_len;
                memcpy(gw, fs->gw, sizeof(gw));
            }
        } else {
            has_gw = true;
        }
    }

    /* Always rewritten with NLM_F_REPLACE: link-down purges device routes behind our back. */
    bool enodev = false;
    firc_err_t err = firc_rtnl_route_add_iface(l->rtnl, family, l->table, 10, ifindex,
                                          has_gw ? gw : NULL, gw_len, &enodev);
    if (err != FIRC_OK) { return err; }
    if (enodev) {
        FIRC_WARN("interface %s not ready for this IP family, skipping route", l->iface_name);
        fs->iface_route_present = false;
        return FIRC_OK;
    }

    fs->iface_route_present = true;
    fs->iface_has_gw = has_gw;
    fs->gw_len = gw_len;
    memcpy(fs->gw, gw, sizeof(fs->gw));
    return FIRC_OK;
}

static firc_err_t insert_ip_route(firc_ipset_to_link_t *l) {
    if (l->ipt4) {
        firc_err_t err = firc_rtnl_route_add_blackhole(l->rtnl, AF_INET, l->table, 20);
        if (err != FIRC_OK) { return err; }
        l->v4.blackhole_added = true;
    }
    if (l->ipt6) {
        firc_err_t err = firc_rtnl_route_add_blackhole(l->rtnl, AF_INET6, l->table, 20);
        if (err != FIRC_OK) { return err; }
        l->v6.blackhole_added = true;
    }

    if (strcmp(l->iface_name, FIRC_IPSET_TO_LINK_BLACKHOLE) == 0) { return FIRC_OK; }

    firc_link_info_t li;
    bool found;
    firc_err_t err = firc_rtnl_link_by_name(l->rtnl, l->iface_name, &li, &found);
    if (err != FIRC_OK) { return err; }
    if (!found) {
        FIRC_WARN("interface %s not found, it can be caught later", l->iface_name);
        return FIRC_OK;
    }
    if (!li.up) {
        FIRC_WARN("interface %s is down", l->iface_name);
        return FIRC_OK;
    }

    if (l->ipt4) {
        err = update_iface_route(l, AF_INET, li.ifindex, li.point_to_point, &l->v4);
        if (err != FIRC_OK) { return err; }
    }
    if (l->ipt6) {
        err = update_iface_route(l, AF_INET6, li.ifindex, li.point_to_point, &l->v6);
        if (err != FIRC_OK) { return err; }
    }
    return FIRC_OK;
}

static firc_err_t delete_ip_route(firc_ipset_to_link_t *l) {
    firc_err_t first_err = FIRC_OK;

    if (l->v4.iface_route_present) {
        firc_link_info_t li;
        bool found;
        firc_rtnl_link_by_name(l->rtnl, l->iface_name, &li, &found);
        int ifindex = found ? li.ifindex : 0;
        firc_err_t err = firc_rtnl_route_del_iface(l->rtnl, AF_INET, l->table, 10, ifindex,
                                              l->v4.iface_has_gw ? l->v4.gw : NULL, l->v4.gw_len);
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        l->v4.iface_route_present = false;
    }
    if (l->v6.iface_route_present) {
        firc_link_info_t li;
        bool found;
        firc_rtnl_link_by_name(l->rtnl, l->iface_name, &li, &found);
        int ifindex = found ? li.ifindex : 0;
        firc_err_t err = firc_rtnl_route_del_iface(l->rtnl, AF_INET6, l->table, 10, ifindex,
                                              l->v6.iface_has_gw ? l->v6.gw : NULL, l->v6.gw_len);
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        l->v6.iface_route_present = false;
    }
    if (l->v4.blackhole_added) {
        firc_err_t err = firc_rtnl_route_del_blackhole(l->rtnl, AF_INET, l->table, 20);
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        l->v4.blackhole_added = false;
    }
    if (l->v6.blackhole_added) {
        firc_err_t err = firc_rtnl_route_del_blackhole(l->rtnl, AF_INET6, l->table, 20);
        if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
        l->v6.blackhole_added = false;
    }
    return first_err;
}

/* A zero group value would match every unmarked flow on the router. */
void firc_ipset_to_link_flush_mark(firc_ct_t *ct, uint32_t group_value, const char *who) {
    if (ct == NULL || group_value == 0) { return; }
    size_t dropped = 0;
    /* Handled bit in value and mask: the field alone would flush firmware-policy flows. */
    firc_err_t err = firc_ct_flush_by_mark(ct, group_value | FIRC_MARK_HANDLED,
                                           FIRC_MARK_GROUP_MASK | FIRC_MARK_HANDLED, &dropped);
    if (dropped > 0) {
        FIRC_DEBUG("dropped %zu live flow(s) of %s", dropped, who);
    }
    if (err != FIRC_OK) {
        FIRC_WARN("could not drop all of %s's live flows: %s; any left keep their old route "
                  "until they end",
                  who, firc_err_str(err));
    }
}

static void flush_flows(firc_ipset_to_link_t *l) {
    if (l->mark_field == 0) { return; }
    firc_ipset_to_link_flush_mark(l->ct, firc_mark_group_value(l->mark_field), l->chain_name);
}

void firc_ipset_to_link_set_conntrack(firc_ipset_to_link_t *l, firc_ct_t *ct) {
    if (l != NULL) { l->ct = ct; }
}

uint32_t firc_ipset_to_link_mark_field(const firc_ipset_to_link_t *l) {
    return l == NULL ? 0 : l->mark_field;
}

bool firc_ipset_to_link_has_iface_route(const firc_ipset_to_link_t *l, int family) {
    if (l == NULL) { return false; }
    return family == AF_INET6 ? l->v6.iface_route_present : l->v4.iface_route_present;
}

static firc_err_t teardown(firc_ipset_to_link_t *l, firc_nf_write_t mode) {
    /* Rule first, then routes, so the rule never points at an emptying table. */
    firc_err_t e2 = delete_ip_rule(l);
    firc_err_t e1 = delete_ip_route(l);
    /* By the committer the caller tombstones the chains. */
    firc_err_t e3 = mode == FIRC_NF_WRITE_NOW ? delete_iptables_rules(l, l->ipt4) : FIRC_OK;
    firc_err_t e4 = mode == FIRC_NF_WRITE_NOW ? delete_iptables_rules(l, l->ipt6) : FIRC_OK;
    if (e1 != FIRC_OK) { return e1; }
    if (e2 != FIRC_OK) { return e2; }
    if (e3 != FIRC_OK) { return e3; }
    return e4;
}

firc_err_t firc_ipset_to_link_enable(firc_ipset_to_link_t *l, firc_nf_write_t mode, const char **step) {
    if (l->enabled) { return FIRC_OK; }
    const char *failed = NULL;

    uint32_t idx;
    firc_err_t err = firc_rtnl_alloc_mark_table(l->rtnl, l->start_idx, &idx);
    if (err != FIRC_OK) {
        if (step) { *step = "routing table"; }
        return err;
    }
    l->table = idx;
    uint32_t field = 0;
    /* By group id, so a re-created group keeps the field its live flows carry. */
    firc_err_t ferr = firc_rtnl_alloc_mark_field_for(l->rtnl, l->group_id, &field);
    if (ferr != FIRC_OK) {
        if (step) { *step = "mark field"; }
        return ferr;
    }
    l->mark_field = field;
    if (!firc_mark_for_field(field, &l->mark)) {
        if (step) { *step = "mark field"; }
        return FIRC_ERR_LIMIT;
    }

    /* Routes before the rule that points at them. */
    err = insert_ip_route(l);
    if (err != FIRC_OK) { failed = "route"; }
    if (err == FIRC_OK) { err = insert_ip_rule(l, &failed); }
    if (err == FIRC_OK && mode == FIRC_NF_WRITE_NOW) {
        err = insert_iptables_rules(l, l->ipt4);
        if (err == FIRC_OK) { err = insert_iptables_rules(l, l->ipt6); }
        if (err != FIRC_OK) { failed = "iptables"; }
    }

    if (err != FIRC_OK) {
        teardown(l, mode);
        if (step) { *step = failed; }
        return err;
    }

    l->enabled = true;
    FIRC_DEBUG("using ip table and mark 0x%x for chain %s", l->mark, l->chain_name);
    return FIRC_OK;
}

firc_err_t firc_ipset_to_link_disable(firc_ipset_to_link_t *l, firc_flows_t flows, firc_nf_write_t mode) {
    if (!l->enabled) { return FIRC_OK; }
    l->enabled = false;
    firc_err_t err = teardown(l, mode);
    /* After rules and routes are gone, so nothing re-marks a flow; the committer path queues it instead. */
    if (flows == FIRC_FLOWS_DROP && mode == FIRC_NF_WRITE_NOW) { flush_flows(l); }
    return err;
}

firc_err_t firc_ipset_to_link_on_link_up(firc_ipset_to_link_t *l) {
    if (!l->enabled) { return FIRC_OK; }
    return insert_ip_route(l);
}

firc_err_t firc_ipset_to_link_on_addr_change(firc_ipset_to_link_t *l) {
    if (!l->enabled || strcmp(l->iface_name, FIRC_IPSET_TO_LINK_BLACKHOLE) == 0) { return FIRC_OK; }

    firc_link_info_t li;
    bool found;
    firc_err_t err = firc_rtnl_link_by_name(l->rtnl, l->iface_name, &li, &found);
    if (err != FIRC_OK) { return err; }
    if (!found) { return FIRC_OK; }
    /* A down link's routes would be refused; link-up puts them back. */
    if (!li.up) { return FIRC_OK; }

    /* Both families, whatever one says: they fail independently. */
    firc_err_t first = FIRC_OK;
    if (l->ipt4) {
        err = update_iface_route(l, AF_INET, li.ifindex, li.point_to_point, &l->v4);
        if (err != FIRC_OK) { first = err; }
    }
    if (l->ipt6) {
        err = update_iface_route(l, AF_INET6, li.ifindex, li.point_to_point, &l->v6);
        if (err != FIRC_OK && first == FIRC_OK) { first = err; }
    }
    return first;
}
