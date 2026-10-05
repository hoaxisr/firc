#include "firc/ruleset.h"

#include "firc/mark.h"
#include "firc/devices.h"
#include "firc/ifacename.h"
#include "firc/match.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "firc/log.h"

struct firc_ruleset {
    const firc_group_t *group;
    firc_ruleset_deps_t deps;
    bool enabled;
    firc_ipset_to_link_t *ipset_to_link;
    firc_ruleset_retry_t retry;
    /* Valid only right after a sync or refresh, which clear it first. */
    bool dev_narrowed;
};

firc_ruleset_retry_t *firc_ruleset_retry(firc_ruleset_t *rs) { return &rs->retry; }

static firc_err_t subnets_apply(firc_ruleset_t *rs, bool *changed);
static firc_err_t devices_apply(firc_ruleset_t *rs, bool *changed);

/* A newline or empty interface name would break the whole restore transcript. */
static bool iface_usable(const firc_ruleset_t *rs) {
    return firc_is_interface_name(rs->group->iface);
}

static bool configured_enabled(const firc_ruleset_t *rs) {
    return rs->group->enable && iface_usable(rs);
}

firc_ruleset_t *firc_ruleset_new(const firc_group_t *group, const firc_ruleset_deps_t *deps) {
    firc_ruleset_t *rs = calloc(1, sizeof(*rs));
    if (!rs) { return NULL; }
    rs->group = group;
    rs->deps = *deps;
    return rs;
}

void firc_ruleset_free(firc_ruleset_t *rs) {
    if (!rs) { return; }
    firc_ipset_to_link_free(rs->ipset_to_link);
    free(rs);
}

const firc_group_t *firc_ruleset_group(const firc_ruleset_t *rs) {
    return rs->group;
}

uint32_t firc_ruleset_mark_field(const firc_ruleset_t *rs) {
    if (rs == NULL || rs->ipset_to_link == NULL) { return 0; }
    return firc_mark_group_value(firc_ipset_to_link_mark_field(rs->ipset_to_link));
}

bool firc_ruleset_has_iface_route(const firc_ruleset_t *rs, int family) {
    return rs != NULL && firc_ipset_to_link_has_iface_route(rs->ipset_to_link, family);
}

firc_group_t *firc_ruleset_group_mut(firc_ruleset_t *rs) {
    return (firc_group_t *)rs->group;
}

bool firc_ruleset_runtime_enabled(const firc_ruleset_t *rs) {
    return rs->enabled;
}

bool firc_ruleset_routed(const firc_ruleset_t *rs) {
    return rs != NULL && rs->enabled && configured_enabled(rs) && rs->ipset_to_link != NULL;
}

bool firc_ruleset_in_view(const firc_ruleset_t *rs) {
    return rs != NULL && rs->enabled && rs->group->enable;
}

void firc_ruleset_chain_name_for(const char *prefix, firc_id_t id, char *out, size_t cap) {
    char id_buf[FIRC_ID_STR_LEN];
    firc_id_format(id, id_buf);
    snprintf(out, cap, "%s%s", prefix != NULL ? prefix : "", id_buf);
}

static firc_err_t ruleset_enable_locked(firc_ruleset_t *rs, firc_nf_write_t mode, const char **step) {
    if (rs->enabled) { return FIRC_OK; }
    rs->enabled = true;
    if (rs->group->enable && !iface_usable(rs)) {
        /* Sanitised: the name is refused for what it can do to a line of text. */
        char safe[IF_NAMESIZE + 8];
        firc_interface_name_for_log(rs->group->iface, safe, sizeof(safe));
        FIRC_WARN("group %s routes nothing: \"%s\" is not an interface name",
                  rs->group->name != NULL ? rs->group->name : "?", safe);
    }
    if (!configured_enabled(rs)) { return FIRC_OK; }

    char id_buf[FIRC_ID_STR_LEN];
    firc_id_format(rs->group->id, id_buf);
    char chain_name[128];
    firc_ruleset_chain_name_for(rs->deps.chain_prefix, rs->group->id, chain_name, sizeof(chain_name));

    const char *iface = rs->group->iface != NULL ? rs->group->iface : "";
    firc_ipset_to_link_t *link = firc_ipset_to_link_new(chain_name, iface, rs->deps.ipt4,
                                                    rs->deps.ipt6, rs->deps.rtnl,
                                                    rs->deps.start_idx, rs->deps.pool, id_buf,
                                                    rs->deps.snap, rs->deps.snap_ud);
    if (!link) {
        if (step) { *step = "memory"; }
        return FIRC_ERR_NOMEM;
    }
    firc_ipset_to_link_set_conntrack(link, rs->deps.ct);

    /* Set before enable writes the chain, so the first commit carries prefixes and devices. */
    rs->ipset_to_link = link;
    firc_err_t err = subnets_apply(rs, NULL);
    if (err == FIRC_OK) { err = devices_apply(rs, NULL); }
    rs->dev_narrowed = false;
    rs->ipset_to_link = NULL;
    if (err != FIRC_OK) {
        if (step) { *step = "memory"; }
        firc_ipset_to_link_free(link);
        return err;
    }

    err = firc_ipset_to_link_enable(link, mode, step);
    if (err != FIRC_OK) {
        firc_ipset_to_link_free(link);
        return err;
    }
    rs->ipset_to_link = link;
    return FIRC_OK;
}

firc_err_t firc_ruleset_enable(firc_ruleset_t *rs, firc_nf_write_t mode, const char **step) {
    firc_err_t err = ruleset_enable_locked(rs, mode, step);
    if (err != FIRC_OK) {
        /* The routing never came up, so nothing is steering by its mark. */
        firc_ruleset_disable(rs, FIRC_FLOWS_KEEP, mode);
        return err;
    }
    return FIRC_OK;
}

firc_err_t firc_ruleset_disable(firc_ruleset_t *rs, firc_flows_t flows, firc_nf_write_t mode) {
    if (!rs->enabled) { return FIRC_OK; }
    rs->enabled = false;
    if (!configured_enabled(rs)) { return FIRC_OK; }

    firc_err_t e1 = FIRC_OK;
    firc_err_t e2 = FIRC_OK;
    if (rs->ipset_to_link) {
        e1 = firc_ipset_to_link_disable(rs->ipset_to_link, flows, mode);
        firc_ipset_to_link_free(rs->ipset_to_link);
        rs->ipset_to_link = NULL;
    }

    return e1 != FIRC_OK ? e1 : e2;
}

firc_err_t firc_ruleset_prepare_iptables(firc_ruleset_t *rs) {
    if (!rs->enabled) { return FIRC_OK; }
    if (!configured_enabled(rs)) { return FIRC_OK; }
    if (!rs->ipset_to_link) { return FIRC_OK; }
    return firc_ipset_to_link_prepare_iptables(rs->ipset_to_link);
}

firc_err_t firc_ruleset_on_link_up(firc_ruleset_t *rs) {
    if (!rs->enabled) { return FIRC_OK; }
    if (!configured_enabled(rs)) { return FIRC_OK; }
    if (!rs->ipset_to_link) { return FIRC_OK; }
    return firc_ipset_to_link_on_link_up(rs->ipset_to_link);
}

firc_err_t firc_ruleset_on_addr_change(firc_ruleset_t *rs) {
    if (!rs->enabled) { return FIRC_OK; }
    if (!configured_enabled(rs)) { return FIRC_OK; }
    if (!rs->ipset_to_link) { return FIRC_OK; }
    return firc_ipset_to_link_on_addr_change(rs->ipset_to_link);
}

typedef struct subnets {
    firc_ipv4_subnet_t *v4;
    size_t n4;
    firc_ipv6_subnet_t *v6;
    size_t n6;
} subnets_t;

/* An unusable proto/ports is skipped, never written as a match-all rule. */
static bool subnet_match_fill(const char *what, const char *proto_s, const char *ports_s, uint8_t *proto,
                              char *ports, size_t cap, bool warn) {
    if (!firc_rule_parse_proto(proto_s, proto)) {
        if (warn) { FIRC_WARN("subnet rule \"%s\" has proto \"%s\" and routes nothing", what, proto_s); }
        return false;
    }
    if (!firc_rule_parse_ports(ports_s, ports, cap) || (*proto == 0 && ports[0] != '\0')) {
        if (warn) { FIRC_WARN("subnet rule \"%s\" has ports \"%s\" and routes nothing", what, ports_s); }
        return false;
    }
    return true;
}

static firc_err_t append_v4(subnets_t *out, const firc_ipv4_subnet_t *subnet) {
    firc_ipv4_subnet_t *grown = realloc(out->v4, (out->n4 + 1) * sizeof(*grown));
    if (grown == NULL) { return FIRC_ERR_NOMEM; }
    out->v4 = grown;
    out->v4[out->n4++] = *subnet;
    return FIRC_OK;
}

static firc_err_t append_v6(subnets_t *out, const firc_ipv6_subnet_t *subnet) {
    firc_ipv6_subnet_t *grown = realloc(out->v6, (out->n6 + 1) * sizeof(*grown));
    if (grown == NULL) { return FIRC_ERR_NOMEM; }
    out->v6 = grown;
    out->v6[out->n6++] = *subnet;
    return FIRC_OK;
}

static firc_err_t subnets_collect(const firc_group_t *g, subnets_t *out) {
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < g->n_rules; i++) {
        const firc_rule_t *rule = g->rules[i];
        if (!rule->enable) { continue; }
        if (strcmp(rule->type, FIRC_RULE_SUBNET) == 0) {
            firc_ipv4_subnet_t subnet;
            if (!firc_rule_parse_subnet4(rule->rule, &subnet)) {
                FIRC_WARN("subnet rule \"%s\" is not a prefix and routes nothing", rule->rule);
                continue;
            }
            if (!subnet_match_fill(rule->rule, rule->proto, rule->ports, &subnet.proto, subnet.ports,
                                   sizeof(subnet.ports), true)) {
                continue;
            }
            firc_err_t err = append_v4(out, &subnet);
            if (err != FIRC_OK) { return err; }
        } else if (strcmp(rule->type, FIRC_RULE_SUBNET6) == 0) {
            firc_ipv6_subnet_t subnet;
            if (!firc_rule_parse_subnet6(rule->rule, &subnet)) {
                FIRC_WARN("subnet6 rule \"%s\" is not a prefix and routes nothing", rule->rule);
                continue;
            }
            if (!subnet_match_fill(rule->rule, rule->proto, rule->ports, &subnet.proto, subnet.ports,
                                   sizeof(subnet.ports), true)) {
                continue;
            }
            firc_err_t err = append_v6(out, &subnet);
            if (err != FIRC_OK) { return err; }
        }
    }
    /* List lines are skipped silently: the list apply already warned once. */
    const firc_sub_rules_t *lr = g->list != NULL ? &g->list->rules : NULL;
    for (size_t i = 0; lr != NULL && i < lr->n; i++) {
        if (!firc_sub_rules_enable(lr, i)) { continue; }
        const char *type = firc_sub_rules_type(lr, i);
        const char *text = firc_sub_rules_text(lr, i);
        if (strcmp(type, FIRC_RULE_SUBNET) == 0) {
            firc_ipv4_subnet_t subnet;
            if (!firc_rule_parse_subnet4(text, &subnet)) { continue; }
            if (!subnet_match_fill(text, firc_sub_rules_proto(lr, i), firc_sub_rules_ports(lr, i), &subnet.proto,
                                   subnet.ports, sizeof(subnet.ports), false)) {
                continue;
            }
            firc_err_t err = append_v4(out, &subnet);
            if (err != FIRC_OK) { return err; }
        } else if (strcmp(type, FIRC_RULE_SUBNET6) == 0) {
            firc_ipv6_subnet_t subnet;
            if (!firc_rule_parse_subnet6(text, &subnet)) { continue; }
            if (!subnet_match_fill(text, firc_sub_rules_proto(lr, i), firc_sub_rules_ports(lr, i), &subnet.proto,
                                   subnet.ports, sizeof(subnet.ports), false)) {
                continue;
            }
            firc_err_t err = append_v6(out, &subnet);
            if (err != FIRC_OK) { return err; }
        }
    }
    return FIRC_OK;
}

static void subnets_free(subnets_t *s) {
    free(s->v4);
    free(s->v6);
}

static firc_err_t subnets_apply(firc_ruleset_t *rs, bool *changed) {
    subnets_t s;
    firc_err_t err = subnets_collect(rs->group, &s);
    if (err == FIRC_OK) {
        err = firc_ipset_to_link_set_subnets(rs->ipset_to_link, s.v4, s.n4, s.v6, s.n6, changed);
    }
    subnets_free(&s);
    return err;
}

void firc_ruleset_devices_chain_name_for(const char *prefix, firc_id_t id, char *out, size_t cap) {
    char chain[128];
    firc_ruleset_chain_name_for(prefix, id, chain, sizeof(chain));
    if (firc_ipset_to_link_devices_chain_of(chain, out, cap) != FIRC_OK && cap > 0) { out[0] = '\0'; }
}

typedef struct render {
    firc_nf_devices_t *out;
    size_t refused_deny;
    size_t refused_allow;
} render_t;

static void refuse(render_t *r, bool deny) {
    if (deny) {
        r->refused_deny++;
    } else {
        r->refused_allow++;
    }
}

/* Host bits cleared: iptables-save echoes the network, and a mismatch rewrites the chain every pass. */
static bool addr_source(const firc_ip_t *a, uint8_t prefix, firc_nf_source_t *s) {
    if ((a->len != 4 && a->len != 16) || prefix > a->len * 8u) { return false; }
    memset(s, 0, sizeof(*s));
    s->kind = FIRC_NF_SRC_ADDR;
    s->family = a->len == 4 ? 4 : 6;
    s->prefix = prefix;
    for (size_t i = 0; i < a->len; i++) {
        size_t bit = i * 8u;
        if (bit + 8u <= prefix) {
            s->addr[i] = a->b[i];
        } else if (bit < prefix) {
            s->addr[i] = (uint8_t)(a->b[i] & (0xffu << (8u - (prefix - bit))));
        }
    }
    return true;
}

typedef struct expand {
    render_t *r;
    bool deny;
    const firc_devsel_entry_t *entry; /* NULL: a policy's hosts */
    firc_err_t err;
} expand_t;

static void expand_one(const firc_ip_t *a, void *ud) {
    expand_t *x = ud;
    if (x->err != FIRC_OK) { return; }
    if (x->entry != NULL && firc_devsel_prefix_covers(&x->entry->addr, x->entry->prefix, a)) { return; }
    firc_nf_source_t s;
    if (!addr_source(a, (uint8_t)(a->len * 8u), &s)) {
        refuse(x->r, x->deny);
        return;
    }
    x->err = firc_nf_devices_push(x->r->out, x->deny, &s);
}

static void expand_net(const firc_ip_t *net, uint8_t prefix, void *ud) {
    expand_t *x = ud;
    if (x->err != FIRC_OK) { return; }
    firc_nf_source_t s;
    if (!addr_source(net, prefix, &s)) {
        refuse(x->r, x->deny);
        return;
    }
    x->err = firc_nf_devices_push(x->r->out, x->deny, &s);
}

static firc_err_t render_entry(render_t *r, const char *text, bool deny, const firc_ruleset_lookup_t *lk) {
    firc_devsel_entry_t e;
    firc_err_t err = firc_devsel_entry_parse(text, &e); /* e.policy points into text, the group's */
    if (err == FIRC_ERR_NOMEM) { return err; }
    if (err != FIRC_OK) {
        refuse(r, deny);
        return FIRC_OK;
    }
    firc_nf_source_t s;
    memset(&s, 0, sizeof(s));
    switch (e.kind) {
    case FIRC_DEVSEL_ADDR:
        if (!addr_source(&e.addr, e.prefix, &s)) {
            refuse(r, deny);
            return FIRC_OK;
        }
        err = firc_nf_devices_push(r->out, deny, &s);
        /* Deny asks for every host tied to the entry; allow only for the sure ones. */
        if (err == FIRC_OK && lk != NULL && lk->host_addrs != NULL) {
            expand_t x = {r, deny, &e, FIRC_OK};
            err = lk->host_addrs(&e.addr, e.prefix, deny, expand_one, &x, lk->ud);
            if (err == FIRC_OK) { err = x.err; }
        }
        return err;
    case FIRC_DEVSEL_MAC:
        s.kind = FIRC_NF_SRC_MAC;
        memcpy(s.mac, e.mac.b, sizeof(s.mac));
        return firc_nf_devices_push(r->out, deny, &s);
    case FIRC_DEVSEL_POLICY: {
        uint32_t mark = 0;
        if (lk != NULL && lk->policy_mark != NULL && lk->policy_mark(e.policy, &mark, lk->ud)) {
            s.kind = FIRC_NF_SRC_MARK;
            s.mark = mark & FIRC_MARK_POLICY_MASK;
            /* A zero mark under the mask would match every unmarked packet. */
            if (s.mark == 0) {
                refuse(r, deny);
            } else {
                err = firc_nf_devices_push(r->out, deny, &s);
            }
        }
        if (err == FIRC_OK && lk != NULL && lk->policy_hosts != NULL) {
            expand_t x = {r, deny, NULL, FIRC_OK};
            err = lk->policy_hosts(e.policy, deny, expand_one, &x, lk->ud);
            if (err == FIRC_OK) { err = x.err; }
        }
        if (err == FIRC_OK && lk != NULL && lk->policy_nets != NULL) {
            expand_t x = {r, deny, NULL, FIRC_OK};
            err = lk->policy_nets(e.policy, deny, expand_net, &x, lk->ud);
            if (err == FIRC_OK) { err = x.err; }
        }
        return err;
    }
    }
    return FIRC_OK;
}

static firc_err_t render_devices(const firc_group_t *g, const firc_ruleset_lookup_t *lk, render_t *r) {
    firc_nf_devices_t *out = r->out;
    memset(out, 0, sizeof(*out));
    const firc_devsel_spec_t *ds = &g->devices;
    if (ds->n_allow == 0 && ds->n_deny == 0) { return FIRC_OK; }
    out->active = true;
    out->allow_all = ds->n_allow == 0; /* the SELECTOR's list, not what it rendered to */
    firc_err_t err = FIRC_OK;
    for (size_t i = 0; err == FIRC_OK && i < ds->n_deny; i++) { err = render_entry(r, ds->deny[i], true, lk); }
    for (size_t i = 0; err == FIRC_OK && i < ds->n_allow; i++) { err = render_entry(r, ds->allow[i], false, lk); }
    if (err != FIRC_OK) {
        firc_nf_devices_clear(out);
        return err;
    }
    if (r->refused_deny > 0) {
        /* A deny we could not write: mark nobody rather than the devices it keeps out. */
        free(out->allow);
        out->allow = NULL;
        out->n_allow = 0;
        out->cap_allow = 0;
        out->allow_all = false;
    }
    return FIRC_OK;
}

firc_err_t firc_ruleset_render_devices(const firc_group_t *g, const firc_ruleset_lookup_t *lk,
                                       firc_nf_devices_t *out) {
    render_t r = {out, 0, 0};
    return render_devices(g, lk, &r);
}

static firc_err_t devices_apply(firc_ruleset_t *rs, bool *changed) {
    firc_nf_devices_t d;
    render_t r = {&d, 0, 0};
    bool moved = false;
    rs->dev_narrowed = false;
    firc_err_t err = render_devices(rs->group, rs->deps.lookup, &r);
    /* Compared before the copy is replaced. */
    bool narrows = err == FIRC_OK && firc_nf_devices_narrows(firc_ipset_to_link_devices(rs->ipset_to_link), &d);
    if (err == FIRC_OK) { err = firc_ipset_to_link_set_devices(rs->ipset_to_link, &d, &moved); }
    firc_nf_devices_clear(&d);
    if (changed) { *changed = moved; }
    rs->dev_narrowed = err == FIRC_OK && moved && narrows;
    const char *name = rs->group->name != NULL ? rs->group->name : "?";
    if (err == FIRC_OK && moved && r.refused_deny > 0) {
        FIRC_WARN("group %s marks no device: %zu deny entr%s of its selector could not be written", name,
                  r.refused_deny, r.refused_deny == 1 ? "y" : "ies");
    }
    if (err == FIRC_OK && moved && r.refused_allow > 0) {
        FIRC_WARN("group %s: %zu allow entr%s of its selector could not be written and mark%s nobody", name,
                  r.refused_allow, r.refused_allow == 1 ? "y" : "ies", r.refused_allow == 1 ? "s" : "");
    }
    return err;
}

bool firc_ruleset_devices_narrowed(const firc_ruleset_t *rs) { return rs != NULL && rs->dev_narrowed; }

const firc_nf_devices_t *firc_ruleset_devices(const firc_ruleset_t *rs) {
    return firc_ruleset_routed(rs) ? firc_ipset_to_link_devices(rs->ipset_to_link) : NULL;
}

bool firc_ruleset_has_devices(const firc_ruleset_t *rs) {
    return rs != NULL && rs->group->devices.n_allow + rs->group->devices.n_deny > 0;
}

bool firc_ruleset_devices_follow_table(const firc_ruleset_t *rs) {
    if (rs == NULL) { return false; }
    const firc_devsel_spec_t *ds = &rs->group->devices;
    size_t mlen = strlen(FIRC_DEVSEL_MAC_PREFIX);
    for (size_t i = 0; i < ds->n_allow + ds->n_deny; i++) {
        const char *e = i < ds->n_allow ? ds->allow[i] : ds->deny[i - ds->n_allow];
        if (strncmp(e, FIRC_DEVSEL_MAC_PREFIX, mlen) != 0) { return true; }
    }
    return false;
}

firc_err_t firc_ruleset_devices_would_move(const firc_ruleset_t *rs, bool *moved) {
    *moved = false;
    if (!firc_ruleset_routed(rs) || !firc_ruleset_devices_follow_table(rs)) { return FIRC_OK; }
    firc_nf_devices_t d;
    render_t r = {&d, 0, 0};
    firc_err_t err = render_devices(rs->group, rs->deps.lookup, &r);
    if (err == FIRC_OK) { *moved = !firc_nf_devices_equal(firc_ipset_to_link_devices(rs->ipset_to_link), &d); }
    firc_nf_devices_clear(&d);
    return err;
}

firc_err_t firc_ruleset_refresh_devices(firc_ruleset_t *rs, bool *changed) {
    if (changed) { *changed = false; }
    rs->dev_narrowed = false;
    if (!firc_ruleset_routed(rs) || !firc_ruleset_devices_follow_table(rs)) { return FIRC_OK; }
    return devices_apply(rs, changed);
}

firc_err_t firc_ruleset_rewrite_chains(firc_ruleset_t *rs) {
    if (!rs->enabled || !configured_enabled(rs) || !rs->ipset_to_link) { return FIRC_OK; }
    return firc_ipset_to_link_rewrite_chains(rs->ipset_to_link);
}

firc_err_t firc_ruleset_plan_subnets(const firc_group_t *g, firc_ruleset_plan_fn fn, void *ud) {
    subnets_t s;
    firc_err_t err = subnets_collect(g, &s);
    for (size_t i = 0; err == FIRC_OK && i < s.n4; i++) {
        fn(4, s.v4[i].addr, s.v4[i].cidr, s.v4[i].proto, s.v4[i].ports, ud);
    }
    for (size_t i = 0; err == FIRC_OK && i < s.n6; i++) {
        fn(6, s.v6[i].addr, s.v6[i].cidr, s.v6[i].proto, s.v6[i].ports, ud);
    }
    subnets_free(&s);
    return err;
}

firc_err_t firc_ruleset_sync(firc_ruleset_t *rs, bool *chain_changed) {
    if (chain_changed) { *chain_changed = false; }
    if (!rs->enabled) { return FIRC_OK; }
    if (!configured_enabled(rs)) { return FIRC_OK; }
    /* Only hands prefixes and devices to the link; the committer writes the chain when they changed. */
    bool sub = false, dev = false;
    rs->dev_narrowed = false;
    firc_err_t err = subnets_apply(rs, &sub);
    /* On a devices failure the subnets' change is still reported: the link already holds it. */
    if (err == FIRC_OK) { err = devices_apply(rs, &dev); }
    if (chain_changed) { *chain_changed = sub || dev; }
    return err;
}
