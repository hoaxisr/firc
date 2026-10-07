#ifndef FIRC_RULESET_H
#define FIRC_RULESET_H

#include <stdbool.h>
#include <stdint.h>

#include "firc/fakeip.h"
#include "firc/err.h"
#include "firc/ipset_to_link.h"
#include "firc/iptables.h"
#include "firc/models.h"
#include "firc/conntrack.h"
#include "firc/devices.h"
#include "firc/rtnl.h"

typedef struct firc_ruleset firc_ruleset_t;

/* Selector lookups; every function nullable. Called on the loop thread only. */
typedef struct firc_ruleset_lookup {
    firc_devsel_mark_fn policy_mark;
    firc_devsel_hosts_fn host_addrs;
    firc_devsel_policy_hosts_fn policy_hosts;
    firc_devsel_policy_nets_fn policy_nets;
    void *ud;
    bool (*policies_read)(void *ud);
} firc_ruleset_lookup_t;

/* All pointers borrowed and must outlive every ruleset built with them; pool, ct, lookup nullable. */
typedef struct firc_ruleset_deps {
    const firc_fakeip_t *pool;
    const firc_fakeip_snapshot_t *(*snap)(void *ud);
    void *snap_ud;
    firc_ipt_t *ipt4;
    firc_ipt_t *ipt6;
    firc_rtnl_t *rtnl;
    firc_ct_t *ct;
    const char *chain_prefix;
    uint32_t start_idx;
    const firc_ruleset_lookup_t *lookup;
} firc_ruleset_deps_t;

/* group borrowed (must outlive the ruleset); deps copied. Mutated on the loop thread only. */
firc_ruleset_t *firc_ruleset_new(const firc_group_t *group, const firc_ruleset_deps_t *deps);
void firc_ruleset_free(firc_ruleset_t *rs);

const firc_group_t *firc_ruleset_group(const firc_ruleset_t *rs);
/* Shifted group field (firc_mark_group_value), or 0 when not in the kernel. */
uint32_t firc_ruleset_mark_field(const firc_ruleset_t *rs);
bool firc_ruleset_has_iface_route(const firc_ruleset_t *rs, int family);
firc_group_t *firc_ruleset_group_mut(firc_ruleset_t *rs);
bool firc_ruleset_runtime_enabled(const firc_ruleset_t *rs);
/* Retry state for a failed enable; kept here, read and written by the app on the loop. */
typedef struct firc_ruleset_retry {
    uint32_t backoff_ms; /* 0: no failure since the last enable that held */
    uint64_t at_ms;      /* monotonic ms */
    bool warned;
} firc_ruleset_retry_t;
firc_ruleset_retry_t *firc_ruleset_retry(firc_ruleset_t *rs);
/* Enabled at runtime and in config, holding its link; only routed groups get DNAT rules. */
bool firc_ruleset_routed(const firc_ruleset_t *rs);
/* Enabled at runtime and in config; may be in the DNS view without being routed. */
bool firc_ruleset_in_view(const firc_ruleset_t *rs);
void firc_ruleset_chain_name_for(const char *prefix, firc_id_t id, char *out, size_t cap);
/* "" when it does not fit in cap. */
void firc_ruleset_devices_chain_name_for(const char *prefix, firc_id_t id, char *out, size_t cap);

/* `mode` and `step` as firc_ipset_to_link_enable, plus "memory". */
firc_err_t firc_ruleset_enable(firc_ruleset_t *rs, firc_nf_write_t mode, const char **step);
/* FIRC_FLOWS_KEEP unless the group's packets should stop going where they go. */
firc_err_t firc_ruleset_disable(firc_ruleset_t *rs, firc_flows_t flows, firc_nf_write_t mode);

/* Re-stages the chains for a full rebuild; ip rule and routes are left alone. No-op unless enabled. */
firc_err_t firc_ruleset_prepare_iptables(firc_ruleset_t *rs);

/* Hands the subnet prefixes and devices to the link; the next pass writes them. *chain_changed is set even on error. */
firc_err_t firc_ruleset_sync(firc_ruleset_t *rs, bool *chain_changed);

/* Renders a selector into a devices chain; *out is filled from zero and the caller clears it. */
firc_err_t firc_ruleset_render_devices(const firc_group_t *g, const firc_ruleset_lookup_t *lk,
                                       firc_nf_devices_t *out);
bool firc_ruleset_has_devices(const firc_ruleset_t *rs);
bool firc_ruleset_devices_follow_table(const firc_ruleset_t *rs);
/* Re-renders a routed group's devices chain; loop thread, under the netfilter lock. */
firc_err_t firc_ruleset_refresh_devices(firc_ruleset_t *rs, bool *changed);
/* Render-and-compare only; loop thread, no lock needed. */
firc_err_t firc_ruleset_devices_would_move(const firc_ruleset_t *rs, bool *moved);
/* Whether the last sync or refresh dropped a device the old chain marked; false after enable. */
bool firc_ruleset_devices_narrowed(const firc_ruleset_t *rs);
/* NULL while not routed; loop thread only. */
const firc_nf_devices_t *firc_ruleset_devices(const firc_ruleset_t *rs);

/* Test seam: proto is 0, IPPROTO_TCP or IPPROTO_UDP; ports in iptables form, "" for all. */
typedef void (*firc_ruleset_plan_fn)(int family, const uint8_t *addr, uint8_t cidr, uint8_t proto, const char *ports,
                                     void *ud);

/* Re-stages and commits the chains synchronously, for a daemon without a committer. No-op unless enabled. */
firc_err_t firc_ruleset_rewrite_chains(firc_ruleset_t *rs);

firc_err_t firc_ruleset_plan_subnets(const firc_group_t *g, firc_ruleset_plan_fn fn, void *ud);

/* Call only for rulesets whose interface the netlink event names. */
firc_err_t firc_ruleset_on_link_up(firc_ruleset_t *rs);
firc_err_t firc_ruleset_on_addr_change(firc_ruleset_t *rs);

#endif /* FIRC_RULESET_H */
