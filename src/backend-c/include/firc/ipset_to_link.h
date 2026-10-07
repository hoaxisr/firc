#ifndef FIRC_IPSET_TO_LINK_H
#define FIRC_IPSET_TO_LINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/err.h"
#include "firc/fakeip.h"
#include "firc/subnet.h"
#include "firc/iptables.h"
#include "firc/conntrack.h"
#include "firc/rtnl.h"

#define FIRC_IPSET_TO_LINK_BLACKHOLE "blackhole"

typedef struct firc_ipset_to_link firc_ipset_to_link_t;

typedef enum {
    FIRC_NF_SRC_ADDR = 1,
    FIRC_NF_SRC_MAC = 2,
    FIRC_NF_SRC_MARK = 3,
} firc_nf_src_kind_t;

/* Compared by what it renders, so padding and unused fields need no memset. */
typedef struct firc_nf_source {
    uint8_t kind;     /* firc_nf_src_kind_t */
    uint8_t family;   /* 4 or 6 */
    uint8_t prefix;   /* host bits cleared */
    uint8_t addr[16];
    uint8_t mac[6];
    uint32_t mark;
} firc_nf_source_t;

typedef struct firc_nf_devices {
    bool active;
    bool allow_all;
    firc_nf_source_t *deny;
    size_t n_deny;
    firc_nf_source_t *allow;
    size_t n_allow;
    size_t cap_deny;
    size_t cap_allow;
} firc_nf_devices_t;

/* FIRC_ERR_INVAL if `<chain>D` does not fit in cap. */
firc_err_t firc_ipset_to_link_devices_chain_of(const char *chain, char *out, size_t cap);

/* Pointers borrowed; ipt4/ipt6 nullable (not both), base chains already registered. Rules read from snap. */
firc_ipset_to_link_t *firc_ipset_to_link_new(const char *chain_name, const char *iface_name,
                                         firc_ipt_t *ipt4, firc_ipt_t *ipt6,
                                         firc_rtnl_t *rtnl, uint32_t start_idx,
                                             const firc_fakeip_t *pool, const char *group_id,
                                             const firc_fakeip_snapshot_t *(*snap)(void *ud),
                                             void *snap_ud);
void firc_ipset_to_link_free(firc_ipset_to_link_t *l);

/* Optional: where to drop the group's flows when its routing goes away. */
void firc_ipset_to_link_set_conntrack(firc_ipset_to_link_t *l, firc_ct_t *ct);

/* Drops flows whose mark has group_value plus the handled bit; no-op for NULL ct or zero value. */
void firc_ipset_to_link_flush_mark(firc_ct_t *ct, uint32_t group_value, const char *who);

/* The group field given at enable, or 0. */
uint32_t firc_ipset_to_link_mark_field(const firc_ipset_to_link_t *l);

bool firc_ipset_to_link_has_iface_route(const firc_ipset_to_link_t *l, int family);

/* Takes a copy of the subnet rules; call under the netfilter lock. *changed is nullable. */
firc_err_t firc_ipset_to_link_set_subnets(firc_ipset_to_link_t *l, const firc_ipv4_subnet_t *v4,
                                          size_t n4, const firc_ipv6_subnet_t *v6, size_t n6,
                                          bool *changed);

void firc_nf_devices_clear(firc_nf_devices_t *d);
/* Appends unless an equal-rendering source is there; FIRC_ERR_NOMEM. */
firc_err_t firc_nf_devices_push(firc_nf_devices_t *d, bool deny, const firc_nf_source_t *s);
bool firc_nf_devices_equal(const firc_nf_devices_t *a, const firc_nf_devices_t *b);
/* Whether `now` stops marking a device `was` marked (compared as rendered sets). */
bool firc_nf_devices_narrows(const firc_nf_devices_t *was, const firc_nf_devices_t *now);
/* dst is overwritten, not freed; FIRC_ERR_NOMEM leaves it zeroed. */
firc_err_t firc_nf_devices_copy(firc_nf_devices_t *dst, const firc_nf_devices_t *src);
/* Takes a copy; call under the netfilter lock. *changed is nullable. */
firc_err_t firc_ipset_to_link_set_devices(firc_ipset_to_link_t *l, const firc_nf_devices_t *d, bool *changed);
/* The copy set_devices last took; the loop thread may read it without the lock. */
const firc_nf_devices_t *firc_ipset_to_link_devices(const firc_ipset_to_link_t *l);

/* Re-stages and commits the group's chains; no-op unless enabled. Loop thread, under the netfilter lock. */
firc_err_t firc_ipset_to_link_rewrite_chains(firc_ipset_to_link_t *l);

/* Test seam: stages the rules as a rebuild would, without enable. */
firc_err_t firc_ipset_to_link_stage_for_test(firc_ipset_to_link_t *l);

/* One MARK and one CONNMARK per prefix of the engine's family. */
firc_err_t firc_ipset_to_link_build_subnet_rules(firc_ipt_t *ipt, const char *chain_name,
                                                 uint32_t mark, const firc_ipv4_subnet_t *v4,
                                                 size_t n4, const firc_ipv6_subnet_t *v6,
                                                 size_t n6);

/* Same, each rule jumping to the devices chain when dev is active. */
firc_err_t firc_ipset_to_link_build_subnet_rules_dev(firc_ipt_t *ipt, const char *chain_name, uint32_t mark,
                                                     const firc_ipv4_subnet_t *v4, size_t n4,
                                                     const firc_ipv6_subnet_t *v6, size_t n6,
                                                     const firc_nf_devices_t *dev);

/* Whether the group's flows survive its routing coming down. Callers must choose. */
typedef enum {
    FIRC_FLOWS_KEEP = 0,
    FIRC_FLOWS_DROP = 1,
} firc_flows_t;

/* NOW commits chains on this thread; BY_COMMITTER leaves chains to the committer but writes routes and rules. */
typedef enum {
    FIRC_NF_WRITE_NOW = 0,
    FIRC_NF_WRITE_BY_COMMITTER = 1,
} firc_nf_write_t;

/* On failure *step (nullable) names what failed; everything put in is taken back. */
firc_err_t firc_ipset_to_link_enable(firc_ipset_to_link_t *l, firc_nf_write_t mode, const char **step);
firc_err_t firc_ipset_to_link_disable(firc_ipset_to_link_t *l, firc_flows_t flows, firc_nf_write_t mode);

/* Stages (no commit) removal of the chain, its devices chain and their jumps. ipt NULL is FIRC_OK. */
firc_err_t firc_ipset_to_link_stage_delete(firc_ipt_t *ipt, const char *chain_name);

/* Stages removal of a devices chain alone. ipt NULL is FIRC_OK. */
firc_err_t firc_ipset_to_link_stage_delete_devices(firc_ipt_t *ipt, const char *devices_chain);

/* Re-stages the group's chains for a full rebuild without committing; no-op unless enabled. */
firc_err_t firc_ipset_to_link_prepare_iptables(firc_ipset_to_link_t *l);

/* The rules a group's chains carry, built without netlink (for tests). */
firc_err_t firc_ipset_to_link_build_rules(firc_ipt_t *ipt, const char *chain_name,
                                          const char *iface_name,
                                          uint32_t mark, uint32_t mark_field,
                                          const firc_fakeip_snapshot_t *snap,
                                          const char *group_id);

/* Same, with each chunk jumping to the devices chain when dev is active. */
firc_err_t firc_ipset_to_link_build_rules_dev(firc_ipt_t *ipt, const char *chain_name, const char *iface_name,
                                              uint32_t mark, uint32_t mark_field,
                                              const firc_fakeip_snapshot_t *snap, const char *group_id,
                                              const firc_nf_devices_t *dev);

/* Call for each link whose interface the netlink event was about. */
firc_err_t firc_ipset_to_link_on_link_up(firc_ipset_to_link_t *l);
firc_err_t firc_ipset_to_link_on_addr_change(firc_ipset_to_link_t *l);

#endif /* FIRC_IPSET_TO_LINK_H */
