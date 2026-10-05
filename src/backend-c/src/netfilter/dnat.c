#include "firc/dnat.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

typedef struct {
    firc_ipt_t *ipt;
    const char *chain;
    uint8_t want_len; /* 4 or 16 */
    firc_err_t err;
    firc_dnat_routed_fn routed; /* NULL: every group */
    void *routed_ud;
} emit_ctx_t;

static bool to_text(const firc_ip_t *a, char *out, size_t out_len) {
    return inet_ntop(a->len == 4 ? AF_INET : AF_INET6, a->b, out, (socklen_t)out_len) != NULL;
}

static void emit_mapping(void *ud, const char *group_id, unsigned family, const firc_ip_t *fake,
                         const firc_ip_t *real) {
    emit_ctx_t *e = ud;
    (void)family;
    if (e->err != FIRC_OK) { return; }
    if (fake == NULL || fake->len != e->want_len) { return; }
    if (e->routed != NULL && (group_id == NULL || !e->routed(group_id, e->routed_ud))) { return; }
    if (real == NULL) { return; }
    /* Redundant given the pool's contract; a mixed family would fail the whole restore. */
    if (real->len != e->want_len) { return; }

    char fake_s[INET6_ADDRSTRLEN], real_s[INET6_ADDRSTRLEN];
    if (!to_text(fake, fake_s, sizeof(fake_s)) || !to_text(real, real_s, sizeof(real_s))) {
        e->err = FIRC_ERR_INVAL;
        return;
    }

    char dst[INET6_ADDRSTRLEN + 8];
    if (snprintf(dst, sizeof(dst), "%s/%d", fake_s, e->want_len == 4 ? 32 : 128) >=
        (int)sizeof(dst)) {
        e->err = FIRC_ERR_INVAL;
        return;
    }

    const char *args[] = {"-d", dst, "-j", "DNAT", "--to-destination", real_s};
    e->err = firc_ipt_append(e->ipt, "nat", e->chain, args, 6);
}

firc_err_t firc_dnat_build_rules(firc_ipt_t *ipt, const char *chain_prefix,
                                 const firc_fakeip_snapshot_t *snap,
                                 firc_dnat_routed_fn routed, void *routed_ud) {
    if (ipt == NULL || chain_prefix == NULL) { return FIRC_ERR_INVAL; }

    char chain[128];
    if (snprintf(chain, sizeof(chain), "%s%s", chain_prefix, FIRC_DNAT_CHAIN_SUFFIX) >=
        (int)sizeof(chain)) {
        return FIRC_ERR_INVAL;
    }

    /* Override, not patch: a pass emits the whole chain, and patching it is quadratic. */
    firc_err_t err = firc_ipt_register_chain_override(ipt, "nat", chain);
    if (err != FIRC_OK) { return err; }

    bool v6 = firc_ipt_proto(ipt) == FIRC_IPT_PROTO_IPV6;
    unsigned family = v6 ? FIRC_FAM_V6 : FIRC_FAM_V4;
    uint8_t want_len = v6 ? 16 : 4;

    /* Without a pool the chain is staged empty for a later pass to fill. */
    if (snap != NULL) {
        firc_ip_t base;
        uint8_t prefix = 0;
        if (firc_fakeip_snapshot_pool_prefix(snap, family, &base, &prefix)) {
            char addr[INET6_ADDRSTRLEN], cidr[INET6_ADDRSTRLEN + 8];
            if (!to_text(&base, addr, sizeof(addr)) ||
                snprintf(cidr, sizeof(cidr), "%s/%u", addr, prefix) >= (int)sizeof(cidr)) {
                return FIRC_ERR_INVAL;
            }
            const char *jump[] = {"-d", cidr, "-j", chain};
            err = firc_ipt_append(ipt, "nat", "PREROUTING", jump, 4);
            if (err != FIRC_OK) { return err; }
        }

        emit_ctx_t e = {.ipt = ipt, .chain = chain, .want_len = want_len, .err = FIRC_OK,
                        .routed = routed, .routed_ud = routed_ud};
        firc_fakeip_snapshot_walk(snap, emit_mapping, &e);
        if (e.err != FIRC_OK) { return e.err; }
    }
    return FIRC_OK;
}

firc_err_t firc_dnat_delete_rules(firc_ipt_t *ipt, const char *chain_prefix,
                                  const firc_fakeip_snapshot_t *snap) {
    if (ipt == NULL || chain_prefix == NULL) { return FIRC_ERR_INVAL; }
    char chain[128];
    if (snprintf(chain, sizeof(chain), "%s%s", chain_prefix, FIRC_DNAT_CHAIN_SUFFIX) >=
        (int)sizeof(chain)) {
        return FIRC_ERR_INVAL;
    }
    firc_err_t err = firc_ipt_register_chain_delete(ipt, "nat", chain);
    if (err != FIRC_OK) { return err; }
    if (snap == NULL) { return FIRC_OK; }
    bool v6 = firc_ipt_proto(ipt) == FIRC_IPT_PROTO_IPV6;
    firc_ip_t base;
    uint8_t prefix = 0;
    if (!firc_fakeip_snapshot_pool_prefix(snap, v6 ? FIRC_FAM_V6 : FIRC_FAM_V4, &base, &prefix)) {
        return FIRC_OK;
    }
    char addr[INET6_ADDRSTRLEN], cidr[INET6_ADDRSTRLEN + 8];
    if (!to_text(&base, addr, sizeof(addr)) ||
        snprintf(cidr, sizeof(cidr), "%s/%u", addr, prefix) >= (int)sizeof(cidr)) {
        return FIRC_ERR_INVAL;
    }
    const char *jump[] = {"-d", cidr, "-j", chain};
    err = firc_ipt_delete(ipt, "nat", "PREROUTING", jump, 4);
    return err == FIRC_ERR_NOENT ? FIRC_OK : err;
}
