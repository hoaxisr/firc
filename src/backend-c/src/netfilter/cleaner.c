#include "firc/netfilter_cleaner.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "firc/pool_reject.h"

/* The barrier survives every sweep; the next pass rewrites it in place. */
static bool is_barrier_chain(const char *chain) {
    size_t n = strlen(chain), m = strlen(FIRC_POOL_REJECT_CHAIN_SUFFIX);
    return n >= m && strcmp(chain + n - m, FIRC_POOL_REJECT_CHAIN_SUFFIX) == 0;
}

static firc_err_t clean_one(firc_ipt_t *ipt, const char *chain_prefix, bool keep_barrier) {
    if (!ipt) { return FIRC_OK; }

    char jump[128];
    snprintf(jump, sizeof(jump), "-j %s", chain_prefix);
    size_t prefix_len = strlen(chain_prefix);

    firc_err_t err = firc_ipt_register_sweep(ipt, "nat", chain_prefix);
    if (err == FIRC_OK) { err = firc_ipt_commit_nat(ipt); }
    if (err != FIRC_OK) { return err; }

    static const char *const k_text_tables[] = {"filter", "mangle"};
    firc_ipt_rules_snapshot_t *snap;
    err = firc_ipt_get_current_rules(ipt, k_text_tables, 2, &snap);
    if (err != FIRC_OK) { return err; }

    for (size_t ti = 0; ti < snap->n_tables && err == FIRC_OK; ti++) {
        const firc_ipt_table_rules_t *t = &snap->tables[ti];
        for (size_t ci = 0; ci < t->n_chains && err == FIRC_OK; ci++) {
            const firc_ipt_chain_rules_t *c = &t->chains[ci];

            if (strncmp(c->chain_name, chain_prefix, prefix_len) == 0) {
                if (keep_barrier && is_barrier_chain(c->chain_name)) { continue; }
                err = firc_ipt_register_chain_delete(ipt, t->table_name, c->chain_name);
                continue;
            }

            for (size_t ri = 0; ri < c->n_rules && err == FIRC_OK; ri++) {
                firc_ipt_rule_t *r = c->rules[ri];
                if (!firc_ipt_rule_contains(r, jump)) { continue; }
                if (keep_barrier && r->n_parts >= 2 && is_barrier_chain(r->parts[r->n_parts - 1])) { continue; }

                err = firc_ipt_delete(ipt, t->table_name, c->chain_name,
                                    (const char *const *)r->parts, r->n_parts);
                if (firc_ipt_err_is_chain_not_initialized(err)) {
                    err = firc_ipt_register_chain_patch(ipt, t->table_name, c->chain_name);
                    if (err == FIRC_OK) {
                        err = firc_ipt_delete(ipt, t->table_name, c->chain_name,
                                           (const char *const *)r->parts, r->n_parts);
                    }
                }
            }
        }
    }

    firc_ipt_rules_snapshot_free(snap);
    if (err != FIRC_OK) { return err; }
    return firc_ipt_commit_text(ipt);
}

firc_err_t firc_netfilter_clean_iptables(firc_ipt_t *ipt4, firc_ipt_t *ipt6, const char *chain_prefix) {
    firc_err_t e1 = clean_one(ipt4, chain_prefix, true);
    firc_err_t e2 = clean_one(ipt6, chain_prefix, true);
    return e1 != FIRC_OK ? e1 : e2;
}

firc_err_t firc_netfilter_purge_iptables(firc_ipt_t *ipt4, firc_ipt_t *ipt6, const char *chain_prefix) {
    firc_err_t e1 = clean_one(ipt4, chain_prefix, false);
    firc_err_t e2 = clean_one(ipt6, chain_prefix, false);
    return e1 != FIRC_OK ? e1 : e2;
}

firc_err_t firc_netfilter_register_base_chains(firc_ipt_t *ipt4, firc_ipt_t *ipt6) {
    static const struct {
        const char *table;
        const char *chain;
    } base[] = {
        {"filter", "FORWARD"},
        {"mangle", "PREROUTING"},
        {"nat", "PREROUTING"},
        {"nat", "POSTROUTING"},
    };

    firc_ipt_t *ipts[2] = {ipt4, ipt6};
    for (size_t i = 0; i < 2; i++) {
        if (!ipts[i]) { continue; }
        for (size_t b = 0; b < sizeof(base) / sizeof(base[0]); b++) {
            firc_err_t err = firc_ipt_register_chain_patch(ipts[i], base[b].table, base[b].chain);
            if (err != FIRC_OK) { return err; }
        }
    }
    return FIRC_OK;
}

#define RETRY_ATTEMPTS 3

firc_err_t firc_netfilter_retry_races(firc_err_t (*step)(void *ud), void *ud) {
    firc_err_t err = FIRC_ERR_AGAIN;
    for (int attempt = 0; attempt < RETRY_ATTEMPTS && (err == FIRC_ERR_AGAIN || err == FIRC_ERR_CANCELED);
         attempt++) {
        if (attempt > 0) {
            struct timespec pause = {0, 200 * 1000 * 1000};
            nanosleep(&pause, NULL);
        }
        err = step(ud);
    }
    return err;
}

typedef struct {
    firc_ipt_t *ipt4, *ipt6;
    const char *prefix;
} clean_args_t;

static firc_err_t clean_step(void *ud) {
    const clean_args_t *a = ud;
    return firc_netfilter_clean_iptables(a->ipt4, a->ipt6, a->prefix);
}

static firc_err_t purge_step(void *ud) {
    const clean_args_t *a = ud;
    return firc_netfilter_purge_iptables(a->ipt4, a->ipt6, a->prefix);
}

firc_err_t firc_netfilter_clean_iptables_retrying(firc_ipt_t *ipt4, firc_ipt_t *ipt6, const char *chain_prefix) {
    clean_args_t a = {ipt4, ipt6, chain_prefix};
    return firc_netfilter_retry_races(clean_step, &a);
}

firc_err_t firc_netfilter_purge_iptables_retrying(firc_ipt_t *ipt4, firc_ipt_t *ipt6, const char *chain_prefix) {
    clean_args_t a = {ipt4, ipt6, chain_prefix};
    return firc_netfilter_retry_races(purge_step, &a);
}
