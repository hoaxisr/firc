#ifndef FIRC_XTABLES_H
#define FIRC_XTABLES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/cancel.h"
#include "firc/err.h"
#include "firc/iptables.h"

#define FIRC_XT_NAME_LEN 32
#define FIRC_XT_NUMHOOKS 5
#define FIRC_XT_LOCK_WAIT_MS 200u

typedef struct firc_xt_info {
    uint32_t valid_hooks;
    uint32_t hook_entry[FIRC_XT_NUMHOOKS];
    uint32_t underflow[FIRC_XT_NUMHOOKS];
    uint32_t num_entries;
    uint32_t size;
} firc_xt_info_t;

typedef struct firc_xt_counter {
    uint64_t pcnt, bcnt;
} firc_xt_counter_t;

/* The kernel boundary: each returns 0 or an errno. */
typedef struct firc_xt_kernel_ops {
    int (*get_info)(void *ud, firc_ipt_proto_t fam, const char *table, firc_xt_info_t *out);
    int (*get_entries)(void *ud, firc_ipt_proto_t fam, const char *table, uint8_t *blob, uint32_t size);
    int (*replace)(void *ud, firc_ipt_proto_t fam, const char *table, const firc_xt_info_t *info,
                   const uint8_t *blob, uint32_t num_counters, firc_xt_counter_t *old_counters);
    int (*add_counters)(void *ud, firc_ipt_proto_t fam, const char *table,
                        const firc_xt_counter_t *counters, uint32_t n);
    int (*get_revision)(void *ud, firc_ipt_proto_t fam, bool target, const char *name, uint8_t revision);
    int (*lock)(void *ud, unsigned wait_ms);
    void (*unlock)(void *ud);
    void (*destroy)(void *ud);
} firc_xt_kernel_ops_t;

typedef enum firc_xt_stage_kind {
    FIRC_XT_STAGE_OVERRIDE = 0,
    FIRC_XT_STAGE_DELETE,
    FIRC_XT_STAGE_PATCH,
} firc_xt_stage_kind_t;

typedef struct firc_xt_patch_op {
    firc_ipt_option_t option;
    int rule_num;
    firc_ipt_rule_t *rule;
} firc_xt_patch_op_t;

/* One registered chain as the engine staged it; rules for an override, ops for a patch. */
typedef struct firc_xt_stage_chain {
    const char *name;
    firc_xt_stage_kind_t kind;
    firc_ipt_rule_t *const *rules;
    size_t n_rules;
    const firc_xt_patch_op_t *ops;
    size_t n_ops;
} firc_xt_stage_chain_t;

/* A table's staging; sweep_prefix non-NULL also drops every unstaged chain and jump of ours. */
typedef struct firc_xt_stage {
    const firc_xt_stage_chain_t *chains;
    size_t n_chains;
    const char *sweep_prefix;
} firc_xt_stage_t;

/* A handle over ops; ops->destroy(ud) runs at firc_xt_free. NULL when ops is NULL or memory runs out. */
firc_xt_t *firc_xt_new(firc_ipt_proto_t fam, const firc_xt_kernel_ops_t *ops, void *ud);
void firc_xt_free(firc_xt_t *xt);
firc_ipt_proto_t firc_xt_proto(const firc_xt_t *xt);

/* Asks for every extension revision the encoder writes; each missing one is logged at ERR. FIRC_ERR_NOSYS if any is. */
firc_err_t firc_xt_probe(firc_xt_t *xt);

/* At debug log level a refused table is written to dir/refused-<family>-<table>.bin; NULL turns it off. */
firc_err_t firc_xt_set_dump_dir(firc_xt_t *xt, const char *dir);

/* Reads table, merges stage, replaces the table when the result differs. AGAIN and CANCELED mean build it again. */
firc_err_t firc_xt_commit(firc_xt_t *xt, const char *table, const firc_xt_stage_t *stage, firc_cancel_t *cancel);

/* The kernel through a raw socket of the family; NULL with errno set when the socket cannot be opened. */
firc_xt_t *firc_xt_real_new(firc_ipt_proto_t fam);

#endif
