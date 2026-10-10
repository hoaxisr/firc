#ifndef FIRC_IPTABLES_H
#define FIRC_IPTABLES_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "firc/cancel.h"
#include "firc/err.h"

typedef enum firc_ipt_proto {
    FIRC_IPT_PROTO_IPV4 = 0,
    FIRC_IPT_PROTO_IPV6 = 1,
} firc_ipt_proto_t;

typedef struct firc_xt firc_xt_t;
struct firc_xt_stage_chain;

/* argv-style rule parts, each owned. */
typedef struct firc_ipt_rule {
    char **parts;
    size_t n_parts;
} firc_ipt_rule_t;

firc_ipt_rule_t *firc_ipt_rule_new(const char *const *args, size_t n_args);
firc_ipt_rule_t *firc_ipt_rule_clone(const firc_ipt_rule_t *r);
void firc_ipt_rule_free(firc_ipt_rule_t *r);
bool firc_ipt_rule_equal(const firc_ipt_rule_t *a, const firc_ipt_rule_t *b);
char *firc_ipt_rule_string(const firc_ipt_rule_t *r);
bool firc_ipt_rule_contains(const firc_ipt_rule_t *r, const char *substr);

typedef struct firc_ipt_executable firc_ipt_executable_t;

typedef struct firc_ipt_executable_ops {
    /* *out is malloc'd, not NUL-terminated. */
    firc_err_t (*save)(firc_ipt_executable_t *self, const char *table, uint8_t **out, size_t *out_len);
    firc_err_t (*restore)(firc_ipt_executable_t *self, const uint8_t *data, size_t len);
    firc_ipt_proto_t (*proto)(firc_ipt_executable_t *self);
    void (*destroy)(firc_ipt_executable_t *self);
    /* Optional: a token whose raise kills an in-flight transfer. */
    void (*set_cancel)(firc_ipt_executable_t *self, firc_cancel_t *cancel);
} firc_ipt_executable_ops_t;

struct firc_ipt_executable {
    const firc_ipt_executable_ops_t *ops;
};

/* True when iptables-restore's stderr says another writer raced us; len-bounded, not NUL-terminated. */
bool firc_ipt_stderr_is_retryable(const char *stderr_text, size_t len);

/* Forks (ip6)iptables-save / -restore --noflush via execvp, no shell. */
firc_ipt_executable_t *firc_ipt_executable_real_new(firc_ipt_proto_t proto);

/* The transcript line a "line N failed" stderr names, pointing into data; NULL if none. */
const char *firc_ipt_offending_line(const uint8_t *data, size_t len, const char *stderr_text,
                                    size_t stderr_len, size_t *out_len);

static inline void firc_ipt_executable_free(firc_ipt_executable_t *exe) {
    if (exe) { exe->ops->destroy(exe); }
}

typedef enum firc_ipt_option {
    FIRC_IPT_OP_APPEND = 0,
    FIRC_IPT_OP_DELETE,
    FIRC_IPT_OP_INSERT,
    FIRC_IPT_OP_FLUSH,
    FIRC_IPT_OP_DELETE_CHAIN,
} firc_ipt_option_t;

typedef struct firc_ipt_command {
    firc_ipt_option_t option;
    char *chain;
    int rule_num;
    firc_ipt_rule_t *rule; /* NULL for FLUSH/DELETE_CHAIN */
} firc_ipt_command_t;

void firc_ipt_command_list_free(firc_ipt_command_t *cmds, size_t n);

typedef struct firc_ipt_chain firc_ipt_chain_t;

typedef struct firc_ipt_chain_ops {
    /* existing NULL: chain absent. *out_priority orders chains in commit (patch 0, override -128, delete 127).
     * append, insert and remove may be NULL: the kind does not take that operation. */
    firc_err_t (*compile)(firc_ipt_chain_t *self, const char *chain_name,
                         firc_ipt_rule_t *const *existing, size_t n_existing,
                         firc_ipt_command_t **out_cmds, size_t *out_n,
                         int8_t *out_priority);
    firc_err_t (*append)(firc_ipt_chain_t *self, const firc_ipt_rule_t *rule);
    firc_err_t (*insert)(firc_ipt_chain_t *self, int rule_num, const firc_ipt_rule_t *rule);
    firc_err_t (*remove)(firc_ipt_chain_t *self, const firc_ipt_rule_t *rule);
    void (*destroy)(firc_ipt_chain_t *self);
    /* The registration as staged, for a table x_tables writes; out->name is the engine's. */
    void (*stage)(firc_ipt_chain_t *self, struct firc_xt_stage_chain *out);
} firc_ipt_chain_ops_t;

struct firc_ipt_chain {
    const firc_ipt_chain_ops_t *ops;
};

firc_ipt_chain_t *firc_ipt_chain_patch_new(void);
firc_ipt_chain_t *firc_ipt_chain_override_new(void);
firc_ipt_chain_t *firc_ipt_chain_delete_new(void);

typedef struct firc_ipt firc_ipt_t;

/* Takes exe and xt on success (xt NULL: this engine never stages nat). Not thread-safe: one thread per firc_ipt_t. */
firc_ipt_t *firc_ipt_new(firc_ipt_executable_t *exe, firc_xt_t *xt);

/* Writes data as is with restore --noflush, outside any registration; iptables --test is no substitute. */
firc_err_t firc_ipt_write_transcript(firc_ipt_t *ipt, const uint8_t *data, size_t len);
void firc_ipt_free(firc_ipt_t *ipt);
firc_ipt_proto_t firc_ipt_proto(const firc_ipt_t *ipt);

/* Borrowed token, NULL detaches; a raised token makes commit return FIRC_ERR_CANCELED with staging intact. */
void firc_ipt_set_cancel(firc_ipt_t *ipt, firc_cancel_t *cancel);

/* Drops every registration and staged rule; call after an aborted pass. Keeps what was last written. */
void firc_ipt_discard(firc_ipt_t *ipt);

/* The next commit reads and compares every table it has work for, as a full pass must. */
void firc_ipt_forget_written(firc_ipt_t *ipt);

/* Per table, what the commits since the last call did ("mangle 12 ms, nat skipped"); then empties it. */
void firc_ipt_take_report(firc_ipt_t *ipt, char *out, size_t cap);

/* Registering a chain again replaces it and drops its staged rules. */
firc_err_t firc_ipt_register_chain_delete(firc_ipt_t *ipt, const char *table, const char *chain);
firc_err_t firc_ipt_register_chain_patch(firc_ipt_t *ipt, const char *table, const char *chain);
firc_err_t firc_ipt_register_chain_override(firc_ipt_t *ipt, const char *table, const char *chain);
/* nat only: the next commit also drops every chain of ours it does not override and every jump into one it does not stage. */
firc_err_t firc_ipt_register_sweep(firc_ipt_t *ipt, const char *table, const char *prefix);

/* FIRC_ERR_STATE when the chain was never registered. */
firc_err_t firc_ipt_append(firc_ipt_t *ipt, const char *table, const char *chain,
                       const char *const *args, size_t n_args);
firc_err_t firc_ipt_insert(firc_ipt_t *ipt, const char *table, const char *chain,
                       int rule_num, const char *const *args, size_t n_args);
firc_err_t firc_ipt_delete(firc_ipt_t *ipt, const char *table, const char *chain,
                       const char *const *args, size_t n_args);
/* True when err came from appending to an unregistered chain. */
bool firc_ipt_err_is_chain_not_initialized(firc_err_t err);

typedef struct firc_ipt_chain_rules {
    char *chain_name;
    firc_ipt_rule_t **rules; /* NULL/0: declared but empty */
    size_t n_rules;
} firc_ipt_chain_rules_t;

typedef struct firc_ipt_table_rules {
    char *table_name;
    firc_ipt_chain_rules_t *chains;
    size_t n_chains;
} firc_ipt_table_rules_t;

typedef struct firc_ipt_rules_snapshot {
    firc_ipt_table_rules_t *tables;
    size_t n_tables;
} firc_ipt_rules_snapshot_t;

const firc_ipt_table_rules_t *firc_ipt_rules_snapshot_find_table(
    const firc_ipt_rules_snapshot_t *snap, const char *table_name);
/* NULL when the chain is absent, unlike a declared-but-empty one. */
const firc_ipt_chain_rules_t *firc_ipt_table_rules_find_chain(
    const firc_ipt_table_rules_t *table, const char *chain_name);

firc_err_t firc_ipt_get_current_rules(firc_ipt_t *ipt, const char *const *tables, size_t n_tables,
                                      firc_ipt_rules_snapshot_t **out);
void firc_ipt_rules_snapshot_free(firc_ipt_rules_snapshot_t *snap);

/* filter and mangle in one restore, then nat through x_tables (FIRC_ERR_STATE without a handle); FIRC_ERR_CANCELED/AGAIN mean rebuild. */
firc_err_t firc_ipt_commit(firc_ipt_t *ipt);

#endif /* FIRC_IPTABLES_H */
