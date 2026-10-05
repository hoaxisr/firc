#include "firc/iptables.h"

#include <stdlib.h>
#include <string.h>

typedef struct chain_delete {
    firc_ipt_chain_t base;
} chain_delete_t;

static firc_err_t delete_compile(firc_ipt_chain_t *self, const char *chain_name,
                               firc_ipt_rule_t *const *existing, size_t n_existing,
                               firc_ipt_command_t **out_cmds, size_t *out_n,
                               int8_t *out_priority) {
    (void)self;
    (void)n_existing;
    *out_priority = 127;
    *out_cmds = NULL;
    *out_n = 0;

    if (existing == NULL) { return FIRC_OK; }

    firc_ipt_command_t *cmds = calloc(2, sizeof(*cmds));
    if (!cmds) { return FIRC_ERR_NOMEM; }

    cmds[0].option = FIRC_IPT_OP_FLUSH;
    cmds[0].chain = strdup(chain_name);
    cmds[1].option = FIRC_IPT_OP_DELETE_CHAIN;
    cmds[1].chain = strdup(chain_name);
    if (!cmds[0].chain || !cmds[1].chain) {
        firc_ipt_command_list_free(cmds, 2);
        return FIRC_ERR_NOMEM;
    }

    *out_cmds = cmds;
    *out_n = 2;
    return FIRC_OK;
}

static firc_err_t delete_noop_append(firc_ipt_chain_t *self, const firc_ipt_rule_t *rule) {
    (void)self;
    (void)rule;
    return FIRC_OK;
}

static firc_err_t delete_noop_insert(firc_ipt_chain_t *self, int rule_num, const firc_ipt_rule_t *rule) {
    (void)self;
    (void)rule_num;
    (void)rule;
    return FIRC_OK;
}

static firc_err_t delete_noop_remove(firc_ipt_chain_t *self, const firc_ipt_rule_t *rule) {
    (void)self;
    (void)rule;
    return FIRC_OK;
}

static void delete_destroy(firc_ipt_chain_t *self) {
    free(self);
}

static const firc_ipt_chain_ops_t k_delete_ops = {
    .compile = delete_compile,
    .append = delete_noop_append,
    .insert = delete_noop_insert,
    .remove = delete_noop_remove,
    .destroy = delete_destroy,
};

firc_ipt_chain_t *firc_ipt_chain_delete_new(void) {
    chain_delete_t *c = calloc(1, sizeof(*c));
    if (!c) { return NULL; }
    c->base.ops = &k_delete_ops;
    return &c->base;
}
