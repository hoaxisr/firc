#include "firc/iptables.h"
#include "firc/xtables.h"

#include <stdlib.h>
#include <string.h>

typedef struct chain_override {
    firc_ipt_chain_t base;
    firc_ipt_rule_t **rules;
    size_t n, cap;
} chain_override_t;

static firc_err_t override_compile(firc_ipt_chain_t *self, const char *chain_name,
                                 firc_ipt_rule_t *const *existing, size_t n_existing,
                                 firc_ipt_command_t **out_cmds, size_t *out_n,
                                 int8_t *out_priority) {
    chain_override_t *c = (chain_override_t *)self;
    *out_cmds = NULL;
    *out_n = 0;
    *out_priority = -128;

    if (existing != NULL && n_existing == c->n) {
        bool match = true;
        for (size_t i = 0; i < c->n; i++) {
            if (!firc_ipt_rule_equal(c->rules[i], existing[i])) {
                match = false;
                break;
            }
        }
        if (match) { return FIRC_OK; }
    }

    firc_ipt_command_t *cmds = calloc(c->n + 1, sizeof(*cmds));
    if (!cmds) { return FIRC_ERR_NOMEM; }

    cmds[0].option = FIRC_IPT_OP_FLUSH;
    cmds[0].chain = strdup(chain_name);
    cmds[0].rule = NULL;
    if (!cmds[0].chain) {
        free(cmds);
        return FIRC_ERR_NOMEM;
    }

    for (size_t i = 0; i < c->n; i++) {
        cmds[i + 1].option = FIRC_IPT_OP_APPEND;
        cmds[i + 1].chain = strdup(chain_name);
        cmds[i + 1].rule = firc_ipt_rule_clone(c->rules[i]);
        if (!cmds[i + 1].chain || !cmds[i + 1].rule) {
            firc_ipt_command_list_free(cmds, i + 2);
            return FIRC_ERR_NOMEM;
        }
    }

    *out_cmds = cmds;
    *out_n = c->n + 1;
    return FIRC_OK;
}

static firc_err_t override_append(firc_ipt_chain_t *self, const firc_ipt_rule_t *rule) {
    chain_override_t *c = (chain_override_t *)self;
    if (c->n + 1 > c->cap) {
        size_t newcap = c->cap == 0 ? 8 : c->cap * 2;
        firc_ipt_rule_t **tmp = realloc(c->rules, newcap * sizeof(*tmp));
        if (!tmp) { return FIRC_ERR_NOMEM; }
        c->rules = tmp;
        c->cap = newcap;
    }
    firc_ipt_rule_t *owned = firc_ipt_rule_clone(rule);
    if (!owned) { return FIRC_ERR_NOMEM; }
    c->rules[c->n++] = owned;
    return FIRC_OK;
}

static void override_stage(firc_ipt_chain_t *self, firc_xt_stage_chain_t *out) {
    chain_override_t *c = (chain_override_t *)self;
    out->kind = FIRC_XT_STAGE_OVERRIDE;
    out->rules = c->rules;
    out->n_rules = c->n;
    out->ops = NULL;
    out->n_ops = 0;
}

static void override_destroy(firc_ipt_chain_t *self) {
    chain_override_t *c = (chain_override_t *)self;
    if (!c) { return; }
    for (size_t i = 0; i < c->n; i++) { firc_ipt_rule_free(c->rules[i]); }
    free(c->rules);
    free(c);
}

static const firc_ipt_chain_ops_t k_override_ops = {
    .compile = override_compile,
    .append = override_append,
    .destroy = override_destroy,
    .stage = override_stage,
};

firc_ipt_chain_t *firc_ipt_chain_override_new(void) {
    chain_override_t *c = calloc(1, sizeof(*c));
    if (!c) { return NULL; }
    c->base.ops = &k_override_ops;
    return &c->base;
}
