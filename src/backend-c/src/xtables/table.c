#include "xt_internal.h"

#include <stdio.h>
#include <stdlib.h>

bool firc_xt_entry_same(const firc_xt_entry_t *a, const firc_xt_entry_t *b) {
    return a->len == b->len && a->points_at == b->points_at && strcmp(a->jump, b->jump) == 0 &&
           memcmp(a->bytes, b->bytes, a->len) == 0;
}

static firc_err_t insert_rule(firc_xt_chain_t *c, size_t at, firc_xt_entry_t *e) {
    if (c->n_rules == c->cap_rules) {
        size_t cap = c->cap_rules ? c->cap_rules * 2 : 8;
        firc_xt_entry_t *grown = realloc(c->rules, cap * sizeof(*grown));
        if (grown == NULL) { return FIRC_ERR_NOMEM; }
        c->rules = grown;
        c->cap_rules = cap;
    }
    memmove(&c->rules[at + 1], &c->rules[at], (c->n_rules - at) * sizeof(*c->rules));
    c->rules[at] = *e;
    c->n_rules++;
    memset(e, 0, sizeof(*e));
    return FIRC_OK;
}

static void cut_rule(firc_xt_chain_t *c, size_t at) {
    firc_xt_entry_clear(&c->rules[at]);
    memmove(&c->rules[at], &c->rules[at + 1], (c->n_rules - at - 1) * sizeof(*c->rules));
    c->n_rules--;
}

static firc_err_t encode_one(firc_xt_table_t *t, const char *chain, const firc_ipt_rule_t *r, firc_xt_entry_t *e,
                             uint32_t *exts, char *why, size_t why_len) {
    firc_err_t err = firc_xt_encode(t->fam, r, e, exts);
    if (err == FIRC_ERR_INVAL) {
        char *words = firc_ipt_rule_string(r);
        snprintf(why, why_len, "the rule \"%s\" is outside what firc writes", words != NULL ? words : "");
        free(words);
        return err;
    }
    if (err != FIRC_OK || e->jump[0] == '\0') { return err; }
    const firc_xt_chain_t *to = firc_xt_find_chain(t, e->jump);
    if (to != NULL && to->hook >= 0) {
        snprintf(why, why_len, "a rule in %s jumps to %s, a built-in chain", chain, e->jump);
        firc_xt_entry_clear(e);
        return FIRC_ERR_INVAL;
    }
    return FIRC_OK;
}

static firc_err_t chain_for(firc_xt_table_t *t, const char *name, firc_xt_chain_t **c) {
    *c = firc_xt_find_chain(t, name);
    return *c != NULL ? FIRC_OK : firc_xt_add_user_chain(t, name, c);
}

static void clear_entries(firc_xt_entry_t *e, size_t n) {
    for (size_t i = 0; i < n; i++) { firc_xt_entry_clear(&e[i]); }
}

static firc_err_t do_override(firc_xt_table_t *t, const firc_xt_stage_chain_t *sc, uint32_t *exts, char *why,
                              size_t why_len) {
    size_t n = sc->n_rules;
    firc_xt_entry_t *fresh = calloc(n ? n : 1, sizeof(*fresh));
    if (fresh == NULL) { return FIRC_ERR_NOMEM; }
    for (size_t i = 0; i < n; i++) {
        firc_err_t err = encode_one(t, sc->name, sc->rules[i], &fresh[i], exts, why, why_len);
        if (err != FIRC_OK) {
            clear_entries(fresh, i);
            free(fresh);
            return err;
        }
    }
    firc_xt_chain_t *c = NULL;
    firc_err_t err = chain_for(t, sc->name, &c);
    if (err != FIRC_OK) {
        clear_entries(fresh, n);
        free(fresh);
        return err;
    }
    for (size_t i = 0; i < n && i < c->n_rules; i++) {
        if (firc_xt_entry_same(&fresh[i], &c->rules[i])) {
            fresh[i].old_index = c->rules[i].old_index;
            fresh[i].old_off = c->rules[i].old_off;
        }
    }
    clear_entries(c->rules, c->n_rules);
    free(c->rules);
    c->rules = fresh;
    c->n_rules = n;
    c->cap_rules = n ? n : 1;
    return FIRC_OK;
}

static firc_err_t do_patch(firc_xt_table_t *t, const firc_xt_stage_chain_t *sc, uint32_t *exts, char *why,
                           size_t why_len) {
    firc_xt_chain_t *c = NULL;
    firc_err_t err = chain_for(t, sc->name, &c);
    if (err != FIRC_OK) { return err; }
    for (size_t k = 0; k < sc->n_ops; k++) {
        const firc_xt_patch_op_t *op = &sc->ops[k];
        firc_xt_entry_t e;
        err = encode_one(t, sc->name, op->rule, &e, exts, why, why_len);
        if (err != FIRC_OK) { return err; }
        size_t count = 0;
        for (size_t r = 0; r < c->n_rules; r++) { count += firc_xt_entry_same(&c->rules[r], &e) ? 1u : 0u; }
        for (; count > 1; count--) {
            size_t r = 0;
            while (!firc_xt_entry_same(&c->rules[r], &e)) { r++; }
            cut_rule(c, r);
        }
        size_t at = 0;
        while (count == 1 && !firc_xt_entry_same(&c->rules[at], &e)) { at++; }
        switch (op->option) {
        case FIRC_IPT_OP_APPEND:
        case FIRC_IPT_OP_INSERT:
            if (count == 1) {
                c->rules[at].staged = true;
                break;
            }
            if (op->option == FIRC_IPT_OP_INSERT && (op->rule_num < 1 || (size_t)op->rule_num - 1 > c->n_rules)) {
                snprintf(why, why_len, "an insert at %d into %s, which has %zu rules", op->rule_num, c->name, c->n_rules);
                err = FIRC_ERR_INVAL;
                break;
            }
            e.staged = true;
            err = insert_rule(c, op->option == FIRC_IPT_OP_INSERT ? (size_t)op->rule_num - 1 : c->n_rules, &e);
            break;
        case FIRC_IPT_OP_DELETE:
            if (count == 1) { cut_rule(c, at); }
            break;
        default:
            snprintf(why, why_len, "a patch of %s carries an op firc does not write", c->name);
            err = FIRC_ERR_INVAL;
            break;
        }
        firc_xt_entry_clear(&e);
        if (err != FIRC_OK) { return err; }
    }
    return FIRC_OK;
}

static bool overridden(const firc_xt_stage_t *s, const char *name) {
    for (size_t i = 0; i < s->n_chains; i++) {
        if (s->chains[i].kind == FIRC_XT_STAGE_OVERRIDE && strcmp(s->chains[i].name, name) == 0) { return true; }
    }
    return false;
}

static void do_sweep(firc_xt_table_t *t, const firc_xt_stage_t *s) {
    const char *prefix = s->sweep_prefix;
    size_t plen = strlen(prefix);
    for (size_t i = t->n_chains; i-- > 0;) {
        firc_xt_chain_t *c = &t->chains[i];
        if (c->hook < 0 && strncmp(c->name, prefix, plen) == 0 && !overridden(s, c->name)) { (void)firc_xt_drop_chain(t, c); }
    }
    for (size_t i = 0; i < t->n_chains; i++) {
        firc_xt_chain_t *c = &t->chains[i];
        if (c->hook < 0 && strncmp(c->name, prefix, plen) == 0) { continue; }
        for (size_t r = c->n_rules; r-- > 0;) {
            const firc_xt_entry_t *e = &c->rules[r];
            if (e->jump[0] != '\0' && strncmp(e->jump, prefix, plen) == 0 && !e->staged) { cut_rule(c, r); }
        }
    }
}

firc_err_t firc_xt_merge(firc_xt_table_t *t, const firc_xt_stage_t *stage, uint32_t *exts, char *why, size_t why_len) {
    why[0] = '\0';
    for (size_t i = 0; i < stage->n_chains; i++) {
        const firc_xt_stage_chain_t *sc = &stage->chains[i];
        firc_err_t err = FIRC_OK;
        if (sc->kind == FIRC_XT_STAGE_DELETE) {
            firc_xt_chain_t *c = firc_xt_find_chain(t, sc->name);
            if (c != NULL && firc_xt_drop_chain(t, c) != FIRC_OK) {
                snprintf(why, why_len, "%s is a built-in chain and cannot be deleted", sc->name);
                err = FIRC_ERR_INVAL;
            }
        } else if (sc->kind == FIRC_XT_STAGE_OVERRIDE) {
            err = do_override(t, sc, exts, why, why_len);
        } else if (sc->kind == FIRC_XT_STAGE_PATCH) {
            err = do_patch(t, sc, exts, why, why_len);
        } else {
            snprintf(why, why_len, "%s is staged in a way firc does not write", sc->name);
            err = FIRC_ERR_INVAL;
        }
        if (err != FIRC_OK) { return err; }
    }
    if (stage->sweep_prefix != NULL && stage->sweep_prefix[0] != '\0') { do_sweep(t, stage); }
    return FIRC_OK;
}

bool firc_xt_blob_equal(const firc_xt_info_t *ai, const uint8_t *a, const firc_xt_info_t *bi, const uint8_t *b) {
    if (ai->valid_hooks != bi->valid_hooks || ai->num_entries != bi->num_entries || ai->size != bi->size) { return false; }
    for (int h = 0; h < FIRC_XT_NUMHOOKS; h++) {
        if (!(ai->valid_hooks & (1u << h))) { continue; }
        if (ai->hook_entry[h] != bi->hook_entry[h] || ai->underflow[h] != bi->underflow[h]) { return false; }
    }
    return memcmp(a, b, ai->size) == 0;
}

firc_err_t firc_xt_carry_counters(const int32_t *old_index, uint32_t n_new, const firc_xt_counter_t *old,
                                  uint32_t n_old, firc_xt_counter_t **out) {
    *out = calloc(n_new ? n_new : 1, sizeof(**out));
    if (*out == NULL) { return FIRC_ERR_NOMEM; }
    for (uint32_t i = 0; i < n_new; i++) {
        if (old_index[i] >= 0 && (uint32_t)old_index[i] < n_old) { (*out)[i] = old[old_index[i]]; }
    }
    return FIRC_OK;
}
