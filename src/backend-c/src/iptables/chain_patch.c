#include "firc/iptables.h"

#include <stdlib.h>
#include <string.h>

typedef struct patch_entry {
    firc_ipt_option_t option;
    int rule_num;
    firc_ipt_rule_t *rule;
} patch_entry_t;

typedef struct chain_patch {
    firc_ipt_chain_t base;
    patch_entry_t *entries;
    size_t n, cap;
} chain_patch_t;

static firc_err_t add_rule(chain_patch_t *c, firc_ipt_option_t option, int rule_num,
                         const firc_ipt_rule_t *rule) {
    firc_ipt_rule_t *owned = firc_ipt_rule_clone(rule);
    if (!owned) { return FIRC_ERR_NOMEM; }

    size_t shifted = 0;
    for (size_t i = 0; i < c->n; i++) {
        if (firc_ipt_rule_equal(c->entries[i].rule, owned)) {
            firc_ipt_rule_free(c->entries[i].rule);
            continue;
        }
        if (shifted != i) { c->entries[shifted] = c->entries[i]; }
        shifted++;
    }
    c->n = shifted;

    if (c->n + 1 > c->cap) {
        size_t newcap = c->cap == 0 ? 8 : c->cap * 2;
        patch_entry_t *tmp = realloc(c->entries, newcap * sizeof(*tmp));
        if (!tmp) {
            firc_ipt_rule_free(owned);
            return FIRC_ERR_NOMEM;
        }
        c->entries = tmp;
        c->cap = newcap;
    }
    c->entries[c->n].option = option;
    c->entries[c->n].rule_num = rule_num;
    c->entries[c->n].rule = owned;
    c->n++;
    return FIRC_OK;
}

typedef struct str_count {
    char *key;
    uint32_t count;
} str_count_t;

static str_count_t *count_lookup(str_count_t *map, size_t map_n, const char *key) {
    for (size_t i = 0; i < map_n; i++) {
        if (strcmp(map[i].key, key) == 0) { return &map[i]; }
    }
    return NULL;
}

static firc_err_t count_bump(str_count_t **map, size_t *map_n, size_t *map_cap,
                           const char *key) {
    str_count_t *e = count_lookup(*map, *map_n, key);
    if (e) {
        e->count++;
        return FIRC_OK;
    }
    if (*map_n + 1 > *map_cap) {
        size_t newcap = *map_cap == 0 ? 8 : *map_cap * 2;
        str_count_t *tmp = realloc(*map, newcap * sizeof(**map));
        if (!tmp) { return FIRC_ERR_NOMEM; }
        *map = tmp;
        *map_cap = newcap;
    }
    (*map)[*map_n].key = strdup(key);
    if (!(*map)[*map_n].key) { return FIRC_ERR_NOMEM; }
    (*map)[*map_n].count = 1;
    (*map_n)++;
    return FIRC_OK;
}

static void count_map_free(str_count_t *map, size_t n) {
    if (!map) { return; }
    for (size_t i = 0; i < n; i++) { free(map[i].key); }
    free(map);
}

static firc_err_t cmds_push(firc_ipt_command_t **cmds, size_t *n, size_t *cap,
                          firc_ipt_option_t option, const char *chain_name,
                          int rule_num, const firc_ipt_rule_t *rule) {
    if (*n + 1 > *cap) {
        size_t newcap = *cap == 0 ? 8 : *cap * 2;
        firc_ipt_command_t *tmp = realloc(*cmds, newcap * sizeof(**cmds));
        if (!tmp) { return FIRC_ERR_NOMEM; }
        *cmds = tmp;
        *cap = newcap;
    }
    firc_ipt_command_t *c = &(*cmds)[*n];
    c->option = option;
    c->chain = strdup(chain_name);
    c->rule_num = rule_num;
    c->rule = rule ? firc_ipt_rule_clone(rule) : NULL;
    if (!c->chain || (rule && !c->rule)) {
        free(c->chain);
        firc_ipt_rule_free(c->rule);
        return FIRC_ERR_NOMEM;
    }
    (*n)++;
    return FIRC_OK;
}

static firc_err_t patch_compile(firc_ipt_chain_t *self, const char *chain_name,
                              firc_ipt_rule_t *const *existing, size_t n_existing,
                              firc_ipt_command_t **out_cmds, size_t *out_n,
                              int8_t *out_priority) {
    chain_patch_t *c = (chain_patch_t *)self;
    *out_cmds = NULL;
    *out_n = 0;
    *out_priority = 0;

    str_count_t *map = NULL;
    size_t map_n = 0, map_cap = 0;
    firc_err_t err = FIRC_OK;

    for (size_t i = 0; i < n_existing && err == FIRC_OK; i++) {
        char *key = firc_ipt_rule_string(existing[i]);
        if (!key) {
            err = FIRC_ERR_NOMEM;
            break;
        }
        err = count_bump(&map, &map_n, &map_cap, key);
        free(key);
    }
    if (err != FIRC_OK) {
        count_map_free(map, map_n);
        return err;
    }

    firc_ipt_command_t *cmds = NULL;
    size_t n = 0, cap = 0;

    for (size_t i = 0; i < c->n && err == FIRC_OK; i++) {
        patch_entry_t *e = &c->entries[i];
        char *key = firc_ipt_rule_string(e->rule);
        if (!key) {
            err = FIRC_ERR_NOMEM;
            break;
        }
        str_count_t *found = count_lookup(map, map_n, key);
        free(key);
        uint32_t count = found ? found->count : 0;

        while (count > 1 && err == FIRC_OK) {
            err = cmds_push(&cmds, &n, &cap, FIRC_IPT_OP_DELETE, chain_name, 0, e->rule);
            count--;
        }
        if (err != FIRC_OK) { break; }

        switch (e->option) {
        case FIRC_IPT_OP_APPEND:
            if (count > 0) { continue; }
            err = cmds_push(&cmds, &n, &cap, FIRC_IPT_OP_APPEND, chain_name, 0, e->rule);
            break;
        case FIRC_IPT_OP_INSERT:
            if (count > 0) { continue; }
            err = cmds_push(&cmds, &n, &cap, FIRC_IPT_OP_INSERT, chain_name, e->rule_num, e->rule);
            break;
        case FIRC_IPT_OP_DELETE:
            if (count == 0) { continue; }
            err = cmds_push(&cmds, &n, &cap, FIRC_IPT_OP_DELETE, chain_name, 0, e->rule);
            break;
        default:
            break;
        }
    }

    count_map_free(map, map_n);

    if (err != FIRC_OK) {
        firc_ipt_command_list_free(cmds, n);
        return err;
    }

    *out_cmds = cmds;
    *out_n = n;
    return FIRC_OK;
}

static firc_err_t patch_append(firc_ipt_chain_t *self, const firc_ipt_rule_t *rule) {
    return add_rule((chain_patch_t *)self, FIRC_IPT_OP_APPEND, 0, rule);
}

static firc_err_t patch_insert(firc_ipt_chain_t *self, int rule_num, const firc_ipt_rule_t *rule) {
    return add_rule((chain_patch_t *)self, FIRC_IPT_OP_INSERT, rule_num, rule);
}

static firc_err_t patch_remove(firc_ipt_chain_t *self, const firc_ipt_rule_t *rule) {
    return add_rule((chain_patch_t *)self, FIRC_IPT_OP_DELETE, 0, rule);
}

static void patch_destroy(firc_ipt_chain_t *self) {
    chain_patch_t *c = (chain_patch_t *)self;
    if (!c) { return; }
    for (size_t i = 0; i < c->n; i++) { firc_ipt_rule_free(c->entries[i].rule); }
    free(c->entries);
    free(c);
}

static const firc_ipt_chain_ops_t k_patch_ops = {
    .compile = patch_compile,
    .append = patch_append,
    .insert = patch_insert,
    .remove = patch_remove,
    .destroy = patch_destroy,
};

firc_ipt_chain_t *firc_ipt_chain_patch_new(void) {
    chain_patch_t *c = calloc(1, sizeof(*c));
    if (!c) { return NULL; }
    c->base.ops = &k_patch_ops;
    return &c->base;
}
