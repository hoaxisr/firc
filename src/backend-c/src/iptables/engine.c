#include "firc/iptables.h"
#include "firc/bytebuf.h"
#include "firc/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct chain_reg {
    char *chain_name;
    firc_ipt_chain_t *chain;
} chain_reg_t;

typedef struct table_reg {
    char *table_name;
    chain_reg_t *chains;
    size_t n_chains, cap_chains;
} table_reg_t;

struct firc_ipt {
    table_reg_t *tables;
    size_t n_tables, cap_tables;
    firc_ipt_executable_t *exe;
    firc_cancel_t *cancel;
};

firc_ipt_t *firc_ipt_new(firc_ipt_executable_t *exe) {
    firc_ipt_t *ipt = calloc(1, sizeof(*ipt));
    if (!ipt) { return NULL; }
    ipt->exe = exe;
    return ipt;
}

static void chain_reg_destroy(chain_reg_t *r) {
    free(r->chain_name);
    if (r->chain) { r->chain->ops->destroy(r->chain); }
}

static void table_reg_destroy(table_reg_t *t) {
    for (size_t i = 0; i < t->n_chains; i++) { chain_reg_destroy(&t->chains[i]); }
    free(t->chains);
    free(t->table_name);
}

void firc_ipt_free(firc_ipt_t *ipt) {
    if (!ipt) { return; }
    for (size_t i = 0; i < ipt->n_tables; i++) { table_reg_destroy(&ipt->tables[i]); }
    free(ipt->tables);
    firc_ipt_executable_free(ipt->exe);
    free(ipt);
}

void firc_ipt_discard(firc_ipt_t *ipt) {
    if (!ipt) { return; }
    for (size_t i = 0; i < ipt->n_tables; i++) { table_reg_destroy(&ipt->tables[i]); }
    free(ipt->tables);
    ipt->tables = NULL;
    ipt->n_tables = 0;
    ipt->cap_tables = 0;
}

firc_err_t firc_ipt_write_transcript(firc_ipt_t *ipt, const uint8_t *data, size_t len) {
    if (ipt == NULL) { return FIRC_ERR_INVAL; }
    return ipt->exe->ops->restore(ipt->exe, data, len);
}

firc_ipt_proto_t firc_ipt_proto(const firc_ipt_t *ipt) {
    return ipt->exe->ops->proto(ipt->exe);
}

static table_reg_t *find_table(firc_ipt_t *ipt, const char *name) {
    for (size_t i = 0; i < ipt->n_tables; i++) {
        if (strcmp(ipt->tables[i].table_name, name) == 0) { return &ipt->tables[i]; }
    }
    return NULL;
}

static table_reg_t *find_or_create_table(firc_ipt_t *ipt, const char *name) {
    table_reg_t *t = find_table(ipt, name);
    if (t) { return t; }

    if (ipt->n_tables + 1 > ipt->cap_tables) {
        size_t newcap = ipt->cap_tables == 0 ? 4 : ipt->cap_tables * 2;
        table_reg_t *tmp = realloc(ipt->tables, newcap * sizeof(*tmp));
        if (!tmp) { return NULL; }
        ipt->tables = tmp;
        ipt->cap_tables = newcap;
    }
    table_reg_t *nt = &ipt->tables[ipt->n_tables];
    memset(nt, 0, sizeof(*nt));
    nt->table_name = strdup(name);
    if (!nt->table_name) { return NULL; }
    ipt->n_tables++;
    return nt;
}

static chain_reg_t *find_chain_reg(table_reg_t *t, const char *name) {
    for (size_t i = 0; i < t->n_chains; i++) {
        if (strcmp(t->chains[i].chain_name, name) == 0) { return &t->chains[i]; }
    }
    return NULL;
}

static firc_err_t register_chain(firc_ipt_t *ipt, const char *table, const char *chain,
                               firc_ipt_chain_t *(*ctor)(void)) {
    table_reg_t *t = find_or_create_table(ipt, table);
    if (!t) { return FIRC_ERR_NOMEM; }

    firc_ipt_chain_t *newchain = ctor();
    if (!newchain) { return FIRC_ERR_NOMEM; }

    chain_reg_t *c = find_chain_reg(t, chain);
    if (c) {
        c->chain->ops->destroy(c->chain);
        c->chain = newchain;
        return FIRC_OK;
    }

    if (t->n_chains + 1 > t->cap_chains) {
        size_t newcap = t->cap_chains == 0 ? 4 : t->cap_chains * 2;
        chain_reg_t *tmp = realloc(t->chains, newcap * sizeof(*tmp));
        if (!tmp) {
            newchain->ops->destroy(newchain);
            return FIRC_ERR_NOMEM;
        }
        t->chains = tmp;
        t->cap_chains = newcap;
    }
    chain_reg_t *nc = &t->chains[t->n_chains];
    nc->chain_name = strdup(chain);
    if (!nc->chain_name) {
        newchain->ops->destroy(newchain);
        return FIRC_ERR_NOMEM;
    }
    nc->chain = newchain;
    t->n_chains++;
    return FIRC_OK;
}

firc_err_t firc_ipt_register_chain_delete(firc_ipt_t *ipt, const char *table, const char *chain) {
    return register_chain(ipt, table, chain, firc_ipt_chain_delete_new);
}
firc_err_t firc_ipt_register_chain_patch(firc_ipt_t *ipt, const char *table, const char *chain) {
    return register_chain(ipt, table, chain, firc_ipt_chain_patch_new);
}
firc_err_t firc_ipt_register_chain_override(firc_ipt_t *ipt, const char *table, const char *chain) {
    return register_chain(ipt, table, chain, firc_ipt_chain_override_new);
}

static firc_err_t dispatch_rule_op(firc_ipt_t *ipt, const char *table, const char *chain,
                                 const char *const *args, size_t n_args, int rule_num,
                                 int op /* 0=append 1=insert 2=delete */) {
    table_reg_t *t = find_table(ipt, table);
    chain_reg_t *c = t ? find_chain_reg(t, chain) : NULL;
    if (!c) { return FIRC_ERR_STATE; }

    firc_ipt_rule_t *rule = firc_ipt_rule_new(args, n_args);
    if (!rule) { return FIRC_ERR_NOMEM; }

    firc_err_t err;
    switch (op) {
    case 0: err = c->chain->ops->append(c->chain, rule); break;
    case 1: err = c->chain->ops->insert(c->chain, rule_num, rule); break;
    default: err = c->chain->ops->remove(c->chain, rule); break;
    }
    firc_ipt_rule_free(rule);
    return err;
}

firc_err_t firc_ipt_append(firc_ipt_t *ipt, const char *table, const char *chain,
                       const char *const *args, size_t n_args) {
    return dispatch_rule_op(ipt, table, chain, args, n_args, 0, 0);
}
firc_err_t firc_ipt_insert(firc_ipt_t *ipt, const char *table, const char *chain, int rule_num,
                       const char *const *args, size_t n_args) {
    return dispatch_rule_op(ipt, table, chain, args, n_args, rule_num, 1);
}
firc_err_t firc_ipt_delete(firc_ipt_t *ipt, const char *table, const char *chain,
                       const char *const *args, size_t n_args) {
    return dispatch_rule_op(ipt, table, chain, args, n_args, 0, 2);
}

bool firc_ipt_err_is_chain_not_initialized(firc_err_t err) {
    return err == FIRC_ERR_STATE;
}

typedef struct chain_builder {
    char *chain_name;
    firc_ipt_rule_t **rules;
    size_t n_rules, cap_rules;
} chain_builder_t;

typedef struct table_builder {
    char *table_name;
    chain_builder_t *chains;
    size_t n_chains, cap_chains;
} table_builder_t;

static chain_builder_t *builder_find_chain(table_builder_t *t, const char *name, size_t len) {
    for (size_t i = 0; i < t->n_chains; i++) {
        if (strlen(t->chains[i].chain_name) == len &&
            memcmp(t->chains[i].chain_name, name, len) == 0) {
            return &t->chains[i];
}
    }
    return NULL;
}

static chain_builder_t *builder_find_or_create_chain(table_builder_t *t, const char *name,
                                                     size_t len) {
    chain_builder_t *c = builder_find_chain(t, name, len);
    if (c) { return c; }

    if (t->n_chains + 1 > t->cap_chains) {
        size_t newcap = t->cap_chains == 0 ? 4 : t->cap_chains * 2;
        chain_builder_t *tmp = realloc(t->chains, newcap * sizeof(*tmp));
        if (!tmp) { return NULL; }
        t->chains = tmp;
        t->cap_chains = newcap;
    }
    chain_builder_t *nc = &t->chains[t->n_chains];
    nc->chain_name = strndup(name, len);
    if (!nc->chain_name) { return NULL; }
    /* Non-NULL even when empty: NULL means the chain is absent. */
    nc->rules = calloc(1, sizeof(firc_ipt_rule_t *));
    if (!nc->rules) { return NULL; }
    nc->n_rules = 0;
    nc->cap_rules = 1;
    t->n_chains++;
    return nc;
}

static firc_err_t chain_builder_add_rule(chain_builder_t *c, firc_ipt_rule_t *rule) {
    if (c->n_rules + 1 > c->cap_rules) {
        size_t newcap = c->cap_rules == 0 ? 4 : c->cap_rules * 2;
        firc_ipt_rule_t **tmp = realloc(c->rules, newcap * sizeof(*tmp));
        if (!tmp) { return FIRC_ERR_NOMEM; }
        c->rules = tmp;
        c->cap_rules = newcap;
    }
    c->rules[c->n_rules++] = rule;
    return FIRC_OK;
}

static table_builder_t *tb_find(table_builder_t *tables, size_t n, const char *name, size_t len) {
    for (size_t i = 0; i < n; i++) {
        if (strlen(tables[i].table_name) == len && memcmp(tables[i].table_name, name, len) == 0) {
            return &tables[i];
}
    }
    return NULL;
}

static table_builder_t *tb_find_or_create(table_builder_t **tables, size_t *n, size_t *cap,
                                          const char *name, size_t len) {
    table_builder_t *t = tb_find(*tables, *n, name, len);
    if (t) { return t; }

    if (*n + 1 > *cap) {
        size_t newcap = *cap == 0 ? 4 : *cap * 2;
        table_builder_t *tmp = realloc(*tables, newcap * sizeof(*tmp));
        if (!tmp) { return NULL; }
        *tables = tmp;
        *cap = newcap;
    }
    table_builder_t *nt = &(*tables)[*n];
    memset(nt, 0, sizeof(*nt));
    nt->table_name = strndup(name, len);
    if (!nt->table_name) { return NULL; }
    (*n)++;
    return nt;
}

/* Leaves the `tables` array itself alone; the caller frees it once. */
static void builders_free_range(table_builder_t *tables, size_t start, size_t end) {
    for (size_t ti = start; ti < end; ti++) {
        table_builder_t *t = &tables[ti];
        for (size_t ci = 0; ci < t->n_chains; ci++) {
            chain_builder_t *c = &t->chains[ci];
            for (size_t ri = 0; ri < c->n_rules; ri++) { firc_ipt_rule_free(c->rules[ri]); }
            free(c->rules);
            free(c->chain_name);
        }
        free(t->chains);
        free(t->table_name);
    }
}

static void builders_free(table_builder_t *tables, size_t n) {
    builders_free_range(tables, 0, n);
    free(tables);
}

/* Spans point into the caller's buffer. */
typedef struct field_span {
    size_t off, len;
} field_span_t;

static firc_err_t split_fields(const uint8_t *line, size_t line_len, field_span_t **out,
                             size_t *out_n) {
    field_span_t *fields = NULL;
    size_t n = 0, cap = 0;
    long start = -1;

    for (size_t i = 0; i < line_len; i++) {
        uint8_t b = line[i];
        if (b == ' ' || b == '\t') {
            if (start >= 0) {
                if (n + 1 > cap) {
                    size_t newcap = cap == 0 ? 8 : cap * 2;
                    field_span_t *tmp = realloc(fields, newcap * sizeof(*tmp));
                    if (!tmp) {
                        free(fields);
                        return FIRC_ERR_NOMEM;
                    }
                    fields = tmp;
                    cap = newcap;
                }
                fields[n].off = (size_t)start;
                fields[n].len = i - (size_t)start;
                n++;
                start = -1;
            }
        } else if (start < 0) {
            start = (long)i;
        }
    }
    if (start >= 0) {
        if (n + 1 > cap) {
            field_span_t *tmp = realloc(fields, (n + 1) * sizeof(*tmp));
            if (!tmp) {
                free(fields);
                return FIRC_ERR_NOMEM;
            }
            fields = tmp;
        }
        fields[n].off = (size_t)start;
        fields[n].len = line_len - (size_t)start;
        n++;
    }

    *out = fields;
    *out_n = n;
    return FIRC_OK;
}

firc_err_t firc_ipt_get_current_rules(firc_ipt_t *ipt, firc_ipt_rules_snapshot_t **out) {
    *out = NULL;

    uint8_t *data = NULL;
    size_t data_len = 0;
    firc_err_t err = ipt->exe->ops->save(ipt->exe, &data, &data_len);
    if (err != FIRC_OK) { return err; }

    table_builder_t *tables = NULL;
    size_t n_tables = 0, cap_tables = 0;
    table_builder_t *cur_table = NULL;

    size_t line_start = 0;
    for (size_t i = 0; i <= data_len && err == FIRC_OK; i++) {
        if (i < data_len && data[i] != '\n') { continue; }

        const uint8_t *line = data + line_start;
        size_t line_len = i - line_start;
        line_start = i + 1;

        if (line_len == 0) { continue; }

        switch (line[0]) {
        case '*': {
            cur_table = tb_find_or_create(&tables, &n_tables, &cap_tables,
                                          (const char *)line + 1, line_len - 1);
            if (!cur_table) { err = FIRC_ERR_NOMEM; }
            break;
        }
        case ':': {
            size_t name_len;
            const uint8_t *body = line + 1;
            size_t body_len = line_len - 1;
            size_t space_idx = body_len;
            for (size_t k = 0; k < body_len; k++) {
                if (body[k] == ' ') {
                    space_idx = k;
                    break;
                }
            }
            name_len = space_idx;
            if (name_len == 0) {
                err = FIRC_ERR_PROTO;
                break;
            }
            if (!cur_table) {
                err = FIRC_ERR_PROTO;
                break;
            }
            if (!builder_find_or_create_chain(cur_table, (const char *)body, name_len)) {
                err = FIRC_ERR_NOMEM;
}
            break;
        }
        case '-': {
            if (!cur_table) {
                err = FIRC_ERR_PROTO;
                break;
            }
            field_span_t *fields = NULL;
            size_t n_fields = 0;
            err = split_fields(line, line_len, &fields, &n_fields);
            if (err != FIRC_OK) { break; }
            if (n_fields < 2) {
                err = FIRC_ERR_PROTO;
                free(fields);
                break;
            }
            if (fields[0].len < 2) {
                err = FIRC_ERR_PROTO;
                free(fields);
                break;
            }
            uint8_t op = line[fields[0].off + 1];
            chain_builder_t *cb = builder_find_or_create_chain(
                cur_table, (const char *)line + fields[1].off, fields[1].len);
            if (!cb) {
                err = FIRC_ERR_NOMEM;
                free(fields);
                break;
            }
            if (op == 'A') {
                size_t n_parts = n_fields - 2;
                char **parts = NULL;
                if (n_parts > 0) {
                    parts = calloc(n_parts, sizeof(char *));
                    if (!parts) {
                        err = FIRC_ERR_NOMEM;
                        free(fields);
                        break;
                    }
                    for (size_t k = 0; k < n_parts; k++) {
                        parts[k] = strndup((const char *)line + fields[k + 2].off,
                                           fields[k + 2].len);
                        if (!parts[k]) {
                            for (size_t j = 0; j < k; j++) { free(parts[j]); }
                            free(parts);
                            parts = NULL;
                            err = FIRC_ERR_NOMEM;
                            break;
                        }
                    }
                }
                if (err == FIRC_OK) {
                    firc_ipt_rule_t *rule = firc_ipt_rule_new((const char *const *)parts, n_parts);
                    for (size_t k = 0; k < n_parts; k++) { free(parts[k]); }
                    free(parts);
                    if (!rule) {
                        err = FIRC_ERR_NOMEM;
                    } else {
                        err = chain_builder_add_rule(cb, rule);
                        if (err != FIRC_OK) { firc_ipt_rule_free(rule); }
                    }
                }
            } else {
                err = FIRC_ERR_PROTO;
            }
            free(fields);
            break;
        }
        case '#':
            break; /* comment */
        case 'C':
            cur_table = NULL; /* COMMIT */
            break;
        default:
            err = FIRC_ERR_PROTO;
            break;
        }
    }

    free(data);

    if (err != FIRC_OK) {
        builders_free(tables, n_tables);
        return err;
    }

    firc_ipt_rules_snapshot_t *snap = calloc(1, sizeof(*snap));
    if (!snap) {
        builders_free(tables, n_tables);
        return FIRC_ERR_NOMEM;
    }
    if (n_tables > 0) {
        snap->tables = calloc(n_tables, sizeof(*snap->tables));
        if (!snap->tables) {
            free(snap);
            builders_free(tables, n_tables);
            return FIRC_ERR_NOMEM;
        }
    }
    snap->n_tables = n_tables;

    for (size_t ti = 0; ti < n_tables; ti++) {
        table_builder_t *tb = &tables[ti];
        firc_ipt_table_rules_t *dst = &snap->tables[ti];
        dst->table_name = tb->table_name;
        dst->n_chains = tb->n_chains;
        if (tb->n_chains > 0) {
            dst->chains = calloc(tb->n_chains, sizeof(*dst->chains));
            if (!dst->chains) {
                /* snap owns tables[0,ti); tables[ti..) still own their names. */
                snap->n_tables = ti;
                firc_ipt_rules_snapshot_free(snap);
                builders_free_range(tables, ti, n_tables);
                free(tables);
                return FIRC_ERR_NOMEM;
            }
        } else {
            dst->chains = NULL;
        }
        for (size_t ci = 0; ci < tb->n_chains; ci++) {
            chain_builder_t *cb = &tb->chains[ci];
            dst->chains[ci].chain_name = cb->chain_name;
            dst->chains[ci].rules = cb->rules;
            dst->chains[ci].n_rules = cb->n_rules;
        }
        free(tb->chains); /* shell only: fields moved above */
    }
    free(tables);

    *out = snap;
    return FIRC_OK;
}

const firc_ipt_table_rules_t *firc_ipt_rules_snapshot_find_table(const firc_ipt_rules_snapshot_t *snap,
                                                              const char *table_name) {
    if (!snap) { return NULL; }
    for (size_t i = 0; i < snap->n_tables; i++) {
        if (strcmp(snap->tables[i].table_name, table_name) == 0) { return &snap->tables[i]; }
    }
    return NULL;
}

const firc_ipt_chain_rules_t *firc_ipt_table_rules_find_chain(const firc_ipt_table_rules_t *table,
                                                          const char *chain_name) {
    if (!table) { return NULL; }
    for (size_t i = 0; i < table->n_chains; i++) {
        if (strcmp(table->chains[i].chain_name, chain_name) == 0) { return &table->chains[i]; }
    }
    return NULL;
}

void firc_ipt_rules_snapshot_free(firc_ipt_rules_snapshot_t *snap) {
    if (!snap) { return; }
    for (size_t ti = 0; ti < snap->n_tables; ti++) {
        firc_ipt_table_rules_t *t = &snap->tables[ti];
        for (size_t ci = 0; ci < t->n_chains; ci++) {
            firc_ipt_chain_rules_t *c = &t->chains[ci];
            for (size_t ri = 0; ri < c->n_rules; ri++) { firc_ipt_rule_free(c->rules[ri]); }
            free(c->rules);
            free(c->chain_name);
        }
        free(t->chains);
        free(t->table_name);
    }
    free(snap->tables);
    free(snap);
}

typedef struct prio_bucket {
    int8_t priority;
    firc_ipt_command_t *cmds;
    size_t n, cap;
} prio_bucket_t;

static prio_bucket_t *bucket_find_or_create(prio_bucket_t **buckets, size_t *n, size_t *cap,
                                            int8_t priority) {
    for (size_t i = 0; i < *n; i++) {
        if ((*buckets)[i].priority == priority) { return &(*buckets)[i]; }
    }
    if (*n + 1 > *cap) {
        size_t newcap = *cap == 0 ? 4 : *cap * 2;
        prio_bucket_t *tmp = realloc(*buckets, newcap * sizeof(*tmp));
        if (!tmp) { return NULL; }
        *buckets = tmp;
        *cap = newcap;
    }
    prio_bucket_t *b = &(*buckets)[*n];
    b->priority = priority;
    b->cmds = NULL;
    b->n = 0;
    b->cap = 0;
    (*n)++;
    return b;
}

static firc_err_t bucket_append_range(prio_bucket_t *b, firc_ipt_command_t *src, size_t n_src) {
    if (b->n + n_src > b->cap) {
        size_t newcap = b->cap == 0 ? 8 : b->cap;
        while (newcap < b->n + n_src) { newcap *= 2; }
        firc_ipt_command_t *tmp = realloc(b->cmds, newcap * sizeof(*tmp));
        if (!tmp) { return FIRC_ERR_NOMEM; }
        b->cmds = tmp;
        b->cap = newcap;
    }
    memcpy(b->cmds + b->n, src, n_src * sizeof(*src));
    b->n += n_src;
    return FIRC_OK;
}

static int bucket_cmp(const void *a, const void *b) {
    int8_t pa = ((const prio_bucket_t *)a)->priority;
    int8_t pb = ((const prio_bucket_t *)b)->priority;
    return (pa > pb) - (pa < pb);
}

static void buckets_free(prio_bucket_t *buckets, size_t n) {
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < buckets[i].n; j++) {
            free(buckets[i].cmds[j].chain);
            firc_ipt_rule_free(buckets[i].cmds[j].rule);
        }
        free(buckets[i].cmds);
    }
    free(buckets);
}

static firc_err_t write_rule_string(firc_bytebuf_t *buf, const firc_ipt_rule_t *rule) {
    firc_err_t err = FIRC_OK;
    for (size_t i = 0; i < rule->n_parts && err == FIRC_OK; i++) {
        if (i > 0) { err = firc_bytebuf_append_byte(buf, ' '); }
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(buf, rule->parts[i]); }
    }
    return err;
}

static firc_err_t write_command(firc_bytebuf_t *buf, const firc_ipt_command_t *cmd) {
    firc_err_t err = FIRC_OK;
    switch (cmd->option) {
    case FIRC_IPT_OP_APPEND:
        err = firc_bytebuf_append_str(buf, "-A ");
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(buf, cmd->chain); }
        if (err == FIRC_OK && cmd->rule && cmd->rule->n_parts > 0) {
            err = firc_bytebuf_append_byte(buf, ' ');
            if (err == FIRC_OK) { err = write_rule_string(buf, cmd->rule); }
        }
        if (err == FIRC_OK) { err = firc_bytebuf_append_byte(buf, '\n'); }
        break;
    case FIRC_IPT_OP_DELETE:
        err = firc_bytebuf_append_str(buf, "-D ");
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(buf, cmd->chain); }
        if (err == FIRC_OK && cmd->rule && cmd->rule->n_parts > 0) {
            err = firc_bytebuf_append_byte(buf, ' ');
            if (err == FIRC_OK) { err = write_rule_string(buf, cmd->rule); }
        }
        if (err == FIRC_OK) { err = firc_bytebuf_append_byte(buf, '\n'); }
        break;
    case FIRC_IPT_OP_INSERT: {
        char num[32];
        int written = snprintf(num, sizeof(num), "%d", cmd->rule_num);
        if (written < 0 || (size_t)written >= sizeof(num)) { return FIRC_ERR_INVAL; }
        err = firc_bytebuf_append_str(buf, "-I ");
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(buf, cmd->chain); }
        if (err == FIRC_OK) { err = firc_bytebuf_append_byte(buf, ' '); }
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(buf, num); }
        if (err == FIRC_OK && cmd->rule && cmd->rule->n_parts > 0) {
            err = firc_bytebuf_append_byte(buf, ' ');
            if (err == FIRC_OK) { err = write_rule_string(buf, cmd->rule); }
        }
        if (err == FIRC_OK) { err = firc_bytebuf_append_byte(buf, '\n'); }
        break;
    }
    case FIRC_IPT_OP_FLUSH:
        err = firc_bytebuf_append_str(buf, "-F ");
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(buf, cmd->chain); }
        if (err == FIRC_OK) { err = firc_bytebuf_append_byte(buf, '\n'); }
        break;
    case FIRC_IPT_OP_DELETE_CHAIN:
        err = firc_bytebuf_append_str(buf, "-X ");
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(buf, cmd->chain); }
        if (err == FIRC_OK) { err = firc_bytebuf_append_byte(buf, '\n'); }
        break;
    }
    return err;
}

void firc_ipt_set_cancel(firc_ipt_t *ipt, firc_cancel_t *cancel) {
    ipt->cancel = cancel;
    if (ipt->exe->ops->set_cancel) { ipt->exe->ops->set_cancel(ipt->exe, cancel); }
}

firc_err_t firc_ipt_commit(firc_ipt_t *ipt) {
    /* Checked here too, so an abort between the two transfers stops the write. */
    if (firc_cancel_raised(ipt->cancel)) { return FIRC_ERR_CANCELED; }

    struct timespec t0, t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_ipt_rules_snapshot_t *cur = NULL;
    firc_err_t err = firc_ipt_get_current_rules(ipt, &cur);
    if (err != FIRC_OK) { return err; }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    firc_bytebuf_t buf;
    firc_bytebuf_init(&buf);

    for (size_t ti = 0; ti < ipt->n_tables && err == FIRC_OK; ti++) {
        table_reg_t *t = &ipt->tables[ti];
        const firc_ipt_table_rules_t *cur_table = firc_ipt_rules_snapshot_find_table(cur, t->table_name);

        prio_bucket_t *buckets = NULL;
        size_t n_buckets = 0, cap_buckets = 0;
        bool table_written = false;

        for (size_t ci = 0; ci < t->n_chains && err == FIRC_OK; ci++) {
            chain_reg_t *c = &t->chains[ci];
            const firc_ipt_chain_rules_t *cur_chain =
                cur_table ? firc_ipt_table_rules_find_chain(cur_table, c->chain_name) : NULL;
            firc_ipt_rule_t *const *existing = cur_chain ? cur_chain->rules : NULL;
            size_t n_existing = cur_chain ? cur_chain->n_rules : 0;

            firc_ipt_command_t *cmds = NULL;
            size_t n_cmds = 0;
            int8_t priority = 0;
            err = c->chain->ops->compile(c->chain, c->chain_name, existing, n_existing, &cmds,
                                         &n_cmds, &priority);
            if (err != FIRC_OK) { break; }
            if (n_cmds == 0) { continue; }

            if (!table_written) {
                err = firc_bytebuf_append_byte(&buf, '*');
                if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, t->table_name); }
                if (err == FIRC_OK) { err = firc_bytebuf_append_byte(&buf, '\n'); }
                if (err != FIRC_OK) {
                    firc_ipt_command_list_free(cmds, n_cmds);
                    break;
                }
                table_written = true;
            }
            err = firc_bytebuf_append_byte(&buf, ':');
            if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, c->chain_name); }
            if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, " - [0:0]\n"); }
            if (err != FIRC_OK) {
                firc_ipt_command_list_free(cmds, n_cmds);
                break;
            }

            prio_bucket_t *bucket = bucket_find_or_create(&buckets, &n_buckets, &cap_buckets, priority);
            if (!bucket) {
                firc_ipt_command_list_free(cmds, n_cmds);
                err = FIRC_ERR_NOMEM;
                break;
            }
            err = bucket_append_range(bucket, cmds, n_cmds);
            free(cmds); /* shallow: ownership of chain/rule moved into bucket */
        }

        if (err == FIRC_OK && table_written) {
            qsort(buckets, n_buckets, sizeof(*buckets), bucket_cmp);
            for (size_t bi = 0; bi < n_buckets && err == FIRC_OK; bi++) {
                for (size_t ci = 0; ci < buckets[bi].n && err == FIRC_OK; ci++) {
                    err = write_command(&buf, &buckets[bi].cmds[ci]);
                }
            }
            if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, "COMMIT\n"); }
        }

        buckets_free(buckets, n_buckets);
    }

    firc_ipt_rules_snapshot_free(cur);
    clock_gettime(CLOCK_MONOTONIC, &t2);
    FIRC_DEBUG("iptables commit: read %lld ms, compile %lld ms, %zu bytes",
               (long long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000),
               (long long)((t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_nsec - t1.tv_nsec) / 1000000), buf.len);

    if (err != FIRC_OK) {
        firc_bytebuf_free(&buf);
        return err;
    }

    if (buf.len == 0) {
        firc_bytebuf_free(&buf);
        return FIRC_OK;
    }

    if (firc_cancel_raised(ipt->cancel)) {
        firc_bytebuf_free(&buf);
        return FIRC_ERR_CANCELED;
    }

    err = ipt->exe->ops->restore(ipt->exe, buf.data, buf.len);
    firc_bytebuf_free(&buf);
    return err;
}
