#include "fake_iptables.h"

#include "firc/bytebuf.h"
#include "xt_golden.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct fake_chain {
    char *name;
    firc_ipt_rule_t **rules;
    size_t n, cap;
} fake_chain_t;

typedef struct fake_table {
    char *name;
    fake_chain_t *chains;
    size_t n_chains, cap_chains;
} fake_table_t;

typedef struct nat_view {
    firc_ipt_rule_t **rules;
    size_t n;
    struct nat_view *next;
} nat_view_t;

struct firc_fake_ipt {
    firc_ipt_executable_t base;
    pthread_mutex_t mu;
    firc_ipt_proto_t proto;
    fake_table_t *tables;
    size_t n_tables, cap_tables;
    firc_err_t next_restore_err;
    size_t fail_at_commit;
    firc_err_t fail_at_err;
    size_t restore_calls;
    char *refuse;
    char *log;
    size_t log_len;
    char *saved;
    size_t saved_len;
    firc_fake_xt_t *xt;
    nat_view_t *nat_views;
    void (*on_restore)(void *ud);
    void *on_restore_ud;
};

static void log_append(firc_fake_ipt_t *f, const char *text, size_t len) {
    char *grown = realloc(f->log, f->log_len + len + 1);
    if (grown == NULL) { return; }
    memcpy(grown + f->log_len, text, len);
    f->log_len += len;
    grown[f->log_len] = '\0';
    f->log = grown;
}

static int nat_before(void *ud, firc_ipt_proto_t fam, const char *table, const firc_xt_info_t *info,
                      const uint8_t *blob) {
    firc_fake_ipt_t *f = ud;
    (void)table;
    char *text = firc_test_xt_print(fam, info, blob);
    pthread_mutex_lock(&f->mu);
    int err = 0;
    if (f->next_restore_err != FIRC_OK && f->next_restore_err != FIRC_ERR_CANCELED) {
        err = f->next_restore_err == FIRC_ERR_AGAIN ? EAGAIN : EINVAL;
        f->next_restore_err = FIRC_OK;
    } else if (text != NULL && f->refuse != NULL && f->refuse[0] != '\0' && strstr(text, f->refuse) != NULL) {
        err = EINVAL;
    }
    pthread_mutex_unlock(&f->mu);
    free(text);
    return err;
}

static void nat_after(void *ud, const char *table) {
    firc_fake_ipt_t *f = ud;
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    if (!firc_fake_xt_blob(f->xt, table, &info, &blob)) { return; }
    char *text = firc_test_xt_print(f->proto, &info, blob);
    free(blob);
    if (text == NULL) { return; }
    pthread_mutex_lock(&f->mu);
    log_append(f, text, strlen(text));
    pthread_mutex_unlock(&f->mu);
    free(text);
}

static void nat_view_clear(firc_fake_ipt_t *f) {
    while (f->nat_views != NULL) {
        nat_view_t *v = f->nat_views;
        f->nat_views = v->next;
        for (size_t i = 0; i < v->n; i++) { firc_ipt_rule_free(v->rules[i]); }
        free(v->rules);
        free(v);
    }
}

static bool nat_rules(firc_fake_ipt_t *f, const char *chain, firc_ipt_rule_t *const **out, size_t *n) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    if (!firc_fake_xt_blob(f->xt, "nat", &info, &blob)) { return false; }
    char *text = firc_test_xt_print(f->proto, &info, blob);
    free(blob);
    if (text == NULL) { return false; }
    char decl[64], rule[64];
    snprintf(decl, sizeof(decl), ":%s ", chain);
    int rule_len = snprintf(rule, sizeof(rule), "-A %s", chain);
    bool exists = false;
    nat_view_t *v = calloc(1, sizeof(*v));
    for (char *save = NULL, *line = strtok_r(text, "\n", &save); v != NULL && line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        if (strncmp(line, decl, strlen(decl)) == 0) { exists = true; }
        if (strncmp(line, rule, (size_t)rule_len) != 0 || (line[rule_len] != ' ' && line[rule_len] != '\0')) { continue; }
        firc_ipt_rule_t **grown = realloc(v->rules, (v->n + 1) * sizeof(*grown));
        if (grown == NULL) { break; }
        v->rules = grown;
        v->rules[v->n++] = firc_test_rule(line + rule_len);
    }
    if (out != NULL) { *out = v != NULL ? v->rules : NULL; }
    if (n != NULL) { *n = v != NULL ? v->n : 0; }
    if (v != NULL) {
        pthread_mutex_lock(&f->mu);
        v->next = f->nat_views;
        f->nat_views = v;
        pthread_mutex_unlock(&f->mu);
    }
    free(text);
    return exists;
}

/* Whether the fake refuses this transcript; call with the lock held. */
static bool fake_refuses(const firc_fake_ipt_t *f, const uint8_t *data, size_t len) {
    if (f->refuse == NULL) { return false; }
    size_t n = strlen(f->refuse);
    if (n == 0 || len < n) { return false; }
    for (size_t i = 0; i + n <= len; i++) {
        if (memcmp(data + i, f->refuse, n) == 0) { return true; }
    }
    return false;
}

static fake_table_t *ft_find(firc_fake_ipt_t *f, const char *name) {
    for (size_t i = 0; i < f->n_tables; i++) {
        if (strcmp(f->tables[i].name, name) == 0) { return &f->tables[i]; }
}
    return NULL;
}

static fake_table_t *ft_find_or_create(firc_fake_ipt_t *f, const char *name, size_t name_len) {
    for (size_t i = 0; i < f->n_tables; i++) {
        if (strlen(f->tables[i].name) == name_len &&
            memcmp(f->tables[i].name, name, name_len) == 0) {
            return &f->tables[i];
}
    }
    if (f->n_tables + 1 > f->cap_tables) {
        size_t newcap = f->cap_tables == 0 ? 4 : f->cap_tables * 2;
        fake_table_t *tmp = realloc(f->tables, newcap * sizeof(*tmp));
        if (!tmp) { return NULL; }
        f->tables = tmp;
        f->cap_tables = newcap;
    }
    fake_table_t *nt = &f->tables[f->n_tables];
    memset(nt, 0, sizeof(*nt));
    nt->name = strndup(name, name_len);
    if (!nt->name) { return NULL; }
    f->n_tables++;
    return nt;
}

static fake_chain_t *fc_find(fake_table_t *t, const char *name) {
    for (size_t i = 0; i < t->n_chains; i++) {
        if (strcmp(t->chains[i].name, name) == 0) { return &t->chains[i]; }
}
    return NULL;
}

static fake_chain_t *fc_find_or_create(fake_table_t *t, const char *name, size_t name_len) {
    for (size_t i = 0; i < t->n_chains; i++) {
        if (strlen(t->chains[i].name) == name_len &&
            memcmp(t->chains[i].name, name, name_len) == 0) {
            return &t->chains[i];
}
    }
    if (t->n_chains + 1 > t->cap_chains) {
        size_t newcap = t->cap_chains == 0 ? 4 : t->cap_chains * 2;
        fake_chain_t *tmp = realloc(t->chains, newcap * sizeof(*tmp));
        if (!tmp) { return NULL; }
        t->chains = tmp;
        t->cap_chains = newcap;
    }
    fake_chain_t *nc = &t->chains[t->n_chains];
    memset(nc, 0, sizeof(*nc));
    nc->name = strndup(name, name_len);
    if (!nc->name) { return NULL; }
    t->n_chains++;
    return nc;
}

static firc_err_t fc_append_owned(fake_chain_t *c, firc_ipt_rule_t *r) {
    if (c->n + 1 > c->cap) {
        size_t newcap = c->cap == 0 ? 4 : c->cap * 2;
        firc_ipt_rule_t **tmp = realloc(c->rules, newcap * sizeof(*tmp));
        if (!tmp) { return FIRC_ERR_NOMEM; }
        c->rules = tmp;
        c->cap = newcap;
    }
    c->rules[c->n++] = r;
    return FIRC_OK;
}

static void fc_clear(fake_chain_t *c) {
    for (size_t i = 0; i < c->n; i++) { firc_ipt_rule_free(c->rules[i]); }
    c->n = 0;
}

firc_err_t firc_fake_ipt_set_initial_rules(firc_fake_ipt_t *f, const char *table, const char *chain,
                                       const char *const *const *rules, const size_t *rule_lens,
                                       size_t n_rules) {
    if (strcmp(table, "nat") == 0) {
        firc_ipt_rule_t **rs = calloc(n_rules ? n_rules : 1, sizeof(*rs));
        if (rs == NULL) { return FIRC_ERR_NOMEM; }
        for (size_t i = 0; i < n_rules; i++) { rs[i] = firc_ipt_rule_new(rules[i], rule_lens[i]); }
        firc_xt_stage_chain_t sc = {chain, FIRC_XT_STAGE_OVERRIDE, rs, n_rules, NULL, 0};
        firc_xt_stage_t stage = {&sc, 1, NULL};
        firc_fake_xt_set_write_hooks(f->xt, NULL, NULL, NULL);
        firc_xt_t *h = firc_fake_xt_handle(f->xt);
        firc_err_t err = h != NULL ? firc_xt_commit(h, "nat", &stage, NULL) : FIRC_ERR_NOMEM;
        firc_xt_free(h);
        firc_fake_xt_set_write_hooks(f->xt, nat_before, nat_after, f);
        for (size_t i = 0; i < n_rules; i++) { firc_ipt_rule_free(rs[i]); }
        free(rs);
        return err;
    }
    fake_table_t *t = ft_find_or_create(f, table, strlen(table));
    if (!t) { return FIRC_ERR_NOMEM; }
    fake_chain_t *c = fc_find_or_create(t, chain, strlen(chain));
    if (!c) { return FIRC_ERR_NOMEM; }
    fc_clear(c);

    for (size_t i = 0; i < n_rules; i++) {
        firc_ipt_rule_t *r = firc_ipt_rule_new(rules[i], rule_lens[i]);
        if (!r) { return FIRC_ERR_NOMEM; }
        firc_err_t err = fc_append_owned(c, r);
        if (err != FIRC_OK) {
            firc_ipt_rule_free(r);
            return err;
        }
    }
    return FIRC_OK;
}

bool firc_fake_ipt_get_rules(firc_fake_ipt_t *f, const char *table, const char *chain,
                          firc_ipt_rule_t *const **out_rules, size_t *out_n) {
    if (strcmp(table, "nat") == 0) { return nat_rules(f, chain, out_rules, out_n); }
    fake_table_t *t = ft_find(f, table);
    fake_chain_t *c = t ? fc_find(t, chain) : NULL;
    if (!c) {
        *out_rules = NULL;
        *out_n = 0;
        return false;
    }
    *out_rules = c->rules;
    *out_n = c->n;
    return true;
}

bool firc_fake_ipt_chain_exists(firc_fake_ipt_t *f, const char *table, const char *chain) {
    if (strcmp(table, "nat") == 0) { return nat_rules(f, chain, NULL, NULL); }
    pthread_mutex_lock(&f->mu);
    fake_table_t *t = ft_find(f, table);
    bool found = t ? fc_find(t, chain) != NULL : false;
    pthread_mutex_unlock(&f->mu);
    return found;
}

static int name_cmp_table(const void *a, const void *b) {
    const fake_table_t *ta = *(const fake_table_t *const *)a;
    const fake_table_t *tb = *(const fake_table_t *const *)b;
    return strcmp(ta->name, tb->name);
}

static int name_cmp_chain(const void *a, const void *b) {
    const fake_chain_t *ca = *(const fake_chain_t *const *)a;
    const fake_chain_t *cb = *(const fake_chain_t *const *)b;
    return strcmp(ca->name, cb->name);
}

static firc_err_t write_rule_parts(firc_bytebuf_t *buf, const firc_ipt_rule_t *r) {
    firc_err_t err = FIRC_OK;
    for (size_t i = 0; i < r->n_parts && err == FIRC_OK; i++) {
        err = firc_bytebuf_append_byte(buf, ' ');
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(buf, r->parts[i]); }
    }
    return err;
}

static firc_err_t fake_save_locked(firc_ipt_executable_t *self, const char *table, uint8_t **out,
                                   size_t *out_len) {
    firc_fake_ipt_t *f = (firc_fake_ipt_t *)self;
    firc_bytebuf_t buf;
    firc_bytebuf_init(&buf);
    firc_err_t err = FIRC_OK;

    fake_table_t **tables = NULL;
    if (f->n_tables > 0) {
        tables = malloc(f->n_tables * sizeof(*tables));
        if (!tables) { return FIRC_ERR_NOMEM; }
        for (size_t i = 0; i < f->n_tables; i++) { tables[i] = &f->tables[i]; }
        qsort(tables, f->n_tables, sizeof(*tables), name_cmp_table);
    }

    for (size_t ti = 0; ti < f->n_tables && err == FIRC_OK; ti++) {
        fake_table_t *t = tables[ti];
        if (strcmp(t->name, table) != 0) { continue; }
        err = firc_bytebuf_append_byte(&buf, '*');
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, t->name); }
        if (err == FIRC_OK) { err = firc_bytebuf_append_byte(&buf, '\n'); }
        if (err != FIRC_OK) { break; }

        fake_chain_t **chains = NULL;
        if (t->n_chains > 0) {
            chains = malloc(t->n_chains * sizeof(*chains));
            if (!chains) {
                err = FIRC_ERR_NOMEM;
                break;
            }
            for (size_t i = 0; i < t->n_chains; i++) { chains[i] = &t->chains[i]; }
            qsort(chains, t->n_chains, sizeof(*chains), name_cmp_chain);
        }

        for (size_t ci = 0; ci < t->n_chains && err == FIRC_OK; ci++) {
            err = firc_bytebuf_append_byte(&buf, ':');
            if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, chains[ci]->name); }
            if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, " - [0:0]\n"); }
        }
        for (size_t ci = 0; ci < t->n_chains && err == FIRC_OK; ci++) {
            fake_chain_t *c = chains[ci];
            for (size_t ri = 0; ri < c->n && err == FIRC_OK; ri++) {
                err = firc_bytebuf_append_str(&buf, "-A ");
                if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, c->name); }
                if (err == FIRC_OK) { err = write_rule_parts(&buf, c->rules[ri]); }
                if (err == FIRC_OK) { err = firc_bytebuf_append_byte(&buf, '\n'); }
            }
        }
        free(chains);
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(&buf, "COMMIT\n"); }
    }
    free(tables);

    if (err != FIRC_OK) {
        firc_bytebuf_free(&buf);
        return err;
    }
    *out = buf.data;
    *out_len = buf.len;
    return FIRC_OK;
}

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
        field_span_t *tmp = realloc(fields, (n + 1) * sizeof(*tmp));
        if (!tmp) {
            free(fields);
            return FIRC_ERR_NOMEM;
        }
        fields = tmp;
        fields[n].off = (size_t)start;
        fields[n].len = line_len - (size_t)start;
        n++;
    }
    *out = fields;
    *out_n = n;
    return FIRC_OK;
}

static firc_err_t rule_from_fields(const uint8_t *line, const field_span_t *fields,
                                 size_t start_field, size_t n_fields, firc_ipt_rule_t **out) {
    size_t n_parts = n_fields - start_field;
    char **parts = NULL;
    if (n_parts > 0) {
        parts = calloc(n_parts, sizeof(char *));
        if (!parts) { return FIRC_ERR_NOMEM; }
        for (size_t k = 0; k < n_parts; k++) {
            const field_span_t *fs = &fields[start_field + k];
            parts[k] = strndup((const char *)line + fs->off, fs->len);
            if (!parts[k]) {
                for (size_t j = 0; j < k; j++) { free(parts[j]); }
                free(parts);
                return FIRC_ERR_NOMEM;
            }
        }
    }
    firc_ipt_rule_t *r = firc_ipt_rule_new((const char *const *)parts, n_parts);
    for (size_t k = 0; k < n_parts; k++) { free(parts[k]); }
    free(parts);
    if (!r) { return FIRC_ERR_NOMEM; }
    *out = r;
    return FIRC_OK;
}

/* Bytes of `data` up to and including the `k`th COMMIT line; 0 for 0, all when there are fewer. */
static size_t commit_prefix_len(const uint8_t *data, size_t len, size_t k) {
    if (k == 0) { return 0; }
    size_t seen = 0, line = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] != '\n') { continue; }
        if (i - line >= 6 && memcmp(data + line, "COMMIT", 6) == 0 && ++seen == k) { return i + 1; }
        line = i + 1;
    }
    return len;
}

static bool builtin_chain(const char *name, size_t len) {
    static const char *const k_builtin[] = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"};
    for (size_t i = 0; i < sizeof(k_builtin) / sizeof(k_builtin[0]); i++) {
        if (strlen(k_builtin[i]) == len && memcmp(k_builtin[i], name, len) == 0) { return true; }
    }
    return false;
}

static firc_err_t fake_restore_locked(firc_ipt_executable_t *self, const uint8_t *data, size_t len) {
    firc_fake_ipt_t *f = (firc_fake_ipt_t *)self;
    fake_table_t *cur_table = NULL;
    firc_err_t err = FIRC_OK;

    size_t line_start = 0;
    for (size_t i = 0; i <= len && err == FIRC_OK; i++) {
        if (i < len && data[i] != '\n') { continue; }
        const uint8_t *line = data + line_start;
        size_t line_len = i - line_start;
        line_start = i + 1;
        if (line_len == 0) { continue; }

        switch (line[0]) {
        case '*':
            cur_table = ft_find_or_create(f, (const char *)line + 1, line_len - 1);
            if (!cur_table) { err = FIRC_ERR_NOMEM; }
            break;

        case ':': {
            field_span_t *fields = NULL;
            size_t n_fields = 0;
            err = split_fields(line + 1, line_len - 1, &fields, &n_fields);
            if (err != FIRC_OK) { break; }
            if (n_fields == 0) {
                err = FIRC_ERR_PROTO;
                free(fields);
                break;
            }
            if (!cur_table) {
                err = FIRC_ERR_PROTO;
                free(fields);
                break;
            }
            const char *cname = (const char *)(line + 1) + fields[0].off;
            fake_chain_t *c = fc_find_or_create(cur_table, cname, fields[0].len);
            if (!c) {
                err = FIRC_ERR_NOMEM;
            } else if (!builtin_chain(cname, fields[0].len)) {
                fc_clear(c);
            }
            free(fields);
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
            if (n_fields < 2 || fields[0].len < 2) {
                err = FIRC_ERR_PROTO;
                free(fields);
                break;
            }
            const char *chain_name = (const char *)line + fields[1].off;
            size_t chain_name_len = fields[1].len;
            uint8_t op = line[fields[0].off + 1];

            switch (op) {
            case 'A': {
                fake_chain_t *c = fc_find_or_create(cur_table, chain_name, chain_name_len);
                if (!c) {
                    err = FIRC_ERR_NOMEM;
                    break;
                }
                firc_ipt_rule_t *r;
                err = rule_from_fields(line, fields, 2, n_fields, &r);
                if (err == FIRC_OK) {
                    err = fc_append_owned(c, r);
                    if (err != FIRC_OK) { firc_ipt_rule_free(r); }
                }
                break;
            }
            case 'I': {
                if (n_fields < 3) {
                    err = FIRC_ERR_PROTO;
                    break;
                }
                char posbuf[32];
                size_t poslen = fields[2].len < sizeof(posbuf) - 1 ? fields[2].len
                                                                   : sizeof(posbuf) - 1;
                memcpy(posbuf, line + fields[2].off, poslen);
                posbuf[poslen] = '\0';
                char *endp = NULL;
                long pos = strtol(posbuf, &endp, 10);
                if (endp == posbuf || *endp != '\0' || pos < 1) {
                    err = FIRC_ERR_PROTO;
                    break;
                }
                fake_chain_t *c = fc_find_or_create(cur_table, chain_name, chain_name_len);
                if (!c) {
                    err = FIRC_ERR_NOMEM;
                    break;
                }
                firc_ipt_rule_t *r;
                err = rule_from_fields(line, fields, 3, n_fields, &r);
                if (err != FIRC_OK) { break; }

                size_t insert_idx = (size_t)pos - 1;
                if (insert_idx > c->n) { insert_idx = c->n; }

                if (c->n + 1 > c->cap) {
                    size_t newcap = c->cap == 0 ? 4 : c->cap * 2;
                    firc_ipt_rule_t **tmp = realloc(c->rules, newcap * sizeof(*tmp));
                    if (!tmp) {
                        firc_ipt_rule_free(r);
                        err = FIRC_ERR_NOMEM;
                        break;
                    }
                    c->rules = tmp;
                    c->cap = newcap;
                }
                for (size_t k = c->n; k > insert_idx; k--) { c->rules[k] = c->rules[k - 1]; }
                c->rules[insert_idx] = r;
                c->n++;
                break;
            }
            case 'D': {
                fake_chain_t *c = NULL;
                for (size_t ci = 0; ci < cur_table->n_chains; ci++) {
                    if (strlen(cur_table->chains[ci].name) == chain_name_len &&
                        memcmp(cur_table->chains[ci].name, chain_name, chain_name_len) == 0) {
                        c = &cur_table->chains[ci];
                        break;
                    }
                }
                firc_ipt_rule_t *want;
                err = rule_from_fields(line, fields, 2, n_fields, &want);
                if (err != FIRC_OK) { break; }

                bool found = false;
                if (c) {
                    for (size_t ri = 0; ri < c->n; ri++) {
                        if (!firc_ipt_rule_equal(c->rules[ri], want)) { continue; }
                        firc_ipt_rule_free(c->rules[ri]);
                        for (size_t k = ri; k + 1 < c->n; k++) { c->rules[k] = c->rules[k + 1]; }
                        c->n--;
                        found = true;
                        break;
                    }
                }
                firc_ipt_rule_free(want);
                if (!found) { err = FIRC_ERR_NOENT; }
                break;
            }
            case 'F': {
                fake_chain_t *c = fc_find_or_create(cur_table, chain_name, chain_name_len);
                if (!c) {
                    err = FIRC_ERR_NOMEM;
                    break;
                }
                fc_clear(c);
                break;
            }
            case 'X': {
                fake_chain_t *c = NULL;
                size_t idx = 0;
                for (size_t ci = 0; ci < cur_table->n_chains; ci++) {
                    if (strlen(cur_table->chains[ci].name) == chain_name_len &&
                        memcmp(cur_table->chains[ci].name, chain_name, chain_name_len) == 0) {
                        c = &cur_table->chains[ci];
                        idx = ci;
                        break;
                    }
                }
                if (c) {
                    if (c->n != 0) {
                        err = FIRC_ERR_STATE;
                        break;
                    }
                    bool referenced = false;
                    for (size_t ci = 0; ci < cur_table->n_chains && !referenced; ci++) {
                        const fake_chain_t *other = &cur_table->chains[ci];
                        for (size_t ri = 0; ri < other->n && !referenced; ri++) {
                            const firc_ipt_rule_t *rule = other->rules[ri];
                            for (size_t pi = 0; pi + 1 < rule->n_parts; pi++) {
                                if (strcmp(rule->parts[pi], "-j") == 0 && strcmp(rule->parts[pi + 1], c->name) == 0) {
                                    referenced = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (referenced) {
                        err = FIRC_ERR_STATE;
                        break;
                    }
                    free(c->name);
                    free(c->rules);
                    for (size_t k = idx; k + 1 < cur_table->n_chains; k++) {
                        cur_table->chains[k] = cur_table->chains[k + 1];
}
                    cur_table->n_chains--;
                }
                break;
            }
            default:
                err = FIRC_ERR_PROTO;
                break;
            }
            free(fields);
            break;
        }

        case '#':
            break;
        case 'C':
            cur_table = NULL;
            break;
        default:
            err = FIRC_ERR_PROTO;
            break;
        }
    }

    return err;
}

static firc_ipt_proto_t fake_proto(firc_ipt_executable_t *self) {
    return ((firc_fake_ipt_t *)self)->proto;
}

static void fake_clear(firc_fake_ipt_t *f) {
    for (size_t ti = 0; ti < f->n_tables; ti++) {
        fake_table_t *t = &f->tables[ti];
        for (size_t ci = 0; ci < t->n_chains; ci++) {
            fake_chain_t *c = &t->chains[ci];
            for (size_t ri = 0; ri < c->n; ri++) { firc_ipt_rule_free(c->rules[ri]); }
            free(c->rules);
            free(c->name);
        }
        free(t->chains);
        free(t->name);
    }
    free(f->tables);
    f->tables = NULL;
    f->n_tables = 0;
    f->cap_tables = 0;
}

void firc_fake_ipt_reset(firc_fake_ipt_t *f) {
    if (!f) { return; }
    pthread_mutex_lock(&f->mu);
    fake_clear(f);
    nat_view_clear(f);
    free(f->saved);
    f->saved = NULL;
    f->saved_len = 0;
    pthread_mutex_unlock(&f->mu);
    firc_fake_xt_reset(f->xt);
}

const char *firc_fake_ipt_saved_log(firc_fake_ipt_t *f) {
    pthread_mutex_lock(&f->mu);
    const char *s = f->saved != NULL ? f->saved : "";
    pthread_mutex_unlock(&f->mu);
    return s;
}

static firc_err_t fake_save(firc_ipt_executable_t *self, const char *table, uint8_t **out, size_t *out_len) {
    firc_fake_ipt_t *f = (firc_fake_ipt_t *)self;
    pthread_mutex_lock(&f->mu);
    size_t tl = strlen(table);
    char *grown = realloc(f->saved, f->saved_len + tl + 2);
    if (grown != NULL) {
        memcpy(grown + f->saved_len, table, tl);
        grown[f->saved_len + tl] = '\n';
        f->saved_len += tl + 1;
        grown[f->saved_len] = '\0';
        f->saved = grown;
    }
    firc_err_t err = fake_save_locked(self, table, out, out_len);
    pthread_mutex_unlock(&f->mu);
    return err;
}

/* Every transcript handed to `restore`, in order, refused ones included, and every nat table written */
const char *firc_fake_ipt_restore_log(firc_fake_ipt_t *f) {
    pthread_mutex_lock(&f->mu);
    const char *s = f->log;
    pthread_mutex_unlock(&f->mu);
    return s;
}

static firc_err_t fake_restore(firc_ipt_executable_t *self, const uint8_t *data, size_t len) {
    firc_fake_ipt_t *f = (firc_fake_ipt_t *)self;
    pthread_mutex_lock(&f->mu);
    f->restore_calls++;
    log_append(f, (const char *)data, len);
    bool names_nat = false;
    for (size_t i = 0; i + 4 <= len && !names_nat; i++) {
        names_nat = (i == 0 || data[i - 1] == '\n') && memcmp(data + i, "*nat", 4) == 0 &&
                    (i + 4 == len || data[i + 4] == '\n');
    }
    if (names_nat) {
        pthread_mutex_unlock(&f->mu);
        return FIRC_ERR_STATE;
    }
    firc_err_t err = f->next_restore_err;
    if (err != FIRC_OK) {
        f->next_restore_err = FIRC_OK;
    } else if (f->fail_at_commit != 0) {
        size_t upto = commit_prefix_len(data, len, f->fail_at_commit - 1);
        err = f->fail_at_err;
        f->fail_at_commit = 0;
        if (upto > 0) { (void)fake_restore_locked(self, data, upto); }
    } else if (fake_refuses(f, data, len)) {
        err = FIRC_ERR_IO;
    } else {
        err = fake_restore_locked(self, data, len);
    }
    void (*fn)(void *) = err == FIRC_OK ? f->on_restore : NULL;
    void *ud = f->on_restore_ud;
    pthread_mutex_unlock(&f->mu);
    if (fn != NULL) { fn(ud); }
    return err;
}

void firc_fake_ipt_on_restore(firc_fake_ipt_t *f, void (*fn)(void *ud), void *ud) {
    pthread_mutex_lock(&f->mu);
    f->on_restore = fn;
    f->on_restore_ud = ud;
    pthread_mutex_unlock(&f->mu);
}

size_t firc_fake_ipt_restore_calls(firc_fake_ipt_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->restore_calls;
    pthread_mutex_unlock(&f->mu);
    return n;
}

void firc_fake_ipt_fail_next_restore(firc_fake_ipt_t *f, firc_err_t err) {
    pthread_mutex_lock(&f->mu);
    f->next_restore_err = err;
    pthread_mutex_unlock(&f->mu);
}

void firc_fake_ipt_fail_at_commit(firc_fake_ipt_t *f, size_t n, firc_err_t err) {
    pthread_mutex_lock(&f->mu);
    f->fail_at_commit = n;
    f->fail_at_err = err;
    pthread_mutex_unlock(&f->mu);
}

bool firc_fake_ipt_failure_armed(firc_fake_ipt_t *f) {
    pthread_mutex_lock(&f->mu);
    bool armed = f->next_restore_err != FIRC_OK || f->fail_at_commit != 0;
    pthread_mutex_unlock(&f->mu);
    return armed;
}

void firc_fake_ipt_refuse_rules_containing(firc_fake_ipt_t *f, const char *substr) {
    pthread_mutex_lock(&f->mu);
    free(f->refuse);
    f->refuse = substr != NULL ? strdup(substr) : NULL;
    pthread_mutex_unlock(&f->mu);
}

static void fake_destroy(firc_ipt_executable_t *self) {
    firc_fake_ipt_t *f = (firc_fake_ipt_t *)self;
    if (!f) { return; }
    fake_clear(f);
    nat_view_clear(f);
    firc_fake_xt_free(f->xt);
    free(f->refuse);
    free(f->log);
    free(f->saved);
    pthread_mutex_destroy(&f->mu);
    free(f);
}

static const firc_ipt_executable_ops_t k_fake_ops = {
    .save = fake_save,
    .restore = fake_restore,
    .proto = fake_proto,
    .destroy = fake_destroy,
};

firc_fake_ipt_t *firc_fake_ipt_new(firc_ipt_proto_t proto) {
    firc_fake_ipt_t *f = calloc(1, sizeof(*f));
    if (!f) { return NULL; }
    f->base.ops = &k_fake_ops;
    f->proto = proto;
    pthread_mutex_init(&f->mu, NULL);
    f->xt = firc_fake_xt_new(proto);
    if (f->xt == NULL) {
        pthread_mutex_destroy(&f->mu);
        free(f);
        return NULL;
    }
    firc_fake_xt_set_write_hooks(f->xt, nat_before, nat_after, f);
    return f;
}

firc_ipt_executable_t *firc_fake_ipt_as_executable(firc_fake_ipt_t *f) {
    return &f->base;
}

firc_xt_t *firc_fake_ipt_as_xt(firc_fake_ipt_t *f) {
    return firc_fake_xt_handle(f->xt);
}

firc_fake_xt_t *firc_fake_ipt_xt(firc_fake_ipt_t *f) {
    return f->xt;
}
