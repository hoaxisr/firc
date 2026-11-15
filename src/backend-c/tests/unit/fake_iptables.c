#include "fake_iptables.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xt_golden.h"

typedef struct view {
    firc_ipt_rule_t **rules;
    size_t n;
    struct view *next;
} view_t;

struct firc_fake_ipt {
    pthread_mutex_t mu;
    firc_ipt_proto_t proto;
    firc_fake_xt_t *xt;
    unsigned handles;
    int next_err;
    size_t fail_at;
    int fail_at_err;
    size_t writes;
    size_t attempts;
    char *refuse;
    char *refuse_also;
    char *log;
    size_t log_len;
    char *reads;
    size_t reads_len;
    view_t *views;
    void (*on_write)(void *ud);
    void *on_write_ud;
};

static void append(char **buf, size_t *len, const char *text) {
    size_t n = strlen(text);
    char *grown = realloc(*buf, *len + n + 1);
    if (grown == NULL) { return; }
    memcpy(grown + *len, text, n + 1);
    *len += n;
    *buf = grown;
}

static int before_write(void *ud, firc_ipt_proto_t fam, const char *table, const firc_xt_info_t *info,
                        const uint8_t *blob) {
    firc_fake_ipt_t *f = ud;
    char *text = firc_test_xt_print_named(fam, table, info, blob, firc_fake_xt_namer, f->xt);
    pthread_mutex_lock(&f->mu);
    f->attempts++;
    int err = 0;
    if (f->next_err != 0) {
        err = f->next_err;
        f->next_err = 0;
    } else if (f->fail_at != 0 && --f->fail_at == 0) {
        err = f->fail_at_err;
    } else if (f->refuse != NULL && f->refuse[0] != '\0' && text != NULL && strstr(text, f->refuse) != NULL) {
        err = EINVAL;
    } else if (f->refuse_also != NULL && text != NULL && strstr(text, f->refuse_also) != NULL) {
        err = EINVAL;
    }
    pthread_mutex_unlock(&f->mu);
    free(text);
    return err;
}

static void after_write(void *ud, const char *table) {
    firc_fake_ipt_t *f = ud;
    char *text = firc_fake_ipt_print(f, table);
    pthread_mutex_lock(&f->mu);
    if (text != NULL) { append(&f->log, &f->log_len, text); }
    f->writes++;
    void (*fn)(void *) = f->on_write;
    void *fn_ud = f->on_write_ud;
    pthread_mutex_unlock(&f->mu);
    free(text);
    if (fn != NULL) { fn(fn_ud); }
}

static void on_read(void *ud, const char *table) {
    firc_fake_ipt_t *f = ud;
    pthread_mutex_lock(&f->mu);
    append(&f->reads, &f->reads_len, table);
    append(&f->reads, &f->reads_len, "\n");
    pthread_mutex_unlock(&f->mu);
}

static void hooks_on(firc_fake_ipt_t *f) {
    firc_fake_xt_set_write_hooks(f->xt, before_write, after_write, f);
    firc_fake_xt_on_read(f->xt, on_read, f);
}

static void hooks_off(firc_fake_ipt_t *f) {
    firc_fake_xt_set_write_hooks(f->xt, NULL, NULL, NULL);
    firc_fake_xt_on_read(f->xt, NULL, NULL);
}

static void views_clear(firc_fake_ipt_t *f) {
    while (f->views != NULL) {
        view_t *v = f->views;
        f->views = v->next;
        for (size_t i = 0; i < v->n; i++) { firc_ipt_rule_free(v->rules[i]); }
        free(v->rules);
        free(v);
    }
}

static void fake_free(firc_fake_ipt_t *f) {
    firc_fake_xt_free(f->xt);
    views_clear(f);
    free(f->refuse);
    free(f->refuse_also);
    free(f->log);
    free(f->reads);
    pthread_mutex_destroy(&f->mu);
    free(f);
}

firc_fake_ipt_t *firc_fake_ipt_new(firc_ipt_proto_t proto) {
    firc_fake_ipt_t *f = calloc(1, sizeof(*f));
    if (f == NULL) { return NULL; }
    pthread_mutex_init(&f->mu, NULL);
    f->proto = proto;
    f->xt = firc_fake_xt_new(proto);
    if (f->xt == NULL) {
        pthread_mutex_destroy(&f->mu);
        free(f);
        return NULL;
    }
    hooks_on(f);
    return f;
}

void firc_fake_ipt_free(firc_fake_ipt_t *f) {
    if (f != NULL && f->handles == 0) { fake_free(f); }
}

static firc_fake_xt_t *inner(void *ud) { return ((firc_fake_ipt_t *)ud)->xt; }

static int h_get_info(void *ud, firc_ipt_proto_t fam, const char *t, firc_xt_info_t *o) {
    return firc_fake_xt_ops()->get_info(inner(ud), fam, t, o);
}
static int h_get_entries(void *ud, firc_ipt_proto_t fam, const char *t, uint8_t *b, uint32_t s) {
    return firc_fake_xt_ops()->get_entries(inner(ud), fam, t, b, s);
}
static int h_replace(void *ud, firc_ipt_proto_t fam, const char *t, const firc_xt_info_t *i, uint8_t *b, uint32_t n,
                     firc_xt_counter_t *old) {
    return firc_fake_xt_ops()->replace(inner(ud), fam, t, i, b, n, old);
}
static int h_add_counters(void *ud, firc_ipt_proto_t fam, const char *t, const firc_xt_counter_t *c, uint32_t n) {
    return firc_fake_xt_ops()->add_counters(inner(ud), fam, t, c, n);
}
static int h_get_revision(void *ud, firc_ipt_proto_t fam, bool target, const char *name, uint8_t rev) {
    return firc_fake_xt_ops()->get_revision(inner(ud), fam, target, name, rev);
}
static int h_set_index(void *ud, const char *name, uint16_t *index) {
    return firc_fake_xt_ops()->set_index(inner(ud), name, index);
}
static int h_lock(void *ud, unsigned wait_ms) { return firc_fake_xt_ops()->lock(inner(ud), wait_ms); }
static void h_unlock(void *ud) { firc_fake_xt_ops()->unlock(inner(ud)); }
static void h_destroy(void *ud) {
    firc_fake_ipt_t *f = ud;
    pthread_mutex_lock(&f->mu);
    bool last = --f->handles == 0;
    pthread_mutex_unlock(&f->mu);
    if (last) { fake_free(f); }
}

static const firc_xt_kernel_ops_t k_handle_ops = {h_get_info, h_get_entries, h_replace, h_add_counters,
                                                  h_get_revision, h_lock, h_unlock, h_destroy, h_set_index};

firc_xt_t *firc_fake_ipt_as_xt(firc_fake_ipt_t *f) {
    firc_xt_t *xt = firc_xt_new(f->proto, &k_handle_ops, f);
    if (xt != NULL) {
        pthread_mutex_lock(&f->mu);
        f->handles++;
        pthread_mutex_unlock(&f->mu);
    }
    return xt;
}

firc_fake_xt_t *firc_fake_ipt_xt(firc_fake_ipt_t *f) { return f->xt; }

char *firc_fake_ipt_print(firc_fake_ipt_t *f, const char *table) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    if (!firc_fake_xt_blob(f->xt, table, &info, &blob)) { return NULL; }
    char *text = firc_test_xt_print_named(f->proto, table, &info, blob, firc_fake_xt_namer, f->xt);
    free(blob);
    return text;
}

firc_err_t firc_fake_ipt_set_initial_rules(firc_fake_ipt_t *f, const char *table, const char *chain,
                                           const char *const *const *rules, const size_t *rule_lens, size_t n_rules) {
    firc_ipt_rule_t **rs = calloc(n_rules ? n_rules : 1, sizeof(*rs));
    if (rs == NULL) { return FIRC_ERR_NOMEM; }
    for (size_t i = 0; i < n_rules; i++) { rs[i] = firc_ipt_rule_new(rules[i], rule_lens[i]); }
    firc_xt_stage_chain_t sc = {chain, FIRC_XT_STAGE_OVERRIDE, rs, n_rules, NULL, 0, NULL};
    firc_xt_stage_t stage = {&sc, 1, NULL, false};
    hooks_off(f);
    firc_xt_t *h = firc_fake_xt_handle(f->xt);
    firc_err_t err = h != NULL ? firc_xt_commit(h, table, &stage, NULL) : FIRC_ERR_NOMEM;
    firc_xt_free(h);
    hooks_on(f);
    for (size_t i = 0; i < n_rules; i++) { firc_ipt_rule_free(rs[i]); }
    free(rs);
    return err;
}

static bool chain_rules(firc_fake_ipt_t *f, const char *table, const char *chain, firc_ipt_rule_t *const **out, size_t *n) {
    char *text = firc_fake_ipt_print(f, table);
    if (text == NULL) { return false; }
    char decl[64], rule[64];
    snprintf(decl, sizeof(decl), ":%s ", chain);
    int rule_len = snprintf(rule, sizeof(rule), "-A %s", chain);
    bool exists = false;
    view_t *v = calloc(1, sizeof(*v));
    for (char *save = NULL, *line = strtok_r(text, "\n", &save); v != NULL && line != NULL; line = strtok_r(NULL, "\n", &save)) {
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
        v->next = f->views;
        f->views = v;
        pthread_mutex_unlock(&f->mu);
    }
    free(text);
    return exists;
}

bool firc_fake_ipt_get_rules(firc_fake_ipt_t *f, const char *table, const char *chain, firc_ipt_rule_t *const **out_rules,
                             size_t *out_n) {
    return chain_rules(f, table, chain, out_rules, out_n);
}

bool firc_fake_ipt_chain_exists(firc_fake_ipt_t *f, const char *table, const char *chain) {
    return chain_rules(f, table, chain, NULL, NULL);
}

void firc_fake_ipt_reset(firc_fake_ipt_t *f) {
    firc_fake_xt_reset(f->xt);
    pthread_mutex_lock(&f->mu);
    views_clear(f);
    f->next_err = 0;
    f->fail_at = 0;
    f->writes = 0;
    free(f->refuse);
    f->refuse = NULL;
    free(f->refuse_also);
    f->refuse_also = NULL;
    free(f->log);
    f->log = NULL;
    f->log_len = 0;
    free(f->reads);
    f->reads = NULL;
    f->reads_len = 0;
    pthread_mutex_unlock(&f->mu);
}

static int to_errno(firc_err_t err) {
    if (err == FIRC_ERR_CANCELED) {
        fprintf(stderr, "fake_iptables: a kernel cannot answer CANCELED; raise the engine's token instead\n");
        abort();
    }
    return err == FIRC_ERR_AGAIN ? EAGAIN : EINVAL;
}

void firc_fake_ipt_fail_next_write(firc_fake_ipt_t *f, firc_err_t err) {
    int e = to_errno(err);
    pthread_mutex_lock(&f->mu);
    f->next_err = e;
    pthread_mutex_unlock(&f->mu);
}

void firc_fake_ipt_fail_at_commit(firc_fake_ipt_t *f, size_t n, firc_err_t err) {
    int e = to_errno(err);
    pthread_mutex_lock(&f->mu);
    f->fail_at = n;
    f->fail_at_err = e;
    pthread_mutex_unlock(&f->mu);
}

bool firc_fake_ipt_failure_armed(firc_fake_ipt_t *f) {
    pthread_mutex_lock(&f->mu);
    bool armed = f->next_err != 0 || f->fail_at != 0;
    pthread_mutex_unlock(&f->mu);
    return armed;
}

void firc_fake_ipt_refuse_rules_containing(firc_fake_ipt_t *f, const char *substr) {
    pthread_mutex_lock(&f->mu);
    free(f->refuse);
    f->refuse = substr != NULL ? strdup(substr) : NULL;
    pthread_mutex_unlock(&f->mu);
}

void firc_fake_ipt_refuse_also_containing(firc_fake_ipt_t *f, const char *substr) {
    pthread_mutex_lock(&f->mu);
    free(f->refuse_also);
    f->refuse_also = substr != NULL ? strdup(substr) : NULL;
    pthread_mutex_unlock(&f->mu);
}

const char *firc_fake_ipt_writes_log(firc_fake_ipt_t *f) { return f->log != NULL ? f->log : ""; }
const char *firc_fake_ipt_reads_log(firc_fake_ipt_t *f) { return f->reads != NULL ? f->reads : ""; }

size_t firc_fake_ipt_writes(firc_fake_ipt_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->writes;
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t firc_fake_ipt_attempts(firc_fake_ipt_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->attempts;
    pthread_mutex_unlock(&f->mu);
    return n;
}

void firc_fake_ipt_on_write(firc_fake_ipt_t *f, void (*fn)(void *ud), void *ud) {
    pthread_mutex_lock(&f->mu);
    f->on_write = fn;
    f->on_write_ud = ud;
    pthread_mutex_unlock(&f->mu);
}
