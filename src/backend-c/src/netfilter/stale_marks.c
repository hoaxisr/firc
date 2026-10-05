#include "firc/stale_marks.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "firc/log.h"
#include "firc/match.h"

typedef struct {
    firc_ct_chunk_t *v;
    size_t n, cap;
    uint32_t field;
    bool inexact;
    bool oom;
} table_t;

static firc_ct_chunk_t *reserve(table_t *t) {
    if (t->oom) { return NULL; }
    if (t->n == t->cap) {
        size_t cap = t->cap ? t->cap * 2 : 16;
        firc_ct_chunk_t *v = realloc(t->v, cap * sizeof(*v));
        if (v == NULL) {
            t->oom = true;
            return NULL;
        }
        t->v = v;
        t->cap = cap;
    }
    firc_ct_chunk_t *c = &t->v[t->n++];
    memset(c, 0, sizeof(*c));
    return c;
}

static void append(table_t *t, const firc_ct_chunk_t *src) {
    firc_ct_chunk_t *c = reserve(t);
    if (c != NULL) { *c = *src; }
}

static void collect_chunk(void *ud, const char *group_id, unsigned family, const firc_ip_t *base,
                          uint8_t prefix) {
    (void)group_id;
    table_t *t = ud;
    firc_ct_chunk_t *c = reserve(t);
    if (c == NULL) { return; }
    c->family = (uint8_t)(family == FIRC_FAM_V4 ? AF_INET : AF_INET6);
    size_t n = base->len <= sizeof(c->base) ? base->len : sizeof(c->base);
    memcpy(c->base, base->b, n);
    c->prefix = prefix;
    c->field = t->field;
    c->inexact = t->inexact;
}

bool firc_stale_group_subnets(const firc_group_t *g, uint32_t field, firc_ct_chunk_t **out,
                              size_t *out_n) {
    *out = NULL;
    *out_n = 0;
    if (g == NULL || (g->n_rules == 0 && (g->list == NULL || g->list->rules.n == 0))) {
        return true;
    }
    const firc_sub_rules_t *lr = g->list != NULL ? &g->list->rules : NULL;
    /* Counted first: a long list holds only a handful of subnet rules. */
    size_t want = 0;
    for (size_t i = 0; i < g->n_rules; i++) {
        const firc_rule_t *r = g->rules[i];
        if (!r->enable || r->type == NULL || r->rule == NULL) { continue; }
        if (strcmp(r->type, FIRC_RULE_SUBNET) == 0 || strcmp(r->type, FIRC_RULE_SUBNET6) == 0) {
            want++;
        }
    }
    for (size_t i = 0; lr != NULL && i < lr->n; i++) {
        if (!firc_sub_rules_enable(lr, i)) { continue; }
        const char *type = firc_sub_rules_type(lr, i);
        if (strcmp(type, FIRC_RULE_SUBNET) == 0 || strcmp(type, FIRC_RULE_SUBNET6) == 0) {
            want++;
        }
    }
    if (want == 0) { return true; }
    firc_ct_chunk_t *v = calloc(want, sizeof(*v));
    if (v == NULL) { return false; }

    size_t n = 0;
    for (size_t i = 0; i < g->n_rules && n < want; i++) {
        const firc_rule_t *r = g->rules[i];
        if (!r->enable || r->type == NULL || r->rule == NULL) { continue; }
        if (strcmp(r->type, FIRC_RULE_SUBNET) == 0) {
            firc_ipv4_subnet_t s4;
            if (!firc_rule_parse_subnet4(r->rule, &s4)) { continue; }
            v[n].family = AF_INET;
            memcpy(v[n].base, s4.addr, 4);
            v[n].prefix = s4.cidr;
        } else if (strcmp(r->type, FIRC_RULE_SUBNET6) == 0) {
            firc_ipv6_subnet_t s6;
            if (!firc_rule_parse_subnet6(r->rule, &s6)) { continue; }
            v[n].family = AF_INET6;
            memcpy(v[n].base, s6.addr, 16);
            v[n].prefix = s6.cidr;
        } else {
            continue;
        }
        v[n].is_subnet = true;
        v[n].field = field;
        n++;
    }
    for (size_t i = 0; lr != NULL && i < lr->n && n < want; i++) {
        if (!firc_sub_rules_enable(lr, i)) { continue; }
        const char *type = firc_sub_rules_type(lr, i);
        const char *text = firc_sub_rules_text(lr, i);
        if (strcmp(type, FIRC_RULE_SUBNET) == 0) {
            firc_ipv4_subnet_t s4;
            if (!firc_rule_parse_subnet4(text, &s4)) { continue; }
            v[n].family = AF_INET;
            memcpy(v[n].base, s4.addr, 4);
            v[n].prefix = s4.cidr;
        } else if (strcmp(type, FIRC_RULE_SUBNET6) == 0) {
            firc_ipv6_subnet_t s6;
            if (!firc_rule_parse_subnet6(text, &s6)) { continue; }
            v[n].family = AF_INET6;
            memcpy(v[n].base, s6.addr, 16);
            v[n].prefix = s6.cidr;
        } else {
            continue;
        }
        v[n].is_subnet = true;
        v[n].field = field;
        n++;
    }
    if (n == 0) {
        free(v);
        return true;
    }
    *out = v;
    *out_n = n;
    return true;
}

firc_err_t firc_stale_marks_sweep(firc_ct_t *ct, const firc_fakeip_t *pool, bool pool_state_trusted,
                                  const firc_stale_group_t *groups, size_t n_groups, uint32_t mask,
                                  size_t *dropped) {
    if (dropped != NULL) { *dropped = 0; }
    if (ct == NULL || pool == NULL) { return FIRC_OK; }
    if (!pool_state_trusted) {
        FIRC_INFO("not checking for flows marked by a previous run: the pool state this run holds is "
                  "not the one that issued their addresses");
        return FIRC_OK;
    }

    table_t t = {0};
    for (size_t i = 0; i < n_groups; i++) {
        t.field = groups[i].field & mask;
        t.inexact = groups[i].inexact;
        if (groups[i].id != NULL) { firc_fakeip_walk_chunks(pool, groups[i].id, collect_chunk, &t); }
        for (size_t k = 0; k < groups[i].n_subnets && !t.oom; k++) {
            firc_ct_chunk_t sub = groups[i].subnets[k];
            sub.is_subnet = true;
            sub.field = t.field;
            append(&t, &sub);
        }
    }
    if (t.oom) {
        /* A partial table would call live chunks orphaned: touch nothing. */
        FIRC_WARN("not enough memory to check for flows marked by a previous run; none were touched");
        free(t.v);
        return FIRC_ERR_NOMEM;
    }

    firc_ip_t b4, b6;
    uint8_t l4 = 0, l6 = 0;
    bool has4 = firc_fakeip_pool_prefix(pool, FIRC_FAM_V4, &b4, &l4);
    bool has6 = firc_fakeip_pool_prefix(pool, FIRC_FAM_V6, &b6, &l6);
    firc_err_t err = firc_ct_flush_stale_group_marks(ct, has4 ? b4.b : NULL, has4 ? l4 : 0,
                                                     has6 ? b6.b : NULL, has6 ? l6 : 0, t.v, t.n, mask,
                                                     dropped);
    free(t.v);
    return err;
}
