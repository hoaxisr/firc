#include "fake_xtables.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/xtables/abi.h"
#include "xt_golden.h"

typedef struct fake_table {
    char name[32];
    firc_xt_info_t info;
    uint8_t *blob;
    firc_xt_counter_t *counters;
} fake_table_t;

typedef struct fake_lack {
    bool target;
    char name[32];
    uint8_t rev;
    bool any;
    int err;
} fake_lack_t;

struct firc_fake_xt {
    pthread_mutex_t mu;
    firc_ipt_proto_t fam;
    fake_table_t tables[4];
    size_t n_tables;
    int fail_replace, fail_counters, fail_revisions;
    struct { char name[32]; int err; } fail_tables[4];
    char *order, *rorder;
    size_t order_len, rorder_len;
    firc_fake_xt_race_t race;
    unsigned infos_since_race;
    fake_lack_t lacks[8];
    size_t n_lacks;
    struct { char name[32]; uint16_t index; } sets[16];
    size_t n_sets, set_asks;
    int fail_sets;
    bool lock_held, firc_holds;
    size_t replaces, reads, revision_asks, reads_under_lock, writes_outside_lock;
    void (*on_read)(void *ud, const char *table);
    void *read_ud;
    void (*on_unlock)(void *ud);
    void *unlock_ud;
    int (*before)(void *ud, firc_ipt_proto_t fam, const char *table, const firc_xt_info_t *info, const uint8_t *blob);
    void (*after)(void *ud, const char *table);
    void *hook_ud;
};

static uint16_t g16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t g32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static fake_table_t *find(firc_fake_xt_t *f, const char *table) {
    for (size_t i = 0; i < f->n_tables; i++) {
        if (strcmp(f->tables[i].name, table) == 0) { return &f->tables[i]; }
    }
    return NULL;
}

static bool on_entry(const uint32_t *offs, uint32_t n, uint32_t x) {
    for (uint32_t i = 0; i < n; i++) {
        if (offs[i] == x) { return true; }
    }
    return false;
}

static bool kernel_accepts(bool v6, const firc_xt_info_t *in, const uint8_t *b) {
    uint32_t eh = v6 ? 168u : 112u, at_t = v6 ? 140u : 88u, ip_len = v6 ? 136u : 84u;
    uint32_t cap = in->size / 152u + 2u, n = 0;
    uint32_t *offs = malloc(cap * sizeof(*offs));
    bool ok = offs != NULL;
    for (uint32_t off = 0; ok && off < in->size;) {
        if (off % 8u != 0 || in->size - off < eh + 32u || n == cap) { ok = false; break; }
        uint16_t toff = g16(b + off + at_t), next = g16(b + off + at_t + 2);
        if (next < eh + 32u || next > in->size - off || toff < eh || (uint32_t)toff + 32u > next) { ok = false; break; }
        uint32_t m = eh;
        while (m < toff) {
            uint16_t ms = g16(b + off + m);
            if (ms < 32u || ms > toff - m) { break; }
            m += ms;
        }
        if (m != toff || (uint32_t)toff + g16(b + off + toff) > next) { ok = false; break; }
        offs[n++] = off;
        off += next;
    }
    ok = ok && n > 0 && n == in->num_entries;
    if (ok) {
        const uint8_t *last = b + offs[n - 1];
        ok = strcmp((const char *)last + g16(last + at_t) + 2, "ERROR") == 0;
    }
    static const uint8_t zero[136];
    for (int h = 0; ok && h < 5; h++) {
        if (!(in->valid_hooks & (1u << h))) { continue; }
        ok = on_entry(offs, n, in->hook_entry[h]) && on_entry(offs, n, in->underflow[h]);
        if (!ok) { break; }
        const uint8_t *u = b + in->underflow[h];
        int32_t v = (int32_t)g32(u + eh + 32);
        ok = g16(u + at_t) == eh && u[eh + 2] == '\0' && (v == -1 || v == -2) && memcmp(u, zero, ip_len) == 0;
    }
    for (uint32_t i = 0; ok && i < n; i++) {
        const uint8_t *e = b + offs[i];
        const uint8_t *t = e + g16(e + at_t);
        if (t[2] != '\0') { continue; }
        int32_t v = (int32_t)g32(t + 32);
        ok = g16(t) == 40u && (v >= 0 ? on_entry(offs, n, (uint32_t)v) : v >= -5);
    }
    free(offs);
    return ok;
}

enum { HOOK_PRE = 1u << 0, HOOK_IN = 1u << 1, HOOK_FWD = 1u << 2, HOOK_OUT = 1u << 3, HOOK_POST = 1u << 4 };

typedef struct kview {
    const uint8_t *b;
    const uint32_t *offs;
    uint32_t n, eh, at_t, ip_len;
    uint32_t *mask;
    uint8_t *onpath;
} kview_t;

static int index_of(const kview_t *v, uint32_t off) {
    uint32_t lo = 0, hi = v->n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (v->offs[mid] == off) { return (int)mid; }
        if (v->offs[mid] < off) { lo = mid + 1; } else { hi = mid; }
    }
    return -1;
}

static const uint8_t *target_at(const kview_t *v, uint32_t i) { return v->b + v->offs[i] + g16(v->b + v->offs[i] + v->at_t); }

static bool unconditional(const kview_t *v, uint32_t i) {
    static const uint8_t zero[136];
    const uint8_t *e = v->b + v->offs[i];
    return g16(e + v->at_t) == v->eh && memcmp(e, zero, v->ip_len) == 0;
}

static int walk(kview_t *v, uint32_t k, unsigned hook) {
    uint32_t first = k;
    int err = 0;
    for (;; k++) {
        if (k >= v->n) {
            err = ELOOP;
            break;
        }
        if (v->onpath[k]) {
            err = ELOOP;
            break;
        }
        bool visited = (v->mask[k] & (1u << hook)) != 0;
        v->mask[k] |= 1u << hook;
        v->onpath[k] = 1;
        const uint8_t *t = target_at(v, k);
        bool standard = t[2] == '\0';
        int32_t verdict = (int32_t)g32(t + 32);
        if (visited || (standard && verdict < 0 && unconditional(v, k))) { break; }
        if (standard && verdict >= 0 && (err = walk(v, (uint32_t)index_of(v, (uint32_t)verdict), hook)) != 0) { break; }
    }
    for (uint32_t i = first; i <= k && i < v->n; i++) { v->onpath[i] = 0; }
    return err;
}

typedef struct kext {
    const char *name;
    bool target;
    uint8_t rev, fam, proto;
    uint32_t size, hooks;
    const char *table;
} kext_t;

#define ALL_HOOKS 0x1fu
static const kext_t k_exts[] = {
    {"", true, 0, 0, 0, sizeof(int32_t), ALL_HOOKS, NULL},
    {"ERROR", true, 0, 0, 0, XT_ERRORNAME_LEN, ALL_HOOKS, NULL},
    {"DNAT", true, 0, 4, 0, sizeof(xt_nat_ipv4_compat_t), HOOK_PRE | HOOK_OUT, "nat"},
    {"DNAT", true, 1, 4, 0, sizeof(xt_nat_range_t), HOOK_PRE | HOOK_OUT, "nat"},
    {"DNAT", true, 1, 6, 0, sizeof(xt_nat_range_t), HOOK_PRE | HOOK_OUT, "nat"},
    {"SNAT", true, 0, 4, 0, sizeof(xt_nat_ipv4_compat_t), HOOK_POST | HOOK_IN, "nat"},
    {"SNAT", true, 1, 4, 0, sizeof(xt_nat_range_t), HOOK_POST | HOOK_IN, "nat"},
    {"SNAT", true, 1, 6, 0, sizeof(xt_nat_range_t), HOOK_POST | HOOK_IN, "nat"},
    {"MASQUERADE", true, 0, 4, 0, sizeof(xt_nat_ipv4_compat_t), HOOK_POST, "nat"},
    {"MASQUERADE", true, 0, 6, 0, sizeof(xt_nat_range_t), HOOK_POST, "nat"},
    {"REDIRECT", true, 0, 4, 0, sizeof(xt_nat_ipv4_compat_t), HOOK_PRE | HOOK_OUT, "nat"},
    {"REDIRECT", true, 0, 6, 0, sizeof(xt_nat_range_t), HOOK_PRE | HOOK_OUT, "nat"},
    {"REJECT", true, 0, 4, 0, sizeof(xt_reject_info_t), HOOK_IN | HOOK_FWD | HOOK_OUT, "filter"},
    {"REJECT", true, 0, 6, 0, sizeof(xt_reject_info_t), HOOK_IN | HOOK_FWD | HOOK_OUT, "filter"},
    {"MARK", true, 2, 0, 0, sizeof(xt_mark_tginfo2_t), ALL_HOOKS, NULL},
    {"CONNMARK", true, 1, 0, 0, sizeof(xt_connmark_tginfo1_t), ALL_HOOKS, NULL},
    {"NFLOG", true, 0, 0, 0, sizeof(xt_nflog_info_t), ALL_HOOKS, NULL},
    {"TCPMSS", true, 0, 4, 6, sizeof(xt_tcpmss_info_t), HOOK_FWD | HOOK_OUT | HOOK_POST, NULL},
    {"TCPMSS", true, 0, 6, 6, sizeof(xt_tcpmss_info_t), HOOK_FWD | HOOK_OUT | HOOK_POST, NULL},
    {"mark", false, 1, 0, 0, sizeof(xt_mark_mtinfo1_t), ALL_HOOKS, NULL},
    {"connmark", false, 1, 0, 0, sizeof(xt_connmark_mtinfo1_t), ALL_HOOKS, NULL},
    {"tcp", false, 0, 4, 6, sizeof(xt_tcp_t), ALL_HOOKS, NULL},
    {"tcp", false, 0, 6, 6, sizeof(xt_tcp_t), ALL_HOOKS, NULL},
    {"udp", false, 0, 4, 17, sizeof(xt_udp_t), ALL_HOOKS, NULL},
    {"udp", false, 0, 6, 17, sizeof(xt_udp_t), ALL_HOOKS, NULL},
    {"conntrack", false, 3, 0, 0, sizeof(xt_conntrack_mtinfo3_t), ALL_HOOKS, NULL},
    {"multiport", false, 1, 4, 0, sizeof(xt_multiport_v1_t), ALL_HOOKS, NULL},
    {"multiport", false, 1, 6, 0, sizeof(xt_multiport_v1_t), ALL_HOOKS, NULL},
    {"mac", false, 0, 0, 0, sizeof(xt_mac_info_t), HOOK_PRE | HOOK_IN | HOOK_FWD, NULL},
    {"mac", false, 1, 0, 0, sizeof(xt_mac_info_t), HOOK_PRE | HOOK_IN | HOOK_FWD | HOOK_POST, NULL},
    {"limit", false, 0, 0, 0, sizeof(xt_rateinfo_t), ALL_HOOKS, NULL},
    {"length", false, 0, 4, 0, sizeof(xt_length_info_t), ALL_HOOKS, NULL},
    {"length", false, 0, 6, 0, sizeof(xt_length_info_t), ALL_HOOKS, NULL},
    {"connbytes", false, 0, 0, 0, sizeof(xt_connbytes_info_t), ALL_HOOKS, NULL},
    {"string", false, 1, 0, 0, sizeof(xt_string_info_t), ALL_HOOKS, NULL},
    {"addrtype", false, 0, 4, 0, 12u, ALL_HOOKS, NULL},
    {"addrtype", false, 1, 0, 0, sizeof(xt_addrtype_info_v1_t), ALL_HOOKS, NULL},
    {"set", false, 1, 0, 0, sizeof(xt_set_info_t), ALL_HOOKS, NULL},
    {"set", false, 4, 0, 0, 48u, ALL_HOOKS, NULL},
};

static const kext_t *kext_find(bool v6, bool target, const char *name, uint8_t rev, int *miss) {
    *miss = ENOENT;
    for (size_t i = 0; i < sizeof(k_exts) / sizeof(k_exts[0]); i++) {
        const kext_t *k = &k_exts[i];
        if (k->target != target || (k->fam != 0 && k->fam != (v6 ? 6 : 4)) || strncmp(name, k->name, XT_NAME_LEN) != 0) {
            continue;
        }
        if (k->rev == rev) { return k; }
        if (*miss == ENOENT) { *miss = k->fam == 0 ? EPROTOTYPE : EPROTONOSUPPORT; }
    }
    return NULL;
}

typedef struct kentry {
    bool v6, inv_proto, f_proto;
    uint16_t proto;
    uint32_t mask;
    const char *table;
    const firc_fake_xt_t *f;
} kentry_t;

static bool lacked(const firc_fake_xt_t *f, const char *name, uint8_t rev) {
    for (size_t i = 0; i < f->n_lacks; i++) {
        const fake_lack_t *l = &f->lacks[i];
        if (!l->any && !l->target && l->rev == rev && strncmp(l->name, name, XT_NAME_LEN) == 0) { return true; }
    }
    return false;
}

static bool set_known(const firc_fake_xt_t *f, uint16_t index) {
    for (size_t i = 0; i < f->n_sets; i++) {
        if (f->sets[i].index == index) { return true; }
    }
    return false;
}

static bool ip_proto_is(const kentry_t *e, uint16_t proto) { return e->proto == proto && !e->inv_proto; }

static int ext_check(const kentry_t *e, const uint8_t *x, bool target) {
    int miss = 0;
    const kext_t *k = kext_find(e->v6, target, (const char *)x + 2, x[31], &miss);
    if (k == NULL) { return miss == EPROTONOSUPPORT ? ENOENT : miss; }
    if (!target && strcmp(k->name, "set") == 0 && (lacked(e->f, k->name, k->rev) || !set_known(e->f, g16(x + 32)))) {
        return ENOENT;
    }
    if ((uint32_t)g16(x) - 32u != XT_ALIGN8(k->size) || (k->table != NULL && strcmp(k->table, e->table) != 0) ||
        (e->mask & ~k->hooks) != 0 || (k->proto != 0 && !ip_proto_is(e, k->proto))) {
        return EINVAL;
    }
    if (!target && strcmp(k->name, "multiport") == 0) {
        static const uint16_t ok[] = {6, 17, 33, 132, 136};
        bool any = false;
        for (size_t i = 0; i < 5; i++) { any = any || ip_proto_is(e, ok[i]); }
        return any ? 0 : EINVAL;
    }
    if (target && strcmp(k->name, "REJECT") == 0) {
        uint32_t with = g32(x + 32);
        if (with == (e->v6 ? 5u : 4u)) { return EINVAL; }
        if (with == (e->v6 ? XT_REJECT_V6_TCP_RESET : XT_REJECT_V4_TCP_RESET) &&
            (!ip_proto_is(e, 6) || (e->v6 && !e->f_proto))) {
            return EINVAL;
        }
    }
    return 0;
}

static int kernel_check(const firc_fake_xt_t *f, bool v6, const char *table, const firc_xt_info_t *in, const uint8_t *b) {
    if (!kernel_accepts(v6, in, b)) { return EINVAL; }
    uint32_t at_flags = v6 ? 131u : 82u;
    uint8_t flag_mask = v6 ? 0x07u : 0x03u;
    uint32_t n = in->num_entries;
    uint32_t *offs = malloc(n * sizeof(*offs));
    uint32_t *mask = calloc(n, sizeof(*mask));
    uint8_t *onpath = calloc(n, 1);
    if (offs == NULL || mask == NULL || onpath == NULL) {
        free(onpath);
        free(mask);
        free(offs);
        return ENOMEM;
    }
    kview_t v = {b, offs, n, v6 ? 168u : 112u, v6 ? 140u : 88u, v6 ? 136u : 84u, mask, onpath};
    int err = 0;
    for (uint32_t i = 0, off = 0; err == 0 && i < n; off += g16(b + off + v.at_t + 2), i++) {
        offs[i] = off;
        if ((b[off + at_flags] & ~flag_mask) != 0 || (b[off + at_flags + 1] & ~0x7fu) != 0) { err = EINVAL; }
    }
    for (unsigned h = 0; err == 0 && h < 5; h++) {
        if (in->valid_hooks & (1u << h)) { err = walk(&v, (uint32_t)index_of(&v, in->hook_entry[h]), h); }
    }
    for (uint32_t i = 0; err == 0 && i < n; i++) {
        const uint8_t *e = b + offs[i];
        kentry_t ke = {v6, (e[at_flags + 1] & 0x40u) != 0, (e[at_flags] & XT_IP6T_F_PROTO) != 0, g16(e + (v6 ? 128u : 80u)),
                       mask[i], table, f};
        for (uint32_t m = v.eh; err == 0 && m < g16(e + v.at_t); m += g16(e + m)) { err = ext_check(&ke, e + m, false); }
        if (err == 0) { err = ext_check(&ke, target_at(&v, i), true); }
    }
    free(onpath);
    free(mask);
    free(offs);
    return err;
}

static void dirty(bool v6, uint8_t *b, uint32_t size, const firc_xt_counter_t *counters) {
    uint32_t eh = v6 ? 168u : 112u, at_t = v6 ? 140u : 88u, at_from = v6 ? 144u : 92u, at_cnt = v6 ? 152u : 96u;
    uint32_t i = 0;
    for (uint32_t off = 0; off < size; off += g16(b + off + at_t + 2), i++) {
        uint8_t *e = b + off;
        uint32_t from = 0x1fu;
        memcpy(e + at_from, &from, 4);
        memcpy(e + at_cnt, &counters[i], sizeof(counters[i]));
        uint16_t toff = g16(e + at_t);
        for (uint32_t m = eh;; m += g16(e + m)) {
            size_t len = strnlen((const char *)e + m + 2, 29);
            if (len + 1 < 29) { memset(e + m + 2 + len + 1, 0xa5, 29 - len - 1); }
            if (m == toff) { break; }
        }
    }
}

static bool append_line(char **buf, size_t *len, const char *table) {
    size_t n = strlen(table);
    char *grown = realloc(*buf, *len + n + 2);
    if (grown == NULL) { return false; }
    memcpy(grown + *len, table, n);
    grown[*len + n] = '\n';
    grown[*len + n + 1] = '\0';
    *buf = grown;
    *len += n + 1;
    return true;
}

static int op_get_info(void *ud, firc_ipt_proto_t fam, const char *table, firc_xt_info_t *out) {
    firc_fake_xt_t *f = ud;
    (void)fam;
    pthread_mutex_lock(&f->mu);
    fake_table_t *t = find(f, table);
    int err = 0;
    if (t == NULL) {
        err = ENOENT;
    } else {
        *out = t->info;
        if (f->race == FIRC_FAKE_XT_RACE_SIZE_AT_SECOND_INFO && ++f->infos_since_race == 2) {
            out->size += 8;
            f->race = FIRC_FAKE_XT_RACE_NONE;
        }
    }
    pthread_mutex_unlock(&f->mu);
    return err;
}

static int op_get_entries(void *ud, firc_ipt_proto_t fam, const char *table, uint8_t *blob, uint32_t size) {
    firc_fake_xt_t *f = ud;
    pthread_mutex_lock(&f->mu);
    void (*hook)(void *, const char *) = f->on_read;
    void *hook_ud = f->read_ud;
    pthread_mutex_unlock(&f->mu);
    if (hook != NULL) { hook(hook_ud, table); }
    pthread_mutex_lock(&f->mu);
    f->reads++;
    bool logged = append_line(&f->rorder, &f->rorder_len, table);
    f->reads_under_lock += f->firc_holds ? 1u : 0u;
    fake_table_t *t = find(f, table);
    int err = 0;
    if (!logged) {
        err = ENOMEM;
    } else if (t == NULL) {
        err = ENOENT;
    } else if (size != t->info.size) {
        err = EAGAIN;
    } else {
        memcpy(blob, t->blob, size);
        dirty(fam == FIRC_IPT_PROTO_IPV6, blob, size, t->counters);
    }
    pthread_mutex_unlock(&f->mu);
    return err;
}

static int armed_failure(firc_fake_xt_t *f, const char *table) {
    for (size_t i = 0; i < 4; i++) {
        if (f->fail_tables[i].err != 0 && strcmp(table, f->fail_tables[i].name) == 0) {
            int err = f->fail_tables[i].err;
            f->fail_tables[i].err = 0;
            return err;
        }
    }
    int err = f->fail_replace;
    f->fail_replace = 0;
    return err;
}

static int op_replace(void *ud, firc_ipt_proto_t fam, const char *table, const firc_xt_info_t *info,
                      uint8_t *blob, uint32_t num_counters, firc_xt_counter_t *old) {
    firc_fake_xt_t *f = ud;
    pthread_mutex_lock(&f->mu);
    int (*before)(void *, firc_ipt_proto_t, const char *, const firc_xt_info_t *, const uint8_t *) = f->before;
    void (*after)(void *, const char *) = f->after;
    void *hook_ud = f->hook_ud;
    pthread_mutex_unlock(&f->mu);
    if (before != NULL) {
        int e = before(hook_ud, fam, table, info, blob);
        if (e != 0) { return e; }
    }
    bool v6 = fam == FIRC_IPT_PROTO_IPV6;
    pthread_mutex_lock(&f->mu);
    f->writes_outside_lock += f->firc_holds ? 0u : 1u;
    fake_table_t *t = find(f, table);
    int err = armed_failure(f, table);
    if (err != 0 || t == NULL) {
        err = err != 0 ? err : ENOENT;
    } else if (f->race == FIRC_FAKE_XT_RACE_MORE_ENTRIES) {
        f->race = FIRC_FAKE_XT_RACE_NONE;
        err = EAGAIN;
    } else {
        if (f->race == FIRC_FAKE_XT_RACE_SAME_COUNT) {
            f->race = FIRC_FAKE_XT_RACE_NONE;
            t->blob[v6 ? 31 : 7] ^= 0x01u;
        }
        int ke = kernel_check(f, v6, table, info, blob);
        uint8_t *nb = malloc(info->size ? info->size : 1);
        firc_xt_counter_t *nc = calloc(info->num_entries ? info->num_entries : 1, sizeof(*nc));
        if (nb == NULL || nc == NULL) {
            err = ENOMEM;
        } else if (ke != 0) {
            err = ke;
        } else if (info->valid_hooks != t->info.valid_hooks) {
            err = EINVAL;
        } else if (num_counters != t->info.num_entries) {
            err = EAGAIN;
        } else if (!append_line(&f->order, &f->order_len, table)) {
            err = ENOMEM;
        } else {
            memcpy(old, t->counters, num_counters * sizeof(*old));
            memcpy(nb, blob, info->size);
            free(t->blob);
            free(t->counters);
            t->blob = nb;
            t->counters = nc;
            t->info = *info;
            nb = NULL;
            nc = NULL;
            f->replaces++;
        }
        free(nb);
        free(nc);
    }
    pthread_mutex_unlock(&f->mu);
    if (err == 0 && after != NULL) { after(hook_ud, table); }
    return err;
}

static int op_add_counters(void *ud, firc_ipt_proto_t fam, const char *table, const firc_xt_counter_t *c, uint32_t n) {
    firc_fake_xt_t *f = ud;
    (void)fam;
    pthread_mutex_lock(&f->mu);
    fake_table_t *t = find(f, table);
    int err = 0;
    if (f->fail_counters != 0) {
        err = f->fail_counters;
        f->fail_counters = 0;
    } else if (t == NULL || n != t->info.num_entries) {
        err = EINVAL;
    } else {
        for (uint32_t i = 0; i < n; i++) {
            t->counters[i].pcnt += c[i].pcnt;
            t->counters[i].bcnt += c[i].bcnt;
        }
    }
    pthread_mutex_unlock(&f->mu);
    return err;
}

static int op_get_revision(void *ud, firc_ipt_proto_t fam, bool target, const char *name, uint8_t revision) {
    firc_fake_xt_t *f = ud;
    pthread_mutex_lock(&f->mu);
    f->revision_asks++;
    int err = f->fail_revisions;
    int miss = 0;
    if (err == 0 && kext_find(fam == FIRC_IPT_PROTO_IPV6, target, name, revision, &miss) == NULL) {
        err = miss == ENOENT ? ENOENT : EPROTONOSUPPORT;
    }
    for (size_t i = 0; i < f->n_lacks; i++) {
        const fake_lack_t *l = &f->lacks[i];
        if (strcmp(l->name, name) == 0 && (l->any || (l->target == target && l->rev == revision))) { err = l->err; }
    }
    pthread_mutex_unlock(&f->mu);
    return err;
}

static int op_lock(void *ud, unsigned wait_ms) {
    firc_fake_xt_t *f = ud;
    (void)wait_ms;
    pthread_mutex_lock(&f->mu);
    int err = f->lock_held ? EAGAIN : 0;
    f->firc_holds = err == 0;
    pthread_mutex_unlock(&f->mu);
    return err;
}

static void op_unlock(void *ud) {
    firc_fake_xt_t *f = ud;
    pthread_mutex_lock(&f->mu);
    void (*hook)(void *) = f->on_unlock;
    void *hook_ud = f->unlock_ud;
    pthread_mutex_unlock(&f->mu);
    if (hook != NULL) { hook(hook_ud); }
    pthread_mutex_lock(&f->mu);
    f->firc_holds = false;
    pthread_mutex_unlock(&f->mu);
}
static void op_destroy(void *ud) { (void)ud; }

static int op_set_index(void *ud, const char *name, uint16_t *index) {
    firc_fake_xt_t *f = ud;
    pthread_mutex_lock(&f->mu);
    f->set_asks++;
    int err = f->fail_sets != 0 ? f->fail_sets : ENOENT;
    for (size_t i = 0; i < f->n_sets && f->fail_sets == 0; i++) {
        if (strcmp(f->sets[i].name, name) == 0) {
            *index = f->sets[i].index;
            err = 0;
        }
    }
    pthread_mutex_unlock(&f->mu);
    return err;
}

static const firc_xt_kernel_ops_t k_ops = {op_get_info, op_get_entries, op_replace, op_add_counters,
                                           op_get_revision, op_lock, op_unlock, op_destroy, op_set_index};

bool firc_fake_xt_load(firc_fake_xt_t *f, const char *table, const firc_xt_info_t *info, const uint8_t *blob) {
    pthread_mutex_lock(&f->mu);
    fake_table_t *t = find(f, table);
    if (t == NULL && f->n_tables < 4) {
        t = &f->tables[f->n_tables++];
        memset(t, 0, sizeof(*t));
        strncpy(t->name, table, sizeof(t->name) - 1);
    }
    bool ok = t != NULL;
    if (ok) {
        uint8_t *nb = malloc(info->size ? info->size : 1);
        firc_xt_counter_t *nc = calloc(info->num_entries ? info->num_entries : 1, sizeof(*nc));
        ok = nb != NULL && nc != NULL;
        if (ok) {
            memcpy(nb, blob, info->size);
            free(t->blob);
            free(t->counters);
            t->blob = nb;
            t->counters = nc;
            t->info = *info;
        } else {
            free(nb);
            free(nc);
        }
    }
    pthread_mutex_unlock(&f->mu);
    return ok;
}

static void load_empty(firc_fake_xt_t *f) {
    static const struct { const char *golden, *table; } k[] = {{"empty", "nat"}, {"f-empty", "filter"}, {"m-empty", "mangle"}};
    for (size_t i = 0; i < 3; i++) {
        firc_xt_info_t info;
        uint8_t *blob = NULL;
        if (!firc_test_xt_read(k[i].golden, f->fam, &info, &blob) || !firc_fake_xt_load(f, k[i].table, &info, blob)) { abort(); }
        free(blob);
    }
}

firc_fake_xt_t *firc_fake_xt_new(firc_ipt_proto_t fam) {
    firc_fake_xt_t *f = calloc(1, sizeof(*f));
    if (f == NULL) { return NULL; }
    pthread_mutex_init(&f->mu, NULL);
    f->fam = fam;
    load_empty(f);
    return f;
}

void firc_fake_xt_free(firc_fake_xt_t *f) {
    if (f == NULL) { return; }
    for (size_t i = 0; i < f->n_tables; i++) {
        free(f->tables[i].blob);
        free(f->tables[i].counters);
    }
    free(f->order);
    free(f->rorder);
    pthread_mutex_destroy(&f->mu);
    free(f);
}

void firc_fake_xt_reset(firc_fake_xt_t *f) {
    pthread_mutex_lock(&f->mu);
    for (size_t i = 0; i < f->n_tables; i++) {
        free(f->tables[i].blob);
        free(f->tables[i].counters);
    }
    f->n_tables = 0;
    f->fail_replace = 0;
    f->fail_counters = 0;
    f->fail_revisions = 0;
    f->race = FIRC_FAKE_XT_RACE_NONE;
    f->infos_since_race = 0;
    f->n_lacks = 0;
    f->n_sets = 0;
    f->set_asks = 0;
    f->fail_sets = 0;
    f->lock_held = false;
    memset(f->fail_tables, 0, sizeof(f->fail_tables));
    free(f->order);
    free(f->rorder);
    f->order = NULL;
    f->rorder = NULL;
    f->order_len = 0;
    f->rorder_len = 0;
    pthread_mutex_unlock(&f->mu);
    load_empty(f);
}

firc_xt_t *firc_fake_xt_handle(firc_fake_xt_t *f) { return firc_xt_new(f->fam, &k_ops, f); }

const firc_xt_kernel_ops_t *firc_fake_xt_ops(void) { return &k_ops; }

void firc_fake_xt_drop_table(firc_fake_xt_t *f, const char *table) {
    pthread_mutex_lock(&f->mu);
    fake_table_t *t = find(f, table);
    if (t != NULL) {
        free(t->blob);
        free(t->counters);
        *t = f->tables[--f->n_tables];
    }
    pthread_mutex_unlock(&f->mu);
}

bool firc_fake_xt_blob(firc_fake_xt_t *f, const char *table, firc_xt_info_t *info, uint8_t **blob) {
    pthread_mutex_lock(&f->mu);
    fake_table_t *t = find(f, table);
    bool ok = t != NULL;
    if (ok) {
        *info = t->info;
        *blob = malloc(t->info.size ? t->info.size : 1);
        ok = *blob != NULL;
        if (ok) { memcpy(*blob, t->blob, t->info.size); }
    }
    pthread_mutex_unlock(&f->mu);
    return ok;
}

#define FAKE_SET(field, value) do { pthread_mutex_lock(&f->mu); f->field = (value); pthread_mutex_unlock(&f->mu); } while (0)

void firc_fake_xt_fail_next_replace(firc_fake_xt_t *f, int err) { FAKE_SET(fail_replace, err); }
void firc_fake_xt_fail_next_counters(firc_fake_xt_t *f, int err) { FAKE_SET(fail_counters, err); }
void firc_fake_xt_hold_lock(firc_fake_xt_t *f, bool held) { FAKE_SET(lock_held, held); }
void firc_fake_xt_fail_revisions(firc_fake_xt_t *f, int err) { FAKE_SET(fail_revisions, err); }
void firc_fake_xt_fail_sets(firc_fake_xt_t *f, int err) { FAKE_SET(fail_sets, err); }

void firc_fake_xt_race_next(firc_fake_xt_t *f, firc_fake_xt_race_t how) {
    pthread_mutex_lock(&f->mu);
    f->race = how;
    f->infos_since_race = 0;
    pthread_mutex_unlock(&f->mu);
}

static void add_lack(firc_fake_xt_t *f, bool target, const char *name, uint8_t revision, bool any, int err) {
    pthread_mutex_lock(&f->mu);
    if (f->n_lacks < 8) {
        fake_lack_t *l = &f->lacks[f->n_lacks++];
        memset(l, 0, sizeof(*l));
        l->target = target;
        strncpy(l->name, name, sizeof(l->name) - 1);
        l->rev = revision;
        l->any = any;
        l->err = err;
    }
    pthread_mutex_unlock(&f->mu);
}

void firc_fake_xt_lack(firc_fake_xt_t *f, bool target, const char *name, uint8_t revision) {
    add_lack(f, target, name, revision, false, ENOENT);
}

void firc_fake_xt_fail_revision(firc_fake_xt_t *f, const char *name, int err) { add_lack(f, false, name, 0, true, err); }

void firc_fake_xt_set_counters(firc_fake_xt_t *f, const char *table, uint64_t base) {
    pthread_mutex_lock(&f->mu);
    fake_table_t *t = find(f, table);
    for (uint32_t i = 0; t != NULL && i < t->info.num_entries; i++) {
        t->counters[i].pcnt = base + i;
        t->counters[i].bcnt = 2 * (base + i);
    }
    pthread_mutex_unlock(&f->mu);
}

bool firc_fake_xt_counter(firc_fake_xt_t *f, const char *table, uint32_t index, firc_xt_counter_t *out) {
    pthread_mutex_lock(&f->mu);
    fake_table_t *t = find(f, table);
    bool ok = t != NULL && index < t->info.num_entries;
    if (ok) { *out = t->counters[index]; }
    pthread_mutex_unlock(&f->mu);
    return ok;
}

void firc_fake_xt_on_read(firc_fake_xt_t *f, void (*fn)(void *ud, const char *table), void *ud) {
    pthread_mutex_lock(&f->mu);
    f->on_read = fn;
    f->read_ud = ud;
    pthread_mutex_unlock(&f->mu);
}

void firc_fake_xt_on_unlock(firc_fake_xt_t *f, void (*fn)(void *ud), void *ud) {
    pthread_mutex_lock(&f->mu);
    f->on_unlock = fn;
    f->unlock_ud = ud;
    pthread_mutex_unlock(&f->mu);
}

void firc_fake_xt_set_write_hooks(firc_fake_xt_t *f,
                                  int (*before)(void *ud, firc_ipt_proto_t fam, const char *table,
                                                const firc_xt_info_t *info, const uint8_t *blob),
                                  void (*after)(void *ud, const char *table), void *ud) {
    pthread_mutex_lock(&f->mu);
    f->before = before;
    f->after = after;
    f->hook_ud = ud;
    pthread_mutex_unlock(&f->mu);
}

size_t firc_fake_xt_replaces(firc_fake_xt_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->replaces;
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t firc_fake_xt_reads(firc_fake_xt_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->reads;
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t firc_fake_xt_revision_asks(firc_fake_xt_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->revision_asks;
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t firc_fake_xt_reads_under_lock(firc_fake_xt_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->reads_under_lock;
    pthread_mutex_unlock(&f->mu);
    return n;
}

size_t firc_fake_xt_writes_outside_lock(firc_fake_xt_t *f) {
    pthread_mutex_lock(&f->mu);
    size_t n = f->writes_outside_lock;
    pthread_mutex_unlock(&f->mu);
    return n;
}

void firc_fake_xt_fail_table(firc_fake_xt_t *f, const char *table, int err) {
    pthread_mutex_lock(&f->mu);
    size_t slot = 0;
    while (slot < 3 && f->fail_tables[slot].err != 0 && strcmp(f->fail_tables[slot].name, table) != 0) { slot++; }
    memset(f->fail_tables[slot].name, 0, sizeof(f->fail_tables[slot].name));
    strncpy(f->fail_tables[slot].name, table, sizeof(f->fail_tables[slot].name) - 1);
    f->fail_tables[slot].err = err;
    pthread_mutex_unlock(&f->mu);
}

static char *copy_order(firc_fake_xt_t *f, const char *const *buf) {
    pthread_mutex_lock(&f->mu);
    char *out = strdup(*buf != NULL ? *buf : "");
    pthread_mutex_unlock(&f->mu);
    return out;
}

char *firc_fake_xt_write_order(firc_fake_xt_t *f) { return copy_order(f, (const char *const *)&f->order); }
char *firc_fake_xt_read_order(firc_fake_xt_t *f) { return copy_order(f, (const char *const *)&f->rorder); }

void firc_fake_xt_set(firc_fake_xt_t *k, const char *name, uint16_t index) {
    pthread_mutex_lock(&k->mu);
    size_t i = 0;
    while (i < k->n_sets && strcmp(k->sets[i].name, name) != 0) { i++; }
    if (i < 16) {
        if (i == k->n_sets) { k->n_sets++; }
        memset(k->sets[i].name, 0, sizeof(k->sets[i].name));
        strncpy(k->sets[i].name, name, sizeof(k->sets[i].name) - 1);
        k->sets[i].index = index;
    }
    pthread_mutex_unlock(&k->mu);
}

void firc_fake_xt_set_drop(firc_fake_xt_t *k, const char *name) {
    pthread_mutex_lock(&k->mu);
    for (size_t i = 0; i < k->n_sets; i++) {
        if (strcmp(k->sets[i].name, name) == 0) {
            k->sets[i] = k->sets[--k->n_sets];
            break;
        }
    }
    pthread_mutex_unlock(&k->mu);
}

size_t firc_fake_xt_set_asks(firc_fake_xt_t *k) {
    pthread_mutex_lock(&k->mu);
    size_t n = k->set_asks;
    pthread_mutex_unlock(&k->mu);
    return n;
}

bool firc_fake_xt_namer(void *k, uint16_t index, char *out) {
    firc_fake_xt_t *f = k;
    pthread_mutex_lock(&f->mu);
    bool found = false;
    for (size_t i = 0; i < f->n_sets && !found; i++) {
        if (f->sets[i].index == index) {
            memcpy(out, f->sets[i].name, sizeof(f->sets[i].name));
            found = true;
        }
    }
    pthread_mutex_unlock(&f->mu);
    return found;
}
