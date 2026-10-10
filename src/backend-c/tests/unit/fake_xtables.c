#include "fake_xtables.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
} fake_lack_t;

struct firc_fake_xt {
    pthread_mutex_t mu;
    firc_ipt_proto_t fam;
    fake_table_t tables[4];
    size_t n_tables;
    int fail_replace, fail_counters, fail_revisions;
    firc_fake_xt_race_t race;
    unsigned infos_since_race;
    fake_lack_t lacks[8];
    size_t n_lacks;
    bool lock_held, firc_holds;
    size_t replaces, reads, revision_asks, reads_under_lock, writes_outside_lock;
    void (*on_read)(void *ud);
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
    void (*hook)(void *) = f->on_read;
    void *hook_ud = f->read_ud;
    pthread_mutex_unlock(&f->mu);
    if (hook != NULL) { hook(hook_ud); }
    pthread_mutex_lock(&f->mu);
    f->reads++;
    f->reads_under_lock += f->firc_holds ? 1u : 0u;
    fake_table_t *t = find(f, table);
    int err = 0;
    if (t == NULL) {
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

static int op_replace(void *ud, firc_ipt_proto_t fam, const char *table, const firc_xt_info_t *info,
                      const uint8_t *blob, uint32_t num_counters, firc_xt_counter_t *old) {
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
    int err = 0;
    if (f->fail_replace != 0) {
        err = f->fail_replace;
        f->fail_replace = 0;
    } else if (t == NULL) {
        err = ENOENT;
    } else if (f->race == FIRC_FAKE_XT_RACE_MORE_ENTRIES) {
        f->race = FIRC_FAKE_XT_RACE_NONE;
        err = EAGAIN;
    } else {
        if (f->race == FIRC_FAKE_XT_RACE_SAME_COUNT) {
            f->race = FIRC_FAKE_XT_RACE_NONE;
            t->blob[v6 ? 31 : 7] ^= 0x01u;
        }
        uint8_t *nb = malloc(info->size ? info->size : 1);
        firc_xt_counter_t *nc = calloc(info->num_entries ? info->num_entries : 1, sizeof(*nc));
        if (nb == NULL || nc == NULL) {
            err = ENOMEM;
        } else if (!kernel_accepts(v6, info, blob) || info->valid_hooks != t->info.valid_hooks) {
            err = EINVAL;
        } else if (num_counters != t->info.num_entries) {
            err = EAGAIN;
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
    (void)fam;
    pthread_mutex_lock(&f->mu);
    f->revision_asks++;
    int err = f->fail_revisions;
    for (size_t i = 0; i < f->n_lacks; i++) {
        if (f->lacks[i].target == target && strcmp(f->lacks[i].name, name) == 0 && f->lacks[i].rev == revision) { err = ENOENT; }
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

static const firc_xt_kernel_ops_t k_ops = {op_get_info, op_get_entries, op_replace, op_add_counters,
                                           op_get_revision, op_lock, op_unlock, op_destroy};

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

firc_fake_xt_t *firc_fake_xt_new(firc_ipt_proto_t fam) {
    firc_fake_xt_t *f = calloc(1, sizeof(*f));
    if (f == NULL) { return NULL; }
    pthread_mutex_init(&f->mu, NULL);
    f->fam = fam;
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    if (!firc_test_xt_read("empty", fam, &info, &blob) || !firc_fake_xt_load(f, "nat", &info, blob)) { abort(); }
    free(blob);
    return f;
}

void firc_fake_xt_free(firc_fake_xt_t *f) {
    if (f == NULL) { return; }
    for (size_t i = 0; i < f->n_tables; i++) {
        free(f->tables[i].blob);
        free(f->tables[i].counters);
    }
    pthread_mutex_destroy(&f->mu);
    free(f);
}

void firc_fake_xt_reset(firc_fake_xt_t *f) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    if (!firc_test_xt_read("empty", f->fam, &info, &blob)) { abort(); }
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
    f->lock_held = false;
    pthread_mutex_unlock(&f->mu);
    if (!firc_fake_xt_load(f, "nat", &info, blob)) { abort(); }
    free(blob);
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

void firc_fake_xt_race_next(firc_fake_xt_t *f, firc_fake_xt_race_t how) {
    pthread_mutex_lock(&f->mu);
    f->race = how;
    f->infos_since_race = 0;
    pthread_mutex_unlock(&f->mu);
}

void firc_fake_xt_lack(firc_fake_xt_t *f, bool target, const char *name, uint8_t revision) {
    pthread_mutex_lock(&f->mu);
    if (f->n_lacks < 8) {
        fake_lack_t *l = &f->lacks[f->n_lacks++];
        l->target = target;
        strncpy(l->name, name, sizeof(l->name) - 1);
        l->rev = revision;
    }
    pthread_mutex_unlock(&f->mu);
}

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

void firc_fake_xt_on_read(firc_fake_xt_t *f, void (*fn)(void *ud), void *ud) {
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
