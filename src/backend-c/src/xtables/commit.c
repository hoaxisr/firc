#include "xt_internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "firc/atomic_write.h"
#include "firc/log.h"

struct firc_xt {
    firc_ipt_proto_t fam;
    const firc_xt_kernel_ops_t *ops;
    void *ud;
    uint32_t missing;
    bool failing;
    char *dump_dir;
};

firc_xt_t *firc_xt_new(firc_ipt_proto_t fam, const firc_xt_kernel_ops_t *ops, void *ud) {
    if (ops == NULL) { return NULL; }
    firc_xt_t *xt = calloc(1, sizeof(*xt));
    if (xt == NULL) { return NULL; }
    xt->fam = fam;
    xt->ops = ops;
    xt->ud = ud;
    return xt;
}

void firc_xt_free(firc_xt_t *xt) {
    if (xt == NULL) { return; }
    if (xt->ops->destroy != NULL) { xt->ops->destroy(xt->ud); }
    free(xt->dump_dir);
    free(xt);
}

firc_ipt_proto_t firc_xt_proto(const firc_xt_t *xt) { return xt->fam; }

firc_err_t firc_xt_set_dump_dir(firc_xt_t *xt, const char *dir) {
    free(xt->dump_dir);
    xt->dump_dir = NULL;
    if (dir == NULL) { return FIRC_OK; }
    xt->dump_dir = strdup(dir);
    return xt->dump_dir != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}

static const char *fam_name(const firc_xt_t *xt) { return xt->fam == FIRC_IPT_PROTO_IPV6 ? "ipv6" : "ipv4"; }

static const char *errname(int e, char *buf, size_t cap) {
    switch (e) {
    case EAGAIN: return "EAGAIN";
    case EINVAL: return "EINVAL";
    case ENOENT: return "ENOENT";
    case ENOMEM: return "ENOMEM";
    case ELOOP: return "ELOOP";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
    case ENOPROTOOPT: return "ENOPROTOOPT";
    case EFAULT: return "EFAULT";
    case EBUSY: return "EBUSY";
    default:
        snprintf(buf, cap, "errno %d", e);
        return buf;
    }
}

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static firc_err_t failed(firc_xt_t *xt, firc_err_t err, const char *fmt, ...) FIRC_PRINTF(3, 4);

static firc_err_t failed(firc_xt_t *xt, firc_err_t err, const char *fmt, ...) {
    char msg[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (!xt->failing) {
        FIRC_WARN("%s", msg);
        xt->failing = true;
    } else {
        FIRC_DEBUG("%s", msg);
    }
    return err;
}

firc_err_t firc_xt_probe(firc_xt_t *xt) {
    firc_err_t first = FIRC_OK;
    xt->missing = 0;
    for (size_t i = 0; i < firc_xt_n_exts; i++) {
        const firc_xt_ext_desc_t *x = &firc_xt_exts[i];
        uint8_t rev = xt->fam == FIRC_IPT_PROTO_IPV6 ? x->rev6 : x->rev4;
        int e = xt->ops->get_revision(xt->ud, xt->fam, x->target, x->name, rev);
        if (e == 0) { continue; }
        char b[24];
        if (e != ENOENT && e != EPROTONOSUPPORT) {
            FIRC_ERROR("x_tables: cannot probe %s %s %s revision %u (%s)", fam_name(xt), x->target ? "target" : "match",
                       x->name, rev, errname(e, b, sizeof(b)));
            return FIRC_ERR_IO;
        }
        xt->missing |= x->bit;
        FIRC_ERROR("x_tables: no %s %s %s revision %u (%s): %s rules cannot be written", fam_name(xt),
                   x->target ? "target" : "match", x->name, rev, errname(e, b, sizeof(b)), x->name);
        first = FIRC_ERR_NOSYS;
    }
    return first;
}

static void dump_refused(const firc_xt_t *xt, const char *table, const firc_xt_info_t *info, const uint8_t *blob) {
    if (xt->dump_dir == NULL || firc_log_level() > FIRC_LOG_DEBUG) { return; }
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/refused-%s-%s.bin", xt->dump_dir, fam_name(xt), table);
    if (n < 0 || (size_t)n >= sizeof(path)) { return; }
    size_t len = XT_REPLACE_HDR_LEN + (size_t)info->size;
    char *buf = calloc(1, len);
    if (buf == NULL) { return; }
    xt_replace_hdr_t h;
    memset(&h, 0, sizeof(h));
    memcpy(h.name, table, strnlen(table, XT_TABLE_LEN - 1));
    h.valid_hooks = info->valid_hooks;
    h.num_entries = info->num_entries;
    h.size = info->size;
    memcpy(h.hook_entry, info->hook_entry, sizeof(h.hook_entry));
    memcpy(h.underflow, info->underflow, sizeof(h.underflow));
    memcpy(buf, &h, sizeof(h));
    memcpy(buf + XT_REPLACE_HDR_LEN, blob, info->size);
    if (firc_atomic_write(path, buf, len) != FIRC_OK) { FIRC_DEBUG("x_tables: %s not written", path); }
    free(buf);
}

static bool same_shape(const firc_xt_info_t *a, const firc_xt_info_t *b) {
    if (a->size != b->size || a->num_entries != b->num_entries || a->valid_hooks != b->valid_hooks) { return false; }
    for (int h = 0; h < FIRC_XT_NUMHOOKS; h++) {
        if (!(a->valid_hooks & (1u << h))) { continue; }
        if (a->hook_entry[h] != b->hook_entry[h] || a->underflow[h] != b->underflow[h]) { return false; }
    }
    return true;
}

static const firc_xt_ext_desc_t *first_missing(uint32_t bits) {
    for (size_t i = 0; i < firc_xt_n_exts; i++) {
        if (bits & firc_xt_exts[i].bit) { return &firc_xt_exts[i]; }
    }
    return NULL;
}

typedef struct work {
    uint8_t *read;
    uint8_t *written;
    int32_t *old_index;
    firc_xt_counter_t *old;
    firc_xt_counter_t *carried;
    firc_xt_table_t view;
} work_t;

static void work_free(work_t *w) {
    free(w->read);
    free(w->written);
    free(w->old_index);
    free(w->old);
    free(w->carried);
    firc_xt_table_clear(&w->view);
}

static firc_err_t write_locked(firc_xt_t *xt, const char *table, const firc_xt_info_t *read_info,
                               const firc_xt_info_t *new_info, work_t *w, uint64_t t0, uint64_t t1, uint64_t t2,
                               int *refused);

static firc_err_t stage_failed(firc_xt_t *xt, firc_err_t err, const char *what, const char *table) {
    return failed(xt, err, "x_tables %s %s: %s (%s)", fam_name(xt), table, what, firc_err_str(err));
}

static firc_err_t commit_table(firc_xt_t *xt, const char *table, const firc_xt_stage_t *stage,
                               firc_cancel_t *cancel, work_t *w) {
    char eb[24];
    const char *fam = fam_name(xt);
    uint64_t t0 = now_us();
    firc_xt_info_t info;
    int e = xt->ops->get_info(xt->ud, xt->fam, table, &info);
    if (e != 0) { return failed(xt, FIRC_ERR_IO, "x_tables cannot read %s %s (%s)", fam, table, errname(e, eb, sizeof(eb))); }
    w->read = malloc(info.size ? info.size : 1);
    if (w->read == NULL) { return stage_failed(xt, FIRC_ERR_NOMEM, "no memory for the read", table); }
    e = xt->ops->get_entries(xt->ud, xt->fam, table, w->read, info.size);
    if (e == EAGAIN) {
        FIRC_DEBUG("x_tables %s %s changed while it was read, starting over", fam, table);
        return FIRC_ERR_AGAIN;
    }
    if (e != 0) { return failed(xt, FIRC_ERR_IO, "x_tables cannot read %s %s (%s)", fam, table, errname(e, eb, sizeof(eb))); }
    uint64_t t1 = now_us();
    const char *bad = NULL;
    firc_err_t err = firc_xt_parse(xt->fam, &info, w->read, &w->view, &bad);
    if (err == FIRC_ERR_PROTO) {
        return failed(xt, err, "x_tables %s %s: the table read back is malformed: %s", fam, table, bad);
    }
    if (err != FIRC_OK) { return stage_failed(xt, err, "the table read back cannot be parsed", table); }
    uint32_t exts = 0;
    char why[512];
    err = firc_xt_merge(&w->view, stage, &exts, why, sizeof(why));
    if (err == FIRC_ERR_INVAL) { return failed(xt, err, "x_tables %s %s: %s", fam, table, why); }
    if (err != FIRC_OK) { return stage_failed(xt, err, "the staging cannot be merged", table); }
    const firc_xt_ext_desc_t *gone = first_missing(exts & xt->missing);
    if (gone != NULL) {
        return failed(xt, FIRC_ERR_IO, "x_tables %s %s needs %s %s revision %u, which this kernel lacks", fam, table,
                      gone->target ? "target" : "match", gone->name,
                      xt->fam == FIRC_IPT_PROTO_IPV6 ? gone->rev6 : gone->rev4);
    }
    firc_xt_info_t ni;
    err = firc_xt_serialise(&w->view, &w->written, &ni, &w->old_index, why, sizeof(why));
    if (err == FIRC_ERR_IO) { return failed(xt, err, "x_tables %s %s: %s", fam, table, why); }
    if (err != FIRC_OK) { return stage_failed(xt, err, "the table cannot be written out", table); }
    uint64_t t2 = now_us();
    if (firc_xt_blob_equal(&ni, w->written, &info, w->read)) {
        FIRC_DEBUG("x_tables %s %s: unchanged, read %llu us, merge %llu us", fam, table,
                   (unsigned long long)(t1 - t0), (unsigned long long)(t2 - t1));
        xt->failing = false;
        return FIRC_OK;
    }
    if (firc_cancel_raised(cancel)) { return FIRC_ERR_CANCELED; }
    e = xt->ops->lock(xt->ud, FIRC_XT_LOCK_WAIT_MS);
    if (e == EAGAIN) {
        FIRC_DEBUG("x_tables %s %s: another writer holds the xtables lock, starting over", fam, table);
        return FIRC_ERR_AGAIN;
    }
    if (e != 0) {
        return failed(xt, FIRC_ERR_IO, "x_tables %s %s: the xtables lock cannot be taken (%s)", fam, table,
                      errname(e, eb, sizeof(eb)));
    }
    int refused = 0;
    err = write_locked(xt, table, &info, &ni, w, t0, t1, t2, &refused);
    xt->ops->unlock(xt->ud);
    if (refused != 0) {
        dump_refused(xt, table, &ni, w->written);
        return failed(xt, FIRC_ERR_IO, "x_tables refused %s %s (%s), %u entries, %u KB", fam, table,
                      errname(refused, eb, sizeof(eb)), ni.num_entries, (ni.size + 1023u) / 1024u);
    }
    if (err == FIRC_ERR_NOMEM) { return stage_failed(xt, err, "no memory for the old counters", table); }
    return err;
}

static firc_err_t write_locked(firc_xt_t *xt, const char *table, const firc_xt_info_t *read_info,
                               const firc_xt_info_t *new_info, work_t *w, uint64_t t0, uint64_t t1, uint64_t t2,
                               int *refused) {
    char eb[24];
    const char *fam = fam_name(xt);
    firc_xt_info_t info = *read_info, ni = *new_info;
    firc_xt_info_t again;
    int e = xt->ops->get_info(xt->ud, xt->fam, table, &again);
    if (e != 0 || !same_shape(&again, &info)) {
        FIRC_DEBUG("x_tables %s %s changed since it was read, starting over", fam, table);
        return FIRC_ERR_AGAIN;
    }
    w->old = calloc(info.num_entries ? info.num_entries : 1, sizeof(*w->old));
    if (w->old == NULL) { return FIRC_ERR_NOMEM; }
    e = xt->ops->replace(xt->ud, xt->fam, table, &ni, w->written, info.num_entries, w->old);
    if (e == EAGAIN) {
        FIRC_DEBUG("x_tables %s %s lost a race with another writer, starting over", fam, table);
        return FIRC_ERR_AGAIN;
    }
    if (e != 0) {
        *refused = e;
        return FIRC_ERR_IO;
    }
    uint64_t t3 = now_us();
    if (firc_xt_carry_counters(w->old_index, ni.num_entries, w->old, info.num_entries, &w->carried) == FIRC_OK) {
        e = xt->ops->add_counters(xt->ud, xt->fam, table, w->carried, ni.num_entries);
        if (e != 0) { FIRC_DEBUG("x_tables %s %s: counters not carried (%s)", fam, table, errname(e, eb, sizeof(eb))); }
    }
    uint64_t t4 = now_us();
    FIRC_DEBUG("x_tables %s %s: read %llu us, merge %llu us, write %llu us, counters %llu us, %u entries, %u bytes",
               fam, table, (unsigned long long)(t1 - t0), (unsigned long long)(t2 - t1),
               (unsigned long long)(t3 - t2), (unsigned long long)(t4 - t3), ni.num_entries, ni.size);
    xt->failing = false;
    return FIRC_OK;
}

firc_err_t firc_xt_commit(firc_xt_t *xt, const char *table, const firc_xt_stage_t *stage, firc_cancel_t *cancel) {
    if (xt == NULL || table == NULL || stage == NULL) { return FIRC_ERR_INVAL; }
    if (firc_cancel_raised(cancel)) { return FIRC_ERR_CANCELED; }
    work_t w;
    memset(&w, 0, sizeof(w));
    firc_err_t err = commit_table(xt, table, stage, cancel, &w);
    work_free(&w);
    return err;
}
