#ifndef FIRC_TEST_FAKE_XTABLES_H
#define FIRC_TEST_FAKE_XTABLES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/xtables.h"

typedef struct firc_fake_xt firc_fake_xt_t;
typedef enum firc_fake_xt_race { FIRC_FAKE_XT_RACE_NONE = 0, FIRC_FAKE_XT_RACE_SAME_COUNT, FIRC_FAKE_XT_RACE_MORE_ENTRIES, FIRC_FAKE_XT_RACE_SIZE_AT_SECOND_INFO } firc_fake_xt_race_t;
firc_fake_xt_t *firc_fake_xt_new(firc_ipt_proto_t fam);
void firc_fake_xt_free(firc_fake_xt_t *f);
void firc_fake_xt_reset(firc_fake_xt_t *f);
firc_xt_t *firc_fake_xt_handle(firc_fake_xt_t *f);
bool firc_fake_xt_load(firc_fake_xt_t *f, const char *table, const firc_xt_info_t *info, const uint8_t *blob);
void firc_fake_xt_drop_table(firc_fake_xt_t *f, const char *table);
bool firc_fake_xt_blob(firc_fake_xt_t *f, const char *table, firc_xt_info_t *info, uint8_t **blob);
void firc_fake_xt_fail_next_replace(firc_fake_xt_t *f, int err);
void firc_fake_xt_fail_next_counters(firc_fake_xt_t *f, int err);
void firc_fake_xt_race_next(firc_fake_xt_t *f, firc_fake_xt_race_t how);
void firc_fake_xt_lack(firc_fake_xt_t *f, bool target, const char *name, uint8_t revision);
void firc_fake_xt_hold_lock(firc_fake_xt_t *f, bool held);
void firc_fake_xt_fail_revisions(firc_fake_xt_t *f, int err);
void firc_fake_xt_on_unlock(firc_fake_xt_t *f, void (*fn)(void *ud), void *ud);
void firc_fake_xt_set_counters(firc_fake_xt_t *f, const char *table, uint64_t base);
bool firc_fake_xt_counter(firc_fake_xt_t *f, const char *table, uint32_t index, firc_xt_counter_t *out);
void firc_fake_xt_on_read(firc_fake_xt_t *f, void (*fn)(void *ud), void *ud);
void firc_fake_xt_set_write_hooks(firc_fake_xt_t *f, int (*before)(void *ud, firc_ipt_proto_t fam, const char *table, const firc_xt_info_t *info, const uint8_t *blob), void (*after)(void *ud, const char *table), void *ud);
size_t firc_fake_xt_replaces(firc_fake_xt_t *f);
size_t firc_fake_xt_reads(firc_fake_xt_t *f);
size_t firc_fake_xt_revision_asks(firc_fake_xt_t *f);
size_t firc_fake_xt_reads_under_lock(firc_fake_xt_t *f);
size_t firc_fake_xt_writes_outside_lock(firc_fake_xt_t *f);
const firc_xt_kernel_ops_t *firc_fake_xt_ops(void);

#endif
