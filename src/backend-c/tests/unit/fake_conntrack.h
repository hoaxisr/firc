#ifndef FIRC_TEST_FAKE_CONNTRACK_H
#define FIRC_TEST_FAKE_CONNTRACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/conntrack.h"

typedef struct fake_ct fake_ct_t;

fake_ct_t *fake_ct_start(firc_ct_t **out);
void fake_ct_stop(fake_ct_t *f);

/* An entry the kernel reports in a dump */
void fake_ct_add(fake_ct_t *f, int family, const uint8_t *orig_src, const uint8_t *orig_dst,
                 const uint8_t *reply_src, uint32_t mark);
void fake_ct_last_is_icmp(fake_ct_t *f);
void fake_ct_set_dump_padding(fake_ct_t *f, size_t bytes);
void fake_ct_fail_next_dump(fake_ct_t *f, int err);
void fake_ct_fail_dump_of(fake_ct_t *f, int family, int err);
void fake_ct_fail_next_delete(fake_ct_t *f, int err);

void fake_ct_recreate_on_next_delete(fake_ct_t *f);

size_t fake_ct_unread(fake_ct_t *f);

void fake_ct_delay_dumps(fake_ct_t *f, int ms);
void fake_ct_ignore_mark_filter(fake_ct_t *f);
void fake_ct_reject_mark_filter(fake_ct_t *f, int err);

void fake_ct_never_answer_dumps(fake_ct_t *f);
void fake_ct_never_answer_deletes(fake_ct_t *f);

size_t fake_ct_dumps(fake_ct_t *f);

bool fake_ct_dump_filtered_on_mark(fake_ct_t *f, uint32_t *value, uint32_t *mask);

size_t fake_ct_deletes(fake_ct_t *f);
bool fake_ct_deleted(fake_ct_t *f, const uint8_t *reply_src, size_t len);
size_t fake_ct_remaining(fake_ct_t *f);

#endif
