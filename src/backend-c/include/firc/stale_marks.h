#ifndef FIRC_STALE_MARKS_H
#define FIRC_STALE_MARKS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/conntrack.h"
#include "firc/err.h"
#include "firc/fakeip.h"
#include "firc/models.h"

typedef struct {
    const char *id;
    uint32_t field; /* 0: not in the kernel */
    const firc_ct_chunk_t *subnets;
    size_t n_subnets;
    bool inexact;
} firc_stale_group_t;

/* False only on allocation failure, and then the caller must not sweep. Caller frees *out. */
bool firc_stale_group_subnets(const firc_group_t *g, uint32_t field, firc_ct_chunk_t **out,
                              size_t *out_n);

/* Skipped (FIRC_OK, *dropped 0) unless pool_state_trusted: an untrusted empty pool would drop every flow. */
firc_err_t firc_stale_marks_sweep(firc_ct_t *ct, const firc_fakeip_t *pool, bool pool_state_trusted,
                                  const firc_stale_group_t *groups, size_t n_groups,
                                  uint32_t mask, size_t *dropped);

#endif /* FIRC_STALE_MARKS_H */
