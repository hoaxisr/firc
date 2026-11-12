#ifndef FIRC_PURGE_H
#define FIRC_PURGE_H

#include <stdbool.h>
#include <stddef.h>

#include "firc/err.h"
#include "firc/iptables.h"
#include "firc/rtnl.h"
#include "firc/setnl.h"

typedef struct {
    const char *pool_file;
    const char *fields_file;
    const char *sock;
    const char *lock;
    const char *run_dir;
} firc_purge_paths_t;

typedef struct {
    bool iptables_ok;
    bool routes_ok;
    size_t rules_removed;
    size_t routes_removed;
    size_t sets;
    bool run_dir_removed;
} firc_purge_report_t;

/* `fircd --purge`: runs every step even after a failure, returns the first error. Args nullable. */
firc_err_t firc_purge(firc_ipt_t *ipt4, firc_ipt_t *ipt6, firc_rtnl_t *rtnl, firc_setnl_t *sets,
                      const char *chain_prefix, const firc_purge_paths_t *paths, firc_purge_report_t *report);

/* Destroys every set named chain_prefix*, saying what it did; a set in use is FIRC_ERR_AGAIN. NULL sets: FIRC_OK. */
firc_err_t firc_purge_sets(firc_setnl_t *sets, const char *chain_prefix, size_t *destroyed);

#endif
