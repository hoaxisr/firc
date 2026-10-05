#ifndef FIRC_PURGE_H
#define FIRC_PURGE_H

#include <stdbool.h>
#include <stddef.h>

#include "firc/err.h"
#include "firc/iptables.h"
#include "firc/rtnl.h"

typedef struct {
    const char *pool_file;
    const char *sock;
    const char *lock;
    const char *run_dir;
} firc_purge_paths_t;

typedef struct {
    bool iptables_ok;
    bool routes_ok;
    size_t rules_removed;
    size_t routes_removed;
    bool run_dir_removed;
} firc_purge_report_t;

/* `fircd --purge`: runs every step even after a failure, returns the first error. Args nullable. */
firc_err_t firc_purge(firc_ipt_t *ipt4, firc_ipt_t *ipt6, firc_rtnl_t *rtnl, const char *chain_prefix,
                      const firc_purge_paths_t *paths, firc_purge_report_t *report);

#endif
