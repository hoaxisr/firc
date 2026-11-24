#ifndef FIRC_TEST_APP_LISTS_UTIL_H
#define FIRC_TEST_APP_LISTS_UTIL_H

#include "firc/app.h"
#include "firc/ruleset.h"

static inline firc_id_t list_at(firc_app_t *app, firc_id_t gid, size_t i)
{
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, gid);
    const firc_group_t *g = rs != NULL ? firc_ruleset_group(rs) : NULL;
    firc_id_t none = {{0, 0, 0, 0}};
    return g != NULL && i < g->n_lists ? g->lists[i]->id : none;
}

static inline firc_id_t list0(firc_app_t *app, firc_id_t gid) { return list_at(app, gid, 0); }

#endif
