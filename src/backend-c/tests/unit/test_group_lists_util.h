#ifndef FIRC_TEST_GROUP_LISTS_UTIL_H
#define FIRC_TEST_GROUP_LISTS_UTIL_H

#include <stdlib.h>

#include "firc/models.h"

static inline firc_group_list_t *test_group_set_list(firc_group_t *g)
{
    firc_group_list_t *l = firc_group_list_new();
    if (l == NULL) { return NULL; }
    if (firc_id_random(&l->id) != FIRC_OK || firc_group_add_list(g, l) != FIRC_OK) {
        firc_group_list_free(l);
        return NULL;
    }
    return l;
}

static inline firc_group_list_t *test_group_add_list_at(firc_group_t *g, const char *url)
{
    firc_group_list_t *l = firc_group_list_new();
    if (l == NULL) { return NULL; }
    if (firc_strset(&l->url, url) != FIRC_OK || firc_id_random(&l->id) != FIRC_OK ||
        firc_group_add_list(g, l) != FIRC_OK) {
        firc_group_list_free(l);
        return NULL;
    }
    return l;
}

static inline void test_group_drop_lists(firc_group_t *g)
{
    while (g->n_lists != 0) { firc_group_remove_list(g, g->n_lists - 1); }
}

#endif
