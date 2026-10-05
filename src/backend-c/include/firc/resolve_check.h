#ifndef FIRC_RESOLVE_CHECK_H
#define FIRC_RESOLVE_CHECK_H

#include <stdbool.h>
#include <stddef.h>

#include "firc/fakeip.h"
#include "firc/models.h"

/* True if server parses and lies inside pool (a resolver there is a fake address, unreachable). */
bool firc_resolve_server_in_pool(const char *server, const firc_fakeip_t *pool);

/* The first group whose server lies inside the pool, or NULL. */
const firc_group_t *firc_resolve_groups_in_pool(firc_group_t *const *groups, size_t n,
                                                const firc_fakeip_t *pool);

#endif
