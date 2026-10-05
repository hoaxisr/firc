#include "firc/resolve_check.h"

#include "firc/resolver_addr.h"

bool firc_resolve_server_in_pool(const char *server, const firc_fakeip_t *pool)
{
    if (server == NULL || server[0] == '\0' || pool == NULL) { return false; }
    firc_resolver_addr_t a;
    if (firc_resolver_addr_parse(server, &a) != FIRC_RESOLVER_ADDR_OK) { return false; }
    return firc_fakeip_overlaps(pool, &a.ip, (uint8_t)(a.ip.len * 8));
}

const firc_group_t *firc_resolve_groups_in_pool(firc_group_t *const *groups, size_t n,
                                                const firc_fakeip_t *pool)
{
    for (size_t i = 0; i < n; i++) {
        if (groups[i] != NULL && firc_resolve_server_in_pool(groups[i]->resolve.server, pool)) {
            return groups[i];
        }
    }
    return NULL;
}
