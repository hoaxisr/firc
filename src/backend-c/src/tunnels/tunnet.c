#include "firc/tunnet.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "firc/mark.h"

const char *firc_tunnet_uplink_device(const firc_tunnel_t *t, const firc_tunnels_t *all) {
    if (t->uplink == FIRC_UPLINK_IFACE) { return t->uplink_ref; }
    if (t->uplink != FIRC_UPLINK_TUNNEL) { return NULL; }
    for (size_t i = 0; all != NULL && i < all->n; i++) {
        if (strcmp(all->t[i].id, t->uplink_ref) == 0) { return all->t[i].device; }
    }
    return NULL;
}

static firc_err_t write_default(firc_rtnl_t *r, const char *dev, firc_tunnet_uplink_t *u) {
    u->routed = false;
    if (dev == NULL) { return FIRC_OK; }
    firc_link_info_t li;
    bool found;
    firc_err_t err = firc_rtnl_link_by_name(r, dev, &li, &found);
    if (err != FIRC_OK || !found || !li.up) { return err; }
    snprintf(u->dev, sizeof(u->dev), "%s", dev);
    err = firc_iface_route_update(r, AF_INET, u->table, dev, li.ifindex, li.point_to_point, &u->route);
    u->routed = err == FIRC_OK && u->route.present;
    return err;
}

firc_err_t firc_tunnet_uplink_apply(firc_rtnl_t *r, uint32_t start_table, const firc_tunnel_t *t,
                                    const firc_tunnels_t *all, firc_tunnet_uplink_t *out) {
    memset(out, 0, sizeof(*out));
    if (t->uplink == FIRC_UPLINK_AUTO) {
        out->routed = true;
        return FIRC_OK;
    }
    char owner[24];
    snprintf(owner, sizeof(owner), FIRC_MARK_TUNNEL_OWNER "%s", t->id);
    uint32_t field = 0, table = 0;
    firc_err_t err = firc_rtnl_alloc_mark_table(r, start_table, &table);
    if (err == FIRC_OK) { err = firc_rtnl_alloc_mark_field_for(r, owner, &field); }
    if (err != FIRC_OK) { return err; }
    out->table = table;
    err = firc_rtnl_route_add_blackhole(r, AF_INET, table, 20);
    if (err != FIRC_OK) { return err; }
    err = firc_rtnl_rule_add(r, AF_INET, firc_mark_group_value(field), FIRC_MARK_GROUP_MASK, table,
                             FIRC_RULE_PRIORITY_TUNNEL);
    if (err != FIRC_OK) {
        (void)firc_rtnl_route_del_blackhole(r, AF_INET, table, 20);
        out->table = 0;
        return err;
    }
    out->mark = firc_mark_group_value(field);
    return write_default(r, firc_tunnet_uplink_device(t, all), out);
}

firc_err_t firc_tunnet_uplink_remove(firc_rtnl_t *r, const firc_tunnet_uplink_t *u) {
    if (u->mark == 0) { return FIRC_OK; }
    firc_iface_route_t route = u->route;
    firc_err_t first = firc_rtnl_rule_del(r, AF_INET, u->mark, FIRC_MARK_GROUP_MASK, u->table,
                                          FIRC_RULE_PRIORITY_TUNNEL);
    firc_err_t err = firc_iface_route_remove(r, AF_INET, u->table, u->dev, &route);
    if (first == FIRC_OK) { first = err; }
    err = firc_rtnl_route_del_blackhole(r, AF_INET, u->table, 20);
    return first == FIRC_OK ? err : first;
}

firc_err_t firc_tunnet_uplink_refresh(firc_rtnl_t *r, const firc_tunnel_t *t, const firc_tunnels_t *all,
                                      firc_tunnet_uplink_t *u) {
    if (u->mark == 0) { return FIRC_OK; }
    const char *dev = firc_tunnet_uplink_device(t, all);
    if (u->dev[0] != 0 && (dev == NULL || strcmp(dev, u->dev) != 0)) {
        firc_err_t err = firc_iface_route_remove(r, AF_INET, u->table, u->dev, &u->route);
        if (err != FIRC_OK) { return err; }
        memset(&u->route, 0, sizeof(u->route));
        u->dev[0] = 0;
        u->routed = false;
    }
    return write_default(r, dev, u);
}
