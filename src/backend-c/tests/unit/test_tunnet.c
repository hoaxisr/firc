#include "greatest.h"

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <string.h>

#include "fake_rtnl.h"
#include "firc/mark.h"
#include "firc/rtnl.h"
#include "firc/tunnet.h"

#define START 4200u

typedef struct {
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    firc_tunnel_t t[2];
    firc_tunnels_t all;
} fx_t;

static bool up(fx_t *f, unsigned link_flags) {
    memset(f, 0, sizeof(*f));
    f->kernel = fake_rtnl_start(&f->rtnl);
    if (f->kernel == NULL) { return false; }
    fake_rtnl_set_link_flags(f->kernel, link_flags);
    strcpy(f->t[0].id, "a");
    strcpy(f->t[0].device, "tunvless0");
    f->t[0].enable = true;
    strcpy(f->t[1].id, "b");
    strcpy(f->t[1].device, "lo");
    f->t[1].enable = true;
    f->all.t = f->t;
    f->all.n = 2;
    return true;
}

static void down(fx_t *f) {
    firc_rtnl_close(f->rtnl);
    fake_rtnl_stop(f->kernel);
}

static void uplink(fx_t *f, firc_uplink_kind_t kind, const char *ref) {
    f->t[0].uplink = kind;
    strcpy(f->t[0].uplink_ref, ref);
}

static size_t count(fx_t *f, uint16_t type, uint8_t rtm_type, uint32_t table, uint32_t priority, uint32_t oif) {
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f->kernel, m, 64), c = 0;
    for (size_t i = 0; i < n && i < 64; i++) {
        if (m[i].type != type || m[i].table != table || m[i].priority != priority) { continue; }
        if (rtm_type != 0 && m[i].rtm_type != rtm_type) { continue; }
        if (oif != 0 && m[i].oif != oif) { continue; }
        c++;
    }
    return c;
}

/* catches: a missing blackhole, a wrong priority, or a mark not taken from the shared allocator */
TEST an_iface_uplink_writes_the_rule_the_default_and_the_blackhole(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x10000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY);
    const uint8_t gw[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw, 4);
    uplink(&f, FIRC_UPLINK_IFACE, "lo");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT_EQ_FMT(0x20000u, u.mark, "%#x");
    ASSERT(u.table >= START);
    ASSERT(u.routed);

    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), rules = 0, defaults = 0, holes = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == RTM_NEWRULE) {
            rules++;
            ASSERT_EQ_FMT(AF_INET, (int)m[i].family, "%d");
            ASSERT_EQ_FMT(48u, m[i].priority, "%u");
            ASSERT_EQ_FMT(0x20000u, m[i].mark, "%#x");
            ASSERT_EQ_FMT(0x00ff0000u, m[i].mask, "%#x");
            ASSERT_EQ_FMT(u.table, m[i].table, "%u");
        } else if (m[i].type == RTM_NEWROUTE && m[i].rtm_type == RTN_UNICAST) {
            defaults++;
            ASSERT_EQ_FMT(u.table, m[i].table, "%u");
            ASSERT_EQ_FMT(10u, m[i].priority, "%u");
            ASSERT_EQ_FMT(1u, m[i].oif, "%u");
            ASSERT_EQ_FMT(4, (int)m[i].gw_len, "%d");
            ASSERT_MEM_EQ(gw, m[i].gw, 4);
        } else if (m[i].type == RTM_NEWROUTE && m[i].rtm_type == RTN_BLACKHOLE) {
            holes++;
            ASSERT_EQ_FMT(u.table, m[i].table, "%u");
            ASSERT_EQ_FMT(20u, m[i].priority, "%u");
        }
    }
    ASSERT_EQ_FMT((size_t)1, rules, "%zu");
    ASSERT_EQ_FMT((size_t)1, defaults, "%zu");
    ASSERT_EQ_FMT((size_t)1, holes, "%zu");
    down(&f);
    PASS();
}

/* catches: auto taking a mark field or writing a rule that would bypass the router's own routing */
TEST auto_writes_nothing(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    uplink(&f, FIRC_UPLINK_AUTO, "");
    firc_tunnet_uplink_t u;
    memset(&u, 0xab, sizeof(u));
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT_EQ_FMT(0u, u.mark, "%#x");
    ASSERT(u.routed);
    ASSERT_EQ_FMT((size_t)0, fake_rtnl_count(f.kernel, RTM_NEWRULE, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_rtnl_count(f.kernel, RTM_NEWROUTE, 0), "%zu");
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_remove(f.rtnl, &u));
    ASSERT_EQ_FMT((size_t)0, fake_rtnl_messages(f.kernel, NULL, 0), "%zu");
    down(&f);
    PASS();
}

/* catches: a tunnel uplink naming the tunnel id as an interface instead of its device */
TEST a_tunnel_uplink_routes_through_that_tunnels_device(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    uplink(&f, FIRC_UPLINK_TUNNEL, "b");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT(u.routed);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_UNICAST, u.table, 10, 1), "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWRULE, 0, u.table, 48, 0), "%zu");
    down(&f);
    PASS();
}

/* catches: refusing to start, or leaving the tunnel's packets on main, when the uplink is missing */
TEST a_missing_uplink_fails_closed(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    uplink(&f, FIRC_UPLINK_IFACE, "firc-nope0");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT_FALSE(u.routed);
    ASSERT(u.mark != 0);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWRULE, 0, u.table, 48, 0), "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_BLACKHOLE, u.table, 20, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_rtnl_count(f.kernel, RTM_NEWROUTE, RTN_UNICAST), "%zu");
    down(&f);
    PASS();
}

/* catches: a missing tunnel named as uplink taken for routed */
TEST a_tunnel_uplink_to_an_unknown_tunnel_fails_closed(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    uplink(&f, FIRC_UPLINK_TUNNEL, "lo");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT_FALSE(u.routed);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_BLACKHOLE, u.table, 20, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_rtnl_count(f.kernel, RTM_NEWROUTE, RTN_UNICAST), "%zu");
    down(&f);
    PASS();
}

/* catches: a PPPoE reconnect leaving the tunnel closed until SIGHUP */
TEST link_down_then_up_writes_the_default_again(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    uplink(&f, FIRC_UPLINK_IFACE, "lo");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_UNICAST, u.table, 10, 1), "%zu");

    fake_rtnl_set_link_flags(f.kernel, 0);
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_refresh(f.rtnl, &f.t[0], &f.all, &u));
    ASSERT_FALSE(u.routed);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_UNICAST, u.table, 10, 1), "%zu");

    fake_rtnl_set_link_flags(f.kernel, IFF_UP | IFF_POINTOPOINT);
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_refresh(f.rtnl, &f.t[0], &f.all, &u));
    ASSERT(u.routed);
    ASSERT_EQ_FMT((size_t)2, count(&f, RTM_NEWROUTE, RTN_UNICAST, u.table, 10, 1), "%zu");
    down(&f);
    PASS();
}

/* catches: a link-up for a tunnel that never had the interface at apply not writing the default */
TEST refresh_routes_an_uplink_that_appeared_after_apply(void) {
    fx_t f;
    ASSERT(up(&f, 0));
    uplink(&f, FIRC_UPLINK_TUNNEL, "b");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT_FALSE(u.routed);
    fake_rtnl_set_link_flags(f.kernel, IFF_UP | IFF_POINTOPOINT);
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_refresh(f.rtnl, &f.t[0], &f.all, &u));
    ASSERT(u.routed);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_UNICAST, u.table, 10, 1), "%zu");
    down(&f);
    PASS();
}

/* catches: an uplink moved to another device keeping the default via the one it left */
TEST refresh_moves_the_default_off_a_device_the_uplink_left(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    uplink(&f, FIRC_UPLINK_IFACE, "lo");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_UNICAST, u.table, 10, 1), "%zu");
    uplink(&f, FIRC_UPLINK_IFACE, "firc-nope0");
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_refresh(f.rtnl, &f.t[0], &f.all, &u));
    ASSERT_FALSE(u.routed);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELROUTE, RTN_UNICAST, u.table, 10, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELROUTE, RTN_BLACKHOLE, u.table, 20, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELRULE, 0, u.table, 48, 0), "%zu");
    down(&f);
    PASS();
}

static bool same_key(const fake_rtnl_msg_t *a, const fake_rtnl_msg_t *b) {
    return a->family == b->family && a->table == b->table && a->priority == b->priority &&
           a->rtm_type == b->rtm_type && a->mark == b->mark && a->mask == b->mask && a->oif == b->oif &&
           a->gw_len == b->gw_len && memcmp(a->gw, b->gw, a->gw_len) == 0;
}

/* catches: remove leaving a route or the rule (a leaked mark field) or deleting something apply never wrote */
TEST remove_deletes_exactly_what_apply_wrote(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw, 4);
    uplink(&f, FIRC_UPLINK_IFACE, "lo");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    size_t applied = fake_rtnl_messages(f.kernel, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_remove(f.rtnl, &u));

    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0, dels = 0;
    ASSERT(n <= 64);
    for (size_t i = 0; i < applied; i++) {
        uint16_t want = m[i].type == RTM_NEWRULE ? RTM_DELRULE : m[i].type == RTM_NEWROUTE ? RTM_DELROUTE : 0;
        if (want == 0) { continue; }
        adds++;
        size_t matched = 0;
        for (size_t j = applied; j < n; j++) {
            if (m[j].type == want && same_key(&m[i], &m[j])) { matched++; }
        }
        ASSERT_EQ_FMT((size_t)1, matched, "%zu");
    }
    for (size_t j = applied; j < n; j++) {
        if (m[j].type == RTM_DELRULE || m[j].type == RTM_DELROUTE) { dels++; }
    }
    ASSERT_EQ_FMT((size_t)3, adds, "%zu");
    ASSERT_EQ_FMT(adds, dels, "%zu");
    down(&f);
    PASS();
}

/* catches: a field taken under another owner name, so a group can grab the tunnel's field between restarts */
TEST the_field_is_held_under_the_tunnel_owner(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    uplink(&f, FIRC_UPLINK_IFACE, "lo");
    firc_tunnet_uplink_t u;
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_apply(f.rtnl, START, &f.t[0], &f.all, &u));
    ASSERT_EQ_FMT(0x10000u, u.mark, "%#x");
    ASSERT_EQ(FIRC_OK, firc_tunnet_uplink_remove(f.rtnl, &u));
    uint32_t field = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "g1", &field));
    ASSERT_EQ_FMT(2u, field, "%u");
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "tun:a", &field));
    ASSERT_EQ_FMT(1u, field, "%u");
    down(&f);
    PASS();
}

/* catches: a killed daemon's tunnel rule surviving the start sweep and holding its mark field forever */
TEST the_start_sweep_removes_a_left_tunnel_rule(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x30000, FIRC_MARK_GROUP_MASK, 4200, FIRC_RULE_PRIORITY_TUNNEL);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x30000, 0xffffffff, 4201, FIRC_RULE_PRIORITY_TUNNEL);
    size_t removed = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_clean_stale_rules(f.rtnl, &removed));
    ASSERT_EQ_FMT((size_t)1, removed, "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELRULE, 0, 4200, 48, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELRULE, 0, 4201, 48, 0), "%zu");
    down(&f);
    PASS();
}

/* catches: a killed daemon's tunnel table keeping its blackhole and default, so its number stays taken */
TEST the_start_sweep_flushes_a_left_tunnel_table(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0};
    const uint8_t ten[4] = {10, 0, 0, 0};
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x30000, FIRC_MARK_GROUP_MASK, 4200, FIRC_RULE_PRIORITY_TUNNEL);
    fake_rtnl_add_route(f.kernel, AF_INET, 4200, RTN_BLACKHOLE, FIRC_RTPROT, any, 0, 20);
    fake_rtnl_add_route(f.kernel, AF_INET, 4200, RTN_UNICAST, FIRC_RTPROT, any, 0, 10);
    fake_rtnl_add_route(f.kernel, AF_INET, 4200, RTN_UNICAST, RTPROT_STATIC, ten, 8, 0);
    fake_rtnl_add_route(f.kernel, AF_INET, 4202, RTN_BLACKHOLE, FIRC_RTPROT, any, 0, 20);
    size_t removed = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_clean_stale_rules(f.rtnl, &removed));
    ASSERT_EQ_FMT((size_t)1, removed, "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELROUTE, RTN_BLACKHOLE, 4200, 20, 0), "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELROUTE, RTN_UNICAST, 4200, 10, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELROUTE, 0, 4200, 0, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELROUTE, 0, 4202, 20, 0), "%zu");
    down(&f);
    PASS();
}

/* catches: the sweep flushing the table of a group rule, whose routes the group still owns */
TEST the_start_sweep_leaves_group_tables_alone(void) {
    fx_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0};
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x30000, FIRC_MARK_GROUP_MASK, 4300, FIRC_RULE_PRIORITY);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x40000, FIRC_MARK_GROUP_MASK, 4301, FIRC_RULE_PRIORITY_TUNNEL);
    fake_rtnl_add_route(f.kernel, AF_INET, 4300, RTN_BLACKHOLE, FIRC_RTPROT, any, 0, 20);
    fake_rtnl_add_route(f.kernel, AF_INET, 4301, RTN_BLACKHOLE, FIRC_RTPROT, any, 0, 20);
    size_t removed = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_clean_stale_rules(f.rtnl, &removed));
    ASSERT_EQ_FMT((size_t)2, removed, "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELROUTE, 0, 4301, 20, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELROUTE, 0, 4300, 20, 0), "%zu");
    down(&f);
    PASS();
}

SUITE(tunnet) {
    RUN_TEST(an_iface_uplink_writes_the_rule_the_default_and_the_blackhole);
    RUN_TEST(auto_writes_nothing);
    RUN_TEST(a_tunnel_uplink_routes_through_that_tunnels_device);
    RUN_TEST(a_missing_uplink_fails_closed);
    RUN_TEST(a_tunnel_uplink_to_an_unknown_tunnel_fails_closed);
    RUN_TEST(link_down_then_up_writes_the_default_again);
    RUN_TEST(refresh_routes_an_uplink_that_appeared_after_apply);
    RUN_TEST(refresh_moves_the_default_off_a_device_the_uplink_left);
    RUN_TEST(remove_deletes_exactly_what_apply_wrote);
    RUN_TEST(the_field_is_held_under_the_tunnel_owner);
    RUN_TEST(the_start_sweep_removes_a_left_tunnel_rule);
    RUN_TEST(the_start_sweep_flushes_a_left_tunnel_table);
    RUN_TEST(the_start_sweep_leaves_group_tables_alone);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tunnet);
    GREATEST_MAIN_END();
}
