#include "greatest.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "firc/dnspipeline.h"
#include "firc/log.h"
#include "firc/resolveroute.h"
#include "firc/rulesnap.h"

static firc_group_t *group(const char *name, const char *iface, uint8_t id_last)
{
    firc_group_t *g = firc_group_new();
    firc_strset(&g->name, name);
    firc_strset(&g->iface, iface);
    g->enable = true;
    g->id.b[3] = id_last;
    return g;
}

static firc_resolver_addr_t addr(const char *s)
{
    firc_resolver_addr_t a;
    (void)firc_resolver_addr_parse(s, &a);
    return a;
}

#define MARK1 0x40010000u

/* Catches: server, firmware and none taken in another order, `tunnel: false` routed, or a blackhole. */
TEST precedence_is_server_then_firmware_then_none(void)
{
    firc_group_t *own = group("own", "nwg0", 1);
    firc_strset(&own->resolve.server, "8.8.8.8");
    firc_group_t *fw = group("fw", "nwg0", 2);
    firc_group_t *none = group("none", "nwg1", 3);
    firc_group_t *off = group("off", "nwg0", 4);
    off->resolve.tunnel = false;
    firc_group_t *bh = group("bh", "blackhole", 5);
    firc_strset(&bh->resolve.server, "9.9.9.9");

    firc_resolver_addr_t nwg0[2] = {addr("9.9.9.9"), addr("1.0.0.1")};
    firc_resolve_input_t in[] = {
        {.group = own, .mark = MARK1, .firmware = nwg0, .n_firmware = 2},
        {.group = fw, .mark = MARK1, .firmware = nwg0, .n_firmware = 2},
        {.group = none, .mark = MARK1},
        {.group = off, .mark = MARK1, .firmware = nwg0, .n_firmware = 2},
        {.group = bh, .mark = MARK1, .blackhole = true},
    };
    firc_resolve_table_t t = {0};
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 5, NULL, &t));
    ASSERT_EQ((size_t)5, t.n);

    ASSERT_EQ(FIRC_RESOLVE_SOURCE_GROUP, t.items[0].source);
    ASSERT_EQ((size_t)1, t.items[0].n_servers);
    ASSERT_EQ(8, t.items[0].servers[0].ip.b[0]);
    ASSERT(firc_resolve_route_usable(&t.items[0]));

    ASSERT_EQ(FIRC_RESOLVE_SOURCE_FIRMWARE, t.items[1].source);
    ASSERT_EQ((size_t)2, t.items[1].n_servers);
    ASSERT_EQ(9, t.items[1].servers[0].ip.b[0]);

    ASSERT_EQ(FIRC_RESOLVE_SOURCE_NONE, t.items[2].source);
    ASSERT_FALSE(firc_resolve_route_usable(&t.items[2]));

    ASSERT_EQ(FIRC_RESOLVE_SOURCE_OFF, t.items[3].source);
    ASSERT_EQ((size_t)0, t.items[3].n_servers);
    ASSERT_FALSE(firc_resolve_route_usable(&t.items[3]));

    ASSERT_EQ(FIRC_RESOLVE_SOURCE_NONE, t.items[4].source);
    ASSERT(t.items[4].blackhole);
    ASSERT_FALSE(firc_resolve_route_usable(&t.items[4]));

    ASSERT_STR_EQ("nwg0", t.items[0].iface);
    ASSERT_STR_EQ("own", t.items[0].group_name);
    ASSERT_EQ(MARK1, t.items[0].mark);

    firc_resolve_table_free(&t);
    firc_group_t *all[] = {own, fw, none, off, bh};
    for (int i = 0; i < 5; i++) { firc_group_free(all[i]); }
    PASS();
}

/* Catches: a group with mark 0 counted as usable, so its query leaves by the WAN. */
TEST a_group_with_no_mark_is_not_usable(void)
{
    firc_group_t *g = group("g", "nwg0", 1);
    firc_strset(&g->resolve.server, "9.9.9.9");
    firc_resolve_input_t in = {.group = g, .mark = 0};
    firc_resolve_table_t t = {0};
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    ASSERT_EQ(FIRC_RESOLVE_SOURCE_GROUP, t.items[0].source);
    ASSERT_EQ((size_t)1, t.items[0].n_servers);
    ASSERT_FALSE(firc_resolve_route_usable(&t.items[0]));
    firc_resolve_table_free(&t);
    firc_group_free(g);
    PASS();
}

TEST v4_first_and_v6_only_with_a_v6_route(void)
{
    firc_group_t *g = group("g", "nwg0", 1);
    firc_resolver_addr_t fw[3] = {addr("2620:fe::fe"), addr("9.9.9.9"), addr("2620:fe::9")};
    firc_resolve_input_t in = {.group = g, .mark = MARK1, .firmware = fw, .n_firmware = 3, .v6_route = true};
    firc_resolve_table_t t = {0};
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    ASSERT_EQ((size_t)3, t.items[0].n_servers);
    ASSERT_EQ(4, t.items[0].servers[0].ip.len);
    ASSERT_EQ(0xfe, t.items[0].servers[1].ip.b[15]);
    ASSERT_EQ(0x09, t.items[0].servers[2].ip.b[15]);
    firc_resolve_table_free(&t);

    in.v6_route = false;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    ASSERT_EQ((size_t)1, t.items[0].n_servers);
    ASSERT_EQ(4, t.items[0].servers[0].ip.len);
    firc_resolve_table_free(&t);

    firc_strset(&g->resolve.server, "[2620:fe::fe]:53");
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    ASSERT_EQ(FIRC_RESOLVE_SOURCE_GROUP, t.items[0].source);
    ASSERT_EQ((size_t)0, t.items[0].n_servers);
    firc_resolve_table_free(&t);
    firc_group_free(g);
    PASS();
}

/* Catches: a rebuild bumping the generation with nothing changed, or keeping it on a real change. */
TEST the_generation_moves_only_on_a_real_change(void)
{
    firc_group_t *g = group("g", "nwg0", 1);
    firc_group_t *h = group("h", "nwg1", 2);
    firc_resolver_addr_t fw[1] = {addr("9.9.9.9")};
    firc_resolve_input_t in[2] = {
        {.group = g, .mark = MARK1, .firmware = fw, .n_firmware = 1},
        {.group = h, .mark = 0x40020000u, .firmware = fw, .n_firmware = 1},
    };
    firc_resolve_table_t t1 = {0}, t2 = {0}, t3 = {0}, t4 = {0}, t5 = {0};
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, NULL, &t1));
    ASSERT(t1.items[0].gen != 0 && t1.items[1].gen != 0 && t1.items[0].gen != t1.items[1].gen);

    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, &t1, &t2));
    ASSERT_EQ(t1.items[0].gen, t2.items[0].gen);
    ASSERT_EQ(t1.items[1].gen, t2.items[1].gen);

    in[0].mark = 0x40030000u;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, &t2, &t3));
    ASSERT(t3.items[0].gen != t2.items[0].gen);
    ASSERT(t3.items[0].gen > t2.last_gen);
    ASSERT_EQ(t2.items[1].gen, t3.items[1].gen);

    firc_strset(&h->iface, "nwg2");
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, &t3, &t4));
    ASSERT(t4.items[1].gen != t3.items[1].gen);

    firc_resolver_addr_t fw2[1] = {addr("1.0.0.1")};
    in[0].firmware = fw2;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, &t4, &t5));
    ASSERT(t5.items[0].gen != t4.items[0].gen);

    firc_resolve_table_t *all[] = {&t1, &t2, &t3, &t4, &t5};
    for (int i = 0; i < 5; i++) { firc_resolve_table_free(all[i]); }
    firc_group_free(g);
    firc_group_free(h);
    PASS();
}

/* Catches: the log line missing the interface, servers or source, or "not through the tunnel". */
TEST each_route_is_described_for_the_log(void)
{
    firc_group_t *g = group("nl", "nwg0", 1);
    firc_resolver_addr_t fw[2] = {addr("9.9.9.9"), addr("1.0.0.1")};
    firc_resolve_input_t in = {.group = g, .mark = MARK1, .firmware = fw, .n_firmware = 2};
    firc_resolve_table_t t = {0};
    char buf[256];

    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    ASSERT(firc_resolve_route_describe(&t.items[0], buf, sizeof(buf)) > 0);
    ASSERT_STR_EQ("resolves through nwg0: 9.9.9.9, 1.0.0.1 (the firmware's for nwg0)", buf);
    firc_resolve_table_free(&t);

    firc_strset(&g->resolve.server, "[2620:fe::fe]:853");
    in.v6_route = true;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    firc_resolve_route_describe(&t.items[0], buf, sizeof(buf));
    ASSERT_STR_EQ("resolves through nwg0: [2620:fe::fe]:853 (resolve.server)", buf);
    firc_resolve_table_free(&t);

    in.firmware = NULL;
    in.n_firmware = 0;
    free(g->resolve.server);
    g->resolve.server = NULL;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    firc_resolve_route_describe(&t.items[0], buf, sizeof(buf));
    ASSERT_STR_EQ("uses the common upstream: the firmware binds no resolver to nwg0", buf);
    firc_resolve_table_free(&t);

    g->resolve.tunnel = false;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    firc_resolve_route_describe(&t.items[0], buf, sizeof(buf));
    ASSERT_STR_EQ("uses the common upstream: resolving through the tunnel is off", buf);
    firc_resolve_table_free(&t);

    g->resolve.tunnel = true;
    firc_strset(&g->resolve.server, "9.9.9.9");
    in.mark = 0;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    firc_resolve_route_describe(&t.items[0], buf, sizeof(buf));
    ASSERT_STR_EQ("uses the common upstream until nwg0 is routed (9.9.9.9, resolve.server)", buf);
    firc_resolve_table_free(&t);

    free(g->resolve.server);
    g->resolve.server = NULL;
    firc_resolver_addr_t fw_v6[1] = {addr("2620:fe::9")};
    in.mark = MARK1;
    in.firmware = fw_v6;
    in.n_firmware = 1;
    in.v6_route = false;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    firc_resolve_route_describe(&t.items[0], buf, sizeof(buf));
    ASSERT_STR_EQ("uses the common upstream: its resolvers for nwg0 are IPv6 and nwg0 has no IPv6 route", buf);
    firc_resolve_table_free(&t);

    firc_strset(&g->resolve.server, "2620:fe::9");
    in.firmware = NULL;
    in.n_firmware = 0;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(&in, 1, NULL, &t));
    firc_resolve_route_describe(&t.items[0], buf, sizeof(buf));
    ASSERT_STR_EQ("uses the common upstream: its resolver, resolve.server, is IPv6 and nwg0 has no IPv6 route",
                  buf);
    firc_resolve_table_free(&t);
    firc_group_free(g);
    PASS();
}

static size_t publish_logged(firc_resolve_router_t *r, firc_resolve_table_t *t, char *out, size_t cap)
{
    int fds[2];
    if (pipe(fds) != 0) { return 0; }
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    firc_resolve_router_publish(r, t);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    ssize_t n = read(fds[0], out, cap - 1);
    close(fds[0]);
    if (n < 0) { n = 0; }
    out[n] = '\0';
    return (size_t)n;
}

/* Catches: an unchanged group logged on every publish, a change unsaid, or a copy freed by a publish. */
TEST a_publish_logs_what_changed_and_hands_out_copies(void)
{
    firc_resolve_router_t *r = firc_resolve_router_new(NULL);
    ASSERT(r != NULL);
    firc_group_t *g = group("nl", "nwg0", 1);
    firc_group_t *h = group("de", "nwg1", 2);
    firc_resolver_addr_t fw[1] = {addr("9.9.9.9")};
    firc_resolve_input_t in[2] = {
        {.group = g, .mark = MARK1, .firmware = fw, .n_firmware = 1},
        {.group = h, .mark = 0x40020000u},
    };
    char log[2048];
    firc_resolve_table_t t = {0};
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, firc_resolve_router_table(r), &t));
    publish_logged(r, &t, log, sizeof(log));
    ASSERT_EQ(NULL, t.items);
    ASSERTm(log, strstr(log, "group \"nl\" resolves through nwg0: 9.9.9.9") != NULL);
    ASSERTm(log, strstr(log, "group \"de\" uses the common upstream") != NULL);

    firc_resolve_route_t copy;
    ASSERT(firc_resolve_router_route(r, g->id, &copy));

    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, firc_resolve_router_table(r), &t));
    publish_logged(r, &t, log, sizeof(log));
    ASSERT_STR_EQm("nothing changed, nothing said", "", log);

    firc_resolver_addr_t fw2[1] = {addr("1.0.0.1")};
    in[0].firmware = fw2;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, firc_resolve_router_table(r), &t));
    publish_logged(r, &t, log, sizeof(log));
    ASSERTm(log, strstr(log, "group \"nl\" resolves through nwg0: 1.0.0.1") != NULL);
    ASSERTm(log, strstr(log, "\"de\"") == NULL);

    ASSERT_EQ(9, copy.servers[0].ip.b[0]);
    ASSERT_STR_EQ("nwg0", copy.iface);

    firc_id_t unknown = {0};
    ASSERT_FALSE(firc_resolve_router_route(r, unknown, &copy));
    firc_resolve_router_free(r);
    firc_group_free(g);
    firc_group_free(h);
    PASS();
}

static firc_dns_msg_t *query(const char *name, uint16_t qtype)
{
    uint8_t b[300] = {0};
    b[1] = 0x42;
    b[2] = 0x01;
    b[5] = 1;
    size_t p = 12;
    for (const char *s = name; *s != '\0';) {
        const char *dot = strchr(s, '.');
        size_t l = dot != NULL ? (size_t)(dot - s) : strlen(s);
        b[p++] = (uint8_t)l;
        memcpy(b + p, s, l);
        p += l;
        s += l + (dot != NULL ? 1 : 0);
    }
    b[p++] = 0;
    b[p++] = (uint8_t)(qtype >> 8);
    b[p++] = (uint8_t)qtype;
    b[p++] = 0;
    b[p++] = 1;
    firc_dns_msg_t *m = NULL;
    return firc_dns_msg_parse(b, p, &m) == FIRC_OK ? m : NULL;
}

static void add_namespace_rule(firc_group_t *g, const char *domain)
{
    firc_rule_t *r = firc_rule_new();
    r->id = firc_id_random();
    firc_strset(&r->type, "namespace");
    firc_strset(&r->rule, domain);
    r->enable = true;
    firc_group_add_rule(g, r);
}

typedef struct {
    firc_config_t cfg;
    firc_dns_pipeline_t *pl;
    firc_resolve_router_t *router;
} decide_fx_t;

/* Five groups: one routed, and one for each way a query must not be routed. */
static bool decide_fx_up(decide_fx_t *fx)
{
    memset(fx, 0, sizeof(*fx));
    if (firc_config_init_defaults(&fx->cfg) != FIRC_OK) { return false; }
    const char *names[] = {"nl", "off", "none", "unmarked", "bh"};
    const char *doms[] = {"example.com", "off.test", "none.test", "unmarked.test", "bh.test"};
    const char *ifs[] = {"nwg0", "nwg0", "nwg1", "nwg0", "blackhole"};
    for (int i = 0; i < 5; i++) {
        firc_group_t *g = group(names[i], ifs[i], (uint8_t)(i + 1));
        add_namespace_rule(g, doms[i]);
        firc_config_add_group(&fx->cfg, g);
    }
    firc_group_t **gs = fx->cfg.groups;
    gs[0]->devices.allow = calloc(1, sizeof(char *));
    gs[0]->devices.allow[0] = strdup("192.168.1.0/24");
    gs[0]->devices.n_allow = 1;
    gs[1]->resolve.tunnel = false;
    firc_strset(&gs[3]->resolve.server, "8.8.8.8");
    firc_strset(&gs[4]->resolve.server, "8.8.8.8");

    fx->pl = firc_dns_pipeline_create();
    fx->router = firc_resolve_router_new(fx->pl);
    if (fx->pl == NULL || fx->router == NULL) { return false; }
    firc_dns_pipeline_set_snapshot(fx->pl, firc_ruleset_snapshot_build(&fx->cfg));

    static firc_resolver_addr_t fw[1];
    fw[0] = addr("9.9.9.9");
    firc_resolve_input_t in[5] = {
        {.group = gs[0], .mark = MARK1, .firmware = fw, .n_firmware = 1},
        {.group = gs[1], .mark = MARK1, .firmware = fw, .n_firmware = 1},
        {.group = gs[2], .mark = MARK1},
        {.group = gs[3], .mark = 0},
        {.group = gs[4], .mark = MARK1, .blackhole = true},
    };
    firc_resolve_table_t t;
    if (firc_resolve_table_build(in, 5, NULL, &t) != FIRC_OK) { return false; }
    firc_resolve_router_publish(fx->router, &t);
    return true;
}

static void decide_fx_down(decide_fx_t *fx)
{
    firc_resolve_router_free(fx->router);
    firc_dns_pipeline_destroy(fx->pl);
    firc_config_clear(&fx->cfg);
}

static bool decide(decide_fx_t *fx, const char *name, uint16_t qtype, const char *client,
                   firc_dnsproxy_route_t *out)
{
    firc_ip_t c = {.len = 4};
    const firc_ip_t *cp = NULL;
    if (client != NULL) {
        inet_pton(AF_INET, client, c.b);
        cp = &c;
    }
    firc_dns_msg_t *q = query(name, qtype);
    bool got = firc_resolve_router_decide(fx->router, q, cp, out);
    firc_dns_msg_free(q);
    return got;
}

/* Catches: the mark, server or port not copied, or the route read from a replaced table. */
TEST the_owner_of_a_covered_query_is_routed_by_value(void)
{
    decide_fx_t fx;
    ASSERT(decide_fx_up(&fx));
    firc_dnsproxy_route_t r;
    ASSERT(decide(&fx, "a.example.com", 1 , "192.168.1.5", &r));
    ASSERT_EQ(MARK1, r.mark);
    ASSERT_EQ((size_t)1, r.n_servers);
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)&r.servers[0];
    ASSERT_EQ(AF_INET, s4->sin_family);
    ASSERT_EQ(htons(53), s4->sin_port);
    ASSERT_EQ(htonl(0x09090909u), s4->sin_addr.s_addr);
    ASSERT_EQ((socklen_t)sizeof(struct sockaddr_in), r.server_lens[0]);
    ASSERT(firc_id_equal(fx.cfg.groups[0]->id, r.group_id));
    ASSERT(r.gen != 0);

    firc_resolve_table_t empty = {0};
    firc_resolve_router_publish(fx.router, &empty);
    ASSERT_EQ(htonl(0x09090909u), s4->sin_addr.s_addr);
    ASSERT_FALSE(decide(&fx, "a.example.com", 1, "192.168.1.5", &r));
    decide_fx_down(&fx);
    PASS();
}

/* Catches: the router stricter than the selector for an unknown client. */
TEST a_query_with_no_client_address_is_routed_like_the_pipeline_covers_it(void)
{
    decide_fx_t fx;
    ASSERT(decide_fx_up(&fx));
    firc_dnsproxy_route_t r;
    ASSERT(decide(&fx, "a.example.com", 1, NULL, &r));
    ASSERT_EQ(MARK1, r.mark);
    decide_fx_down(&fx);
    PASS();
}

/* Catches: the routing decision filtering on qtype. */
TEST every_query_type_is_routed(void)
{
    decide_fx_t fx;
    ASSERT(decide_fx_up(&fx));
    firc_dnsproxy_route_t r;
    const uint16_t types[] = {1, 28, 16 , 15 , 65 , 33 };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        ASSERTm("qtype", decide(&fx, "a.example.com", types[i], "192.168.1.5", &r));
    }
    decide_fx_down(&fx);
    PASS();
}

/* Catches: an unowned, uncovered, off, resolverless, unmarked or blackhole query tunnelled. */
TEST what_is_not_routed_goes_to_the_common_upstream(void)
{
    decide_fx_t fx;
    ASSERT(decide_fx_up(&fx));
    firc_dnsproxy_route_t r;
    ASSERT_FALSEm("no owner", decide(&fx, "a.example.org", 1, "192.168.1.5", &r));
    ASSERT_FALSEm("not covered", decide(&fx, "a.example.com", 1, "10.0.0.5", &r));
    ASSERT_FALSEm("switch off", decide(&fx, "x.off.test", 1, "192.168.1.5", &r));
    ASSERT_FALSEm("no resolver", decide(&fx, "x.none.test", 1, "192.168.1.5", &r));
    ASSERT_FALSEm("mark 0", decide(&fx, "x.unmarked.test", 1, "192.168.1.5", &r));
    ASSERT_FALSEm("blackhole", decide(&fx, "x.bh.test", 1, "192.168.1.5", &r));
    firc_resolve_router_t *bare = firc_resolve_router_new(NULL);
    firc_dns_msg_t *q = query("a.example.com", 1);
    firc_ip_t c = {.b = {192, 168, 1, 5}, .len = 4};
    ASSERT_FALSEm("no pipeline", firc_resolve_router_decide(bare, q, &c, &r));
    firc_dns_msg_free(q);
    firc_resolve_router_free(bare);
    decide_fx_down(&fx);
    PASS();
}

/* Catches: an unchanged group reported stale, a changed one missed, or rewired taken for removed. */
TEST the_stale_groups_are_the_removed_and_the_rewired(void)
{
    firc_group_t *g = group("g", "nwg0", 1), *h = group("h", "nwg1", 2), *k = group("k", "nwg2", 3);
    firc_resolver_addr_t fw[1] = {addr("9.9.9.9")};
    firc_resolve_input_t in[3] = {
        {.group = g, .mark = MARK1, .firmware = fw, .n_firmware = 1},
        {.group = h, .mark = 0x40020000u, .firmware = fw, .n_firmware = 1},
        {.group = k, .mark = 0x40030000u, .firmware = fw, .n_firmware = 1},
    };
    firc_resolve_table_t a = {0}, b = {0};
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 3, NULL, &a));
    in[1].mark = 0x40040000u;
    ASSERT_EQ(FIRC_OK, firc_resolve_table_build(in, 2, &a, &b));
    firc_id_t out[4];
    size_t n = firc_resolve_table_stale(&a, &b, out, 4);
    ASSERT_EQ((size_t)2, n);
    ASSERT(firc_id_equal(out[0], h->id));
    ASSERT(firc_id_equal(out[1], k->id));
    ASSERT_EQm("cap bounds the list", (size_t)1, firc_resolve_table_stale(&a, &b, out, 1));
    ASSERT(firc_id_equal(out[0], h->id));
    ASSERT_EQ((size_t)0, firc_resolve_table_stale(&b, &b, out, 4));
    ASSERT_EQ((size_t)0, firc_resolve_table_stale(NULL, &b, out, 4));

    ASSERT_EQm("only k is gone", (size_t)1, firc_resolve_table_gone(&a, &b, out, 4));
    ASSERT(firc_id_equal(out[0], k->id));
    ASSERT_EQ((size_t)0, firc_resolve_table_gone(&b, &b, out, 4));
    ASSERT_EQ((size_t)0, firc_resolve_table_gone(NULL, &b, out, 4));
    firc_resolve_table_t empty = {0};
    ASSERT_EQm("everything is gone from an empty table", (size_t)2, firc_resolve_table_gone(&b, &empty, out, 4));
    firc_resolve_table_free(&a);
    firc_resolve_table_free(&b);
    firc_group_free(g);
    firc_group_free(h);
    firc_group_free(k);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(precedence_is_server_then_firmware_then_none);
    RUN_TEST(a_group_with_no_mark_is_not_usable);
    RUN_TEST(v4_first_and_v6_only_with_a_v6_route);
    RUN_TEST(the_generation_moves_only_on_a_real_change);
    RUN_TEST(each_route_is_described_for_the_log);
    RUN_TEST(a_publish_logs_what_changed_and_hands_out_copies);
    RUN_TEST(the_owner_of_a_covered_query_is_routed_by_value);
    RUN_TEST(a_query_with_no_client_address_is_routed_like_the_pipeline_covers_it);
    RUN_TEST(every_query_type_is_routed);
    RUN_TEST(what_is_not_routed_goes_to_the_common_upstream);
    RUN_TEST(the_stale_groups_are_the_removed_and_the_rewired);
    GREATEST_MAIN_END();
}
