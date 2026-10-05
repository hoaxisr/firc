#include "greatest.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "firc/fakeip.h"
#include "firc/fakeip_from_config.h"
#include "firc/models.h"
#include "firc/resolve_check.h"
#include "firc/resolver_addr.h"
#include "firc/yamlio.h"

static firc_resolver_addr_res_t parse(const char *s, firc_resolver_addr_t *a)
{
    memset(a, 0xAB, sizeof(*a));
    return firc_resolver_addr_parse(s, a);
}

/* Catches: a valid address shape refused, a port read off the wrong side of v6, or no default 53. */
TEST each_shape_parses(void)
{
    firc_resolver_addr_t a;
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("9.9.9.9", &a));
    ASSERT_EQ(4, a.ip.len);
    ASSERT_EQ(9, a.ip.b[0]);
    ASSERT_EQ(9, a.ip.b[3]);
    ASSERT_EQ(53, a.port);

    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("9.9.9.9:5353", &a));
    ASSERT_EQ(5353, a.port);

    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("2620:fe::fe", &a));
    ASSERT_EQ(16, a.ip.len);
    ASSERT_EQ(0x26, a.ip.b[0]);
    ASSERT_EQ(0xfe, a.ip.b[15]);
    ASSERT_EQ(53, a.port);

    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("[2620:fe::fe]:853", &a));
    ASSERT_EQ(16, a.ip.len);
    ASSERT_EQ(853, a.port);

    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("[2620:fe::fe]", &a));
    ASSERT_EQ(53, a.port);

    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("2620:fe::fe:53", &a));
    ASSERT_EQ(16, a.ip.len);
    ASSERT_EQ(0x00, a.ip.b[14]);
    ASSERT_EQ(0x53, a.ip.b[15]);
    ASSERT_EQ(53, a.port);
    PASS();
}

/* Catches: a host name, partial address, bracketed v4 or out-of-range port accepted. */
TEST what_is_not_an_address_is_refused(void)
{
    firc_resolver_addr_t a;
    const char *syntax[] = {"",           "dns.google",   "9.9.9",        "9.9.9.9:",
                            "[9.9.9.9]",  "[9.9.9.9]:53", "[2620:fe::fe", "2620:fe::fe]",
                            "9.9.9.9:53x", " 9.9.9.9",    "9.9.9.9 ",     "[2620:fe::fe]53"};
    for (size_t i = 0; i < sizeof(syntax) / sizeof(syntax[0]); i++) {
        ASSERT_EQm(syntax[i], FIRC_RESOLVER_ADDR_SYNTAX, parse(syntax[i], &a));
    }
    const char *port[] = {"9.9.9.9:0",     "9.9.9.9:65536",    "9.9.9.9:+53", "9.9.9.9:053535",
                          "[2620:fe::fe]:0", "9.9.9.9:-1",      "9.9.9.9:+",   "[2620:fe::fe]:-"};
    for (size_t i = 0; i < sizeof(port) / sizeof(port[0]); i++) {
        ASSERT_EQm(port[i], FIRC_RESOLVER_ADDR_PORT, parse(port[i], &a));
    }
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("9.9.9.9:65535", &a));
    ASSERT_EQ(65535, a.port);
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("9.9.9.9:1", &a));
    ASSERT_EQ(1, a.port);
    ASSERT_EQ(FIRC_RESOLVER_ADDR_SYNTAX, firc_resolver_addr_parse(NULL, &a));
    PASS();
}

/* Catches: 127/8 narrowed, a sink's neighbour refused, or a v4-mapped sink let through. */
TEST sinks_are_refused_and_their_neighbours_are_not(void)
{
    firc_resolver_addr_t a;
    const char *sinks[] = {"0.0.0.0", "127.0.0.1", "127.255.255.254:53", "::", "::1", "[::1]:53", "[::]:5353"};
    for (size_t i = 0; i < sizeof(sinks) / sizeof(sinks[0]); i++) {
        ASSERT_EQm(sinks[i], FIRC_RESOLVER_ADDR_SINK, parse(sinks[i], &a));
    }
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("126.255.255.255", &a));
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("128.0.0.1", &a));
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("0.0.0.1", &a));
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("::2", &a));
    ASSERT_EQ(FIRC_RESOLVER_ADDR_MAPPED, parse("::ffff:127.0.0.1", &a));
    ASSERT_EQ(FIRC_RESOLVER_ADDR_MAPPED, parse("::ffff:9.9.9.9", &a));
    PASS();
}

/* Catches: answers and validation disagreeing on sinks, or a v4-mapped AAAA not read as v4. */
TEST the_sink_test_takes_a_bare_address(void)
{
    firc_ip_t ip = {.len = 4};
    ASSERT(firc_resolver_ip_is_sink(&ip));
    ip.b[0] = 127; ip.b[3] = 9;
    ASSERT(firc_resolver_ip_is_sink(&ip));
    ip.b[0] = 9;
    ASSERT_FALSE(firc_resolver_ip_is_sink(&ip));
    firc_ip_t v6 = {.len = 16};
    ASSERT(firc_resolver_ip_is_sink(&v6));
    v6.b[15] = 1;
    ASSERT(firc_resolver_ip_is_sink(&v6));
    v6.b[15] = 2;
    ASSERT_FALSE(firc_resolver_ip_is_sink(&v6));
    firc_ip_t mapped = {.len = 16};
    mapped.b[10] = 0xff;
    mapped.b[11] = 0xff;
    ASSERT(firc_resolver_ip_is_sink(&mapped));
    mapped.b[12] = 127;
    mapped.b[15] = 9;
    ASSERT(firc_resolver_ip_is_sink(&mapped));
    mapped.b[12] = 9;
    ASSERT_FALSE(firc_resolver_ip_is_sink(&mapped));
    PASS();
}

/* Catches: port 53 written, a v6 port without brackets, or a small buffer overrun. */
TEST an_address_formats_back_to_what_parses(void)
{
    const char *in[] = {"9.9.9.9", "9.9.9.9:5353", "2620:fe::fe", "[2620:fe::fe]:853"};
    for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); i++) {
        firc_resolver_addr_t a;
        ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse(in[i], &a));
        char buf[FIRC_RESOLVER_ADDR_STRLEN];
        ASSERT(firc_resolver_addr_format(&a, buf, sizeof(buf)) > 0);
        ASSERT_STR_EQ(in[i], buf);
    }
    firc_resolver_addr_t a;
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("[2620:fe::fe]", &a));
    char buf[FIRC_RESOLVER_ADDR_STRLEN];
    ASSERT(firc_resolver_addr_format(&a, buf, sizeof(buf)) > 0);
    ASSERT_STR_EQ("2620:fe::fe", buf);
    char tiny[4];
    ASSERT_EQ((size_t)0, firc_resolver_addr_format(&a, tiny, sizeof(tiny)));
    PASS();
}

/* Catches: the port left in host order, or the wrong family. */
TEST an_address_becomes_a_sockaddr(void)
{
    firc_resolver_addr_t a;
    struct sockaddr_storage ss;
    socklen_t len = 0;
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("1.0.0.1:5353", &a));
    firc_resolver_addr_sockaddr(&a, &ss, &len);
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)&ss;
    ASSERT_EQ(AF_INET, s4->sin_family);
    ASSERT_EQ((socklen_t)sizeof(struct sockaddr_in), len);
    ASSERT_EQ(htons(5353), s4->sin_port);
    ASSERT_EQ(htonl(0x01000001u), s4->sin_addr.s_addr);
    ASSERT_EQ(FIRC_RESOLVER_ADDR_OK, parse("2620:fe::fe", &a));
    firc_resolver_addr_sockaddr(&a, &ss, &len);
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)&ss;
    ASSERT_EQ(AF_INET6, s6->sin6_family);
    ASSERT_EQ((socklen_t)sizeof(struct sockaddr_in6), len);
    ASSERT_EQ(htons(53), s6->sin6_port);
    ASSERT_EQ(0xfe, s6->sin6_addr.s6_addr[15]);
    PASS();
}

static char g_ula[192];

/* A pool from the shipped defaults (198.18.0.0/15) with fd00:1234::/48 as its v6 half. */
static firc_fakeip_t *pool_for_test(void)
{
    const char *dir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    snprintf(g_ula, sizeof(g_ula), "%s/resolver_addr_ula", dir);
    unlink(g_ula);
    firc_config_t cfg;
    if (firc_config_init_defaults(&cfg) != FIRC_OK) { return NULL; }
    firc_fakeip_t *f = NULL;
    firc_fakeip_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    if (firc_strset(&cfg.app.fakeip.v6.pool, "fd00:1234::/48") == FIRC_OK &&
        firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc) == FIRC_OK) {
        (void)firc_fakeip_new(&pc, &f);
    }
    firc_config_clear(&cfg);
    return f;
}

/* Catches: a resolve server inside the pool accepted, checked against the wrong family, or off the edge. */
TEST a_server_inside_the_pool_is_refused_at_startup(void)
{
    firc_fakeip_t *pool = pool_for_test();
    ASSERT(pool != NULL);
    ASSERT(firc_resolve_server_in_pool("198.18.0.1", pool));
    ASSERT(firc_resolve_server_in_pool("198.19.255.255:5353", pool));
    ASSERT_FALSE(firc_resolve_server_in_pool("198.20.0.0", pool));
    ASSERT_FALSE(firc_resolve_server_in_pool("198.17.255.255", pool));
    ASSERT(firc_resolve_server_in_pool("fd00:1234::53", pool));
    ASSERT(firc_resolve_server_in_pool("[fd00:1234::ffff:1]:53", pool));
    ASSERT_FALSE(firc_resolve_server_in_pool("[fd00:1234:ffff::1]:53", pool));
    ASSERT_FALSE(firc_resolve_server_in_pool("fd00:1235::1", pool));
    ASSERT_FALSE(firc_resolve_server_in_pool("", pool));
    ASSERT_FALSE(firc_resolve_server_in_pool(NULL, pool));

    firc_group_t *g[3] = {firc_group_new(), firc_group_new(), firc_group_new()};
    ASSERT(g[0] && g[1] && g[2]);
    ASSERT_EQ(FIRC_OK, firc_strset(&g[1]->resolve.server, "9.9.9.9"));
    ASSERT_EQ(FIRC_OK, firc_strset(&g[2]->resolve.server, "198.18.7.7"));
    ASSERT_EQ(g[2], firc_resolve_groups_in_pool(g, 3, pool));
    ASSERT_EQ(NULL, firc_resolve_groups_in_pool(g, 2, pool));
    for (int i = 0; i < 3; i++) { firc_group_free(g[i]); }
    firc_fakeip_free(pool);
    unlink(g_ula);
    PASS();
}

/* Catches: firc_group_new not defaulting to the tunnel. */
TEST a_new_group_resolves_through_its_tunnel(void)
{
    firc_group_t *g = firc_group_new();
    ASSERT(g != NULL);
    ASSERT(g->resolve.tunnel);
    ASSERT_EQ(NULL, g->resolve.server);
    firc_group_free(g);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(each_shape_parses);
    RUN_TEST(what_is_not_an_address_is_refused);
    RUN_TEST(sinks_are_refused_and_their_neighbours_are_not);
    RUN_TEST(the_sink_test_takes_a_bare_address);
    RUN_TEST(an_address_formats_back_to_what_parses);
    RUN_TEST(an_address_becomes_a_sockaddr);
    RUN_TEST(a_server_inside_the_pool_is_refused_at_startup);
    RUN_TEST(a_new_group_resolves_through_its_tunnel);
    GREATEST_MAIN_END();
}
