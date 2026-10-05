#include "greatest.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "firc/keenetic_rci.h"
#include "firc/keenetic_resolvers.h"

static firc_kn_id_map_t bench_ids(void)
{
    static firc_kn_id_entry_t items[] = {
        {.id = "Wireguard0", .system_name = "nwg0"},
        {.id = "Wireguard1", .system_name = "nwg1"},
        {.id = "GigabitEthernet0/Vlan2", .system_name = "eth2.2"},
    };
    firc_kn_id_map_t m = {.items = items, .n = 3};
    return m;
}

static const firc_kn_iface_resolvers_t *find(const firc_kn_resolver_map_t *m, const char *iface)
{
    for (size_t i = 0; i < m->n; i++) {
        if (strcmp(m->items[i].iface, iface) == 0) { return &m->items[i]; }
    }
    return NULL;
}

/* Catches: an interface id not mapped, server order lost, or servers filed under another interface. */
TEST the_bench_list_maps_to_kernel_names(void)
{
    const char *json =
        "[{\"address\":\"9.9.9.9\",\"domain\":\"\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"1.0.0.1\",\"domain\":\"\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"1.1.1.1\",\"domain\":\"\",\"interface\":\"Wireguard1\"},"
        " {\"address\":\"1.0.0.1\",\"domain\":\"\",\"interface\":\"Wireguard1\"}]";
    firc_kn_id_map_t ids = bench_ids();
    firc_kn_resolver_map_t m = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_resolver_map_parse(json, &ids, &m));
    ASSERT_EQ((size_t)2, m.n);
    const firc_kn_iface_resolvers_t *w0 = find(&m, "nwg0");
    const firc_kn_iface_resolvers_t *w1 = find(&m, "nwg1");
    ASSERT(w0 != NULL && w1 != NULL);
    ASSERT_EQ((size_t)2, w0->n);
    ASSERT_EQ(9, w0->servers[0].ip.b[0]);
    ASSERT_EQ(1, w0->servers[1].ip.b[0]);
    ASSERT_EQ(0, w0->servers[1].ip.b[1]);
    ASSERT_EQ(53, w0->servers[0].port);
    ASSERT_EQ((size_t)2, w1->n);
    ASSERT_EQ(1, w1->servers[0].ip.b[3]);
    ASSERT_EQ((size_t)0, m.dropped);
    firc_kn_resolver_map_free(&m);
    PASS();
}

/* Catches: a split-DNS or global entry taken for an interface resolver. */
TEST split_dns_and_global_entries_are_not_interface_resolvers(void)
{
    const char *json =
        "[{\"address\":\"10.8.0.1\",\"domain\":\"corp.example\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"109.194.176.3\",\"domain\":\"\"},"
        " {\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"}]";
    firc_kn_id_map_t ids = bench_ids();
    firc_kn_resolver_map_t m = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_resolver_map_parse(json, &ids, &m));
    ASSERT_EQ((size_t)1, m.n);
    ASSERT_EQ((size_t)1, m.items[0].n);
    ASSERT_EQ(9, m.items[0].servers[0].ip.b[0]);
    firc_kn_resolver_map_free(&m);
    PASS();
}

/* Catches: an unknown interface id mapped to some interface, or failing the whole list. */
TEST an_unknown_interface_id_is_dropped(void)
{
    const char *json =
        "[{\"address\":\"8.8.8.8\",\"domain\":\"\",\"interface\":\"Wireguard2\"},"
        " {\"address\":\"9.9.9.9\",\"domain\":\"\",\"interface\":\"Wireguard0\"}]";
    firc_kn_id_map_t ids = bench_ids();
    firc_kn_resolver_map_t m = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_resolver_map_parse(json, &ids, &m));
    ASSERT_EQ((size_t)1, m.n);
    ASSERT_STR_EQ("nwg0", m.items[0].iface);
    ASSERT_EQ((size_t)1, m.dropped);
    firc_kn_resolver_map_free(&m);
    PASS();
}

TEST a_malformed_entry_is_dropped_not_fatal(void)
{
    const char *json =
        "[{\"address\":\"9.9.9.9\",\"port\":5353,\"interface\":\"Wireguard0\"},"
        " {\"address\":\"1.1.1.1\",\"port\":\"53\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"1.1.1.2\",\"port\":0,\"interface\":\"Wireguard0\"},"
        " {\"address\":\"dns.google\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"127.0.0.1\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"[2620:fe::fe]\",\"interface\":\"Wireguard1\"},"
        " {\"address\":\"2620:fe::9\",\"interface\":\"Wireguard1\"},"
        " 42,"
        " {\"address\":5,\"interface\":\"Wireguard1\"}]";
    firc_kn_id_map_t ids = bench_ids();
    firc_kn_resolver_map_t m = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_resolver_map_parse(json, &ids, &m));
    const firc_kn_iface_resolvers_t *w0 = find(&m, "nwg0");
    const firc_kn_iface_resolvers_t *w1 = find(&m, "nwg1");
    ASSERT(w0 != NULL && w1 != NULL);
    ASSERT_EQ((size_t)1, w0->n);
    ASSERT_EQ(5353, w0->servers[0].port);
    ASSERT_EQ((size_t)1, w1->n);
    ASSERT_EQ(16, w1->servers[0].ip.len);
    ASSERT_EQ(0x09, w1->servers[0].ip.b[15]);
    ASSERT_EQ((size_t)7, m.dropped);
    firc_kn_resolver_map_free(&m);
    PASS();
}

/* Catches: a duplicate kept twice, or the cap not enforced. */
TEST duplicates_collapse_and_the_cap_holds(void)
{
    const char *json =
        "[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"9.9.9.10\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"9.9.9.11\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"9.9.9.12\",\"interface\":\"Wireguard0\"},"
        " {\"address\":\"9.9.9.13\",\"interface\":\"Wireguard0\"}]";
    firc_kn_id_map_t ids = bench_ids();
    firc_kn_resolver_map_t m = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_resolver_map_parse(json, &ids, &m));
    ASSERT_EQ((size_t)1, m.n);
    ASSERT_EQ((size_t)FIRC_RESOLVE_MAX_SERVERS, m.items[0].n);
    ASSERT_EQ(12, m.items[0].servers[3].ip.b[3]);
    ASSERT_EQ((size_t)1, m.dropped);
    firc_kn_resolver_map_free(&m);
    PASS();
}

/* Catches: a body that is not a list taken as no resolvers. */
TEST a_body_that_is_not_a_list_is_an_error(void)
{
    firc_kn_id_map_t ids = bench_ids();
    firc_kn_resolver_map_t m = {0};
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_resolver_map_parse("{\"address\":\"9.9.9.9\"}", &ids, &m));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_resolver_map_parse("not json", &ids, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_resolver_map_parse("[]", &ids, &m));
    ASSERT_EQ((size_t)0, m.n);
    firc_kn_resolver_map_free(&m);
    PASS();
}

/* Catches: an interface without a kernel name mapped to "". */
TEST the_id_map_is_built_from_the_interface_metas(void)
{
    firc_kn_iface_meta_t metas[3] = {0};
    strcpy(metas[0].id, "Wireguard0");
    strcpy(metas[0].system_name, "nwg0");
    strcpy(metas[1].id, "Wireguard9");
    strcpy(metas[2].id, "GigabitEthernet0/Vlan2");
    strcpy(metas[2].system_name, "eth2.2");
    firc_kn_id_map_t m = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_id_map(metas, 3, &m));
    ASSERT_EQ((size_t)2, m.n);
    ASSERT_STR_EQ("nwg0", firc_kn_id_map_lookup(&m, "Wireguard0"));
    ASSERT_STR_EQ("eth2.2", firc_kn_id_map_lookup(&m, "GigabitEthernet0/Vlan2"));
    ASSERT_EQ(NULL, firc_kn_id_map_lookup(&m, "Wireguard9"));
    ASSERT_EQ(NULL, firc_kn_id_map_lookup(&m, "nwg0"));
    firc_kn_id_map_free(&m);
    ASSERT_EQ((size_t)0, m.n);
    PASS();
}

static atomic_int g_changes;
static void count_change(void *ud)
{
    (void)ud;
    atomic_fetch_add(&g_changes, 1);
}

static firc_kn_resolver_map_t parsed(const char *json)
{
    firc_kn_id_map_t ids = bench_ids();
    firc_kn_resolver_map_t m = {0};
    (void)firc_kn_resolver_map_parse(json, &ids, &m);
    return m;
}

/* Catches: an equal swap reported as a change, a real one missed, or the map's memory handed out. */
TEST a_swap_reports_only_a_real_change_and_reads_copy(void)
{
    atomic_store(&g_changes, 0);
    firc_kn_resolvers_t *r = firc_kn_resolvers_start(NULL, 30, count_change, NULL);
    ASSERT(r != NULL);
    firc_resolver_addr_t out[FIRC_RESOLVE_MAX_SERVERS];
    ASSERT_EQ((size_t)0, firc_kn_resolvers_for(r, "nwg0", out, FIRC_RESOLVE_MAX_SERVERS));

    const char *a = "[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"}]";
    firc_kn_resolver_map_t m1 = parsed(a);
    firc_kn_resolvers_swap(r, &m1);
    ASSERT_EQ(1, atomic_load(&g_changes));
    firc_kn_resolver_map_t m2 = parsed(a);
    firc_kn_resolvers_swap(r, &m2);
    ASSERT_EQ(1, atomic_load(&g_changes));
    firc_kn_resolver_map_t m3 = parsed("[{\"address\":\"1.0.0.1\",\"interface\":\"Wireguard0\"}]");
    firc_kn_resolvers_swap(r, &m3);
    ASSERT_EQ(2, atomic_load(&g_changes));

    ASSERT_EQ((size_t)1, firc_kn_resolvers_for(r, "nwg0", out, FIRC_RESOLVE_MAX_SERVERS));
    ASSERT_EQ(1, out[0].ip.b[0]);
    ASSERT_EQ((size_t)0, firc_kn_resolvers_for(r, "nwg1", out, FIRC_RESOLVE_MAX_SERVERS));
    firc_kn_iface_resolvers_t all[4];
    ASSERT_EQ((size_t)1, firc_kn_resolvers_list(r, all, 4));
    ASSERT_STR_EQ("nwg0", all[0].iface);
    ASSERT_EQ((size_t)0, firc_kn_resolvers_for(NULL, "nwg0", out, FIRC_RESOLVE_MAX_SERVERS));
    firc_kn_resolvers_stop(r);
    PASS();
}

static int g_id_fetches;
static firc_err_t counting_ids(void *ud, firc_kn_id_map_t *out)
{
    const char *extra = ud;
    g_id_fetches++;
    size_t n = extra != NULL ? 3 : 2;
    out->items = calloc(n, sizeof(*out->items));
    if (out->items == NULL) { return FIRC_ERR_NOMEM; }
    strcpy(out->items[0].id, "Wireguard0");
    strcpy(out->items[0].system_name, "nwg0");
    strcpy(out->items[1].id, "Wireguard1");
    strcpy(out->items[1].system_name, "nwg1");
    if (extra != NULL) {
        strcpy(out->items[2].id, extra);
        strcpy(out->items[2].system_name, "nwg2");
    }
    out->n = n;
    return FIRC_OK;
}

/* Catches: the id map fetched on every refresh, or never for a new id. */
TEST the_id_map_is_fetched_only_when_an_id_is_new(void)
{
    firc_kn_resolvers_t *r = firc_kn_resolvers_start(NULL, 30, NULL, NULL);
    ASSERT(r != NULL);
    g_id_fetches = 0;
    const char *two = "[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"}]";
    ASSERT_EQ(FIRC_OK, firc_kn_resolvers_refresh_from(r, two, counting_ids, NULL));
    ASSERT_EQ(1, g_id_fetches);
    ASSERT_EQ(FIRC_OK, firc_kn_resolvers_refresh_from(r, two, counting_ids, NULL));
    ASSERT_EQ(1, g_id_fetches);
    const char *three = "[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"},"
                        " {\"address\":\"8.8.8.8\",\"interface\":\"Wireguard2\"}]";
    ASSERT_EQ(FIRC_OK, firc_kn_resolvers_refresh_from(r, three, counting_ids, "Wireguard2"));
    ASSERT_EQ(2, g_id_fetches);
    firc_resolver_addr_t out[FIRC_RESOLVE_MAX_SERVERS];
    ASSERT_EQ((size_t)1, firc_kn_resolvers_for(r, "nwg2", out, FIRC_RESOLVE_MAX_SERVERS));
    ASSERT_EQ(FIRC_OK, firc_kn_resolvers_refresh_from(r, three, counting_ids, "Wireguard2"));
    ASSERT_EQ(2, g_id_fetches);
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_resolvers_refresh_from(r, "{}", counting_ids, NULL));
    ASSERT_EQ(2, g_id_fetches);
    ASSERT_EQ((size_t)1, firc_kn_resolvers_for(r, "nwg2", out, FIRC_RESOLVE_MAX_SERVERS));
    ASSERT_EQ(8, out[0].ip.b[0]);
    firc_kn_resolvers_stop(r);
    PASS();
}

/* Catches: an id map fetched for a body that is not a list. */
TEST an_id_fetch_is_not_attempted_for_a_body_that_is_not_a_list(void)
{
    firc_kn_resolvers_t *r = firc_kn_resolvers_start(NULL, 30, NULL, NULL);
    ASSERT(r != NULL);
    g_id_fetches = 0;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_resolvers_refresh_from(r, "{}", counting_ids, NULL));
    ASSERT_EQ(0, g_id_fetches);
    firc_kn_resolvers_stop(r);
    PASS();
}

static firc_err_t failing_ids(void *ud, firc_kn_id_map_t *out)
{
    (void)ud;
    (void)out;
    return FIRC_ERR_UPSTREAM;
}

TEST a_failed_id_fetch_keeps_the_last_good_list(void)
{
    firc_kn_resolvers_t *r = firc_kn_resolvers_start(NULL, 30, NULL, NULL);
    ASSERT(r != NULL);
    const char *one = "[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"}]";
    ASSERT_EQ(FIRC_OK, firc_kn_resolvers_refresh_from(r, one, counting_ids, NULL));
    firc_resolver_addr_t out[FIRC_RESOLVE_MAX_SERVERS];
    ASSERT_EQ((size_t)1, firc_kn_resolvers_for(r, "nwg0", out, FIRC_RESOLVE_MAX_SERVERS));
    ASSERT_EQ(9, out[0].ip.b[0]);

    const char *unknown_id = "[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"},"
                             " {\"address\":\"8.8.8.8\",\"interface\":\"Wireguard2\"}]";
    ASSERT_EQ(FIRC_ERR_UPSTREAM, firc_kn_resolvers_refresh_from(r, unknown_id, failing_ids, NULL));

    ASSERT_EQ((size_t)1, firc_kn_resolvers_for(r, "nwg0", out, FIRC_RESOLVE_MAX_SERVERS));
    ASSERT_EQ(9, out[0].ip.b[0]);
    ASSERT_EQ((size_t)0, firc_kn_resolvers_for(r, "nwg2", out, FIRC_RESOLVE_MAX_SERVERS));
    firc_kn_resolvers_stop(r);
    PASS();
}

/* Catches: a reorder with no content change reported as a change. */
TEST swap_ignores_the_firmwares_own_order(void)
{
    atomic_store(&g_changes, 0);
    firc_kn_resolvers_t *r = firc_kn_resolvers_start(NULL, 30, count_change, NULL);
    ASSERT(r != NULL);
    firc_kn_resolver_map_t m1 = parsed("[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"},"
                                       " {\"address\":\"1.1.1.1\",\"interface\":\"Wireguard1\"}]");
    firc_kn_resolvers_swap(r, &m1);
    ASSERT_EQ(1, atomic_load(&g_changes));
    firc_kn_resolver_map_t m2 = parsed("[{\"address\":\"1.1.1.1\",\"interface\":\"Wireguard1\"},"
                                       " {\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"}]");
    firc_kn_resolvers_swap(r, &m2);
    ASSERT_EQ(1, atomic_load(&g_changes));
    firc_kn_resolvers_stop(r);
    PASS();
}

/* Catches: the same server under another interface name not reported as a change. */
TEST swap_reports_a_change_when_only_the_iface_name_differs(void)
{
    atomic_store(&g_changes, 0);
    firc_kn_resolvers_t *r = firc_kn_resolvers_start(NULL, 30, count_change, NULL);
    ASSERT(r != NULL);
    firc_kn_resolver_map_t m1 = parsed("[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard0\"}]");
    firc_kn_resolvers_swap(r, &m1);
    ASSERT_EQ(1, atomic_load(&g_changes));
    firc_kn_resolver_map_t m2 = parsed("[{\"address\":\"9.9.9.9\",\"interface\":\"Wireguard1\"}]");
    firc_kn_resolvers_swap(r, &m2);
    ASSERT_EQ(2, atomic_load(&g_changes));
    firc_kn_resolvers_stop(r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_id_map_is_fetched_only_when_an_id_is_new);
    RUN_TEST(an_id_fetch_is_not_attempted_for_a_body_that_is_not_a_list);
    RUN_TEST(a_failed_id_fetch_keeps_the_last_good_list);
    RUN_TEST(swap_ignores_the_firmwares_own_order);
    RUN_TEST(swap_reports_a_change_when_only_the_iface_name_differs);
    RUN_TEST(the_bench_list_maps_to_kernel_names);
    RUN_TEST(split_dns_and_global_entries_are_not_interface_resolvers);
    RUN_TEST(an_unknown_interface_id_is_dropped);
    RUN_TEST(a_malformed_entry_is_dropped_not_fatal);
    RUN_TEST(duplicates_collapse_and_the_cap_holds);
    RUN_TEST(a_body_that_is_not_a_list_is_an_error);
    RUN_TEST(the_id_map_is_built_from_the_interface_metas);
    RUN_TEST(a_swap_reports_only_a_real_change_and_reads_copy);
    GREATEST_MAIN_END();
}
