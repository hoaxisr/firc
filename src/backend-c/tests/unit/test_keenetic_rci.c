#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "firc/keenetic_rci.h"

static const char *const LIST_JSON =
    "{\"Wireguard0\":{\"description\":\"Home VPN\"},"
    "\"Wireguard1\":{\"interface-name\":\"Backup VPN\"}}";

static const char *const NAMES_JSON =
    "[{\"show\":{\"interface\":{\"system-name\":\"nwg0\"}}},"
    "{\"show\":{\"interface\":{\"system-name\":\"nwg1\"}}}]";

static const firc_kn_iface_meta_t *find_meta(const firc_kn_iface_meta_t *metas, size_t n,
                                           const char *id)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(metas[i].id, id) == 0) {
            return &metas[i];
        }
    }
    return NULL;
}

TEST parse_interface_list_reads_both_label_fields(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(LIST_JSON, &metas, &n));
    ASSERT_EQ(2, n);

    const firc_kn_iface_meta_t *wg0 = find_meta(metas, n, "Wireguard0");
    const firc_kn_iface_meta_t *wg1 = find_meta(metas, n, "Wireguard1");
    ASSERT(wg0 != NULL);
    ASSERT(wg1 != NULL);
    ASSERT_STR_EQ("Home VPN", wg0->description);
    ASSERT_STR_EQ("", wg0->interface_name);
    ASSERT_STR_EQ("", wg1->description);
    ASSERT_STR_EQ("Backup VPN", wg1->interface_name);

    free(metas);
    PASS();
}

TEST parse_interface_list_skips_non_object_entries(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(
                         "{\"Good\":{\"description\":\"ok\"},\"Bad\":\"nope\",\"Also\":123}",
                         &metas, &n));
    ASSERT_EQ(1, n);
    ASSERT_STR_EQ("Good", metas[0].id);

    free(metas);
    PASS();
}

TEST parse_interface_list_rejects_malformed(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_parse_interface_list("{oops", &metas, &n));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_parse_interface_list("[\"an array\"]", &metas, &n));
    PASS();
}

TEST build_system_name_request_is_one_batch(void)
{
    firc_kn_iface_meta_t metas[2] = {0};
    snprintf(metas[0].id, sizeof(metas[0].id), "%s", "Wireguard0");
    snprintf(metas[1].id, sizeof(metas[1].id), "%s", "Wireguard1");

    char *body = firc_kn_build_system_name_request(metas, 2);
    ASSERT(body != NULL);
    ASSERT_STR_EQ(
        "[{\"show\":{\"interface\":{\"name\":\"Wireguard0\",\"details\":\"yes\","
        "\"system-name\":\"yes\"}}},"
        "{\"show\":{\"interface\":{\"name\":\"Wireguard1\",\"details\":\"yes\","
        "\"system-name\":\"yes\"}}}]",
        body);

    free(body);
    PASS();
}

/* Catches: RCI responses not matched to their requests by position. */
TEST parse_system_names_matches_positionally(void)
{
    firc_kn_iface_meta_t metas[2] = {0};
    snprintf(metas[0].id, sizeof(metas[0].id), "%s", "Wireguard0");
    snprintf(metas[1].id, sizeof(metas[1].id), "%s", "Wireguard1");

    ASSERT_EQ(FIRC_OK, firc_kn_parse_system_names(NAMES_JSON, metas, 2));
    ASSERT_STR_EQ("nwg0", metas[0].system_name);
    ASSERT_STR_EQ("nwg1", metas[1].system_name);
    PASS();
}

TEST parse_system_names_tolerates_length_mismatch(void)
{
    firc_kn_iface_meta_t few[1] = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_parse_system_names(NAMES_JSON, few, 1));
    ASSERT_STR_EQ("nwg0", few[0].system_name);

    firc_kn_iface_meta_t many[3] = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_parse_system_names(NAMES_JSON, many, 3));
    ASSERT_STR_EQ("nwg0", many[0].system_name);
    ASSERT_STR_EQ("nwg1", many[1].system_name);
    ASSERT_STR_EQ("", many[2].system_name);
    PASS();
}

TEST aliases_prefer_description_then_interface_name(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(LIST_JSON, &metas, &n));
    ASSERT_EQ(2, n);

    for (size_t i = 0; i < n; i++) {
        if (strcmp(metas[i].id, "Wireguard0") == 0) {
            snprintf(metas[i].system_name, sizeof(metas[i].system_name), "%s", "nwg0");
        } else {
            snprintf(metas[i].system_name, sizeof(metas[i].system_name), "%s", "nwg1");
        }
    }

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, n, &aliases));
    ASSERT_EQ(2, aliases.n);
    ASSERT_STR_EQ("Home VPN", firc_kn_aliases_lookup(&aliases, "nwg0"));
    ASSERT_STR_EQ("Backup VPN", firc_kn_aliases_lookup(&aliases, "nwg1"));
    ASSERT(firc_kn_aliases_lookup(&aliases, "br0") == NULL);

    firc_kn_aliases_free(&aliases);
    free(metas);
    PASS();
}

TEST aliases_skip_empty_and_redundant(void)
{
    firc_kn_iface_meta_t metas[4] = {0};

    snprintf(metas[0].description, sizeof(metas[0].description), "%s", "Orphan");

    snprintf(metas[1].system_name, sizeof(metas[1].system_name), "%s", "eth0");

    snprintf(metas[2].description, sizeof(metas[2].description), "%s", "eth1");
    snprintf(metas[2].system_name, sizeof(metas[2].system_name), "%s", "eth1");

    snprintf(metas[3].description, sizeof(metas[3].description), "%s", "   ");
    snprintf(metas[3].system_name, sizeof(metas[3].system_name), "%s", "eth2");

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, 4, &aliases));
    ASSERT_EQ(0, aliases.n);
    ASSERT(firc_kn_aliases_lookup(&aliases, "eth0") == NULL);

    firc_kn_aliases_free(&aliases);
    PASS();
}

TEST labels_and_system_names_are_trimmed(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list(
                         "{\"Wg\":{\"description\":\"  Padded VPN \\t\"}}", &metas, &n));
    ASSERT_EQ(1, n);
    ASSERT_STR_EQ("Padded VPN", metas[0].description);

    ASSERT_EQ(FIRC_OK, firc_kn_parse_system_names(
                         "[{\"show\":{\"interface\":{\"system-name\":\"  nwg0  \"}}}]", metas, 1));
    ASSERT_STR_EQ("nwg0", metas[0].system_name);

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, 1, &aliases));
    ASSERT_EQ(1, aliases.n);
    ASSERT_STR_EQ("Padded VPN", firc_kn_aliases_lookup(&aliases, "nwg0"));

    firc_kn_aliases_free(&aliases);
    free(metas);
    PASS();
}

TEST empty_list_yields_no_aliases(void)
{
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_parse_interface_list("{}", &metas, &n));
    ASSERT_EQ(0, n);

    firc_kn_aliases_t aliases = {0};
    ASSERT_EQ(FIRC_OK, firc_kn_build_aliases(metas, n, &aliases));
    ASSERT_EQ(0, aliases.n);
    ASSERT(aliases.items == NULL);

    firc_kn_aliases_free(&aliases);
    free(metas);
    PASS();
}

/* Catches: the default lookup misbehaving when RCI does not answer. */
TEST platform_default_is_empty_and_safe(void)
{
    firc_kn_aliases_t aliases = {0};
    firc_err_t err = firc_kn_get_iface_aliases(&aliases);
#ifdef FIRC_ENTWARE_KN
    (void)err;
#else
    ASSERT_EQ(FIRC_OK, err);
#endif
    ASSERT_EQ(0, aliases.n);
    ASSERT(aliases.items == NULL);
    ASSERT(firc_kn_aliases_lookup(&aliases, "br0") == NULL);

    firc_kn_aliases_free(&aliases);
    firc_kn_aliases_free(&aliases);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(parse_interface_list_reads_both_label_fields);
    RUN_TEST(parse_interface_list_skips_non_object_entries);
    RUN_TEST(parse_interface_list_rejects_malformed);
    RUN_TEST(build_system_name_request_is_one_batch);
    RUN_TEST(parse_system_names_matches_positionally);
    RUN_TEST(parse_system_names_tolerates_length_mismatch);
    RUN_TEST(aliases_prefer_description_then_interface_name);
    RUN_TEST(aliases_skip_empty_and_redundant);
    RUN_TEST(labels_and_system_names_are_trimmed);
    RUN_TEST(empty_list_yields_no_aliases);
    RUN_TEST(platform_default_is_empty_and_safe);
    GREATEST_MAIN_END();
}
