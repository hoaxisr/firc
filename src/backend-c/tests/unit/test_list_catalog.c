#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

#include "firc/list_catalog.h"

#define SAGER "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs"
#define HOAX "https://raw.githubusercontent.com/hoaxisr/rulesets/master/srs/{}.srs"

static firc_err_t parse(const char *body, cJSON **out, char *why, size_t cap) {
    return firc_list_catalog_parse(body, strlen(body), NULL, out, why, cap);
}

static void refuses_as(const char *provider, const char *body, const char *needle) {
    cJSON *out = NULL;
    char why[160] = "";
    firc_err_t err = firc_list_catalog_parse(body, strlen(body), provider, &out, why, sizeof why);
    if (err != FIRC_ERR_INVAL || out != NULL || strcmp(why, needle) != 0) {
        fprintf(stderr, "body %s: err %d why \"%s\" wanted \"%s\"\n", body, (int)err, why, needle);
        abort();
    }
}

static void refuses(const char *body, const char *needle) { refuses_as(NULL, body, needle); }

/* Catches: names or urls altered on the way, unknown keys kept, or a valid index refused. */
TEST the_spec_example_parses_and_round_trips(void) {
    const char *body = "{\"generated\":\"2026-10-22T19:00:00Z\",\"extra\":1,\"sources\":["
                       "{\"id\":\"sagernet\",\"url\":\"" SAGER "\",\"junk\":true,"
                       "\"names\":[\"youtube\",\"youtube@cn\",\"category-ads-all\"]},"
                       "{\"id\":\"hoaxisr\",\"url\":\"" HOAX "\",\"names\":[\"claude\",\"discord-full\"]}]}";
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, parse(body, &out, why, sizeof why));
    ASSERT(out != NULL);
    ASSERT_STR_EQ("2026-10-22T19:00:00Z", cJSON_GetObjectItemCaseSensitive(out, "generated")->valuestring);
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "extra"));
    cJSON *src = cJSON_GetObjectItemCaseSensitive(out, "sources");
    ASSERT_EQ(2, cJSON_GetArraySize(src));
    cJSON *s0 = cJSON_GetArrayItem(src, 0);
    ASSERT_STR_EQ("sagernet", cJSON_GetObjectItemCaseSensitive(s0, "id")->valuestring);
    ASSERT_STR_EQ(SAGER, cJSON_GetObjectItemCaseSensitive(s0, "url")->valuestring);
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(s0, "junk"));
    cJSON *n0 = cJSON_GetObjectItemCaseSensitive(s0, "names");
    ASSERT_EQ(3, cJSON_GetArraySize(n0));
    ASSERT_STR_EQ("youtube@cn", cJSON_GetArrayItem(n0, 1)->valuestring);
    cJSON *s1 = cJSON_GetArrayItem(src, 1);
    ASSERT_STR_EQ("hoaxisr", cJSON_GetObjectItemCaseSensitive(s1, "id")->valuestring);
    ASSERT_STR_EQ("discord-full",
                  cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(s1, "names"), 1)->valuestring);
    cJSON_Delete(out);
    PASS();
}

/* Catches: an index with nothing in it refused. */
TEST an_empty_sources_array_parses(void) {
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, parse("{\"generated\":\"x\",\"sources\":[]}", &out, why, sizeof why));
    ASSERT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "sources")));
    cJSON_Delete(out);
    PASS();
}

/* Catches: a source id outside [a-z0-9-]{1,32} accepted. */
TEST a_bad_id_is_refused(void) {
    refuses("{\"sources\":[{\"id\":\"Bad_ID\",\"url\":\"" HOAX "\",\"names\":[]}]}", "source 1 has no valid id");
    refuses("{\"sources\":[{\"id\":\"\",\"url\":\"" HOAX "\",\"names\":[]}]}", "source 1 has no valid id");
    refuses("{\"sources\":[{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"url\":\"" HOAX "\",\"names\":[]}]}",
            "source 1 has no valid id");
    refuses("{\"sources\":[{\"id\":5,\"url\":\"" HOAX "\",\"names\":[]}]}", "source 1 has no valid id");
    PASS();
}

/* Catches: an insecure, foreign or off-host url accepted. */
TEST a_url_off_the_allowed_host_is_refused(void) {
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"http://raw.githubusercontent.com/x/{}\",\"names\":[]}]}",
            "source 1 has no url on raw.githubusercontent.com");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"https://example.com/{}.srs\",\"names\":[]}]}",
            "source 1 has no url on raw.githubusercontent.com");
    PASS();
}

/* Catches: a url with no placeholder or two of them accepted; the reason must name the source. */
TEST a_url_without_exactly_one_placeholder_is_refused(void) {
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[]},"
            "{\"id\":\"b\",\"url\":\"https://raw.githubusercontent.com/x/y.srs\",\"names\":[]}]}",
            "source 2 has no {} in its url");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"https://raw.githubusercontent.com/x/{}/{}.srs\","
            "\"names\":[]}]}",
            "source 1 has more than one {} in its url");
    PASS();
}

/* Catches: a name outside [A-Za-z0-9._@!-]{1,128} accepted, or the reason losing its position. */
TEST a_bad_name_is_refused_by_position(void) {
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[\"ok\",\"a b\"]}]}",
            "name 2 of a is not a rule-set name");
    char longname[140];
    memset(longname, 'a', 129);
    longname[129] = '\0';
    char body[512];
    snprintf(body, sizeof body, "{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[\"%s\"]}]}", longname);
    refuses(body, "name 1 of a is not a rule-set name");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[\"\"]}]}",
            "name 1 of a is not a rule-set name");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[5]}]}",
            "name 1 of a is not a rule-set name");
    PASS();
}

/* Catches: a url that is not a string, or names that are not an array, passing or sharing a reason. */
TEST a_source_missing_its_url_or_names_is_refused(void) {
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":7,\"names\":[]}]}", "source 1 has no url");
    refuses("{\"sources\":[{\"id\":\"a\",\"names\":[]}]}", "source 1 has no url");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":\"x\"}]}",
            "source 1 has no names array");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\"}]}", "source 1 has no names array");
    PASS();
}

/* Catches: a name of exactly 128 characters refused. */
TEST a_name_of_128_characters_is_accepted(void) {
    char name[130];
    memset(name, 'a', 128);
    name[128] = '\0';
    char body[512];
    snprintf(body, sizeof body, "{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[\"%s\"]}]}", name);
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, parse(body, &out, why, sizeof why));
    cJSON_Delete(out);
    PASS();
}

/* Catches: a body that is not an index passed through. */
TEST a_body_that_is_not_an_index_is_refused(void) {
    refuses("<html>", "not JSON");
    refuses("{\"sources\":{}}", "sources is not an array");
    refuses("{}", "sources is not an array");
    refuses("[]", "sources is not an array");
    PASS();
}

/* Catches: a reason overrunning a short buffer. */
TEST a_short_why_buffer_is_cut_not_overrun(void) {
    cJSON *out = NULL;
    char why[8];
    ASSERT_EQ(FIRC_ERR_INVAL, parse("<html>", &out, why, sizeof why));
    ASSERT_EQ(7, (int)strlen(why));
    PASS();
}

#define LS "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/{}.txt"
#define WITH_PROVIDERS(list) "{\"sources\":[],\"providers\":" list "}"

/* Catches: the provider list dropped, its order changed, or unknown keys passed on to the WebUI. */
TEST providers_of_the_index_are_checked_and_copied(void) {
    const char *body = "{\"generated\":\"g\",\"sources\":[],\"providers\":["
                       "{\"id\":\"sagernet\",\"name\":\"SagerNet\",\"x\":1},{\"id\":\"loyalsoldier\",\"name\":\"Loyalsoldier\"}]}";
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, parse(body, &out, why, sizeof why));
    cJSON *ps = cJSON_GetObjectItemCaseSensitive(out, "providers");
    ASSERT_EQ(2, cJSON_GetArraySize(ps));
    ASSERT_STR_EQ("SagerNet", cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(ps, 0), "name")->valuestring);
    ASSERT_STR_EQ("loyalsoldier", cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(ps, 1), "id")->valuestring);
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(ps, 0), "x"));
    cJSON_Delete(out);
    PASS();
}

/* Catches: an index of today (no providers) gaining an empty list, which the WebUI would read as "none". */
TEST an_index_without_providers_has_none(void) {
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, parse("{\"sources\":[]}", &out, why, sizeof why));
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "providers"));
    cJSON_Delete(out);
    PASS();
}

/* Catches: a provider the WebUI could not show or address accepted. */
TEST a_bad_provider_is_refused(void) {
    refuses(WITH_PROVIDERS("{}"), "providers is not an array");
    refuses(WITH_PROVIDERS("[{\"name\":\"A\"}]"), "provider 1 has no valid id");
    refuses(WITH_PROVIDERS("[{\"id\":\"A_b\",\"name\":\"A\"}]"), "provider 1 has no valid id");
    refuses(WITH_PROVIDERS("[{\"id\":\"a\"}]"), "provider a has no valid name");
    refuses(WITH_PROVIDERS("[{\"id\":\"a\",\"name\":\"\"}]"), "provider a has no valid name");
    refuses(WITH_PROVIDERS("[{\"id\":\"a\",\"name\":\"x\\ny\"}]"), "provider a has no valid name");
    refuses(WITH_PROVIDERS("[{\"id\":\"a\",\"name\":\"123456789012345678901234567890123\"}]"),
            "provider a has no valid name");
    refuses(WITH_PROVIDERS("[{\"id\":\"a\",\"name\":\"A\"},{\"id\":\"a\",\"name\":\"B\"}]"), "provider a is listed twice");
    char body[8192] = "{\"sources\":[],\"providers\":[";
    for (int i = 0; i < 65; i++) {
        snprintf(body + strlen(body), sizeof body - strlen(body), "%s{\"id\":\"p%d\",\"name\":\"P\"}", i ? "," : "", i);
    }
    snprintf(body + strlen(body), sizeof body - strlen(body), "]}");
    refuses(body, "more than 64 providers");
    PASS();
}

/* Catches: one provider's file publishing sources under another provider's name, or its own refused. */
TEST a_provider_file_holds_only_its_own_sources(void) {
    const char *own = "{\"sources\":[{\"id\":\"loyalsoldier\",\"url\":\"" LS "\",\"names\":[\"ru\"]},"
                      "{\"id\":\"loyalsoldier-geoip\",\"url\":\"" LS "\",\"names\":[\"ru\"]}],"
                      "\"providers\":[{\"id\":\"x\",\"name\":\"X\"}]}";
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, firc_list_catalog_parse(own, strlen(own), "loyalsoldier", &out, why, sizeof why));
    ASSERT_EQ(2, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "sources")));
    ASSERTm("a provider's file names no providers", cJSON_GetObjectItemCaseSensitive(out, "providers") == NULL);
    cJSON_Delete(out);
    refuses_as("loyalsoldier", "{\"sources\":[{\"id\":\"sagernet\",\"url\":\"" LS "\",\"names\":[]}]}",
               "source sagernet is not one of loyalsoldier");
    refuses_as("loyal", "{\"sources\":[{\"id\":\"loyalsoldier-geoip\",\"url\":\"" LS "\",\"names\":[]}]}",
               "source loyalsoldier-geoip is not one of loyal");
    PASS();
}

/* Catches: a provider file looked for outside the index's directory, or a URL cut short. */
TEST a_provider_file_sits_beside_the_index(void) {
    char buf[256];
    ASSERT(firc_list_catalog_provider_url(FIRC_LIST_CATALOG_URL, "loyalsoldier", buf, sizeof buf));
    ASSERT_STR_EQ("https://raw.githubusercontent.com/hoaxisr/rulesets/master/catalog/loyalsoldier.json", buf);
    ASSERT(firc_list_catalog_provider_url("http://127.0.0.1:8080/catalog", "a", buf, sizeof buf));
    ASSERT_STR_EQ("http://127.0.0.1:8080/catalog/a.json", buf);
    ASSERT_FALSEm("no path", firc_list_catalog_provider_url("http://host", "a", buf, sizeof buf));
    ASSERT_FALSEm("no scheme", firc_list_catalog_provider_url("host/catalog.json", "a", buf, sizeof buf));
    ASSERT_FALSEm("too short", firc_list_catalog_provider_url(FIRC_LIST_CATALOG_URL, "a", buf, 20));
    PASS();
}

/* Catches: a provider id that is not a safe path segment accepted. */
TEST provider_ids_are_catalog_ids(void) {
    ASSERT(firc_list_catalog_id_ok("ground-zerro"));
    ASSERT(firc_list_catalog_id_ok("v2fly"));
    const char *bad[] = {"", "..", "a/b", "A", "a.b", "a%2f", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) { ASSERT_FALSE(firc_list_catalog_id_ok(bad[i])); }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_spec_example_parses_and_round_trips);
    RUN_TEST(an_empty_sources_array_parses);
    RUN_TEST(a_bad_id_is_refused);
    RUN_TEST(a_url_off_the_allowed_host_is_refused);
    RUN_TEST(a_url_without_exactly_one_placeholder_is_refused);
    RUN_TEST(a_bad_name_is_refused_by_position);
    RUN_TEST(a_source_missing_its_url_or_names_is_refused);
    RUN_TEST(a_name_of_128_characters_is_accepted);
    RUN_TEST(a_body_that_is_not_an_index_is_refused);
    RUN_TEST(a_short_why_buffer_is_cut_not_overrun);
    RUN_TEST(providers_of_the_index_are_checked_and_copied);
    RUN_TEST(an_index_without_providers_has_none);
    RUN_TEST(a_bad_provider_is_refused);
    RUN_TEST(a_provider_file_holds_only_its_own_sources);
    RUN_TEST(a_provider_file_sits_beside_the_index);
    RUN_TEST(provider_ids_are_catalog_ids);
    GREATEST_MAIN_END();
}
