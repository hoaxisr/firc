#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "firc/json.h"
#include "firc/models.h"

TEST error_shape_matches_go_ErrorRes(void)
{
    cJSON *obj = firc_json_error("something went wrong");
    ASSERT(obj != NULL);

    char *dump = firc_json_dump(obj);
    ASSERT(dump != NULL);
    ASSERT_STR_EQ("{\"error\":\"something went wrong\"}", dump);

    free(dump);
    cJSON_Delete(obj);
    PASS();
}

TEST list_sync_carries_cached_at(void)
{
    /* Catches: cachedAt dropped from the sync object or fed from the wrong field. */
    firc_group_list_t l;
    memset(&l, 0, sizeof(l));
    l.last_check = 1700000000;
    l.cached_at = 1699990000;
    cJSON *obj = firc_api_list_sync_json(&l);
    ASSERT(obj != NULL);
    ASSERT_EQ(1699990000, (int64_t)cJSON_GetObjectItem(obj, "cachedAt")->valuedouble);
    ASSERT_EQ(1700000000, (int64_t)cJSON_GetObjectItem(obj, "lastCheck")->valuedouble);
    cJSON_Delete(obj);

    l.cached_at = 0;
    obj = firc_api_list_sync_json(&l);
    ASSERT(obj != NULL);
    ASSERT(cJSON_GetObjectItem(obj, "cachedAt") != NULL);
    ASSERT_EQ(0, (int64_t)cJSON_GetObjectItem(obj, "cachedAt")->valuedouble);
    cJSON_Delete(obj);
    PASS();
}

TEST dump_is_compact_no_whitespace(void)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "a", "b");
    cJSON_AddNumberToObject(obj, "n", 42);

    char *dump = firc_json_dump(obj);
    ASSERT(dump != NULL);
    ASSERT(strchr(dump, '\n') == NULL);
    ASSERT(strchr(dump, ' ') == NULL);
    ASSERT_STR_EQ("{\"a\":\"b\",\"n\":42}", dump);

    free(dump);
    cJSON_Delete(obj);
    PASS();
}

TEST parse_roundtrip(void)
{
    const char *text = "{\"login\":\"admin\",\"password\":\"hunter2\"}";
    cJSON *parsed = cJSON_Parse(text);
    ASSERT(parsed != NULL);
    cJSON *login = cJSON_GetObjectItemCaseSensitive(parsed, "login");
    ASSERT(cJSON_IsString(login));
    ASSERT_STR_EQ("admin", login->valuestring);
    cJSON_Delete(parsed);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(error_shape_matches_go_ErrorRes);
    RUN_TEST(list_sync_carries_cached_at);
    RUN_TEST(dump_is_compact_no_whitespace);
    RUN_TEST(parse_roundtrip);
    GREATEST_MAIN_END();
}
