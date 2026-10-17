#include "greatest.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "firc/subhdr.h"
#include "firc/version.h"

static firc_subhdr_set_t g_defaults;
static firc_subhdr_set_t g_set;

static int is_at(const firc_subhdr_set_t *s, size_t i, const char *name, const char *value)
{
    return i < s->n && strcmp(s->h[i].name, name) == 0 && strcmp(s->h[i].value, value) == 0;
}

/* Catches: a default left out, renamed, reordered or given another value. */
TEST the_defaults_name_the_router_in_order(void)
{
    firc_subhdr_set_t s;
    firc_subhdr_defaults("6e58d9776d738a31", "5.01.C.6.0-1", "Ultra (KN-1810)", &s);
    ASSERT_EQ_FMT((size_t)5, s.n, "%zu");
    ASSERT(is_at(&s, 0, "User-Agent", "firc/" FIRC_VERSION));
    ASSERT(is_at(&s, 1, "X-HWID", "6e58d9776d738a31"));
    ASSERT(is_at(&s, 2, "X-Device-OS", "KeeneticOS"));
    ASSERT(is_at(&s, 3, "X-Ver-OS", "5.01.C.6.0-1"));
    ASSERT(is_at(&s, 4, "X-Device-Model", "Ultra (KN-1810)"));
    PASS();
}

/* Catches: a value RCI did not give sent empty or invented, or an unsendable one sent anyway. */
TEST a_value_rci_did_not_give_is_left_out(void)
{
    firc_subhdr_set_t s;
    firc_subhdr_defaults(NULL, "", "Ultra\x01", &s);
    ASSERT_EQ_FMT((size_t)2, s.n, "%zu");
    ASSERT(is_at(&s, 0, "User-Agent", "firc/" FIRC_VERSION));
    ASSERT(is_at(&s, 1, "X-Device-OS", "KeeneticOS"));
    PASS();
}

/* Catches: a hand header matched by exact case only, moved to the end, or sent next to the default it replaces. */
TEST an_own_header_replaces_a_default_by_name_in_any_case(void)
{
    firc_subhdr_pair_t own[] = {{"user-agent", "sing-box/1.12.0"}, {"X-Extra", "1"}};
    firc_subhdr_merge(&g_defaults, own, 2, &g_set);
    ASSERT_EQ_FMT((size_t)6, g_set.n, "%zu");
    ASSERT(is_at(&g_set, 0, "user-agent", "sing-box/1.12.0"));
    ASSERT(is_at(&g_set, 1, "X-HWID", "6e58d9776d738a31"));
    ASSERT(is_at(&g_set, 4, "X-Device-Model", "Ultra (KN-1810)"));
    ASSERT(is_at(&g_set, 5, "X-Extra", "1"));
    PASS();
}

/* Catches: an empty value sent as an empty header instead of leaving the default out, or an empty own header sent. */
TEST an_empty_value_leaves_the_header_out(void)
{
    firc_subhdr_pair_t own[] = {{"x-hwid", ""}, {"X-Nothing", ""}};
    firc_subhdr_merge(&g_defaults, own, 2, &g_set);
    ASSERT_EQ_FMT((size_t)4, g_set.n, "%zu");
    for (size_t i = 0; i < g_set.n; i++) {
        ASSERT(strcasecmp(g_set.h[i].name, "X-HWID") != 0);
        ASSERT(strcmp(g_set.h[i].name, "X-Nothing") != 0);
    }
    PASS();
}

/* Catches: a header missing from the request lines, a line in another shape, or curl's own agent sent once the operator removed it. */
TEST the_lines_carry_the_set_and_drop_curls_agent_when_removed(void)
{
    char **v = firc_subhdr_lines(&g_defaults);
    ASSERT(v != NULL);
    ASSERT_STR_EQ("User-Agent: firc/" FIRC_VERSION, v[0]);
    ASSERT_STR_EQ("X-Device-Model: Ultra (KN-1810)", v[4]);
    ASSERT_EQ(NULL, v[5]);
    char **c = firc_subhdr_lines_copy(v);
    firc_subhdr_lines_free(v);
    ASSERT(c != NULL);
    ASSERT_STR_EQ("X-HWID: 6e58d9776d738a31", c[1]);
    firc_subhdr_lines_free(c);
    firc_subhdr_pair_t own[] = {{"User-Agent", ""}};
    firc_subhdr_merge(&g_defaults, own, 1, &g_set);
    v = firc_subhdr_lines(&g_set);
    ASSERT(v != NULL);
    ASSERT_STR_EQ("X-HWID: 6e58d9776d738a31", v[0]);
    ASSERT_STR_EQ("User-Agent:", v[4]);
    ASSERT_EQ(NULL, v[5]);
    firc_subhdr_lines_free(v);
    PASS();
}

/* Catches: a bound off by one, a refused name let through in another case, a control character or a broken name taken, or the value echoed in the reason. */
TEST hand_headers_keep_their_bounds(void)
{
    char name64[65], name65[66], value512[513], value513[514];
    memset(name64, 'a', 64);
    name64[64] = '\0';
    memset(name65, 'a', 65);
    name65[65] = '\0';
    memset(value512, 'v', 512);
    value512[512] = '\0';
    memset(value513, 'v', 513);
    value513[513] = '\0';
    ASSERT_EQ(NULL, firc_subhdr_check(name64, value512));
    ASSERT_EQ(NULL, firc_subhdr_check("X-A!#$%&'*+-.^_`|~9", "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82"));
    ASSERT_EQ(NULL, firc_subhdr_check("X-A", ""));
    static const char *const bad_names[] = {"", "X Bad", "X:A", "\xd0\xa5-A", "X\tA"};
    for (size_t i = 0; i < sizeof bad_names / sizeof bad_names[0]; i++) {
        const char *why = firc_subhdr_check(bad_names[i], "1");
        ASSERTm(bad_names[i], why != NULL && strstr(why, "header name") != NULL);
    }
    ASSERT(firc_subhdr_check(name65, "1") != NULL);
    static const char *const refused[] = {"host", "Content-Length", "TRANSFER-ENCODING", "connection"};
    for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
        ASSERT_STR_EQm(refused[i], "set by the fetch itself, not by hand", firc_subhdr_check(refused[i], "x"));
    }
    ASSERT(firc_subhdr_check("X-A", value513) != NULL);
    static const char *const bad_values[] = {"a\tb", "a\x7f", "a\xc2\x85", "s3cr3t\x01", "\xff"};
    for (size_t i = 0; i < sizeof bad_values / sizeof bad_values[0]; i++) {
        const char *why = firc_subhdr_check("X-A", bad_values[i]);
        ASSERT(why != NULL);
        ASSERT_EQ(NULL, strstr(why, "s3cr3t"));
    }
    ASSERT(firc_subhdr_name_ok("X-HWID"));
    ASSERT_FALSE(firc_subhdr_name_ok("X HWID"));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    firc_subhdr_defaults("6e58d9776d738a31", "5.01.C.6.0-1", "Ultra (KN-1810)", &g_defaults);
    RUN_TEST(the_defaults_name_the_router_in_order);
    RUN_TEST(a_value_rci_did_not_give_is_left_out);
    RUN_TEST(an_own_header_replaces_a_default_by_name_in_any_case);
    RUN_TEST(an_empty_value_leaves_the_header_out);
    RUN_TEST(the_lines_carry_the_set_and_drop_curls_agent_when_removed);
    RUN_TEST(hand_headers_keep_their_bounds);
    GREATEST_MAIN_END();
}
