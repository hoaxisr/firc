#include "greatest.h"

#include <inttypes.h>
#include <string.h>

#include "firc/subinfo.h"

/* Catches: a field read into the wrong slot, a key matched case-sensitively, or spaces kept in a number. */
TEST the_four_fields_are_read_in_any_case_and_order(void)
{
    firc_subinfo_t i;
    ASSERT(firc_subinfo_parse(" EXPIRE=1767225600 ;Total = 107374182400; download=2000;upload=100 ", &i));
    ASSERT(i.have);
    ASSERT_EQ_FMT((uint64_t)100, i.upload, "%" PRIu64);
    ASSERT_EQ_FMT((uint64_t)2000, i.download, "%" PRIu64);
    ASSERT_EQ_FMT((uint64_t)107374182400, i.total, "%" PRIu64);
    ASSERT_EQ_FMT((int64_t)1767225600, i.expire, "%" PRId64);
    PASS();
}

/* Catches: a missing total or expire taken as a limit, or an unknown key refusing the rest. */
TEST missing_fields_are_zero_and_unknown_ones_skipped(void)
{
    firc_subinfo_t i;
    ASSERT(firc_subinfo_parse("upload=5; download=6; plan=gold", &i));
    ASSERT_EQ_FMT((uint64_t)0, i.total, "%" PRIu64);
    ASSERT_EQ_FMT((int64_t)0, i.expire, "%" PRId64);
    ASSERT(firc_subinfo_parse("total=10.0; expire=1700000000.5", &i));
    ASSERT_EQ_FMT((uint64_t)10, i.total, "%" PRIu64);
    ASSERT_EQ_FMT((int64_t)1700000000, i.expire, "%" PRId64);
    PASS();
}

/* Catches: garbage, a negative or an overflowing number taken as a value, or a header with none of the four
   reported as present. */
TEST a_bad_value_is_refused_whole(void)
{
    firc_subinfo_t i;
    ASSERT_FALSE(firc_subinfo_parse("plan=gold", &i));
    ASSERT_FALSE(i.have);
    ASSERT_FALSE(firc_subinfo_parse("upload=1; total=lots", &i));
    ASSERT_FALSE(i.have);
    ASSERT_EQ_FMT((uint64_t)0, i.upload, "%" PRIu64);
    ASSERT_FALSE(firc_subinfo_parse("download=-1", &i));
    ASSERT_FALSE(firc_subinfo_parse("total=1e9", &i));
    ASSERT_FALSE(firc_subinfo_parse("total=99999999999999999999", &i));
    ASSERT_FALSE(firc_subinfo_parse("expire=9223372036854775808", &i));
    ASSERT_FALSE(firc_subinfo_parse("", &i));
    ASSERT_FALSE(firc_subinfo_parse(NULL, &i));
    PASS();
}

/* Catches: the body line missed after a BOM or another comment, or looked for past the first node. */
TEST the_body_line_is_read_only_among_the_opening_comments(void)
{
    firc_subinfo_t i;
    const char *ok = "\xEF\xBB\xBF#profile-title: P\r\n\r\n# Subscription-Userinfo : total=3; expire=4\r\nvless://x\n";
    ASSERT(firc_subinfo_from_body(ok, strlen(ok), &i));
    ASSERT_EQ_FMT((uint64_t)3, i.total, "%" PRIu64);
    ASSERT_EQ_FMT((int64_t)4, i.expire, "%" PRId64);
    const char *late = "vless://x\n#subscription-userinfo: total=3\n";
    ASSERT_FALSE(firc_subinfo_from_body(late, strlen(late), &i));
    const char *none = "#profile-title: P\n";
    ASSERT_FALSE(firc_subinfo_from_body(none, strlen(none), &i));
    ASSERT_FALSE(firc_subinfo_from_body("", 0, &i));
    PASS();
}

/* Catches: the kept line not read back as the same numbers. */
TEST the_format_reads_back(void)
{
    firc_subinfo_t a = {.have = true, .upload = 1, .download = 2, .total = 3, .expire = 4}, b;
    char line[FIRC_SUBINFO_LINE_MAX + 1];
    firc_subinfo_format(&a, line, sizeof line);
    ASSERT_STR_EQ("upload=1; download=2; total=3; expire=4", line);
    ASSERT(firc_subinfo_parse(line, &b));
    ASSERT(b.upload == a.upload && b.download == a.download && b.total == a.total && b.expire == a.expire);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_four_fields_are_read_in_any_case_and_order);
    RUN_TEST(missing_fields_are_zero_and_unknown_ones_skipped);
    RUN_TEST(a_bad_value_is_refused_whole);
    RUN_TEST(the_body_line_is_read_only_among_the_opening_comments);
    RUN_TEST(the_format_reads_back);
    GREATEST_MAIN_END();
}
