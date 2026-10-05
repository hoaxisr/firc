#include "greatest.h"

#include "firc/mark.h"

/* Catches: firc's mark layout overlapping the bits the firmware or zapret use. */
TEST the_write_mask_clears_the_firmwares_bits(void) {
    ASSERT_EQ_FMTm("0x989 must fall outside everything firc writes, or firc erases "
                   "the firmware's own policy routing",
                   0u, FIRC_MARK_WRITE_MASK & 0x989u, "%#x");

    ASSERT_EQ_FMTm("nothing below 0x10000 is ours", 0u, FIRC_MARK_WRITE_MASK & 0xffffu, "%#x");
    PASS();
}

TEST the_handled_bit_is_the_one_other_tools_test(void) {
    ASSERT_EQ_FMT(0x40000000u, FIRC_MARK_HANDLED & 0x40000000u, "%#x");
    ASSERTm("the handled bit must be inside what firc writes, or setting it is a no-op",
            (FIRC_MARK_WRITE_MASK & FIRC_MARK_HANDLED) == FIRC_MARK_HANDLED);
    ASSERTm("and outside the group field, or it would be read as a group number",
            (FIRC_MARK_GROUP_MASK & FIRC_MARK_HANDLED) == 0);
    PASS();
}

/* Catches: the ip rule's match value carrying the handled bit as well as the group field. */
TEST a_groups_mark_carries_both_halves_and_its_rule_only_one(void) {
    uint32_t m = 0;
    ASSERT(firc_mark_for_field(1, &m));
    ASSERT_EQ_FMTm("group 1 sits at 0x00010000 with the handled bit", 0x40010000u, m, "%#x");
    ASSERT_EQ_FMTm("the rule matches the field alone", 0x00010000u, firc_mark_group_value(1),
                   "%#x");

    ASSERT(firc_mark_for_field(255, &m));
    ASSERT_EQ_FMT(0x40ff0000u, m, "%#x");
    ASSERT_EQ_FMT(0x00ff0000u, firc_mark_group_value(255), "%#x");

    for (uint32_t f = 1; f <= FIRC_MARK_MAX_GROUPS; f++) {
        ASSERT(firc_mark_for_field(f, &m));
        if ((m & ~FIRC_MARK_WRITE_MASK) != 0) { FAILm("a group's mark escaped the write mask"); }
        if (((m & FIRC_MARK_GROUP_MASK) >> FIRC_MARK_GROUP_SHIFT) != f) {
            FAILm("the field did not survive the round trip");
        }
        if (firc_mark_group_value(f) == 0) { FAILm("a legal group produced an empty match"); }
    }
    PASS();
}

/* Catches: field 0 or a field past 255 accepted. */
TEST fields_outside_the_range_are_refused(void) {
    uint32_t m = 0xdeadbeefu;
    ASSERT_FALSEm("zero is what an unmarked packet carries", firc_mark_for_field(0, &m));
    ASSERT_EQ_FMTm("a refusal must not write the output", 0xdeadbeefu, m, "%#x");
    ASSERT_FALSE(firc_mark_for_field(256, &m));
    ASSERT_FALSE(firc_mark_for_field(0xffffffffu, &m));
    ASSERT_EQ_FMT(0xdeadbeefu, m, "%#x");
    PASS();
}

TEST every_group_shares_firc_s_one_rule_priority(void) {
    ASSERT_EQ_FMTm("one priority, whatever the field", firc_rule_priority_for_field(1),
                   firc_rule_priority_for_field(FIRC_MARK_MAX_GROUPS), "%u");
    ASSERTm("ahead of the lowest fwmark rule measured (90)", firc_rule_priority_for_field(1) < 90u);
    ASSERTm("priority 0 belongs to `local`", firc_rule_priority_for_field(1) > 0u);
    ASSERT_EQ_FMT(FIRC_RULE_PRIORITY, firc_rule_priority_for_field(7), "%u");
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_write_mask_clears_the_firmwares_bits);
    RUN_TEST(the_handled_bit_is_the_one_other_tools_test);
    RUN_TEST(a_groups_mark_carries_both_halves_and_its_rule_only_one);
    RUN_TEST(fields_outside_the_range_are_refused);
    RUN_TEST(every_group_shares_firc_s_one_rule_priority);
    GREATEST_MAIN_END();
}
