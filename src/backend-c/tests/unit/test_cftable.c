#include "greatest.h"

#include <stdio.h>
#include <string.h>

#include "firc/cfedge.h"
#include "firc/fakeip.h"

#define NOW 5000
#define G "aaaaaaaa"

static firc_ip_t ip4(uint8_t d)
{
    firc_ip_t a;
    memset(&a, 0, sizeof a);
    a.len = 4;
    a.b[0] = 104;
    a.b[1] = 16;
    a.b[3] = d;
    return a;
}

static firc_cfprobe_t pr(uint8_t d, bool ok, double m)
{
    firc_cfprobe_t p;
    memset(&p, 0, sizeof p);
    p.addr = ip4(d);
    p.ok = ok;
    p.median_s = m;
    return p;
}

static bool tgt_is(firc_cftable_t *t, const char *g, unsigned fam, uint8_t d)
{
    firc_fakeip_cf_cand_t o;
    return firc_cftable_target(t, g, fam, &o) && o.addr.len == 4 && o.addr.b[3] == d;
}

TEST the_first_working_candidate_becomes_the_target(void)
{
    firc_cftable_t *t = firc_cftable_new();
    firc_cfprobe_t r[] = {pr(1, false, 0), pr(2, true, 0.2)};
    ASSERT_EQ(1, firc_cftable_apply(t, G, FIRC_FAM_V4, r, 2, NOW));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 2));
    firc_cftable_free(t);
    PASS();
}

TEST the_fastest_of_several_wins_at_first_pick(void)
{
    firc_cftable_t *t = firc_cftable_new();
    firc_cfprobe_t r[] = {pr(1, true, 0.3), pr(2, true, 0.1), pr(3, true, 0.2)};
    ASSERT_EQ(1, firc_cftable_apply(t, G, FIRC_FAM_V4, r, 3, NOW));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 2));
    firc_cftable_free(t);
    PASS();
}

TEST none_working_means_no_target_and_due_in_30_s(void)
{
    firc_cftable_t *t = firc_cftable_new();
    firc_cfprobe_t r[] = {pr(1, false, 0)};
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, r, 1, NOW));
    firc_fakeip_cf_cand_t o;
    ASSERT(!firc_cftable_target(t, G, FIRC_FAM_V4, &o));
    ASSERT(!firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 29));
    ASSERT(firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 30));
    firc_cftable_free(t);
    PASS();
}

static firc_cftable_t *with_target_300(void)
{
    firc_cftable_t *t = firc_cftable_new();
    firc_cfprobe_t r[] = {pr(1, true, 0.3)};
    firc_cftable_apply(t, G, FIRC_FAM_V4, r, 1, NOW);
    return t;
}

TEST a_candidate_19_percent_faster_does_not_replace_the_target(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t r[] = {pr(1, true, 0.3), pr(2, true, 0.243)};
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, r, 2, NOW + 600));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 1));
    firc_cftable_free(t);
    PASS();
}

TEST a_candidate_20_percent_faster_replaces_it(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t r[] = {pr(1, true, 0.3), pr(2, true, 0.240)};
    ASSERT_EQ(1, firc_cftable_apply(t, G, FIRC_FAM_V4, r, 2, NOW + 600));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 2));
    firc_cftable_free(t);
    PASS();
}

TEST a_failed_candidate_never_replaces_the_target(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t r[] = {pr(1, true, 0.3), pr(2, false, 0.001)};
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, r, 2, NOW + 600));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 1));
    firc_cftable_free(t);
    PASS();
}

TEST a_set_without_the_target_compares_against_its_last_median(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t slow[] = {pr(2, true, 0.250)};
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, slow, 1, NOW + 600));
    firc_cfprobe_t fast[] = {pr(2, true, 0.240)};
    ASSERT_EQ(1, firc_cftable_apply(t, G, FIRC_FAM_V4, fast, 1, NOW + 1200));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 2));
    firc_cftable_free(t);
    PASS();
}

TEST a_set_without_the_target_is_not_a_failure_of_it(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t bad[] = {pr(3, false, 0)};
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, bad, 1, NOW + 30));
    firc_cfprobe_t other[] = {pr(2, true, 0.29)};
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, other, 1, NOW + 60));
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, bad, 1, NOW + 90));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 1));
    firc_cftable_free(t);
    PASS();
}

TEST one_failed_check_keeps_the_target_two_drop_it(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t bad[] = {pr(1, false, 0)};
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, bad, 1, NOW + 600));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 1));
    ASSERT_EQ(-1, firc_cftable_apply(t, G, FIRC_FAM_V4, bad, 1, NOW + 630));
    firc_fakeip_cf_cand_t o;
    ASSERT(!firc_cftable_target(t, G, FIRC_FAM_V4, &o));
    firc_cftable_free(t);
    PASS();
}

TEST a_pass_between_two_failures_resets_the_count(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t bad[] = {pr(1, false, 0)};
    firc_cfprobe_t good[] = {pr(1, true, 0.3)};
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, bad, 1, NOW + 600));
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, good, 1, NOW + 630));
    ASSERT_EQ(0, firc_cftable_apply(t, G, FIRC_FAM_V4, bad, 1, NOW + 1230));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 1));
    firc_cftable_free(t);
    PASS();
}

TEST a_failed_target_is_replaced_by_a_working_candidate_at_once(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t bad[] = {pr(1, false, 0)};
    firc_cftable_apply(t, G, FIRC_FAM_V4, bad, 1, NOW + 600);
    firc_cfprobe_t r[] = {pr(1, false, 0), pr(2, true, 0.29)};
    ASSERT_EQ(1, firc_cftable_apply(t, G, FIRC_FAM_V4, r, 2, NOW + 630));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 2));
    firc_cftable_free(t);
    PASS();
}

TEST due_at_once_for_a_group_never_checked(void)
{
    firc_cftable_t *t = firc_cftable_new();
    ASSERT(firc_cftable_due(t, G, FIRC_FAM_V4, NOW));
    firc_cftable_free(t);
    PASS();
}

TEST due_after_600_s_with_a_target(void)
{
    firc_cftable_t *t = with_target_300();
    ASSERT(!firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 599));
    ASSERT(firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 600));
    firc_cftable_free(t);
    PASS();
}

TEST due_after_30_s_after_a_failure(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cfprobe_t bad[] = {pr(1, false, 0)};
    firc_cftable_apply(t, G, FIRC_FAM_V4, bad, 1, NOW + 600);
    ASSERT(!firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 629));
    ASSERT(firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 630));
    firc_cftable_free(t);
    PASS();
}

TEST recheck_makes_it_due_now(void)
{
    firc_cftable_t *t = with_target_300();
    ASSERT(!firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 1));
    ASSERT(firc_cftable_recheck(t, G));
    ASSERT(firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 1));
    ASSERT_FALSE(firc_cftable_recheck(t, "bbbbbbbb"));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 1));
    firc_cftable_free(t);
    PASS();
}

TEST forget_drops_the_target(void)
{
    firc_cftable_t *t = with_target_300();
    firc_cftable_forget(t, G);
    firc_fakeip_cf_cand_t o;
    ASSERT(!firc_cftable_target(t, G, FIRC_FAM_V4, &o));
    firc_cftable_forget(t, "bbbbbbbb");
    firc_cftable_free(t);
    PASS();
}

TEST groups_are_independent(void)
{
    firc_cftable_t *t = with_target_300();
    firc_fakeip_cf_cand_t o;
    ASSERT(!firc_cftable_target(t, "bbbbbbbb", FIRC_FAM_V4, &o));
    firc_cftable_forget(t, "bbbbbbbb");
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 1));
    firc_cftable_free(t);
    PASS();
}

TEST families_are_independent(void)
{
    firc_cftable_t *t = with_target_300();
    firc_fakeip_cf_cand_t o;
    ASSERT(!firc_cftable_target(t, G, FIRC_FAM_V6, &o));
    ASSERT(firc_cftable_due(t, G, FIRC_FAM_V6, NOW + 1));
    ASSERT(!firc_cftable_due(t, G, FIRC_FAM_V4, NOW + 1));
    firc_cfprobe_t r[] = {pr(7, true, 0.1)};
    ASSERT_EQ(1, firc_cftable_apply(t, G, FIRC_FAM_V6, r, 1, NOW));
    ASSERT(tgt_is(t, G, FIRC_FAM_V4, 1));
    ASSERT(tgt_is(t, G, FIRC_FAM_V6, 7));
    firc_cftable_free(t);
    PASS();
}

TEST the_target_keeps_the_name_it_was_adopted_with(void)
{
    firc_cftable_t *t = firc_cftable_new();
    firc_cfprobe_t r[] = {pr(1, true, 0.3), pr(2, true, 0.1)};
    snprintf(r[0].name, sizeof(r[0].name), "one.example");
    snprintf(r[1].name, sizeof(r[1].name), "two.example");
    firc_cftable_apply(t, G, FIRC_FAM_V4, r, 2, NOW);
    firc_fakeip_cf_cand_t o;
    ASSERT(firc_cftable_target(t, G, FIRC_FAM_V4, &o));
    ASSERT_STR_EQ("two.example", o.name);
    firc_cftable_free(t);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_first_working_candidate_becomes_the_target);
    RUN_TEST(the_fastest_of_several_wins_at_first_pick);
    RUN_TEST(none_working_means_no_target_and_due_in_30_s);
    RUN_TEST(a_candidate_19_percent_faster_does_not_replace_the_target);
    RUN_TEST(a_candidate_20_percent_faster_replaces_it);
    RUN_TEST(a_failed_candidate_never_replaces_the_target);
    RUN_TEST(a_set_without_the_target_compares_against_its_last_median);
    RUN_TEST(a_set_without_the_target_is_not_a_failure_of_it);
    RUN_TEST(one_failed_check_keeps_the_target_two_drop_it);
    RUN_TEST(a_pass_between_two_failures_resets_the_count);
    RUN_TEST(a_failed_target_is_replaced_by_a_working_candidate_at_once);
    RUN_TEST(due_at_once_for_a_group_never_checked);
    RUN_TEST(due_after_600_s_with_a_target);
    RUN_TEST(due_after_30_s_after_a_failure);
    RUN_TEST(recheck_makes_it_due_now);
    RUN_TEST(forget_drops_the_target);
    RUN_TEST(groups_are_independent);
    RUN_TEST(families_are_independent);
    RUN_TEST(the_target_keeps_the_name_it_was_adopted_with);
    GREATEST_MAIN_END();
}
