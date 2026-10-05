#include "greatest.h"

#include "firc/rulesnap.h"
#include <string.h>
#include <unistd.h>
#include "firc/log.h"

static firc_config_t make_cfg(void)
{
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    return cfg;
}

static firc_group_t *make_group(firc_id_t id, const char *name, bool enable)
{
    firc_group_t *g = firc_group_new();
    g->id = id;
    firc_strset(&g->name, name);
    g->enable = enable;
    return g;
}

static firc_rule_t *make_rule(firc_id_t id, const char *type, const char *rule,
                            bool enable)
{
    firc_rule_t *r = firc_rule_new();
    r->id = id;
    firc_strset(&r->type, type);
    firc_strset(&r->rule, rule);
    r->enable = enable;
    return r;
}

TEST disabled_group_excluded(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g1 = make_group((firc_id_t){{1, 0, 0, 0}}, "on", true);
    firc_group_add_rule(g1, make_rule((firc_id_t){{1, 1, 0, 0}}, "domain",
                                    "a.example.com", true));
    firc_group_t *g2 = make_group((firc_id_t){{2, 0, 0, 0}}, "off", false);
    firc_group_add_rule(g2, make_rule((firc_id_t){{2, 1, 0, 0}}, "domain",
                                    "b.example.com", true));
    firc_config_add_group(&cfg, g1);
    firc_config_add_group(&cfg, g2);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT(snap != NULL);
    ASSERT_EQ(1u, (unsigned)snap->n_groups);
    ASSERT_STR_EQ("on", snap->groups[0]->name);

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

TEST disabled_rule_excluded_from_matcher(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g = make_group((firc_id_t){{1, 0, 0, 0}}, "g", true);
    firc_group_add_rule(g, make_rule((firc_id_t){{1, 1, 0, 0}}, "domain",
                                   "enabled.example.com", true));
    firc_group_add_rule(g, make_rule((firc_id_t){{1, 2, 0, 0}}, "domain",
                                   "disabled.example.com", false));
    firc_config_add_group(&cfg, g);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_EQ(1u, (unsigned)snap->n_groups);
    ASSERT(firc_matcher_match(snap->groups[0]->matcher, "enabled.example.com"));
    ASSERT_FALSE(
        firc_matcher_match(snap->groups[0]->matcher, "disabled.example.com"));

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

TEST multiple_groups_independently_match(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g1 = make_group((firc_id_t){{1, 0, 0, 0}}, "g1", true);
    firc_group_add_rule(
        g1, make_rule((firc_id_t){{1, 1, 0, 0}}, "namespace", "example.com",
                      true));
    firc_group_t *g2 = make_group((firc_id_t){{2, 0, 0, 0}}, "g2", true);
    firc_group_add_rule(
        g2, make_rule((firc_id_t){{2, 1, 0, 0}}, "wildcard", "*.example.com",
                      true));
    firc_config_add_group(&cfg, g1);
    firc_config_add_group(&cfg, g2);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_EQ(2u, (unsigned)snap->n_groups);
    int matched = 0;
    for (size_t i = 0; i < snap->n_groups; i++) {
        if (firc_matcher_match(snap->groups[i]->matcher, "sub.example.com")) {
            matched++;
        }
    }
    ASSERT_EQ(2, matched);

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Pushes a rule into a group's list by hand, as a sync would install it. */
static void add_group_list_rule(firc_group_t *g, firc_id_t id, const char *type, const char *rule,
                                bool enable)
{
    if (g->list == NULL) {
        g->list = firc_group_list_new();
    }
    firc_sub_rules_push(&g->list->rules, rule, type, enable, id);
}

/* Catches: a refcount that frees the snapshot under its second holder, or leaks it (under sanitize). */
TEST a_snapshot_with_two_holders_outlives_the_first_free(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g = make_group((firc_id_t){{9, 0, 0, 0}}, "g1", true);
    add_group_list_rule(g, (firc_id_t){{9, 1, 0, 0}}, "domain", "sub.example.com", true);
    firc_config_add_group(&cfg, g);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    firc_ruleset_snapshot_t *other = firc_ruleset_snapshot_ref(snap);
    ASSERT(other == snap);
    firc_ruleset_snapshot_free(snap);
    ASSERT(firc_ruleset_snapshot_first_match(other, "sub.example.com") != NULL);
    firc_ruleset_snapshot_free(other);

    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a list rule not taking config-order priority like a hand rule. */
TEST a_list_group_above_a_manual_group_owns_a_shared_name(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *lg = make_group((firc_id_t){{1, 0, 0, 0}}, "list_group", true);
    add_group_list_rule(lg, (firc_id_t){{1, 1, 0, 0}}, FIRC_RULE_NAMESPACE, "shared.example", true);
    firc_config_add_group(&cfg, lg);

    firc_group_t *mg = make_group((firc_id_t){{2, 0, 0, 0}}, "manual_group", true);
    firc_group_add_rule(mg, make_rule((firc_id_t){{2, 1, 0, 0}}, FIRC_RULE_DOMAIN, "shared.example", true));
    firc_config_add_group(&cfg, mg);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    const firc_group_snapshot_t *owner = firc_ruleset_snapshot_first_match(snap, "shared.example");
    ASSERT(owner != NULL);
    ASSERT(firc_id_equal(lg->id, owner->id));

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

TEST a_manual_group_above_a_list_group_owns_a_shared_name(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *mg = make_group((firc_id_t){{1, 0, 0, 0}}, "manual_group", true);
    firc_group_add_rule(mg, make_rule((firc_id_t){{1, 1, 0, 0}}, FIRC_RULE_DOMAIN, "shared.example", true));
    firc_config_add_group(&cfg, mg);

    firc_group_t *lg = make_group((firc_id_t){{2, 0, 0, 0}}, "list_group", true);
    add_group_list_rule(lg, (firc_id_t){{2, 1, 0, 0}}, FIRC_RULE_NAMESPACE, "shared.example", true);
    firc_config_add_group(&cfg, lg);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    const firc_group_snapshot_t *owner = firc_ruleset_snapshot_first_match(snap, "shared.example");
    ASSERT(owner != NULL);
    ASSERT(firc_id_equal(mg->id, owner->id));

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a group's hand and list rules building two entries instead of one. */
TEST a_hand_rule_and_a_list_rule_of_one_group_give_one_owner(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g = make_group((firc_id_t){{1, 0, 0, 0}}, "g", true);
    firc_group_add_rule(g, make_rule((firc_id_t){{1, 1, 0, 0}}, FIRC_RULE_DOMAIN, "a.example", true));
    add_group_list_rule(g, (firc_id_t){{1, 2, 0, 0}}, FIRC_RULE_DOMAIN, "b.example", true);
    firc_config_add_group(&cfg, g);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_EQ_FMTm("one entry for the group, not two", (size_t)1, snap->n_groups, "%zu");
    const firc_group_snapshot_t *owner_a = firc_ruleset_snapshot_first_match(snap, "a.example");
    const firc_group_snapshot_t *owner_b = firc_ruleset_snapshot_first_match(snap, "b.example");
    ASSERT(owner_a != NULL);
    ASSERT(owner_b != NULL);
    ASSERT(firc_id_equal(g->id, owner_a->id));
    ASSERT(firc_id_equal(g->id, owner_b->id));

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a list group without a body not making the snapshot provisional. */
TEST a_list_group_without_a_body_makes_the_snapshot_provisional(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g = make_group((firc_id_t){{1, 0, 0, 0}}, "g", true);
    g->list = firc_group_list_new();
    firc_config_add_group(&cfg, g);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERTm("no body hash yet: a name this list would route still passes today", snap->provisional);
    firc_ruleset_snapshot_free(snap);

    g->list->has_body_hash = true;
    snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_FALSEm("a list is in: nothing left to be provisional about", snap->provisional);
    firc_ruleset_snapshot_free(snap);

    g->list->has_body_hash = false;
    g->enable = false;
    snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_FALSEm("a disabled group can never route; its missing list is moot", snap->provisional);
    firc_ruleset_snapshot_free(snap);

    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a list group without an interface left out of the names. */
TEST a_list_group_without_an_interface_still_takes_its_names(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g = make_group((firc_id_t){{1, 0, 0, 0}}, "g", true);
    ASSERT_EQ_FMTm("no interface set", (size_t)0, strlen(g->iface != NULL ? g->iface : ""), "%zu");
    add_group_list_rule(g, (firc_id_t){{1, 1, 0, 0}}, FIRC_RULE_DOMAIN, "list.example", true);
    firc_config_add_group(&cfg, g);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_EQ_FMT((size_t)1, snap->n_groups, "%zu");
    ASSERT(firc_matcher_match(snap->groups[0]->matcher, "list.example"));

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

TEST empty_config_yields_empty_snapshot(void)
{
    firc_config_t cfg = make_cfg();
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT(snap != NULL);
    ASSERT_EQ(0u, (unsigned)snap->n_groups);
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: the last matching group, or any, owning a name instead of the first in config order. */
TEST the_first_group_in_config_order_owns_the_name(void)
{
    firc_config_t cfg = make_cfg();

    firc_group_t *first = make_group((firc_id_t){{0x11, 0, 0, 0}}, "first", true);
    firc_group_add_rule(first, make_rule((firc_id_t){{0xaa, 0, 0, 0}}, FIRC_RULE_NAMESPACE, "example.com", true));
    firc_config_add_group(&cfg, first);

    firc_group_t *second = make_group((firc_id_t){{0x22, 0, 0, 0}}, "second", true);
    firc_group_add_rule(second, make_rule((firc_id_t){{0xbb, 0, 0, 0}}, FIRC_RULE_WILDCARD, "*.example.com", true));
    firc_config_add_group(&cfg, second);

    firc_group_t *third = make_group((firc_id_t){{0x33, 0, 0, 0}}, "third", true);
    firc_group_add_rule(third, make_rule((firc_id_t){{0xcc, 0, 0, 0}}, FIRC_RULE_DOMAIN, "other.test", true));
    firc_config_add_group(&cfg, third);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT(snap != NULL);

    const firc_group_snapshot_t *w = firc_ruleset_snapshot_first_match(snap, "www.example.com");
    ASSERT(w != NULL);
    ASSERT_STR_EQm("the earlier group wins, not the later one", "first", w->name);

    w = firc_ruleset_snapshot_first_match(snap, "other.test");
    ASSERT(w != NULL);
    ASSERT_STR_EQ("third", w->name);

    ASSERT_EQ(NULL, firc_ruleset_snapshot_first_match(snap, "unmatched.invalid"));

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a rule that fails to compile added silently to the matcher. */
TEST a_rule_that_cannot_compile_is_said_at_every_rebuild(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g = make_group((firc_id_t){{1, 0, 0, 0}}, "vpn", true);
    firc_group_add_rule(g, make_rule((firc_id_t){{1, 1, 0, 0}}, "regex", "^[a-z", true));
    firc_group_add_rule(g, make_rule((firc_id_t){{1, 2, 0, 0}}, "regex", "^(unclosed", true));
    firc_group_add_rule(g, make_rule((firc_id_t){{1, 3, 0, 0}}, "domain", "ok.example.com", true));
    firc_config_add_group(&cfg, g);

    for (int pass = 0; pass < 2; pass++) {
        int fds[2];
        ASSERT_EQ(0, pipe(fds));
        firc_log_set_level(FIRC_LOG_INFO);
        firc_log_set_fd(fds[1]);
        firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
        firc_log_set_fd(STDOUT_FILENO);
        close(fds[1]);
        char out[2048];
        ssize_t got = read(fds[0], out, sizeof(out) - 1);
        close(fds[0]);
        if (got < 0) { got = 0; }
        out[got] = '\0';
        ASSERT(snap != NULL);

        size_t lines = 0;
        for (const char *c = out; *c != '\0'; c++) {
            if (*c == '\n') { lines++; }
        }
        ASSERT_EQ_FMTm("one line per group, not one per rule and not none", (size_t)1, lines,
                       "%zu");
        ASSERTm("with the count", strstr(out, "2 rule(s)") != NULL);
        ASSERTm("naming the group", strstr(out, "vpn") != NULL);
        ASSERTm("and an example", strstr(out, "^[a-z") != NULL);

        ASSERT(firc_ruleset_snapshot_first_match(snap, "ok.example.com") != NULL);
        firc_ruleset_snapshot_free(snap);
    }
    firc_config_clear(&cfg);
    PASS();
}

TEST a_group_that_compiles_rebuilds_quietly(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g = make_group((firc_id_t){{1, 0, 0, 0}}, "fine", true);
    firc_group_add_rule(g, make_rule((firc_id_t){{1, 1, 0, 0}}, "regex", "^ok\\.example\\.com$", true));
    firc_config_add_group(&cfg, g);

    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    char out[1024];
    ssize_t got = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);
    if (got < 0) { got = 0; }
    ASSERT(snap != NULL);
    ASSERT_EQ_FMTm("nothing to say", (size_t)0, (size_t)got, "%zu");
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

static bool all_but_2(const firc_group_t *g, void *ud) {
    (void)ud;
    return g->id.b[0] != 2;
}

/* Catches: the view filter ignored, not applied to provisional, or NULL not meaning every group. */
TEST a_kept_out_group_is_out_of_the_view_and_of_provisional(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *g1 = make_group((firc_id_t){{1, 0, 0, 0}}, "one", true);
    firc_group_add_rule(g1, make_rule((firc_id_t){{1, 1, 0, 0}}, "domain", "a.example.com", true));
    firc_group_t *g2 = make_group((firc_id_t){{2, 0, 0, 0}}, "two", true);
    firc_group_add_rule(g2, make_rule((firc_id_t){{2, 1, 0, 0}}, "domain", "b.example.com", true));
    g2->list = firc_group_list_new();
    firc_config_add_group(&cfg, g1);
    firc_config_add_group(&cfg, g2);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build_where(&cfg, all_but_2, NULL);
    ASSERT(snap != NULL);
    ASSERT_EQ(1u, (unsigned)snap->n_groups);
    ASSERT(firc_ruleset_snapshot_first_match(snap, "a.example.com") != NULL);
    ASSERT_EQ(NULL, firc_ruleset_snapshot_first_match(snap, "b.example.com"));
    ASSERT_FALSEm("a group out of the view makes nothing provisional", snap->provisional);
    firc_ruleset_snapshot_free(snap);

    snap = firc_ruleset_snapshot_build_where(&cfg, NULL, NULL);
    ASSERT(snap != NULL);
    ASSERT_EQ(2u, (unsigned)snap->n_groups);
    ASSERT(snap->provisional);
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_rule_that_cannot_compile_is_said_at_every_rebuild);
    RUN_TEST(a_group_that_compiles_rebuilds_quietly);
    RUN_TEST(disabled_group_excluded);
    RUN_TEST(disabled_rule_excluded_from_matcher);
    RUN_TEST(multiple_groups_independently_match);
    RUN_TEST(the_first_group_in_config_order_owns_the_name);
    RUN_TEST(empty_config_yields_empty_snapshot);
    RUN_TEST(a_snapshot_with_two_holders_outlives_the_first_free);
    RUN_TEST(a_list_group_above_a_manual_group_owns_a_shared_name);
    RUN_TEST(a_manual_group_above_a_list_group_owns_a_shared_name);
    RUN_TEST(a_hand_rule_and_a_list_rule_of_one_group_give_one_owner);
    RUN_TEST(a_list_group_without_a_body_makes_the_snapshot_provisional);
    RUN_TEST(a_list_group_without_an_interface_still_takes_its_names);
    RUN_TEST(a_kept_out_group_is_out_of_the_view_and_of_provisional);
    GREATEST_MAIN_END();
}
