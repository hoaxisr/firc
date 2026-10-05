#include "greatest.h"

#include <string.h>

#include "firc/models.h"

TEST an_override_is_found_by_text(void) {
    firc_group_list_t *l = firc_group_list_new();
    ASSERT(l != NULL);
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"},
                                                    "domain", &off));

    const firc_sub_override_t *o = firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"});
    ASSERT(o != NULL);
    ASSERT_STR_EQ("domain", o->type);
    ASSERT(o->has_enable);
    ASSERT_FALSE(o->enable);
    ASSERT_EQ(NULL, firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "other.example.com"}));
    ASSERT_EQ(1, (int)l->n_overrides);

    firc_group_list_free(l);
    PASS();
}

TEST a_second_edit_updates_the_same_entry(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"},
                                                    NULL, &off));
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"},
                                                    "wildcard", NULL));

    ASSERT_EQ(1, (int)l->n_overrides);
    const firc_sub_override_t *o = firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"});
    ASSERT(o != NULL);
    ASSERT_STR_EQm("the second edit set it", "wildcard", o->type);
    ASSERTm("and the first edit is still there", o->has_enable);
    ASSERT_FALSE(o->enable);

    firc_group_list_free(l);
    PASS();
}

/* Catches: an override that overrides nothing kept in the config. */
TEST an_edit_back_to_nothing_removes_the_entry(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool off = false, on = true;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"},
                                                    NULL, &off));
    ASSERT_EQ(1, (int)l->n_overrides);

    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"},
                                                    "", &on));
    ASSERT_EQ(0, (int)l->n_overrides);
    ASSERT_EQ(NULL, firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"}));

    firc_group_list_free(l);
    PASS();
}

/* Catches: an off-by-one in compaction losing another rule's override. */
TEST removing_one_leaves_its_neighbours(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool off = false, on = true;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "a.example.com"},
                                                    NULL, &off));
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "b.example.com"},
                                                    NULL, &off));
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "c.example.com"},
                                                    NULL, &off));
    ASSERT_EQ(3, (int)l->n_overrides);

    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "b.example.com"},
                                                    NULL, &on));
    ASSERT_EQ(2, (int)l->n_overrides);
    ASSERT(firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "a.example.com"}) != NULL);
    ASSERT_EQ(NULL, firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "b.example.com"}));
    ASSERT(firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "c.example.com"}) != NULL);

    firc_group_list_free(l);
    PASS();
}

/* Catches: an override with an empty key accepted. */
TEST an_empty_text_is_refused(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool off = false;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = ""},
                                                           NULL, &off));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = NULL},
                                                           NULL, &off));
    ASSERT_EQ(0, (int)l->n_overrides);
    ASSERT_EQ(NULL, firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = NULL}));
    firc_group_list_free(l);
    PASS();
}

/* Catches: overrides lost when the array grows. */
TEST many_overrides_all_survive(void) {
    enum { N = 64 };
    firc_group_list_t *l = firc_group_list_new();
    bool off = false;
    for (int i = 0; i < N; i++) {
        char text[64];
        snprintf(text, sizeof(text), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK,
                  firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = text},
                                               NULL, &off));
    }
    ASSERT_EQ(N, (int)l->n_overrides);
    for (int i = 0; i < N; i++) {
        char text[64];
        snprintf(text, sizeof(text), "n%d.example.com", i);
        ASSERTm(text, firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = text}) != NULL);
    }
    firc_group_list_free(l);
    PASS();
}

static void mk(firc_sub_rules_t *rs, const char *type, const char *text, bool on) {
    firc_sub_rules_push(rs, text, type, on, firc_id_random());
}

TEST an_override_reaches_only_the_rule_with_its_spec(void) {
    firc_group_list_t *l = firc_group_list_new();
    ASSERT(l != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&l->rules, "10.0.0.0/8", FIRC_RULE_SUBNET, true,
                                                (firc_id_t){{1, 0, 0, 0}}, "tcp", "53"));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&l->rules, "10.0.0.0/8", FIRC_RULE_SUBNET, true,
                                                (firc_id_t){{2, 0, 0, 0}}, "udp", "53"));
    bool off = false;
    firc_sub_rule_key_t tcp = {
        .text = "10.0.0.0/8", .list_type = FIRC_RULE_SUBNET, .proto = "tcp", .ports = "53"};
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &tcp, NULL, &off));
    firc_sub_apply_overrides(l, &l->rules);
    ASSERT_FALSE(firc_sub_rules_enable(&l->rules, 0));
    ASSERT(firc_sub_rules_enable(&l->rules, 1));
    ASSERT(firc_group_list_find_override(
               l, &(firc_sub_rule_key_t){.text = "10.0.0.0/8", .list_type = FIRC_RULE_SUBNET}) == NULL);
    firc_group_list_free(l);
    PASS();
}

/* Catches: an override keyed without list_type switching both of a geosite pair. */
TEST an_override_reaches_only_the_rule_with_its_list_type(void) {
    firc_group_list_t *l = firc_group_list_new();
    ASSERT(l != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&l->rules, "a.com", FIRC_RULE_DOMAIN, true, (firc_id_t){{1, 0, 0, 0}}));
    ASSERT_EQ(FIRC_OK,
              firc_sub_rules_push(&l->rules, "a.com", FIRC_RULE_NAMESPACE, true, (firc_id_t){{2, 0, 0, 0}}));
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           l, &(firc_sub_rule_key_t){.text = "a.com", .list_type = FIRC_RULE_DOMAIN}, NULL,
                           &off));
    firc_sub_apply_overrides(l, &l->rules);
    ASSERT_FALSE(firc_sub_rules_enable(&l->rules, 0));
    ASSERTm("the namespace twin is untouched", firc_sub_rules_enable(&l->rules, 1));
    firc_group_list_free(l);
    PASS();
}

TEST an_override_reaches_the_rule_with_that_text(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"},
                                                    "domain", &off));

    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    mk(&rules, "namespace", "ads.example.com", true);
    mk(&rules, "namespace", "cdn.example.com", true);
    firc_sub_apply_overrides(l, &rules);

    ASSERT_STR_EQm("the type it was given", "domain", firc_sub_rules_type(&rules, 0));
    ASSERTm("the interned word, not the override's own string",
            firc_sub_rules_type(&rules, 0) == firc_rule_type_intern("domain"));
    ASSERT_FALSEm("and the enable it was given", firc_sub_rules_enable(&rules, 0));
    ASSERT_STR_EQm("the other rule is untouched", "namespace", firc_sub_rules_type(&rules, 1));
    ASSERT(firc_sub_rules_enable(&rules, 1));

    firc_sub_rules_free(&rules);
    firc_group_list_free(l);
    PASS();
}

TEST an_override_only_changes_what_it_carries(void) {
    firc_group_list_t *l = firc_group_list_new();
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"},
                                                    "wildcard", NULL));

    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    mk(&rules, "namespace", "ads.example.com", true);
    firc_sub_apply_overrides(l, &rules);

    ASSERT_STR_EQ("wildcard", firc_sub_rules_type(&rules, 0));
    ASSERTm("enable is left alone", firc_sub_rules_enable(&rules, 0));

    firc_sub_rules_free(&rules);
    firc_group_list_free(l);
    PASS();
}

/* Catches: an override for a line the list dropped applied elsewhere, or lost. */
TEST an_override_for_a_missing_line_changes_nothing(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "gone.example.com"},
                                                    NULL, &off));

    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    mk(&rules, "namespace", "ads.example.com", true);
    firc_sub_apply_overrides(l, &rules);

    ASSERT(firc_sub_rules_enable(&rules, 0));
    ASSERT_STR_EQ("namespace", firc_sub_rules_type(&rules, 0));
    ASSERT_EQ_FMTm("and the override is kept for when the line returns", 1,
                   (int)l->n_overrides, "%d");

    firc_sub_rules_free(&rules);
    firc_group_list_free(l);
    PASS();
}

/* Catches: an override matched by prefix instead of the whole text. */
TEST an_override_does_not_reach_a_rule_that_merely_starts_the_same(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"},
                                                    "domain", &off));

    ASSERT_EQ_FMTm("a longer name is not it", NULL,
                   (void *)firc_group_list_find_override(
                       l, &(firc_sub_rule_key_t){.text = "ads.example.com.evil.net"}),
                   "%p");
    ASSERT_EQ_FMTm("a sibling sharing a prefix is not it", NULL,
                   (void *)firc_group_list_find_override(
                       l, &(firc_sub_rule_key_t){.text = "adsfoo.example.com"}),
                   "%p");
    ASSERT_EQ_FMTm("a shorter name is not it", NULL,
                   (void *)firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "ads"}), "%p");
    ASSERT(firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "ads.example.com"}) != NULL);

    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    mk(&rules, "namespace", "adsfoo.example.com", true);
    mk(&rules, "namespace", "ads.example.com", true);
    firc_sub_apply_overrides(l, &rules);
    ASSERT_STR_EQm("the neighbour keeps its type", "namespace", firc_sub_rules_type(&rules, 0));
    ASSERTm("and its enable", firc_sub_rules_enable(&rules, 0));
    ASSERT_STR_EQ("domain", firc_sub_rules_type(&rules, 1));

    firc_sub_rules_free(&rules);
    firc_group_list_free(l);
    PASS();
}

/* Catches: an empty edit removing another rule's entry instead of its own. */
TEST an_empty_edit_removes_its_own_entry_and_no_other(void) {
    firc_group_list_t *l = firc_group_list_new();
    bool off = false, on = true;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "kept.example.com"},
                                                    NULL, &off));
    ASSERT_EQ(1, (int)l->n_overrides);

    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "new.example.com"},
                                                    "", &on));

    ASSERT_EQ_FMTm("the new one was not stored", 1, (int)l->n_overrides, "%d");
    ASSERTm("and the old one is still there",
            firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "kept.example.com"}) != NULL);
    ASSERT_EQ(NULL, firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "new.example.com"}));

    firc_group_list_free(l);
    PASS();
}

TEST a_key_naming_a_type_adopts_a_matching_legacy_entry(void) {
    firc_group_list_t *l = firc_group_list_new();
    ASSERT(l != NULL);
    bool off = false, on = true;
    ASSERT_EQ(FIRC_OK,
              firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "r"}, NULL, &off));
    ASSERT_EQ(1, (int)l->n_overrides);

    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           l, &(firc_sub_rule_key_t){.text = "r", .list_type = "domain"}, NULL, &on));
    ASSERTm("nothing left to disagree about: the legacy entry was adopted, not left behind",
            l->n_overrides == 0);
    ASSERT_EQ(NULL,
              firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "r", .list_type = "domain"}));

    firc_group_list_free(l);
    PASS();
}

TEST a_type_edit_adopts_a_legacy_entry_keeping_its_enable(void) {
    firc_group_list_t *l = firc_group_list_new();
    ASSERT(l != NULL);
    bool off = false;
    ASSERT_EQ(FIRC_OK,
              firc_group_list_set_override(l, &(firc_sub_rule_key_t){.text = "r"}, NULL, &off));

    ASSERT_EQ(FIRC_OK,
              firc_group_list_set_override(
                  l, &(firc_sub_rule_key_t){.text = "r", .list_type = "domain"}, "wildcard", NULL));
    ASSERT_EQ_FMTm("adopted in place, not appended", 1, (int)l->n_overrides, "%d");

    const firc_sub_override_t *o =
        firc_group_list_find_override(l, &(firc_sub_rule_key_t){.text = "r", .list_type = "domain"});
    ASSERT(o != NULL);
    ASSERT_STR_EQ("wildcard", o->type);
    ASSERTm("the enable opinion the legacy entry held survives the adoption", o->has_enable);
    ASSERT_FALSE(o->enable);

    firc_group_list_free(l);
    PASS();
}

/* Catches: find_override returning an earlier entry without list_type over an exact one. */
TEST find_override_prefers_an_exact_list_type_over_an_earlier_wildcard(void) {
    firc_group_list_t *l = firc_group_list_new();
    ASSERT(l != NULL);

    firc_sub_override_t *legacy = firc_sub_override_new();
    firc_sub_override_t *specific = firc_sub_override_new();
    ASSERT(legacy != NULL && specific != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&legacy->rule, "r"));
    ASSERT_EQ(FIRC_OK, firc_strset(&specific->rule, "r"));
    ASSERT_EQ(FIRC_OK, firc_strset(&specific->list_type, "domain"));
    ASSERT_EQ(FIRC_OK, firc_strset(&specific->type, "wildcard"));

    l->overrides = calloc(2, sizeof(*l->overrides));
    ASSERT(l->overrides != NULL);
    l->overrides[0] = legacy;
    l->overrides[1] = specific;
    l->n_overrides = 2;

    const firc_sub_override_t *o = firc_group_list_find_override(
        l, &(firc_sub_rule_key_t){.text = "r", .list_type = "domain"});
    ASSERTm("the specific entry is found, not the legacy one sitting before it", o != NULL);
    ASSERTm("it carries the type only the specific entry holds",
            o->type != NULL && strcmp(o->type, "wildcard") == 0);

    firc_group_list_free(l);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(an_override_is_found_by_text);
    RUN_TEST(a_second_edit_updates_the_same_entry);
    RUN_TEST(an_edit_back_to_nothing_removes_the_entry);
    RUN_TEST(removing_one_leaves_its_neighbours);
    RUN_TEST(an_empty_text_is_refused);
    RUN_TEST(many_overrides_all_survive);
    RUN_TEST(an_override_reaches_only_the_rule_with_its_spec);
    RUN_TEST(an_override_reaches_only_the_rule_with_its_list_type);
    RUN_TEST(an_override_reaches_the_rule_with_that_text);
    RUN_TEST(an_override_only_changes_what_it_carries);
    RUN_TEST(an_override_for_a_missing_line_changes_nothing);
    RUN_TEST(an_override_does_not_reach_a_rule_that_merely_starts_the_same);
    RUN_TEST(an_empty_edit_removes_its_own_entry_and_no_other);
    RUN_TEST(a_key_naming_a_type_adopts_a_matching_legacy_entry);
    RUN_TEST(a_type_edit_adopts_a_legacy_entry_keeping_its_enable);
    RUN_TEST(find_override_prefers_an_exact_list_type_over_an_earlier_wildcard);
    GREATEST_MAIN_END();
}
