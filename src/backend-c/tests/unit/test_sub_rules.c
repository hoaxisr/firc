#include "greatest.h"

#include <string.h>

#include "firc/id.h"
#include "firc/models.h"

static firc_id_t id_of(uint8_t b) { return (firc_id_t){{b, 0, 0, 0}}; }

TEST a_rule_reads_back_as_it_went_in(void) {
    firc_sub_rules_t rs;
    firc_sub_rules_init(&rs);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&rs, "ads.example.com", "namespace", true, id_of(1)));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&rs, "10.0.0.0/8", "subnet", false, id_of(2)));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&rs, "x", "nonsense", true, id_of(3)));
    ASSERT_EQ((size_t)3, rs.n);
    ASSERT_STR_EQ("ads.example.com", firc_sub_rules_text(&rs, 0));
    ASSERT_STR_EQ("10.0.0.0/8", firc_sub_rules_text(&rs, 1));
    ASSERT_STR_EQ("x", firc_sub_rules_text(&rs, 2));
    ASSERT(firc_sub_rules_type(&rs, 0) == firc_rule_type_intern("namespace"));
    ASSERT(firc_sub_rules_type(&rs, 1) == firc_rule_type_intern("subnet"));
    ASSERT_STR_EQm("a type the daemon has no name for is none", "", firc_sub_rules_type(&rs, 2));
    ASSERT(firc_sub_rules_enable(&rs, 0));
    ASSERT_FALSE(firc_sub_rules_enable(&rs, 1));
    ASSERT_EQ(2, firc_sub_rules_id(&rs, 1).b[0]);
    size_t at = 99;
    ASSERT(firc_sub_rules_find_id(&rs, id_of(3), &at));
    ASSERT_EQ((size_t)2, at);
    ASSERT_FALSE(firc_sub_rules_find_id(&rs, id_of(4), &at));
    firc_sub_rules_free(&rs);
    ASSERT_EQ((size_t)0, rs.n);
    PASS();
}

/* Catches: rule text lost when the arena grows or shrinks. */
TEST the_arena_survives_growing_and_shrinking(void) {
    firc_sub_rules_t rs;
    firc_sub_rules_init(&rs);
    char text[64];
    for (int i = 0; i < 5000; i++) {
        snprintf(text, sizeof(text), "n%d.ads%d.example.com", i, i % 13);
        ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&rs, text, "namespace", i % 2 == 0, id_of((uint8_t)i)));
    }
    ASSERT(rs.text_cap > rs.text_len);
    firc_sub_rules_shrink(&rs);
    ASSERT_EQ(rs.text_len, rs.text_cap);
    ASSERT_EQ(rs.n, rs.cap);
    for (int i = 0; i < 5000; i++) {
        snprintf(text, sizeof(text), "n%d.ads%d.example.com", i, i % 13);
        ASSERT_STR_EQ(text, firc_sub_rules_text(&rs, (size_t)i));
        ASSERT_EQ(i % 2 == 0, firc_sub_rules_enable(&rs, (size_t)i));
    }
    firc_sub_rules_free(&rs);
    PASS();
}

TEST a_copy_is_its_own_and_a_move_leaves_nothing(void) {
    firc_sub_rules_t a, b, c;
    firc_sub_rules_init(&a);
    firc_sub_rules_init(&b);
    firc_sub_rules_init(&c);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&a, "one.example", "domain", true, id_of(1)));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&a, "two.example", "namespace", false, id_of(2)));

    ASSERT_EQ(FIRC_OK, firc_sub_rules_copy(&b, &a));
    ASSERT_EQ((size_t)2, b.n);
    ASSERT(b.text != a.text);
    ASSERT_STR_EQ("two.example", firc_sub_rules_text(&b, 1));
    firc_sub_rules_set_type(&b, 1, "wildcard");
    ASSERT_STR_EQm("the original is untouched by an edit to the copy", "namespace",
                   firc_sub_rules_type(&a, 1));

    firc_sub_rules_move(&c, &a);
    ASSERT_EQ((size_t)0, a.n);
    ASSERT(a.text == NULL);
    ASSERT_EQ((size_t)2, c.n);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&c, 0));

    ASSERT_EQ(FIRC_OK, firc_sub_rules_copy(&b, &a));
    ASSERT_EQ((size_t)0, b.n);

    firc_sub_rules_free(&a);
    firc_sub_rules_free(&b);
    firc_sub_rules_free(&c);
    PASS();
}

/* Catches: a spec lost, stored under the wrong rule, grown by a plain push, or moved by set_type. */
TEST a_spec_reads_back_with_its_rule(void) {
    firc_sub_rules_t rs;
    firc_sub_rules_init(&rs);
    firc_id_t a = {{1, 0, 0, 0}}, b = {{2, 0, 0, 0}}, c = {{3, 0, 0, 0}};
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&rs, "a.example", FIRC_RULE_DOMAIN, true, a));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&rs, "10.0.0.0/8", FIRC_RULE_SUBNET, true, b,
                                                "udp", "50000-50099,19200-19400"));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&rs, "10.1.0.0/16", FIRC_RULE_SUBNET, true, c, "", NULL));

    ASSERT_EQ(NULL, firc_sub_rules_proto(&rs, 0));
    ASSERT_EQ(NULL, firc_sub_rules_ports(&rs, 0));
    ASSERT_STR_EQ("10.0.0.0/8", firc_sub_rules_text(&rs, 1));
    ASSERT_STR_EQ("udp", firc_sub_rules_proto(&rs, 1));
    ASSERT_STR_EQ("50000-50099,19200-19400", firc_sub_rules_ports(&rs, 1));
    ASSERTm("an empty spec is no spec", firc_sub_rules_proto(&rs, 2) == NULL);
    ASSERT_EQ(0, rs.v[2].flags);
    ASSERT_STR_EQm("the next rule starts after the spec", "10.1.0.0/16", firc_sub_rules_text(&rs, 2));

    firc_sub_rules_t cp;
    firc_sub_rules_init(&cp);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_copy(&cp, &rs));
    firc_sub_rules_shrink(&cp);
    ASSERT_STR_EQ("50000-50099,19200-19400", firc_sub_rules_ports(&cp, 1));

    firc_sub_rules_set_type(&rs, 0, FIRC_RULE_NAMESPACE);
    ASSERT_STR_EQ(FIRC_RULE_NAMESPACE, firc_sub_rules_type(&rs, 0));
    ASSERT_STR_EQm("the list's own type does not move", FIRC_RULE_DOMAIN, firc_sub_rules_list_type(&rs, 0));

    firc_sub_rules_free(&cp);
    firc_sub_rules_free(&rs);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_rule_reads_back_as_it_went_in);
    RUN_TEST(the_arena_survives_growing_and_shrinking);
    RUN_TEST(a_copy_is_its_own_and_a_move_leaves_nothing);
    RUN_TEST(a_spec_reads_back_with_its_rule);
    GREATEST_MAIN_END();
}
