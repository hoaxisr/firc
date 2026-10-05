#include "greatest.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "firc/subparse.h"
#include "firc/match.h"
#include "firc/log.h"

/* Asks only "same?": a failure to tell reads as a difference here, never in the daemon. */
static bool same_rules(const firc_sub_rules_t *left, const firc_sub_rules_t *right) {
    bool same = false;
    return firc_sub_same_rules_checked(left, right, &same) == FIRC_OK && same;
}

TEST type_detection(void)
{
    ASSERT_STR_EQ("namespace", firc_sub_detect_type("example.com"));
    ASSERT_STR_EQ("namespace", firc_sub_detect_type("sub.example.net"));
    ASSERT_STR_EQ("subnet", firc_sub_detect_type("10.0.0.0/8"));
    ASSERT_STR_EQ("subnet", firc_sub_detect_type("192.168.1.1"));
    ASSERT_STR_EQ("subnet6", firc_sub_detect_type("fd00::/8"));
    ASSERT_STR_EQ("subnet6", firc_sub_detect_type("2001:db8::1"));
    ASSERT_STR_EQ("wildcard", firc_sub_detect_type("*.example.com"));
    ASSERT_STR_EQ("regex", firc_sub_detect_type("^example\\.com$"));
    ASSERT_STR_EQ("namespace", firc_sub_detect_type("300.1.2.3"));
    PASS();
}

/* Catches: an underscore label or a trailing dot guessed as an unanchored regex that routes other names. */
TEST a_name_a_list_carries_is_not_guessed_to_be_a_regex(void) {
    ASSERT_STR_EQm("an underscore label is an ordinary name", "namespace",
                   firc_sub_detect_type("_dmarc.example.com"));
    ASSERT_STR_EQm("and so is _acme-challenge", "namespace",
                   firc_sub_detect_type("_acme-challenge.example.com"));
    ASSERT_STR_EQm("a root dot is folded, not promoted", "namespace",
                   firc_sub_detect_type("example.com."));
    PASS();
}

/* Catches: a wildcard such as `a*.` typed as a regex because it happens to compile. */
TEST a_wildcard_that_compiles_as_a_regex_is_still_a_wildcard(void) {
    ASSERT_STR_EQ("wildcard", firc_sub_detect_type("*.example.com"));
    ASSERT_STR_EQ("wildcard", firc_sub_detect_type("a*.example.com"));
    ASSERT_STR_EQ("wildcard", firc_sub_detect_type("a?.example.com"));
    PASS();
}

/* Catches: an unrecognisable line, such as a raw UTF-8 name, promoted to a regex. */
TEST a_line_that_is_nothing_recognisable_is_refused(void) {
    ASSERT_STR_EQm("an IDN as typed cannot be queried at all", "",
                   firc_sub_detect_type("\xd1\x8f\xd0\xbd\xd0\xb4\xd0\xb5\xd0\xba\xd1\x81.com"));
    ASSERT_STR_EQm("a URL is not a name", "", firc_sub_detect_type("https://vk.com"));
    ASSERT_STR_EQ("", firc_sub_detect_type("user@example.com"));
    ASSERT_STR_EQ("regex", firc_sub_detect_type("^example\\.com$"));
    ASSERT_STR_EQ("regex", firc_sub_detect_type("^r[0-9]+\\.example\\.io$"));
    ASSERT_STR_EQm("a class", "regex", firc_sub_detect_type("^r[0-9]\\.example\\.io$"));
    ASSERT_STR_EQm("an alternation inside a group", "regex",
                   firc_sub_detect_type("^(a|b)\\.example\\.com$"));
    ASSERT_STR_EQm("a group", "regex", firc_sub_detect_type("^(a|b)\\.example\\.com$"));
    ASSERT_STR_EQm("a repetition count", "regex", firc_sub_detect_type("^ab{2}\\.example\\.com$"));
    ASSERT_STR_EQm("an escape", "regex", firc_sub_detect_type("^a\\d\\.example\\.com$"));
    PASS();
}

/* Catches: a line like `||example.com^` stored as a regex whose empty branch matches every name. */
TEST a_pattern_that_matches_anything_is_not_a_rule(void) {
    const char *never[] = {
        "^|$",
        "^.*$",
        "^.+$",
        "^a|b\\.example\\.com$",
        "||example.com^",
        "[Adblock Plus 2.0]",
        "^$",
        "^\\d*$",
        "^[a-z]$",
        "^[a-z0-9]+$",
        "^[a-z-]+\\.[a-z]+$",
        "^\\w+\\.\\w+$",
        "^\\w+\\.\\w+\\.\\w+$",
        "^.+\\..+\\..+$",
        "^.+\\..+$",
    };
    for (size_t i = 0; i < sizeof(never) / sizeof(never[0]); i++) {
        ASSERT_STR_EQm(never[i], "", firc_sub_detect_type(never[i]));
    }
    ASSERT_STR_EQ("regex", firc_sub_detect_type("^example\\.com$"));
    ASSERT_STR_EQ("regex", firc_sub_detect_type("^(a|b)\\.example\\.com$"));
    PASS();
}

/* Catches: a line with a PCRE2 control verb such as (*ACCEPT), hidden or not, typed as a regex. */
TEST a_control_verb_is_not_a_rule(void) {
    const char *verbs[] = {
        "^ads(*ACCEPT)$",
        "^vk(*ACCEPT)$",
        "^a(*ACCEPT)b$",
        "^(*ACCEPT)$",
        "^x(*SKIP)y$",
        "^x(*THEN)y$",
    };
    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
        ASSERT_STR_EQm(verbs[i], "", firc_sub_detect_type(verbs[i]));
    }
    ASSERT_STR_EQm("hidden behind an inline comment", "",
                   firc_sub_detect_type("^ads(?#[)(*ACCEPT)$"));
    ASSERT_STR_EQm("hidden behind a quoted run", "",
                   firc_sub_detect_type("^ads\\Q[\\E(*ACCEPT)$"));

    ASSERT_STR_EQ("regex", firc_sub_detect_type("^(a|b)\\.example\\.com$"));
    ASSERT_STR_EQ("regex", firc_sub_detect_type("^a\\*b\\.example\\.com$"));
    PASS();
}

/* Catches: the usability check run on the bare line, storing a wrapped pattern that never compiles. */
TEST a_pattern_that_only_compiles_unwrapped_is_dropped(void) {
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules("^abc\\Q\\Z\n"
                                            "^(?x)abc #$\n"
                                            "^ok\\.example\\.com$\n",
                                            &rules));
    ASSERT_EQ_FMTm("only the one that survives wrapping", (size_t)1, rules.n, "%zu");
    ASSERT_STR_EQ("\\A(?:^ok\\.example\\.com$)\\z", firc_sub_rules_text(&rules, 0));
    firc_rule_matcher_t *m = firc_rule_matcher_new(FIRC_RULE_REGEX, firc_sub_rules_text(&rules, 0));
    ASSERT(m != NULL);
    ASSERT(firc_rule_matcher_ok(m));
    firc_rule_matcher_free(m);
    firc_sub_rules_free(&rules);
    PASS();
}

TEST derived_regex_is_anchored_by_construction(void) {
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules("^v|q$\n^example\\.com$", &rules));
    ASSERT_EQ(2, (int)rules.n);

    ASSERT_STR_EQ("regex", firc_sub_rules_type(&rules, 0));
    ASSERT_STR_EQm("wrapped, not stored as written", "\\A(?:^v|q$)\\z", firc_sub_rules_text(&rules, 0));
    firc_rule_matcher_t *m = firc_rule_matcher_new(FIRC_RULE_REGEX, firc_sub_rules_text(&rules, 0));
    ASSERT(m != NULL);
    ASSERT_FALSEm("vk.com must not route", firc_rule_matcher_match(m, "vk.com"));
    ASSERT_FALSEm("nor anything ending in q", firc_rule_matcher_match(m, "example.q"));
    ASSERTm("what the line did claim still matches", firc_rule_matcher_match(m, "v"));
    firc_rule_matcher_free(m);

    m = firc_rule_matcher_new(FIRC_RULE_REGEX, firc_sub_rules_text(&rules, 1));
    ASSERT(m != NULL);
    ASSERT(firc_rule_matcher_match(m, "example.com"));
    ASSERT_FALSE(firc_rule_matcher_match(m, "not-example.com"));
    firc_rule_matcher_free(m);

    firc_sub_rules_free(&rules);
    PASS();
}

TEST an_unanchored_line_is_never_called_a_regex(void) {
    ASSERT_STR_EQm("adblock syntax is not a regex", "", firc_sub_detect_type("||example.com^"));
    ASSERT_STR_EQm("nor with options", "",
                   firc_sub_detect_type("||ads.example.com^$third-party"));
    ASSERT_STR_EQm("a bare alternation is not intent", "",
                   firc_sub_detect_type("a|b.example.com"));
    ASSERT_STR_EQ("", firc_sub_detect_type("example.com|"));
    ASSERT_STR_EQm("nor an unanchored class", "", firc_sub_detect_type("r[0-9]\\.example\\.io"));
    ASSERT_STR_EQm("anchored at the head only", "", firc_sub_detect_type("^ads"));
    ASSERT_STR_EQm("anchored at the tail only", "", firc_sub_detect_type("example\\.com$"));
    ASSERT_STR_EQ("regex", firc_sub_detect_type("^example\\.com$"));
    ASSERT_STR_EQ("regex", firc_sub_detect_type("^r[0-9]+\\.example\\.io$"));
    PASS();
}

/* Catches: an untyped line stored with type "", which makes every Save of the group a 400. */
TEST a_line_with_no_type_is_dropped(void) {
    const char *list =
        "example.com\n"
        "0.0.0.0 tracker.example\n"
        "||ads.example.net^\n"
        "https://vk.com\n"
        "aa:bb:cc:dd:ee:ff\n"
        "010.0.0.1\n"
        ":::\n"
        "good.example.org\n";
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules(list, &rules));
    ASSERT_EQ_FMTm("only the two that are names", (size_t)2, rules.n, "%zu");
    for (size_t i = 0; i < rules.n; i++) {
        ASSERTm("and every one kept has a type",
                firc_sub_rules_type(&rules, i) != NULL && firc_sub_rules_type(&rules, i)[0] != '\0');
    }
    firc_sub_rules_free(&rules);
    PASS();
}

/* Catches: a stored unanchored regex from an older derivation kept instead of re-derived on sync. */
TEST a_legacy_unanchored_regex_is_re_derived_on_sync(void) {
    firc_sub_rules_t old;
    firc_sub_rules_init(&old);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "_dmarc.example.com", "namespace", true, firc_id_random()));
    firc_sub_rules_set_type(&old, 0, "regex");

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("_dmarc.example.com\n", &old, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_STR_EQm("re-derived as the name it is", "namespace", firc_sub_rules_type(&out, 0));
    firc_sub_rules_free(&out);
    firc_sub_rules_free(&old);
    PASS();
}

/* Catches: a wrapped regex not matched to its stored unwrapped form, losing its id and enable flag. */
TEST the_wrap_does_not_lose_what_the_operator_set(void) {
    firc_sub_rules_t old;
    firc_sub_rules_init(&old);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "^v|q$", "regex", false, (firc_id_t){{0, 0, 0, 7}}));

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("^v|q$\n", &old, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_STR_EQm("stored wrapped from now on", "\\A(?:^v|q$)\\z", firc_sub_rules_text(&out, 0));
    ASSERT_FALSEm("and it stays off", firc_sub_rules_enable(&out, 0));
    ASSERT_EQ_FMTm("and keeps its id", 7, (int)firc_sub_rules_id(&out, 0).b[3], "%d");

    firc_sub_rules_free(&out);
    firc_sub_rules_free(&old);
    PASS();
}

/* Catches: a rule stored wrapped not found again by the next sync. */
TEST a_wrapped_rule_matches_itself_on_the_next_sync(void) {
    firc_sub_rules_t old;
    firc_sub_rules_init(&old);
    ASSERT_EQ(FIRC_OK,
              firc_sub_rules_push(&old, "\\A(?:^v|q$)\\z", "regex", false, (firc_id_t){{0, 0, 0, 9}}));

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("^v|q$\n", &old, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_FALSEm("still off", firc_sub_rules_enable(&out, 0));
    ASSERT_EQ_FMTm("still its id", 9, (int)firc_sub_rules_id(&out, 0).b[3], "%d");
    firc_sub_rules_free(&out);
    firc_sub_rules_free(&old);
    PASS();
}

/* Catches: an operator's stored type that cannot work (subnet on a name) restored on every sync. */
TEST an_unusable_stored_type_is_not_restored(void) {
    firc_sub_rules_t old;
    firc_sub_rules_init(&old);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "example.com", "namespace", true, firc_id_random()));
    firc_sub_rules_set_type(&old, 0, "subnet");

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("example.com\n", &old, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_STR_EQm("re-derived, not locked", "namespace", firc_sub_rules_type(&out, 0));
    ASSERTm("and it is a rule the API would take",
            firc_rule_is_usable(firc_sub_rules_type(&out, 0), firc_sub_rules_text(&out, 0), NULL));
    firc_sub_rules_free(&out);
    firc_sub_rules_free(&old);
    PASS();
}

/* Catches: a type the operator chose overwritten by the guess on sync. */
TEST an_operator_s_chosen_type_survives_a_sync(void) {
    firc_sub_rules_t old;
    firc_sub_rules_init(&old);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "example.com", "namespace", true, firc_id_random()));
    firc_sub_rules_set_type(&old, 0, "domain");

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("example.com\n", &old, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_STR_EQm("kept", "domain", firc_sub_rules_type(&out, 0));
    firc_sub_rules_free(&out);
    firc_sub_rules_free(&old);
    PASS();
}

TEST parse_dedup_and_comments(void)
{
    const char *list =
        "# comment\n"
        "example.com\n"
        "example.com\n"
        "  spaced.example.com  \n"
        "\n"
        "a.com,b.com\r\nc.com";
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules(list, &rules));
    ASSERT_EQ(5u, (unsigned)rules.n);
    ASSERT_STR_EQ("example.com", firc_sub_rules_text(&rules, 0));
    ASSERT_STR_EQ("spaced.example.com", firc_sub_rules_text(&rules, 1));
    ASSERT_STR_EQ("a.com", firc_sub_rules_text(&rules, 2));
    ASSERT_STR_EQ("b.com", firc_sub_rules_text(&rules, 3));
    ASSERT_STR_EQ("c.com", firc_sub_rules_text(&rules, 4));
    for (size_t i = 0; i < rules.n; i++) {
        ASSERT(firc_sub_rules_enable(&rules, i));
        ASSERT_FALSE(firc_id_is_zero(firc_sub_rules_id(&rules, i)));
    }
    firc_sub_rules_free(&rules);
    PASS();
}

TEST refresh_preserves_existing_overrides(void)
{
    firc_sub_rules_t existing;
    firc_sub_rules_init(&existing);
    firc_id_t ex0_id = {{0xaa, 0xbb, 0xcc, 0xdd}};
    firc_id_t ex1_id = {{0x11, 0x22, 0x33, 0x44}};
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, "example.com", "namespace", false, ex0_id));
    firc_sub_rules_set_type(&existing, 0, "domain");
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, "*.example.org", "wildcard", true, ex1_id));

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("example.com\nsub.example.net\n",
                                          &existing, &out));
    ASSERT_EQ(2u, (unsigned)out.n);
    ASSERT_STR_EQ("example.com", firc_sub_rules_text(&out, 0));
    ASSERT(firc_id_equal(firc_sub_rules_id(&out, 0), ex0_id));
    ASSERT_STR_EQ("domain", firc_sub_rules_type(&out, 0));
    ASSERT_FALSE(firc_sub_rules_enable(&out, 0));
    ASSERT_STR_EQ("sub.example.net", firc_sub_rules_text(&out, 1));
    ASSERT_FALSE(firc_id_is_zero(firc_sub_rules_id(&out, 1)));
    ASSERT(firc_sub_rules_enable(&out, 1));

    firc_sub_rules_free(&existing);
    firc_sub_rules_free(&out);
    PASS();
}

TEST same_rules_ignores_order(void)
{
    firc_sub_rules_t left, right;
    firc_sub_rules_init(&left);
    firc_sub_rules_init(&right);
    firc_id_t l0_id = {{1, 2, 3, 4}};
    firc_id_t l1_id = {{5, 6, 7, 8}};
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&left, "example.com", "domain", true, l0_id));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&left, "*.example.org", "wildcard", false, l1_id));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&right, "*.example.org", "wildcard", false, l1_id));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&right, "example.com", "domain", true, l0_id));

    ASSERT(same_rules(&left, &right));

    right.v[1].enable = false;
    ASSERT_FALSE(same_rules(&left, &right));

    firc_sub_rules_free(&left);
    firc_sub_rules_free(&right);
    PASS();
}

TEST is_due_logic(void)
{
    firc_group_list_t *l = firc_group_list_new();
    ASSERT(l != NULL);
    bool enable = true;
    firc_strset(&l->url, "https://example.com/list.txt");
    l->interval = 3600;
    l->last_update = 0;
    l->last_check = 0;
    ASSERT(firc_sub_is_due(enable, l, 1000000));
    l->last_check = 999000;
    ASSERT_FALSE(firc_sub_is_due(enable, l, 1000000));
    ASSERT(firc_sub_is_due(enable, l, 999000 + 3600));
    enable = false;
    ASSERT_FALSE(firc_sub_is_due(enable, l, 999000 + 7200));
    enable = true;
    l->interval = 0;
    ASSERT_FALSE(firc_sub_is_due(enable, l, 999000 + 7200));
    firc_group_list_free(l);
    PASS();
}

/* A list of `n` distinct names, one per line. */
static char *name_list(size_t n) {
    size_t cap = n * 24 + 1;
    char *list = malloc(cap);
    if (list == NULL) { return NULL; }
    size_t at = 0;
    for (size_t i = 0; i < n; i++) {
        at += (size_t)snprintf(list + at, cap - at, "host%07zu.example.com\n", i);
    }
    return list;
}

static double seconds_to_parse(size_t n, size_t *out_rules) {
    char *list = name_list(n);
    if (list == NULL) { return -1.0; }
    struct timespec t0, t1;
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_err_t err = firc_sub_parse_rules(list, &rules);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    size_t got = rules.n;
    firc_sub_rules_free(&rules);
    free(list);
    if (out_rules != NULL) { *out_rules = got; }
    if (err != FIRC_OK) { return -1.0; }
    return (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
}

/* Catches: a quadratic parse, which blocks the loop thread for minutes on a large list. */
TEST a_big_list_does_not_take_the_thread_for_seconds(void) {
    size_t got = 0;
    (void)seconds_to_parse(20000, &got);
    double small = seconds_to_parse(50000, &got);
    ASSERT_EQ_FMTm("every line is a rule", (size_t)50000, got, "%zu");
    double large = seconds_to_parse(200000, &got);
    ASSERT_EQ_FMTm("every line is a rule", (size_t)200000, got, "%zu");
    ASSERT(small > 0.0 && large > 0.0);
    ASSERTm("four times the lines must not cost sixteen times the time", large / small < 8.0);
    PASS();
}

/* Catches: a regex line split at the comma in `{1,3}` instead of kept whole. */
TEST a_comma_inside_a_repetition_count_is_not_a_separator(void) {
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules("^ads[0-9]{1,3}\\.example\\.com$\n"
                                            "^cdn\\d{2,4}\\.example\\.net$\n"
                                            "a.example.com,b.example.com\n",
                                            &rules));
    ASSERT_EQ_FMTm("two regexes and two names", (size_t)4, rules.n, "%zu");
    ASSERT_STR_EQ("regex", firc_sub_rules_type(&rules, 0));
    ASSERT_STR_EQm("kept whole", "\\A(?:^ads[0-9]{1,3}\\.example\\.com$)\\z",
                   firc_sub_rules_text(&rules, 0));
    ASSERT_STR_EQ("regex", firc_sub_rules_type(&rules, 1));
    ASSERT_STR_EQm("still split when the line is not a rule", "namespace", firc_sub_rules_type(&rules, 2));
    ASSERT_STR_EQ("a.example.com", firc_sub_rules_text(&rules, 2));
    ASSERT_STR_EQ("b.example.com", firc_sub_rules_text(&rules, 3));
    firc_sub_rules_free(&rules);
    PASS();
}

/* Catches: the dropped count counting the pieces of split lines instead of lines. */
TEST the_dropped_count_counts_lines(void) {
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules_counted("0.0.0.0 tracker.example,also junk\n"
                                                    "ok.example.com\n",
                                                    &rules, &dropped));
    ASSERT_EQ_FMT((size_t)1, rules.n, "%zu");
    ASSERT_EQ_FMTm("one line was junk, not the two pieces it was cut into", (size_t)1, dropped, "%zu");
    firc_sub_rules_free(&rules);
    PASS();
}

/* Catches: a list line stored unfolded, or two lines that fold alike stored as two rules. */
TEST a_list_line_is_stored_folded_like_a_query(void) {
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules("Google.COM.\n"
                                            "google.com\n"
                                            "*.Example.COM\n"
                                            "^Ads[0-9]+\\.example\\.com$\n",
                                            &rules));
    ASSERT_EQ_FMTm("two forms of one name are one rule", (size_t)3, rules.n, "%zu");
    ASSERT_STR_EQ("google.com", firc_sub_rules_text(&rules, 0));
    ASSERT_STR_EQ("namespace", firc_sub_rules_type(&rules, 0));
    ASSERT_STR_EQ("*.example.com", firc_sub_rules_text(&rules, 1));
    ASSERT_STR_EQ("wildcard", firc_sub_rules_type(&rules, 1));
    ASSERT_STR_EQ("\\A(?:^Ads[0-9]+\\.example\\.com$)\\z", firc_sub_rules_text(&rules, 2));
    firc_sub_rules_free(&rules);
    PASS();
}

/* Catches: a rule's type copied per rule instead of pointing at the one interned word. */
TEST the_type_is_one_word_shared_by_every_rule(void) {
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules("a.example.com\nb.example.com\n", &rules));
    ASSERT_EQ((size_t)2, rules.n);
    ASSERT(firc_sub_rules_type(&rules, 0) == firc_sub_rules_type(&rules, 1));
    ASSERT(firc_sub_rules_type(&rules, 0) == firc_rule_type_intern("namespace"));
    ASSERT_STR_EQ("", firc_rule_type_intern("nonsense"));
    ASSERT_STR_EQ("", firc_rule_type_intern(NULL));
    firc_sub_rules_free(&rules);
    PASS();
}

/* Catches: comments, blanks, repeats or split lines counted as dropped, warning on a clean list. */
TEST an_ordinary_list_is_parsed_without_complaint(void) {
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules_counted("# a comment\n"
                                                    "\n"
                                                    "a.example.com,b.example.com\n"
                                                    "a.example.com\n"
                                                    "^ok\\.example\\.com$\n",
                                                    &rules, &dropped));
    ASSERT_EQ_FMTm("the duplicate collapsed", (size_t)3, rules.n, "%zu");
    ASSERT_EQ_FMTm("and nothing counted as junk", (size_t)0, dropped, "%zu");
    firc_sub_rules_free(&rules);
    PASS();
}

/* Seconds to resync `n` names against their stored parse; `*out_kept` says ids and flags survived. */
static double seconds_to_resync(size_t n, bool *out_kept) {
    char *list = name_list(n);
    if (list == NULL) { return -1.0; }
    firc_sub_rules_t stored;
    firc_sub_rules_init(&stored);
    if (firc_sub_parse_rules(list, &stored) != FIRC_OK || stored.n != n) {
        firc_sub_rules_free(&stored);
        free(list);
        return -1.0;
    }
    stored.v[0].enable = false;
    firc_id_t kept = firc_sub_rules_id(&stored, 0);

    struct timespec t0, t1;
    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_err_t err = firc_sub_refresh_rules(list, &stored, &out);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (out_kept != NULL) {
        *out_kept = err == FIRC_OK && out.n == n && firc_id_equal(firc_sub_rules_id(&out, 0), kept) &&
                    !firc_sub_rules_enable(&out, 0);
    }
    firc_sub_rules_free(&out);
    firc_sub_rules_free(&stored);
    free(list);
    if (err != FIRC_OK) { return -1.0; }
    return (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
}

/* Catches: rules compared as a set of keys, so a repeated rule with two ids differs from itself. */
TEST a_repeated_rule_is_compared_occurrence_by_occurrence(void) {
    firc_sub_rules_t left, right;
    firc_sub_rules_init(&left);
    firc_sub_rules_init(&right);
    firc_sub_rules_t *all[2] = {&left, &right};
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ(FIRC_OK, firc_sub_rules_push(all[i], "dup.example.com", "namespace", true,
                                               (firc_id_t){{0, 0, 0, 1}}));
        ASSERT_EQ(FIRC_OK, firc_sub_rules_push(all[i], "dup.example.com", "namespace", true,
                                               (firc_id_t){{0, 0, 0, 2}}));
    }
    ASSERTm("two occurrences, the same two on both sides: nothing changed",
            same_rules(&left, &right));

    ASSERTm("an array has not changed from itself",
            same_rules(&left, &left));

    right.v[1].id.b[3] = 3;
    ASSERTm("one occurrence carries a different id", !same_rules(&left, &right));

    right.v[0].id.b[3] = 1;
    right.v[1].id.b[3] = 1;
    ASSERTm("the same key twice is not the same as two different ids",
            !same_rules(&left, &right));

    right.v[0].id.b[3] = 1;
    right.v[1].id.b[3] = 2;
    right.v[1].enable = false;
    ASSERTm("one occurrence is disabled on one side", !same_rules(&left, &right));

    firc_sub_rules_free(&left);
    firc_sub_rules_free(&right);
    PASS();
}

/* Seconds for firc_sub_same_rules_checked over two parses of the same list. */
static double seconds_to_compare(size_t n, bool *out_same) {
    char *list = name_list(n);
    if (list == NULL) { return -1.0; }
    firc_sub_rules_t a, b;
    firc_sub_rules_init(&a);
    firc_sub_rules_init(&b);
    if (firc_sub_parse_rules(list, &a) != FIRC_OK) {
        firc_sub_rules_free(&a);
        free(list);
        return -1.0;
    }
    if (firc_sub_refresh_rules(list, &a, &b) != FIRC_OK) {
        firc_sub_rules_free(&b);
        firc_sub_rules_free(&a);
        free(list);
        return -1.0;
    }
    struct timespec t0, t1;
    bool same = true;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int rep = 0; rep < 20; rep++) {
        same = same_rules(&a, &b) && same;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (out_same != NULL) { *out_same = same; }
    firc_sub_rules_free(&a);
    firc_sub_rules_free(&b);
    free(list);
    return (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
}

/* The best of `trials` timings, to keep scheduler noise out of the ratio. */
static double best_of(size_t n, int trials) {
    double best = -1.0;
    for (int i = 0; i < trials; i++) {
        bool same = false;
        double t = seconds_to_compare(n, &same);
        if (t > 0.0 && (best < 0.0 || t < best)) { best = t; }
    }
    return best;
}

/* Catches: a quadratic same-rules check after a sync. */
TEST deciding_a_sync_changed_nothing_is_linear(void) {
    bool same = false;
    (void)seconds_to_compare(4000, &same);
    double small = seconds_to_compare(8000, &same);
    ASSERTm("a sync that changed nothing says so", same);
    ASSERTm("8 000 rules must not take seconds to compare", small < 2.0);
    double large = seconds_to_compare(32000, &same);
    ASSERTm("a sync that changed nothing says so", same);
    ASSERT(small > 0.0 && large > 0.0);

    if (large / small >= 12.0 && large < 2.0) {
        small = best_of(8000, 5);
        large = best_of(32000, 5);
        ASSERT(small > 0.0 && large > 0.0);
    }
    ASSERTm("four times the rules must not cost sixteen times the time", large / small < 12.0);
    PASS();
}

/* Catches: a quadratic match of parsed against stored rules on resync. */
TEST a_big_resync_does_not_take_the_thread_for_seconds(void) {
    bool kept = false;
    (void)seconds_to_resync(8000, &kept);
    double small = seconds_to_resync(16000, &kept);
    ASSERTm("the stored id and flag survive a re-sync", kept);
    double large = seconds_to_resync(64000, &kept);
    ASSERTm("the stored id and flag survive a re-sync", kept);
    ASSERT(small > 0.0 && large > 0.0);
    ASSERTm("four times the rules must not cost sixteen times the time", large / small < 8.0);
    PASS();
}

/* Catches: the last of two stored rules with one text matched, handing over the wrong enable flag. */
TEST the_first_stored_rule_of_a_text_is_the_one_matched(void) {
    firc_sub_rules_t existing;
    firc_sub_rules_init(&existing);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, "dup.example.com", "namespace", false,
                                           (firc_id_t){{0, 0, 0, 11}}));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, "dup.example.com", "namespace", true,
                                           (firc_id_t){{0, 0, 0, 22}}));

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("dup.example.com\n", &existing, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_EQ_FMTm("the first one", 11, (int)firc_sub_rules_id(&out, 0).b[3], "%d");
    ASSERT_FALSEm("and its flag", firc_sub_rules_enable(&out, 0));

    firc_sub_rules_free(&out);
    firc_sub_rules_free(&existing);
    PASS();
}

/* Catches: a later exact match beating an earlier wrapped one, so a disabled rule comes back on. */
TEST the_earlier_stored_rule_wins_whichever_form_it_is_in(void) {
    const char *legacy_text = "^foo[0-9]+$";
    const char *wrapped_text = "\\A(?:^foo[0-9]+$)\\z";
    firc_id_t legacy_id = {{0, 0, 0, 11}};
    firc_id_t wrapped_id = {{0, 0, 0, 22}};
    firc_sub_rules_t existing;
    firc_sub_rules_init(&existing);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, legacy_text, "regex", false, legacy_id));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, wrapped_text, "regex", true, wrapped_id));

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("^foo[0-9]+$\n", &existing, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERTm("the one stored first", firc_id_equal(firc_sub_rules_id(&out, 0), legacy_id));
    ASSERT_FALSEm("and its flag", firc_sub_rules_enable(&out, 0));

    firc_sub_rules_free(&out);

    firc_sub_rules_t other;
    firc_sub_rules_init(&other);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&other, wrapped_text, "regex", true, wrapped_id));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&other, legacy_text, "regex", false, legacy_id));
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("^foo[0-9]+$\n", &other, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERTm("the one stored first, again", firc_id_equal(firc_sub_rules_id(&out, 0), wrapped_id));
    ASSERTm("and its flag, again", firc_sub_rules_enable(&out, 0));

    firc_sub_rules_free(&out);
    firc_sub_rules_free(&other);
    firc_sub_rules_free(&existing);
    PASS();
}

/* Catches: an index that matches by hash alone, giving one rule another's id and enable flag. */
TEST a_hash_collision_is_not_a_match(void) {
    firc_id_t a_id = {{0, 0, 0, 77}};
    firc_sub_rules_t existing;
    firc_sub_rules_init(&existing);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, "h84337.example.com", "namespace", false, a_id));

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("h1340180.example.com\n", &existing, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERTm("it is a different rule, not the stored one",
            !firc_id_equal(firc_sub_rules_id(&out, 0), a_id));
    ASSERTm("and it does not inherit a flag it never had", firc_sub_rules_enable(&out, 0));

    firc_sub_rules_free(&out);
    firc_sub_rules_free(&existing);
    PASS();
}

/* Catches: an id lookup that never answers yes, so a parsed rule takes an id already held. */
TEST a_duplicate_id_is_moved_rather_than_repeated(void) {
    firc_sub_rules_t existing;
    firc_sub_rules_init(&existing);
    firc_id_t shared_id = {{0, 0, 0, 42}};
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, "a.example.com", "namespace", true, shared_id));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&existing, "b.example.com", "namespace", true, shared_id));

    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK,
              firc_sub_refresh_rules("a.example.com\nb.example.com\n", &existing, &out));
    ASSERT_EQ_FMT((size_t)2, out.n, "%zu");
    ASSERTm("the second one was moved off the id the first took",
            !firc_id_equal(firc_sub_rules_id(&out, 0), firc_sub_rules_id(&out, 1)));

    firc_sub_rules_free(&out);
    firc_sub_rules_free(&existing);
    PASS();
}

/* Catches: repeated lines in a large list stored more than once. */
TEST duplicates_are_still_collapsed_at_size(void) {
    const size_t N = 20000;
    size_t cap = N * 24 + 1;
    char *list = malloc(cap);
    ASSERT(list != NULL);
    size_t at = 0;
    for (size_t i = 0; i < N; i++) {
        at += (size_t)snprintf(list + at, cap - at, "d%05zu.example.com\n", i % (N / 2));
    }
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules(list, &rules));
    ASSERT_EQ_FMTm("each distinct line once", N / 2, rules.n, "%zu");
    firc_sub_rules_free(&rules);
    free(list);
    PASS();
}

/* Catches: inherit forgetting to carry id, enable or type, or carrying them onto the wrong index. */
TEST inherit_carries_id_enable_type_by_text(void) {
    firc_sub_rules_t old, cur;
    firc_sub_rules_init(&old); firc_sub_rules_init(&cur);
    firc_id_t kept = {{1, 2, 3, 4}};
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "a.example", "namespace", false, kept));
    firc_sub_rules_set_type(&old, 0, "domain");
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules_counted("a.example\nb.example\n", &cur, NULL));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_inherit(&cur, &old));
    ASSERT(firc_id_equal(cur.v[0].id, kept));
    ASSERT_EQ(false, cur.v[0].enable);
    ASSERT_STR_EQ("domain", firc_sub_rules_type(&cur, 0));
    ASSERT(!firc_id_equal(cur.v[1].id, kept));
    firc_sub_rules_free(&old); firc_sub_rules_free(&cur);
    PASS();
}

/* Catches: parse then inherit giving a different array than firc_sub_refresh_rules. */
TEST refresh_equals_parse_then_inherit(void) {
    firc_sub_rules_t old;
    firc_sub_rules_init(&old);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "a.example", "namespace", false, (firc_id_t){{0, 0, 0, 1}}));
    firc_sub_rules_set_type(&old, 0, "domain");
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "b.example", "namespace", true, (firc_id_t){{0, 0, 0, 2}}));
    firc_sub_rules_set_type(&old, 1, "wildcard");

    firc_sub_rules_t r1;
    firc_sub_rules_init(&r1);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules("a.example\nb.example\n", &old, &r1));

    firc_sub_rules_t r2;
    firc_sub_rules_init(&r2);
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules_counted("a.example\nb.example\n", &r2, NULL));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_inherit(&r2, &old));

    ASSERT_EQ_FMT(r1.n, r2.n, "%zu");
    for (size_t i = 0; i < r1.n; i++) {
        ASSERTm("same id", firc_id_equal(r1.v[i].id, r2.v[i].id));
        ASSERT_EQ_FMTm("same type", r1.v[i].type, r2.v[i].type, "%d");
        ASSERT_EQ_FMTm("same enable", r1.v[i].enable, r2.v[i].enable, "%d");
    }

    firc_sub_rules_free(&old);
    firc_sub_rules_free(&r1);
    firc_sub_rules_free(&r2);
    PASS();
}

static bool count_progress(void *ud, size_t lines) {
    size_t *calls = ud;
    (*calls)++;
    (void)lines;
    return true;
}

static bool abort_progress(void *ud, size_t lines) {
    (void)ud;
    (void)lines;
    return false;
}

/* Catches: progress reported at the wrong interval, or an aborted parse leaving rules in `out`. */
TEST parse_reports_progress_every_20000_lines_and_can_abort(void) {
    char *list = name_list(45000);
    ASSERT(list != NULL);

    firc_sub_rules_t rs;
    firc_sub_rules_init(&rs);
    size_t calls = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_parse_rules_progress(list, &rs, NULL, count_progress, &calls));
    ASSERT_EQ_FMT((size_t)2, calls, "%zu");
    ASSERT_EQ_FMT((size_t)45000, rs.n, "%zu");
    firc_sub_rules_free(&rs);

    firc_sub_rules_init(&rs);
    ASSERT_EQ(FIRC_ERR_CANCELED,
              firc_sub_parse_rules_progress(list, &rs, NULL, abort_progress, NULL));
    ASSERT_EQ_FMT((size_t)0, rs.n, "%zu");
    firc_sub_rules_free(&rs);

    free(list);
    PASS();
}

/* Catches: inherit keyed on text alone, so a CIDR's udp rule takes its tcp twin's enable flag. */
TEST inherit_tells_a_cidr_s_protocols_apart(void) {
    firc_sub_rules_t old, fresh;
    firc_sub_rules_init(&old);
    firc_sub_rules_init(&fresh);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&old, "10.0.0.0/8", FIRC_RULE_SUBNET, false,
                                                (firc_id_t){{1, 0, 0, 0}}, "tcp", "53"));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&old, "10.0.0.0/8", FIRC_RULE_SUBNET, true,
                                                (firc_id_t){{2, 0, 0, 0}}, "udp", "53"));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&fresh, "10.0.0.0/8", FIRC_RULE_SUBNET, true,
                                                (firc_id_t){{9, 0, 0, 0}}, "udp", "53"));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&fresh, "10.0.0.0/8", FIRC_RULE_SUBNET, true,
                                                (firc_id_t){{8, 0, 0, 0}}, "tcp", "53"));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_inherit(&fresh, &old));
    ASSERT_STR_EQ("udp", firc_sub_rules_proto(&fresh, 0));
    ASSERTm("udp stays on", firc_sub_rules_enable(&fresh, 0));
    ASSERT(firc_id_equal(firc_sub_rules_id(&fresh, 0), (firc_id_t){{2, 0, 0, 0}}));
    ASSERT_FALSEm("tcp stays off", firc_sub_rules_enable(&fresh, 1));
    ASSERT(firc_id_equal(firc_sub_rules_id(&fresh, 1), (firc_id_t){{1, 0, 0, 0}}));
    firc_sub_rules_free(&old);
    firc_sub_rules_free(&fresh);
    PASS();
}

/* Catches: the same-rules check ignoring proto, so a udp-to-tcp change is never applied. */
TEST a_changed_protocol_is_a_changed_list(void) {
    firc_sub_rules_t a, b;
    firc_sub_rules_init(&a);
    firc_sub_rules_init(&b);
    firc_id_t id = {{1, 0, 0, 0}};
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&a, "10.0.0.0/8", FIRC_RULE_SUBNET, true, id, "udp", "53"));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&b, "10.0.0.0/8", FIRC_RULE_SUBNET, true, id, "tcp", "53"));
    ASSERT_FALSE(same_rules(&a, &b));
    firc_sub_rules_free(&b);
    firc_sub_rules_init(&b);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push_spec(&b, "10.0.0.0/8", FIRC_RULE_SUBNET, true, id, "udp", "53"));
    ASSERT(same_rules(&a, &b));
    firc_sub_rules_free(&a);
    firc_sub_rules_free(&b);
    PASS();
}

/* Catches: inherit keyed on text alone, so a namespace rule takes a domain rule's id and type. */
TEST one_text_under_two_types_keeps_both_across_a_sync(void) {
    firc_sub_rules_t old, fresh;
    firc_sub_rules_init(&old);
    firc_sub_rules_init(&fresh);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "a.com", FIRC_RULE_DOMAIN, true, (firc_id_t){{1, 0, 0, 0}}));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&old, "a.com", FIRC_RULE_NAMESPACE, false, (firc_id_t){{2, 0, 0, 0}}));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&fresh, "a.com", FIRC_RULE_DOMAIN, true, (firc_id_t){{9, 0, 0, 0}}));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&fresh, "a.com", FIRC_RULE_NAMESPACE, true, (firc_id_t){{8, 0, 0, 0}}));
    ASSERT_EQ(FIRC_OK, firc_sub_rules_inherit(&fresh, &old));
    ASSERT_STR_EQ(FIRC_RULE_DOMAIN, firc_sub_rules_type(&fresh, 0));
    ASSERT(firc_id_equal(firc_sub_rules_id(&fresh, 0), (firc_id_t){{1, 0, 0, 0}}));
    ASSERT_STR_EQm("the namespace stays a namespace", FIRC_RULE_NAMESPACE, firc_sub_rules_type(&fresh, 1));
    ASSERT(firc_id_equal(firc_sub_rules_id(&fresh, 1), (firc_id_t){{2, 0, 0, 0}}));
    ASSERT_FALSEm("and keeps its own off", firc_sub_rules_enable(&fresh, 1));
    ASSERT(same_rules(&old, &fresh));
    firc_sub_rules_free(&old);
    firc_sub_rules_free(&fresh);
    PASS();
}

/* Catches: a refused or cancelled parse changing a rule set the caller had already filled. */
TEST a_prefilled_out_survives_a_refused_or_cancelled_parse(void) {
    firc_sub_rules_t out;
    firc_sub_rules_init(&out);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&out, "example.com", "namespace", true, firc_id_random()));

    firc_sub_parse_stats_t st;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_sub_parse_rules_stats("<!DOCTYPE html>", &out, &st, NULL, NULL));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_STR_EQ("example.com", firc_sub_rules_text(&out, 0));

    char *list = name_list(45000);
    ASSERT(list != NULL);
    ASSERT_EQ(FIRC_ERR_CANCELED, firc_sub_parse_rules_stats(list, &out, &st, abort_progress, NULL));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_STR_EQ("example.com", firc_sub_rules_text(&out, 0));
    free(list);

    firc_sub_rules_free(&out);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(type_detection);
    RUN_TEST(a_name_a_list_carries_is_not_guessed_to_be_a_regex);
    RUN_TEST(a_wildcard_that_compiles_as_a_regex_is_still_a_wildcard);
    RUN_TEST(a_line_that_is_nothing_recognisable_is_refused);
    RUN_TEST(a_pattern_that_matches_anything_is_not_a_rule);
    RUN_TEST(a_control_verb_is_not_a_rule);
    RUN_TEST(a_pattern_that_only_compiles_unwrapped_is_dropped);
    RUN_TEST(derived_regex_is_anchored_by_construction);
    RUN_TEST(an_unanchored_line_is_never_called_a_regex);
    RUN_TEST(a_line_with_no_type_is_dropped);
    RUN_TEST(a_legacy_unanchored_regex_is_re_derived_on_sync);
    RUN_TEST(the_wrap_does_not_lose_what_the_operator_set);
    RUN_TEST(a_wrapped_rule_matches_itself_on_the_next_sync);
    RUN_TEST(an_unusable_stored_type_is_not_restored);
    RUN_TEST(an_operator_s_chosen_type_survives_a_sync);
    RUN_TEST(parse_dedup_and_comments);
    RUN_TEST(refresh_preserves_existing_overrides);
    RUN_TEST(same_rules_ignores_order);
    RUN_TEST(a_big_list_does_not_take_the_thread_for_seconds);
    RUN_TEST(a_comma_inside_a_repetition_count_is_not_a_separator);
    RUN_TEST(the_dropped_count_counts_lines);
    RUN_TEST(an_ordinary_list_is_parsed_without_complaint);
    RUN_TEST(a_list_line_is_stored_folded_like_a_query);
    RUN_TEST(the_type_is_one_word_shared_by_every_rule);
    RUN_TEST(a_big_resync_does_not_take_the_thread_for_seconds);
    RUN_TEST(a_repeated_rule_is_compared_occurrence_by_occurrence);
    RUN_TEST(deciding_a_sync_changed_nothing_is_linear);
    RUN_TEST(the_first_stored_rule_of_a_text_is_the_one_matched);
    RUN_TEST(the_earlier_stored_rule_wins_whichever_form_it_is_in);
    RUN_TEST(a_hash_collision_is_not_a_match);
    RUN_TEST(a_duplicate_id_is_moved_rather_than_repeated);
    RUN_TEST(duplicates_are_still_collapsed_at_size);
    RUN_TEST(inherit_carries_id_enable_type_by_text);
    RUN_TEST(refresh_equals_parse_then_inherit);
    RUN_TEST(parse_reports_progress_every_20000_lines_and_can_abort);
    RUN_TEST(is_due_logic);
    RUN_TEST(inherit_tells_a_cidr_s_protocols_apart);
    RUN_TEST(a_changed_protocol_is_a_changed_list);
    RUN_TEST(one_text_under_two_types_keeps_both_across_a_sync);
    RUN_TEST(a_prefilled_out_survives_a_refused_or_cancelled_parse);
    GREATEST_MAIN_END();
}
