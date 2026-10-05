#include "greatest.h"
#include <netinet/in.h>

#include <stdlib.h>
#include <string.h>

#include "firc/match.h"

static bool m1(const char *type, const char *rule, const char *domain)
{
    firc_rule_matcher_t *m = firc_rule_matcher_new(type, rule);
    if (m == NULL) {
        return false;
    }
    bool ok = firc_rule_matcher_match(m, domain);
    firc_rule_matcher_free(m);
    return ok;
}

TEST domain_exact(void)
{
    ASSERT(m1("domain", "example.com", "example.com"));
    ASSERT_FALSE(m1("domain", "example.com", "noexample.com"));
    ASSERT_FALSE(m1("domain", "example.com", "sub.example.com"));
    ASSERT_FALSE(m1("domain", "example.com", "example.com.ru"));
    ASSERT_FALSE(m1("domain", "example.com", ""));
    PASS();
}

TEST namespace_suffix(void)
{
    ASSERT(m1("namespace", "example.com", "example.com"));
    ASSERT(m1("namespace", "example.com", "sub.example.com"));
    ASSERT(m1("namespace", "example.com", "deep.sub.example.com"));
    ASSERT_FALSE(m1("namespace", "example.com", "noexample.com"));
    ASSERT_FALSE(m1("namespace", "example.com", "notexample.com"));
    ASSERT_FALSE(m1("namespace", "example.com", "example.com.ru"));
    ASSERT_FALSE(m1("namespace", "example.com", "fakeexample.com"));
    ASSERT_FALSE(m1("namespace", "example.com", ""));
    ASSERT_FALSE(m1("namespace", "example.com", "com"));
    ASSERT(m1("namespace", "example.com", ".example.com"));
    ASSERT(m1("namespace", "ru", "ru"));
    ASSERT(m1("namespace", "ru", "example.ru"));
    ASSERT(m1("namespace", "ru", "sub.example.ru"));
    ASSERT_FALSE(m1("namespace", "ru", "ru.com"));
    ASSERT_FALSE(m1("namespace", "ru", ""));
    ASSERT_FALSE(m1("namespace", "ru", "r"));
    PASS();
}

TEST wildcard_go_corpus(void)
{
    ASSERT(m1("wildcard", "ex*le.com", "example.com"));
    ASSERT(m1("wildcard", "ex*le.com", "exle.com"));
    ASSERT_FALSE(m1("wildcard", "ex*le.com", "noexample.com"));
    ASSERT(m1("wildcard", "*.example.com", "sub.example.com"));
    ASSERT_FALSE(m1("wildcard", "*.example.com", "example.com"));
    ASSERT(m1("wildcard", "*example*", "example.com"));
    ASSERT(m1("wildcard", "*example*", "myexamplesite.ru"));
    ASSERT(m1("wildcard", "test*.com", "test123.com"));
    ASSERT(m1("wildcard", "test??.com", "test12.com"));
    ASSERT_FALSE(m1("wildcard", "test??.com", "test123.com"));
    ASSERT_FALSE(m1("wildcard", "test.com", "test12.com"));
    PASS();
}

TEST wildcard_dot_matches_any_byte(void)
{
    ASSERT(m1("wildcard", "test.com", "testXcom"));
    ASSERT(m1("wildcard", "a.b", "aXb"));
    ASSERT_FALSE(m1("wildcard", "a.b", "ab"));
    PASS();
}

TEST regex_pcre2(void)
{
    ASSERT(m1("regex", "^ex[apm]{3}le.com$", "example.com"));
    ASSERT(m1("regex", "^ex[apm]{3}le.com$", "exapple.com"));
    ASSERT_FALSE(m1("regex", "^ex[apm]{3}le.com$", "noexample.com"));
    ASSERT(m1("regex", "example", "example.com"));
    ASSERT_FALSE(m1("regex", "^example$", "example.com"));
    ASSERT(m1("regex", "(?i)EXAMPLE", "example.com"));
    ASSERT(m1("regex", "\\d+\\.example", "123.example"));
    ASSERT(m1("regex", "EXAMPLE", "example.com"));
    PASS();
}

TEST invalid_regex_never_matches(void)
{
    firc_rule_matcher_t *m = firc_rule_matcher_new("regex", "[invalid(regex");
    ASSERT(m != NULL);
    ASSERT_FALSE(firc_rule_matcher_ok(m));
    ASSERT_FALSE(firc_rule_matcher_match(m, "anything"));
    firc_rule_matcher_free(m);
    PASS();
}

TEST subnet_types_never_match(void)
{
    ASSERT_FALSE(m1("subnet", "10.0.0.0/8", "example.com"));
    ASSERT_FALSE(m1("subnet6", "fd00::/8", "example.com"));
    ASSERT_FALSE(m1("unknown", "example.com", "example.com"));
    PASS();
}

/* Catches: a rule not folded like the query (case, trailing dot), so it matches nothing. */
TEST a_rule_is_folded_the_same_way_the_query_is(void) {
    struct {
        const char *type;
        const char *rule;
        const char *query;
    } cases[] = {
        {FIRC_RULE_DOMAIN, "Google.COM", "google.com"},
        {FIRC_RULE_DOMAIN, "example.com.", "example.com"},
        {FIRC_RULE_DOMAIN, "  example.com  ", "example.com"},
        {FIRC_RULE_NAMESPACE, "Example.COM", "a.example.com"},
        {FIRC_RULE_NAMESPACE, "example.com.", "a.example.com"},
        {FIRC_RULE_WILDCARD, "*.Example.COM", "a.example.com"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        firc_rule_matcher_t *m = firc_rule_matcher_new(cases[i].type, cases[i].rule);
        ASSERT(m != NULL);
        ASSERT_EQ_FMTm(cases[i].rule, true, firc_rule_matcher_match(m, cases[i].query), "%d");
        firc_rule_matcher_free(m);
    }
    PASS();
}

TEST folding_does_not_widen_a_rule(void) {
    firc_rule_matcher_t *m = firc_rule_matcher_new(FIRC_RULE_DOMAIN, "Example.COM");
    ASSERT(m != NULL);
    ASSERT_FALSEm("not a subdomain", firc_rule_matcher_match(m, "a.example.com"));
    ASSERT_FALSEm("not a longer name", firc_rule_matcher_match(m, "example.com.ru"));
    firc_rule_matcher_free(m);
    m = firc_rule_matcher_new(FIRC_RULE_DOMAIN, "example.com..");
    ASSERT(m != NULL);
    ASSERT_FALSEm("an empty label is not folded away", firc_rule_matcher_match(m, "example.com"));
    firc_rule_matcher_free(m);
    m = firc_rule_matcher_new(FIRC_RULE_NAMESPACE, "example.com.");
    ASSERT(m != NULL);
    ASSERT_FALSEm("a namespace still needs the label boundary",
                  firc_rule_matcher_match(m, "notexample.com"));
    firc_rule_matcher_free(m);
    PASS();
}

/* Catches: a regex folded, which changes what classes like \D mean. */
TEST a_regex_is_left_exactly_as_written(void) {
    firc_rule_matcher_t *m = firc_rule_matcher_new(FIRC_RULE_REGEX, "^a\\Db\\.example\\.com$");
    ASSERT(m != NULL);
    ASSERTm("a non-digit is what was asked for", firc_rule_matcher_match(m, "a-b.example.com"));
    ASSERT_FALSEm("a digit is not", firc_rule_matcher_match(m, "a1b.example.com"));
    firc_rule_matcher_free(m);
    PASS();
}

TEST a_pattern_no_query_can_equal_is_refused(void) {
    const char *never[] = {
        "https://vk.com",
        "vk.com/feed",
        "a\\.b.example.com",
        "exa mple.com",
        ".example.com",
        "example..com",
        "   ",
        "2001:db8::1",
        "[a-z].example.com",
        "user@example.com",
        "example.com..",
        "a..",
        "\xd1\x8f\xd0\xbd\xd0\xb4\xd0\xb5\xd0\xba\xd1\x81.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
    };
    char too_long[400];
    size_t at = 0;
    for (int seg = 0; seg < 5; seg++) {
        if (seg > 0) { too_long[at++] = '.'; }
        for (int k = 0; k < 62; k++) { too_long[at++] = 'a'; }
    }
    too_long[at] = '\0';
    ASSERT_FALSEm("a name over 253 characters", firc_rule_is_usable(FIRC_RULE_DOMAIN, too_long, NULL));

    for (size_t i = 0; i < sizeof(never) / sizeof(never[0]); i++) {
        const char *why = NULL;
        ASSERT_FALSEm(never[i], firc_rule_is_usable(FIRC_RULE_DOMAIN, never[i], &why));
        ASSERTm("and says why", why != NULL);
        ASSERT_FALSEm(never[i], firc_rule_is_usable(FIRC_RULE_NAMESPACE, never[i], NULL));
        ASSERT_FALSEm(never[i], firc_rule_is_usable(FIRC_RULE_WILDCARD, never[i], NULL));
    }

    const char *why = NULL;
    ASSERT_FALSE(firc_rule_is_usable(
        FIRC_RULE_DOMAIN, "\xd1\x8f\xd0\xbd\xd0\xb4\xd0\xb5\xd0\xba\xd1\x81.com", &why));
    ASSERT(why != NULL);
    ASSERTm("the message names the form that works", strstr(why, "xn--") != NULL);
    PASS();
}

TEST a_pattern_a_query_can_carry_is_accepted(void) {
    const char *ok[] = {
        "example.com",
        "Google.COM",
        "example.com.",
        "  example.com  ",
        "_dmarc.example.com",
        "_acme-challenge.example.com",
        "xn--80ak6aa92e.com",
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        ASSERT_FALSEm(ok[i], !firc_rule_is_usable(FIRC_RULE_DOMAIN, ok[i], NULL));
        ASSERT_FALSEm(ok[i], !firc_rule_is_usable(FIRC_RULE_NAMESPACE, ok[i], NULL));
    }
    ASSERT(firc_rule_is_usable(FIRC_RULE_WILDCARD, "*.example.com", NULL));
    ASSERT(firc_rule_is_usable(FIRC_RULE_WILDCARD, "a?.example.com", NULL));
    ASSERT_FALSEm("a domain rule is not a wildcard",
                  firc_rule_is_usable(FIRC_RULE_DOMAIN, "*.example.com", NULL));
    PASS();
}

/* Catches: the indexed matcher not folding rules like the reference matcher. */
TEST the_index_folds_a_rule_the_same_way_the_reference_does(void) {
    struct {
        const char *type;
        const char *rule;
        const char *query;
    } cases[] = {
        {FIRC_RULE_DOMAIN, "Google.COM", "google.com"},
        {FIRC_RULE_DOMAIN, "example.com.", "example.com"},
        {FIRC_RULE_DOMAIN, "  example.com  ", "example.com"},
        {FIRC_RULE_NAMESPACE, "Example.COM", "a.example.com"},
        {FIRC_RULE_NAMESPACE, "example.com.", "a.example.com"},
        {FIRC_RULE_WILDCARD, "*.Example.COM", "a.example.com"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        firc_matcher_t *m = firc_matcher_new();
        ASSERT(m != NULL);
        ASSERT_EQ(FIRC_OK, firc_matcher_add(m, cases[i].type, cases[i].rule));
        ASSERT_EQ_FMTm(cases[i].rule, true, firc_matcher_match(m, cases[i].query), "%d");
        firc_rule_matcher_t *r = firc_rule_matcher_new(cases[i].type, cases[i].rule);
        ASSERT(r != NULL);
        ASSERT_EQ_FMTm(cases[i].rule, true, firc_rule_matcher_match(r, cases[i].query), "%d");
        firc_rule_matcher_free(r);
        firc_matcher_free(m);
    }
    PASS();
}

TEST the_index_fold_does_not_widen_a_rule(void) {
    firc_matcher_t *m = firc_matcher_new();
    ASSERT(m != NULL);
    ASSERT_EQ(FIRC_OK, firc_matcher_add(m, FIRC_RULE_DOMAIN, "Example.COM"));
    ASSERT_FALSEm("not a subdomain", firc_matcher_match(m, "a.example.com"));
    ASSERT_FALSEm("not a longer name", firc_matcher_match(m, "example.com.ru"));
    firc_matcher_free(m);
    m = firc_matcher_new();
    ASSERT(m != NULL);
    ASSERT_EQ(FIRC_OK, firc_matcher_add(m, FIRC_RULE_NAMESPACE, "Example.COM."));
    ASSERTm("the zone itself", firc_matcher_match(m, "example.com"));
    ASSERT_FALSEm("still needs the label boundary", firc_matcher_match(m, "notexample.com"));
    firc_matcher_free(m);
    PASS();
}

TEST group_index_matches_like_rules(void)
{
    firc_matcher_t *m = firc_matcher_new();
    ASSERT(m != NULL);
    ASSERT_EQ(FIRC_OK, firc_matcher_add(m, "domain", "exact.example.com"));
    ASSERT_EQ(FIRC_OK, firc_matcher_add(m, "namespace", "ns.example.org"));
    ASSERT_EQ(FIRC_OK, firc_matcher_add(m, "wildcard", "*.wild.net"));
    ASSERT_EQ(FIRC_OK, firc_matcher_add(m, "regex", "^r[0-9]+\\.example\\.io$"));
    ASSERT_EQ(FIRC_OK, firc_matcher_add(m, "subnet", "10.0.0.0/8"));

    ASSERT(firc_matcher_match(m, "exact.example.com"));
    ASSERT_FALSE(firc_matcher_match(m, "sub.exact.example.com"));
    ASSERT(firc_matcher_match(m, "ns.example.org"));
    ASSERT(firc_matcher_match(m, "a.b.ns.example.org"));
    ASSERT(firc_matcher_match(m, ".ns.example.org"));
    ASSERT_FALSE(firc_matcher_match(m, "xns.example.org"));
    ASSERT(firc_matcher_match(m, "a.wild.net"));
    ASSERT_FALSE(firc_matcher_match(m, "wild.net"));
    ASSERT(firc_matcher_match(m, "r42.example.io"));
    ASSERT_FALSE(firc_matcher_match(m, "rx.example.io"));
    ASSERT_FALSE(firc_matcher_match(m, "10.0.0.1"));

    firc_matcher_free(m);
    PASS();
}

/* Catches: add_name borrowing a hand name, which is then read after it is freed. */
TEST a_matcher_copies_one_name_and_borrows_another(void)
{
    firc_matcher_t *m = firc_matcher_new();
    ASSERT(m != NULL);
    char *hand = strdup("hand.example");
    static const char list_text[] = "list.example";
    ASSERT_EQ(FIRC_OK, firc_matcher_add(m, FIRC_RULE_DOMAIN, hand));
    ASSERT_EQ(FIRC_OK, firc_matcher_add_borrowed(m, FIRC_RULE_NAMESPACE, list_text));
    memset(hand, 'x', strlen(hand));
    free(hand);
    ASSERT(firc_matcher_match(m, "hand.example"));
    ASSERT(firc_matcher_match(m, "www.list.example"));
    ASSERT_FALSE(firc_matcher_match(m, "xxxx.example"));
    firc_matcher_free(m);
    PASS();
}

/* Catches: a borrowing matcher freeing the caller's text (under sanitize). */
TEST a_borrowing_matcher_reads_the_text_it_is_handed(void)
{
    char *name = strdup("ads.example.com");
    char *exact = strdup("tracker.example.net");
    firc_matcher_t *m = firc_matcher_new();
    ASSERT(m != NULL);
    ASSERT_EQ(FIRC_OK, firc_matcher_add_borrowed(m, FIRC_RULE_NAMESPACE, name));
    ASSERT_EQ(FIRC_OK, firc_matcher_add_borrowed(m, FIRC_RULE_DOMAIN, exact));
    ASSERT(firc_matcher_match(m, "a.ads.example.com"));
    ASSERT(firc_matcher_match(m, "ads.example.com"));
    ASSERT(firc_matcher_match(m, "tracker.example.net"));
    ASSERT_FALSE(firc_matcher_match(m, "a.tracker.example.net"));
    ASSERT_FALSE(firc_matcher_match(m, "xads.example.com"));
    name[0] = 'x';
    ASSERT_FALSEm("the old name is gone with the caller's text",
                  firc_matcher_match(m, "a.ads.example.com"));
    name[0] = 'a';
    firc_matcher_free(m);
    ASSERT_STR_EQ("ads.example.com", name);
    free(name);
    free(exact);
    PASS();
}

/* Catches: unfolded text borrowed as is instead of copied and folded. */
TEST a_borrowing_matcher_copies_what_is_not_folded(void)
{
    static const char *const unfolded[] = {"Ads.example.com", "ads.example.com.",
                                           " ads.example.com", "ads.example.com\t"};
    for (size_t i = 0; i < sizeof(unfolded) / sizeof(unfolded[0]); i++) {
        firc_matcher_t *m = firc_matcher_new();
        ASSERT(m != NULL);
        ASSERT_EQ(FIRC_OK, firc_matcher_add_borrowed(m, FIRC_RULE_NAMESPACE, unfolded[i]));
        ASSERTm(unfolded[i], firc_matcher_match(m, "a.ads.example.com"));
        firc_matcher_free(m);
    }
    PASS();
}

TEST a_node_with_many_children_finds_every_one(void)
{
    enum { N = 500 };
    firc_matcher_t *m = firc_matcher_new();
    ASSERT(m != NULL);
    for (int i = 0; i < N; i++) {
        char rule[64];
        snprintf(rule, sizeof(rule), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_matcher_add(m, FIRC_RULE_NAMESPACE, rule));
    }
    for (int i = 0; i < N; i++) {
        char name[64];
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERTm(name, firc_matcher_match(m, name));
        snprintf(name, sizeof(name), "deep.n%d.example.com", i);
        ASSERTm(name, firc_matcher_match(m, name));
    }
    ASSERT_FALSE(firc_matcher_match(m, "n500.example.com"));
    ASSERT_FALSE(firc_matcher_match(m, "n.example.com"));
    ASSERT_FALSE(firc_matcher_match(m, "n1x.example.com"));
    ASSERT_FALSE(firc_matcher_match(m, "example.com"));
    firc_matcher_free(m);
    PASS();
}

/* Catches: the ninth child's index losing the eight children already scanned. */
TEST the_children_already_there_survive_the_index(void)
{
    firc_matcher_t *m = firc_matcher_new();
    ASSERT(m != NULL);
    static const char *labels[] = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"};
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        char rule[32];
        snprintf(rule, sizeof(rule), "%s.example.com", labels[i]);
        ASSERT_EQ(FIRC_OK, firc_matcher_add(m, FIRC_RULE_NAMESPACE, rule));
    }
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        char name[32];
        snprintf(name, sizeof(name), "%s.example.com", labels[i]);
        ASSERTm(name, firc_matcher_match(m, name));
    }
    ASSERT_FALSE(firc_matcher_match(m, "k.example.com"));
    firc_matcher_free(m);
    PASS();
}

/* Catches: a port list not normalised to iptables' form, or an invalid one accepted. */
TEST a_port_list_is_normalised_or_refused(void) {
    char out[FIRC_PORTS_STR_MAX];
    ASSERT(firc_rule_parse_ports("53", out, sizeof(out)));
    ASSERT_STR_EQ("53", out);
    ASSERT(firc_rule_parse_ports("1000-2000", out, sizeof(out)));
    ASSERT_STR_EQ("1000:2000", out);
    ASSERT(firc_rule_parse_ports("53,443,1000-2000", out, sizeof(out)));
    ASSERT_STR_EQ("53,443,1000:2000", out);
    ASSERT(firc_rule_parse_ports("1-65535", out, sizeof(out)));
    ASSERT(firc_rule_parse_ports("", out, sizeof(out)));
    ASSERT_STR_EQ("", out);
    ASSERT(firc_rule_parse_ports(NULL, out, sizeof(out)));
    ASSERT(firc_rule_parse_ports("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15", out, sizeof(out)));
    ASSERT_FALSEm("sixteen entries", firc_rule_parse_ports("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16", out, sizeof(out)));
    ASSERTm("seven ranges and a single fill the fifteen slots",
            firc_rule_parse_ports("1-2,3-4,5-6,7-8,9-10,11-12,13-14,15", out, sizeof(out)));
    ASSERT_FALSEm("eight ranges are sixteen slots",
                  firc_rule_parse_ports("1-2,3-4,5-6,7-8,9-10,11-12,13-14,15-16", out, sizeof(out)));
    ASSERT_FALSEm("seven ranges and two singles too",
                  firc_rule_parse_ports("1-2,3-4,5-6,7-8,9-10,11-12,13-14,15,16", out, sizeof(out)));
    ASSERT(firc_rule_parse_ports("65535", out, sizeof(out)));
    ASSERT(firc_rule_parse_ports("00053", out, sizeof(out)));
    ASSERT_STR_EQ("53", out);
    ASSERT_FALSEm("six digits, whatever they spell", firc_rule_parse_ports("000053", out, sizeof(out)));
    ASSERT_FALSEm("port zero", firc_rule_parse_ports("0", out, sizeof(out)));
    ASSERT_FALSEm("past 16 bits", firc_rule_parse_ports("65536", out, sizeof(out)));
    ASSERT_FALSEm("a range upside down", firc_rule_parse_ports("2000-1000", out, sizeof(out)));
    ASSERT_FALSEm("a trailing comma", firc_rule_parse_ports("53,", out, sizeof(out)));
    ASSERT_FALSEm("a space", firc_rule_parse_ports("53, 443", out, sizeof(out)));
    ASSERT_FALSEm("a sign", firc_rule_parse_ports("-53", out, sizeof(out)));
    ASSERT_FALSEm("iptables' own colon is not the config form", firc_rule_parse_ports("53:443", out, sizeof(out)));
    ASSERT_FALSEm("letters", firc_rule_parse_ports("dns", out, sizeof(out)));
    ASSERT_FALSEm("an open range", firc_rule_parse_ports("53-", out, sizeof(out)));
    uint8_t p = 99;
    ASSERT(firc_rule_parse_proto("udp", &p));
    ASSERT_EQ(IPPROTO_UDP, p);
    ASSERT(firc_rule_parse_proto("tcp", &p));
    ASSERT_EQ(IPPROTO_TCP, p);
    ASSERT(firc_rule_parse_proto("", &p));
    ASSERT_EQ(0, p);
    ASSERT(firc_rule_parse_proto(NULL, &p));
    ASSERT_FALSE(firc_rule_parse_proto("UDP", &p));
    ASSERT_FALSE(firc_rule_parse_proto("icmp", &p));
    PASS();
}

TEST proto_and_ports_belong_to_subnet_rules(void) {
    const char *why = NULL;
    ASSERT(firc_rule_spec_is_usable("subnet", "10.0.0.0/8", "udp", "53,1000-2000", &why));
    ASSERT(firc_rule_spec_is_usable("subnet6", "fd00::/8", "tcp", "", &why));
    ASSERT(firc_rule_spec_is_usable("subnet", "10.0.0.0/8", "", "", &why));
    ASSERT(firc_rule_spec_is_usable("domain", "example.com", NULL, NULL, &why));
    ASSERT_FALSE(firc_rule_spec_is_usable("domain", "example.com", "udp", "", &why));
    ASSERT_STR_EQ("proto and ports apply to subnet and subnet6 rules only", why);
    ASSERT_FALSE(firc_rule_spec_is_usable("subnet", "10.0.0.0/8", "", "53", &why));
    ASSERT_STR_EQ("ports need a protocol (tcp or udp)", why);
    ASSERT_FALSE(firc_rule_spec_is_usable("subnet", "10.0.0.0/8", "icmp", "", &why));
    ASSERT_STR_EQ("proto is tcp or udp", why);
    ASSERT_FALSE(firc_rule_spec_is_usable("subnet", "10.0.0.0/8", "udp", "53:443", &why));
    ASSERT_STR_EQ("ports are a comma-separated list of ports or ranges, like 53,1000-2000 (at most 15 ports, a range counts as two)", why);
    ASSERT_FALSEm("the prefix is still checked first", firc_rule_spec_is_usable("subnet", "nonsense", "udp", "53", &why));
    ASSERT_STR_EQ("a subnet is an IPv4 address or prefix, like 10.0.0.0/8", why);
    ASSERT_FALSEm("a NULL why is tolerated", firc_rule_spec_is_usable("subnet", "10.0.0.0/8", "", "53", NULL));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(domain_exact);
    RUN_TEST(namespace_suffix);
    RUN_TEST(wildcard_go_corpus);
    RUN_TEST(wildcard_dot_matches_any_byte);
    RUN_TEST(regex_pcre2);
    RUN_TEST(invalid_regex_never_matches);
    RUN_TEST(subnet_types_never_match);
    RUN_TEST(a_port_list_is_normalised_or_refused);
    RUN_TEST(proto_and_ports_belong_to_subnet_rules);
    RUN_TEST(a_rule_is_folded_the_same_way_the_query_is);
    RUN_TEST(a_regex_is_left_exactly_as_written);
    RUN_TEST(a_pattern_no_query_can_equal_is_refused);
    RUN_TEST(a_pattern_a_query_can_carry_is_accepted);
    RUN_TEST(folding_does_not_widen_a_rule);
    RUN_TEST(the_index_folds_a_rule_the_same_way_the_reference_does);
    RUN_TEST(the_index_fold_does_not_widen_a_rule);
    RUN_TEST(group_index_matches_like_rules);
    RUN_TEST(a_matcher_copies_one_name_and_borrows_another);
    RUN_TEST(a_borrowing_matcher_reads_the_text_it_is_handed);
    RUN_TEST(a_borrowing_matcher_copies_what_is_not_folded);
    RUN_TEST(a_node_with_many_children_finds_every_one);
    RUN_TEST(the_children_already_there_survive_the_index);
    GREATEST_MAIN_END();
}
