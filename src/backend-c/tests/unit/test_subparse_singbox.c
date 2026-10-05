#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "firc/subparse.h"

typedef struct got {
    firc_sub_rules_t rs;
    firc_sub_parse_stats_t st;
    firc_err_t err;
} got_t;

static got_t parse(const char *body) {
    got_t g;
    memset(&g, 0, sizeof(g));
    firc_sub_rules_init(&g.rs);
    g.err = firc_sub_parse_rules_stats(body, &g.rs, &g.st, NULL, NULL);
    return g;
}

/* The i-th rule as "type text proto ports", "-" for an absent field. */
static const char *row(const got_t *g, size_t i) {
    static char buf[512];
    const char *p = firc_sub_rules_proto(&g->rs, i), *q = firc_sub_rules_ports(&g->rs, i);
    snprintf(buf, sizeof(buf), "%s %s %s %s", firc_sub_rules_type(&g->rs, i), firc_sub_rules_text(&g->rs, i),
             p ? p : "-", q ? q : "-");
    return buf;
}

static const char discord[] =
    "{\"version\":2,\"rules\":["
    "{\"domain_suffix\":[\"discord.com\",\"discord.gg\",\"discord.media\",\"discordapp.com\","
    "\"discordapp.net\",\"discord-attachments-uploads-prd.storage.googleapis.com\"]},"
    "{\"network\":[\"udp\"],\"ip_cidr\":[\"138.128.136.0/21\",\"162.158.0.0/15\",\"172.64.0.0/13\","
    "\"34.0.0.0/15\",\"34.2.0.0/16\",\"34.3.0.0/23\",\"34.3.2.0/24\",\"35.192.0.0/12\",\"35.208.0.0/12\","
    "\"35.224.0.0/12\",\"35.240.0.0/13\",\"5.200.14.128/25\",\"66.22.192.0/18\",\"104.29.0.0/16\"],"
    "\"port_range\":[\"50000:50099\",\"19200:19400\"]}]}";

/* Catches: a wrong type mapping, udp spec or port-range rewrite on a real rule-set. */
TEST discord_full_is_six_namespaces_and_fourteen_udp_prefixes(void) {
    got_t g = parse(discord);
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)20, g.rs.n, "%zu");
    ASSERT_STR_EQ("namespace discord.com - -", row(&g, 0));
    ASSERT_STR_EQ("namespace discord-attachments-uploads-prd.storage.googleapis.com - -", row(&g, 5));
    ASSERT_STR_EQ("subnet 138.128.136.0/21 udp 50000-50099,19200-19400", row(&g, 6));
    ASSERT_STR_EQ("subnet 104.29.0.0/16 udp 50000-50099,19200-19400", row(&g, 19));
    ASSERT_EQ_FMT((size_t)0, g.st.dropped, "%zu");
    ASSERT_EQ_FMT((size_t)0, g.st.unconstrained, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: ports emitted without a protocol (iptables refuses them), or for one protocol only. */
TEST ports_without_network_are_a_tcp_and_a_udp_rule(void) {
    got_t g = parse("{\"rules\":[{\"ip_cidr\":\"10.0.0.0/8\",\"port\":53}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    ASSERT_STR_EQ("subnet 10.0.0.0/8 tcp 53", row(&g, 0));
    ASSERT_STR_EQ("subnet 10.0.0.0/8 udp 53", row(&g, 1));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a port list over 15 multiport slots not split into a second rule. */
TEST sixteen_slots_are_two_rules(void) {
    got_t g = parse("{\"rules\":[{\"ip_cidr\":[\"10.0.0.0/8\"],\"network\":\"tcp\",\"port_range\":"
                    "[\"1:2\",\"3:4\",\"5:6\",\"7:8\",\"9:10\",\"11:12\",\"13:14\",\"15:16\"]}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    ASSERT_STR_EQ("subnet 10.0.0.0/8 tcp 1-2,3-4,5-6,7-8,9-10,11-12,13-14", row(&g, 0));
    ASSERT_STR_EQ("subnet 10.0.0.0/8 tcp 15-16", row(&g, 1));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a port list of exactly 15 slots split into two rules. */
TEST fifteen_slots_are_one_rule(void) {
    got_t g = parse("{\"rules\":[{\"ip_cidr\":[\"10.0.0.0/8\"],\"network\":\"tcp\",\"port\":[99],\"port_range\":"
                    "[\"1:2\",\"3:4\",\"5:6\",\"7:8\",\"9:10\",\"11:12\",\"13:14\"]}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
    ASSERT_STR_EQ("subnet 10.0.0.0/8 tcp 99,1-2,3-4,5-6,7-8,9-10,11-12,13-14", row(&g, 0));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: open-ended ranges, a one-port range or the order of ports and ranges written wrongly. */
TEST ranges_open_at_either_end_and_single_ports(void) {
    got_t g = parse("{\"rules\":[{\"ip_cidr\":[\"10.0.0.0/8\"],\"network\":[\"udp\"],\"port\":[443,80],"
                    "\"port_range\":[\"60000:\",\":10\",\"7:7\"]}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
    ASSERT_STR_EQ("subnet 10.0.0.0/8 udp 443,80,60000-65535,1-10,7", row(&g, 0));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a network of both protocols read as a constraint, or a lone network losing its protocol. */
TEST network_without_ports(void) {
    got_t g = parse("{\"rules\":[{\"ip_cidr\":[\"10.0.0.0/8\"],\"network\":[\"tcp\",\"udp\"]},"
                    "{\"ip_cidr\":[\"10.1.0.0/16\"],\"network\":\"tcp\"}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    ASSERT_STR_EQ("subnet 10.0.0.0/8 - -", row(&g, 0));
    ASSERT_STR_EQ("subnet 10.1.0.0/16 tcp -", row(&g, 1));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: names dropped with their object's constraint, a domain made a namespace, or a lost count. */
TEST names_beside_a_constraint_are_taken_unconstrained(void) {
    got_t g = parse("{\"rules\":[{\"domain\":[\"a.com\"],\"domain_keyword\":\"kw\",\"network\":\"udp\","
                    "\"port\":443}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    ASSERT_STR_EQ("domain a.com - -", row(&g, 0));
    ASSERT_STR_EQ("wildcard *kw* - -", row(&g, 1));
    ASSERT_EQ_FMT((size_t)2, g.st.unconstrained, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a condition firc cannot honour ignored, so the rule routes more than it says. */
TEST an_object_firc_cannot_honour_is_dropped_whole(void) {
    got_t g = parse("{\"rules\":["
                    "{\"domain\":[\"a.com\"],\"invert\":true},"
                    "{\"type\":\"logical\",\"mode\":\"and\",\"rules\":[{\"domain\":[\"x.com\"]}]},"
                    "{\"source_ip_cidr\":[\"10.0.0.0/8\"],\"domain\":[\"b.com\"]},"
                    "{\"domain\":[\"c.com\"],\"wifi_ssid\":[\"x\"]},"
                    "{\"domain\":[\"d.com\"]},"
                    "{\"domain\":[\"e.com\"],\"invert\":false,\"type\":\"default\"}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    ASSERT_STR_EQ("domain d.com - -", row(&g, 0));
    ASSERT_STR_EQ("domain e.com - -", row(&g, 1));
    ASSERT_EQ_FMT((size_t)4, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a bad network or port widening its rule, or a bad CIDR dropping its neighbours. */
TEST a_value_that_cannot_be_honoured_drops_what_it_constrains(void) {
    got_t g = parse("{\"rules\":["
                    "{\"ip_cidr\":[\"10.0.0.0/8\"],\"network\":[\"icmp\"]},"
                    "{\"ip_cidr\":[\"10.0.0.0/8\"],\"port\":[0]},"
                    "{\"ip_cidr\":[\"10.0.0.0/8\"],\"port_range\":[\"200:100\"]},"
                    "{\"ip_cidr\":[\"not-a-cidr\",\"10.9.0.0/16\"]},"
                    "{\"domain\":[1,\"k.com\"],\"ip_cidr\":[{}]},"
                    "{\"ip_cidr\":[\"10.8.0.0/16\"],\"port\":1e300}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    ASSERT_STR_EQ("subnet 10.9.0.0/16 - -", row(&g, 0));
    ASSERT_STR_EQ("domain k.com - -", row(&g, 1));
    ASSERT_EQ_FMT((size_t)7, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a leading dot or case kept, v6 taken for v4, a bare address refused, or a regex altered. */
TEST spelling_of_names_addresses_and_regexes(void) {
    got_t g = parse("{\"rules\":[{\"domain_suffix\":[\".Example.COM\"],"
                    "\"ip_cidr\":[\"2001:db8::/32\",\"1.2.3.4\"],"
                    "\"domain_regex\":[\"^A\\\\.example\\\\.com$\"]}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)4, g.rs.n, "%zu");
    ASSERT_STR_EQ("namespace example.com - -", row(&g, 0));
    ASSERT_STR_EQ("regex ^A\\.example\\.com$ - -", row(&g, 1));
    ASSERT_STR_EQ("subnet6 2001:db8::/32 - -", row(&g, 2));
    ASSERT_STR_EQ("subnet 1.2.3.4 - -", row(&g, 3));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: an HTML page or a broken rule-set read as an empty list instead of refused. */
TEST what_is_not_a_rule_set_is_refused_with_a_reason(void) {
    got_t g = parse("\n  <!DOCTYPE html><html>");
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT(g.st.why != NULL && strstr(g.st.why, "HTML") != NULL && strstr(g.st.why, "raw") != NULL);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    g = parse("{not json");
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT(g.st.why != NULL && strstr(g.st.why, "sing-box") != NULL);
    g = parse("{\"version\":2}");
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    g = parse("\xEF\xBB\xBF{\"rules\":[]}");
    ASSERT_EQm("a BOM and an empty rules array are an empty list", FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a repeated rule stored twice. */
TEST a_repeated_rule_is_stored_once(void) {
    got_t g = parse("{\"rules\":[{\"ip_cidr\":[\"10.0.0.0/8\"],\"network\":\"udp\",\"port\":53},"
                    "{\"ip_cidr\":[\"10.0.0.0/8\"],\"network\":\"udp\",\"port\":53},"
                    "{\"domain\":[\"a.com\",\"A.com\"]}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

static bool stop_at_first(void *ud, size_t n) {
    (void)n;
    ++*(int *)ud;
    return false;
}

/* Catches: no progress calls on a JSON list, so a huge one cannot be cancelled. */
TEST a_json_parse_reports_progress_and_can_be_stopped(void) {
    size_t n = 20001, cap = 32 + n * 16;
    char *body = malloc(cap);
    ASSERT(body != NULL);
    size_t at = (size_t)snprintf(body, cap, "{\"rules\":[{\"domain\":[");
    for (size_t i = 0; i < n; i++) {
        at += (size_t)snprintf(body + at, cap - at, "%s\"n%zu.com\"", i ? "," : "", i);
    }
    snprintf(body + at, cap - at, "]}]}");
    firc_sub_rules_t rs;
    firc_sub_rules_init(&rs);
    firc_sub_parse_stats_t st;
    int calls = 0;
    ASSERT_EQ(FIRC_ERR_CANCELED, firc_sub_parse_rules_stats(body, &rs, &st, stop_at_first, &calls));
    ASSERT_EQ(1, calls);
    ASSERT_EQ_FMT((size_t)0, rs.n, "%zu");
    free(body);
    PASS();
}

/* Catches: a repeated key read by its first value, where sing-box takes the last one. */
TEST a_repeated_key_is_not_widened_by_reading_the_first(void) {
    got_t g = parse("{\"rules\":[{\"domain\":[\"a.com\"],\"invert\":false,\"invert\":true}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    ASSERT_EQ_FMT((size_t)1, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a typed value read as a `#` comment and dropped silently, or an empty one not counted. */
TEST a_typed_value_is_never_a_comment_or_silently_swallowed(void) {
    got_t g = parse("{\"rules\":[{\"domain_regex\":[\"#x\"]},{\"domain\":[\"\"]}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
    ASSERT_STR_EQ("regex #x - -", row(&g, 0));
    ASSERT_EQ_FMT((size_t)1, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a domain_keyword with `*` or `?` turned into a wildcard that matches more. */
TEST a_literal_asterisk_in_a_keyword_is_dropped_not_widened(void) {
    got_t g = parse("{\"rules\":[{\"domain_keyword\":[\"a*b\",\"ok\"]}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
    ASSERT_STR_EQ("wildcard *ok* - -", row(&g, 0));
    ASSERT_EQ_FMT((size_t)1, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: an object that yields no rule neither refused nor counted as dropped. */
TEST an_object_that_yields_nothing_is_counted(void) {
    got_t g = parse("{\"rules\":[{},{\"network\":\"udp\"},{\"domain\":[\"a.com\"]}]}");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
    ASSERT_STR_EQ("domain a.com - -", row(&g, 0));
    ASSERT_EQ_FMT((size_t)2, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: text after the JSON value ignored instead of refused. */
TEST trailing_garbage_after_the_json_value_is_refused(void) {
    got_t g = parse("{\"rules\":[]}<html>");
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT(g.st.why != NULL && strstr(g.st.why, "sing-box") != NULL);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Builds `{"rules":[0,...]}` with `n` numbers: n+1 JSON value starts outside any string. */
static char *number_rules_body(size_t n) {
    size_t cap = 32 + n * 2;
    char *body = malloc(cap);
    if (body == NULL) { return NULL; }
    size_t at = (size_t)snprintf(body, cap, "{\"rules\":[");
    for (size_t i = 0; i < n; i++) { at += (size_t)snprintf(body + at, cap - at, "%s0", i ? "," : ""); }
    snprintf(body + at, cap - at, "]}");
    return body;
}

/* Catches: a body over the JSON value budget reaching cJSON, which can use 40x its size. */
TEST a_body_over_the_value_budget_is_refused_before_it_is_parsed(void) {
    char *body = number_rules_body(400000);
    ASSERT(body != NULL);
    got_t g = parse(body);
    free(body);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT(g.st.why != NULL && strstr(g.st.why, "too large") != NULL);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: an off-by-one in the budget check refusing a body exactly at the budget. */
TEST a_body_at_the_value_budget_boundary_parses(void) {
    char *body = number_rules_body(399999);
    ASSERT(body != NULL);
    got_t g = parse(body);
    free(body);
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    ASSERT_EQ_FMT((size_t)399999, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: commas and braces inside a string counted as JSON value starts. */
TEST commas_and_braces_inside_a_string_do_not_count_toward_the_budget(void) {
    size_t junk = 400001;
    size_t cap = 64 + junk;
    char *body = malloc(cap);
    ASSERT(body != NULL);
    size_t at = (size_t)snprintf(body, cap, "{\"rules\":[{\"domain_regex\":\"");
    for (size_t i = 0; i < junk; i++) { body[at++] = (i % 2 == 0) ? ',' : '{'; }
    at += (size_t)snprintf(body + at, cap - at, "\"}]}");
    body[at] = '\0';
    got_t g = parse(body);
    free(body);
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERTm("not the budget's refusal", g.st.why == NULL || strstr(g.st.why, "JSON values") == NULL);
    firc_sub_rules_free(&g.rs);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(discord_full_is_six_namespaces_and_fourteen_udp_prefixes);
    RUN_TEST(ports_without_network_are_a_tcp_and_a_udp_rule);
    RUN_TEST(sixteen_slots_are_two_rules);
    RUN_TEST(fifteen_slots_are_one_rule);
    RUN_TEST(ranges_open_at_either_end_and_single_ports);
    RUN_TEST(network_without_ports);
    RUN_TEST(names_beside_a_constraint_are_taken_unconstrained);
    RUN_TEST(an_object_firc_cannot_honour_is_dropped_whole);
    RUN_TEST(a_value_that_cannot_be_honoured_drops_what_it_constrains);
    RUN_TEST(spelling_of_names_addresses_and_regexes);
    RUN_TEST(what_is_not_a_rule_set_is_refused_with_a_reason);
    RUN_TEST(a_repeated_rule_is_stored_once);
    RUN_TEST(a_json_parse_reports_progress_and_can_be_stopped);
    RUN_TEST(a_repeated_key_is_not_widened_by_reading_the_first);
    RUN_TEST(a_typed_value_is_never_a_comment_or_silently_swallowed);
    RUN_TEST(a_literal_asterisk_in_a_keyword_is_dropped_not_widened);
    RUN_TEST(an_object_that_yields_nothing_is_counted);
    RUN_TEST(trailing_garbage_after_the_json_value_is_refused);
    RUN_TEST(a_body_over_the_value_budget_is_refused_before_it_is_parsed);
    RUN_TEST(a_body_at_the_value_budget_boundary_parses);
    RUN_TEST(commas_and_braces_inside_a_string_do_not_count_toward_the_budget);
    GREATEST_MAIN_END();
}
