#include "greatest.h"

#include "firc/rulesnap.h"
#include <arpa/inet.h>
#include <stdlib.h>
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

static void add_entry(char ***list, size_t *n, const char *entry)
{
    char **grown = realloc(*list, (*n + 1) * sizeof(char *));
    if (grown == NULL) { abort(); }
    *list = grown;
    grown[(*n)++] = strdup(entry);
}

static firc_group_t *shared_group(firc_config_t *cfg, uint8_t id, const char *name, bool rule_on)
{
    firc_group_t *g = make_group((firc_id_t){{id, 0, 0, 0}}, name, true);
    firc_group_add_rule(g, make_rule((firc_id_t){{id, 1, 0, 0}}, "namespace", "shared.test", rule_on));
    firc_config_add_group(cfg, g);
    return g;
}

static firc_ip_t client_at(const char *text)
{
    firc_ip_t c = {{0}, 4};
    if (inet_pton(AF_INET, text, c.b) != 1) { abort(); }
    return c;
}

static const char *owner_for(const firc_ruleset_snapshot_t *snap, const char *client)
{
    firc_ip_t c = client_at(client);
    const firc_group_snapshot_t *g =
        firc_ruleset_snapshot_owner(snap, "x.shared.test", &c, NULL, NULL, NULL, NULL);
    return g != NULL ? g->name : "-";
}

static bool in_kids(const char *policy, const firc_ip_t *client, void *ud)
{
    (void)ud;
    return strcmp(policy, "Kids") == 0 && client->b[3] == 5;
}

/* Catches: the owner chosen by the device first, so a scoped group below takes an unscoped upper group's devices. */
TEST an_unscoped_upper_group_owns_every_device(void)
{
    firc_config_t cfg = make_cfg();
    shared_group(&cfg, 1, "upper", true);
    firc_group_t *lower = shared_group(&cfg, 2, "lower", true);
    add_entry(&lower->devices.allow, &lower->devices.n_allow, "192.168.1.5");
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_STR_EQ("upper", owner_for(snap, "192.168.1.5"));
    ASSERT_STR_EQ("upper", owner_for(snap, "192.168.1.9"));
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: the first matching group kept for a device its selector turns away, or the search stopping there. */
TEST disjoint_selectors_split_one_name(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *upper = shared_group(&cfg, 1, "upper", true);
    add_entry(&upper->devices.allow, &upper->devices.n_allow, "192.168.1.5");
    firc_group_t *lower = shared_group(&cfg, 2, "lower", true);
    add_entry(&lower->devices.allow, &lower->devices.n_allow, "192.168.1.9");
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_STR_EQ("upper", owner_for(snap, "192.168.1.5"));
    ASSERT_STR_EQ("lower", owner_for(snap, "192.168.1.9"));
    ASSERT_STR_EQm("a device neither admits has no owner", "-", owner_for(snap, "192.168.1.7"));
    firc_ip_t stranger = client_at("192.168.1.7");
    const firc_group_snapshot_t *first = NULL;
    ASSERT_EQ(NULL, firc_ruleset_snapshot_owner(snap, "x.shared.test", &stranger, NULL, NULL, NULL, &first));
    ASSERTm("the first matching group is still named", first != NULL && strcmp(first->name, "upper") == 0);
    ASSERT_EQ(NULL, firc_ruleset_snapshot_owner(snap, "x.other.test", &stranger, NULL, NULL, NULL, &first));
    ASSERT_EQm("no match names no group", NULL, first);
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a query without a client address given no owner instead of the first matching group. */
TEST a_query_without_a_client_goes_to_the_first_matching_group(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *upper = shared_group(&cfg, 1, "upper", true);
    add_entry(&upper->devices.allow, &upper->devices.n_allow, "192.168.1.5");
    shared_group(&cfg, 2, "lower", true);
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    const firc_group_snapshot_t *g =
        firc_ruleset_snapshot_owner(snap, "x.shared.test", NULL, NULL, NULL, NULL, NULL);
    ASSERT(g != NULL);
    ASSERT_STR_EQ("upper", g->name);
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a deny entry in the upper group read as the end of the search. */
TEST a_deny_in_the_upper_group_passes_that_device_down(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *upper = shared_group(&cfg, 1, "upper", true);
    add_entry(&upper->devices.deny, &upper->devices.n_deny, "192.168.1.5");
    shared_group(&cfg, 2, "lower", true);
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_STR_EQ("lower", owner_for(snap, "192.168.1.5"));
    ASSERT_STR_EQ("upper", owner_for(snap, "192.168.1.9"));
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a disabled rule or a disabled group still taking the name. */
TEST a_disabled_rule_or_group_is_skipped(void)
{
    firc_config_t cfg = make_cfg();
    shared_group(&cfg, 1, "rule-off", false);
    firc_group_t *off = shared_group(&cfg, 2, "group-off", true);
    off->enable = false;
    shared_group(&cfg, 3, "lower", true);
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT_STR_EQ("lower", owner_for(snap, "192.168.1.5"));
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: the selector asked without the caller's policy resolver. */
TEST a_policy_entry_is_resolved_by_the_callers_resolver(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *upper = shared_group(&cfg, 1, "upper", true);
    add_entry(&upper->devices.allow, &upper->devices.n_allow, "policy:Kids");
    shared_group(&cfg, 2, "lower", true);
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    firc_ip_t kid = client_at("192.168.1.5"), other = client_at("192.168.1.9");
    const firc_group_snapshot_t *g = firc_ruleset_snapshot_owner(snap, "x.shared.test", &kid, in_kids, NULL, NULL, NULL);
    ASSERT(g != NULL && strcmp(g->name, "upper") == 0);
    g = firc_ruleset_snapshot_owner(snap, "x.shared.test", &other, in_kids, NULL, NULL, NULL);
    ASSERT(g != NULL && strcmp(g->name, "lower") == 0);
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
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
    ASSERT(firc_ruleset_snapshot_owner(other, "sub.example.com", NULL, NULL, NULL, NULL, NULL) != NULL);
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
    const firc_group_snapshot_t *owner =
        firc_ruleset_snapshot_owner(snap, "shared.example", NULL, NULL, NULL, NULL, NULL);
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
    const firc_group_snapshot_t *owner =
        firc_ruleset_snapshot_owner(snap, "shared.example", NULL, NULL, NULL, NULL, NULL);
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
    const firc_group_snapshot_t *owner_a =
        firc_ruleset_snapshot_owner(snap, "a.example", NULL, NULL, NULL, NULL, NULL);
    const firc_group_snapshot_t *owner_b =
        firc_ruleset_snapshot_owner(snap, "b.example", NULL, NULL, NULL, NULL, NULL);
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

    const firc_group_snapshot_t *w =
        firc_ruleset_snapshot_owner(snap, "www.example.com", NULL, NULL, NULL, NULL, NULL);
    ASSERT(w != NULL);
    ASSERT_STR_EQm("the earlier group wins, not the later one", "first", w->name);

    w = firc_ruleset_snapshot_owner(snap, "other.test", NULL, NULL, NULL, NULL, NULL);
    ASSERT(w != NULL);
    ASSERT_STR_EQ("third", w->name);

    ASSERT_EQ(NULL, firc_ruleset_snapshot_owner(snap, "unmatched.invalid", NULL, NULL, NULL, NULL, NULL));

    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a rule the config load already reported said again at every rebuild, or one that does not compile taking the rest of its group with it. */
TEST a_rule_that_cannot_compile_is_skipped_quietly_at_rebuild(void)
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
        firc_log_set_output_floor(FIRC_LOG_INFO);
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
        ASSERT_EQ_FMTm(out, (size_t)0, lines, "%zu");

        ASSERT(firc_ruleset_snapshot_owner(snap, "ok.example.com", NULL, NULL, NULL, NULL, NULL) != NULL);
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
    firc_log_set_output_floor(FIRC_LOG_INFO);
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
    ASSERT(firc_ruleset_snapshot_owner(snap, "a.example.com", NULL, NULL, NULL, NULL, NULL) != NULL);
    ASSERT_EQ(NULL, firc_ruleset_snapshot_owner(snap, "b.example.com", NULL, NULL, NULL, NULL, NULL));
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

/* Catches: the snapshot dropping the answer, or marking a routing group as a block group. */
TEST the_snapshot_carries_a_block_groups_answer(void)
{
    firc_config_t cfg = make_cfg();
    firc_group_t *b = make_group((firc_id_t){{1, 0, 0, 0}}, "b", true);
    firc_strset(&b->iface, FIRC_IFACE_BLOCK);
    b->block = FIRC_BLOCK_REFUSED;
    firc_group_t *n = make_group((firc_id_t){{2, 0, 0, 0}}, "n", true);
    firc_strset(&n->iface, "nwg0");
    n->block = FIRC_BLOCK_NXDOMAIN;
    firc_group_t *z = make_group((firc_id_t){{3, 0, 0, 0}}, "z", true);
    firc_strset(&z->iface, FIRC_IFACE_BLOCK);
    firc_config_add_group(&cfg, b);
    firc_config_add_group(&cfg, n);
    firc_config_add_group(&cfg, z);
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERT(snap != NULL);
    ASSERT_EQ(3u, (unsigned)snap->n_groups);
    ASSERT_EQ((int)FIRC_BLOCK_REFUSED, (int)snap->groups[0]->block);
    ASSERT_EQ(-1, (int)snap->groups[1]->block);
    ASSERT_EQ((int)FIRC_BLOCK_NULL, (int)snap->groups[2]->block);
    firc_ruleset_snapshot_free(snap);
    firc_config_clear(&cfg);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_rule_that_cannot_compile_is_skipped_quietly_at_rebuild);
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
    RUN_TEST(an_unscoped_upper_group_owns_every_device);
    RUN_TEST(disjoint_selectors_split_one_name);
    RUN_TEST(a_query_without_a_client_goes_to_the_first_matching_group);
    RUN_TEST(a_deny_in_the_upper_group_passes_that_device_down);
    RUN_TEST(a_disabled_rule_or_group_is_skipped);
    RUN_TEST(a_policy_entry_is_resolved_by_the_callers_resolver);
    RUN_TEST(the_snapshot_carries_a_block_groups_answer);
    GREATEST_MAIN_END();
}
