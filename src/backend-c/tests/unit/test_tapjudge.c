#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "firc/tap.h"

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {0};
    ip.len = 4;
    ip.b[0] = a; ip.b[1] = b; ip.b[2] = c; ip.b[3] = d;
    return ip;
}

typedef struct {
    uint8_t id;
    const char *name;
    const char *ns;
    const char *allow;
} gspec_t;

static firc_ruleset_snapshot_t *make_snap(const gspec_t *g, size_t n) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    for (size_t i = 0; i < n; i++) {
        firc_group_t *grp = firc_group_new();
        grp->id = (firc_id_t){{g[i].id, 0, 0, 0}};
        firc_strset(&grp->name, g[i].name);
        grp->enable = true;
        if (g[i].allow != NULL) {
            grp->devices.allow = calloc(1, sizeof(char *));
            grp->devices.allow[0] = strdup(g[i].allow);
            grp->devices.n_allow = 1;
        }
        firc_rule_t *r = firc_rule_new();
        r->id = (firc_id_t){{g[i].id, 1, 0, 0}};
        firc_strset(&r->type, "namespace");
        firc_strset(&r->rule, g[i].ns);
        r->enable = true;
        firc_group_add_rule(grp, r);
        firc_config_add_group(&cfg, grp);
    }
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    firc_config_clear(&cfg);
    return snap;
}

typedef struct {
    firc_dns_pipeline_t *p;
    firc_recall_t *recall;
    firc_tap_ctx_t ctx;
} rig_t;

static bool rig_up(rig_t *r, const gspec_t *g, size_t n) {
    memset(r, 0, sizeof(*r));
    r->p = firc_dns_pipeline_create();
    r->recall = firc_recall_new(64, 64, FIRC_RECALL_HORIZON);
    firc_ruleset_snapshot_t *snap = make_snap(g, n);
    if (r->p == NULL || r->recall == NULL || snap == NULL) { return false; }
    firc_dns_pipeline_set_snapshot(r->p, snap);
    r->ctx.snap = firc_dns_pipeline_snapshot(r->p);
    r->ctx.pipeline = r->p;
    r->ctx.recall = r->recall;
    return true;
}

static void rig_down(rig_t *r) {
    firc_recall_free(r->recall);
    firc_dns_pipeline_destroy(r->p);
}

static const gspec_t MEDIA_LAN[] = {{1, "media", "example.com", "192.168.1.0/24"}};

/* Catches: a covered client going to a real address firc recalled for a name not judged a bypass. */
TEST a_covered_client_going_to_a_recalled_address_is_a_bypass(void) {
    rig_t r;
    ASSERT(rig_up(&r, MEDIA_LAN, 1));
    firc_ip_t real = v4(104, 21, 0, 5), client = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "Video.Example.com", "01000000", 100);

    firc_tap_find_t f;
    ASSERT(firc_tap_judge_addr(&r.ctx, &client, &real, &f));
    ASSERT(f.group != NULL);
    ASSERT_STR_EQ("media", f.group->name);
    ASSERT_STR_EQm("the name the recall keeps, folded", "video.example.com", f.name);
    ASSERT_EQ_FMT((unsigned)FIRC_BYPASS_BY_ADDR, (unsigned)f.how, "%u");
    rig_down(&r);
    PASS();
}

/* Catches: an address the recall does not know judged a bypass. */
TEST an_address_the_recall_does_not_know_is_not(void) {
    rig_t r;
    ASSERT(rig_up(&r, MEDIA_LAN, 1));
    firc_ip_t real = v4(104, 21, 0, 5), other = v4(104, 21, 0, 6), client = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 100);

    firc_tap_find_t f;
    ASSERTm("the rig: the known one is", firc_tap_judge_addr(&r.ctx, &client, &real, &f));
    ASSERT_FALSE(firc_tap_judge_addr(&r.ctx, &client, &other, &f));
    ASSERT_EQ(NULL, f.group);

    r.ctx.recall = NULL;
    ASSERT_FALSE(firc_tap_judge_addr(&r.ctx, &client, &real, &f));
    rig_down(&r);
    PASS();
}

/* Catches: a client covered by another group reported for a name whose owner does not cover it. */
TEST a_client_the_owner_does_not_cover_is_not_reported(void) {
    static const gspec_t g[] = {
        {1, "media", "example.com", "192.168.1.42"},
        {2, "other", "other.org", "192.168.1.43"},
    };
    rig_t r;
    ASSERT(rig_up(&r, g, 2));
    firc_ip_t real = v4(104, 21, 0, 5), owned = v4(192, 168, 1, 42), other = v4(192, 168, 1, 43);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 100);
    ASSERTm("the rig: .43 is covered", firc_dns_pipeline_covers(r.p, &other));

    firc_tap_find_t f;
    ASSERTm("the owner's own client is", firc_tap_judge_addr(&r.ctx, &owned, &real, &f));
    ASSERT_FALSEm("another group's client is not", firc_tap_judge_addr(&r.ctx, &other, &real, &f));
    ASSERT_FALSE(firc_tap_judge_sni(&r.ctx, &other, &real, "video.example.com", &f));
    rig_down(&r);
    PASS();
}

/* Catches: a client no group covers reported. */
TEST a_client_nobody_covers_is_not_reported(void) {
    static const gspec_t g[] = {{1, "media", "example.com", "192.168.1.42"}};
    rig_t r;
    ASSERT(rig_up(&r, g, 1));
    firc_ip_t real = v4(104, 21, 0, 5), stranger = v4(10, 0, 0, 7), owned = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 100);

    firc_tap_find_t f;
    ASSERTm("the rig: the covered one is", firc_tap_judge_addr(&r.ctx, &owned, &real, &f));
    ASSERT_FALSE(firc_tap_judge_addr(&r.ctx, &stranger, &real, &f));
    ASSERT_FALSE(firc_tap_judge_sni(&r.ctx, &stranger, &real, "video.example.com", &f));

    r.ctx.pipeline = NULL;
    ASSERT_FALSE(firc_tap_judge_addr(&r.ctx, &owned, &real, &f));
    ASSERT_FALSE(firc_tap_judge_sni(&r.ctx, &owned, &real, "video.example.com", &f));
    rig_down(&r);
    PASS();
}

/* Catches: a recalled name judged by the group it had, not the one that owns it today. */
TEST a_recalled_name_now_owned_by_another_group_is_judged_by_that_group(void) {
    static const gspec_t g[] = {
        {2, "video", "video.example.com", "192.168.1.43"},
        {1, "media", "example.com", "192.168.1.0/24"},
    };
    rig_t r;
    ASSERT(rig_up(&r, g, 2));
    firc_ip_t real = v4(104, 21, 0, 5);
    firc_ip_t by_new = v4(192, 168, 1, 43), by_old_only = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 100);

    firc_tap_find_t f;
    ASSERT(firc_tap_judge_addr(&r.ctx, &by_new, &real, &f));
    ASSERT_STR_EQm("named by today's owner", "video", f.group->name);
    ASSERT_FALSEm("and a client only the old owner covers is not its bypass",
                  firc_tap_judge_addr(&r.ctx, &by_old_only, &real, &f));
    rig_down(&r);
    PASS();
}

/* Catches: a recalled name no group owns any more judged a bypass. */
TEST a_recalled_name_no_group_owns_any_more_is_not_a_bypass(void) {
    rig_t r;
    ASSERT(rig_up(&r, MEDIA_LAN, 1));
    firc_ip_t real = v4(104, 21, 0, 5), gone = v4(104, 21, 0, 6), client = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 100);
    firc_recall_real(r.recall, &gone, "video.example.org", "01000000", 100);

    firc_tap_find_t f;
    ASSERTm("the rig: an owned one is", firc_tap_judge_addr(&r.ctx, &client, &real, &f));
    ASSERT_FALSE(firc_tap_judge_addr(&r.ctx, &client, &gone, &f));
    ASSERT_EQ(NULL, f.group);
    rig_down(&r);
    PASS();
}

/* Catches: an SNI a group matches not judged a bypass, or not folded like the recall. */
TEST an_sni_a_group_matches_is_a_bypass(void) {
    rig_t r;
    ASSERT(rig_up(&r, MEDIA_LAN, 1));
    firc_ip_t dst = v4(104, 21, 0, 5), client = v4(192, 168, 1, 42);
    firc_tap_find_t f;
    ASSERT(firc_tap_judge_sni(&r.ctx, &client, &dst, "Video.Example.COM", &f));
    ASSERT_STR_EQ("media", f.group->name);
    ASSERT_STR_EQ("video.example.com", f.name);
    ASSERT_EQ_FMT((unsigned)FIRC_BYPASS_BY_SNI, (unsigned)f.how, "%u");
    rig_down(&r);
    PASS();
}

TEST an_sni_no_group_matches_is_not(void) {
    rig_t r;
    ASSERT(rig_up(&r, MEDIA_LAN, 1));
    firc_ip_t dst = v4(104, 21, 0, 5), client = v4(192, 168, 1, 42);
    firc_tap_find_t f;
    ASSERTm("the rig: a matched one is", firc_tap_judge_sni(&r.ctx, &client, &dst, "example.com", &f));
    ASSERT_FALSE(firc_tap_judge_sni(&r.ctx, &client, &dst, "bank.example.org", &f));
    ASSERT_EQ(NULL, f.group);
    ASSERT_FALSEm("no name is no bypass", firc_tap_judge_sni(&r.ctx, &client, &dst, "", &f));
    ASSERT_FALSE(firc_tap_judge_sni(&r.ctx, &client, &dst, NULL, &f));
    rig_down(&r);
    PASS();
}

/* A policy resolver that puts only the client .42 in the policy. */
static bool only_42(const char *policy, const firc_ip_t *client, void *ud) {
    int *calls = ud;
    if (calls != NULL) { (*calls)++; }
    return strcmp(policy, "Kids") == 0 && client->len == 4 && client->b[3] == 42;
}

TEST a_policy_in_the_selector_is_resolved_by_the_callers_resolver(void) {
    static const gspec_t g[] = {{1, "media", "example.com", "policy:Kids"}};
    rig_t r;
    ASSERT(rig_up(&r, g, 1));
    firc_dns_pipeline_set_policy_resolver(r.p, only_42, NULL, NULL);
    int calls = 0;
    r.ctx.policy = only_42;
    r.ctx.ud = &calls;
    firc_ip_t real = v4(104, 21, 0, 5), kid = v4(192, 168, 1, 42), adult = v4(192, 168, 1, 43);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 100);

    firc_tap_find_t f;
    ASSERT(firc_tap_judge_addr(&r.ctx, &kid, &real, &f));
    ASSERTm("through the caller's resolver, with the caller's ud", calls > 0);
    ASSERT_FALSE(firc_tap_judge_addr(&r.ctx, &adult, &real, &f));

    r.ctx.policy = NULL;
    ASSERT_FALSEm("with none, the entry matches nobody",
                  firc_tap_judge_addr(&r.ctx, &kid, &real, &f));
    rig_down(&r);
    PASS();
}

/* Catches: anything judged, on either path, while there is no snapshot. */
TEST nothing_is_judged_without_a_snapshot(void) {
    rig_t r;
    ASSERT(rig_up(&r, MEDIA_LAN, 1));
    firc_ip_t dst = v4(104, 21, 0, 5), client = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &dst, "example.com", "01000000", 1000);
    firc_tap_find_t f;
    ASSERTm("the rig would judge a bypass", firc_tap_judge_addr(&r.ctx, &client, &dst, &f));
    ASSERT(firc_tap_judge_sni(&r.ctx, &client, &dst, "example.com", &f));
    r.ctx.snap = NULL;
    memset(&f, 0x5a, sizeof(f));
    ASSERT_FALSEm("by address", firc_tap_judge_addr(&r.ctx, &client, &dst, &f));
    ASSERT_EQm("and the find is cleared", NULL, f.group);
    memset(&f, 0x5a, sizeof(f));
    ASSERT_FALSEm("by SNI", firc_tap_judge_sni(&r.ctx, &client, &dst, "example.com", &f));
    ASSERT_EQ(NULL, f.group);
    rig_down(&r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_covered_client_going_to_a_recalled_address_is_a_bypass);
    RUN_TEST(an_address_the_recall_does_not_know_is_not);
    RUN_TEST(a_client_the_owner_does_not_cover_is_not_reported);
    RUN_TEST(a_client_nobody_covers_is_not_reported);
    RUN_TEST(a_recalled_name_now_owned_by_another_group_is_judged_by_that_group);
    RUN_TEST(a_recalled_name_no_group_owns_any_more_is_not_a_bypass);
    RUN_TEST(an_sni_a_group_matches_is_a_bypass);
    RUN_TEST(an_sni_no_group_matches_is_not);
    RUN_TEST(a_policy_in_the_selector_is_resolved_by_the_callers_resolver);
    RUN_TEST(nothing_is_judged_without_a_snapshot);
    GREATEST_MAIN_END();
}
