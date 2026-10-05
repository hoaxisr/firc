#include "greatest.h"

#include <string.h>
#include <sys/socket.h>

#include "fake_conntrack.h"
#include "firc/mark.h"
#include "firc/models.h"
#include "firc/stale_marks.h"

typedef struct {
    fake_ct_t *kernel;
    firc_ct_t *ct;
    firc_fakeip_t *pool;
} fx_t;

static bool up(fx_t *f) {
    memset(f, 0, sizeof(*f));
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37;
    c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    if (firc_fakeip_new(&c, &f->pool) != FIRC_OK) { return false; }
    f->kernel = fake_ct_start(&f->ct);
    return f->kernel != NULL;
}
static void down(fx_t *f) {
    firc_ct_close(f->ct);
    fake_ct_stop(f->kernel);
    firc_fakeip_free(f->pool);
}

/* Issues `name` for `group` so the pool takes a chunk; `addr` gets the chunk's first v4 address. */
static bool issue(fx_t *f, const char *group, const char *name, firc_ip_t *addr) {
    return firc_fakeip_get(f->pool, name, group, 1000, addr, NULL) == FIRC_OK;
}

/* Catches: a flow deleted although its group still holds the field it is marked with. */
TEST a_group_that_kept_its_field_keeps_its_flows(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "g1", "a.example.com", &a));
    uint32_t field = firc_mark_group_value(1);
    const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, a.b, reply, field | FIRC_MARK_HANDLED);

    firc_stale_group_t groups[1] = {{.id = "g1", .field = field}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("nothing is stale", (size_t)0, dropped, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a flow kept although its group now holds another field. */
TEST a_group_whose_field_moved_loses_its_flows(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "g1", "a.example.com", &a));
    const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, a.b, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_stale_group_t groups[1] = {{.id = "g1", .field = firc_mark_group_value(2)}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("the flow steered by the old field goes", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

TEST a_group_that_is_gone_loses_its_flows(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "gone", "a.example.com", &a));
    const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, a.b, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_stale_group_t groups[1] = {{.id = "still-here", .field = firc_mark_group_value(1)}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("its flows go with it", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

/* Catches: a sweep run on an empty, untrusted pool, deleting every routed flow. */
TEST an_untrusted_pool_state_sweeps_nothing(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 3, 9}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_stale_group_t groups[1] = {{.id = "g1", .field = firc_mark_group_value(1)}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, false, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("nothing was decided, so nothing was deleted", (size_t)0, dropped, "%zu");
    ASSERT_EQ_FMTm("the kernel was not even asked", (size_t)0, fake_ct_deletes(f.kernel), "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a flow kept for a group that holds no field this run. */
TEST a_group_that_holds_no_field_loses_its_flows(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "g1", "a.example.com", &a));
    const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, a.b, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_stale_group_t groups[1] = {{.id = "g1", .field = 0}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("a group that routes nothing steers nothing", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

/* Catches: a subnet flow kept although its field's new holder cannot have marked it. */
TEST a_flow_to_a_subnet_its_field_holder_cannot_reach_goes(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {10, 1, 2, 3}, reply[4] = {10, 1, 2, 3};
    uint32_t f1 = firc_mark_group_value(1);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, f1 | FIRC_MARK_HANDLED);

    firc_ct_chunk_t subs[1] = {{.family = AF_INET, .base = {192, 168, 0, 0}, .prefix = 16, .field = f1}};
    firc_stale_group_t groups[1] = {{.id = "g1", .field = f1, .subnets = subs, .n_subnets = 1}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("its holder cannot have produced it", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

TEST a_flow_inside_its_field_holder_s_subnet_stays(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {10, 1, 2, 3}, reply[4] = {10, 1, 2, 3};
    uint32_t f1 = firc_mark_group_value(1);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, f1 | FIRC_MARK_HANDLED);

    firc_ct_chunk_t subs[1] = {{.family = AF_INET, .base = {10, 0, 0, 0}, .prefix = 8, .field = f1}};
    firc_stale_group_t groups[1] = {{.id = "g1", .field = f1, .subnets = subs, .n_subnets = 1}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("10.1.2.3 is inside 10.0.0.0/8", (size_t)0, dropped, "%zu");
    down(&f);
    PASS();
}

/* Catches: a flow deleted although its field's holder routes 0.0.0.0/0. */
TEST a_holder_that_routes_everything_makes_nothing_stale(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {8, 8, 8, 8}, reply[4] = {8, 8, 8, 8};
    uint32_t f1 = firc_mark_group_value(1);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, f1 | FIRC_MARK_HANDLED);

    firc_ct_chunk_t subs[1] = {{.family = AF_INET, .base = {0, 0, 0, 0}, .prefix = 0, .field = f1}};
    firc_stale_group_t groups[1] = {{.id = "g1", .field = f1, .subnets = subs, .n_subnets = 1}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("a /0 holder could have produced it", (size_t)0, dropped, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a flow to a fake address no live chunk covers kept. */
TEST a_fake_address_no_live_chunk_covers_goes(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "gone", "a.example.com", &a));
    const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, a.b, reply, firc_mark_group_value(7) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t subs[1] = {
        {.family = AF_INET, .base = {10, 0, 0, 0}, .prefix = 8, .field = firc_mark_group_value(1)}};
    firc_stale_group_t groups[1] = {
        {.id = "g1", .field = firc_mark_group_value(1), .subnets = subs, .n_subnets = 1}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("an issued address nobody owns now", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

TEST a_chunk_names_its_owner_even_under_a_holder_that_routes_everything(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "g2", "a.example.com", &a));
    const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
    uint32_t f1 = firc_mark_group_value(1), f2 = firc_mark_group_value(2);
    fake_ct_add(f.kernel, AF_INET, src, a.b, reply, f1 | FIRC_MARK_HANDLED);

    firc_ct_chunk_t subs[1] = {{.family = AF_INET, .base = {0, 0, 0, 0}, .prefix = 0, .field = f1}};
    firc_stale_group_t groups[2] = {
        {.id = "g1", .field = f1, .subnets = subs, .n_subnets = 1},
        {.id = "g2", .field = f2},
    };
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 2, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("the chunk's owner decides, not the /0", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

TEST a_field_nobody_holds_is_left_alone_outside_the_pool(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {10, 1, 2, 3}, reply[4] = {10, 1, 2, 3};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, firc_mark_group_value(7) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t subs[1] = {
        {.family = AF_INET, .base = {10, 0, 0, 0}, .prefix = 8, .field = firc_mark_group_value(1)}};
    firc_stale_group_t groups[1] = {
        {.id = "g1", .field = firc_mark_group_value(1), .subnets = subs, .n_subnets = 1}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 1, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("nobody holds field 7, and nothing says it is ours", (size_t)0, dropped, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a subnet covering the pool vouching for an address another group's chunk owns. */
TEST a_subnet_covering_the_pool_does_not_answer_for_a_chunk(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "g2", "a.example.com", &a));
    const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
    uint32_t f1 = firc_mark_group_value(1), f2 = firc_mark_group_value(2);
    fake_ct_add(f.kernel, AF_INET, src, a.b, reply, f1 | FIRC_MARK_HANDLED);

    firc_ct_chunk_t subs[1] = {
        {.family = AF_INET, .base = {198, 18, 0, 0}, .prefix = 15, .field = f1}};
    firc_stale_group_t groups[2] = {
        {.id = "g1", .field = f1, .subnets = subs, .n_subnets = 1},
        {.id = "g2", .field = f2},
    };
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 2, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("the chunk's owner decides inside the pool", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

/* Catches: another group's subnet vouching for a flow marked with this field. */
TEST another_group_s_subnet_does_not_vouch_for_this_field(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "g1", "a.example.com", &a));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {10, 1, 2, 3}, reply[4] = {10, 1, 2, 3};
    uint32_t f1 = firc_mark_group_value(1), f2 = firc_mark_group_value(2);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, f1 | FIRC_MARK_HANDLED);

    firc_ct_chunk_t subs[1] = {
        {.family = AF_INET, .base = {10, 0, 0, 0}, .prefix = 8, .field = f2}};
    firc_stale_group_t groups[2] = {
        {.id = "g1", .field = f1},
        {.id = "g2", .field = f2, .subnets = subs, .n_subnets = 1},
    };
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 2, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("g1 could not have produced it", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

TEST a_group_s_subnet_rules_become_prefixes(void) {
    firc_group_t *g = firc_group_new();
    ASSERT(g != NULL);
    const char *types[] = {FIRC_RULE_SUBNET, FIRC_RULE_SUBNET6, FIRC_RULE_DOMAIN,
                           FIRC_RULE_SUBNET,  FIRC_RULE_SUBNET};
    const char *pats[] = {"10.0.0.0/8", "fd00::/16", "example.com", "not-a-prefix", "192.168.5.0/24"};
    const bool on[] = {true, true, true, true, false};
    for (size_t i = 0; i < 5; i++) {
        firc_rule_t *r = firc_rule_new();
        ASSERT(r != NULL);
        ASSERT_EQ(FIRC_OK, firc_strset(&r->type, types[i]));
        ASSERT_EQ(FIRC_OK, firc_strset(&r->rule, pats[i]));
        r->enable = on[i];
        ASSERT_EQ(FIRC_OK, firc_group_add_rule(g, r));
    }

    firc_ct_chunk_t *v = NULL;
    size_t n = 0;
    uint32_t field = firc_mark_group_value(3);
    ASSERTm("a group whose rules parse is not a failure",
            firc_stale_group_subnets(g, field, &v, &n));
    ASSERT_EQ_FMTm("the domain, the unparseable and the disabled are all out", (size_t)2, n, "%zu");
    ASSERT_EQ_FMT((int)AF_INET, (int)v[0].family, "%d");
    ASSERT_EQ_FMT(8, (int)v[0].prefix, "%d");
    ASSERT_EQ_FMTm("tagged with the field its group holds", field, v[0].field & FIRC_MARK_GROUP_MASK, "%u");
    ASSERTm("marked as a routed prefix, not an issued chunk", v[0].is_subnet);
    ASSERT_EQ_FMTm("the v6 rule is not dropped", (int)AF_INET6, (int)v[1].family, "%d");
    ASSERT_EQ_FMT(16, (int)v[1].prefix, "%d");
    free(v);
    firc_group_free(g);
    PASS();
}

/* Catches: a group with no subnet rules read as a failure that skips the sweep. */
TEST a_group_with_no_subnet_rules_is_not_a_failure(void) {
    firc_group_t *g = firc_group_new();
    ASSERT(g != NULL);
    firc_rule_t *r = firc_rule_new();
    ASSERT(r != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&r->type, FIRC_RULE_DOMAIN));
    ASSERT_EQ(FIRC_OK, firc_strset(&r->rule, "example.com"));
    r->enable = true;
    ASSERT_EQ(FIRC_OK, firc_group_add_rule(g, r));

    firc_ct_chunk_t *v = NULL;
    size_t n = 0;
    ASSERT(firc_stale_group_subnets(g, firc_mark_group_value(1), &v, &n));
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    ASSERT(v == NULL);
    firc_group_free(g);
    PASS();
}

/* Catches: a list group with no hand rules skipped by the sweep. */
TEST a_list_group_with_no_hand_rules_is_swept(void) {
    firc_group_t *g = firc_group_new();
    ASSERT(g != NULL);
    ASSERT_EQ_FMTm("no hand rules", (size_t)0, g->n_rules, "%zu");
    g->list = firc_group_list_new();
    ASSERT(g->list != NULL);
    ASSERT_EQ(FIRC_OK,
              firc_sub_rules_push(&g->list->rules, "10.0.0.0/8", FIRC_RULE_SUBNET, true,
                                  (firc_id_t){{1, 0, 0, 0}}));

    firc_ct_chunk_t *v = NULL;
    size_t n = 0;
    uint32_t field = firc_mark_group_value(1);
    ASSERTm("a group whose list rules parse is not a failure",
            firc_stale_group_subnets(g, field, &v, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_EQ_FMT((int)AF_INET, (int)v[0].family, "%d");
    ASSERT_EQ_FMT(8, (int)v[0].prefix, "%d");
    ASSERT_EQ_FMTm("tagged with the field its group holds", field, v[0].field & FIRC_MARK_GROUP_MASK,
                   "%u");
    free(v);
    firc_group_free(g);
    PASS();
}

/* Catches: every chunk tagged with the first group's field instead of its own. */
TEST each_group_s_chunks_carry_that_group_s_field(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a1 = {{0}, 0}, a2 = {{0}, 0};
    ASSERT(issue(&f, "g1", "a.example.com", &a1));
    ASSERT(issue(&f, "g2", "b.example.com", &a2));
    ASSERTm("the two groups got different chunks", memcmp(a1.b, a2.b, 3) != 0);
    uint32_t f1 = firc_mark_group_value(1), f2 = firc_mark_group_value(2);
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t r1[4] = {104, 18, 29, 1}, r2[4] = {104, 18, 29, 2};
    fake_ct_add(f.kernel, AF_INET, src, a1.b, r1, f1 | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, a2.b, r2, f1 | FIRC_MARK_HANDLED);

    firc_stale_group_t groups[2] = {{.id = "g1", .field = f1}, {.id = "g2", .field = f2}};
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 2, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("only the one whose chunk belongs to the other group", (size_t)1, dropped, "%zu");
    ASSERTm("g1's own flow stayed", !fake_ct_deleted(f.kernel, r1, 4));
    ASSERTm("the one in g2's chunk went", fake_ct_deleted(f.kernel, r2, 4));
    down(&f);
    PASS();
}

/* Catches: a group with no chunks making the sweep refuse. */
TEST a_group_with_no_chunks_yet_does_not_stop_the_sweep(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ip_t a = {{0}, 0};
    ASSERT(issue(&f, "g1", "a.example.com", &a));
    const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, a.b, reply, firc_mark_group_value(3) | FIRC_MARK_HANDLED);

    firc_stale_group_t groups[2] = {
        {.id = "quiet", .field = firc_mark_group_value(1)},
        {.id = "g1", .field = firc_mark_group_value(2)},
    };
    size_t dropped = 0;
    ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 2, FIRC_MARK_GROUP_MASK, &dropped));
    ASSERT_EQ_FMTm("g1's stale flow is still judged", (size_t)1, dropped, "%zu");
    down(&f);
    PASS();
}

/* Catches: `inexact` not reaching the chunks the sweep builds. */
TEST a_selector_group_s_chunk_keeps_a_flow_another_group_s_subnet_marked(void) {
    for (int sel = 1; sel >= 0; sel--) {
        fx_t f;
        ASSERT(up(&f));
        firc_ip_t a = {{0}, 0};
        ASSERT(issue(&f, "g1", "a.example.com", &a));
        const uint8_t src[4] = {192, 168, 1, 10}, reply[4] = {104, 18, 29, 7};
        uint32_t f1 = firc_mark_group_value(1), f2 = firc_mark_group_value(2);
        fake_ct_add(f.kernel, AF_INET, src, a.b, reply, f2 | FIRC_MARK_HANDLED);
        firc_ct_chunk_t all = {.family = AF_INET, .prefix = 0, .is_subnet = true};
        firc_stale_group_t groups[2] = {
            {.id = "g1", .field = f1, .inexact = sel == 1},
            {.id = "g2", .field = f2, .subnets = &all, .n_subnets = 1},
        };
        size_t dropped = 0;
        ASSERT_EQ(FIRC_OK, firc_stale_marks_sweep(f.ct, f.pool, true, groups, 2, FIRC_MARK_GROUP_MASK, &dropped));
        ASSERT_EQ_FMTm(sel ? "kept in a selector group's chunk" : "deleted in an ordinary chunk",
                       (size_t)(sel ? 0 : 1), dropped, "%zu");
        down(&f);
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_group_that_kept_its_field_keeps_its_flows);
    RUN_TEST(a_group_whose_field_moved_loses_its_flows);
    RUN_TEST(a_group_that_is_gone_loses_its_flows);
    RUN_TEST(an_untrusted_pool_state_sweeps_nothing);
    RUN_TEST(a_group_that_holds_no_field_loses_its_flows);
    RUN_TEST(a_flow_to_a_subnet_its_field_holder_cannot_reach_goes);
    RUN_TEST(a_flow_inside_its_field_holder_s_subnet_stays);
    RUN_TEST(a_holder_that_routes_everything_makes_nothing_stale);
    RUN_TEST(a_fake_address_no_live_chunk_covers_goes);
    RUN_TEST(a_chunk_names_its_owner_even_under_a_holder_that_routes_everything);
    RUN_TEST(a_field_nobody_holds_is_left_alone_outside_the_pool);
    RUN_TEST(a_subnet_covering_the_pool_does_not_answer_for_a_chunk);
    RUN_TEST(another_group_s_subnet_does_not_vouch_for_this_field);
    RUN_TEST(a_group_s_subnet_rules_become_prefixes);
    RUN_TEST(a_group_with_no_subnet_rules_is_not_a_failure);
    RUN_TEST(a_list_group_with_no_hand_rules_is_swept);
    RUN_TEST(each_group_s_chunks_carry_that_group_s_field);
    RUN_TEST(a_group_with_no_chunks_yet_does_not_stop_the_sweep);
    RUN_TEST(a_selector_group_s_chunk_keeps_a_flow_another_group_s_subnet_marked);
    GREATEST_MAIN_END();
}
