#include "greatest.h"

#include <errno.h>
#include <stdio.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include "fake_rtnl.h"
#include "firc/mark.h"
#include "firc/rtnl.h"

typedef struct {
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
} fx_t;

static bool up(fx_t *f) {
    f->kernel = fake_rtnl_start(&f->rtnl);
    return f->kernel != NULL;
}
static void down(fx_t *f) {
    firc_rtnl_close(f->rtnl);
    fake_rtnl_stop(f->kernel);
}

TEST the_sweep_removes_only_rules_with_firc_s_mask_at_firc_s_priority(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x10000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY);
    fake_rtnl_add_rule(f.kernel, AF_INET6, 0x20000, FIRC_MARK_GROUP_MASK, 101, FIRC_RULE_PRIORITY);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x10000, FIRC_MARK_GROUP_MASK, RT_TABLE_MAIN, 49);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x6, 0xffffffff, 78, 49);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x30000, FIRC_MARK_GROUP_MASK, 102, 500);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x989, 0x989, 989, 90);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0xffffaaa, 0xffffffff, 4096, 100);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x5, 0xffffffff, 77, FIRC_RULE_PRIORITY);

    size_t removed = 99;
    ASSERT_EQ(FIRC_OK, firc_rtnl_clean_stale_rules(f.rtnl, &removed));
    ASSERT_EQ_FMT((size_t)3, removed, "%zu");
    fake_rtnl_msg_t m[16];
    size_t n = fake_rtnl_messages(f.kernel, m, 16), dels = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_DELRULE) { continue; }
        dels++;
        ASSERTm("only firc's priorities are touched", m[i].priority == FIRC_RULE_PRIORITY || m[i].priority == 49u);
        ASSERT_EQ_FMTm("only firc's mask is touched", FIRC_MARK_GROUP_MASK, m[i].mask, "%#x");
        ASSERTm("the foreign rule over our bits stays", m[i].mark != 0x30000);
    }
    ASSERT_EQ_FMT((size_t)3, dels, "%zu");
    down(&f);
    PASS();
}

/* Catches: a field taken although a rule with firc's mask at another priority holds it. */
TEST the_allocator_skips_every_field_a_rule_with_firc_s_mask_holds(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x10000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY);
    fake_rtnl_add_rule(f.kernel, AF_INET6, 0x20000, FIRC_MARK_GROUP_MASK, 101, 500);
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x989, 0x989, 989, 90);
    uint32_t field = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field(f.rtnl, &field));
    ASSERT_EQ_FMT(3u, field, "%u");
    down(&f);
    PASS();
}

/* Catches: a rule added at another priority, mask or table. */
TEST a_rule_is_added_at_firc_s_priority_over_the_group_mask(void) {
    fx_t f;
    ASSERT(up(&f));
    ASSERT_EQ(FIRC_OK, firc_rtnl_rule_add(f.rtnl, AF_INET, firc_mark_group_value(7), FIRC_MARK_GROUP_MASK, 107,
                                         firc_rule_priority_for_field(7)));
    fake_rtnl_msg_t m[4];
    ASSERT_EQ_FMT((size_t)1, fake_rtnl_messages(f.kernel, m, 4), "%zu");
    ASSERT_EQ_FMT((unsigned)RTM_NEWRULE, (unsigned)m[0].type, "%u");
    ASSERT_EQ_FMT(FIRC_RULE_PRIORITY, m[0].priority, "%u");
    ASSERT_EQ_FMT(0x70000u, m[0].mark, "%#x");
    ASSERT_EQ_FMT(FIRC_MARK_GROUP_MASK, m[0].mask, "%#x");
    ASSERT_EQ_FMT(107u, m[0].table, "%u");
    down(&f);
    PASS();
}

/* Catches: the reply twin added without its iif or suppress_prefixlength 0. */
TEST the_reply_add_carries_its_iif_and_suppress_prefixlength_zero(void) {
    fx_t f;
    ASSERT(up(&f));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_rtnl_rule_add_reply(f.rtnl, AF_INET, 0x70000, FIRC_MARK_GROUP_MASK, NULL, RT_TABLE_MAIN, 49));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_rtnl_rule_add_reply(f.rtnl, AF_INET, 0x70000, FIRC_MARK_GROUP_MASK, "", RT_TABLE_MAIN, 49));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_rtnl_rule_add_reply(f.rtnl, AF_INET, 0x70000, FIRC_MARK_GROUP_MASK, "sixteen-chars-xx", RT_TABLE_MAIN, 49));
    ASSERT_EQ(FIRC_OK, firc_rtnl_rule_add_reply(f.rtnl, AF_INET, 0x70000, FIRC_MARK_GROUP_MASK, "nwg0", RT_TABLE_MAIN, 49));
    ASSERT_EQ(FIRC_OK, firc_rtnl_rule_add(f.rtnl, AF_INET, 0x70000, FIRC_MARK_GROUP_MASK, 107, 50));
    fake_rtnl_msg_t m[4];
    ASSERT_EQ_FMT((size_t)2, fake_rtnl_messages(f.kernel, m, 4), "%zu");
    ASSERT_EQ_FMT(0, m[0].suppress, "%d");
    ASSERT_STR_EQ("nwg0", m[0].iif);
    ASSERT_STR_EQ("", m[1].iif);
    ASSERT_EQ_FMT((uint32_t)RT_TABLE_MAIN, m[0].table, "%u");
    ASSERT_EQ_FMTm("a plain add carries none", -1, m[1].suppress, "%d");
    down(&f);
    PASS();
}

/* Catches: an operator's route at the pool prefix taken over, or our own from a past run refused. */
TEST an_add_that_finds_a_foreign_route_at_the_pool_prefix_is_refused(void) {
    fx_t f;
    ASSERT(up(&f));
    static const uint8_t pool[4] = {198, 18, 0, 0};
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, pool, 15, 4096);
    fake_rtnl_fail_next(f.kernel, EEXIST);
    ASSERT_EQ_FMT(FIRC_ERR_EXIST, firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    down(&f);
    ASSERT(up(&f));
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, FIRC_RTPROT, pool, 15, 4096);
    fake_rtnl_fail_next(f.kernel, EEXIST);
    ASSERT_EQ_FMTm("our own leftover is adopted", FIRC_OK, firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    ASSERT_EQ_FMTm("adopted means no second write", (size_t)1, fake_rtnl_count(f.kernel, RTM_NEWROUTE, 0), "%zu");
    down(&f);
    ASSERT(up(&f));
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, FIRC_RTPROT, pool, 15, 4096);
    fake_rtnl_fail_next(f.kernel, EEXIST);
    ASSERT_EQ_FMT(FIRC_ERR_EXIST, firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    down(&f);
    ASSERT(up(&f));
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, pool, 15, 100);
    fake_rtnl_add_route(f.kernel, AF_INET, 200, RTN_UNICAST, RTPROT_BOOT, pool, 15, 4096);
    fake_rtnl_fail_next(f.kernel, EEXIST);
    ASSERT_EQ_FMTm("nothing at our key: the add is tried once more, and lands", FIRC_OK,
                   firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    ASSERT_EQ_FMT((size_t)2, fake_rtnl_count(f.kernel, RTM_NEWROUTE, 0), "%zu");
    down(&f);
    ASSERT(up(&f));
    fake_rtnl_fail_times(f.kernel, RTM_NEWROUTE, EEXIST, 2);
    ASSERT_EQ_FMT(FIRC_ERR_EXIST, firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    down(&f);
    PASS();
}

/* Catches: an untagged reject route at our key left without the tag. */
TEST an_untagged_reject_route_at_the_pool_prefix_is_restamped(void) {
    fx_t f;
    ASSERT(up(&f));
    static const uint8_t pool[4] = {198, 18, 0, 0};
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, RTPROT_BOOT, pool, 15, 4096);
    fake_rtnl_fail_next(f.kernel, EEXIST);
    ASSERT_EQ_FMT(FIRC_OK, firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    fake_rtnl_msg_t msgs[8];
    size_t n = fake_rtnl_messages(f.kernel, msgs, 8);
    size_t replaced = 0;
    for (size_t i = 0; i < n; i++) {
        if (msgs[i].type == RTM_NEWROUTE && (msgs[i].flags & NLM_F_REPLACE) && msgs[i].protocol == FIRC_RTPROT) { replaced++; }
    }
    ASSERT_EQ_FMTm("one tagged replace was sent", (size_t)1, replaced, "%zu");
    size_t removed = 0, left = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_purge_tagged_routes(f.rtnl, &removed, &left));
    ASSERT_EQ_FMTm("...and a purge now finds it", (size_t)1, removed, "%zu");
    down(&f);
    PASS();
}

/* Catches: a queued ACK of an earlier request read as this request's answer. */
TEST an_answer_of_another_exchange_is_not_read_as_this_ones(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_rtnl_stray_reply(f.kernel);
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWRULE, EPERM);
    firc_err_t err = firc_rtnl_rule_add(f.rtnl, AF_INET, 0x10000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY);
    ASSERT_EQ_FMTm("the kernel's refusal, not the stray success", FIRC_ERR_SYS, err, "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_rtnl_rule_add(f.rtnl, AF_INET, 0x10000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY),
                  "%d");
    down(&f);
    PASS();
}

/* Catches: a dump abandoned on a malformed message left running, so the next dump fails. */
TEST a_dump_abandoned_on_a_bad_message_is_read_to_its_end(void) {
    fx_t f;
    ASSERT(up(&f));
    static const uint8_t pool[4] = {198, 18, 0, 0};
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, FIRC_RTPROT, pool, 15, 4096);
    fake_rtnl_add_route(f.kernel, AF_INET, 100, RTN_UNREACHABLE, FIRC_RTPROT, pool, 15, 5);
    fake_rtnl_short_error_in_dump(f.kernel);
    size_t removed = 0, left = 0;
    ASSERT_EQ_FMTm("a message too short to be the error it claims to be", FIRC_ERR_PROTO,
                   firc_rtnl_purge_tagged_routes(f.rtnl, &removed, &left), "%d");
    ASSERT_EQ_FMTm("the next dump runs", FIRC_OK, firc_rtnl_purge_tagged_routes(f.rtnl, &removed, &left), "%d");
    ASSERT_EQ_FMT((size_t)2, removed, "%zu");
    down(&f);
    PASS();
}

/* Catches: only the first route at the key checked, hiding an operator's route behind ours. */
TEST every_route_at_the_key_is_looked_at_not_only_the_first(void) {
    fx_t f;
    ASSERT(up(&f));
    static const uint8_t pool[4] = {198, 18, 0, 0};
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, FIRC_RTPROT, pool, 15, 4096);
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, pool, 15, 4096);
    fake_rtnl_route_via(f.kernel, 5, NULL, 0);
    ASSERT_EQ_FMT(FIRC_ERR_EXIST, firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    down(&f);
    PASS();
}

/* Catches: a v6 purge delete without a device, taking an operator's route at the same key. */
TEST a_purge_takes_its_own_v6_route_not_the_operators_at_the_same_key(void) {
    fx_t f;
    ASSERT(up(&f));
    static const uint8_t pool[16] = {0xfd, 0x00, 0x66, 0x69};
    static const uint8_t their_gw[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    fake_rtnl_add_route(f.kernel, AF_INET6, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, pool, 32, 4096);
    fake_rtnl_route_via(f.kernel, 5, their_gw, 16);
    fake_rtnl_add_route(f.kernel, AF_INET6, RT_TABLE_MAIN, RTN_UNREACHABLE, FIRC_RTPROT, pool, 32, 4096);
    size_t removed = 0, left = 0;
    ASSERT_EQ_FMT(FIRC_OK, firc_rtnl_purge_tagged_routes(f.rtnl, &removed, &left), "%d");
    ASSERT_EQ_FMT((size_t)1, removed, "%zu");
    ASSERT_EQ_FMTm("nothing of ours is left", (size_t)0, left, "%zu");
    ASSERT_EQ_FMTm("the operator's route survived the purge", FIRC_ERR_EXIST,
                   firc_rtnl_route_add_unreachable(f.rtnl, AF_INET6, RT_TABLE_MAIN, 4096, pool, 32), "%d");
    down(&f);
    static const uint8_t our_gw[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    ASSERT(up(&f));
    fake_rtnl_add_route(f.kernel, AF_INET6, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, pool, 32, 4096);
    fake_rtnl_route_via(f.kernel, 5, their_gw, 16);
    fake_rtnl_add_route(f.kernel, AF_INET6, RT_TABLE_MAIN, RTN_UNICAST, FIRC_RTPROT, pool, 32, 4096);
    fake_rtnl_route_via(f.kernel, 5, our_gw, 16);
    removed = 0;
    left = 0;
    ASSERT_EQ_FMT(FIRC_OK, firc_rtnl_purge_tagged_routes(f.rtnl, &removed, &left), "%d");
    ASSERT_EQ_FMT((size_t)1, removed, "%zu");
    ASSERT_EQ_FMTm("ours went, not the operator's route ahead of it on the same device", (size_t)0, left, "%zu");
    down(&f);
    PASS();
}

/* Catches: our tagged route restamped because an untagged one sits beside it. */
TEST a_tagged_route_anywhere_at_the_key_is_adopted_not_restamped(void) {
    fx_t f;
    ASSERT(up(&f));
    static const uint8_t pool[4] = {198, 18, 0, 0};
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, FIRC_RTPROT, pool, 15, 4096);
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_BLACKHOLE, RTPROT_BOOT, pool, 15, 4096);
    ASSERT_EQ_FMT(FIRC_OK, firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    ASSERT_EQ_FMTm("adopted: the one exclusive add, nothing written after it", (size_t)1,
                   fake_rtnl_count(f.kernel, RTM_NEWROUTE, 0), "%zu");
    down(&f);
    PASS();
}

/* Catches: a dump abandoned half-way left running, so the next one fails with EBUSY. */
TEST an_abandoned_dump_is_read_to_its_end_so_the_next_dump_can_start(void) {
    fx_t f;
    ASSERT(up(&f));
    static const uint8_t pool[4] = {198, 18, 0, 0};
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, FIRC_RTPROT, pool, 15, 4096);
    fake_rtnl_add_route(f.kernel, AF_INET, 100, RTN_UNREACHABLE, FIRC_RTPROT, pool, 15, 5);
    fake_rtnl_add_route(f.kernel, AF_INET, 200, RTN_UNREACHABLE, FIRC_RTPROT, pool, 15, 5);
    fake_rtnl_set_dump_reply_padding(f.kernel, 12000);
    size_t removed = 0, left = 0;
    ASSERT_EQ_FMT(FIRC_ERR_LIMIT, firc_rtnl_purge_tagged_routes(f.rtnl, &removed, &left), "%d");
    fake_rtnl_set_dump_reply_padding(f.kernel, 0);
    ASSERT_EQ_FMTm("the next dump runs", FIRC_OK, firc_rtnl_purge_tagged_routes(f.rtnl, &removed, &left), "%d");
    ASSERT_EQ_FMT((size_t)3, removed, "%zu");
    down(&f);
    PASS();
}

/* Catches: an end-of-file from the kernel read as success. */
TEST a_kernel_gone_silent_is_an_error_not_a_yes(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_rtnl_hangup(f.kernel);
    firc_err_t err = firc_rtnl_rule_add(f.rtnl, AF_INET, 0x10000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY);
    ASSERT_EQ_FMT(FIRC_ERR_IO, err, "%d");
    down(&f);
    PASS();
}

/* Catches: an EEXIST the dump cannot explain retried as a replace. */
TEST an_unexplained_eexist_is_retried_exclusively_never_as_a_replace(void) {
    fx_t f;
    ASSERT(up(&f));
    static const uint8_t pool[4] = {198, 18, 0, 0};
    fake_rtnl_fail_next(f.kernel, EEXIST);
    ASSERT_EQ_FMT(FIRC_OK, firc_rtnl_route_add_unreachable(f.rtnl, AF_INET, RT_TABLE_MAIN, 4096, pool, 15), "%d");
    fake_rtnl_msg_t m[8];
    size_t n = fake_rtnl_messages(f.kernel, m, 8), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE) { continue; }
        adds++;
        ASSERTm("exclusive", (m[i].flags & NLM_F_EXCL) != 0);
        ASSERT_FALSEm("never a replace: the occupant is unknown, not ours", (m[i].flags & NLM_F_REPLACE) != 0);
    }
    ASSERT_EQ_FMTm("the first add and one retry", (size_t)2, adds, "%zu");
    down(&f);
    PASS();
}

TEST a_reply_larger_than_the_buffer_is_an_error_not_a_miss(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_rtnl_set_link_reply_padding(f.kernel, 12000);
    firc_link_info_t li;
    bool found = true;
    firc_err_t err = firc_rtnl_link_by_name(f.rtnl, "lo", &li, &found);
    ASSERTm("an error, not a clean miss", err != FIRC_OK);
    down(&f);
    PASS();
}

typedef struct {
    size_t calls;
    size_t n;
    char owner[4][48];
    uint32_t field[4];
} seen_fields_t;

static void store_cb(void *ud, const firc_rtnl_field_t *v, size_t n) {
    seen_fields_t *s = ud;
    s->calls++;
    s->n = n;
    for (size_t i = 0; i < n && i < 4; i++) {
        snprintf(s->owner[i], sizeof(s->owner[i]), "%s", v[i].owner);
        s->field[i] = v[i].field;
    }
}

/* Catches: the seed ignored, so a group comes back on the lowest free field. */
TEST a_seeded_owner_gets_its_field_back_over_a_lower_free_one(void) {
    fx_t f;
    ASSERT(up(&f));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "aaaaaaaa", 5));
    uint32_t field = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "aaaaaaaa", &field));
    ASSERT_EQ_FMT(5u, field, "%u");
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "bbbbbbbb", &field));
    ASSERT_EQ_FMT(1u, field, "%u");
    down(&f);
    PASS();
}

/* Catches: seeded entries not counted as taken, so a new group lands on another owner's field. */
TEST a_new_owner_never_takes_a_seeded_field(void) {
    fx_t f;
    ASSERT(up(&f));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "aaaaaaaa", 1));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "cccccccc", 2));
    uint32_t field = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "bbbbbbbb", &field));
    ASSERT_EQ_FMT(3u, field, "%u");
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "cccccccc", &field));
    ASSERT_EQ_FMT(2u, field, "%u");
    down(&f);
    PASS();
}

/* Catches: two owners on one field, one owner on two fields, or a field outside 1..255 entering the table. */
TEST a_seed_naming_a_field_or_owner_already_seeded_is_refused(void) {
    fx_t f;
    ASSERT(up(&f));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "aaaaaaaa", 3));
    ASSERT_EQ(FIRC_ERR_EXIST, firc_rtnl_seed_mark_field(f.rtnl, "bbbbbbbb", 3));
    ASSERT_EQ(FIRC_ERR_EXIST, firc_rtnl_seed_mark_field(f.rtnl, "aaaaaaaa", 4));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_rtnl_seed_mark_field(f.rtnl, "dddddddd", 0));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_rtnl_seed_mark_field(f.rtnl, "dddddddd", 256));
    ASSERT_EQ(FIRC_ERR_INVAL,
              firc_rtnl_seed_mark_field(f.rtnl, "0123456789012345678901234567890123456789012345678", 7));
    uint32_t field = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "bbbbbbbb", &field));
    ASSERT_EQ_FMT(1u, field, "%u");
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "aaaaaaaa", &field));
    ASSERT_EQ_FMT(3u, field, "%u");
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "dddddddd", &field));
    ASSERT_EQ_FMT(2u, field, "%u");
    down(&f);
    PASS();
}

/* Catches: a change of assignment not reported to the store, or a report on no change or on a seed. */
TEST the_store_is_told_at_every_change_and_only_then(void) {
    fx_t f;
    ASSERT(up(&f));
    seen_fields_t got = {0};
    firc_rtnl_watch_mark_fields(f.rtnl, store_cb, &got);
    uint32_t field = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "aaaaaaaa", &field));
    ASSERT_EQ_FMT((size_t)1, got.calls, "%zu");
    ASSERT_EQ_FMT((size_t)1, got.n, "%zu");
    ASSERT_STR_EQ("aaaaaaaa", got.owner[0]);
    ASSERT_EQ_FMT(1u, got.field[0], "%u");
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "aaaaaaaa", &field));
    ASSERT_EQ_FMT((size_t)1, got.calls, "%zu");
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "bbbbbbbb", &field));
    ASSERT_EQ_FMT((size_t)2, got.calls, "%zu");
    ASSERT_EQ_FMT((size_t)2, got.n, "%zu");
    firc_rtnl_forget_mark_field(f.rtnl, "aaaaaaaa");
    ASSERT_EQ_FMT((size_t)3, got.calls, "%zu");
    ASSERT_EQ_FMT((size_t)1, got.n, "%zu");
    ASSERT_STR_EQ("bbbbbbbb", got.owner[0]);
    ASSERT_EQ_FMT(2u, got.field[0], "%u");
    firc_rtnl_forget_mark_field(f.rtnl, "eeeeeeee");
    ASSERT_EQ_FMT((size_t)3, got.calls, "%zu");
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "cccccccc", 9));
    ASSERT_EQ_FMT((size_t)3, got.calls, "%zu");
    fake_rtnl_add_rule(f.kernel, AF_INET, 0x20000, FIRC_MARK_GROUP_MASK, 100, FIRC_RULE_PRIORITY);
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "bbbbbbbb", &field));
    ASSERT_EQ_FMT(1u, field, "%u");
    ASSERT_EQ_FMT((size_t)4, got.calls, "%zu");
    ASSERT_EQ_FMT((size_t)2, got.n, "%zu");
    firc_rtnl_watch_mark_fields(f.rtnl, NULL, NULL);
    firc_rtnl_forget_mark_field(f.rtnl, "bbbbbbbb");
    ASSERT_EQ_FMT((size_t)4, got.calls, "%zu");
    down(&f);
    PASS();
}

/* Catches: the table handed on demand missing a seeded entry or calling the watcher instead. */
TEST the_table_is_handed_whole_on_demand(void) {
    fx_t f;
    ASSERT(up(&f));
    seen_fields_t watched = {0}, now = {0};
    firc_rtnl_watch_mark_fields(f.rtnl, store_cb, &watched);
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "aaaaaaaa", 5));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "bbbbbbbb", 2));
    firc_rtnl_fields_now(f.rtnl, store_cb, &now);
    ASSERT_EQ_FMT((size_t)1, now.calls, "%zu");
    ASSERT_EQ_FMT((size_t)2, now.n, "%zu");
    ASSERT_STR_EQ("aaaaaaaa", now.owner[0]);
    ASSERT_EQ_FMT(5u, now.field[0], "%u");
    ASSERT_STR_EQ("bbbbbbbb", now.owner[1]);
    ASSERT_EQ_FMT(2u, now.field[1], "%u");
    ASSERT_EQ_FMT((size_t)0, watched.calls, "%zu");
    down(&f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_sweep_removes_only_rules_with_firc_s_mask_at_firc_s_priority);
    RUN_TEST(the_allocator_skips_every_field_a_rule_with_firc_s_mask_holds);
    RUN_TEST(a_rule_is_added_at_firc_s_priority_over_the_group_mask);
    RUN_TEST(the_reply_add_carries_its_iif_and_suppress_prefixlength_zero);
    RUN_TEST(an_add_that_finds_a_foreign_route_at_the_pool_prefix_is_refused);
    RUN_TEST(an_untagged_reject_route_at_the_pool_prefix_is_restamped);
    RUN_TEST(an_answer_of_another_exchange_is_not_read_as_this_ones);
    RUN_TEST(a_dump_abandoned_on_a_bad_message_is_read_to_its_end);
    RUN_TEST(every_route_at_the_key_is_looked_at_not_only_the_first);
    RUN_TEST(a_purge_takes_its_own_v6_route_not_the_operators_at_the_same_key);
    RUN_TEST(a_tagged_route_anywhere_at_the_key_is_adopted_not_restamped);
    RUN_TEST(an_abandoned_dump_is_read_to_its_end_so_the_next_dump_can_start);
    RUN_TEST(a_kernel_gone_silent_is_an_error_not_a_yes);
    RUN_TEST(an_unexplained_eexist_is_retried_exclusively_never_as_a_replace);
    RUN_TEST(a_reply_larger_than_the_buffer_is_an_error_not_a_miss);
    RUN_TEST(a_seeded_owner_gets_its_field_back_over_a_lower_free_one);
    RUN_TEST(a_new_owner_never_takes_a_seeded_field);
    RUN_TEST(a_seed_naming_a_field_or_owner_already_seeded_is_refused);
    RUN_TEST(the_store_is_told_at_every_change_and_only_then);
    RUN_TEST(the_table_is_handed_whole_on_demand);
    GREATEST_MAIN_END();
}
