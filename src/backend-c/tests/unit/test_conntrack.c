#include "greatest.h"

#include <time.h>

#define FIRC_CT_FLUSH_BUDGET_MS 1000
#define FIRC_CT_DRAIN_BUDGET_MS 500

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "fake_conntrack.h"
#include "firc/conntrack.h"
#include "firc/mark.h"

typedef struct {
    fake_ct_t *kernel;
    firc_ct_t *ct;
} fx_t;

static bool up(fx_t *f) {
    f->kernel = fake_ct_start(&f->ct);
    return f->kernel != NULL;
}
static void down(fx_t *f) {
    firc_ct_close(f->ct);
    fake_ct_stop(f->kernel);
}

/* Catches: a flush by mark leaving a group's flows on the old interface they were offloaded on. */
TEST a_groups_flows_go_when_its_mark_is_flushed(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, reply[4] = {198, 18, 0, 5};
    const uint8_t other_reply[4] = {8, 8, 8, 8};
    uint32_t ours = firc_mark_group_value(3);
    uint32_t theirs = firc_mark_group_value(4);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, ours | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, dst, other_reply, theirs);
    fake_ct_add(f.kernel, AF_INET, src, dst, other_reply, 0);

    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("only this group's flow", (size_t)1, deleted, "%zu");
    ASSERTm("ours went", fake_ct_deleted(f.kernel, reply, 4));
    ASSERTm("another group's flow stayed", !fake_ct_deleted(f.kernel, other_reply, 4));
    ASSERT_EQ_FMT((size_t)2, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a flush by mark comparing the handled bit or the firmware's bits as well as the group field. */
TEST the_mark_is_matched_on_the_group_field_alone(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, reply[4] = {198, 18, 0, 7};
    uint32_t ours = firc_mark_group_value(3);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, ours | FIRC_MARK_HANDLED | 0x989u);
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("the firmware's own bits do not hide it", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a flow to a fake address with no NAT binding, left from a fail-open window, kept. */
TEST flows_answered_with_a_fake_address_and_no_binding_go(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5};
    const uint8_t in_pool[4] = {198, 18, 3, 9}, outside[4] = {1, 1, 1, 1};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    const uint8_t v6_src[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const uint8_t v6_dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
    const uint8_t v6_in[16] = {0xfd, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const uint8_t v6_out[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4};
    const uint8_t pool6[16] = {0xfd, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, dst, in_pool, 0);
    fake_ct_add(f.kernel, AF_INET, src, dst, outside, 0);
    fake_ct_add(f.kernel, AF_INET6, v6_src, v6_dst, v6_in, 0);
    fake_ct_add(f.kernel, AF_INET6, v6_src, v6_dst, v6_out, 0);

    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_pool_replies(f.ct, pool4, 15, pool6, 16, &deleted));
    ASSERT_EQ_FMTm("one per family", (size_t)2, deleted, "%zu");
    ASSERTm("the v4 flow in the pool went", fake_ct_deleted(f.kernel, in_pool, 4));
    ASSERTm("the v6 flow in the pool went", fake_ct_deleted(f.kernel, v6_in, 16));
    ASSERTm("a real address is somebody else's flow", !fake_ct_deleted(f.kernel, outside, 4));
    ASSERTm("...in either family", !fake_ct_deleted(f.kernel, v6_out, 16));
    down(&f);
    PASS();
}

/* Catches: the last partial byte of the pool prefix masked the wrong way round. */
TEST the_last_partial_byte_of_the_pool_prefix_is_masked_correctly(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5};
    const uint8_t inside[4] = {198, 19, 0, 9};
    const uint8_t outside[4] = {198, 20, 0, 9};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, dst, inside, 0);
    fake_ct_add(f.kernel, AF_INET, src, dst, outside, 0);

    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_pool_replies(f.ct, pool4, 15, NULL, 0, &deleted));
    ASSERT_EQ_FMTm("only the one inside the prefix", (size_t)1, deleted, "%zu");
    ASSERTm("198.19.0.9 is in the pool", fake_ct_deleted(f.kernel, inside, 4));
    ASSERTm("198.20.0.9 is not", !fake_ct_deleted(f.kernel, outside, 4));
    down(&f);
    PASS();
}

/* Catches: a zero-length v6 pool prefix matching every v6 flow. */
TEST a_pool_with_no_v6_half_deletes_no_v6_flows(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t v6_src[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const uint8_t v6_dst[16] = {0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
    const uint8_t v6_any[16] = {0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET6, v6_src, v6_dst, v6_any, 0);
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_pool_replies(f.ct, pool4, 15, NULL, 0, &deleted));
    ASSERT_EQ_FMTm("nothing", (size_t)0, deleted, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a delete that re-encodes the tuple from fields, missing a flow without ports (ping). */
TEST a_flow_whose_tuple_has_no_ports_is_named_back_exactly(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, reply[4] = {198, 18, 0, 5};
    uint32_t ours = firc_mark_group_value(3);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, ours);
    fake_ct_last_is_icmp(f.kernel);
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("the ping's flow went", (size_t)1, deleted, "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a dump abandoned half-way, so every later dump on the socket fails with EBUSY. */
TEST an_abandoned_dump_is_read_to_its_end_so_the_next_flush_works(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5};
    const uint8_t r1[4] = {198, 18, 0, 5}, r2[4] = {198, 18, 0, 6};
    uint32_t ours = firc_mark_group_value(3);
    fake_ct_add(f.kernel, AF_INET, src, dst, r1, ours);
    fake_ct_add(f.kernel, AF_INET, src, dst, r2, ours);

    fake_ct_set_dump_padding(f.kernel, 40000);
    size_t deleted = 0;
    ASSERT_FALSEm("the over-long datagram is an error",
                  firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted) == FIRC_OK);
    ASSERT_EQ_FMTm("and the rest of that dump was read off the socket, not left there",
                   (size_t)0, fake_ct_unread(f.kernel), "%zu");

    fake_ct_set_dump_padding(f.kernel, 0);
    deleted = 0;
    ASSERT_EQ_FMTm("so the next flush runs", FIRC_OK,
                   firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted), "%d");
    ASSERT_EQ_FMTm("and drops both flows", (size_t)2, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a failed second-family dump discarding what the first family found. */
TEST a_second_family_that_fails_does_not_discard_the_first(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, reply[4] = {198, 18, 0, 5};
    uint32_t ours = firc_mark_group_value(3);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, ours);
    fake_ct_fail_dump_of(f.kernel, AF_INET6, EPERM);

    size_t deleted = 0;
    ASSERT_FALSEm("the refusal reaches the caller",
                  firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted) == FIRC_OK);
    ASSERT_EQ_FMTm("and the v4 flow it did find went", (size_t)1, deleted, "%zu");
    ASSERTm("really went", fake_ct_deleted(f.kernel, reply, 4));
    down(&f);
    PASS();
}

/* Catches: a delete without CTA_ID resetting a new flow that reuses the tuple. */
TEST a_delete_names_the_entry_the_dump_found_not_the_tuple(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, reply[4] = {198, 18, 0, 5};
    uint32_t ours = firc_mark_group_value(3);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, ours);
    fake_ct_recreate_on_next_delete(f.kernel);

    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("the entry firc saw was already gone, so nothing was dropped", (size_t)0, deleted,
                   "%zu");
    ASSERT_EQ_FMTm("and the flow that took its place is untouched", (size_t)1,
                   fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: the startup sweep deleting a flow whose group kept its mark field across a restart. */
TEST a_flow_whose_group_kept_its_field_stays(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {198, 18, 3, 7};
    const uint8_t reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    uint32_t field1 = firc_mark_group_value(1);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, field1 | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[1] = {{.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = field1}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("nothing is stale", (size_t)0, deleted, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a flow kept although its group now holds another field and another group steers it. */
TEST a_flow_whose_group_now_holds_another_field_goes(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {198, 18, 3, 7};
    const uint8_t reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(2)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("the flow steered by the old field goes", (size_t)1, deleted, "%zu");
    ASSERTm("really went", fake_ct_deleted(f.kernel, reply, 4));
    down(&f);
    PASS();
}

/* Catches: a flow kept although no group owns its chunk any more. */
TEST a_flow_whose_group_is_gone_goes(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t orphan[4] = {198, 18, 9, 4};
    const uint8_t reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, orphan, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(1)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("a chunk nobody owns is a group that is gone", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: the sweep judging a mark without the handled bit, deleting the firmware's policy flows. */
TEST a_mark_firc_did_not_write_is_left_alone(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t issued[4] = {198, 18, 9, 5}, reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, 0x0ffffaaau);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(2)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("the firmware's flow is untouched", (size_t)0, deleted, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a flow to a fake address no live chunk covers kept because its field is unheld. */
TEST a_fake_address_no_live_chunk_covers_goes(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t issued[4] = {198, 18, 9, 5}, reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(2)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("its group is gone", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a flow to a real address deleted only because nobody holds its field. */
TEST a_field_nobody_holds_outside_the_pool_is_left_alone(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t elsewhere[4] = {10, 1, 2, 3}, reply[4] = {10, 1, 2, 3};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, elsewhere, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(2)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("nobody holds field 1, and nothing says it is ours", (size_t)0, deleted, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a v4 chunk naming the owner of a v6 flow whose address happens to share its leading bytes. */
TEST a_chunk_answers_only_for_its_own_family(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    const uint8_t issued6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const uint8_t reply6[16] = {0x26, 0x06, 0x28, 0, 2, 0x20, 0, 1, 2, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46};
    const uint8_t pool6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    fake_ct_add(f.kernel, AF_INET6, src6, issued6, reply6, firc_mark_group_value(2) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {0xfd, 0x37, 0, 0}, .prefix = 16, .field = firc_mark_group_value(2)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, NULL, 0, pool6, 48, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("no v6 chunk covers it, so its group is gone", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a subnet rule covering the pool naming an owner for a flow inside it. */
TEST inside_the_pool_a_subnet_does_not_name_an_owner(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t issued[4] = {198, 18, 3, 9}, reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[2] = {
        {.family = AF_INET, .base = {198, 18, 0, 0}, .prefix = 15, .is_subnet = true,
         .field = firc_mark_group_value(1)},
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24,
         .field = firc_mark_group_value(2)},
    };
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 2,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("the chunk's owner decides, and it is not g1", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: another group's subnet vouching for a flow marked with the holder's field. */
TEST outside_the_pool_only_the_holder_s_own_subnet_vouches(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {10, 1, 2, 3}, reply[4] = {10, 1, 2, 3};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[2] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24,
         .field = firc_mark_group_value(1)},
        {.family = AF_INET, .base = {10, 0, 0, 0}, .prefix = 8, .is_subnet = true,
         .field = firc_mark_group_value(2)},
    };
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 2,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("g1 could not have produced it", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a flush with no overall time budget blocking the loop on a silent kernel. */
TEST a_kernel_that_never_answers_does_not_stop_the_flush(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {198, 18, 3, 7}, reply[4] = {198, 18, 3, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, 0);
    fake_ct_never_answer_dumps(f.kernel);

    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    size_t deleted = 0;
    firc_err_t err = firc_ct_flush_pool_replies(f.ct, pool4, 15, NULL, 0, &deleted);
    clock_gettime(CLOCK_MONOTONIC, &b);
    int64_t ms = (int64_t)(b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;

    ASSERT_EQ_FMTm("it gave up rather than finishing", FIRC_ERR_AGAIN, err, "%d");
    ASSERT_EQ_FMTm("and deleted nothing, having seen nothing", (size_t)0, deleted, "%zu");
    ASSERTm("it came back", ms < 4000);
    ASSERTm("and it did not pay the budget twice, once per family", ms < 2000);
    ASSERT_EQ_FMTm("the spent budget stopped the next request being sent", (size_t)1,
                   fake_ct_dumps(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: deletes the kernel never acked reported as a flush with nothing to do. */
TEST deletes_the_kernel_never_acks_are_not_reported_as_success(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {198, 18, 3, 7}, reply[4] = {198, 18, 3, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    const uint8_t dst2[4] = {198, 18, 3, 8}, dst3[4] = {198, 18, 3, 9};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, 0);
    fake_ct_add(f.kernel, AF_INET, src, dst2, dst2, 0);
    fake_ct_add(f.kernel, AF_INET, src, dst3, dst3, 0);
    fake_ct_never_answer_deletes(f.kernel);

    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    size_t deleted = 0;
    firc_err_t err = firc_ct_flush_pool_replies(f.ct, pool4, 15, NULL, 0, &deleted);
    clock_gettime(CLOCK_MONOTONIC, &b);
    int64_t ms = (int64_t)(b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;

    ASSERTm("the dump found it", fake_ct_deletes(f.kernel) > 0);
    ASSERT_EQ_FMTm("nothing was confirmed gone", (size_t)0, deleted, "%zu");
    ASSERT_EQ_FMTm("and the caller is told the flush did not finish", FIRC_ERR_AGAIN, err, "%d");
    ASSERT_EQ_FMTm("inside one budget and one drain", true,
                   ms < FIRC_CT_FLUSH_BUDGET_MS + FIRC_CT_DRAIN_BUDGET_MS + 300, "%d");
    down(&f);
    PASS();
}

/* Catches: a flush that spends its budget dumping both families and deletes nothing. */
TEST a_flush_that_runs_out_of_time_still_repairs_what_it_found(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t issued[4] = {198, 18, 3, 7}, pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, issued, issued, 0);
    const uint8_t src6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    const uint8_t issued6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const uint8_t pool6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    fake_ct_add(f.kernel, AF_INET6, src6, issued6, issued6, 0);

    fake_ct_delay_dumps(f.kernel, 600);

    size_t deleted = 0;
    firc_err_t err = firc_ct_flush_pool_replies(f.ct, pool4, 15, pool6, 48, &deleted);

    ASSERT_EQ_FMTm("it could not finish", FIRC_ERR_AGAIN, err, "%d");
    ASSERTm("but the family it did dump was repaired", fake_ct_deleted(f.kernel, issued, 4));
    ASSERT_EQ_FMTm("and says so", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a flush by mark dumping the whole table instead of sending a CTA_MARK filter. */
TEST a_flush_by_mark_asks_the_kernel_for_that_mark(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {8, 8, 8, 8}, reply[4] = {8, 8, 8, 8};
    uint32_t ours = firc_mark_group_value(3) | FIRC_MARK_HANDLED;
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, ours);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, firc_mark_group_value(4) | FIRC_MARK_HANDLED);

    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, firc_mark_group_value(3),
                                             FIRC_MARK_GROUP_MASK, &deleted));
    uint32_t value = 0, mask = 0;
    ASSERTm("the request named a mark", fake_ct_dump_filtered_on_mark(f.kernel, &value, &mask));
    ASSERT_EQ_FMTm("the group's field", firc_mark_group_value(3), value & FIRC_MARK_GROUP_MASK, "%u");
    ASSERT_EQ_FMTm("masked to the field", (uint32_t)FIRC_MARK_GROUP_MASK, mask, "%u");
    ASSERT_EQ_FMTm("only ours", (size_t)1, deleted, "%zu");
    ASSERT_EQ_FMTm("the other group's flow is untouched", (size_t)1, fake_ct_remaining(f.kernel),
                   "%zu");
    down(&f);
    PASS();
}

/* Catches: a filter value sent unmasked, which a real kernel matches against nothing. */
TEST a_filter_value_is_masked_before_it_is_sent(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {8, 8, 8, 8}, reply[4] = {8, 8, 8, 8};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply,
                firc_mark_group_value(3) | FIRC_MARK_HANDLED);

    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct,
                                             firc_mark_group_value(3) | FIRC_MARK_HANDLED,
                                             FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("the group's flow is still found", (size_t)1, deleted, "%zu");
    uint32_t value = 0, mask = 0;
    ASSERT(fake_ct_dump_filtered_on_mark(f.kernel, &value, &mask));
    ASSERT_EQ_FMTm("nothing outside the mask reaches the kernel", (uint32_t)0, value & ~mask, "%u");
    down(&f);
    PASS();
}

/* Catches: the stale-mark sweep not filtering on the handled bit as both value and mask. */
TEST the_stale_mark_sweep_asks_for_entries_firc_marked(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t issued[4] = {198, 18, 9, 5}, reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, 0x0ffffaaau);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(2)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    uint32_t value = 0, mask = 0;
    ASSERTm("the request named a mark", fake_ct_dump_filtered_on_mark(f.kernel, &value, &mask));
    ASSERT_EQ_FMTm("the handled bit", (uint32_t)FIRC_MARK_HANDLED, value, "%u");
    ASSERT_EQ_FMTm("...as the mask too", (uint32_t)FIRC_MARK_HANDLED, mask, "%u");
    ASSERT_EQ_FMTm("the issued address nobody owns goes", (size_t)1, deleted, "%zu");
    ASSERT_EQ_FMTm("the firmware's flow stays", (size_t)1, fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: wanted() dropping its handled-bit check when the kernel ignores the filter. */
TEST a_kernel_that_ignores_the_filter_still_gets_the_right_answer(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t issued[4] = {198, 18, 9, 5}, reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, 0x0ffffaaau);
    fake_ct_ignore_mark_filter(f.kernel);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(2)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERTm("it asked all the same", fake_ct_dump_filtered_on_mark(f.kernel, NULL, NULL));
    ASSERT_EQ_FMTm("and firc still judged only its own", (size_t)1, deleted, "%zu");
    ASSERT_EQ_FMTm("the firmware's flow survives the fallback path", (size_t)1,
                   fake_ct_remaining(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: a kernel that rejects the filter read as a clean table instead of retried unfiltered. */
TEST a_kernel_that_refuses_the_filter_falls_back_to_the_whole_table(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t a_issued[4] = {198, 18, 9, 5}, a_reply[4] = {104, 18, 29, 7};
    const uint8_t b_issued[4] = {198, 18, 9, 6}, b_reply[4] = {104, 18, 29, 8};
    fake_ct_add(f.kernel, AF_INET, src, a_issued, a_reply,
                firc_mark_group_value(1) | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, b_issued, b_reply,
                firc_mark_group_value(2) | FIRC_MARK_HANDLED);
    fake_ct_reject_mark_filter(f.kernel, EOPNOTSUPP);

    size_t deleted = 0;
    ASSERT_EQ_FMTm("the refusal is absorbed, not reported", (int)FIRC_OK,
                   (int)firc_ct_flush_by_mark(f.ct, firc_mark_group_value(1),
                                              FIRC_MARK_GROUP_MASK, &deleted),
                   "%d");
    ASSERT_EQ_FMTm("and the right flow still goes", (size_t)1, deleted, "%zu");
    ASSERT_EQ_FMTm("the other group's flow stays", (size_t)1, fake_ct_remaining(f.kernel), "%zu");

    size_t before = fake_ct_dumps(f.kernel);
    deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, firc_mark_group_value(2),
                                             FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("no retry after the first refusal", (size_t)2,
                   fake_ct_dumps(f.kernel) - before, "%zu");
    ASSERT_FALSEm("and it stopped sending the filter", fake_ct_dump_filtered_on_mark(f.kernel, NULL, NULL));
    ASSERT_EQ_FMTm("the second group goes too", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: the filter disabled for good although the unfiltered retry failed too. */
TEST a_refusal_that_is_not_about_the_filter_does_not_disarm_it(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t issued[4] = {198, 18, 9, 5}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);
    fake_ct_reject_mark_filter(f.kernel, EOPNOTSUPP);
    fake_ct_fail_next_dump(f.kernel, EOPNOTSUPP);
    fake_ct_fail_dump_of(f.kernel, AF_INET6, EOPNOTSUPP);

    size_t deleted = 0;
    ASSERTm("the failure reaches the caller",
            firc_ct_flush_by_mark(f.ct, firc_mark_group_value(1) | FIRC_MARK_HANDLED,
                                  FIRC_MARK_GROUP_MASK | FIRC_MARK_HANDLED, &deleted) != FIRC_OK);

    fake_ct_reject_mark_filter(f.kernel, 0);
    deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, firc_mark_group_value(1) | FIRC_MARK_HANDLED,
                                             FIRC_MARK_GROUP_MASK | FIRC_MARK_HANDLED, &deleted));
    ASSERTm("and the filter is still being sent", fake_ct_dump_filtered_on_mark(f.kernel, NULL, NULL));
    ASSERT_EQ_FMTm("and it works", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: EINVAL (ctnetlink not loaded yet) read as no filter support, losing the filter for good. */
TEST einval_is_reported_rather_than_read_as_no_filter(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t issued[4] = {198, 18, 9, 5}, reply[4] = {104, 18, 29, 7};
    fake_ct_add(f.kernel, AF_INET, src, issued, reply, firc_mark_group_value(1) | FIRC_MARK_HANDLED);
    fake_ct_reject_mark_filter(f.kernel, EINVAL);

    size_t deleted = 0;
    ASSERTm("the caller is told", firc_ct_flush_by_mark(f.ct, firc_mark_group_value(1) | FIRC_MARK_HANDLED,
                                                        FIRC_MARK_GROUP_MASK | FIRC_MARK_HANDLED,
                                                        &deleted) != FIRC_OK);
    ASSERT_EQ_FMTm("and nothing was deleted on a guess", (size_t)0, deleted, "%zu");

    fake_ct_reject_mark_filter(f.kernel, 0);
    deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, firc_mark_group_value(1) | FIRC_MARK_HANDLED,
                                             FIRC_MARK_GROUP_MASK | FIRC_MARK_HANDLED, &deleted));
    ASSERTm("still filtering", fake_ct_dump_filtered_on_mark(f.kernel, NULL, NULL));
    ASSERT_EQ_FMT((size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: the pool-reply sweep filtering by mark, though flows born in its window carry none. */
TEST the_pool_reply_sweep_cannot_ask_for_a_mark(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {198, 18, 3, 7}, reply[4] = {198, 18, 3, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, 0);

    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_pool_replies(f.ct, pool4, 15, NULL, 0, &deleted));
    ASSERT_FALSEm("no mark filter, or the flow it is looking for would be hidden",
                  fake_ct_dump_filtered_on_mark(f.kernel, NULL, NULL));
    ASSERT_EQ_FMTm("and it still finds it", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

static int64_t frozen_clock(void) { return 1000000; }

/* Catches: the hit array not reset between families, so one over the cap starves the other. */
TEST a_family_over_the_hit_cap_does_not_starve_the_other(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_ct_set_clock(f.ct, frozen_clock);
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    const uint8_t pool6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4100; i++) {
        uint8_t d[4] = {198, 18, (uint8_t)(3 + i / 250), (uint8_t)(i % 250)};
        fake_ct_add(f.kernel, AF_INET, src, d, d, 0);
    }
    const uint8_t src6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    const uint8_t issued6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    fake_ct_add(f.kernel, AF_INET6, src6, issued6, issued6, 0);

    size_t deleted = 0;
    firc_err_t err = firc_ct_flush_pool_replies(f.ct, pool4, 15, pool6, 48, &deleted);

    ASSERT_EQ_FMTm("it says there is more to do", FIRC_ERR_AGAIN, err, "%d");
    ASSERTm("the v6 flow was repaired even so", fake_ct_deleted(f.kernel, issued6, 16));
    down(&f);
    PASS();
}

/* Catches: the stale-mark sweep deleting an unmarked flow, which the pool-reply sweep owns. */
TEST an_unmarked_flow_is_not_this_querys_business(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t dst[4] = {198, 18, 3, 7};
    const uint8_t reply[4] = {104, 18, 29, 7};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, 0);

    firc_ct_chunk_t chunks[1] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(2)}};
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 1,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("field 0 is every unmarked flow on the router", (size_t)0, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: v6 flows not judged by the group's /64 chunks of the ULA prefix. */
TEST the_v6_half_is_judged_by_its_own_chunks(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t v6_src[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const uint8_t stale[16] = {0xfd, 0x66, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5};
    const uint8_t kept[16] = {0xfd, 0x66, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 5};
    const uint8_t reply_a[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const uint8_t reply_b[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const uint8_t pool6[16] = {0xfd, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t f1 = firc_mark_group_value(1), f2 = firc_mark_group_value(2);
    fake_ct_add(f.kernel, AF_INET6, v6_src, stale, reply_a, f1 | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET6, v6_src, kept, reply_b, f2 | FIRC_MARK_HANDLED);

    firc_ct_chunk_t chunks[2] = {
        {.family = AF_INET6, .base = {0xfd, 0x66, 0, 0, 0, 0, 0, 1}, .prefix = 64, .field = f2},
        {.family = AF_INET6, .base = {0xfd, 0x66, 0, 0, 0, 0, 0, 2}, .prefix = 64, .field = f2},
    };
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, NULL, 0, pool6, 48, chunks, 2,
                                                       FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("only the one whose field moved", (size_t)1, deleted, "%zu");
    ASSERTm("the stale one went", fake_ct_deleted(f.kernel, reply_a, 16));
    ASSERTm("the matching one stayed", !fake_ct_deleted(f.kernel, reply_b, 16));
    down(&f);
    PASS();
}

/* Catches: a refused dump not reported, or followed by deletes on a guess. */
TEST a_dump_the_kernel_refuses_deletes_nothing(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, reply[4] = {198, 18, 0, 5};
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, firc_mark_group_value(3));
    fake_ct_fail_next_dump(f.kernel, EPERM);
    size_t deleted = 0;
    ASSERT_FALSEm("the refusal reaches the caller",
                  firc_ct_flush_by_mark(f.ct, firc_mark_group_value(3), FIRC_MARK_GROUP_MASK, &deleted) == FIRC_OK);
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(f.kernel), "%zu");
    down(&f);
    PASS();
}

/* Catches: one refused delete unreported, or stopping the deletes after it. */
TEST a_refused_delete_does_not_stop_the_others(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5};
    const uint8_t r1[4] = {198, 18, 0, 5}, r2[4] = {198, 18, 0, 6};
    uint32_t ours = firc_mark_group_value(3);
    fake_ct_add(f.kernel, AF_INET, src, dst, r1, ours);
    fake_ct_add(f.kernel, AF_INET, src, dst, r2, ours);
    fake_ct_fail_next_delete(f.kernel, EPERM);
    size_t deleted = 0;
    ASSERT_FALSEm("reported", firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted) == FIRC_OK);
    ASSERT_EQ_FMTm("both were asked for", (size_t)2, fake_ct_deletes(f.kernel), "%zu");
    ASSERT_EQ_FMTm("the second went", (size_t)1, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a delete answered ENOENT reported as an error. */
TEST an_entry_already_gone_is_not_an_error(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10}, dst[4] = {198, 18, 0, 5}, reply[4] = {198, 18, 0, 5};
    uint32_t ours = firc_mark_group_value(3);
    fake_ct_add(f.kernel, AF_INET, src, dst, reply, ours);
    fake_ct_fail_next_delete(f.kernel, ENOENT);
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(f.ct, ours, FIRC_MARK_GROUP_MASK, &deleted));
    ASSERT_EQ_FMTm("not counted, not an error", (size_t)0, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a narrowing flush by mark alone, ignoring the mark, or without the handled bit. */
TEST a_narrowed_selector_resets_only_its_chunk_flows(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t chunk[4] = {198, 18, 3, 7}, chunk_reply[4] = {104, 18, 29, 7};
    const uint8_t sub[4] = {10, 1, 2, 3};
    const uint8_t other_reply[4] = {104, 18, 29, 8}, unhandled_reply[4] = {104, 18, 29, 9};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    uint32_t ours = firc_mark_group_value(3), theirs = firc_mark_group_value(4);
    fake_ct_add(f.kernel, AF_INET, src, chunk, chunk_reply, ours | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, sub, sub, ours | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, chunk, other_reply, theirs | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, chunk, unhandled_reply, ours);
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_group_chunk_flows(f.ct, ours, pool4, 15, NULL, 0, &deleted));
    ASSERT_EQ_FMT((size_t)1, deleted, "%zu");
    ASSERTm("the chunk flow went", fake_ct_deleted(f.kernel, chunk_reply, 4));
    ASSERT_FALSEm("the subnet flow stayed", fake_ct_deleted(f.kernel, sub, 4));
    ASSERT_FALSE(fake_ct_deleted(f.kernel, other_reply, 4));
    ASSERT_FALSE(fake_ct_deleted(f.kernel, unhandled_reply, 4));
    uint32_t value = 0, mask = 0;
    ASSERT(fake_ct_dump_filtered_on_mark(f.kernel, &value, &mask));
    ASSERT_EQ_FMT(ours | FIRC_MARK_HANDLED, value, "0x%x");
    ASSERT_EQ_FMT(FIRC_MARK_GROUP_MASK | FIRC_MARK_HANDLED, mask, "0x%x");
    down(&f);
    PASS();
}

/* Catches: wanted() leaving the narrowing's mark to a kernel that ignores the filter. */
TEST a_narrowing_on_a_kernel_that_ignores_the_filter_judges_the_mark_itself(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t chunk[4] = {198, 18, 3, 7}, chunk_reply[4] = {104, 18, 29, 7};
    const uint8_t other_reply[4] = {104, 18, 29, 8}, unhandled_reply[4] = {104, 18, 29, 9};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    uint32_t ours = firc_mark_group_value(3), theirs = firc_mark_group_value(4);
    fake_ct_add(f.kernel, AF_INET, src, chunk, chunk_reply, ours | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, chunk, other_reply, theirs | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, chunk, unhandled_reply, ours);
    fake_ct_ignore_mark_filter(f.kernel);
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_group_chunk_flows(f.ct, ours, pool4, 15, NULL, 0, &deleted));
    ASSERTm("the filter was asked for", fake_ct_dump_filtered_on_mark(f.kernel, NULL, NULL));
    ASSERT_EQ_FMT((size_t)1, deleted, "%zu");
    ASSERT(fake_ct_deleted(f.kernel, chunk_reply, 4));
    ASSERT_FALSE(fake_ct_deleted(f.kernel, other_reply, 4));
    ASSERT_FALSE(fake_ct_deleted(f.kernel, unhandled_reply, 4));
    down(&f);
    PASS();
}

/* Catches: v6 flows judged by the v4 prefix, or a zero-length prefix covering everything. */
TEST a_narrowing_judges_v6_flows_by_the_v6_pool(void) {
    const uint8_t src6[16] = {0xfd, 0x00, [15] = 0x10};
    const uint8_t dst6[16] = {0xfd, 0x37, 0x00, 0x00, [15] = 0x05}, reply6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 0x07};
    const uint8_t pool6[16] = {0xfd, 0x37};
    uint32_t ours = firc_mark_group_value(3);
    for (int with6 = 1; with6 >= 0; with6--) {
        fx_t f;
        ASSERT(up(&f));
        fake_ct_add(f.kernel, AF_INET6, src6, dst6, reply6, ours | FIRC_MARK_HANDLED);
        size_t deleted = 0;
        ASSERT_EQ(FIRC_OK, firc_ct_flush_group_chunk_flows(f.ct, ours, NULL, 0, with6 ? pool6 : NULL,
                                                           with6 ? 48 : 0, &deleted));
        ASSERT_EQ_FMTm(with6 ? "inside the v6 pool" : "no v6 pool, nothing inside it", (size_t)with6, deleted, "%zu");
        down(&f);
    }
    PASS();
}

/* Catches: a selector group's chunk deleting a flow whose field's holder routes a covering subnet. */
TEST a_selector_group_s_chunk_keeps_a_field_whose_holder_routes_the_address(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t d7[4] = {198, 18, 3, 7}, d8[4] = {198, 18, 3, 8};
    const uint8_t r7[4] = {104, 18, 29, 7}, r8[4] = {104, 18, 29, 8};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, d7, r7, firc_mark_group_value(2) | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, d8, r8, firc_mark_group_value(1) | FIRC_MARK_HANDLED);
    firc_ct_chunk_t chunks[2] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(1), .inexact = true},
        {.family = AF_INET, .base = {0, 0, 0, 0}, .prefix = 0, .is_subnet = true, .field = firc_mark_group_value(2)},
    };
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 2, FIRC_MARK_GROUP_MASK,
                                                       &deleted));
    ASSERT_EQ_FMT((size_t)0, deleted, "%zu");
    down(&f);
    PASS();
}

/* Catches: a selector group's chunk keeping a flow whose field nobody holds or vouches for. */
TEST a_selector_group_s_chunk_drops_a_field_nobody_vouches_for(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src[4] = {192, 168, 1, 10};
    const uint8_t d7[4] = {198, 18, 3, 7}, d9[4] = {198, 18, 3, 9};
    const uint8_t r7[4] = {104, 18, 29, 7}, r9[4] = {104, 18, 29, 9};
    const uint8_t pool4[4] = {198, 18, 0, 0};
    fake_ct_add(f.kernel, AF_INET, src, d7, r7, firc_mark_group_value(2) | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET, src, d9, r9, firc_mark_group_value(3) | FIRC_MARK_HANDLED);
    firc_ct_chunk_t chunks[2] = {
        {.family = AF_INET, .base = {198, 18, 3, 0}, .prefix = 24, .field = firc_mark_group_value(1), .inexact = true},
        {.family = AF_INET, .base = {198, 18, 9, 0}, .prefix = 24, .field = firc_mark_group_value(2)},
    };
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, pool4, 15, NULL, 0, chunks, 2, FIRC_MARK_GROUP_MASK,
                                                       &deleted));
    ASSERT_EQ_FMT((size_t)2, deleted, "%zu");
    ASSERT(fake_ct_deleted(f.kernel, r7, 4) && fake_ct_deleted(f.kernel, r9, 4));
    down(&f);
    PASS();
}

/* Catches: the covering-subnet check ignoring the family, or the v6 chunk ignoring `inexact`. */
TEST a_selector_group_s_v6_chunk_keeps_only_a_field_whose_holder_routes_v6(void) {
    fx_t f;
    ASSERT(up(&f));
    const uint8_t src6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    const uint8_t d7[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 7};
    const uint8_t d8[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 8};
    const uint8_t r7[16] = {0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};
    const uint8_t r8[16] = {0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8};
    const uint8_t pool6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    fake_ct_add(f.kernel, AF_INET6, src6, d7, r7, firc_mark_group_value(4) | FIRC_MARK_HANDLED);
    fake_ct_add(f.kernel, AF_INET6, src6, d8, r8, firc_mark_group_value(2) | FIRC_MARK_HANDLED);
    firc_ct_chunk_t chunks[3] = {
        {.family = AF_INET6,
         .base = {0xfd, 0x37, 0, 0, 0, 0, 0, 3},
         .prefix = 64,
         .field = firc_mark_group_value(1),
         .inexact = true},
        {.family = AF_INET, .base = {0, 0, 0, 0}, .prefix = 0, .is_subnet = true, .field = firc_mark_group_value(2)},
        {.family = AF_INET6, .base = {0}, .prefix = 0, .is_subnet = true, .field = firc_mark_group_value(4)},
    };
    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_stale_group_marks(f.ct, NULL, 0, pool6, 48, chunks, 3, FIRC_MARK_GROUP_MASK,
                                                       &deleted));
    ASSERT_EQ_FMT((size_t)1, deleted, "%zu");
    ASSERT(fake_ct_deleted(f.kernel, r8, 16));
    ASSERT_FALSE(fake_ct_deleted(f.kernel, r7, 16));
    down(&f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_groups_flows_go_when_its_mark_is_flushed);
    RUN_TEST(the_mark_is_matched_on_the_group_field_alone);
    RUN_TEST(flows_answered_with_a_fake_address_and_no_binding_go);
    RUN_TEST(the_last_partial_byte_of_the_pool_prefix_is_masked_correctly);
    RUN_TEST(a_pool_with_no_v6_half_deletes_no_v6_flows);
    RUN_TEST(a_flow_whose_tuple_has_no_ports_is_named_back_exactly);
    RUN_TEST(an_abandoned_dump_is_read_to_its_end_so_the_next_flush_works);
    RUN_TEST(a_second_family_that_fails_does_not_discard_the_first);
    RUN_TEST(a_delete_names_the_entry_the_dump_found_not_the_tuple);
    RUN_TEST(a_flow_whose_group_kept_its_field_stays);
    RUN_TEST(a_flow_whose_group_now_holds_another_field_goes);
    RUN_TEST(a_flow_whose_group_is_gone_goes);
    RUN_TEST(a_mark_firc_did_not_write_is_left_alone);
    RUN_TEST(a_fake_address_no_live_chunk_covers_goes);
    RUN_TEST(a_field_nobody_holds_outside_the_pool_is_left_alone);
    RUN_TEST(a_chunk_answers_only_for_its_own_family);
    RUN_TEST(inside_the_pool_a_subnet_does_not_name_an_owner);
    RUN_TEST(outside_the_pool_only_the_holder_s_own_subnet_vouches);
    RUN_TEST(a_kernel_that_never_answers_does_not_stop_the_flush);
    RUN_TEST(deletes_the_kernel_never_acks_are_not_reported_as_success);
    RUN_TEST(a_flush_that_runs_out_of_time_still_repairs_what_it_found);
    RUN_TEST(a_flush_by_mark_asks_the_kernel_for_that_mark);
    RUN_TEST(a_filter_value_is_masked_before_it_is_sent);
    RUN_TEST(the_stale_mark_sweep_asks_for_entries_firc_marked);
    RUN_TEST(a_kernel_that_ignores_the_filter_still_gets_the_right_answer);
    RUN_TEST(a_kernel_that_refuses_the_filter_falls_back_to_the_whole_table);
    RUN_TEST(a_refusal_that_is_not_about_the_filter_does_not_disarm_it);
    RUN_TEST(einval_is_reported_rather_than_read_as_no_filter);
    RUN_TEST(the_pool_reply_sweep_cannot_ask_for_a_mark);
    RUN_TEST(a_family_over_the_hit_cap_does_not_starve_the_other);
    RUN_TEST(an_unmarked_flow_is_not_this_querys_business);
    RUN_TEST(the_v6_half_is_judged_by_its_own_chunks);
    RUN_TEST(a_dump_the_kernel_refuses_deletes_nothing);
    RUN_TEST(a_refused_delete_does_not_stop_the_others);
    RUN_TEST(an_entry_already_gone_is_not_an_error);
    RUN_TEST(a_narrowed_selector_resets_only_its_chunk_flows);
    RUN_TEST(a_narrowing_on_a_kernel_that_ignores_the_filter_judges_the_mark_itself);
    RUN_TEST(a_narrowing_judges_v6_flows_by_the_v6_pool);
    RUN_TEST(a_selector_group_s_chunk_keeps_a_field_whose_holder_routes_the_address);
    RUN_TEST(a_selector_group_s_chunk_drops_a_field_nobody_vouches_for);
    RUN_TEST(a_selector_group_s_v6_chunk_keeps_only_a_field_whose_holder_routes_v6);
    GREATEST_MAIN_END();
}
