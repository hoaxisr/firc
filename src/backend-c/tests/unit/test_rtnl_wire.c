#include "greatest.h"

#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "firc/mark.h"
#include "firc/rtnl.h"
#include "wire_bytes.h"

typedef struct {
    bool seen_fwmark, seen_fwmask;
    uint32_t fwmark, fwmask;
    bool seen_table, seen_priority, seen_dst;
    uint32_t table, priority;
    uint8_t dst[16];
    size_t dst_len;
} attrs_t;

static int collect(const struct nlattr *attr, void *ud) {
    attrs_t *a = (attrs_t *)ud;
    switch (mnl_attr_get_type(attr)) {
    case RTA_TABLE:
        a->seen_table = true;
        a->table = mnl_attr_get_u32(attr);
        break;
    case RTA_PRIORITY:
        a->seen_priority = true;
        a->priority = mnl_attr_get_u32(attr);
        break;
    case FRA_FWMARK:
        a->seen_fwmark = true;
        a->fwmark = mnl_attr_get_u32(attr);
        break;
    case FRA_FWMASK:
        a->seen_fwmask = true;
        a->fwmask = mnl_attr_get_u32(attr);
        break;
    case RTA_DST:
        a->seen_dst = true;
        a->dst_len = mnl_attr_get_payload_len(attr);
        if (a->dst_len <= sizeof(a->dst)) { memcpy(a->dst, mnl_attr_get_payload(attr), a->dst_len); }
        break;
    default:
        break;
    }
    return MNL_CB_OK;
}

TEST an_unreachable_route_carries_the_pool_prefix(void) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    const uint8_t v4[4] = {198, 18, 0, 0};

    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh =
        firc_rtnl_build_unreachable(buf, true, 42, AF_INET, 51999, 5, v4, 15);
    ASSERT(nlh != NULL);

    ASSERT_EQ_FMT((int)RTM_NEWROUTE, (int)nlh->nlmsg_type, "%d");
    ASSERT_EQ_FMT(42u, nlh->nlmsg_seq, "%u");
    ASSERTm("an add must not silently replace an existing route",
            (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)) == (NLM_F_CREATE | NLM_F_EXCL));
    ASSERT((nlh->nlmsg_flags & NLM_F_ACK) != 0);

    struct rtmsg *rtm = (struct rtmsg *)mnl_nlmsg_get_payload(nlh);
    ASSERT_EQ_FMT((int)AF_INET, (int)rtm->rtm_family, "%d");
    ASSERT_EQ_FMTm("the prefix length is what beats the group's default route", 15,
                   (int)rtm->rtm_dst_len, "%d");
    ASSERT_EQ_FMT((int)RTN_UNREACHABLE, (int)rtm->rtm_type, "%d");
    ASSERT_EQ_FMTm("firc's routes must be identifiable as firc's", FIRC_RTPROT,
                   (int)rtm->rtm_protocol, "%d");
    ASSERT_EQ_FMTm("a table id past 255 does not fit the header field",
                   (int)RT_TABLE_UNSPEC, (int)rtm->rtm_table, "%d");

    attrs_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(MNL_CB_OK, mnl_attr_parse(nlh, sizeof(struct rtmsg), collect, &a));
    ASSERT(a.seen_table);
    ASSERT_EQ_FMT(51999u, a.table, "%u");
    ASSERT(a.seen_priority);
    ASSERT_EQ_FMT(5u, a.priority, "%u");
    ASSERT(a.seen_dst);
    ASSERT_EQ_FMT((size_t)4, a.dst_len, "%zu");
    ASSERT_MEM_EQ(v4, a.dst, 4);
    PASS();
}

TEST a_small_table_id_travels_in_the_header(void) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    const uint8_t v4[4] = {198, 18, 0, 0};
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = firc_rtnl_build_unreachable(buf, true, 1, AF_INET, 200, 4096, v4, 15);
    ASSERT(nlh != NULL);

    struct rtmsg *rtm = (struct rtmsg *)mnl_nlmsg_get_payload(nlh);
    ASSERT_EQ_FMTm("200 fits one byte and belongs in the header", 200, (int)rtm->rtm_table, "%d");

    attrs_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(MNL_CB_OK, mnl_attr_parse(nlh, sizeof(struct rtmsg), collect, &a));
    ASSERTm("sending it twice would be redundant, not wrong, but the header is authoritative",
            !a.seen_table);
    ASSERT(a.seen_priority);
    ASSERT_EQ_FMT(4096u, a.priority, "%u");
    PASS();
}

TEST the_v6_pool_prefix_travels_as_sixteen_bytes(void) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    uint8_t v6[16];
    memset(v6, 0, sizeof(v6));
    v6[0] = 0xfd;
    v6[1] = 0x37;
    v6[2] = 0x9a;
    v6[3] = 0x5c;
    v6[4] = 0xbe;
    v6[5] = 0x10;

    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = firc_rtnl_build_unreachable(buf, true, 7, AF_INET6, 51999, 5, v6, 48);
    ASSERT(nlh != NULL);

    struct rtmsg *rtm = (struct rtmsg *)mnl_nlmsg_get_payload(nlh);
    ASSERT_EQ_FMT((int)AF_INET6, (int)rtm->rtm_family, "%d");
    ASSERT_EQ_FMT(48, (int)rtm->rtm_dst_len, "%d");

    attrs_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(MNL_CB_OK, mnl_attr_parse(nlh, sizeof(struct rtmsg), collect, &a));
    ASSERT(a.seen_dst);
    ASSERT_EQ_FMTm("a v6 prefix is sixteen bytes on the wire however short the prefix",
                   (size_t)16, a.dst_len, "%zu");
    ASSERT_MEM_EQ(v6, a.dst, 16);
    PASS();
}

TEST a_delete_does_not_ask_the_kernel_to_create(void) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    const uint8_t v4[4] = {198, 18, 0, 0};
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = firc_rtnl_build_unreachable(buf, false, 9, AF_INET, 51999, 5, v4, 15);
    ASSERT(nlh != NULL);

    ASSERT_EQ_FMT((int)RTM_DELROUTE, (int)nlh->nlmsg_type, "%d");
    ASSERTm("CREATE on a delete would be a kernel-dependent surprise",
            (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)) == 0);
    {
        struct rtmsg *drtm = (struct rtmsg *)mnl_nlmsg_get_payload(nlh);
        ASSERT_EQ_FMTm("a delete without the tag removes somebody else's route",
                       FIRC_RTPROT, (int)drtm->rtm_protocol, "%d");
    }

    struct rtmsg *rtm = (struct rtmsg *)mnl_nlmsg_get_payload(nlh);
    ASSERT_EQ_FMT(15, (int)rtm->rtm_dst_len, "%d");
    attrs_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(MNL_CB_OK, mnl_attr_parse(nlh, sizeof(struct rtmsg), collect, &a));
    ASSERT(a.seen_dst);
    ASSERT_MEM_EQ(v4, a.dst, 4);
    PASS();
}

TEST arguments_that_are_not_a_prefix_are_refused(void) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    const uint8_t v4[4] = {198, 18, 0, 0};

    memset(buf, 0, sizeof(buf));
    ASSERT_EQm("33 bits of a 32-bit address", NULL,
               firc_rtnl_build_unreachable(buf, true, 1, AF_INET, 51999, 5, v4, 33));
    memset(buf, 0, sizeof(buf));
    ASSERT_EQm("129 bits of a 128-bit address", NULL,
               firc_rtnl_build_unreachable(buf, true, 1, AF_INET6, 51999, 5, v4, 129));
    memset(buf, 0, sizeof(buf));
    ASSERT_EQm("a family with no address length", NULL,
               firc_rtnl_build_unreachable(buf, true, 1, AF_UNIX, 51999, 5, v4, 15));
    memset(buf, 0, sizeof(buf));
    ASSERT_EQm("no prefix at all", NULL,
               firc_rtnl_build_unreachable(buf, true, 1, AF_INET, 51999, 5, NULL, 15));

    memset(buf, 0, sizeof(buf));
    ASSERT(firc_rtnl_build_unreachable(buf, true, 1, AF_INET, 51999, 5, v4, 32) != NULL);
    PASS();
}

/* Catches: a mark rule without FRA_FWMASK or FRA_PRIORITY. */
TEST a_policy_rule_carries_a_mask_and_a_priority(void) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh =
        firc_rtnl_build_rule(buf, true, 11, AF_INET, 0x00010000u, 0x00ff0000u, 51999, 1000);
    ASSERT(nlh != NULL);

    ASSERT_EQ_FMT((int)RTM_NEWRULE, (int)nlh->nlmsg_type, "%d");
    ASSERT((nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)) == (NLM_F_CREATE | NLM_F_EXCL));

    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)mnl_nlmsg_get_payload(nlh);
    ASSERT_EQ_FMT((int)AF_INET, (int)frh->family, "%d");
    ASSERT_EQ_FMT((int)FR_ACT_TO_TBL, (int)frh->action, "%d");
    ASSERT_EQ_FMTm("a table id past 255 does not fit the header field", (int)RT_TABLE_UNSPEC,
                   (int)frh->table, "%d");

    attrs_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(MNL_CB_OK, mnl_attr_parse(nlh, sizeof(struct fib_rule_hdr), collect, &a));
    ASSERT(a.seen_fwmark);
    ASSERT_EQ_FMT(0x00010000u, a.fwmark, "%#x");
    ASSERTm("without a mask the kernel compares all 32 bits", a.seen_fwmask);
    ASSERT_EQ_FMT(0x00ff0000u, a.fwmask, "%#x");
    ASSERTm("without a priority the kernel picks one for us", a.seen_priority);
    ASSERT_EQ_FMT(1000u, a.priority, "%u");
    ASSERT(a.seen_table);
    ASSERT_EQ_FMT(51999u, a.table, "%u");
    PASS();
}

/* Catches: a delete naming another mark, mask or priority, or carrying create flags. */
TEST deleting_a_policy_rule_names_the_same_rule(void) {
    uint8_t buf[FIRC_RTNL_REQBUF];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh =
        firc_rtnl_build_rule(buf, false, 12, AF_INET6, 0x00020000u, 0x00ff0000u, 200, 1001);
    ASSERT(nlh != NULL);

    ASSERT_EQ_FMT((int)RTM_DELRULE, (int)nlh->nlmsg_type, "%d");
    ASSERT((nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)) == 0);

    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)mnl_nlmsg_get_payload(nlh);
    ASSERT_EQ_FMT((int)AF_INET6, (int)frh->family, "%d");
    ASSERT_EQ_FMTm("200 fits one byte and belongs in the header", 200, (int)frh->table, "%d");

    attrs_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(MNL_CB_OK, mnl_attr_parse(nlh, sizeof(struct fib_rule_hdr), collect, &a));
    ASSERT_EQ_FMT(0x00020000u, a.fwmark, "%#x");
    ASSERT(a.seen_fwmask);
    ASSERT_EQ_FMT(0x00ff0000u, a.fwmask, "%#x");
    ASSERT(a.seen_priority);
    ASSERT_EQ_FMT(1001u, a.priority, "%u");
    ASSERTm("the table fits the header, so the attribute is redundant", !a.seen_table);
    PASS();
}

GREATEST_MAIN_DEFS();

static void put_rule_hdr(wb_t *w, uint8_t family, uint8_t action) {
    wb_bytes(w, (const uint8_t[]){family, 0, 0, 0, 0, 0, 0, action}, 8);
    wb_h32(w, 0);
}

static void put_rule_attrs(wb_t *w, uint32_t mark, uint32_t mask, uint32_t priority, uint32_t table) {
    wb_attr_h32(w, 10, mark);
    wb_attr_h32(w, 16, mask);
    wb_attr_h32(w, 6, priority);
    wb_attr_h32(w, 15, table);
}

static bool same_bytes(const wb_t *want, const wb_t *got) {
    return want->n == got->n && memcmp(want->b, got->b, want->n) == 0;
}

TEST the_reply_rule_carries_host_order_values_iifname_and_suppress_prefixlength_14(void) {
    int sv[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
    firc_rtnl_t *r = firc_rtnl_open_fd(sv[0]);
    ASSERT(r != NULL);
    wb_t ack = {0};
    wb_ack(&ack, 1, 0);
    ASSERT(wb_send(sv[1], &ack));

    ASSERT_EQ(FIRC_OK, firc_rtnl_rule_add_reply(r, AF_INET, 0x00070000u, 0x00ff0000u, "nwg0",
                                                0x66697263u, 49));

    wb_t want = {0};
    size_t at = wb_nlmsg(&want, 32, 0x0605, 1);
    put_rule_hdr(&want, 2, 1);
    put_rule_attrs(&want, 0x00070000u, 0x00ff0000u, 49, 0x66697263u);
    wb_attr_bytes(&want, 3, "nwg0", 5);
    wb_attr_h32(&want, 14, 0);
    wb_nlmsg_end(&want, at);
    wb_t got = {0};
    ASSERT(wb_recv(sv[1], &got));
    ASSERT(same_bytes(&want, &got));

    firc_rtnl_close(r);
    close(sv[1]);
    PASS();
}

TEST a_stale_rule_read_from_a_dump_is_deleted_with_the_values_it_carried(void) {
    int sv[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
    firc_rtnl_t *r = firc_rtnl_open_fd(sv[0]);
    ASSERT(r != NULL);

    wb_t rule = {0};
    size_t at = wb_nlmsg(&rule, 32, 0x0002, 1);
    put_rule_hdr(&rule, 2, 1);
    wb_attr_h32(&rule, 15, 0x66697263u);
    wb_attr_h32(&rule, 6, FIRC_RULE_PRIORITY);
    wb_attr_h32(&rule, 10, 0x40070000u);
    wb_attr_h32(&rule, 16, FIRC_MARK_GROUP_MASK);
    wb_nlmsg_end(&rule, at);
    ASSERT(wb_send(sv[1], &rule));
    wb_t done1 = {0};
    wb_done(&done1, 1);
    ASSERT(wb_send(sv[1], &done1));
    wb_t done2 = {0};
    wb_done(&done2, 2);
    ASSERT(wb_send(sv[1], &done2));
    wb_t ack3 = {0};
    wb_ack(&ack3, 3, 0);
    ASSERT(wb_send(sv[1], &ack3));

    size_t removed = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_clean_stale_rules(r, &removed));
    ASSERT_EQ_FMT((size_t)1, removed, "%zu");

    wb_t want = {0};
    wb_t got = {0};
    at = wb_nlmsg(&want, 34, 0x0305, 1);
    put_rule_hdr(&want, 2, 0);
    wb_nlmsg_end(&want, at);
    ASSERT(wb_recv(sv[1], &got));
    ASSERT(same_bytes(&want, &got));
    memset(&want, 0, sizeof(want));
    at = wb_nlmsg(&want, 34, 0x0305, 2);
    put_rule_hdr(&want, 10, 0);
    wb_nlmsg_end(&want, at);
    ASSERT(wb_recv(sv[1], &got));
    ASSERT(same_bytes(&want, &got));
    memset(&want, 0, sizeof(want));
    at = wb_nlmsg(&want, 33, 0x0005, 3);
    put_rule_hdr(&want, 2, 0);
    put_rule_attrs(&want, 0x40070000u, FIRC_MARK_GROUP_MASK, FIRC_RULE_PRIORITY, 0x66697263u);
    wb_nlmsg_end(&want, at);
    ASSERT(wb_recv(sv[1], &got));
    ASSERT(same_bytes(&want, &got));

    firc_rtnl_close(r);
    close(sv[1]);
    PASS();
}

static void put_default_route(wb_t *w) {
    wb_bytes(w, (const uint8_t[]){2, 0, 0, 0, 254, 3, 0, 1}, 8);
    wb_h32(w, 0);
    wb_attr_h32(w, 15, 254);
    wb_attr_h32(w, 6, 0x01020304u);
}

TEST a_default_route_is_found_by_its_host_order_oif(void) {
    int sv[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
    firc_rtnl_t *r = firc_rtnl_open_fd(sv[0]);
    ASSERT(r != NULL);

    wb_t route = {0};
    size_t at = wb_nlmsg(&route, 24, 0x0002, 1);
    put_default_route(&route);
    wb_attr_bytes(&route, 5, (const uint8_t[]){192, 168, 1, 1}, 4);
    wb_attr_h32(&route, 4, 0x0107);
    wb_nlmsg_end(&route, at);
    ASSERT(wb_send(sv[1], &route));
    wb_t done = {0};
    wb_done(&done, 1);
    ASSERT(wb_send(sv[1], &done));

    bool found = false, gatewayless = true;
    uint8_t gw[16] = {0};
    uint8_t gw_len = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_gateway_for_iface2(r, AF_INET, 0x0107, &found, gw, &gw_len, &gatewayless));
    ASSERT(found);
    ASSERT_EQ(4, gw_len);
    ASSERT_MEM_EQ(((const uint8_t[]){192, 168, 1, 1}), gw, 4);

    wb_t want = {0};
    at = wb_nlmsg(&want, 26, 0x0305, 1);
    wb_bytes(&want, (const uint8_t[]){2, 0, 0, 0, 0, 0, 0, 0}, 8);
    wb_h32(&want, 0);
    wb_nlmsg_end(&want, at);
    wb_t got = {0};
    ASSERT(wb_recv(sv[1], &got));
    ASSERT(same_bytes(&want, &got));

    firc_rtnl_close(r);
    close(sv[1]);
    PASS();
}

TEST a_multipath_next_hop_is_found_by_its_host_order_ifindex(void) {
    int sv[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
    firc_rtnl_t *r = firc_rtnl_open_fd(sv[0]);
    ASSERT(r != NULL);

    wb_t route = {0};
    size_t at = wb_nlmsg(&route, 24, 0x0002, 1);
    put_default_route(&route);
    size_t mp = wb_attr(&route, 9);
    wb_h16(&route, 16);
    wb_u8(&route, 0);
    wb_u8(&route, 0);
    wb_h32(&route, 0x0203);
    wb_attr_bytes(&route, 5, (const uint8_t[]){10, 9, 8, 7}, 4);
    wb_attr_end(&route, mp);
    wb_nlmsg_end(&route, at);
    ASSERT(wb_send(sv[1], &route));
    wb_t done = {0};
    wb_done(&done, 1);
    ASSERT(wb_send(sv[1], &done));

    bool found = false, gatewayless = true;
    uint8_t gw[16] = {0};
    uint8_t gw_len = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_gateway_for_iface2(r, AF_INET, 0x0203, &found, gw, &gw_len, &gatewayless));
    ASSERT(found);
    ASSERT_EQ(4, gw_len);
    ASSERT_MEM_EQ(((const uint8_t[]){10, 9, 8, 7}), gw, 4);

    firc_rtnl_close(r);
    close(sv[1]);
    PASS();
}

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(an_unreachable_route_carries_the_pool_prefix);
    RUN_TEST(a_small_table_id_travels_in_the_header);
    RUN_TEST(the_v6_pool_prefix_travels_as_sixteen_bytes);
    RUN_TEST(a_delete_does_not_ask_the_kernel_to_create);
    RUN_TEST(arguments_that_are_not_a_prefix_are_refused);
    RUN_TEST(a_policy_rule_carries_a_mask_and_a_priority);
    RUN_TEST(deleting_a_policy_rule_names_the_same_rule);
    RUN_TEST(the_reply_rule_carries_host_order_values_iifname_and_suppress_prefixlength_14);
    RUN_TEST(a_stale_rule_read_from_a_dump_is_deleted_with_the_values_it_carried);
    RUN_TEST(a_default_route_is_found_by_its_host_order_oif);
    RUN_TEST(a_multipath_next_hop_is_found_by_its_host_order_ifindex);
    GREATEST_MAIN_END();
}
