#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netlink.h>

#include "firc/nflog.h"

#define ATTR_HDR ((size_t)4)
static size_t attr_len(size_t payload_len) { return ATTR_HDR + payload_len; }
static size_t attr_step(size_t nla_len) { return (nla_len + 3u) & ~(size_t)3u; }

/* One NFLOG packet message with a prefix attribute before the payload, so the payload is not first. */
static size_t packet_msg(uint8_t *out, uint16_t type, const uint8_t *payload, size_t payload_len,
                         bool with_payload) {
    memset(out, 0, 512);
    struct nlmsghdr *h = (struct nlmsghdr *)out;
    h->nlmsg_type = type;
    h->nlmsg_flags = 0;
    size_t off = NLMSG_HDRLEN;

    struct nfgenmsg *g = (struct nfgenmsg *)(out + off);
    g->nfgen_family = 2;
    g->version = 0;
    g->res_id = 0;
    off += sizeof(*g);

    struct nlattr *a = (struct nlattr *)(out + off);
    static const char prefix[] = "firc";
    a->nla_type = NFULA_PREFIX;
    a->nla_len = (uint16_t)attr_len(sizeof(prefix));
    memcpy(out + off + ATTR_HDR, prefix, sizeof(prefix));
    off += attr_step(a->nla_len);

    if (with_payload) {
        a = (struct nlattr *)(out + off);
        a->nla_type = NFULA_PAYLOAD;
        a->nla_len = (uint16_t)attr_len(payload_len);
        if (payload_len) { memcpy(out + off + ATTR_HDR, payload, payload_len); }
        off += attr_step(a->nla_len);
    }

    h->nlmsg_len = (uint32_t)off;
    return off;
}

#define NFLOG_PACKET ((uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET))

TEST the_payload_is_read_past_the_attributes_in_front_of_it(void) {
    uint8_t buf[512];
    static const uint8_t pkt[] = {0x45, 0x00, 0x00, 0x2c, 0xde, 0xad};
    size_t n = packet_msg(buf, NFLOG_PACKET, pkt, sizeof(pkt), true);
    const uint8_t *out = NULL;
    size_t out_len = 0;
    ASSERT(firc_nflog_payload(buf, n, &out, &out_len));
    ASSERT_EQ_FMT(sizeof(pkt), out_len, "%zu");
    ASSERT_EQ(0, memcmp(out, pkt, sizeof(pkt)));
    PASS();
}

TEST a_message_with_no_payload_has_none(void) {
    uint8_t buf[512];
    size_t n = packet_msg(buf, NFLOG_PACKET, NULL, 0, false);
    const uint8_t *out = NULL;
    size_t out_len = 0;
    ASSERT_FALSE(firc_nflog_payload(buf, n, &out, &out_len));
    PASS();
}

/* Catches: an empty payload attribute read as a packet. */
TEST an_empty_payload_is_no_payload(void) {
    uint8_t buf[512];
    size_t n = packet_msg(buf, NFLOG_PACKET, NULL, 0, true);
    const uint8_t *out = NULL;
    size_t out_len = 0;
    ASSERT_FALSE(firc_nflog_payload(buf, n, &out, &out_len));
    PASS();
}

/* Catches: a non-packet message, such as an ack, read as a packet. */
TEST only_an_nflog_packet_message_is_read(void) {
    uint8_t buf[512];
    static const uint8_t pkt[] = {0x45, 0x00};
    const uint8_t *out = NULL;
    size_t out_len = 0;

    size_t n = packet_msg(buf, NLMSG_ERROR, pkt, sizeof(pkt), true);
    ASSERT_FALSEm("an error is not a packet", firc_nflog_payload(buf, n, &out, &out_len));

    n = packet_msg(buf, (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG), pkt, sizeof(pkt),
                   true);
    ASSERT_FALSEm("a config message is not a packet",
                  firc_nflog_payload(buf, n, &out, &out_len));

    n = packet_msg(buf, (uint16_t)((NFNL_SUBSYS_CTNETLINK << 8) | NFULNL_MSG_PACKET), pkt,
                   sizeof(pkt), true);
    ASSERT_FALSEm("another subsystem's message is not ours",
                  firc_nflog_payload(buf, n, &out, &out_len));
    PASS();
}

/* Catches: a truncated message read past its end. */
TEST every_truncation_is_refused(void) {
    uint8_t buf[512];
    static const uint8_t pkt[] = {0x45, 0x00, 0x00, 0x2c, 0xde, 0xad, 0xbe, 0xef};
    size_t n = packet_msg(buf, NFLOG_PACKET, pkt, sizeof(pkt), true);
    for (size_t cut = 0; cut <= n; cut++) {
        uint8_t *exact = malloc(cut ? cut : 1);
        ASSERT(exact != NULL);
        memcpy(exact, buf, cut);
        const uint8_t *out = NULL;
        size_t out_len = 0;
        if (firc_nflog_payload(exact, cut, &out, &out_len)) {
            ASSERTm("what it reported is inside what it was given",
                    out >= exact && out + out_len <= exact + cut);
        }
        free(exact);
    }
    PASS();
}

TEST an_attribute_length_past_the_message_is_refused(void) {
    uint8_t buf[512];
    static const uint8_t pkt[] = {0x45, 0x00, 0x00, 0x2c};
    size_t n = packet_msg(buf, NFLOG_PACKET, pkt, sizeof(pkt), true);

    uint8_t *exact = malloc(n);
    ASSERT(exact != NULL);
    memcpy(exact, buf, n);
    bool found = false;
    for (size_t off = NLMSG_HDRLEN + 4; off + 4 < n; off += 4) {
        struct nlattr *a = (struct nlattr *)(exact + off);
        if (a->nla_type == NFULA_PAYLOAD) {
            a->nla_len = (uint16_t)(n * 4);
            found = true;
            break;
        }
    }
    if (!found) { free(exact); }
    ASSERTm("the payload attribute was found and made to lie", found);
    const uint8_t *out = NULL;
    size_t out_len = 0;
    bool got = firc_nflog_payload(exact, n, &out, &out_len);
    free(exact);
    ASSERT_FALSEm("an attribute that runs past the message is not read", got);
    PASS();
}

typedef struct {
    size_t n;
    const uint8_t *lo, *hi;
    bool escaped;
} walk_seen_t;

static void walked(const uint8_t *pkt, size_t len, void *ud) {
    walk_seen_t *w = ud;
    w->n++;
    if (pkt < w->lo || pkt + len > w->hi) { w->escaped = true; }
}

static size_t add_packet(uint8_t *buf, size_t off, const uint8_t *payload, size_t payload_len) {
    struct nlmsghdr *h = (struct nlmsghdr *)(buf + off);
    memset(h, 0, NLMSG_HDRLEN);
    h->nlmsg_type = NFLOG_PACKET;
    size_t at = off + NLMSG_HDRLEN;
    memset(buf + at, 0, sizeof(struct nfgenmsg));
    at += sizeof(struct nfgenmsg);
    struct nlattr *a = (struct nlattr *)(buf + at);
    a->nla_type = NFULA_PAYLOAD;
    a->nla_len = (uint16_t)attr_len(payload_len);
    memcpy(buf + at + ATTR_HDR, payload, payload_len);
    at += attr_step(a->nla_len);
    h->nlmsg_len = (uint32_t)(at - off);
    return at;
}

/* Catches: only the first message of a batched datagram read. */
TEST every_packet_in_one_datagram_is_walked(void) {
    uint8_t dg[512];
    static const uint8_t one[] = {0x45, 0x11};
    static const uint8_t two[] = {0x60, 0x22, 0x33};
    size_t off = add_packet(dg, 0, one, sizeof(one));
    off = add_packet(dg, off, two, sizeof(two));

    walk_seen_t w = {0, dg, dg + off, false};
    ASSERT_EQ_FMTm("a whole datagram leaves nothing unwalked", (size_t)0,
                   firc_nflog_walk(dg, off, walked, &w), "%zu");
    ASSERT_EQ_FMT((size_t)2, w.n, "%zu");
    ASSERT_FALSE(w.escaped);
    PASS();
}

/* Catches: a datagram cut at any offset read past its end. */
TEST no_prefix_of_a_datagram_is_read_past(void) {
    uint8_t dg[512];
    static const uint8_t one[] = {0x45, 0x11, 0x22};
    static const uint8_t two[] = {0x60, 0x22, 0x33, 0x44, 0x55};
    size_t off = add_packet(dg, 0, one, sizeof(one));
    off = add_packet(dg, off, two, sizeof(two));

    size_t first = add_packet(dg, 0, one, sizeof(one));
    for (size_t cut = 0; cut <= off; cut++) {
        uint8_t *exact = malloc(cut ? cut : 1);
        ASSERT(exact != NULL);
        memcpy(exact, dg, cut);
        walk_seen_t w = {0, exact, exact + cut, false};
        size_t unwalkable = firc_nflog_walk(exact, cut, walked, &w);
        bool escaped = w.escaped;
        size_t saw = w.n;
        free(exact);
        ASSERT_FALSEm("a packet from outside the datagram", escaped);
        if (cut == 0 || cut == first || cut == off) {
            ASSERT_EQ_FMTm("a datagram that ends on a message boundary is whole",
                           (size_t)0, unwalkable, "%zu");
            size_t want = (cut == 0) ? 0u : (cut == first ? 1u : 2u);
            ASSERT_EQ_FMT(want, saw, "%zu");
        } else {
            ASSERT_EQm("a cut inside a message is loss", (size_t)1, unwalkable);
        }
    }
    PASS();
}

/* Catches: one to three trailing bytes read as a length. */
TEST a_tail_too_short_to_hold_a_length_is_not_read(void) {
    uint8_t dg[512];
    static const uint8_t pkt[] = {0x45, 0x11};
    size_t off = add_packet(dg, 0, pkt, sizeof(pkt));
    for (size_t tail = 1; tail <= 3; tail++) {
        uint8_t *exact = malloc(off + tail);
        ASSERT(exact != NULL);
        memcpy(exact, dg, off);
        memset(exact + off, 0xff, tail);
        walk_seen_t w = {0, exact, exact + off + tail, false};
        size_t unwalkable = firc_nflog_walk(exact, off + tail, walked, &w);
        size_t saw = w.n;
        bool escaped = w.escaped;
        free(exact);
        ASSERT_FALSE(escaped);
        ASSERT_EQ_FMTm("the packet before the tail is still delivered", (size_t)1, saw, "%zu");
        ASSERT_EQ_FMTm("and the tail is counted as loss", (size_t)1, unwalkable, "%zu");
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_payload_is_read_past_the_attributes_in_front_of_it);
    RUN_TEST(a_message_with_no_payload_has_none);
    RUN_TEST(an_empty_payload_is_no_payload);
    RUN_TEST(only_an_nflog_packet_message_is_read);
    RUN_TEST(every_truncation_is_refused);
    RUN_TEST(an_attribute_length_past_the_message_is_refused);
    RUN_TEST(every_packet_in_one_datagram_is_walked);
    RUN_TEST(no_prefix_of_a_datagram_is_read_past);
    RUN_TEST(a_tail_too_short_to_hold_a_length_is_not_read);
    GREATEST_MAIN_END();
}
