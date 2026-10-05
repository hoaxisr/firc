#include "greatest.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <unistd.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netlink.h>

#include "firc/nflogsock.h"
#include "../../src/tap/nflog_internal.h"

#include "fake_nflog.h"

#define ATTR_HDR ((size_t)4)
static size_t attr_step(size_t n) { return (n + 3u) & ~(size_t)3u; }

/* Appends one NFLOG packet message carrying `payload` to `buf`. */
static size_t add_packet(uint8_t *buf, size_t off, const uint8_t *payload, size_t payload_len) {
    struct nlmsghdr *h = (struct nlmsghdr *)(buf + off);
    memset(h, 0, NLMSG_HDRLEN);
    h->nlmsg_type = (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET);
    size_t at = off + NLMSG_HDRLEN;
    memset(buf + at, 0, sizeof(struct nfgenmsg));
    at += sizeof(struct nfgenmsg);
    struct nlattr *a = (struct nlattr *)(buf + at);
    a->nla_type = NFULA_PAYLOAD;
    a->nla_len = (uint16_t)(ATTR_HDR + payload_len);
    memcpy(buf + at + ATTR_HDR, payload, payload_len);
    at += attr_step(a->nla_len);
    h->nlmsg_len = (uint32_t)(at - off);
    return at;
}

typedef struct {
    size_t n;
    uint8_t first[8];
    size_t len[8];
} seen_t;

static void note(const uint8_t *pkt, size_t len, void *ud) {
    seen_t *s = ud;
    if (s->n < 8) {
        s->first[s->n] = len ? pkt[0] : 0;
        s->len[s->n] = len;
    }
    s->n++;
}

/* Catches: a bind split into separate messages, which the kernel answers EBUSY with the mode unset. */
TEST the_bind_is_one_message_the_kernel_would_accept(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);

    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);

    uint16_t group = 0;
    ASSERTm("the group is bound", fake_nflog_is_bound(k, &group));
    ASSERT_EQ_FMT((uint16_t)42, group, "%u");

    uint8_t copy_mode = 0;
    uint32_t copy_range = 0;
    ASSERTm("and the copy mode landed on it", fake_nflog_mode(k, &copy_mode, &copy_range));
    ASSERT_EQ_FMT((uint8_t)NFULNL_COPY_PACKET, copy_mode, "%u");
    ASSERT_EQ_FMT((uint32_t)300, copy_range, "%u");

    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: the bind not setting a queue threshold of 1 and a flush timeout under a second. */
TEST the_kernel_is_asked_not_to_hold_packets(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);

    uint32_t qthresh = 0, timeout = 0;
    ASSERTm("a queue threshold is set", fake_nflog_qthresh(k, &qthresh));
    ASSERT_EQ_FMTm("one packet is one datagram", (uint32_t)1, qthresh, "%u");
    ASSERTm("and a flush timeout", fake_nflog_timeout(k, &timeout));
    ASSERTm("shorter than the kernel's second", timeout < 100 && timeout > 0);

    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a PF_BIND that makes nfnetlink_log the family's default logger. */
TEST nothing_is_registered_as_the_familys_logger(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);
    ASSERT_FALSEm("the tap changes nothing outside its own group",
                  fake_nflog_saw_a_pf_command(k));
    ASSERT_EQ_FMTm("and says it once", (size_t)1, fake_nflog_config_messages(k), "%zu");
    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a refused bind returned as an open socket, or leaking on its failure path. */
TEST a_refused_bind_is_not_an_open_socket(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    fake_nflog_refuse_next(k, -EPERM);

    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT_FALSEm("a group the kernel refused is not a tap", n != NULL);
    ASSERT_FALSEm("and nothing was bound", fake_nflog_is_bound(k, NULL));
    fake_nflog_stop(k);
    PASS();
}

TEST an_answer_to_another_question_is_not_this_ones(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    fake_nflog_stray_ack_first(k);

    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERTm("the refusal in front of it was not this bind's", n != NULL);
    ASSERT(fake_nflog_is_bound(k, NULL));
    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a bind sent without NLM_F_REQUEST, which the kernel acknowledges and never runs. */
TEST the_bind_is_a_request_the_kernel_will_execute(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);
    ASSERTm("the kernel ran it, not just acknowledged it", fake_nflog_is_bound(k, NULL));
    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a copy range of 0 (the whole packet) or more than the reader holds accepted. */
TEST a_range_the_reader_could_not_hold_is_refused(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    ASSERT_FALSEm("zero is the whole packet", firc_nflog_open_fd(fd, 42, 0) != NULL);
    fake_nflog_stop(k);

    k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    ASSERT_FALSEm("and so is more than the reader's buffer",
                  firc_nflog_open_fd(fd, 42, 60000) != NULL);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a reader taking only the first message of a batched datagram. */
TEST every_packet_in_one_datagram_is_read(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);

    uint8_t dg[512];
    static const uint8_t one[] = {0x45, 0x11};
    static const uint8_t two[] = {0x60, 0x22, 0x33};
    size_t off = add_packet(dg, 0, one, sizeof(one));
    off = add_packet(dg, off, two, sizeof(two));
    ASSERT(fake_nflog_send(k, dg, off));

    seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(FIRC_OK, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMT((size_t)2, s.n, "%zu");
    ASSERT_EQ_FMT((size_t)2, s.len[0], "%zu");
    ASSERT_EQ_FMT((uint8_t)0x45, s.first[0], "%u");
    ASSERT_EQ_FMT((size_t)3, s.len[1], "%zu");
    ASSERT_EQ_FMT((uint8_t)0x60, s.first[1], "%u");

    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a non-packet message ending the walk of its datagram. */
TEST a_message_that_is_not_a_packet_does_not_end_the_datagram(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);

    uint8_t dg[512];
    memset(dg, 0, sizeof(dg));
    struct nlmsghdr *h = (struct nlmsghdr *)dg;
    h->nlmsg_type = NLMSG_ERROR;
    h->nlmsg_len = (uint32_t)(NLMSG_HDRLEN + sizeof(struct nlmsgerr));
    size_t off = attr_step(h->nlmsg_len);
    static const uint8_t pkt[] = {0x45, 0x77};
    off = add_packet(dg, off, pkt, sizeof(pkt));
    ASSERT(fake_nflog_send(k, dg, off));

    seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(FIRC_OK, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMT((size_t)1, s.n, "%zu");
    ASSERT_EQ_FMT((uint8_t)0x45, s.first[0], "%u");

    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a message length past the datagram, or too short to step by, walked over. */
TEST a_malformed_message_stops_the_walk(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);

    uint8_t dg[512];
    static const uint8_t pkt[] = {0x45, 0x99};
    size_t off = add_packet(dg, 0, pkt, sizeof(pkt));

    struct nlmsghdr *h = (struct nlmsghdr *)(dg + off);
    memset(h, 0, NLMSG_HDRLEN);
    h->nlmsg_type = (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET);
    h->nlmsg_len = 4096;
    off += NLMSG_HDRLEN;
    ASSERT(fake_nflog_send(k, dg, off));

    seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQm("a message that cannot be stepped past is lost packets",
               FIRC_ERR_LIMIT, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMTm("the good message before it was still delivered", (size_t)1, s.n, "%zu");

    off = add_packet(dg, 0, pkt, sizeof(pkt));
    h = (struct nlmsghdr *)(dg + off);
    memset(h, 0, NLMSG_HDRLEN);
    h->nlmsg_len = 0;
    off += NLMSG_HDRLEN;
    ASSERT(fake_nflog_send(k, dg, off));
    memset(&s, 0, sizeof(s));
    ASSERT_EQm("a message that cannot be stepped past is lost packets",
               FIRC_ERR_LIMIT, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMT((size_t)1, s.n, "%zu");

    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: an empty read reported as an error or a closed window. */
TEST nothing_to_read_is_not_a_failure(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);
    seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMT((size_t)0, s.n, "%zu");
    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a message parsed out of the previous datagram's leftovers in the buffer. */
TEST a_message_claiming_more_than_arrived_reads_no_leftovers(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);

    uint8_t dg[512];
    static const uint8_t earlier[] = {0x45, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    size_t off = add_packet(dg, 0, earlier, sizeof(earlier));
    ASSERT(fake_nflog_send(k, dg, off));
    seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(FIRC_OK, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMT((size_t)1, s.n, "%zu");

    memset(dg, 0, sizeof(dg));
    struct nlmsghdr *h = (struct nlmsghdr *)dg;
    h->nlmsg_type = (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET);
    h->nlmsg_len = 4096;
    ASSERT(fake_nflog_send(k, dg, (size_t)NLMSG_HDRLEN));

    memset(&s, 0, sizeof(s));
    ASSERT_EQm("what could not be walked is reported as loss, not as a quiet window",
               FIRC_ERR_LIMIT, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMTm("the packet before it is not this window's", (size_t)0, s.n, "%zu");

    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a tail shorter than its padding wrapping the remaining count and walking back. */
TEST a_tail_shorter_than_its_own_padding_ends_the_datagram(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);

    uint8_t dg[512];
    static const uint8_t earlier[] = {0x45, 0xbb, 0xbb, 0xbb};
    size_t off = add_packet(dg, 0, earlier, sizeof(earlier));
    ASSERT(fake_nflog_send(k, dg, off));
    seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(FIRC_OK, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMT((size_t)1, s.n, "%zu");

    memset(dg, 0, sizeof(dg));
    struct nlmsghdr *h = (struct nlmsghdr *)dg;
    h->nlmsg_type = (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET);
    h->nlmsg_len = (uint32_t)NLMSG_HDRLEN + 2u;
    ASSERT(fake_nflog_send(k, dg, (size_t)h->nlmsg_len));

    memset(&s, 0, sizeof(s));
    ASSERT_EQm("what could not be walked is reported as loss, not as a quiet window",
               FIRC_ERR_LIMIT, firc_nflog_read(n, note, &s));
    ASSERT_EQ_FMTm("the packet before it is not this window's", (size_t)0, s.n, "%zu");

    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a datagram cut off by the buffer read as a clean batch. */
TEST a_datagram_too_large_for_the_reader_is_lost_packets(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT(n != NULL);

    size_t cap = 4u * FIRC_NFLOG_MAX_RANGE;
    uint8_t *dg = calloc(1, cap);
    ASSERT(dg != NULL);
    static const uint8_t pkt[] = {0x45, 0x55, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    size_t off = 0;
    while (off < FIRC_NFLOG_BUF + 32u) { off = add_packet(dg, off, pkt, sizeof(pkt)); }
    bool boundary = (off == FIRC_NFLOG_BUF + 32u);
    bool sent = fake_nflog_send(k, dg, off);
    free(dg);
    ASSERTm("the messages divide the reader's buffer exactly", boundary);
    ASSERTm("the fake could send it", sent);

    seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQm("a datagram that did not fit is lost packets", FIRC_ERR_LIMIT,
               firc_nflog_read(n, note, &s));
    ASSERTm("and what did fit was still reported", s.n > 0);

    firc_nflog_close(n);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a datagram from a port other than the kernel's (0) read as packets. */
TEST a_datagram_that_did_not_come_from_the_kernel_is_not_read(void) {
    struct sockaddr_nl nl;
    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;
    nl.nl_pid = 0;
    ASSERTm("the kernel", firc_nflog_from_the_kernel(&nl, sizeof(nl)));
    nl.nl_pid = 4242;
    ASSERT_FALSEm("another process on this box",
                  firc_nflog_from_the_kernel(&nl, sizeof(nl)));
    nl.nl_pid = 1;
    ASSERT_FALSEm("and the lowest port id that is not the kernel's",
                  firc_nflog_from_the_kernel(&nl, sizeof(nl)));

    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    ASSERTm("a socketpair has none to present, and is the test seam",
            firc_nflog_from_the_kernel(&un, sizeof(un)));
    ASSERT(firc_nflog_from_the_kernel(NULL, 0));
    PASS();
}

/* Catches: the bind's acknowledgement read out of a previous datagram's leftovers. */
TEST the_bind_does_not_read_its_answer_out_of_leftovers(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    fake_nflog_ack_garbage_first(k);

    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERTm("a malformed answer is not this bind's answer", n == NULL);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: an acknowledgement too short to hold an error read as success. */
TEST an_acknowledgement_too_short_to_carry_an_error_is_not_one(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    fake_nflog_ack_too_short_first(k);

    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERTm("a truncated answer is not a yes", n == NULL);
    ASSERT_FALSEm("and nothing was bound", fake_nflog_is_bound(k, NULL));
    fake_nflog_stop(k);
    PASS();
}

/* Catches: a bind with no receive timeout hanging on a kernel that never answers. */
TEST a_kernel_that_never_answers_does_not_wedge_the_tap(void) {
    int fd = -1;
    fake_nflog_t *k = fake_nflog_start(&fd);
    ASSERT(k != NULL);
    fake_nflog_swallow_next(k);

    firc_nflog_t *n = firc_nflog_open_fd(fd, 42, 300);
    ASSERT_FALSEm("a bind nobody answered is not a tap", n != NULL);
    fake_nflog_stop(k);
    PASS();
}

/* Catches: ENOBUFS (packets dropped) reported as FIRC_OK. */
TEST a_dropped_packet_is_not_a_quiet_window(void) {
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_nflog_recv_error(ENOBUFS));
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_nflog_recv_error(EAGAIN));
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_nflog_recv_error(EINTR));
    ASSERT_EQ(FIRC_ERR_IO, firc_nflog_recv_error(EBADF));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_bind_is_one_message_the_kernel_would_accept);
    RUN_TEST(the_kernel_is_asked_not_to_hold_packets);
    RUN_TEST(nothing_is_registered_as_the_familys_logger);
    RUN_TEST(a_refused_bind_is_not_an_open_socket);
    RUN_TEST(the_bind_is_a_request_the_kernel_will_execute);
    RUN_TEST(an_answer_to_another_question_is_not_this_ones);
    RUN_TEST(a_kernel_that_never_answers_does_not_wedge_the_tap);
    RUN_TEST(the_bind_does_not_read_its_answer_out_of_leftovers);
    RUN_TEST(an_acknowledgement_too_short_to_carry_an_error_is_not_one);
    RUN_TEST(a_datagram_too_large_for_the_reader_is_lost_packets);
    RUN_TEST(a_datagram_that_did_not_come_from_the_kernel_is_not_read);
    RUN_TEST(a_range_the_reader_could_not_hold_is_refused);
    RUN_TEST(every_packet_in_one_datagram_is_read);
    RUN_TEST(a_message_that_is_not_a_packet_does_not_end_the_datagram);
    RUN_TEST(a_malformed_message_stops_the_walk);
    RUN_TEST(a_message_claiming_more_than_arrived_reads_no_leftovers);
    RUN_TEST(a_tail_shorter_than_its_own_padding_ends_the_datagram);
    RUN_TEST(nothing_to_read_is_not_a_failure);
    RUN_TEST(a_dropped_packet_is_not_a_quiet_window);
    GREATEST_MAIN_END();
}
