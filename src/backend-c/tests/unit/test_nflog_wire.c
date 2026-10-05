#include "greatest.h"

#include <sys/socket.h>
#include <unistd.h>

#include "firc/nflog.h"
#include "firc/nflogsock.h"
#include "wire_bytes.h"

TEST the_bind_sends_group_range_and_thresholds_in_network_order(void) {
    int sv[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
    wb_t ack = {0};
    wb_ack(&ack, 1, 0);
    ASSERT(wb_send(sv[1], &ack));

    firc_nflog_t *n = firc_nflog_open_fd(sv[0], 0x0102, 0x0304);
    ASSERT(n != NULL);

    wb_t want = {0};
    size_t at = wb_nlmsg(&want, 0x0401, 0x0005, 1);
    wb_bytes(&want, (const uint8_t[]){0, 0, 0x01, 0x02}, 4);
    wb_attr_bytes(&want, 1, (const uint8_t[]){1}, 1);
    wb_attr_bytes(&want, 2, (const uint8_t[]){0x00, 0x00, 0x03, 0x04, 0x02, 0x00}, 6);
    wb_attr_bytes(&want, 5, (const uint8_t[]){0x00, 0x00, 0x00, 0x01}, 4);
    wb_attr_bytes(&want, 4, (const uint8_t[]){0x00, 0x00, 0x00, 0x01}, 4);
    wb_nlmsg_end(&want, at);

    wb_t got = {0};
    ASSERT(wb_recv(sv[1], &got));
    ASSERT_EQ_FMT(want.n, got.n, "%zu");
    ASSERT_MEM_EQ(want.b, got.b, want.n);

    firc_nflog_close(n);
    close(sv[1]);
    PASS();
}

static void put_packet(wb_t *w, const uint8_t *pkt, size_t len) {
    size_t at = wb_nlmsg(w, 0x0400, 0, 0);
    wb_bytes(w, (const uint8_t[]){2, 0, 0x00, 0x07}, 4);
    wb_attr_bytes(w, 1, (const uint8_t[]){0x08, 0x00, 1, 0}, 4);
    wb_attr_bytes(w, 2, (const uint8_t[]){0x40, 0xa5, 0x00, 0x00}, 4);
    wb_attr_bytes(w, 4, (const uint8_t[]){0x00, 0x00, 0x00, 0x03}, 4);
    wb_attr_bytes(w, 9, pkt, len);
    wb_nlmsg_end(w, at);
}

TEST a_kernel_packet_message_pins_only_the_payload_extraction(void) {
    static const uint8_t pkt[7] = {0x45, 0x00, 0x00, 0x07, 0xde, 0xad, 0x01};
    wb_t w = {0};
    put_packet(&w, pkt, sizeof(pkt));
    const uint8_t *out = NULL;
    size_t out_len = 0;
    ASSERT(firc_nflog_payload(w.b, w.n, &out, &out_len));
    ASSERT_EQ_FMT(sizeof(pkt), out_len, "%zu");
    ASSERT_MEM_EQ(pkt, out, sizeof(pkt));
    PASS();
}

typedef struct {
    size_t n;
    size_t lens[4];
    uint8_t first[4];
} seen_t;

static void seen_cb(const uint8_t *pkt, size_t len, void *ud) {
    seen_t *s = ud;
    if (s->n < 4) {
        s->lens[s->n] = len;
        s->first[s->n] = pkt[0];
    }
    s->n++;
}

TEST a_datagram_of_two_kernel_messages_walks_both_payloads(void) {
    static const uint8_t a[5] = {0x45, 1, 2, 3, 4};
    static const uint8_t b[9] = {0x60, 1, 2, 3, 4, 5, 6, 7, 8};
    wb_t w = {0};
    put_packet(&w, a, sizeof(a));
    put_packet(&w, b, sizeof(b));
    seen_t s = {0};
    ASSERT_EQ_FMT((size_t)0, firc_nflog_walk(w.b, w.n, seen_cb, &s), "%zu");
    ASSERT_EQ_FMT((size_t)2, s.n, "%zu");
    ASSERT_EQ_FMT((size_t)5, s.lens[0], "%zu");
    ASSERT_EQ_FMT((size_t)9, s.lens[1], "%zu");
    ASSERT_EQ(0x45, s.first[0]);
    ASSERT_EQ(0x60, s.first[1]);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_bind_sends_group_range_and_thresholds_in_network_order);
    RUN_TEST(a_kernel_packet_message_pins_only_the_payload_extraction);
    RUN_TEST(a_datagram_of_two_kernel_messages_walks_both_payloads);
    GREATEST_MAIN_END();
}
