#include "greatest.h"

#include <sys/socket.h>
#include <unistd.h>

#include "firc/conntrack.h"
#include "wire_bytes.h"

static const uint8_t SRC4[4] = {10, 0, 0, 2};
static const uint8_t DST4[4] = {198, 18, 0, 5};
static const uint8_t MARK_BE[4] = {0x40, 0xa5, 0x12, 0x34};
static const uint8_t ID_BE[4] = {0x0a, 0x0b, 0x0c, 0x0d};

static void put_tuple_orig(wb_t *w) {
    size_t orig = wb_attr(w, 1 | 0x8000);
    size_t ip = wb_attr(w, 1 | 0x8000);
    wb_attr_bytes(w, 1, SRC4, 4);
    wb_attr_bytes(w, 2, DST4, 4);
    wb_attr_end(w, ip);
    size_t proto = wb_attr(w, 2 | 0x8000);
    wb_attr_bytes(w, 1, (const uint8_t[]){6}, 1);
    wb_attr_bytes(w, 2, (const uint8_t[]){0xc3, 0x50}, 2);
    wb_attr_bytes(w, 3, (const uint8_t[]){0x01, 0xbb}, 2);
    wb_attr_end(w, proto);
    wb_attr_end(w, orig);
}

static void put_dump_request(wb_t *w, uint8_t family, uint32_t seq) {
    size_t at = wb_nlmsg(w, 0x0101, 0x0301, seq);
    wb_bytes(w, (const uint8_t[]){family, 0, 0x00, 0x00}, 4);
    wb_attr_bytes(w, 8, (const uint8_t[]){0x00, 0xa5, 0x00, 0x00}, 4);
    wb_attr_bytes(w, 21, (const uint8_t[]){0x00, 0xff, 0x00, 0x00}, 4);
    wb_nlmsg_end(w, at);
}

TEST a_mark_flush_sends_its_filter_in_network_order_and_deletes_by_the_entry_id(void) {
    int sv[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
    firc_ct_t *ct = firc_ct_open_fd(sv[0]);
    ASSERT(ct != NULL);

    wb_t entry = {0};
    size_t at = wb_nlmsg(&entry, 0x0100, 0x0002, 1);
    wb_bytes(&entry, (const uint8_t[]){2, 0, 0x00, 0x00}, 4);
    put_tuple_orig(&entry);
    wb_attr_bytes(&entry, 8, MARK_BE, 4);
    wb_attr_bytes(&entry, 12, ID_BE, 4);
    wb_nlmsg_end(&entry, at);
    ASSERT(wb_send(sv[1], &entry));
    wb_t done1 = {0};
    wb_done(&done1, 1);
    ASSERT(wb_send(sv[1], &done1));
    wb_t ack2 = {0};
    wb_ack(&ack2, 2, 0);
    ASSERT(wb_send(sv[1], &ack2));
    wb_t done3 = {0};
    wb_done(&done3, 3);
    ASSERT(wb_send(sv[1], &done3));

    size_t deleted = 0;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(ct, 0x00a50000u, 0x00ff0000u, &deleted));
    ASSERT_EQ_FMT((size_t)1, deleted, "%zu");

    wb_t want = {0};
    wb_t got = {0};
    put_dump_request(&want, 2, 1);
    ASSERT(wb_recv(sv[1], &got));
    ASSERT_EQ_FMT(want.n, got.n, "%zu");
    ASSERT_MEM_EQ(want.b, got.b, want.n);

    memset(&want, 0, sizeof(want));
    at = wb_nlmsg(&want, 0x0102, 0x0005, 2);
    wb_bytes(&want, (const uint8_t[]){2, 0, 0x00, 0x00}, 4);
    put_tuple_orig(&want);
    wb_attr_bytes(&want, 12, ID_BE, 4);
    wb_nlmsg_end(&want, at);
    ASSERT(wb_recv(sv[1], &got));
    ASSERT_EQ_FMT(want.n, got.n, "%zu");
    ASSERT_MEM_EQ(want.b, got.b, want.n);

    memset(&want, 0, sizeof(want));
    put_dump_request(&want, 10, 3);
    ASSERT(wb_recv(sv[1], &got));
    ASSERT_EQ_FMT(want.n, got.n, "%zu");
    ASSERT_MEM_EQ(want.b, got.b, want.n);

    firc_ct_close(ct);
    close(sv[1]);
    PASS();
}

TEST an_entry_whose_network_order_mark_misses_the_filter_is_kept(void) {
    int sv[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
    firc_ct_t *ct = firc_ct_open_fd(sv[0]);
    ASSERT(ct != NULL);

    wb_t entry = {0};
    size_t at = wb_nlmsg(&entry, 0x0100, 0x0002, 1);
    wb_bytes(&entry, (const uint8_t[]){2, 0, 0x00, 0x00}, 4);
    put_tuple_orig(&entry);
    wb_attr_bytes(&entry, 8, (const uint8_t[]){0x34, 0x12, 0xa5, 0x40}, 4);
    wb_attr_bytes(&entry, 12, ID_BE, 4);
    wb_nlmsg_end(&entry, at);
    ASSERT(wb_send(sv[1], &entry));
    wb_t done1 = {0};
    wb_done(&done1, 1);
    ASSERT(wb_send(sv[1], &done1));
    wb_t done2 = {0};
    wb_done(&done2, 2);
    ASSERT(wb_send(sv[1], &done2));

    size_t deleted = 9;
    ASSERT_EQ(FIRC_OK, firc_ct_flush_by_mark(ct, 0x00a50000u, 0x00ff0000u, &deleted));
    ASSERT_EQ_FMT((size_t)0, deleted, "%zu");

    firc_ct_close(ct);
    close(sv[1]);
    PASS();
}

SUITE(ct_wire) {
    RUN_TEST(a_mark_flush_sends_its_filter_in_network_order_and_deletes_by_the_entry_id);
    RUN_TEST(an_entry_whose_network_order_mark_misses_the_filter_is_kept);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(ct_wire);
    GREATEST_MAIN_END();
}
