#include "greatest.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include "../../src/dns/pktinfo.h"

typedef union {
    struct cmsghdr hdr;
    unsigned char b[64];
} cbuf_t;

static size_t put_cmsg(cbuf_t *c, int level, int type, const unsigned char *data, size_t len) {
    memset(c, 0, sizeof(*c));
    c->hdr.cmsg_len = CMSG_LEN(len);
    c->hdr.cmsg_level = level;
    c->hdr.cmsg_type = type;
    memcpy(CMSG_DATA(&c->hdr), data, len);
    return CMSG_SPACE(len);
}

static void host_int(unsigned char *at, int v) { memcpy(at, &v, sizeof(v)); }

TEST a_v4_reply_carries_the_host_order_ifindex_then_the_network_order_source(void) {
    firc_pktinfo_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.family = AF_INET;
    memcpy(&pi.dst4, (const unsigned char[]){192, 0, 2, 53}, 4);
    pi.ifindex = 0x01020304;
    firc_pktinfo_cmsg_t got;
    size_t got_len = firc_pktinfo_write(&pi, &got);

    unsigned char data[12] = {0, 0, 0, 0, 192, 0, 2, 53, 0, 0, 0, 0};
    host_int(data, 0x01020304);
    cbuf_t want;
    size_t want_len = put_cmsg(&want, 0, 8, data, sizeof(data));
    ASSERT_EQ_FMT(want_len, got_len, "%zu");
    ASSERT_MEM_EQ(want.b, &got, want_len);
    PASS();
}

TEST a_v6_reply_carries_the_network_order_source_then_the_host_order_ifindex(void) {
    static const unsigned char addr[16] = {0xfd, 0x37, 0x9a, 0x5c, 0xbe, 0x10, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0x12, 0x34};
    firc_pktinfo_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.family = AF_INET6;
    memcpy(&pi.dst6, addr, 16);
    pi.ifindex = 0x0a0b0c0d;
    firc_pktinfo_cmsg_t got;
    size_t got_len = firc_pktinfo_write(&pi, &got);

    unsigned char data[20];
    memcpy(data, addr, 16);
    host_int(data + 16, 0x0a0b0c0d);
    cbuf_t want;
    size_t want_len = put_cmsg(&want, 41, 50, data, sizeof(data));
    ASSERT_EQ_FMT(want_len, got_len, "%zu");
    ASSERT_MEM_EQ(want.b, &got, want_len);
    PASS();
}

TEST a_v4_cmsg_from_the_kernel_yields_its_ifindex_and_destination(void) {
    unsigned char data[12] = {0, 0, 0, 0, 10, 0, 0, 1, 198, 51, 100, 9};
    host_int(data, 0x00000107);
    cbuf_t c;
    put_cmsg(&c, 0, 8, data, sizeof(data));
    firc_pktinfo_t pi;
    memset(&pi, 0xa5, sizeof(pi));
    ASSERT(firc_pktinfo_read(&c.hdr, &pi));
    ASSERT_EQ(AF_INET, pi.family);
    ASSERT_EQ(0x107, pi.ifindex);
    ASSERT_MEM_EQ(((const unsigned char[]){198, 51, 100, 9}), &pi.dst4, 4);
    PASS();
}

TEST a_v6_cmsg_from_the_kernel_yields_its_ifindex_and_destination(void) {
    unsigned char data[20] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53};
    host_int(data + 16, 0x00030201);
    cbuf_t c;
    put_cmsg(&c, 41, 50, data, sizeof(data));
    firc_pktinfo_t pi;
    memset(&pi, 0xa5, sizeof(pi));
    ASSERT(firc_pktinfo_read(&c.hdr, &pi));
    ASSERT_EQ(AF_INET6, pi.family);
    ASSERT_EQ(0x30201, pi.ifindex);
    ASSERT_MEM_EQ(data, &pi.dst6, 16);
    PASS();
}

TEST a_cmsg_that_is_not_pktinfo_or_too_short_is_not_read(void) {
    unsigned char data[12] = {0};
    cbuf_t c;
    firc_pktinfo_t pi;
    put_cmsg(&c, 0, 2, data, sizeof(data));
    ASSERT_FALSE(firc_pktinfo_read(&c.hdr, &pi));
    put_cmsg(&c, 41, 8, data, sizeof(data));
    ASSERT_FALSE(firc_pktinfo_read(&c.hdr, &pi));
    put_cmsg(&c, 0, 8, data, 8);
    ASSERT_FALSE(firc_pktinfo_read(&c.hdr, &pi));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_v4_reply_carries_the_host_order_ifindex_then_the_network_order_source);
    RUN_TEST(a_v6_reply_carries_the_network_order_source_then_the_host_order_ifindex);
    RUN_TEST(a_v4_cmsg_from_the_kernel_yields_its_ifindex_and_destination);
    RUN_TEST(a_v6_cmsg_from_the_kernel_yields_its_ifindex_and_destination);
    RUN_TEST(a_cmsg_that_is_not_pktinfo_or_too_short_is_not_read);
    GREATEST_MAIN_END();
}
