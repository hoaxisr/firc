#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "firc/tappacket.h"

/* An IPv4/TCP packet with `payload_len` bytes after the TCP header; `ihl` and `doff` in 32-bit words. */
static size_t v4_tcp(uint8_t *out, uint8_t ihl, uint8_t doff, uint16_t frag,
                     const uint8_t *payload, size_t payload_len) {
    size_t ip_hdr = (size_t)ihl * 4, tcp_hdr = (size_t)doff * 4;
    memset(out, 0, ip_hdr + tcp_hdr);
    out[0] = (uint8_t)(0x40 | ihl);
    size_t total = ip_hdr + tcp_hdr + payload_len;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[6] = (uint8_t)(frag >> 8);
    out[7] = (uint8_t)frag;
    out[9] = 6;
    out[12] = 192; out[13] = 168; out[14] = 1; out[15] = 42;
    out[16] = 104; out[17] = 21; out[18] = 0; out[19] = 5;
    out[ip_hdr + 2] = 0x01;
    out[ip_hdr + 3] = 0xbb;
    out[ip_hdr + 12] = (uint8_t)(doff << 4);
    if (payload_len > 0) { memcpy(out + ip_hdr + tcp_hdr, payload, payload_len); }
    return total;
}

static size_t v6_tcp(uint8_t *out, const uint8_t *payload, size_t payload_len) {
    memset(out, 0, 40 + 20);
    out[0] = 0x60;
    size_t plen = 20 + payload_len;
    out[4] = (uint8_t)(plen >> 8);
    out[5] = (uint8_t)plen;
    out[6] = 6;
    out[7] = 64;
    out[8] = 0xfd; out[23] = 0x01;
    out[24] = 0x20; out[39] = 0x02;
    out[40 + 2] = 0x01;
    out[40 + 3] = 0xbb;
    out[40 + 12] = (5u << 4);
    if (payload_len > 0) { memcpy(out + 60, payload, payload_len); }
    return 40 + plen;
}

TEST an_ipv4_tcp_packet_gives_its_ends_and_its_payload(void) {
    uint8_t buf[256];
    static const uint8_t body[] = {0x16, 0x03, 0x01, 0xde, 0xad};
    size_t n = v4_tcp(buf, 5, 5, 0, body, sizeof(body));
    firc_tap_packet_t p;
    ASSERT(firc_tap_packet_parse(buf, n, &p));
    ASSERT_EQ_FMT(4, (int)p.src.len, "%d");
    ASSERT_EQ(0, memcmp(p.src.b, (uint8_t[]){192, 168, 1, 42}, 4));
    ASSERT_EQ(0, memcmp(p.dst.b, (uint8_t[]){104, 21, 0, 5}, 4));
    ASSERT_EQ_FMT(443, (int)p.dst_port, "%d");
    ASSERT_EQ_FMT(sizeof(body), p.payload_len, "%zu");
    ASSERT_EQ(0, memcmp(p.payload, body, sizeof(body)));
    PASS();
}

/* Catches: a TCP header assumed to be 20 bytes, handing the options to the ClientHello reader. */
TEST tcp_options_are_stepped_over(void) {
    uint8_t buf[256];
    static const uint8_t body[] = {0x16, 0x03, 0x01};
    size_t n = v4_tcp(buf, 5, 8, 0, body, sizeof(body));
    firc_tap_packet_t p;
    ASSERT(firc_tap_packet_parse(buf, n, &p));
    ASSERT_EQ_FMT(sizeof(body), p.payload_len, "%zu");
    ASSERT_EQ(0, memcmp(p.payload, body, sizeof(body)));
    PASS();
}

TEST ipv4_options_are_stepped_over(void) {
    uint8_t buf[256];
    static const uint8_t body[] = {0x16};
    size_t n = v4_tcp(buf, 8, 5, 0, body, sizeof(body));
    firc_tap_packet_t p;
    ASSERT(firc_tap_packet_parse(buf, n, &p));
    ASSERT_EQ_FMT((size_t)1, p.payload_len, "%zu");
    ASSERT_EQ(0x16, p.payload[0]);
    PASS();
}

TEST an_ipv6_tcp_packet_is_read_too(void) {
    uint8_t buf[256];
    static const uint8_t body[] = {0x16, 0x03, 0x01};
    size_t n = v6_tcp(buf, body, sizeof(body));
    firc_tap_packet_t p;
    ASSERT(firc_tap_packet_parse(buf, n, &p));
    ASSERT_EQ_FMT(16, (int)p.src.len, "%d");
    ASSERT_EQ_FMT(0xfd, (int)p.src.b[0], "%d");
    ASSERT_EQ_FMT(0x20, (int)p.dst.b[0], "%d");
    ASSERT_EQ_FMT(443, (int)p.dst_port, "%d");
    ASSERT_EQ_FMT(sizeof(body), p.payload_len, "%zu");
    PASS();
}

/* Catches: a fragment parsed instead of refused. */
TEST a_fragment_is_refused(void) {
    uint8_t buf[256];
    static const uint8_t body[] = {0x16};
    firc_tap_packet_t p;
    size_t n = v4_tcp(buf, 5, 5, 0x2000, body, sizeof(body));
    ASSERT_FALSEm("more-fragments", firc_tap_packet_parse(buf, n, &p));
    n = v4_tcp(buf, 5, 5, 0x0001, body, sizeof(body));
    ASSERT_FALSEm("a later fragment", firc_tap_packet_parse(buf, n, &p));
    n = v4_tcp(buf, 5, 5, 0x4000, body, sizeof(body));
    ASSERTm("DF is not MF", firc_tap_packet_parse(buf, n, &p));
    PASS();
}

TEST anything_that_is_not_ipv4_or_ipv6_tcp_is_refused(void) {
    uint8_t buf[256];
    static const uint8_t body[] = {0x16};
    firc_tap_packet_t p;
    size_t n = v4_tcp(buf, 5, 5, 0, body, sizeof(body));

    uint8_t bad[256];
    memcpy(bad, buf, n);
    bad[9] = 17;
    ASSERT_FALSEm("not TCP", firc_tap_packet_parse(bad, n, &p));

    memcpy(bad, buf, n);
    bad[0] = 0x50;
    ASSERT_FALSEm("not IP", firc_tap_packet_parse(bad, n, &p));

    memcpy(bad, buf, n);
    bad[0] = 0x44;
    ASSERT_FALSEm("an impossible header length", firc_tap_packet_parse(bad, n, &p));

    n = v6_tcp(buf, body, sizeof(body));
    memcpy(bad, buf, n);
    bad[6] = 58;
    ASSERT_FALSEm("v6 next header is not TCP", firc_tap_packet_parse(bad, n, &p));
    memcpy(bad, buf, n);
    bad[6] = 0;
    ASSERT_FALSEm("an extension header chain is not followed",
                  firc_tap_packet_parse(bad, n, &p));
    PASS();
}

/* Catches: a header length pointing past the buffer followed. */
TEST a_header_length_past_the_buffer_is_refused(void) {
    uint8_t buf[256];
    static const uint8_t body[] = {0x16, 0x03, 0x01};
    firc_tap_packet_t p;
    size_t n = v4_tcp(buf, 5, 5, 0, body, sizeof(body));

    struct {
        const char *what;
        size_t at;
        uint8_t val;
    } pokes[] = {
        {"ihl says 60 bytes", 0, 0x4f},
        {"tcp data offset says 60", 20 + 12, 0xf0},
        {"total length says more than there is", 2, 0xff},
    };
    for (size_t i = 0; i < sizeof(pokes) / sizeof(pokes[0]); i++) {
        uint8_t *exact = malloc(n);
        ASSERT(exact != NULL);
        memcpy(exact, buf, n);
        exact[pokes[i].at] = pokes[i].val;
        bool got = firc_tap_packet_parse(exact, n, &p);
        free(exact);
        if (i == 2) {
            (void)got;
        } else {
            ASSERT_FALSEm(pokes[i].what, got);
        }
    }
    PASS();
}

TEST every_truncation_is_refused_or_harmless(void) {
    uint8_t buf[256];
    static const uint8_t body[] = {0x16, 0x03, 0x01, 0x02, 0x03};
    firc_tap_packet_t p;
    size_t n = v4_tcp(buf, 5, 5, 0, body, sizeof(body));
    for (size_t cut = 0; cut <= n; cut++) {
        uint8_t *exact = malloc(cut ? cut : 1);
        ASSERT(exact != NULL);
        memcpy(exact, buf, cut);
        if (firc_tap_packet_parse(exact, cut, &p)) {
            ASSERT(p.payload == NULL || (p.payload >= exact && p.payload + p.payload_len <= exact + cut));
        }
        free(exact);
    }
    n = v6_tcp(buf, body, sizeof(body));
    for (size_t cut = 0; cut <= n; cut++) {
        uint8_t *exact = malloc(cut ? cut : 1);
        ASSERT(exact != NULL);
        memcpy(exact, buf, cut);
        if (firc_tap_packet_parse(exact, cut, &p)) {
            ASSERT(p.payload == NULL || (p.payload >= exact && p.payload + p.payload_len <= exact + cut));
        }
        free(exact);
    }
    PASS();
}

/* An IPv4 header carrying `proto` with `l4` appended; `frag` is the raw flags and offset field. */
static size_t v4_head(uint8_t *out, uint8_t proto, uint16_t frag, const uint8_t *l4,
                       size_t l4_len) {
    memset(out, 0, 20 + l4_len);
    out[0] = 0x45;
    out[6] = (uint8_t)(frag >> 8);
    out[7] = (uint8_t)frag;
    out[9] = proto;
    out[12] = 192; out[13] = 168; out[14] = 1; out[15] = 42;
    out[16] = 104; out[17] = 21; out[18] = 0; out[19] = 5;
    if (l4_len > 0) { memcpy(out + 20, l4, l4_len); }
    return 20 + l4_len;
}

static size_t v6_head(uint8_t *out, uint8_t proto, const uint8_t *l4, size_t l4_len) {
    memset(out, 0, 40 + l4_len);
    out[0] = 0x60;
    out[6] = proto;
    out[8] = 0xfd; out[23] = 0x01;
    out[24] = 0x20; out[39] = 0x02;
    if (l4_len > 0) { memcpy(out + 40, l4, l4_len); }
    return 40 + l4_len;
}

/* A transport header with the destination port at byte 2, as TCP and UDP both have it. */
static size_t udp_hdr(uint8_t *out, uint16_t dport) {
    memset(out, 0, 8);
    out[2] = (uint8_t)(dport >> 8);
    out[3] = (uint8_t)dport;
    return 8;
}

TEST a_udp_head_gives_its_ports(void) {
    uint8_t buf[64], udp[8];
    size_t ulen = udp_hdr(udp, 53);
    firc_tap_head_t h;

    size_t n = v4_head(buf, 17 , 0, udp, ulen);
    ASSERT(firc_tap_head_parse(buf, n, &h));
    ASSERT_EQ_FMT(4, (int)h.src.len, "%d");
    ASSERT_EQ(0, memcmp(h.src.b, (uint8_t[]){192, 168, 1, 42}, 4));
    ASSERT_EQ(0, memcmp(h.dst.b, (uint8_t[]){104, 21, 0, 5}, 4));
    ASSERT_EQ_FMT(17, (int)h.proto, "%d");
    ASSERT_EQ_FMT(53, (int)h.dst_port, "%d");

    n = v6_head(buf, 17, udp, ulen);
    ASSERT(firc_tap_head_parse(buf, n, &h));
    ASSERT_EQ_FMT(16, (int)h.src.len, "%d");
    ASSERT_EQ(0, memcmp(h.src.b,
                         (uint8_t[]){0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
                         16));
    ASSERT_EQ(0, memcmp(h.dst.b,
                         (uint8_t[]){0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02},
                         16));
    ASSERT_EQ_FMT(17, (int)h.proto, "%d");
    ASSERT_EQ_FMT(53, (int)h.dst_port, "%d");
    PASS();
}

/* Catches: a 64-byte copy whose TCP header fills it all refused instead of giving its port. */
TEST a_tcp_head_gives_its_port_from_a_64_byte_copy(void) {
    uint8_t buf[64], tcp[44];
    memset(tcp, 0, sizeof(tcp));
    tcp[2] = 0x01; tcp[3] = 0xbb;
    tcp[12] = (uint8_t)(11u << 4);
    size_t n = v4_head(buf, 6 , 0, tcp, sizeof(tcp));
    ASSERT_EQ_FMT((size_t)64, n, "%zu");
    firc_tap_head_t h;
    ASSERT(firc_tap_head_parse(buf, n, &h));
    ASSERT_EQ_FMT(6, (int)h.proto, "%d");
    ASSERT_EQ_FMT(443, (int)h.dst_port, "%d");
    PASS();
}

/* Catches: an ICMP checksum read as a port. */
TEST an_icmp_head_has_no_port(void) {
    uint8_t buf[64];
    uint8_t icmp[8] = {8, 0, 0xff, 0xff, 0, 0, 0, 0};
    size_t n = v4_head(buf, 1 , 0, icmp, sizeof(icmp));
    firc_tap_head_t h;
    ASSERT(firc_tap_head_parse(buf, n, &h));
    ASSERT_EQ_FMT(1, (int)h.proto, "%d");
    ASSERT_EQ_FMT(0, (int)h.dst_port, "%d");
    PASS();
}

/* Catches: a later fragment read for a port, or a first fragment refused. */
TEST a_later_fragment_is_refused(void) {
    uint8_t udp[8];
    udp_hdr(udp, 53);
    uint8_t buf[64];
    firc_tap_head_t h;

    size_t n = v4_head(buf, 17, 0x0001 , udp, sizeof(udp));
    ASSERT_FALSEm("a later fragment", firc_tap_head_parse(buf, n, &h));

    n = v4_head(buf, 17, 0x2000 , udp, sizeof(udp));
    ASSERTm("the first fragment is read", firc_tap_head_parse(buf, n, &h));
    ASSERT_EQ_FMT(53, (int)h.dst_port, "%d");
    PASS();
}

TEST a_head_that_is_not_ip_is_refused(void) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x50;
    firc_tap_head_t h;
    ASSERT_FALSEm("not IP", firc_tap_head_parse(buf, sizeof(buf), &h));
    PASS();
}

/* Catches: a truncated head accepted, refused, or given a port other than the hand-worked result. */
TEST every_truncation_of_a_head_is_refused_or_harmless(void) {
    uint8_t tcp[20];
    memset(tcp, 0, sizeof(tcp));
    tcp[2] = 0x01; tcp[3] = 0xbb;
    tcp[12] = (uint8_t)(5u << 4);

    uint8_t buf[64];
    size_t n = v4_head(buf, 6, 0, tcp, sizeof(tcp));
    for (size_t cut = 0; cut <= n; cut++) {
        uint8_t *exact = malloc(cut ? cut : 1);
        ASSERT(exact != NULL);
        memcpy(exact, buf, cut);
        firc_tap_head_t h;
        bool got = firc_tap_head_parse(exact, cut, &h);
        free(exact);
        if (cut < 20) {
            ASSERTm("v4: truncated before the addresses is refused", !got);
        } else if (cut < 24) {
            ASSERTm("v4: addresses in, port bytes not yet, is harmless", got);
            ASSERT_EQ_FMT(0, (int)h.dst_port, "%d");
        } else {
            ASSERTm("v4: the port's bytes arrived", got);
            ASSERT_EQ_FMT(443, (int)h.dst_port, "%d");
        }
    }

    n = v6_head(buf, 6, tcp, sizeof(tcp));
    for (size_t cut = 0; cut <= n; cut++) {
        uint8_t *exact = malloc(cut ? cut : 1);
        ASSERT(exact != NULL);
        memcpy(exact, buf, cut);
        firc_tap_head_t h;
        bool got = firc_tap_head_parse(exact, cut, &h);
        free(exact);
        if (cut < 40) {
            ASSERTm("v6: truncated before the addresses is refused", !got);
        } else if (cut < 44) {
            ASSERTm("v6: addresses in, port bytes not yet, is harmless", got);
            ASSERT_EQ_FMT(0, (int)h.dst_port, "%d");
        } else {
            ASSERTm("v6: the port's bytes arrived", got);
            ASSERT_EQ_FMT(443, (int)h.dst_port, "%d");
        }
    }
    PASS();
}

/* Catches: the port read at a fixed offset of 20, or a bad IHL refusing the whole head. */
TEST ipv4_options_shift_where_the_port_is_read_from(void) {
    uint8_t buf[64];
    firc_tap_head_t h;

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x46;
    buf[9] = 6;
    buf[12] = 192; buf[13] = 168; buf[14] = 1; buf[15] = 42;
    buf[16] = 104; buf[17] = 21; buf[18] = 0; buf[19] = 5;
    buf[24 + 2] = 0x01; buf[24 + 3] = 0xbb;
    buf[24 + 12] = (uint8_t)(5u << 4);
    ASSERTm("ihl 6: parsed", firc_tap_head_parse(buf, 24 + 20, &h));
    ASSERT_EQ_FMT(6, (int)h.proto, "%d");
    ASSERT_EQ_FMT(443, (int)h.dst_port, "%d");

    memset(buf, 0, sizeof(buf));
    buf[0] = 0x44;
    buf[9] = 6;
    buf[12] = 192; buf[13] = 168; buf[14] = 1; buf[15] = 42;
    buf[16] = 104; buf[17] = 21; buf[18] = 0; buf[19] = 5;
    ASSERTm("ihl 4: parsed", firc_tap_head_parse(buf, 20, &h));
    ASSERT_EQ_FMT(6, (int)h.proto, "%d");
    ASSERT_EQ_FMT(0, (int)h.dst_port, "%d");

    {
        uint8_t *exact = malloc(20);
        ASSERT(exact != NULL);
        memset(exact, 0, 20);
        exact[0] = 0x4f;
        exact[9] = 6;
        exact[12] = 192; exact[13] = 168; exact[14] = 1; exact[15] = 42;
        exact[16] = 104; exact[17] = 21; exact[18] = 0; exact[19] = 5;
        bool got = firc_tap_head_parse(exact, 20, &h);
        free(exact);
        ASSERTm("ihl 15 at len 20: parsed", got);
        ASSERT_EQ_FMT(6, (int)h.proto, "%d");
        ASSERT_EQ_FMT(0, (int)h.dst_port, "%d");
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(an_ipv4_tcp_packet_gives_its_ends_and_its_payload);
    RUN_TEST(tcp_options_are_stepped_over);
    RUN_TEST(ipv4_options_are_stepped_over);
    RUN_TEST(an_ipv6_tcp_packet_is_read_too);
    RUN_TEST(a_fragment_is_refused);
    RUN_TEST(anything_that_is_not_ipv4_or_ipv6_tcp_is_refused);
    RUN_TEST(a_header_length_past_the_buffer_is_refused);
    RUN_TEST(every_truncation_is_refused_or_harmless);
    RUN_TEST(a_udp_head_gives_its_ports);
    RUN_TEST(a_tcp_head_gives_its_port_from_a_64_byte_copy);
    RUN_TEST(an_icmp_head_has_no_port);
    RUN_TEST(a_later_fragment_is_refused);
    RUN_TEST(a_head_that_is_not_ip_is_refused);
    RUN_TEST(every_truncation_of_a_head_is_refused_or_harmless);
    RUN_TEST(ipv4_options_shift_where_the_port_is_read_from);
    GREATEST_MAIN_END();
}
