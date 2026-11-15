#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tun.h"
#include "unit.h"

static const unsigned char A[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const unsigned char B[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

static uint32_t words(const unsigned char *d, size_t n, uint32_t acc) {
    for (size_t i = 0; i < n; i += 2)
        acc += ((uint32_t)d[i] << 8) | (i + 1 < n ? d[i + 1] : 0);
    return acc;
}

static uint16_t fold(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)acc;
}

static uint32_t pseudo6(const unsigned char *s, const unsigned char *d, uint32_t len, uint8_t nh) {
    uint32_t acc = words(s, 16, 0);
    acc = words(d, 16, acc);
    acc += (len >> 16) + (len & 0xFFFF);
    return acc + nh;
}

static uint16_t want_csum(const unsigned char *s, const unsigned char *d, uint8_t nh,
                          const unsigned char *l4, size_t n, size_t csum_at) {
    unsigned char *c = malloc(n);
    memcpy(c, l4, n);
    c[csum_at] = c[csum_at + 1] = 0;
    uint16_t r = (uint16_t)~fold(words(c, n, pseudo6(s, d, (uint32_t)n, nh)));
    free(c);
    return r;
}

static uint16_t be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static void mk_syn(unsigned char *p) {
    memset(p, 0, 60);
    p[0] = 0x60;
    p[5] = 20;
    p[6] = 6;
    p[7] = 64;
    memcpy(p + 8, A, 16);
    memcpy(p + 24, B, 16);
    p[40] = 40000 >> 8; p[41] = 40000 & 255;
    p[42] = 443 >> 8; p[43] = 443 & 255;
    p[44] = 0x01; p[45] = 0x02; p[46] = 0x03; p[47] = 0x04;
    p[52] = 0x50;
    p[53] = 0x02;
    p[54] = 0xFF; p[55] = 0xFF;
}

static void test_parse(void) {
    unsigned char p[60];
    struct flow_key k;
    size_t off = 0;
    mk_syn(p);
    check("parse v6 syn", 0, ip_parse(p, 60, &k, &off));
    check("v6 flag", 1, k.v6);
    check_mem("v6 src", A, k.src.b, 16);
    check_mem("v6 dst", B, k.dst.b, 16);
    check("v6 sport", 40000, k.sport);
    check("v6 dport", 443, k.dport);
    check("v6 proto", 6, k.proto);
    check("v6 flags", TCP_SYN, k.tcp_flags);
    check("v6 seq", 0x01020304, (long)k.seq);
    check("v6 window", 0xFFFF, k.window);
    check("v6 payload_off", 60, (long)off);
    check("v6 not a fragment", 0, k.frag);

    mk_syn(p);
    p[6] = 17;
    check("v6 udp parses", 0, ip_parse(p, 60, &k, &off));
    check("v6 udp proto", 17, k.proto);
    check("v6 udp payload_off", 48, (long)off);

    static const int bad[] = {0, 43, 44, 50, 58};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char name[48];
        mk_syn(p);
        p[6] = (unsigned char)bad[i];
        snprintf(name, sizeof name, "v6 next header %d refused", bad[i]);
        check(name, -1, ip_parse(p, 60, &k, &off));
    }
    mk_syn(p);
    check("v6 n=39 refused", -1, ip_parse(p, 39, &k, &off));
    p[5] = 100;
    check("v6 payload length beyond n refused", -1, ip_parse(p, 60, &k, &off));
    mk_syn(p);
    check("v6 tcp header cut short refused", -1, ip_parse(p, 59, &k, &off));
}

static void test_v4_still(void) {
    unsigned char p[40];
    struct flow_key k;
    size_t off = 0;
    memset(p, 0, sizeof p);
    p[0] = 0x45; p[3] = 40; p[8] = 64; p[9] = 6;
    p[12] = 10; p[15] = 1; p[16] = 10; p[19] = 2;
    p[20] = 0x9C; p[21] = 0x40; p[22] = 0x01; p[23] = 0xBB;
    p[32] = 0x50; p[33] = 0x10;
    memset(&k, 0xAA, sizeof k);
    check("v4 parses", 0, ip_parse(p, 40, &k, &off));
    check("v4 flag", 0, k.v6);
    check("v4 upper src bytes zero", 0, k.src.b[4] | k.src.b[15] | k.dst.b[4] | k.dst.b[15]);
    check("v4 sport", 40000, k.sport);
    check("v4 payload_off", 40, (long)off);
}

static void test_tcp6_build(void) {
    unsigned char out[128];
    static const unsigned char mss[4] = {2, 4, 0x05, 0xA0};
    size_t n = tcp6_build(out, sizeof out, A, B, 443, 40000, 0x11223344, 0x01020305,
                          TCP_SYN | TCP_ACK, 65535, mss, 4, NULL, 0);
    check("syn-ack length", 64, (long)n);
    check("version nibble", 6, out[0] >> 4);
    check("traffic class and flow label zero", 0, (out[0] & 15) | out[1] | out[2] | out[3]);
    check("payload length", 24, be16(out + 4));
    check("next header tcp", 6, out[6]);
    check("hop limit", 64, out[7]);
    check_mem("src", A, out + 8, 16);
    check_mem("dst", B, out + 24, 16);
    check("sport", 443, be16(out + 40));
    check("dport", 40000, be16(out + 42));
    check("data offset words", 6, out[52] >> 4);
    check("flags", TCP_SYN | TCP_ACK, out[53]);
    check_mem("mss option", mss, out + 60, 4);
    check("tcp checksum", want_csum(A, B, 6, out + 40, 24, 16), be16(out + 56));

    unsigned char data[5] = {1, 2, 3, 4, 5};
    n = tcp6_build(out, sizeof out, A, B, 443, 40000, 1, 2, TCP_ACK, 100, NULL, 0, data, 5);
    check("data segment length", 65, (long)n);
    check("data payload length", 25, be16(out + 4));
    check_mem("data copied", data, out + 60, 5);
    check("odd data checksum", want_csum(A, B, 6, out + 40, 25, 16), be16(out + 56));
    check("cap too small returns 0", 0, (long)tcp6_build(out, 64, A, B, 1, 2, 1, 2, TCP_ACK, 1, NULL, 0, data, 5));
}

static int g_pair[2];
static struct tun_dev g_dev;

static void setup(int gso) {
    if (g_pair[0] > 0) { close(g_pair[0]); close(g_pair[1]); }
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_pair) != 0) { perror("socketpair"); exit(2); }
    int big = 1 << 20;
    setsockopt(g_pair[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    setsockopt(g_pair[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    int fl = fcntl(g_pair[0], F_GETFL);
    fcntl(g_pair[0], F_SETFL, fl | O_NONBLOCK);
    memset(&g_dev, 0, sizeof g_dev);
    g_dev.fd = g_pair[0];
    g_dev.gso = gso;
}

static int drain(unsigned char *first, size_t cap, size_t *first_n) {
    int cnt = 0;
    for (;;) {
        unsigned char buf[65536];
        ssize_t r = recv(g_pair[1], buf, sizeof buf, MSG_DONTWAIT);
        if (r <= 0) break;
        if (cnt == 0 && first) {
            *first_n = (size_t)r > cap ? cap : (size_t)r;
            memcpy(first, buf, *first_n);
        }
        cnt++;
    }
    return cnt;
}

static void test_udp6(void) {
    unsigned char data[1452], pkt[2048];
    size_t pn = 0;
    for (size_t i = 0; i < sizeof data; i++) data[i] = (unsigned char)(i * 7 + 1);
    setup(0);
    check("udp6 small write", 0, udp6_write_to_client(&g_dev, A, B, 5353, 53000, data, 11));
    check("udp6 one datagram", 1, drain(pkt, sizeof pkt, &pn));
    check("udp6 packet length", 40 + 8 + 11, (long)pn);
    check("udp6 version", 6, pkt[0] >> 4);
    check("udp6 payload length", 19, be16(pkt + 4));
    check("udp6 next header", 17, pkt[6]);
    check("udp6 hop limit", 64, pkt[7]);
    check_mem("udp6 src", A, pkt + 8, 16);
    check_mem("udp6 dst", B, pkt + 24, 16);
    check("udp6 sport", 5353, be16(pkt + 40));
    check("udp6 dport", 53000, be16(pkt + 42));
    check("udp6 length field", 19, be16(pkt + 44));
    check("udp6 checksum", want_csum(A, B, 17, pkt + 40, 19, 6), be16(pkt + 46));
    check("udp6 checksum nonzero", 1, be16(pkt + 46) != 0);
    check_mem("udp6 data", data, pkt + 48, 11);

    unsigned char z[2];
    int found = 0;
    for (unsigned v = 0; v < 65536 && !found; v++) {
        z[0] = (unsigned char)(v >> 8);
        z[1] = (unsigned char)v;
        unsigned char l4[10] = {5353 >> 8, 5353 & 255, 53000 >> 8, 53000 & 255, 0, 10, 0, 0, z[0], z[1]};
        found = want_csum(A, B, 17, l4, 10, 6) == 0;
    }
    check("udp6 zero checksum case exists", 1, found);
    check("udp6 zero checksum write", 0, udp6_write_to_client(&g_dev, A, B, 5353, 53000, z, 2));
    drain(pkt, sizeof pkt, &pn);
    check("udp6 zero checksum goes out as ffff", 0xFFFF, be16(pkt + 46));

    check("udp6 max write", 0, udp6_write_to_client(&g_dev, A, B, 1, 2, data, 1452));
    check("udp6 max one datagram", 1, drain(pkt, sizeof pkt, &pn));
    check("udp6 max packet is the MTU", 1500, (long)pn);
    check("udp6 max checksum", want_csum(A, B, 17, pkt + 40, 1460, 6), be16(pkt + 46));

    unsigned char big[1453] = {0};
    check("udp6 1453 refused", -1, udp6_write_to_client(&g_dev, A, B, 1, 2, big, 1453));
    check("udp6 1453 wrote nothing", 0, drain(NULL, 0, &pn));

    setup(1);
    check("udp6 write with offload", 0, udp6_write_to_client(&g_dev, A, B, 5353, 53000, data, 11));
    unsigned char raw[2048];
    check("udp6 offload one datagram", 1, drain(raw, sizeof raw, &pn));
    check("udp6 offload length", 10 + 59, (long)pn);
    check("udp6 offload header plain", 0, raw[0] | raw[1]);
    check("udp6 offload packet follows", 6, raw[10] >> 4);
}

static void test_data6(void) {
    unsigned char hdr[TUN6_HDR_LEN], data[3000], raw[4096];
    size_t pn = 0;
    for (size_t i = 0; i < sizeof data; i++) data[i] = (unsigned char)(i * 13 + 5);

    setup(0);
    tcp6_hdr_build(hdr, A, B, 443, 40000, 0x0A0B0C0D, 0x01020304, TCP_ACK, 777);
    check("hdr_build version", 6, hdr[0] >> 4);
    check("hdr_build next header", 6, hdr[6]);
    check("hdr_build hop limit", 64, hdr[7]);
    check("hdr_build flow zero", 0, (hdr[0] & 15) | hdr[1] | hdr[2] | hdr[3]);
    check_mem("hdr_build src", A, hdr + 8, 16);
    check_mem("hdr_build dst", B, hdr + 24, 16);
    check("hdr_build sport", 443, be16(hdr + 40));
    check("hdr_build dport", 40000, be16(hdr + 42));
    check("hdr_build data offset", 5, hdr[52] >> 4);
    check("hdr_build window", 777, be16(hdr + 54));
    check("hdr_build checksum left empty", 0, be16(hdr + 56));
    check("write_data6 plain", 0, tun_write_data6(&g_dev, hdr, data, 1000, TUN6_MSS));
    check("plain one datagram", 1, drain(raw, sizeof raw, &pn));
    check("plain length", 1060, (long)pn);
    check("plain payload length", 1020, be16(raw + 4));
    check_mem("plain data", data, raw + 60, 1000);
    check("plain tcp checksum", want_csum(A, B, 6, raw + 40, 1020, 16), be16(raw + 56));

    setup(0);
    tcp6_hdr_build(hdr, A, B, 443, 40000, 1, 2, TCP_ACK, 9);
    check("plain odd write", 0, tun_write_data6(&g_dev, hdr, data, 1001, TUN6_MSS));
    drain(raw, sizeof raw, &pn);
    check("plain odd tcp checksum", want_csum(A, B, 6, raw + 40, 1021, 16), be16(raw + 56));

    setup(1);
    tcp6_hdr_build(hdr, A, B, 443, 40000, 1, 2, TCP_ACK, 9);
    check("write_data6 gso", 0, tun_write_data6(&g_dev, hdr, data, 3000, TUN6_MSS));
    check("gso one datagram", 1, drain(raw, sizeof raw, &pn));
    check("gso length", 10 + 60 + 3000, (long)pn);
    uint16_t h[4];
    memcpy(h, raw + 2, 8);
    check("vnet flags needs csum", 1, raw[0]);
    check("vnet gso type tcpv6", 4, raw[1]);
    check("vnet hdr_len", 60, h[0]);
    check("vnet gso_size", 1440, h[1]);
    check("vnet csum_start", 40, h[2]);
    check("vnet csum_offset", 16, h[3]);
    unsigned char *ip = raw + 10;
    check("gso payload length", 3020, be16(ip + 4));
    check_mem("gso data", data, ip + 60, 3000);
    uint16_t partial = fold(pseudo6(A, B, 3020, 6));
    check("gso partial checksum is the folded pseudo sum", partial, be16(ip + 56));

    setup(1);
    tcp6_hdr_build(hdr, A, B, 443, 40000, 1, 2, TCP_ACK, 9);
    check("write_data6 gso small", 0, tun_write_data6(&g_dev, hdr, data, 1440, TUN6_MSS));
    drain(raw, sizeof raw, &pn);
    check("small segment is not marked gso", 0, raw[1]);
    check("small segment still needs csum", 1, raw[0]);

    setup(1);
    tcp6_hdr_build(hdr, A, B, 443, 40000, 1, 2, TCP_ACK, 9);
    check("write_data6 gso mss 1200", 0, tun_write_data6(&g_dev, hdr, data, 3000, 1200));
    drain(raw, sizeof raw, &pn);
    memcpy(h, raw + 2, 8);
    /* catches: the v6 split taken from the constant, not the given MSS */
    check("v6 gso_size is the given mss", 1200, h[1]);
    check("v6 gso type tcpv6 at mss 1200", 4, raw[1]);

    setup(1);
    tcp6_hdr_build(hdr, A, B, 443, 40000, 1, 2, TCP_ACK, 9);
    check("write_data6 one mss of 1200", 0, tun_write_data6(&g_dev, hdr, data, 1200, 1200));
    drain(raw, sizeof raw, &pn);
    /* catches: a write of exactly one given MSS marked for splitting */
    check("v6 one segment of the given mss is not marked gso", 0, raw[1]);

    setup(1);
    tcp6_hdr_build(hdr, A, B, 443, 40000, 1, 2, TCP_ACK, 9);
    check("write_data6 1300 at mss 1200", 0, tun_write_data6(&g_dev, hdr, data, 1300, 1200));
    drain(raw, sizeof raw, &pn);
    /* catches: the split test still made against 1440 */
    check("v6 1300 bytes at mss 1200 are marked gso", 4, raw[1]);
}

static void test_data4_mss(void) {
    unsigned char hdr[TUN_HDR_LEN], data[3000], raw[4096];
    size_t pn = 0;
    uint16_t h[4];
    memset(data, 'm', sizeof data);
    setup(1);
    tcp_hdr_build(hdr, 0x0100000au, 0x0200000au, 443, 40000, 1, 2, TCP_ACK, 3000, 9, 1);
    check("write_data gso mss 1200", 0, tun_write_data(&g_dev, hdr, data, 3000, 1200));
    check("v4 gso one datagram", 1, drain(raw, sizeof raw, &pn));
    memcpy(h, raw + 2, 8);
    /* catches: the v4 split taken from the constant, not the given MSS */
    check("v4 gso_size is the given mss", 1200, h[1]);
    check("v4 gso type tcpv4", 1, raw[1]);

    setup(1);
    tcp_hdr_build(hdr, 0x0100000au, 0x0200000au, 443, 40000, 1, 2, TCP_ACK, 1200, 9, 1);
    check("write_data one mss of 1200", 0, tun_write_data(&g_dev, hdr, data, 1200, 1200));
    drain(raw, sizeof raw, &pn);
    /* catches: a write of exactly one given MSS marked for splitting */
    check("v4 one segment of the given mss is not marked gso", 0, raw[1]);

    setup(1);
    tcp_hdr_build(hdr, 0x0100000au, 0x0200000au, 443, 40000, 1, 2, TCP_ACK, 1300, 9, 1);
    check("write_data 1300 at mss 1200", 0, tun_write_data(&g_dev, hdr, data, 1300, 1200));
    drain(raw, sizeof raw, &pn);
    /* catches: the split test still made against 1460 */
    check("v4 1300 bytes at mss 1200 are marked gso", 1, raw[1]);
}

static void test_pieces(void) {
    /* catches: a piece count off by one at an exact multiple, or a split asked of one MSS */
    check("pieces 1 byte", 1, (long)tun_pieces(1, 1200));
    check("pieces one mss", 1, (long)tun_pieces(1200, 1200));
    check("pieces one mss and a byte", 2, (long)tun_pieces(1201, 1200));
    check("pieces 14600 at 1460", 10, (long)tun_pieces(14600, 1460));
    check("pieces 16384 at 1200", 14, (long)tun_pieces(16384, 1200));
    check("pieces 0 bytes", 1, (long)tun_pieces(0, 1200));
}

static void test_tcp_hdr_id(void) {
    unsigned char h[TUN_HDR_LEN];
    tcp_hdr_build(h, 0x0100000au, 0x0200000au, 443, 40000, 1, 2, TCP_ACK, 100, 9, 0xBEEF);
    /* catches: the id left at 0, written in host order, or put in after the header checksum */
    check("v4 header id", 0xBEEF, be16(h + 4));
    check("v4 header checksum covers the id", 0xFFFF, fold(words(h, 20, 0)));
    check("v4 total length", 140, be16(h + 2));
}

static void syn_opts_case(const char *name, int v6, const unsigned char *o, size_t n,
                          unsigned want_mss, unsigned want_ws, unsigned want_seen) {
    size_t hl = v6 ? 40 : 20, total = hl + 20 + n;
    unsigned char *p = calloc(1, total);
    struct flow_key k;
    size_t off = 0;
    char w[80];
    if (v6) {
        p[0] = 0x60; p[4] = (unsigned char)((20 + n) >> 8); p[5] = (unsigned char)(20 + n);
        p[6] = 6; p[7] = 64;
        memcpy(p + 8, A, 16); memcpy(p + 24, B, 16);
    } else {
        p[0] = 0x45; p[2] = (unsigned char)(total >> 8); p[3] = (unsigned char)total;
        p[8] = 64; p[9] = 6;
        p[12] = 10; p[15] = 1; p[16] = 10; p[19] = 2;
    }
    p[hl] = 0x9C; p[hl + 1] = 0x40; p[hl + 2] = 0x01; p[hl + 3] = 0xBB;
    p[hl + 12] = (unsigned char)(((20 + n) / 4) << 4);
    p[hl + 13] = TCP_SYN;
    memcpy(p + hl + 20, o, n);
    memset(&k, 0xAA, sizeof k);
    snprintf(w, sizeof w, "%s parses", name);
    check(w, 0, ip_parse(p, total, &k, &off));
    snprintf(w, sizeof w, "%s mss", name);
    check(w, (long)want_mss, k.mss);
    snprintf(w, sizeof w, "%s wscale", name);
    check(w, (long)want_ws, k.wscale);
    snprintf(w, sizeof w, "%s ws_seen", name);
    check(w, (long)want_seen, k.ws_seen);
    free(p);
}

static void test_syn_mss_read(void) {
    static const unsigned char mss_first[8] = {2, 4, 0x05, 0x14, 1, 3, 3, 7};
    static const unsigned char ws_first[8] = {1, 3, 3, 7, 2, 4, 0x05, 0x14};
    static const unsigned char no_mss[8] = {1, 3, 3, 7, 1, 1, 1, 0};
    static const unsigned char bad_len[8] = {1, 3, 3, 7, 1, 2, 3, 5};
    static const unsigned char zero_mss[4] = {2, 4, 0, 0};
    for (int v6 = 0; v6 < 2; v6++) {
        const char *t = v6 ? "v6" : "v4";
        char name[40];
        /* catches: the parse stopping at the first known option, or the MSS bytes read little-endian (0x1405 = 5125) */
        snprintf(name, sizeof name, "%s mss then scale", t);
        syn_opts_case(name, v6, mss_first, 8, 1300, 7, 1);
        snprintf(name, sizeof name, "%s scale then mss", t);
        syn_opts_case(name, v6, ws_first, 8, 1300, 7, 1);
        /* catches: a stale or defaulted MSS reported when the option is absent */
        snprintf(name, sizeof name, "%s no mss option", t);
        syn_opts_case(name, v6, no_mss, 8, 0, 7, 1);
        /* catches: a kind 2 of length 3 accepted, which reads one byte past the option and the buffer */
        snprintf(name, sizeof name, "%s kind 2 length 3 last", t);
        syn_opts_case(name, v6, bad_len, 8, 0, 7, 1);
        /* catches: an MSS option of 0 reported as present */
        snprintf(name, sizeof name, "%s mss zero", t);
        syn_opts_case(name, v6, zero_mss, 4, 0, 0, 0);
    }
}

int main(void) {
    test_parse();
    test_syn_mss_read();
    test_v4_still();
    test_tcp_hdr_id();
    test_tcp6_build();
    test_udp6();
    test_data6();
    test_data4_mss();
    test_pieces();
    return unit_done("tun6match");
}
