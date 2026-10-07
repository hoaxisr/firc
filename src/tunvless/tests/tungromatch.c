/* Coalescing adjacent segments into one device write: what is coalesced, what is not, and the
 * bytes that go out.
 *
 * Nothing looks wrong when this breaks. Coalescing too much hands the client a stream with
 * reordered or duplicated bytes, visible only in a dump. Coalescing nothing still works, only at
 * half the speed, and nothing shows it. Linux turns TCP timestamps on by default, so a rule that
 * demands TCP WITHOUT OPTIONS coalesces nothing; the first case with options below catches that.
 *
 * The device is a datagram socketpair, not a real TUN: one writev makes exactly one datagram, so
 * the test sees HOW MANY writes there were and their exact bytes. A real TUN would need root and
 * would not let us read back what we wrote. The reading end is non-blocking: a packet that is
 * missing fails a check instead of hanging the test.
 *
 * The reverse half is checked here too: splitting a coalesced frame that came FROM the kernel. It
 * fails the same way: segments handed to the data path differently from how they would arrive
 * without coalescing make a stream that cannot exist, while the tunnel is up and traffic flows.
 * Both halves are in one test on purpose: their key property is that they invert each other, and
 * that must be checked on one set of packets, not on two similar ones.
 *
 * Checksums are checked against the test's own byte-pair sum (ref_sum), not against tun.c's
 * csum_add: an oracle built from the code under test agrees with it whatever it computes.
 *
 * No crypto library and no network: tun.c touches neither, so the test includes the source
 * directly and runs in the plain `make unit-test`.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "../src/tunnel/tun.c"
#include "unit.h"

static void ok(const char *what, int good) {
    printf("%-62s %s\n", what, good ? "ok" : "FAIL");
    if (!good) unit_fail++; else unit_pass++;
}

/* ---- reference checksums (RFC 1071, one byte at a time) ---------------------- */

static uint32_t ref_sum(const unsigned char *d, size_t n, uint32_t acc) {
    for (size_t i = 0; i < n; i++) acc += (i & 1) ? d[i] : (uint32_t)d[i] << 8;
    return acc;
}

static uint16_t ref_fold(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)acc;
}

/* Pseudo-header sum of a TCP segment of tcp_n bytes, addresses from the IPv4 header ip. */
static uint32_t ref_pseudo(const unsigned char *ip, size_t tcp_n) {
    return ref_sum(ip + 12, 8, 0) + 6 + (uint32_t)tcp_n;
}

static int ref_ip_ok(const unsigned char *ip) { return ref_fold(ref_sum(ip, 20, 0)) == 0xFFFF; }

static int ref_tcp_ok(const unsigned char *ip, size_t n) {
    return ref_fold(ref_sum(ip + 20, n - 20, ref_pseudo(ip, n - 20))) == 0xFFFF;
}

/* Valid IP and TCP checksums for a packet of n bytes, as a packet from the tunnel carries. */
static void ref_fill(unsigned char *p, size_t n) {
    p[10] = p[11] = 0;
    uint16_t ick = (uint16_t)~ref_fold(ref_sum(p, 20, 0));
    p[10] = (unsigned char)(ick >> 8);
    p[11] = (unsigned char)(ick & 0xFF);
    p[36] = p[37] = 0;
    uint16_t tck = (uint16_t)~ref_fold(ref_sum(p + 20, n - 20, ref_pseudo(p, n - 20)));
    p[36] = (unsigned char)(tck >> 8);
    p[37] = (unsigned char)(tck & 0xFF);
}

/* ---- fixture ---------------------------------------------------------------- */

static int g_pair[2];
static struct tun_dev g_dev;
static struct tun_gro g_gro;

static void nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) { perror("fcntl"); exit(2); }
}

static void setup(int gso) {
    if (g_pair[0] > 0) { close(g_pair[0]); close(g_pair[1]); }
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_pair) != 0) { perror("socketpair"); exit(2); }
    int big = 1 << 20;
    setsockopt(g_pair[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
    setsockopt(g_pair[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
    nonblock(g_pair[0]);
    free(g_dev.rx);              /* split buffer: allocated on the first read */
    memset(&g_dev, 0, sizeof(g_dev));
    g_dev.fd = g_pair[0];
    g_dev.gso = gso;
    g_dev.gro = gso;
    memset(&g_gro, 0, sizeof(g_gro));
}

/* How many datagrams reached the other end; the first one is copied out. */
static int drain(unsigned char *first, size_t cap, size_t *first_n) {
    int cnt = 0;
    for (;;) {
        unsigned char buf[65536];
        ssize_t r = recv(g_pair[1], buf, sizeof(buf), MSG_DONTWAIT);
        if (r <= 0) break;
        if (cnt == 0 && first) {
            *first_n = (size_t)r > cap ? cap : (size_t)r;
            memcpy(first, buf, *first_n);
        }
        cnt++;
    }
    return cnt;
}

/* ---- building packets ------------------------------------------------------- */

#define OPT_TS 12       /* timestamp option: Linux puts it in every segment */

/* IPv4+TCP with a payload. opt_n: bytes of TCP options (0 or 12); fill: the payload byte, so the
 * payload can be recognised later. Checksums are not computed (ref_fill sets them where a case
 * needs them): coalescing recomputes them, an uncoalesced packet goes out as it is. */
static size_t mk(unsigned char *p, uint16_t sport, uint32_t seq, uint32_t ack,
                 uint16_t win, size_t pay_n, unsigned char flags, size_t opt_n,
                 unsigned char fill, unsigned char ts) {
    size_t hdr = 20 + 20 + opt_n;
    size_t tot = hdr + pay_n;
    memset(p, 0, tot);
    p[0] = 0x45;
    p[2] = (unsigned char)(tot >> 8);
    p[3] = (unsigned char)(tot & 0xFF);
    p[6] = 0x40;                              /* DF, as on any Linux segment */
    p[8] = 64;                                /* ttl */
    p[9] = 6;                                 /* TCP */
    p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 1;      /* 10.0.0.1 */
    p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 2;      /* 10.0.0.2 */
    p[20] = (unsigned char)(sport >> 8); p[21] = (unsigned char)sport;
    p[22] = 0x1F; p[23] = 0x90;               /* port 8080 */
    p[24] = (unsigned char)(seq >> 24); p[25] = (unsigned char)(seq >> 16);
    p[26] = (unsigned char)(seq >> 8);  p[27] = (unsigned char)seq;
    p[28] = (unsigned char)(ack >> 24); p[29] = (unsigned char)(ack >> 16);
    p[30] = (unsigned char)(ack >> 8);  p[31] = (unsigned char)ack;
    p[32] = (unsigned char)(((20 + opt_n) / 4) << 4);
    p[33] = flags;
    p[34] = (unsigned char)(win >> 8); p[35] = (unsigned char)win;
    if (opt_n == OPT_TS) {
        p[40] = 1; p[41] = 1;                 /* NOP NOP */
        p[42] = 8; p[43] = 10;                /* timestamp, length 10 */
        p[44] = ts;                           /* TSval: tells "same options" apart */
    }
    memset(p + hdr, fill, pay_n);
    return tot;
}

/* Offload (virtio) header fields of the first datagram. */
struct vh_read { unsigned char flags, gso_type; uint16_t hdr_len, gso_size, cs_start, cs_off; };
static void vh_of(const unsigned char *d, struct vh_read *v) {
    struct vnet_hdr h;
    memcpy(&h, d, sizeof(h));
    v->flags = h.flags; v->gso_type = h.gso_type;
    v->hdr_len = h.hdr_len; v->gso_size = h.gso_size;
    v->cs_start = h.csum_start; v->cs_off = h.csum_offset;
}

/* Two segments pushed one after the other on an offload device: how many writes. The packets are
 * copied first, since coalescing edits the first one in place. */
static int pair_writes(const unsigned char *a, size_t na, const unsigned char *b, size_t nb) {
    static unsigned char pa[2048], pb[2048];
    memcpy(pa, a, na);
    memcpy(pb, b, nb);
    setup(1);
    tun_gro_push(&g_dev, &g_gro, pa, na);
    tun_gro_push(&g_dev, &g_gro, pb, nb);
    tun_gro_flush(&g_dev, &g_gro);
    return drain(NULL, 0, NULL);
}

/* Splitting a coalesced frame that came FROM the kernel. hint_full_first = 1: hdr_len holds the
 * length of the WHOLE first packet (as for a forwarded coalesced frame: skb_headlen is the linear
 * part, not the headers); 0: exactly the header length, as for a packet of a local socket.
 * last_fl: the flags of the last segment, which the super-frame carries; the others have ACK
 * only. ecn: the ECN bit the kernel may add to gso_type. */
static void superframe_case(const char *name, int hint_full_first, unsigned char last_fl,
                            unsigned char ecn) {
    setup(1);
    g_dev.rx_gso = 1;
    const size_t gso = 1400;
    size_t sizes[5] = { gso, gso, gso, gso, 617 };
    static unsigned char want[5][2048];
    size_t want_n[5];
    uint32_t seq = 0x1000;
    for (int i = 0; i < 5; i++) {
        unsigned char fl = (i == 4) ? last_fl : 0x10;
        want_n[i] = mk(want[i], 40000, seq, 0x9000, 64000, sizes[i], fl, OPT_TS, 0xA0 + i, 7);
        /* Splitting increments the IP id per segment. */
        want[i][4] = (unsigned char)(100 >> 8);
        want[i][5] = (unsigned char)(100 + i);
        /* Real checksums: the splitter recomputes them, so compare against correct ones. */
        ref_fill(want[i], want_n[i]);
        seq += (uint32_t)sizes[i];
    }
    /* The super-frame as the kernel hands it over: the first segment's header, all payload in a
     * row, the last segment's flags, the IP length of the whole frame, TCP checksum left to the
     * device. */
    static unsigned char frame[VNET_HDR_LEN + 16384];
    size_t hdr_n = 20 + 20 + OPT_TS;
    memset(frame, 0, sizeof(frame));
    memcpy(frame + VNET_HDR_LEN, want[0], hdr_n);
    size_t off = hdr_n;
    size_t body = 0;
    for (int i = 0; i < 5; i++) {
        memcpy(frame + VNET_HDR_LEN + off, want[i] + hdr_n, sizes[i]);
        off += sizes[i];
        body += sizes[i];
    }
    unsigned char *pkt = frame + VNET_HDR_LEN;
    pkt[33] = last_fl;                       /* PSH and FIN collected, as the kernel does */
    size_t tot = hdr_n + body;
    pkt[2] = (unsigned char)(tot >> 8);
    pkt[3] = (unsigned char)(tot & 0xFF);
    pkt[10] = pkt[11] = 0;
    uint16_t ick = (uint16_t)~ref_fold(ref_sum(pkt, 20, 0));
    pkt[10] = (unsigned char)(ick >> 8);
    pkt[11] = (unsigned char)(ick & 0xFF);
    struct vnet_hdr vh;
    memset(&vh, 0, sizeof(vh));
    vh.flags = VNET_F_NEEDS_CSUM;
    vh.gso_type = (uint8_t)(VNET_GSO_TCPV4 | ecn);
    vh.hdr_len = (uint16_t)(hint_full_first ? hdr_n + sizes[0] : hdr_n);
    vh.gso_size = (uint16_t)gso;
    vh.csum_start = 20;
    vh.csum_offset = 16;
    memcpy(frame, &vh, sizeof(vh));
    if (send(g_pair[1], frame, VNET_HDR_LEN + tot, 0) < 0) { perror("send"); exit(2); }

    int same = 1, count = 0;
    for (int i = 0; i < 6; i++) {
        unsigned char got[2048];
        ssize_t r = tun_read_packet(&g_dev, got, sizeof(got));
        if (r <= 0) break;
        count++;
        if (i >= 5 || (size_t)r != want_n[i] || memcmp(got, want[i], (size_t)r) != 0) {
            same = 0;
            printf("     segment %d differs: %zd bytes vs %zu\n", i, r, i < 5 ? want_n[i] : 0);
            for (size_t k = 0; i < 5 && k < (size_t)r && k < want_n[i]; k++)
                if (got[k] != want[i][k]) { printf("     first diff at byte %zu\n", k); break; }
        }
    }
    char what[96];
    snprintf(what, sizeof(what), "%s: packets handed out", name);
    check(what, 5, count);
    snprintf(what, sizeof(what), "%s: packets same as without coalescing", name);
    check(what, 1, same && count == 5);
    snprintf(what, sizeof(what), "%s: nothing dropped", name);
    check(what, 0, (long)g_dev.rx_dropped);
}

/* A PARTIAL checksum on a SINGLE packet: the kernel hands over packets of its own sockets this
 * way, leaving the checksum to the device. Sent into the tunnel as is, such a packet is dropped
 * silently by the other side's stack. carry: the first payload word is chosen so that the raw sum
 * of the segment ends in 0xFFFF above 0x10000; folding it once carries again, and a fold done
 * only once gives a checksum off by one. */
static void partial_case(const char *name, size_t pay_n, int carry) {
    setup(1);
    g_dev.rx_gso = 1;
    unsigned char p[512];
    size_t n = mk(p, 40002, 0x8000, 0x1000, 60000, pay_n, 0x18, 0, 0xC0, 0);
    ref_fill(p, n);
    /* The field holds the PSEUDO-HEADER sum, the body is not summed: as the kernel does it.
     * The folded sum goes in WITHOUT the complement: that is what the device completes and what
     * the kernel puts there. The complemented one would test the wrong input, and the failure
     * would be blamed on the code. */
    uint16_t part = ref_fold(ref_pseudo(p, n - 20));
    p[36] = (unsigned char)(part >> 8);
    p[37] = (unsigned char)(part & 0xFF);
    if (carry) {
        p[40] = p[41] = 0;
        uint32_t sum = ref_sum(p + 20, n - 20, 0);
        uint32_t w = (sum | 0xFFFF) - sum;
        p[40] = (unsigned char)(w >> 8);
        p[41] = (unsigned char)(w & 0xFF);
    }
    unsigned char frame[VNET_HDR_LEN + 512];
    struct vnet_hdr vh;
    memset(&vh, 0, sizeof(vh));
    vh.flags = VNET_F_NEEDS_CSUM;
    vh.gso_type = VNET_GSO_NONE;
    vh.csum_start = 20;
    vh.csum_offset = 16;
    memcpy(frame, &vh, sizeof(vh));
    memcpy(frame + VNET_HDR_LEN, p, n);
    if (send(g_pair[1], frame, VNET_HDR_LEN + n, 0) < 0) { perror("send"); exit(2); }
    unsigned char got[512];
    ssize_t r = tun_read_packet(&g_dev, got, sizeof(got));
    char what[96];
    snprintf(what, sizeof(what), "%s: packet handed out whole", name);
    check(what, (long)n, (long)r);
    snprintf(what, sizeof(what), "%s: completed to a valid one", name);
    check(what, 1, r > 20 && ref_tcp_ok(got, (size_t)r));
}

/* TSO as the kernel reports it for the device (ethtool): on once TUNSETOFFLOAD took
 * TUN_F_TSO4. -1 if it cannot be read. */
static int dev_tso(const char *name) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ethtool_value ev = { .cmd = ETHTOOL_GTSO };
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_data = (void *)&ev;
    int r = ioctl(s, SIOCETHTOOL, &ifr);
    close(s);
    return r == 0 ? (int)ev.data : -1;
}

/* Whether this machine can create a TUN device at all, asked without tun_open: a probe through
 * tun_open would turn any bug that makes it fail into a skip. */
static int tun_available(void) {
    int fd = open(TUN_DEV, O_RDWR);
    if (fd < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", "xs-rxgso-probe");
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    int ok = ioctl(fd, TUNSETIFF, &ifr) == 0;
    close(fd);
    return ok;
}

int main(void) {
    unsigned char a[2048], b[2048], c[2048];
    unsigned char got[65536];
    size_t got_n = 0;
    const size_t SEG = 1400;

    /* ---- TWO ADJACENT SEGMENTS WITHOUT OPTIONS: one write -----------------------
     * With valid checksums, as packets from the tunnel come: the coalesced header must not
     * inherit anything from them. */
    setup(1);
    size_t na = mk(a, 1234, 1000, 77, 501, SEG, 0x10, 0, 0xA0, 0);
    size_t nb = mk(b, 1234, 1000 + SEG, 77, 501, SEG, 0x10, 0, 0xB0, 0);
    ref_fill(a, na);
    ref_fill(b, nb);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("two segments went out in ONE write", 1, drain(got, sizeof(got), &got_n));
    check("write length: offload header, packet header, two payloads",
          (long)(VNET_HDR_LEN + 40 + 2 * SEG), (long)got_n);
    {
        struct vh_read v;
        vh_of(got, &v);
        check("gso_type: split mark TCPV4", VNET_GSO_TCPV4, v.gso_type);
        check("gso_size: payload of the first packet", (long)SEG, v.gso_size);
        check("hdr_len: IP and TCP headers", 40, v.hdr_len);
        check("flags: checksum left to the kernel", VNET_F_NEEDS_CSUM, v.flags);
        check("csum_start: start of TCP", 20, v.cs_start);
        check("csum_offset: checksum field within TCP", 16, v.cs_off);
        const unsigned char *ip = got + VNET_HDR_LEN;
        check("IP total length rewritten to the whole coalesced frame",
              (long)(40 + 2 * SEG), (long)(((size_t)ip[2] << 8) | ip[3]));
        ok("IP checksum recomputed and valid", ref_ip_ok(ip));
        ok("payloads in the order sent",
           ip[40] == 0xA0 && ip[40 + SEG - 1] == 0xA0 &&
           ip[40 + SEG] == 0xB0 && ip[40 + 2 * SEG - 1] == 0xB0);
        /* The TCP checksum must be PARTIAL: only the pseudo-header, with the length of the
         * WHOLE coalesced frame, folded and not inverted. Inverted once too often, it fails on
         * every piece, and that looks like "packets go out, the client does not see them". */
        long want = ref_fold(ref_pseudo(ip, 20 + 2 * SEG));
        check("TCP checksum: pseudo-header with the full length",
              want, (long)(((uint16_t)ip[36] << 8) | ip[37]));
    }

    /* ---- WITH OPTIONS (timestamps): coalesced too ---------------------------------
     * The common case: an ordinary Linux segment has a 32-byte TCP header, not 20. */
    setup(1);
    na = mk(a, 1234, 2000, 77, 501, SEG, 0x10, OPT_TS, 0xA1, 9);
    nb = mk(b, 1234, 2000 + SEG, 77, 501, SEG, 0x10, OPT_TS, 0xB1, 9);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("segments with timestamps coalesced", 1, drain(got, sizeof(got), &got_n));
    {
        struct vh_read v;
        vh_of(got, &v);
        check("hdr_len includes the options", 52, v.hdr_len);
        check("write length counts the options once",
              (long)(VNET_HDR_LEN + 52 + 2 * SEG), (long)got_n);
    }

    /* Different option bytes are not coalesced: the kernel splits by copying the FIRST packet's
     * options into every piece. */
    na = mk(a, 1234, 3000, 77, 501, SEG, 0x10, OPT_TS, 0xA2, 1);
    nb = mk(b, 1234, 3000 + SEG, 77, 501, SEG, 0x10, OPT_TS, 0xB2, 2);
    check("different timestamps: two writes", 2, pair_writes(a, na, b, nb));

    /* ---- what must NOT be coalesced ---------------------------------------------
     * Each case changes ONE thing in the second of two segments that otherwise coalesce (the
     * control): whatever else is equal, that one difference must keep them apart. */
    na = mk(a, 1234, 4000, 77, 501, SEG, 0x10, 0, 0xA3, 0);
    nb = mk(b, 1234, 4000 + SEG + 1, 77, 501, SEG, 0x10, 0, 0xB3, 0);   /* sequence gap */
    check("sequence gap: two writes", 2, pair_writes(a, na, b, nb));
    {
        static const struct { const char *what; int at; unsigned char val; } var[] = {
            { "another flow: two writes",                      20, 0x55 },   /* source port */
            { "another destination port: two writes",          22, 0x55 },
            { "another source address: two writes",            15, 9 },
            { "another destination address: two writes",       19, 9 },
            { "window changed: two writes",                    35, 0x99 },
            { "ack changed: two writes",                       31, 88 },
            { "ttl changed: two writes",                        8, 63 },
            { "tos changed: two writes",                        1, 0x10 },
            { "fragment (more fragments follow): two writes",   6, 0x20 },
            { "not TCP: two writes",                            9, 17 },
            { "SYN on the second: two writes",                 33, 0x12 },
            { "FIN on the second: two writes",                 33, 0x11 },
            { "RST on the second: two writes",                 33, 0x14 },
            { "URG on the second: two writes",                 33, 0x30 },
            { "second without ACK: two writes",                33, 0x08 },
        };
        na = mk(a, 1234, 5000, 77, 501, SEG, 0x10, 0, 0xA4, 0);
        nb = mk(b, 1234, 5000 + SEG, 77, 501, SEG, 0x10, 0, 0xB4, 0);
        check("control: the same two segments unchanged: one write", 1,
              pair_writes(a, na, b, nb));
        for (size_t i = 0; i < sizeof(var) / sizeof(var[0]); i++) {
            memcpy(c, b, nb);
            c[var[i].at] = var[i].val;
            check(var[i].what, 2, pair_writes(a, na, c, nb));
        }
    }

    /* A SYN starts a connection and goes out on its own, as it is: the segment after it is not
     * coalesced with it, and the SYN carries no split mark and asks for no checksum. */
    setup(1);
    na = mk(a, 1234, 8000, 77, 501, SEG, 0x12, 0, 0xA7, 0);             /* SYN|ACK */
    nb = mk(b, 1234, 8000 + SEG, 77, 501, SEG, 0x10, 0, 0xB7, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("SYN goes out on its own: two writes", 2, drain(got, sizeof(got), &got_n));
    {
        struct vh_read v;
        vh_of(got, &v);
        check("and WITHOUT the split mark", VNET_GSO_NONE, v.gso_type);
        check("and without asking for a checksum", 0, v.flags);
    }

    /* Two bare ACKs alike (a duplicate ACK): nothing to coalesce, a write each. Coalesced, they
     * would make a frame with gso_size 0, which the kernel drops with both ACKs in it. */
    na = mk(a, 1234, 9000, 77, 501, 0, 0x10, 0, 0xA8, 0);
    check("bare ACKs: a write each", 2, pair_writes(a, na, a, na));

    /* ---- PSH and a short piece close the batch at once ---------------------------- */
    setup(1);
    na = mk(a, 1234, 10000, 77, 501, SEG, 0x10, 0, 0xAA, 0);
    nb = mk(b, 1234, 10000 + SEG, 77, 501, SEG, 0x18, 0, 0xBA, 0);      /* ACK|PSH */
    size_t nc = mk(c, 1234, 10000 + 2 * SEG, 77, 501, SEG, 0x10, 0, 0xCA, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    check("PSH closed the batch: written before the next push", 1,
          drain(got, sizeof(got), &got_n));
    check("first write: both segments, up to and including PSH",
          (long)(VNET_HDR_LEN + 40 + 2 * SEG), (long)got_n);
    check("first write: PSH in its header, for the last piece", 0x18,
          got[VNET_HDR_LEN + 33]);
    tun_gro_push(&g_dev, &g_gro, c, nc);
    tun_gro_flush(&g_dev, &g_gro);
    ok("the segment after PSH: a write of its own, with it alone",
       drain(got, sizeof(got), &got_n) == 1 && got_n == VNET_HDR_LEN + nc);

    /* PSH on the very first packet: no batch, it goes out at once and as it is. */
    setup(1);
    na = mk(a, 1234, 10500, 77, 501, SEG, 0x18, 0, 0xAE, 0);
    nb = mk(b, 1234, 10500 + SEG, 77, 501, SEG, 0x10, 0, 0xBE, 0);
    ref_fill(a, na);
    memcpy(c, a, na);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("PSH on the first packet: two writes", 2, drain(got, sizeof(got), &got_n));
    ok("first write: that packet as it is, without the split mark",
       got_n == VNET_HDR_LEN + na && got[1] == VNET_GSO_NONE &&
       memcmp(got + VNET_HDR_LEN, c, na) == 0);

    setup(1);
    na = mk(a, 1234, 11000, 77, 501, SEG, 0x10, 0, 0xAB, 0);
    nb = mk(b, 1234, 11000 + SEG, 77, 501, 200, 0x10, 0, 0xBB, 0);      /* short */
    nc = mk(c, 1234, 11000 + SEG + 200, 77, 501, SEG, 0x10, 0, 0xCB, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    check("short piece closed the batch: written before the next push", 1,
          drain(got, sizeof(got), &got_n));
    check("first write: the full piece and the short one",
          (long)(VNET_HDR_LEN + 40 + SEG + 200), (long)got_n);
    {
        struct vh_read v;
        vh_of(got, &v);
        check("first write: gso_size of the full piece, not the short", (long)SEG, v.gso_size);
    }
    tun_gro_push(&g_dev, &g_gro, c, nc);
    tun_gro_flush(&g_dev, &g_gro);
    ok("the piece after the short one: a write of its own, with it alone",
       drain(got, sizeof(got), &got_n) == 1 && got_n == VNET_HDR_LEN + nc);

    /* A piece LONGER than the first must not be coalesced: splitting would not give it back. */
    na = mk(a, 1234, 12000, 77, 501, 500, 0x10, 0, 0xAC, 0);
    nb = mk(b, 1234, 12000 + 500, 77, 501, SEG, 0x10, 0, 0xBC, 0);
    check("piece longer than the first: two writes", 2, pair_writes(a, na, b, nb));

    /* ---- frame limit -------------------------------------------------------------
     * There are vectors for exactly as many frames as the sender puts in a record; the ninth
     * must start a new batch, not get lost. */
    setup(1);
    {
        static unsigned char many[TUN_GRO_FRAMES + 2][2048];
        int total = TUN_GRO_FRAMES + 1;
        uint32_t seq = 20000;
        for (int i = 0; i < total; i++) {
            size_t nn = mk(many[i], 1234, seq, 77, 501, SEG, 0x10, 0,
                           (unsigned char)(0x50 + i), 0);
            seq += (uint32_t)SEG;
            tun_gro_push(&g_dev, &g_gro, many[i], nn);
        }
        tun_gro_flush(&g_dev, &g_gro);
        check("ninth frame started a new batch, not lost", 2,
              drain(got, sizeof(got), &got_n));
        check("first write: exactly eight frames",
              (long)(VNET_HDR_LEN + 40 + TUN_GRO_FRAMES * SEG), (long)got_n);
    }

    /* ---- no offload, no coalescing ---------------------------------------------- */
    setup(0);
    na = mk(a, 1234, 30000, 77, 501, SEG, 0x10, 0, 0xAD, 0);
    nb = mk(b, 1234, 30000 + SEG, 77, 501, SEG, 0x10, 0, 0xBD, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("device without offload: one write per packet", 2,
          drain(got, sizeof(got), &got_n));
    check("and no offload header in them", (long)(40 + SEG), (long)got_n);

    /* Coalescing switched off on a device WITH offload (gro = 0, STEER_TUN_NOGRO): one write per
     * packet, each still with its offload header. */
    setup(1);
    g_dev.gro = 0;
    na = mk(a, 1234, 31000, 77, 501, SEG, 0x10, 0, 0xAF, 0);
    nb = mk(b, 1234, 31000 + SEG, 77, 501, SEG, 0x10, 0, 0xBF, 0);
    tun_gro_push(&g_dev, &g_gro, a, na);
    tun_gro_push(&g_dev, &g_gro, b, nb);
    tun_gro_flush(&g_dev, &g_gro);
    check("coalescing off (gro 0): one write per packet", 2, drain(got, sizeof(got), &got_n));
    check("and the offload header in them", (long)(VNET_HDR_LEN + 40 + SEG), (long)got_n);

    /* ---- reverse half: splitting a coalesced frame that came FROM the kernel -----
     *
     * KEY PROPERTY: the packets split from a super-frame must be BYTE FOR BYTE those that would
     * have come without coalescing. Otherwise the other side's stack sees a stream that cannot
     * exist, the hardest kind of failure to catch: tunnel up, traffic flowing, some connections
     * stalling.
     *
     * The set: four full-size segments and a short tail (an odd length: the checksum's last
     * byte counts), PSH on the last, the IP id growing per segment, the same timestamp on all
     * (splitting copies the whole header). */
    superframe_case("super-frame split", 0, 0x18, 0);
    /* The same frame with hdr_len = length of the whole first packet: it must not be dropped. */
    superframe_case("hdr_len = whole first packet", 1, 0x18, 0);
    /* FIN goes only to the last piece, like PSH: on every piece it would close the connection
     * after the first. */
    superframe_case("FIN on the last segment", 0, 0x19, 0);
    /* The ECN bit in gso_type does not change splitting. */
    superframe_case("gso_type with the ECN bit", 0, 0x18, VNET_GSO_ECN);

    /* Round trip: coalescing and splitting invert each other. Both halves on one set: packets go
     * into the device one by one, leave as one frame, are split back and must match byte for
     * byte (except the checksums: coalescing leaves them to the device, splitting recomputes). */
    {
        setup(1);
        static unsigned char pkts[4][2048], orig[4][2048];
        size_t pn[4];
        uint32_t seq = 0x5000;
        for (int i = 0; i < 4; i++) {
            pn[i] = mk(pkts[i], 40001, seq, 0x7000, 63000, 1200, i == 3 ? 0x18 : 0x10,
                       OPT_TS, 0xB0 + i, 9);
            seq += 1200;
        }
        /* SNAPSHOT BEFORE COALESCING: it edits the first packet's header IN PLACE (frame length,
         * partial checksum, collected PSH) by design, with no copy. Comparing the split packets
         * with the edited originals would compare against the wrong thing. */
        for (int i = 0; i < 4; i++) memcpy(orig[i], pkts[i], pn[i]);
        for (int i = 0; i < 4; i++) tun_gro_push(&g_dev, &g_gro, pkts[i], pn[i]);
        tun_gro_flush(&g_dev, &g_gro);
        unsigned char frame[65536];
        size_t fn = 0;
        int cnt = 0;
        for (;;) {
            ssize_t r = recv(g_pair[1], frame, sizeof(frame), MSG_DONTWAIT);
            if (r <= 0) break;
            fn = (size_t)r;
            cnt++;
        }
        check("round trip: coalesced into one frame", 1, cnt);
        /* The same frame back into the splitter, on another device: the first has its own state. */
        struct tun_dev in;
        memset(&in, 0, sizeof(in));
        int pr[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pr) != 0) { perror("socketpair"); exit(2); }
        int big = 1 << 20;
        setsockopt(pr[1], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
        nonblock(pr[0]);
        in.fd = pr[0];
        in.gso = 1;
        in.rx_gso = 1;
        if (send(pr[1], frame, fn, 0) < 0) { perror("send"); exit(2); }
        int back = 0, same = 1;
        for (int i = 0; i < 4; i++) {
            unsigned char got[2048];
            ssize_t r = tun_read_packet(&in, got, sizeof(got));
            if (r <= 0) break;
            back++;
            unsigned char a[2048], b[2048];
            memcpy(a, got, (size_t)r);
            memcpy(b, orig[i], pn[i]);
            /* Mask what coalescing and splitting may change: both checksums and the IP ID.
             * Splitting increments the ID per segment, as the kernel's inet_gso_segment does,
             * while the originals all carry one value. The checksums need not equal the
             * originals, but they must be VALID, which is checked below. */
            a[4] = a[5] = b[4] = b[5] = 0;
            a[10] = a[11] = b[10] = b[11] = 0;
            a[36] = a[37] = b[36] = b[37] = 0;
            if ((size_t)r != pn[i] || memcmp(a, b, (size_t)r) != 0) {
                same = 0;
                printf("     round trip: segment %d differs (%zd vs %zu)\n", i, r, pn[i]);
                for (size_t k = 0; k < (size_t)r; k++)
                    if (a[k] != b[k]) {
                        printf("       byte %zu: %02x vs %02x\n", k, a[k], b[k]);
                        break;
                    }
            }
            if (!ref_ip_ok(got) || !ref_tcp_ok(got, (size_t)r)) {
                same = 0;
                printf("     round trip: segment %d: checksum invalid\n", i);
            }
        }
        check("round trip: as many packets split back", 4, back);
        check("round trip: packets match, checksums valid", 1, same);
        close(pr[0]); close(pr[1]);
        free(in.rx);
    }

    /* A partial checksum on a SINGLE packet: 103 bytes of payload make a segment of 4n+3 bytes,
     * so the odd last byte and a pair after the last 4-byte word count too. */
    partial_case("partial checksum", 103, 0);
    partial_case("partial checksum, a sum that carries twice", 102, 1);

    /* ---- live check: the kernel agrees to hand over coalesced frames --------------
     *
     * The vectors above check the splitting arithmetic, not whether the kernel AGREES to hand
     * coalesced frames over: TUNSETOFFLOAD may fail (old kernel, a build without TUN_F_TSO), and
     * then rx_gso stays zero and packets are read one at a time. Only a real device can check
     * that, so root is needed; without it the block says it is skipped, as tunnamematch does. */
    if (!tun_available()) {
        printf("%-62s skipped (needs root and /dev/net/tun)\n", "live: kernel receive offload");
    } else {
        /* The array is filled with garbage ON PURPOSE, not zeroed: the caller declares it on the
         * stack without initialisation (`struct tun_dev queues[MAX_WORKERS];` in stack.c), so
         * tun_open itself must zero the fields. Stack garbage left in the split-buffer pointer or
         * the segment counters sends splitting through a random address, and whether that
         * crashes depends on compiler flags: at -O0 the garbage tends to be zeros, with LTO it is
         * not. Garbage put there on purpose is the only reliable way to catch it. */
        struct tun_dev d[2];
        memset(d, 0xAA, sizeof(d));
        int n = tun_open(d, 1, "xs-rxgso");
        check("live: device opened", 1, n >= 1);
        if (n >= 1) {
            /* With the offload header as the kernel has it, not only as tun_open says. */
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            int vnet = ioctl(d[0].fd, TUNGETIFF, &ifr) == 0 && (ifr.ifr_flags & IFF_VNET_HDR);
            check("live: device opened with offload", 1, d[0].gso && vnet);
            check("live: split buffer pointer not left as garbage", 1, d[0].rx == NULL);
            check("live: no pending single packet", 0, (long)d[0].single);
            check("live: no pending segments", 0, (long)(d[0].seg_i + d[0].seg_n));
            check("live: dropped counter zero", 0, (long)d[0].rx_dropped);
            /* Without the offload header (failed just above) there is nothing to ask for. */
            if (d[0].gso) {
                check("live: kernel agreed to hand over coalesced frames", 1,
                      dev_tso("xs-rxgso") == 1);
                check("live: and tun_open knows it (rx_gso)", 1, d[0].rx_gso != 0);
                if (!d[0].rx_gso)
                    printf("     TUNSETOFFLOAD failed: packets are read one at a time\n");
            }
            /* Do NOT read here: the device descriptor is blocking (poll in the data loop does
             * the waiting), and reading an empty device would hang forever. What splitting
             * does with what it reads is checked by the vectors above, with no real device.
             * Nothing was read, so there is no split buffer to free (rx is checked NULL). */
            close(d[0].fd);
        }
    }

    free(g_dev.rx);
    return unit_done("tungromatch");
}
