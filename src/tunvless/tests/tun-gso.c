/* TUN write offload: does the data arrive, and do the checksums add up.
 *
 * With offload the check field holds an UNFINISHED sum — the pseudo header only — and the kernel
 * is trusted to finish it while segmenting. That is a contract, not observable behaviour: get one
 * length term wrong and packets still go out while the receiver silently drops them, which on a
 * router looks just like "no speedup".
 *
 * Local delivery CANNOT check this: a CHECKSUM_PARTIAL packet delivered to a socket on the same
 * machine skips checksum verification (skb_csum_unnecessary trusts it), so the test would pass
 * with any sum.
 *
 * So the test writes to one device and reads from ANOTHER, making the kernel route the packet
 * between them. On the way out the kernel must both segment and finish the sums, so the test
 * reads exactly what a client would see and checks the sums itself.
 *
 * Run in a network namespace of its own (tests/run-tun-gso.sh): the test brings up devices,
 * enables forwarding and turns off reverse path filtering.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>

#include "../src/tunnel/tun.h"

#define PAYLOAD_N 16000
#define QUEUES 4

static int sh(const char *cmd) {
    int rc = system(cmd);
    if (rc != 0) fprintf(stderr, "failed: %s\n", cmd);
    return rc;
}

/* RFC 1071 sum: a copy of its own, so the test does not depend on the code it checks. */
static uint16_t csum(const unsigned char *d, size_t n, uint32_t acc) {
    for (size_t i = 0; i + 1 < n; i += 2) acc += ((uint32_t)d[i] << 8) | d[i + 1];
    if (n & 1) acc += (uint32_t)d[n - 1] << 8;
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)~acc;
}

int main(void) {
    struct tun_dev in, outq[QUEUES];
    if (tun_open(&in, 1, "tgin") < 0) { fprintf(stderr, "cannot open tgin\n"); return 2; }
    /* The receiving side opens SEVERAL queues to check what all the multithreading relies on:
     * the kernel puts a whole flow into one queue. */
    int nq = tun_open(outq, QUEUES, "tgout");
    if (nq < 0) { fprintf(stderr, "cannot open tgout\n"); return 2; }
    struct tun_dev out = outq[0];
    printf("offload: tgin=%d tgout=%d; tgout queues: %d of %d\n",
           in.gso, out.gso, nq, QUEUES);

    if (sh("ip addr add 10.77.0.1/24 dev tgin && ip link set tgin up") ||
        sh("ip addr add 10.88.0.1/24 dev tgout && ip link set tgout up") ||
        sh("sysctl -qw net.ipv4.ip_forward=1") ||
        sh("sysctl -qw net.ipv4.conf.all.rp_filter=0") ||
        sh("sysctl -qw net.ipv4.conf.tgin.rp_filter=0") ||
        /* There is no neighbour 10.88.0.2 on a point-to-point device, but the kernel still
         * looks for one. Set it by hand, or the packet waits for ARP. */
        sh("ip neigh replace 10.88.0.2 dev tgout lladdr 00:00:00:00:00:00 nud permanent"))
        return 2;

    /* Drain what the kernel put into tgout before our write (announcements and other noise),
     * or it would be checked and look like a broken segment. */
    unsigned char junk[65536];
    for (int q = 0; q < nq; q++) {
        int fl = fcntl(outq[q].fd, F_GETFL, 0);
        fcntl(outq[q].fd, F_SETFL, fl | O_NONBLOCK);
        while (tun_read_packet(&outq[q], junk, sizeof(junk)) > 0) { }
    }

    static unsigned char payload[PAYLOAD_N];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (unsigned char)(i * 31 + 7);

    uint32_t src, dst;
    inet_pton(AF_INET, "10.77.0.2", &src);
    inet_pton(AF_INET, "10.88.0.2", &dst);

    /* The same cut as emit_to_client: with offload the whole write at once, without it by MSS.
     * 16 KB in one packet WITHOUT offload is wrong: the kernel accepts it and cuts it into IP
     * fragments, not TCP segments (11 fragments, only the first with a TCP header). */
    size_t seg = in.gso ? (size_t)TUN_GSO_MAX : (size_t)TUN_MSS;
    for (size_t sent = 0; sent < sizeof(payload); ) {
        size_t chunk = sizeof(payload) - sent > seg ? seg : sizeof(payload) - sent;
        unsigned char hdr[TUN_HDR_LEN];
        tcp_hdr_build(hdr, src, dst, 12345, 9999, (uint32_t)(1000 + sent), 2000,
                      TCP_ACK | TCP_PSH, chunk, 65535);
        if (tun_write_data(&in, hdr, payload + sent, chunk) != 0) {
            fprintf(stderr, "write failed: %s\n", strerror(errno));
            return 2;
        }
        sent += chunk;
    }

    size_t got = 0, segs = 0, bad_ip = 0, bad_tcp = 0, bad_data = 0;
    size_t per_queue[QUEUES] = {0};
    for (int idle = 0; idle < 200 && got < sizeof(payload); ) {
        unsigned char pkt[65536];
        ssize_t n = -1;
        int from = -1;
        for (int q = 0; q < nq; q++) {
            n = tun_read_packet(&outq[q], pkt, sizeof(pkt));
            if (n > 0) { from = q; break; }
        }
        if (n <= 0) {
            struct pollfd p[QUEUES];
            for (int q = 0; q < nq; q++) { p[q].fd = outq[q].fd; p[q].events = POLLIN; }
            poll(p, (unsigned)nq, 10);
            idle++;
            continue;
        }
        idle = 0;
        per_queue[from]++;
        if (n < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6) continue;
        size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
        size_t doff = (size_t)(pkt[ihl + 12] >> 4) * 4;
        size_t dn = (size_t)n - ihl - doff;

        if (csum(pkt, ihl, 0) != 0) bad_ip++;

        unsigned char pseudo[12];
        memcpy(pseudo, pkt + 12, 4);
        memcpy(pseudo + 4, pkt + 16, 4);
        pseudo[8] = 0; pseudo[9] = 6;
        uint16_t tlen = (uint16_t)(doff + dn);
        pseudo[10] = (unsigned char)(tlen >> 8); pseudo[11] = (unsigned char)tlen;
        uint32_t acc = 0;
        for (int i = 0; i < 12; i += 2) acc += ((uint32_t)pseudo[i] << 8) | pseudo[i + 1];
        if (csum(pkt + ihl, doff + dn, acc) != 0) bad_tcp++;

        uint32_t seq = ((uint32_t)pkt[ihl + 4] << 24) | ((uint32_t)pkt[ihl + 5] << 16) |
                       ((uint32_t)pkt[ihl + 6] << 8) | pkt[ihl + 7];
        size_t off = seq - 1000;
        if (off + dn > sizeof(payload) ||
            memcmp(pkt + ihl + doff, payload + off, dn) != 0) bad_data++;
        got += dn;
        segs++;
    }

    printf("segments %zu, bytes %zu of %zu; bad IP sums %zu, bad TCP sums %zu, data "
           "mismatches %zu\n", segs, got, sizeof(payload), bad_ip, bad_tcp, bad_data);

    /* The whole flow must be in ONE queue. Spread over several, the connection would be served
     * by different threads, each with its own table: two independent states of one TCP
     * connection, silent corruption instead of an error. */
    int used = 0, spread = 0;
    for (int q = 0; q < nq; q++) {
        if (!per_queue[q]) continue;
        used++;
        printf("  queue %d: %zu packets\n", q, per_queue[q]);
    }
    if (nq > 1 && used != 1) { printf("FAIL: the flow spread over %d queues\n", used); spread = 1; }
    if (nq == 1) printf("  (kernel without IFF_MULTI_QUEUE: queue affinity not checked)\n");

    int ok = got == sizeof(payload) && !bad_ip && !bad_tcp && !bad_data && !spread;
    printf("%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
