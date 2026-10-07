/* Client for end-to-end checks against a real Xray-core (tests/venc.sh): the node is a vless://
 * link, everything else is as in production (vless_connect → transport_open → tr_venc_open),
 * only without TUN.
 *
 *   vencprobe probe URL N        N probes in a row in one process (vless_probe: a request to
 *                                1.1.1.1:80 through the node; the server needs network access);
 *   vencprobe bulk  URL PORT MB [N]  MB of data there and back through an echo server at
 *                                127.0.0.1:PORT behind the node, writes of random length
 *                                (1..20000), compared byte by byte; N connections in a row in one
 *                                process (default one).
 *
 * Exit code 0 — all probes passed / the data matched. Prints the reason of every failure. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

#include "vless.h"
#include "client.h"
#include "vless_proto.h"
#include "transport.h"

static int cmd_probe(const char *url, int n_probes) {
    struct vless_node n;
    int rc = vless_parse_url(url, &n);
    if (rc) { printf("node unusable (rc=%d): %s\n", rc, n.skip_reason); return 2; }
    int bad = 0;
    for (int i = 0; i < n_probes; i++) {
        char why[160] = "";
        int r = vless_probe(&n, 10, why, sizeof why);
        printf("probe %d: rc=%d %s\n", i + 1, r, why);
        if (r < 0) bad++;
    }
    return bad ? 1 : 0;
}

static int bulk_once(const struct vless_node *np, int port, int mb) {
    const struct vless_node n = *np;
    size_t total = (size_t)mb << 20;
    struct transport t;
    int rc = vless_connect(&n, &t, 10);
    if (rc) { printf("connect: %s\n", transport_strerror(rc)); return 1; }
    unsigned char uuid[16], req[256], ip[4] = { 127, 0, 0, 1 };
    vless_uuid_parse(n.uuid, uuid);
    size_t rn = vless_build_request(uuid, VLESS_CMD_TCP, NULL, ip, (uint16_t)port, n.flow, req, sizeof req);
    unsigned char *out = malloc(total ? total : 1), *in = malloc(total + 64), *buf = malloc(1 << 15);
    for (size_t i = 0; i < total; i++) out[i] = (unsigned char)((i * 2654435761u) >> 13);
    size_t sent = 0, recvd = 0;
    int hdr_done = 0, first = 1;
    unsigned seed = 12345;
    while (recvd < total) {
        const size_t before = recvd;
        if (sent < total) {
            seed = seed * 1103515245 + 12345;
            size_t k = 1 + (seed >> 8) % 20000;
            if (sent + k > total) k = total - sent;
            unsigned char *w = malloc(rn + k);
            size_t wn = 0;
            if (first) { memcpy(w, req, rn); wn = rn; first = 0; }
            memcpy(w + wn, out + sent, k);
            wn += k;
            rc = transport_write(&t, w, wn);
            free(w);
            if (rc) { printf("write after %zu bytes: %s\n", sent, transport_strerror(rc)); return 1; }
            sent += k;
        }
        for (;;) {
            struct pollfd p = { .fd = transport_fd(&t), .events = POLLIN };
            if (!transport_has_data(&t) && poll(&p, 1, sent < total ? 0 : 5000) <= 0) break;
            size_t got = 0;
            rc = transport_read(&t, buf, 1 << 15, &got);
            if (rc) { printf("read after %zu bytes: %s\n", recvd, transport_strerror(rc)); return 1; }
            if (!got) { if (sent >= total) continue; break; }
            const unsigned char *d = buf;
            size_t dn = got;
            if (!hdr_done) {
                size_t skip = 0;
                if (vless_parse_response(buf, got, &skip)) { printf("bad response\n"); return 1; }
                d += skip; dn -= skip; hdr_done = 1;
            }
            if (recvd + dn > total) { printf("extra data\n"); return 1; }
            memcpy(in + recvd, d, dn);
            recvd += dn;
        }
        /* Everything sent and not a byte in 5 s: a hang, not a reason to wait forever. */
        if (sent >= total && recvd == before) { printf("hang: received %zu of %zu\n", recvd, total); return 1; }
    }
    int same = memcmp(in, out, total) == 0;
    printf("%d MB there and back: %s\n", mb, same ? "match" : "DIFFER");
    transport_close(&t);
    return same ? 0 : 1;
}

/* Between connections the probe can stop and let the script do something to the server (a
 * restart: the new server has no tickets): with VENC_SYNC=dir, after connection i it creates
 * ready.i and waits for go.i. */
static void sync_point(int i) {
    const char *d = getenv("VENC_SYNC");
    if (!d) return;
    char f[300];
    snprintf(f, sizeof f, "%s/ready.%d", d, i);
    FILE *fp = fopen(f, "w");
    if (fp) fclose(fp);
    snprintf(f, sizeof f, "%s/go.%d", d, i);
    for (int k = 0; k < 600 && access(f, F_OK) != 0; k++) usleep(50000);
}

/* reps connections in a row in one process: from the second on, VLESS encryption 0rtt uses a
 * ticket. With VENC_SYNC a failed connection does not stop the run (that is how a rejected ticket
 * is tested): the exit code is the last one's. */
static int cmd_bulk(const char *url, int port, int mb, int reps) {
    struct vless_node n;
    if (vless_parse_url(url, &n)) { printf("node unusable: %s\n", n.skip_reason); return 2; }
    int rc = 0;
    for (int i = 0; i < reps; i++) {
        rc = bulk_once(&n, port, mb);
        if (rc && !getenv("VENC_SYNC")) return rc;
        if (i + 1 < reps) sync_point(i + 1);
    }
    return rc;
}

int main(int argc, char **argv) {
    if (argc >= 4 && !strcmp(argv[1], "probe")) return cmd_probe(argv[2], atoi(argv[3]));
    if (argc >= 5 && !strcmp(argv[1], "bulk")) return cmd_bulk(argv[2], atoi(argv[3]), atoi(argv[4]), argc > 5 ? atoi(argv[5]) : 1);
    fprintf(stderr, "vencprobe probe URL N | vencprobe bulk URL PORT MB [REPS]\n");
    return 2;
}
