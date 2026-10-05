#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "firc/clienthello.h"
#include "firc/nflogsock.h"
#include "firc/tappacket.h"

static int g_seen = 0;

static void on_packet(const uint8_t *pkt, size_t len, void *ud) {
    (void)ud;
    g_seen++;
    printf("packet %d: %zu bytes delivered\n", g_seen, len);
    firc_tap_packet_t p;
    if (!firc_tap_packet_parse(pkt, len, &p)) {
        printf("  not a packet this tap reads\n");
        return;
    }
    char src[64] = "", dst[64] = "";
    for (size_t i = 0; i < p.src.len; i++) {
        snprintf(src + strlen(src), sizeof(src) - strlen(src), i ? ".%u" : "%u", p.src.b[i]);
    }
    for (size_t i = 0; i < p.dst.len; i++) {
        snprintf(dst + strlen(dst), sizeof(dst) - strlen(dst), i ? ".%u" : "%u", p.dst.b[i]);
    }
    printf("  %s -> %s:%u, %zu bytes after TCP\n", src, dst, p.dst_port, p.payload_len);
    char sni[256];
    if (firc_tls_client_hello_sni(p.payload, p.payload_len, sni, sizeof(sni))) {
        printf("  SNI=%s\n", sni);
    } else {
        printf("  no server name in it\n");
    }
}

int main(int argc, char **argv) {
    unsigned group = argc > 1 ? (unsigned)atoi(argv[1]) : 42;
    unsigned range = argc > 2 ? (unsigned)atoi(argv[2]) : 300;
    firc_nflog_t *n = firc_nflog_open((uint16_t)group, (uint16_t)range);
    if (n == NULL) {
        printf("open failed\n");
        return 1;
    }
    printf("bound group %u, range %u\n", group, range);
    fflush(stdout);

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        struct pollfd pfd = {firc_nflog_fd(n), POLLIN, 0};
        poll(&pfd, 1, 500);
        firc_err_t e = firc_nflog_read(n, on_packet, NULL);
        if (e != FIRC_OK && e != FIRC_ERR_AGAIN) {
            printf("read: %s\n", firc_err_str(e));
        }
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 12) { break; }
        fflush(stdout);
    }
    firc_nflog_close(n);
    printf("window over, %d packets\n", g_seen);
    return 0;
}
