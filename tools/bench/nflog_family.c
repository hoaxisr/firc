#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "firc/err.h"
#include "firc/nflogsock.h"

struct seen {
    unsigned v4;
    unsigned v6;
    unsigned other;
};

static void on_packet(const uint8_t *pkt, size_t len, void *ud)
{
    struct seen *s = ud;
    if (len == 0) {
        s->other++;
        return;
    }
    switch (pkt[0] >> 4) {
    case 4: s->v4++; break;
    case 6: s->v6++; break;
    default: s->other++; break;
    }
}

int main(int argc, char **argv)
{
    unsigned group = (argc > 1) ? (unsigned)strtoul(argv[1], NULL, 10) : 42u;
    int seconds = (argc > 2) ? atoi(argv[2]) : 10;

    firc_nflog_t *n = firc_nflog_open((uint16_t)group, 256);
    if (n == NULL) {
        fprintf(stderr, "could not bind nflog group %u (CAP_NET_ADMIN? nfnetlink_log?)\n", group);
        return 3;
    }
    printf("bound nflog group %u\n", group);
    fflush(stdout);

    struct seen s = {0, 0, 0};
    struct pollfd p = {.fd = firc_nflog_fd(n), .events = POLLIN};
    for (int i = 0; i < seconds * 10; i++) {
        int rc = poll(&p, 1, 100);
        if (rc > 0) {
            firc_err_t e = firc_nflog_read(n, on_packet, &s);
            if (e != FIRC_OK && e != FIRC_ERR_AGAIN) {
                fprintf(stderr, "read: %s\n", firc_err_str(e));
            }
        }
        if (s.v4 > 0 && s.v6 > 0) { break; }
    }
    firc_nflog_close(n);

    printf("v4=%u v6=%u other=%u\n", s.v4, s.v6, s.other);
    if (s.v4 > 0 && s.v6 > 0) { return 0; }
    return (s.v4 > 0 || s.v6 > 0) ? 1 : 2;
}
