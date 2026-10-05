#ifndef FIRC_LISTEN_H
#define FIRC_LISTEN_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

/* Parses addr (IPv4/IPv6 literal, brackets ok) and port; empty_is_any makes "" and "[]" mean [::]. */
bool firc_listen_addr(const char *addr, uint16_t port, bool empty_is_any,
                      struct sockaddr_storage *sa, socklen_t *sa_len);

enum {
    /* IPV6_V6ONLY off (DNS proxy). */
    FIRC_LISTEN_DUAL_STACK = 1u << 0,
    /* IP_PKTINFO / IPV6_RECVPKTINFO (DNS proxy UDP). */
    FIRC_LISTEN_PKTINFO = 1u << 1,
};

#define FIRC_WEB_LISTEN 0u
#define FIRC_DNS_UDP_LISTEN (FIRC_LISTEN_DUAL_STACK | FIRC_LISTEN_PKTINFO)
#define FIRC_DNS_TCP_LISTEN FIRC_LISTEN_DUAL_STACK

/* Nonblocking close-on-exec socket bound to sa (SO_REUSEADDR, backlog 128 for streams); fd or -errno. */
int firc_listen_open(int type, const struct sockaddr_storage *sa, socklen_t sa_len, unsigned opts);

#endif
