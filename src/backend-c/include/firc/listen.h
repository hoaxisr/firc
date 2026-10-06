#ifndef FIRC_LISTEN_H
#define FIRC_LISTEN_H

#include <stdbool.h>
#include <stddef.h>
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

#define FIRC_WEB_PORTS_MAX 6

/* WebUI ports to try in order: configured first, then the fallbacks other than it and skip; returns the count */
size_t firc_web_ports(uint16_t configured, uint16_t skip, uint16_t out[FIRC_WEB_PORTS_MAX]);

#endif
