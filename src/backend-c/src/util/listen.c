#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */

#include "firc/listen.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

bool firc_listen_addr(const char *addr, uint16_t port, bool empty_is_any,
                      struct sockaddr_storage *sa, socklen_t *sa_len)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", addr != NULL ? addr : "");
    char *host = buf;
    size_t n = strlen(host);
    if (n >= 2 && host[0] == '[' && host[n - 1] == ']') {
        host[n - 1] = '\0';
        host++;
    }

    memset(sa, 0, sizeof(*sa));
    if (strchr(host, ':') != NULL || (empty_is_any && host[0] == '\0')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        if (host[0] == '\0') {
            s6->sin6_addr = in6addr_any;
        } else if (inet_pton(AF_INET6, host, &s6->sin6_addr) != 1) {
            return false;
        }
        *sa_len = sizeof(*s6);
        return true;
    }
    struct sockaddr_in *s4 = (struct sockaddr_in *)sa;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(port);
    if (inet_pton(AF_INET, host, &s4->sin_addr) != 1) { return false; }
    *sa_len = sizeof(*s4);
    return true;
}

int firc_listen_open(int type, const struct sockaddr_storage *sa, socklen_t sa_len, unsigned opts)
{
    int fd = socket(sa->ss_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { return -errno; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if ((opts & FIRC_LISTEN_DUAL_STACK) != 0 && sa->ss_family == AF_INET6) {
        int zero = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    }
    if ((opts & FIRC_LISTEN_PKTINFO) != 0) {
        if (sa->ss_family == AF_INET6) {
            setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        }
        setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
    }
    if (bind(fd, (const struct sockaddr *)sa, sa_len) != 0 ||
        (type == SOCK_STREAM && listen(fd, 128) != 0)) {
        int e = errno;
        close(fd);
        return -e;
    }
    return fd;
}
