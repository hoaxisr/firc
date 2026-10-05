#ifndef FIRC_RESOLVER_ADDR_H
#define FIRC_RESOLVER_ADDR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "firc/fakeip_addr.h"

#define FIRC_RESOLVER_DEFAULT_PORT 53
#define FIRC_RESOLVER_ADDR_STRLEN 56

#define FIRC_RESOLVE_MAX_SERVERS 4

typedef struct firc_resolver_addr {
    firc_ip_t ip;
    uint16_t port; /* host order */
} firc_resolver_addr_t;

typedef enum {
    FIRC_RESOLVER_ADDR_OK = 0,
    FIRC_RESOLVER_ADDR_SYNTAX,
    FIRC_RESOLVER_ADDR_PORT,
    FIRC_RESOLVER_ADDR_SINK,
    FIRC_RESOLVER_ADDR_MAPPED,
} firc_resolver_addr_res_t;

/* An address literal: addr, addr:port, [v6] or [v6]:port. */
firc_resolver_addr_res_t firc_resolver_addr_parse(const char *s, firc_resolver_addr_t *out);

/* The phrase that follows the quoted value in an error sentence. */
const char *firc_resolver_addr_why(firc_resolver_addr_res_t r);

/* 0.0.0.0, 127.0.0.0/8, :: or ::1 (v4-mapped too); the pool is not checked. */
bool firc_resolver_ip_is_sink(const firc_ip_t *ip);

void firc_resolver_addr_sockaddr(const firc_resolver_addr_t *a, struct sockaddr_storage *ss,
                                 socklen_t *len);

/* Shortest text that parses back. strlen, or 0 when it did not fit (buf ""). */
size_t firc_resolver_addr_format(const firc_resolver_addr_t *a, char *buf, size_t cap);

#endif
