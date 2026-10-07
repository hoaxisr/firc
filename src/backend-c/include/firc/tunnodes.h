#ifndef FIRC_TUNNODES_H
#define FIRC_TUNNODES_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/err.h"
#include "firc/tunnels.h"

#define FIRC_TUN_MAX_NODES 256

typedef struct {
    const char *url;
    uint32_t mark;
    const char *body;
    size_t len;
} firc_tun_body_t;

typedef struct {
    char key[192];
    char name[101];
    char source[64];
    bool is_new, excluded, missing, over_cap;
    char skip_reason[96];
    size_t link_len;
    char *link;
} firc_tun_node_t;

typedef struct {
    firc_tun_node_t *v;
    size_t n;
    size_t matched, total;
} firc_tun_nodes_t;

/* Serialises every use of the tunvless parser, whose intern table and insecure flag are global. */
extern pthread_mutex_t firc_tun_parse_mutex;

/* The effective node table of t: ordered rows first, then the rest in source order; a row with a
   link is sent to tunvless. Subscription sources take the body matching (url, mark), if any. */
firc_err_t firc_tun_nodes_build(const firc_tunnel_t *t, uint32_t mark, const firc_tun_body_t *bodies,
                                size_t n_bodies, firc_tun_nodes_t *out);

void firc_tun_nodes_free(firc_tun_nodes_t *n);

#endif
