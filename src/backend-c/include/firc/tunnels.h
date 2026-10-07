#ifndef FIRC_TUNNELS_H
#define FIRC_TUNNELS_H

#include <stdbool.h>
#include <stddef.h>

#include "firc/err.h"

#define FIRC_TUN_MAX 8
#define FIRC_TUN_MAX_SOURCES 256
#define FIRC_TUN_MAX_KEYS 1024
#define FIRC_TUN_KEY_MAX 191
#define FIRC_TUN_DESCRIPTION_MAX 63

typedef enum { FIRC_UPLINK_AUTO, FIRC_UPLINK_IFACE, FIRC_UPLINK_TUNNEL } firc_uplink_kind_t;

typedef struct {
    char name[64];
    char *url;
    int interval_s;
} firc_tun_sub_t;

typedef enum { FIRC_TUN_SRC_LINK, FIRC_TUN_SRC_SUB } firc_tun_src_kind_t;

typedef struct {
    char id[9];
    firc_tun_src_kind_t kind;
    char *link;
    firc_tun_sub_t sub;
} firc_tun_src_t;

typedef struct {
    char id[16];
    char device[16];
    char description[FIRC_TUN_DESCRIPTION_MAX + 1];
    bool enable;
    firc_uplink_kind_t uplink;
    char uplink_ref[16];
    firc_tun_src_t *src;
    size_t n_src;
    char *filter;
    char **order;
    size_t n_order;
    char **exclude;
    size_t n_exclude;
    int active;
    char by[16];
    int interval_s, silence_s, timeout_s;
    bool insecure;
    char ca[256];
} firc_tunnel_t;

typedef struct {
    firc_tunnel_t *t;
    size_t n;
} firc_tunnels_t;

typedef struct {
    char where[96];
    char why[160];
} firc_tun_err_t;

/* Parses and validates a tunnels.yaml document; on failure err names the place and the reason. */
firc_err_t firc_tunnels_load_buffer(firc_tunnels_t *out, const char *buf, size_t len,
                                    firc_tun_err_t *err);

/* Like load_buffer from a file; a missing file is FIRC_OK with no tunnels. */
firc_err_t firc_tunnels_load_file(firc_tunnels_t *out, const char *path, firc_tun_err_t *err);

/* Writes the file atomically with mode 0600 (links are secrets). */
firc_err_t firc_tunnels_save_file(const firc_tunnels_t *in, const char *path);

void firc_tunnels_free(firc_tunnels_t *t);

/* True when tunvless for a would be started with the same options as for b; sources not compared. */
bool firc_tunnel_same_argv(const firc_tunnel_t *a, const firc_tunnel_t *b);

/* True when a and b give tunvless the same nodes: source kinds, links and URLs in order. */
bool firc_tunnel_same_nodes(const firc_tunnel_t *a, const firc_tunnel_t *b);

#endif
