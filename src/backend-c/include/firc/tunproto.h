#ifndef FIRC_TUNPROTO_H
#define FIRC_TUNPROTO_H

#include <stdbool.h>
#include <stddef.h>

#define FIRC_TUN_LINE_MAX 1024

typedef struct {
    char buf[FIRC_TUN_LINE_MAX];
    size_t len;
    bool dropping;
} firc_tun_lines_t;

typedef void (*firc_tun_line_fn)(const char *line, size_t len, void *ud);

/* Splits a byte stream into lines; returns how many oversize lines were dropped in this call. */
size_t firc_tun_lines_feed(firc_tun_lines_t *l, const char *data, size_t n, firc_tun_line_fn fn, void *ud);

typedef enum {
    FIRC_TEV_READY,
    FIRC_TEV_ACTIVE,
    FIRC_TEV_NODE_DOWN,
    FIRC_TEV_NODE_UP,
    FIRC_TEV_NO_NODE,
    FIRC_TEV_NODES,
    FIRC_TEV_PINS_FULL,
    FIRC_TEV_BAD
} firc_tev_kind_t;

/* index and active_index are tunvless's node numbers, -1 when absent; pos and active_pos are the
   positions in the list last given for the tunnel, filled by tunsup, -1 when unknown. */
typedef struct {
    firc_tev_kind_t kind;
    char dev[16];
    char node[128];
    char why[160];
    int retry_s;
    int count;
    int index;
    int pos;
    char active[8][128];
    int active_index[8];
    int active_pos[8];
    size_t n_active;
} firc_tev_t;

/* Parses one line; kind is FIRC_TEV_BAD when it is malformed. Never reads past len. */
void firc_tun_event_parse(const char *line, size_t len, firc_tev_t *out);

#endif
