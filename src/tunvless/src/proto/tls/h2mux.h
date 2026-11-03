#ifndef STEER_H2MUX_H
#define STEER_H2MUX_H
#include <stddef.h>
#include <stdint.h>

#include "h2.h"
#include "h2wire.h"

#define H2M_STREAMS 256

struct h2m_cb {
    void *ctx;
    int  (*out)(void *ctx, const unsigned char *d, size_t n, int control);
    void (*data)(void *ctx, uint16_t slot, const unsigned char *d, size_t n);
    void (*status)(void *ctx, uint16_t slot, int status);
    void (*end)(void *ctx, uint16_t slot, int code);
    void (*goaway)(void *ctx, uint32_t last_sid, uint32_t code);
    void (*ping_ack)(void *ctx);
    void (*room)(void *ctx, uint16_t slot);
};

struct h2m_stream {
    uint32_t sid;
    int32_t send_win, recv_win;
    uint32_t recv_owed;
    uint8_t state;
};

struct h2m {
    struct h2m_cb cb;
    struct h2m_stream *st;
    uint16_t st_cap;
    uint16_t open_n;
    uint32_t next_sid;
    int32_t send_win_conn, recv_win_conn;
    uint32_t conn_owed, lost;
    int32_t peer_init_win;
    uint32_t peer_max_streams, peer_hdr_list;
    uint8_t peer_max_set, peer_settings_seen, peer_hdr_set;
    uint8_t goaway;
    uint32_t goaway_last;
    int dead;

    unsigned char hdr[9];
    uint8_t hdr_n;
    uint32_t f_len, f_left;
    uint32_t f_sid;
    uint16_t f_slot;
    uint8_t f_type, f_flags;
    uint8_t pad_wait, pad_left, skip_left;
    uint8_t peek, paid, grew;
    unsigned char ctl[64];
    uint8_t ctl_n;

    uint8_t cont;
    uint8_t cont_end;
    uint32_t cont_sid;

    unsigned char ping_op[8];
    uint8_t ping_out;
};

int  h2m_start(struct h2m *m, const struct h2m_cb *cb, int conn_update);
int  h2m_feed(struct h2m *m, const unsigned char *d, size_t n);
int  h2m_open(struct h2m *m, const struct h2_req *r, int browser, uint16_t *slot);
long h2m_room(const struct h2m *m, uint16_t slot);
long h2m_conn_room(const struct h2m *m);
int  h2m_send(struct h2m *m, uint16_t slot, const unsigned char *d, size_t n, int end);
int  h2m_reset(struct h2m *m, uint16_t slot, uint32_t code);
void h2m_consumed(struct h2m *m, uint16_t slot, uint32_t n);
void h2m_credit_conn(struct h2m *m, uint32_t n);
uint32_t h2m_take_lost(struct h2m *m);
int  h2m_ping(struct h2m *m, const unsigned char op[8]);
uint32_t h2m_cap(const struct h2m *m);
uint32_t h2m_header_budget(const struct h2m *m, uint32_t server_max);
unsigned h2m_open_n(const struct h2m *m);
void h2m_free(struct h2m *m);

#endif
