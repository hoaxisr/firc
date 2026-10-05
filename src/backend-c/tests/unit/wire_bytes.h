#ifndef FIRC_TEST_WIRE_BYTES_H
#define FIRC_TEST_WIRE_BYTES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct {
    uint8_t b[4096];
    size_t n;
} wb_t;

static inline void wb_bytes(wb_t *w, const void *p, size_t n) {
    memcpy(w->b + w->n, p, n);
    w->n += n;
}

static inline void wb_u8(wb_t *w, uint8_t v) { wb_bytes(w, &v, 1); }

static inline void wb_h16(wb_t *w, uint16_t v) { wb_bytes(w, &v, sizeof(v)); }

static inline void wb_h32(wb_t *w, uint32_t v) { wb_bytes(w, &v, sizeof(v)); }

static inline void wb_pad(wb_t *w) {
    while (w->n % 4u != 0) { w->b[w->n++] = 0; }
}

static inline void wb_patch_h16(wb_t *w, size_t at, uint16_t v) { memcpy(w->b + at, &v, sizeof(v)); }

static inline void wb_patch_h32(wb_t *w, size_t at, uint32_t v) { memcpy(w->b + at, &v, sizeof(v)); }

static inline size_t wb_nlmsg(wb_t *w, uint16_t type, uint16_t flags, uint32_t seq) {
    size_t at = w->n;
    wb_h32(w, 0);
    wb_h16(w, type);
    wb_h16(w, flags);
    wb_h32(w, seq);
    wb_h32(w, 0);
    return at;
}

static inline void wb_nlmsg_end(wb_t *w, size_t at) {
    wb_pad(w);
    wb_patch_h32(w, at, (uint32_t)(w->n - at));
}

static inline size_t wb_attr(wb_t *w, uint16_t type) {
    size_t at = w->n;
    wb_h16(w, 0);
    wb_h16(w, type);
    return at;
}

static inline void wb_attr_end(wb_t *w, size_t at) {
    wb_patch_h16(w, at, (uint16_t)(w->n - at));
    wb_pad(w);
}

static inline void wb_attr_bytes(wb_t *w, uint16_t type, const void *p, size_t n) {
    size_t at = wb_attr(w, type);
    wb_bytes(w, p, n);
    wb_attr_end(w, at);
}

static inline void wb_attr_h32(wb_t *w, uint16_t type, uint32_t v) {
    size_t at = wb_attr(w, type);
    wb_h32(w, v);
    wb_attr_end(w, at);
}

static inline void wb_done(wb_t *w, uint32_t seq) {
    size_t at = wb_nlmsg(w, 3, 2, seq);
    wb_h32(w, 0);
    wb_nlmsg_end(w, at);
}

static inline void wb_ack(wb_t *w, uint32_t seq, int32_t error) {
    size_t at = wb_nlmsg(w, 2, 0, seq);
    uint32_t e;
    memcpy(&e, &error, sizeof(e));
    wb_h32(w, e);
    wb_h32(w, 16);
    wb_h16(w, 0);
    wb_h16(w, 0);
    wb_h32(w, seq);
    wb_h32(w, 0);
    wb_nlmsg_end(w, at);
}

static inline bool wb_send(int fd, const wb_t *w) {
    return send(fd, w->b, w->n, 0) == (ssize_t)w->n;
}

static inline bool wb_recv(int fd, wb_t *w) {
    ssize_t r = recv(fd, w->b, sizeof(w->b), MSG_DONTWAIT);
    if (r < 0) { return false; }
    w->n = (size_t)r;
    return true;
}

#endif
