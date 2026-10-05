#ifndef FIRC_FAKE_NFLOG_H
#define FIRC_FAKE_NFLOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fake_nflog fake_nflog_t;

fake_nflog_t *fake_nflog_start(int *daemon_fd);
void fake_nflog_stop(fake_nflog_t *f);

bool fake_nflog_send(fake_nflog_t *f, const void *buf, size_t len);

bool fake_nflog_is_bound(fake_nflog_t *f, uint16_t *group_out);
bool fake_nflog_mode(fake_nflog_t *f, uint8_t *copy_mode, uint32_t *copy_range);
bool fake_nflog_qthresh(fake_nflog_t *f, uint32_t *out);
bool fake_nflog_timeout(fake_nflog_t *f, uint32_t *out);
bool fake_nflog_saw_a_pf_command(fake_nflog_t *f);
size_t fake_nflog_config_messages(fake_nflog_t *f);

void fake_nflog_refuse_next(fake_nflog_t *f, int err);

void fake_nflog_stray_ack_first(fake_nflog_t *f);

void fake_nflog_swallow_next(fake_nflog_t *f);

void fake_nflog_ack_garbage_first(fake_nflog_t *f);

void fake_nflog_ack_too_short_first(fake_nflog_t *f);

size_t fake_nflog_hello(uint8_t *out, const char *sni);
/* An IPv4/TCP packet from `src` to `dst`:`port` carrying `payload` */
size_t fake_nflog_packet(uint8_t *out, const uint8_t *src, const uint8_t *dst, uint16_t port,
                         const uint8_t *payload, size_t payload_len);
size_t fake_nflog_msg(uint8_t *out, const uint8_t *pkt, size_t pkt_len);

#endif
