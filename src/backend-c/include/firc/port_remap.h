#ifndef FIRC_PORT_REMAP_H
#define FIRC_PORT_REMAP_H

#include <stdint.h>

#include "firc/err.h"
#include "firc/iptables.h"

typedef struct firc_remap_addr {
    int family; /* AF_INET or AF_INET6 */
    uint8_t ip[16];
    uint8_t iplen; /* 4 or 16 */
} firc_remap_addr_t;

typedef struct firc_port_remap firc_port_remap_t;

/* Chain is "<chain_prefix>DNSOR"; nat/PREROUTING must already be a patch chain, else FIRC_ERR_STATE. ipt4/ipt6 borrowed, nullable. */
firc_port_remap_t *firc_port_remap_new(const char *chain_prefix, uint16_t from, uint16_t to,
                                   const firc_remap_addr_t *addrs, size_t n_addrs, firc_ipt_t *ipt4,
                                   firc_ipt_t *ipt6);
void firc_port_remap_free(firc_port_remap_t *p);

firc_err_t firc_port_remap_enable(firc_port_remap_t *p);
firc_err_t firc_port_remap_disable(firc_port_remap_t *p);

/* Re-stages the chain and its jump for a full rebuild without committing; no-op when p is NULL or disabled. */
firc_err_t firc_port_remap_prepare_iptables(firc_port_remap_t *p);

#endif /* FIRC_PORT_REMAP_H */
