#ifndef FIRC_NETFILTER_CLEANER_H
#define FIRC_NETFILTER_CLEANER_H

#include "firc/err.h"
#include "firc/iptables.h"

/* Sweeps leftover chains and jumps of ours, keeping the pool's FORWARD barrier; commits each non-NULL ipt. */
firc_err_t firc_netfilter_clean_iptables(firc_ipt_t *ipt4, firc_ipt_t *ipt6, const char *chain_prefix);
/* The same sweep for `fircd --purge`, barrier included. */
firc_err_t firc_netfilter_purge_iptables(firc_ipt_t *ipt4, firc_ipt_t *ipt6, const char *chain_prefix);

/* Registers the base chains as patch chains; calling it again discards jumps staged by the previous pass. */
firc_err_t firc_netfilter_register_base_chains(firc_ipt_t *ipt4, firc_ipt_t *ipt6);

#endif /* FIRC_NETFILTER_CLEANER_H */
