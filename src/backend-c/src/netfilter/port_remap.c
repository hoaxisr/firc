#include "firc/port_remap.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

struct firc_port_remap {
    char *chain_name;
    firc_remap_addr_t *addrs;
    size_t n_addrs;
    uint16_t from, to;
    firc_ipt_t *ipt4, *ipt6;
    bool enabled;
};

firc_port_remap_t *firc_port_remap_new(const char *chain_prefix, uint16_t from, uint16_t to,
                                   const firc_remap_addr_t *addrs, size_t n_addrs, firc_ipt_t *ipt4,
                                   firc_ipt_t *ipt6) {
    if (!chain_prefix) { return NULL; }
    firc_port_remap_t *p = calloc(1, sizeof(*p));
    if (!p) { return NULL; }

    static const char suffix[] = "DNSOR";
    size_t prefix_len = strlen(chain_prefix);
    if (prefix_len > SIZE_MAX - sizeof(suffix)) {
        free(p);
        return NULL;
    }
    p->chain_name = malloc(prefix_len + sizeof(suffix));
    if (!p->chain_name) {
        free(p);
        return NULL;
    }
    memcpy(p->chain_name, chain_prefix, prefix_len);
    memcpy(p->chain_name + prefix_len, suffix, sizeof(suffix));

    if (n_addrs > 0) {
        p->addrs = calloc(n_addrs, sizeof(*p->addrs));
        if (!p->addrs) {
            free(p->chain_name);
            free(p);
            return NULL;
        }
        memcpy(p->addrs, addrs, n_addrs * sizeof(*p->addrs));
    }
    p->n_addrs = n_addrs;
    p->from = from;
    p->to = to;
    p->ipt4 = ipt4;
    p->ipt6 = ipt6;
    return p;
}

void firc_port_remap_free(firc_port_remap_t *p) {
    if (!p) { return; }
    free(p->chain_name);
    free(p->addrs);
    free(p);
}

static firc_err_t build_rules(firc_port_remap_t *p, firc_ipt_t *ipt) {
    if (!ipt) { return FIRC_OK; }
    firc_ipt_proto_t proto = firc_ipt_proto(ipt);

    firc_err_t err = firc_ipt_register_chain_override(ipt, "nat", p->chain_name);
    if (err != FIRC_OK) { return err; }

    char from_str[8];
    char to_dest[16];
    snprintf(from_str, sizeof(from_str), "%u", p->from);
    snprintf(to_dest, sizeof(to_dest), ":%u", p->to);

    for (size_t i = 0; i < p->n_addrs; i++) {
        bool matches = (proto == FIRC_IPT_PROTO_IPV4 && p->addrs[i].iplen == 4) ||
                       (proto == FIRC_IPT_PROTO_IPV6 && p->addrs[i].iplen == 16);
        if (!matches) { continue; }

        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(p->addrs[i].iplen == 4 ? AF_INET : AF_INET6, p->addrs[i].ip, ip_str,
                  sizeof(ip_str));

        const char *tcp_args[] = {"-p", "tcp", "-d", ip_str, "--dport", from_str,
                                  "-j", "DNAT", "--to-destination", to_dest};
        err = firc_ipt_append(ipt, "nat", p->chain_name, tcp_args, 10);
        if (err != FIRC_OK) { return err; }

        const char *udp_args[] = {"-p", "udp", "-d", ip_str, "--dport", from_str,
                                  "-j", "DNAT", "--to-destination", to_dest};
        err = firc_ipt_append(ipt, "nat", p->chain_name, udp_args, 10);
        if (err != FIRC_OK) { return err; }
    }

    const char *pre_args[] = {"-j", p->chain_name};
    err = firc_ipt_insert(ipt, "nat", "PREROUTING", 1, pre_args, 2);
    if (err != FIRC_OK) { return err; }

    return FIRC_OK;
}

static firc_err_t insert_rules(firc_port_remap_t *p, firc_ipt_t *ipt) {
    if (!ipt) { return FIRC_OK; }

    firc_err_t err = build_rules(p, ipt);
    if (err != FIRC_OK) { return err; }
    return firc_ipt_commit(ipt);
}

firc_err_t firc_port_remap_prepare_iptables(firc_port_remap_t *p) {
    if (!p || !p->enabled) { return FIRC_OK; }

    firc_err_t e4 = build_rules(p, p->ipt4);
    firc_err_t e6 = build_rules(p, p->ipt6);
    return e4 != FIRC_OK ? e4 : e6;
}

static firc_err_t delete_rules(firc_port_remap_t *p, firc_ipt_t *ipt) {
    if (!ipt) { return FIRC_OK; }
    firc_err_t first_err = firc_ipt_register_chain_delete(ipt, "nat", p->chain_name);

    const char *pre_args[] = {"-j", p->chain_name};
    firc_err_t err = firc_ipt_delete(ipt, "nat", "PREROUTING", pre_args, 2);
    if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }

    err = firc_ipt_commit(ipt);
    if (err != FIRC_OK && first_err == FIRC_OK) { first_err = err; }
    return first_err;
}

firc_err_t firc_port_remap_enable(firc_port_remap_t *p) {
    if (p->enabled) { return FIRC_OK; }

    firc_err_t err = insert_rules(p, p->ipt4);
    if (err == FIRC_OK) { err = insert_rules(p, p->ipt6); }
    if (err != FIRC_OK) {
        delete_rules(p, p->ipt4);
        delete_rules(p, p->ipt6);
        return err;
    }
    p->enabled = true;
    return FIRC_OK;
}

firc_err_t firc_port_remap_disable(firc_port_remap_t *p) {
    if (!p->enabled) { return FIRC_OK; }
    p->enabled = false;

    firc_err_t e1 = delete_rules(p, p->ipt4);
    firc_err_t e2 = delete_rules(p, p->ipt6);
    return e1 != FIRC_OK ? e1 : e2;
}
