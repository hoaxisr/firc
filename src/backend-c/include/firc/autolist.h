#ifndef FIRC_AUTOLIST_H
#define FIRC_AUTOLIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/fakeip.h"

#define FIRC_AUTOLIST_FLOWS 1024
#define FIRC_AUTOLIST_HOSTS 512
#define FIRC_AUTOLIST_DOMAINS 512
#define FIRC_AUTOLIST_HINTS 512
#define FIRC_AUTOLIST_FLOW_SECS 300
#define FIRC_AUTOLIST_HINT_SECS 600
#define FIRC_AUTOLIST_NAME_MAX 254

#define FIRC_AUTOLIST_FAIL_THRESHOLD 3
#define FIRC_AUTOLIST_FAIL_SECS 60
#define FIRC_AUTOLIST_RETRANS_THRESHOLD 3
#define FIRC_AUTOLIST_SYN_SPAN_SECS 2

#define FIRC_AUTOLIST_STALL_MIN_BYTES 8192
#define FIRC_AUTOLIST_STALL_MAX_BYTES 32768
#define FIRC_AUTOLIST_STALL_MIN_SECS 10
#define FIRC_AUTOLIST_NOTES 2
#define FIRC_AUTOLIST_NOTE_SECS 120

#define FIRC_AUTOLIST_BYPASS_CLIENTS 16
#define FIRC_AUTOLIST_DAY_SECS 86400
#define FIRC_AUTOLIST_DAY_HOURS 24
#define FIRC_AUTOLIST_POOLS 2

typedef struct firc_autolist firc_autolist_t;

typedef struct firc_autolist_net {
    firc_ip_t base;
    uint8_t prefix;
} firc_autolist_net_t;

typedef struct firc_autolist_params {
    uint32_t fail_threshold;
    uint32_t fail_secs;
    uint32_t retrans_threshold;
} firc_autolist_params_t;

typedef struct firc_autolist_flow {
    firc_ip_t client, server;
    uint16_t client_port, server_port;
} firc_autolist_flow_t;

typedef enum {
    FIRC_AUTOLIST_RETRANS = 1,
    FIRC_AUTOLIST_RESET,
    FIRC_AUTOLIST_NO_CONNECT,
} firc_autolist_why_t;

typedef enum {
    FIRC_AL_NOM_STALL = 1,
    FIRC_AL_NOM_NO_CONNECT = 2,
} firc_autolist_nom_kind_t;

typedef struct firc_autolist_failure {
    char host[FIRC_AUTOLIST_NAME_MAX];
    char domain[FIRC_AUTOLIST_NAME_MAX];
    firc_ip_t client;
    uint32_t fails;
    uint8_t why;
    bool listed;
    bool bypass;
} firc_autolist_failure_t;

typedef struct {
    char host[FIRC_AUTOLIST_NAME_MAX];
    char domain[FIRC_AUTOLIST_NAME_MAX];
    firc_ip_t client;
    uint32_t received;
    uint8_t kind;
    bool bypass;
} firc_autolist_nomination_t;

/* True for an address no site has: 0/8, private, link-local, loopback, CGNAT, 198.18.0.0/15, fc00::/7,
 * fe80::/10, :: and ::1 (v4-mapped too), or one of pools. */
bool firc_autolist_local(const firc_ip_t *ip, const firc_autolist_net_t *pools, size_t n_pools);

firc_autolist_t *firc_autolist_new(void);
void firc_autolist_free(firc_autolist_t *a);

void firc_autolist_set_params(firc_autolist_t *a, const firc_autolist_params_t *p);

void firc_autolist_hint(firc_autolist_t *a, const firc_ip_t *client, const char *name, const firc_ip_t *reals,
                        size_t n_reals, int64_t now);

bool firc_autolist_hello(firc_autolist_t *a, const firc_autolist_flow_t *f, uint32_t seq, uint32_t ack,
                         const char *sni, int64_t now, firc_autolist_failure_t *out);

bool firc_autolist_reply(firc_autolist_t *a, const firc_autolist_flow_t *f, bool rst, int64_t now,
                         firc_autolist_failure_t *out);

bool firc_autolist_fin(firc_autolist_t *a, const firc_autolist_flow_t *f, uint32_t ack, int64_t now,
                       firc_autolist_nomination_t *out);

bool firc_autolist_syn(firc_autolist_t *a, const firc_autolist_flow_t *f, uint32_t seq, int64_t now,
                       firc_autolist_nomination_t *out);

size_t firc_autolist_bypassed(const firc_autolist_t *a, int64_t now, firc_ip_t *clients, uint32_t *fails,
                              size_t cap);

uint32_t firc_autolist_failures_day(const firc_autolist_t *a, int64_t now);

uint32_t firc_autolist_ambiguous_day(const firc_autolist_t *a, int64_t now);

#endif
