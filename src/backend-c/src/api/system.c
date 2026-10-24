#include "firc/system.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cjson/cJSON.h>

#include "firc/keenetic_policy.h"
#include "firc/events.h"
#include "firc/ifacename.h"
#include "firc/json.h"
#include "firc/keenetic_rci.h"
#include "firc/keenetic_resolvers.h"
#include "firc/log.h"
#include "firc/models.h"

static void must_route(firc_httpd_t *h, const char *method, const char *pattern, firc_http_handler_fn fn,
                       void *ud) {
    if (firc_httpd_route(h, method, pattern, fn, ud) != FIRC_OK) {
        FIRC_ERROR("failed to register route %s %s", method, pattern);
    }
}

#define EVENTS_PAGE_MAX 1024

static const char *level_name(firc_log_level_t l) {
    switch (l) {
    case FIRC_LOG_DEBUG: return "debug";
    case FIRC_LOG_INFO: return "info";
    case FIRC_LOG_WARN: return "warn";
    case FIRC_LOG_ERROR: return "error";
    }
    return "error";
}

static void put_ip(cJSON *obj, const char *key, const firc_ip_t *ip) {
    char s[INET6_ADDRSTRLEN];
    if (ip->len == 0 || inet_ntop(ip->len == 4 ? AF_INET : AF_INET6, ip->b, s, sizeof(s)) == NULL) {
        return;
    }
    cJSON_AddStringToObject(obj, key, s);
}

static const char *qtype_name(uint16_t t, char *buf, size_t cap) {
    switch (t) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    }
    snprintf(buf, cap, "TYPE%u", (unsigned)t);
    return buf;
}

static const char *rcode_name(uint8_t r, char *buf, size_t cap) {
    static const char *names[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
    if (r < sizeof(names) / sizeof(names[0])) { return names[r]; }
    snprintf(buf, cap, "RCODE%u", (unsigned)r);
    return buf;
}

static const char *decision_name(uint8_t d) {
    switch ((firc_dns_decision_t)d) {
    case FIRC_DNS_ISSUED: return "issued";
    case FIRC_DNS_NOT_COVERED: return "not-covered";
    case FIRC_DNS_NO_MATCH: return "no-match";
    case FIRC_DNS_POOL_REFUSED: return "pool-refused";
    case FIRC_DNS_PASSED: return "passed";
    case FIRC_DNS_BLOCKED: return "blocked";
    }
    return "passed";
}

static const char *proto_name(uint8_t proto, char *buf, size_t cap) {
    switch (proto) {
    case 6: return "tcp";
    case 17: return "udp";
    case 1: return "icmp";
    case 58: return "icmpv6";
    }
    snprintf(buf, cap, "%u", (unsigned)proto);
    return buf;
}

static const char *bypass_how_name(uint8_t how) {
    switch ((firc_bypass_how_t)how) {
    case FIRC_BYPASS_BY_ADDR: return "addr";
    case FIRC_BYPASS_BY_SNI: return "sni";
    }
    return "addr";
}

static void dns_to_json(cJSON *item, const firc_event_dns_t *d) {
    char tmp[16];
    put_ip(item, "client", &d->client);
    cJSON_AddStringToObject(item, "name", d->name);
    cJSON_AddStringToObject(item, "qtype", qtype_name(d->qtype, tmp, sizeof(tmp)));
    cJSON_AddStringToObject(item, "rcode", rcode_name(d->rcode, tmp, sizeof(tmp)));
    cJSON_AddStringToObject(item, "decision", decision_name(d->decision));
    cJSON_AddStringToObject(item, "resolver", firc_dns_resolver_name(d->resolver));
    if (d->group_id[0] != '\0') {
        cJSON *g = cJSON_AddObjectToObject(item, "group");
        if (g != NULL) {
            cJSON_AddStringToObject(g, "id", d->group_id);
            cJSON_AddStringToObject(g, "name", d->group_name);
        }
    }
    put_ip(item, "fake", &d->fake);
    cJSON *reals = cJSON_AddArrayToObject(item, "reals");
    for (uint8_t i = 0; reals != NULL && i < d->n_reals && i < FIRC_EVENT_REALS; i++) {
        char s[INET6_ADDRSTRLEN];
        const firc_ip_t *ip = &d->reals[i];
        if (inet_ntop(ip->len == 4 ? AF_INET : AF_INET6, ip->b, s, sizeof(s)) != NULL) {
            cJSON_AddItemToArray(reals, cJSON_CreateString(s));
        }
    }
}

/* last is absent when the recall has none inside its horizon (FIRC_BYPASS_NOT_ASKED) */
static void bypass_to_json(cJSON *item, const firc_event_bypass_t *b) {
    char tmp[16];
    put_ip(item, "client", &b->client);
    put_ip(item, "dst", &b->dst);
    if (b->dst_port != 0) { cJSON_AddNumberToObject(item, "port", b->dst_port); }
    cJSON_AddStringToObject(item, "proto", proto_name(b->proto, tmp, sizeof(tmp)));
    cJSON_AddStringToObject(item, "how", bypass_how_name(b->how));
    cJSON_AddStringToObject(item, "name", b->name);
    if (b->group_id[0] != '\0') {
        cJSON *g = cJSON_AddObjectToObject(item, "group");
        if (g != NULL) {
            cJSON_AddStringToObject(g, "id", b->group_id);
            cJSON_AddStringToObject(g, "name", b->group_name);
        }
    }
    if (b->last_decision != FIRC_BYPASS_NOT_ASKED) {
        cJSON *last = cJSON_AddObjectToObject(item, "last");
        if (last != NULL) {
            cJSON_AddStringToObject(last, "decision", decision_name(b->last_decision));
            cJSON_AddNumberToObject(last, "at", (double)b->last_at);
            put_ip(last, "fake", &b->last_fake);
        }
    }
    cJSON_AddNumberToObject(item, "repeats", (double)b->repeats);
}

static cJSON *event_to_json(const firc_event_t *e) {
    cJSON *item = cJSON_CreateObject();
    if (item == NULL) { return NULL; }
    cJSON_AddNumberToObject(item, "seq", (double)e->seq);
    cJSON_AddNumberToObject(item, "at", (double)e->at);
    switch (e->kind) {
    case FIRC_EVENT_LOG:
        cJSON_AddStringToObject(item, "kind", "log");
        cJSON_AddStringToObject(item, "level", level_name(e->u.log.level));
        cJSON_AddStringToObject(item, "source", e->u.log.source[0] != '\0' ? e->u.log.source : "fircd");
        cJSON_AddStringToObject(item, "message", e->u.log.text);
        break;
    case FIRC_EVENT_DNS:
        cJSON_AddStringToObject(item, "kind", "dns");
        dns_to_json(item, &e->u.dns);
        break;
    case FIRC_EVENT_BYPASS:
        cJSON_AddStringToObject(item, "kind", "bypass");
        bypass_to_json(item, &e->u.bypass);
        break;
    }
    return item;
}

/* since is the cursor from the previous answer; 0 asks for everything the ring still holds */
static void handle_events(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    uint64_t since = 0;
    const char *since_s = firc_http_req_query(req, "since");
    if (since_s != NULL) {
        char *end = NULL;
        unsigned long long v = strtoull(since_s, &end, 10);
        if (end == since_s || *end != '\0') {
            firc_http_res_write_error(res, 400, "since must be a whole number");
            return;
        }
        since = (uint64_t)v;
    }

    firc_event_t *events = calloc(EVENTS_PAGE_MAX, sizeof(*events));
    if (events == NULL) {
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    uint64_t next = since, dropped = 0;
    size_t n = firc_event_read(since, events, EVENTS_PAGE_MAX, &next, &dropped);

    cJSON *out = cJSON_CreateObject();
    cJSON *arr = out != NULL ? cJSON_AddArrayToObject(out, "events") : NULL;
    if (arr == NULL) {
        cJSON_Delete(out);
        free(events);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    for (size_t i = 0; i < n; i++) {
        cJSON *item = event_to_json(&events[i]);
        if (item != NULL) { cJSON_AddItemToArray(arr, item); }
    }
    cJSON_AddNumberToObject(out, "next", (double)next);
    cJSON_AddNumberToObject(out, "dropped", (double)dropped);
    cJSON_AddStringToObject(out, "boot", firc_event_boot());
    free(events);
    firc_http_res_write_json(res, 200, out);
}

/* an empty list is an answer, not a failure: this router may have none configured */
static void handle_policies(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    cJSON *out = cJSON_CreateObject();
    if (out == NULL) {
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    cJSON *arr = cJSON_AddArrayToObject(out, "policies");
    firc_system_ctx_t *ctx = ud;
    firc_kn_policy_info_t list[64];
    size_t n = firc_kn_policies_list(ctx->policies, list, sizeof(list) / sizeof(list[0]));
    for (size_t i = 0; i < n; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", list[i].name);
        if (list[i].description[0] != '\0') {
            cJSON_AddStringToObject(item, "description", list[i].description);
        }
        cJSON_AddNumberToObject(item, "devices", (double)list[i].devices);
        cJSON_AddItemToArray(arr, item);
    }
    firc_http_res_write_json(res, 200, out);
}

/* answered from the policy refresher's latest cached table, never a live RCI call */
static void handle_hosts(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    firc_system_ctx_t *ctx = ud;
    cJSON *out = cJSON_CreateObject();
    cJSON *hosts = firc_kn_policies_hosts_json(ctx->policies);
    if (out == NULL || hosts == NULL) {
        cJSON_Delete(out);
        cJSON_Delete(hosts);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    if (!cJSON_AddItemToObject(out, "hosts", hosts)) {
        cJSON_Delete(hosts);
        cJSON_Delete(out);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    firc_http_res_write_json(res, 200, out);
}

/* empty is an answer */
static void handle_resolvers(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    firc_system_ctx_t *ctx = ud;
    cJSON *out = cJSON_CreateObject();
    cJSON *arr = out != NULL ? cJSON_AddArrayToObject(out, "resolvers") : NULL;
    if (arr == NULL) {
        cJSON_Delete(out);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    firc_kn_iface_resolvers_t list[32];
    size_t n = firc_kn_resolvers_list(ctx->resolvers, list, sizeof(list) / sizeof(list[0]));
    for (size_t i = 0; i < n; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "interface", list[i].iface);
        cJSON *servers = cJSON_AddArrayToObject(item, "servers");
        for (size_t j = 0; j < list[i].n; j++) {
            char s[FIRC_RESOLVER_ADDR_STRLEN];
            if (firc_resolver_addr_format(&list[i].servers[j], s, sizeof(s)) > 0) {
                cJSON_AddItemToArray(servers, cJSON_CreateString(s));
            }
        }
        cJSON_AddItemToArray(arr, item);
    }
    firc_http_res_write_json(res, 200, out);
}

/* ok false after 5s of failing passes, or firstWritePending true before the first pass completes */
static void handle_netfilter(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    firc_system_ctx_t *ctx = ud;
    firc_nfcommit_health_t h;
    firc_app_netfilter_health(ctx->app, &h);
    cJSON *out = cJSON_CreateObject();
    if (out == NULL || cJSON_AddBoolToObject(out, "ok", !h.failing && !h.first_pending) == NULL ||
        (h.first_pending && cJSON_AddBoolToObject(out, "firstWritePending", true) == NULL) ||
        (h.failing && (cJSON_AddStringToObject(out, "error", firc_err_str(h.err)) == NULL ||
                       cJSON_AddNumberToObject(out, "since", (double)h.since) == NULL))) {
        cJSON_Delete(out);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    firc_http_res_write_json(res, 200, out);
}

void firc_system_name_tunnels(firc_iface_info_t *ifaces, size_t n, const firc_tunnels_t *ts) {
    for (size_t i = 0; ts != NULL && i < ts->n; i++) {
        if (ts->t[i].description[0] == '\0') { continue; }
        for (size_t j = 0; j < n; j++) {
            if (strcmp(ifaces[j].id, ts->t[i].device) == 0) {
                snprintf(ifaces[j].name, sizeof(ifaces[j].name), "%.63s", ts->t[i].description);
            }
        }
    }
}

typedef struct ifaces_waiter {
    struct ifaces_waiter *next;
    struct ifaces_read *read;
    firc_http_deferred_t *d;
} ifaces_waiter_t;

typedef struct ifaces_read {
    firc_system_ctx_t *ctx;
    firc_loop_t *loop;
    pthread_t thread;
    firc_kn_aliases_t aliases;
    atomic_bool stopping;
    bool posted;
    bool joined;
    ifaces_waiter_t *waiters;
} ifaces_read_t;

static char *interfaces_body(const firc_system_ctx_t *ctx, const firc_kn_aliases_t *aliases, int *status) {
    firc_iface_info_t *ifaces = NULL;
    size_t n = 0;
    firc_err_t err = firc_app_list_interfaces(aliases, &ifaces, &n);
    cJSON *out;
    if (err != FIRC_OK) {
        *status = 500;
        out = firc_json_error(firc_err_str(err));
    } else {
        *status = 200;
        firc_system_name_tunnels(ifaces, n, ctx->tunnels);
        out = cJSON_CreateObject();
        cJSON *arr = cJSON_AddArrayToObject(out, "interfaces");
        cJSON *blackhole = cJSON_CreateObject();
        cJSON_AddStringToObject(blackhole, "id", "blackhole");
        cJSON_AddItemToArray(arr, blackhole);
        cJSON *block = cJSON_CreateObject();
        cJSON_AddStringToObject(block, "id", FIRC_IFACE_BLOCK);
        cJSON_AddItemToArray(arr, block);
        for (size_t i = 0; i < n; i++) {
            cJSON *item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, "id", ifaces[i].id);
            if (ifaces[i].name[0] != '\0') { cJSON_AddStringToObject(item, "name", ifaces[i].name); }
            if (ifaces[i].ndms_name[0] != '\0') { cJSON_AddStringToObject(item, "ndmsName", ifaces[i].ndms_name); }
            cJSON_AddStringToObject(item, "role", firc_iface_role_name(ifaces[i].role));
            cJSON_AddItemToArray(arr, item);
        }
        free(ifaces);
    }
    char *text = out != NULL ? firc_json_dump(out) : NULL;
    cJSON_Delete(out);
    if (text == NULL) {
        *status = 500;
        text = strdup("{\"error\":\"out of memory\"}");
    }
    return text;
}

static void read_free(ifaces_read_t *r) {
    firc_kn_aliases_free(&r->aliases);
    free(r);
}

static void read_done(firc_loop_t *loop, void *ud);

static void read_drop(void *ud) {
    ifaces_read_t *r = ud;
    if (!r->joined) { pthread_join(r->thread, NULL); }
    read_free(r);
}

static void *read_thread(void *arg) {
    ifaces_read_t *r = arg;
    firc_err_t err = firc_kn_get_iface_aliases(&r->aliases);
    if (err != FIRC_OK) {
        FIRC_DEBUG("failed to load interface aliases: %s", firc_err_str(err));
        firc_kn_aliases_free(&r->aliases);
    }
    r->posted = true;
    while (firc_loop_post_with_drop(r->loop, read_done, r, read_drop) != FIRC_OK) {
        if (atomic_load(&r->stopping)) {
            r->posted = false;
            return NULL;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static void read_done(firc_loop_t *loop, void *ud) {
    (void)loop;
    ifaces_read_t *r = ud;
    if (!r->joined) {
        pthread_join(r->thread, NULL);
        r->joined = true;
    }
    if (r->ctx != NULL) {
        r->ctx->ifaces_read = NULL;
        while (r->waiters != NULL) {
            ifaces_waiter_t *w = r->waiters;
            r->waiters = w->next;
            int status;
            char *text = interfaces_body(r->ctx, &r->aliases, &status);
            firc_http_deferred_finish(w->d, status, "application/json; charset=utf-8", (uint8_t *)text,
                                      text != NULL ? strlen(text) : 0);
            free(w);
        }
    }
    read_free(r);
}

static void waiter_left(void *ud) {
    ifaces_waiter_t *w = ud;
    for (ifaces_waiter_t **link = &w->read->waiters; *link != NULL; link = &(*link)->next) {
        if (*link == w) {
            *link = w->next;
            break;
        }
    }
    firc_http_deferred_drop(w->d);
    free(w);
}

static void handle_list_interfaces(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    firc_system_ctx_t *ctx = ud;
    ifaces_waiter_t *w = calloc(1, sizeof(*w));
    if (w == NULL) {
        firc_http_res_write_error(res, 500, "out of memory");
        return;
    }
    ifaces_read_t *r = ctx->ifaces_read;
    if (r == NULL) {
        r = calloc(1, sizeof(*r));
        if (r == NULL) {
            free(w);
            firc_http_res_write_error(res, 500, "out of memory");
            return;
        }
        r->ctx = ctx;
        r->loop = firc_http_res_loop(res);
        atomic_init(&r->stopping, false);
        if (pthread_create(&r->thread, NULL, read_thread, r) != 0) {
            free(r);
            free(w);
            firc_http_res_write_error(res, 500, "failed to start the interface read");
            return;
        }
        ctx->ifaces_read = r;
    }
    w->read = r;
    w->d = firc_http_res_defer(res, waiter_left, w);
    if (w->d == NULL) {
        free(w);
        firc_http_res_write_error(res, 500, "out of memory");
        return;
    }
    w->next = r->waiters;
    r->waiters = w;
}

void firc_system_close(firc_system_ctx_t *ctx) {
    ifaces_read_t *r = ctx->ifaces_read;
    if (r == NULL) { return; }
    ctx->ifaces_read = NULL;
    atomic_store(&r->stopping, true);
    pthread_join(r->thread, NULL);
    r->joined = true;
    while (r->waiters != NULL) {
        ifaces_waiter_t *w = r->waiters;
        r->waiters = w->next;
        firc_http_deferred_drop(w->d);
        free(w);
    }
    if (r->posted) {
        r->ctx = NULL;
    } else {
        read_free(r);
    }
}

static void handle_save_config(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    firc_system_ctx_t *ctx = ud;
    if (!ctx->config_path) {
        firc_http_res_write(res, 200, NULL, NULL, 0);
        return;
    }
    firc_err_t err =
        firc_app_save_config(ctx->app, ctx->config_path, ctx->config_version ? ctx->config_version : "");
    if (err != FIRC_OK) {
        firc_http_res_write_error(res, 500, firc_err_str(err));
        return;
    }
    firc_http_res_write(res, 200, NULL, NULL, 0);
}

static void handle_netfilterd_hook(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_system_ctx_t *ctx = ud;
    size_t body_len;
    const uint8_t *body = firc_http_req_body(req, &body_len);
    cJSON *json = body_len > 0 ? cJSON_ParseWithLength((const char *)body, body_len) : NULL;
    if (!json) {
        firc_http_res_write_error(res, 400, "failed to parse request");
        return;
    }
    cJSON *type_j = cJSON_GetObjectItemCaseSensitive(json, "type");
    cJSON *table_j = cJSON_GetObjectItemCaseSensitive(json, "table");
    FIRC_DEBUG("received netfilter.d event: type=%s table=%s",
            cJSON_IsString(type_j) ? type_j->valuestring : "",
            cJSON_IsString(table_j) ? table_j->valuestring : "");
    cJSON_Delete(json);

    /* never turned into an HTTP error: the firmware fires this hook mid-rewrite and ignores the answer */
    (void)firc_app_force_commit_iptables(ctx->app);
    firc_http_res_write(res, 200, NULL, NULL, 0);
}

static void handle_iflayer_hook(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_system_ctx_t *ctx = ud;
    size_t body_len;
    const uint8_t *body = firc_http_req_body(req, &body_len);
    cJSON *json = body_len > 0 ? cJSON_ParseWithLength((const char *)body, body_len) : NULL;
    const cJSON *iface = cJSON_GetObjectItemCaseSensitive(json, "iface");
    if (!cJSON_IsString(iface) || !firc_is_interface_name(iface->valuestring)) {
        cJSON_Delete(json);
        firc_http_res_write_error(res, 400, "an interface name is required");
        return;
    }
    const cJSON *layer = cJSON_GetObjectItemCaseSensitive(json, "layer");
    const cJSON *level = cJSON_GetObjectItemCaseSensitive(json, "level");
    char l1[33], l2[33];
    firc_interface_name_for_log(cJSON_IsString(layer) ? layer->valuestring : "", l1, sizeof(l1));
    firc_interface_name_for_log(cJSON_IsString(level) ? level->valuestring : "", l2, sizeof(l2));
    FIRC_DEBUG("received iflayerchanged.d event: iface=%s layer=%s level=%s", iface->valuestring, l1, l2);
    if (ctx->iface_event != NULL) { ctx->iface_event(ctx->iface_event_ud, iface->valuestring); }
    cJSON_Delete(json);
    firc_http_res_write(res, 200, NULL, NULL, 0);
}

#define DNSSTAT_PAGE_DEFAULT 50
#define DNSSTAT_PAGE_MAX 500
#define DNSSTAT_PAGE_SPAN 550
#define DNSSTAT_DEVICES_MAX 12
#define DNSSTAT_ROW_CLIENTS 16
#define DNSSTAT_QUERY_VALUE_MAX 511

typedef struct {
    const char *name;
    uint32_t queries, blocked, clients, row;
    int64_t last;
    firc_id_t owner;
    bool owner_blocked, matched;
} stat_name_t;

typedef struct {
    firc_ip_t ip;
    uint32_t queries;
} stat_client_t;

typedef struct {
    uint32_t n;
    stat_client_t c[DNSSTAT_ROW_CLIENTS];
} stat_row_t;

typedef struct {
    stat_name_t *names;
    stat_row_t *rows;
    firc_ip_t devices[DNSSTAT_DEVICES_MAX];
    size_t n_devices;
    bool arpa;
    const char *needle;
    uint64_t queries, blocked;
    size_t domains, matched;
} stat_walk_t;

static uint32_t sat_add32(uint32_t a, uint32_t b) {
    return a > UINT32_MAX - b ? UINT32_MAX : a + b;
}

static bool stat_keeps(const stat_walk_t *w, const char *name, const firc_ip_t *client) {
    if (w->n_devices > 0) {
        size_t i = 0;
        while (i < w->n_devices && !(w->devices[i].len == client->len &&
                                     memcmp(w->devices[i].b, client->b, client->len) == 0)) {
            i++;
        }
        if (i == w->n_devices) { return false; }
    }
    if (!w->arpa && firc_dnsstat_is_arpa(name)) {
        return false;
    }
    return true;
}

static bool stat_aggregate(void *ud, uint32_t slot, const char *name, const firc_ip_t *client,
                           firc_dnsstat_count_t c, int64_t last, firc_id_t owner, bool last_blocked) {
    stat_walk_t *w = ud;
    if (!stat_keeps(w, name, client)) { return true; }
    stat_name_t *n = &w->names[slot];
    if (n->name == NULL) {
        n->name = name;
        w->domains++;
        n->matched = w->needle == NULL || strstr(name, w->needle) != NULL;
        if (n->matched) { w->matched++; }
    }
    n->queries = sat_add32(n->queries, c.queries);
    n->blocked = sat_add32(n->blocked, c.blocked);
    n->clients++;
    if (n->clients == 1 || last > n->last) {
        n->last = last;
        n->owner = owner;
        n->owner_blocked = last_blocked;
    }
    w->queries += c.queries;
    w->blocked += c.blocked;
    return true;
}

static bool stat_collect(void *ud, uint32_t slot, const char *name, const firc_ip_t *client,
                         firc_dnsstat_count_t c, int64_t last, firc_id_t owner, bool last_blocked) {
    (void)last;
    (void)owner;
    (void)last_blocked;
    stat_walk_t *w = ud;
    if (w->names[slot].row == 0 || !stat_keeps(w, name, client)) { return true; }
    stat_row_t *r = &w->rows[w->names[slot].row - 1];
    if (r->n < DNSSTAT_ROW_CLIENTS) {
        r->c[r->n++] = (stat_client_t){*client, c.queries};
        return true;
    }
    size_t low = 0;
    for (size_t i = 1; i < DNSSTAT_ROW_CLIENTS; i++) {
        if (r->c[i].queries < r->c[low].queries) { low = i; }
    }
    if (c.queries > r->c[low].queries) { r->c[low] = (stat_client_t){*client, c.queries}; }
    return true;
}

static bool stat_ranks_below(const stat_name_t *a, const stat_name_t *b) {
    return a->queries < b->queries || (a->queries == b->queries && strcmp(a->name, b->name) > 0);
}

static int stat_cmp_rows(const void *x, const void *y) {
    const stat_name_t *a = *(const stat_name_t *const *)x, *b = *(const stat_name_t *const *)y;
    if (stat_ranks_below(a, b)) { return 1; }
    return stat_ranks_below(b, a) ? -1 : 0;
}

static int stat_cmp_clients(const void *x, const void *y) {
    const stat_client_t *a = x, *b = y;
    if (a->queries != b->queries) { return a->queries < b->queries ? 1 : -1; }
    if (a->ip.len != b->ip.len) { return a->ip.len < b->ip.len ? -1 : 1; }
    return memcmp(a->ip.b, b->ip.b, a->ip.len);
}

static void stat_sift_down(stat_name_t **heap, size_t n, size_t pos) {
    for (;;) {
        size_t low = pos, l = 2 * pos + 1, r = l + 1;
        if (l < n && stat_ranks_below(heap[l], heap[low])) { low = l; }
        if (r < n && stat_ranks_below(heap[r], heap[low])) { low = r; }
        if (low == pos) { return; }
        stat_name_t *t = heap[pos];
        heap[pos] = heap[low];
        heap[low] = t;
        pos = low;
    }
}

static void stat_sift_up(stat_name_t **heap, size_t pos) {
    while (pos > 0) {
        size_t parent = (pos - 1) / 2;
        if (!stat_ranks_below(heap[pos], heap[parent])) { return; }
        stat_name_t *t = heap[pos];
        heap[pos] = heap[parent];
        heap[parent] = t;
        pos = parent;
    }
}

static size_t stat_select(stat_name_t *names, size_t slots, size_t k, stat_name_t **heap) {
    size_t n = 0;
    for (size_t i = 0; i < slots && k > 0; i++) {
        stat_name_t *x = &names[i];
        if (x->name == NULL || !x->matched) { continue; }
        if (n < k) {
            heap[n] = x;
            stat_sift_up(heap, n++);
        } else if (stat_ranks_below(heap[0], x)) {
            heap[0] = x;
            stat_sift_down(heap, n, 0);
        }
    }
    qsort(heap, n, sizeof(*heap), stat_cmp_rows);
    return n;
}

static bool stat_read_devices(firc_http_req_t *req, firc_http_res_t *res, stat_walk_t *w) {
    const char *v = firc_http_req_query(req, "device");
    if (v == NULL || v[0] == '\0') { return true; }
    if (strlen(v) >= DNSSTAT_QUERY_VALUE_MAX) {
        firc_http_res_write_error(res, 400, "device: too long");
        return false;
    }
    char buf[DNSSTAT_QUERY_VALUE_MAX + 1];
    snprintf(buf, sizeof(buf), "%s", v);
    char *p = buf;
    for (;;) {
        char *comma = strchr(p, ',');
        if (comma != NULL) { *comma = '\0'; }
        if (w->n_devices == DNSSTAT_DEVICES_MAX) {
            firc_http_res_write_error(res, 400, "device: at most 12 addresses");
            return false;
        }
        firc_ip_t *ip = &w->devices[w->n_devices];
        struct in6_addr a6;
        if (inet_pton(AF_INET, p, ip->b) == 1) {
            ip->len = 4;
        } else if (inet_pton(AF_INET6, p, &a6) == 1) {
            if (IN6_IS_ADDR_V4MAPPED(&a6)) {
                memcpy(ip->b, &a6.s6_addr[12], 4);
                ip->len = 4;
            } else {
                memcpy(ip->b, &a6, 16);
                ip->len = 16;
            }
        } else {
            char msg[DNSSTAT_QUERY_VALUE_MAX + 48];
            snprintf(msg, sizeof(msg), "device: not an address: \"%s\"", p);
            firc_http_res_write_error(res, 400, msg);
            return false;
        }
        w->n_devices++;
        if (comma == NULL) { return true; }
        p = comma + 1;
    }
}

static int64_t mono_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec;
}

static cJSON *stat_owner_json(const firc_system_ctx_t *ctx, const stat_name_t *n) {
    firc_ruleset_t *rs = firc_id_is_zero(n->owner) || ctx->app == NULL
                             ? NULL
                             : firc_app_find_group_by_id(ctx->app, n->owner);
    if (rs == NULL) { return cJSON_CreateNull(); }
    const firc_group_t *g = firc_ruleset_group(rs);
    char id[FIRC_ID_STR_LEN];
    firc_id_format(n->owner, id);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "id", id);
    cJSON_AddStringToObject(o, "name", g->name != NULL ? g->name : "");
    cJSON_AddStringToObject(o, "interface", firc_ruleset_active_iface(rs));
    cJSON_AddBoolToObject(o, "blocked", n->owner_blocked);
    return o;
}

static char *stat_row_dump(const firc_system_ctx_t *ctx, const stat_name_t *n, stat_row_t *r, int64_t to_unix) {
    cJSON *o = cJSON_CreateObject();
    if (o == NULL) { return NULL; }
    cJSON_AddStringToObject(o, "name", n->name);
    cJSON_AddNumberToObject(o, "queries", n->queries);
    cJSON_AddNumberToObject(o, "blocked", n->blocked);
    cJSON_AddNumberToObject(o, "last", (double)(n->last + to_unix));
    cJSON_AddItemToObject(o, "owner", stat_owner_json(ctx, n));
    cJSON *cl = cJSON_AddArrayToObject(o, "clients");
    qsort(r->c, r->n, sizeof(r->c[0]), stat_cmp_clients);
    for (uint32_t i = 0; cl != NULL && i < r->n; i++) {
        cJSON *c = cJSON_CreateObject();
        put_ip(c, "address", &r->c[i].ip);
        cJSON_AddNumberToObject(c, "queries", r->c[i].queries);
        cJSON_AddItemToArray(cl, c);
    }
    cJSON_AddNumberToObject(o, "clientsTotal", n->clients);
    char *d = firc_json_dump(o);
    cJSON_Delete(o);
    return d;
}

static void handle_dnsstats(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_system_ctx_t *ctx = ud;
    stat_walk_t w;
    memset(&w, 0, sizeof(w));
    size_t offset = 0, limit = DNSSTAT_PAGE_DEFAULT;
    if (!firc_http_req_size(req, res, "offset", 0, &offset)) { return; }
    if (!firc_http_req_size(req, res, "limit", DNSSTAT_PAGE_DEFAULT, &limit)) { return; }
    if (limit == 0) { limit = DNSSTAT_PAGE_DEFAULT; }
    if (limit > DNSSTAT_PAGE_MAX) { limit = DNSSTAT_PAGE_MAX; }
    if (offset > DNSSTAT_PAGE_SPAN - limit) {
        firc_http_res_write_error(res, 400, "invalid offset: offset + limit is at most 550");
        return;
    }
    if (!stat_read_devices(req, res, &w)) { return; }
    const char *arpa = firc_http_req_query(req, "arpa");
    w.arpa = arpa != NULL && strcmp(arpa, "1") == 0;
    char needle[DNSSTAT_QUERY_VALUE_MAX + 1];
    const char *q = firc_http_req_query(req, "q");
    if (q != NULL && q[0] != '\0') {
        size_t i = 0;
        for (; q[i] != '\0' && i < DNSSTAT_QUERY_VALUE_MAX; i++) { needle[i] = (char)tolower((unsigned char)q[i]); }
        needle[i] = '\0';
        w.needle = needle;
    }

    int64_t now_mono = mono_s();
    int64_t to_unix = (int64_t)time(NULL) - now_mono;
    size_t slots = firc_dnsstat_name_slots(ctx->dnsstat);
    w.names = calloc(slots > 0 ? slots : 1, sizeof(*w.names));
    size_t k = offset + limit < slots ? offset + limit : slots;
    stat_name_t **heap = calloc(k > 0 ? k : 1, sizeof(*heap));
    if (w.names == NULL || heap == NULL) {
        free(w.names);
        free(heap);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    firc_dnsstat_each(ctx->dnsstat, now_mono, stat_aggregate, &w);
    size_t n_top = stat_select(w.names, slots, k, heap);
    size_t n_rows = n_top > offset ? n_top - offset : 0;
    w.rows = calloc(n_rows > 0 ? n_rows : 1, sizeof(*w.rows));
    if (w.rows == NULL) {
        free(w.names);
        free(heap);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    for (size_t i = 0; i < n_rows; i++) { heap[offset + i]->row = (uint32_t)(i + 1); }
    if (n_rows > 0) { firc_dnsstat_each(ctx->dnsstat, now_mono, stat_collect, &w); }

    uint64_t queries = w.queries, blocked = w.blocked;
    if (w.n_devices == 0) {
        firc_dnsstat_count_t t = firc_dnsstat_totals(ctx->dnsstat, now_mono);
        firc_dnsstat_count_t a = w.arpa ? (firc_dnsstat_count_t){0, 0} : firc_dnsstat_totals_arpa(ctx->dnsstat, now_mono);
        queries = t.queries > a.queries ? t.queries - a.queries : 0;
        blocked = t.blocked > a.blocked ? t.blocked - a.blocked : 0;
    }
    int64_t since = ctx->dnsstat != NULL ? ctx->dnsstat_since_mono + to_unix : now_mono + to_unix;
    firc_bytebuf_t b;
    firc_bytebuf_init(&b);
    char head[224];
    snprintf(head, sizeof(head),
             "{\"window\":%d,\"now\":%lld,\"since\":%lld,\"queries\":%llu,\"blocked\":%llu,\"domains\":%zu,"
             "\"rows\":[",
             FIRC_DNSSTAT_HOUR * FIRC_DNSSTAT_HOURS, (long long)(now_mono + to_unix), (long long)since,
             (unsigned long long)queries, (unsigned long long)blocked, w.domains);
    firc_err_t err = firc_bytebuf_append_str(&b, head);
    for (size_t i = 0; err == FIRC_OK && i < n_rows; i++) {
        const stat_name_t *n = heap[offset + i];
        char *d = stat_row_dump(ctx, n, &w.rows[n->row - 1], to_unix);
        if (d == NULL) {
            err = FIRC_ERR_NOMEM;
            break;
        }
        if (i > 0) { err = firc_bytebuf_append_byte(&b, ','); }
        if (err == FIRC_OK) { err = firc_bytebuf_append_str(&b, d); }
        free(d);
    }
    if (err == FIRC_OK) {
        char tail[96];
        snprintf(tail, sizeof(tail), "],\"matched\":%zu,\"offset\":%zu}", w.matched, offset);
        err = firc_bytebuf_append_str(&b, tail);
    }
    free(w.names);
    free(heap);
    free(w.rows);
    firc_http_res_take_json(res, &b, err);
}

void firc_system_register_routes(firc_httpd_t *h, firc_system_ctx_t *ctx) {
    must_route(h, "GET", "/api/v1/system/interfaces", handle_list_interfaces, ctx);
    must_route(h, "GET", "/api/v1/system/events", handle_events, ctx);
    must_route(h, "GET", "/api/v1/system/dnsstats", handle_dnsstats, ctx);
    must_route(h, "GET", "/api/v1/system/policies", handle_policies, ctx);
    must_route(h, "GET", "/api/v1/system/hosts", handle_hosts, ctx);
    must_route(h, "GET", "/api/v1/system/resolvers", handle_resolvers, ctx);
    must_route(h, "GET", "/api/v1/system/netfilter", handle_netfilter, ctx);
    must_route(h, "POST", "/api/v1/system/config/save", handle_save_config, ctx);
    must_route(h, "POST", "/api/v1/system/hooks/netfilterd", handle_netfilterd_hook, ctx);
    must_route(h, "POST", "/api/v1/system/hooks/iflayer", handle_iflayer_hook, ctx);
    firc_settings_register_routes(h, ctx);
}
