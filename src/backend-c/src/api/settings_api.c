#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "firc/duration.h"
#include "firc/events.h"
#include "firc/listen.h"
#include "firc/log.h"
#include "firc/paths.h"
#include "firc/settings.h"
#include "firc/spawn.h"
#include "firc/system.h"

static void must_route(firc_httpd_t *h, const char *method, const char *pattern,
                       firc_http_handler_fn fn, void *ud) {
    if (firc_httpd_route(h, method, pattern, fn, ud) != FIRC_OK) {
        FIRC_ERROR("failed to register route %s %s", method, pattern);
    }
}

#define HOUR_NS (INT64_C(3600) * FIRC_DURATION_SEC)

static firc_duration_t unit_of(firc_setting_kind_t kind) {
    switch (kind) {
    case FIRC_SK_MS: return FIRC_DURATION_MS;
    case FIRC_SK_SEC: return FIRC_DURATION_SEC;
    case FIRC_SK_HOURS: return HOUR_NS;
    default: return 1;
    }
}

static const void *slot(const firc_app_config_t *c, size_t off) { return (const char *)c + off; }
static void *slot_mut(firc_app_config_t *c, size_t off) { return (char *)c + off; }

static cJSON *value_json(const firc_setting_t *s, const firc_app_config_t *c) {
    const void *v = slot(c, s->off);
    switch (s->kind) {
    case FIRC_SK_BOOL: return cJSON_CreateBool(*(const bool *)v);
    case FIRC_SK_ADDR:
    case FIRC_SK_STRING: {
        const char *text = *(char *const *)v;
        return cJSON_CreateString(text != NULL ? text : "");
    }
    case FIRC_SK_PORT: return cJSON_CreateNumber(*(const uint16_t *)v);
    case FIRC_SK_U64: return cJSON_CreateNumber((double)*(const uint64_t *)v);
    case FIRC_SK_U32: return cJSON_CreateNumber(*(const uint32_t *)v);
    case FIRC_SK_CHUNK: return cJSON_CreateNumber(*(const uint8_t *)v);
    case FIRC_SK_HEX32: {
        char hex[16];
        snprintf(hex, sizeof(hex), "0x%" PRIx32, *(const uint32_t *)v);
        return cJSON_CreateString(hex);
    }
    case FIRC_SK_MS:
    case FIRC_SK_SEC:
    case FIRC_SK_HOURS:
        return cJSON_CreateNumber((double)(*(const firc_duration_t *)v / unit_of(s->kind)));
    case FIRC_SK_LIST: {
        size_t n = *(const size_t *)slot(c, s->off_n);
        char *const *list = *(char **const *)v;
        cJSON *arr = cJSON_CreateArray();
        for (size_t i = 0; arr != NULL && i < n; i++) {
            cJSON_AddItemToArray(arr, cJSON_CreateString(list[i] != NULL ? list[i] : ""));
        }
        return arr;
    }
    }
    return NULL;
}

/* a double cast outside its target's range is undefined, so the range is checked on the double first */
static bool whole(const cJSON *j, double max, uint64_t *out) {
    if (!cJSON_IsNumber(j)) { return false; }
    double d = j->valuedouble;
    if (!(d >= 0.0 && d <= max)) { return false; }
    uint64_t u = (uint64_t)d;
    if ((double)u != d) { return false; }
    *out = u;
    return true;
}

static bool hex32(const char *s, uint32_t *out) {
    if (s == NULL || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) { return false; }
    const char *p = s + 2;
    size_t n = strlen(p);
    if (n == 0 || n > 8) { return false; }
    uint32_t v = 0;
    for (; *p != '\0'; p++) {
        uint32_t d;
        if (*p >= '0' && *p <= '9') {
            d = (uint32_t)(*p - '0');
        } else if (*p >= 'a' && *p <= 'f') {
            d = (uint32_t)(*p - 'a' + 10);
        } else if (*p >= 'A' && *p <= 'F') {
            d = (uint32_t)(*p - 'A' + 10);
        } else {
            return false;
        }
        v = (v << 4) | d;
    }
    *out = v;
    return true;
}

static const char WHOLE_WHY[] = "must be a whole number in the setting's range";

static firc_err_t list_from_json(const firc_setting_t *s, const cJSON *j, firc_app_config_t *dst,
                                 const char **why) {
    static const char LIST_WHY[] = "must be a list of strings";
    if (!cJSON_IsArray(j)) {
        *why = LIST_WHY;
        return FIRC_ERR_INVAL;
    }
    int count = cJSON_GetArraySize(j);
    char **list = calloc(count > 0 ? (size_t)count : 1, sizeof(char *));
    if (list == NULL) { return FIRC_ERR_NOMEM; }
    size_t k = 0;
    firc_err_t err = FIRC_OK;
    const cJSON *e;
    cJSON_ArrayForEach(e, j) {
        if (!cJSON_IsString(e)) {
            *why = LIST_WHY;
            err = FIRC_ERR_INVAL;
            break;
        }
        list[k] = strdup(e->valuestring);
        if (list[k] == NULL) {
            err = FIRC_ERR_NOMEM;
            break;
        }
        k++;
    }
    if (err != FIRC_OK) {
        for (size_t i = 0; i < k; i++) { free(list[i]); }
        free(list);
        return err;
    }
    char ***to = (char ***)slot_mut(dst, s->off);
    size_t *to_n = (size_t *)slot_mut(dst, s->off_n);
    for (size_t i = 0; i < *to_n; i++) { free((*to)[i]); }
    free(*to);
    *to = list;
    *to_n = k;
    return FIRC_OK;
}

/* checks shape only; whether the value is acceptable is firc_app_config_check's question */
static firc_err_t value_from_json(const firc_setting_t *s, const cJSON *j, firc_app_config_t *dst,
                                  const char **why) {
    void *v = slot_mut(dst, s->off);
    uint64_t u = 0;
    switch (s->kind) {
    case FIRC_SK_BOOL:
        if (!cJSON_IsBool(j)) {
            *why = "must be true or false";
            return FIRC_ERR_INVAL;
        }
        *(bool *)v = cJSON_IsTrue(j);
        return FIRC_OK;
    case FIRC_SK_ADDR:
    case FIRC_SK_STRING:
        if (!cJSON_IsString(j)) {
            *why = "must be a string";
            return FIRC_ERR_INVAL;
        }
        return firc_strset((char **)v, j->valuestring);
    case FIRC_SK_PORT:
        if (!whole(j, 65535.0, &u)) { break; }
        *(uint16_t *)v = (uint16_t)u;
        return FIRC_OK;
    case FIRC_SK_CHUNK:
        if (!whole(j, 128.0, &u)) { break; }
        *(uint8_t *)v = (uint8_t)u;
        return FIRC_OK;
    case FIRC_SK_U32:
        if (!whole(j, 4294967295.0, &u)) { break; }
        *(uint32_t *)v = (uint32_t)u;
        return FIRC_OK;
    case FIRC_SK_U64:
        if (!whole(j, 9007199254740992.0, &u)) { break; } /* 2^53: past it a JSON number is no longer exact */
        *(uint64_t *)v = u;
        return FIRC_OK;
    case FIRC_SK_HEX32: {
        uint32_t x = 0;
        if (!cJSON_IsString(j) || !hex32(j->valuestring, &x)) {
            *why = "must be a hex number such as 0x66697263";
            return FIRC_ERR_INVAL;
        }
        *(uint32_t *)v = x;
        return FIRC_OK;
    }
    case FIRC_SK_MS:
    case FIRC_SK_SEC:
    case FIRC_SK_HOURS: {
        firc_duration_t unit = unit_of(s->kind);
        if (!whole(j, (double)(INT64_MAX / unit), &u)) { break; } /* bounds u*unit below overflow */
        *(firc_duration_t *)v = (firc_duration_t)u * unit;
        return FIRC_OK;
    }
    case FIRC_SK_LIST: return list_from_json(s, j, dst, why);
    }
    *why = WHOLE_WHY;
    return FIRC_ERR_INVAL;
}

static cJSON *pending_json(const firc_app_t *app) {
    bool pending[FIRC_SETTINGS_COUNT];
    (void)firc_app_pending_restart(app, pending);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; arr != NULL && i < FIRC_SETTINGS_COUNT; i++) {
        if (pending[i]) { cJSON_AddItemToArray(arr, cJSON_CreateString(firc_settings[i].path)); }
    }
    return arr;
}

typedef struct listener {
    const char *addr_key, *port_key;
    const char *addr;
    uint16_t port;
    bool empty_is_any;
    unsigned tcp_opts, udp_opts;
    bool udp;
    bool own_port_ok; /* EADDRINUSE on this listener's own running port is let through; WebUI only */
    bool run_on; /* what the daemon runs with; false if it holds no such socket */
    const char *run_addr;
    uint16_t run_port;
} listener_t;

static firc_err_t probe_one(const listener_t *l, const char **field, char *why, size_t cap) {
    struct sockaddr_storage sa, run;
    socklen_t len = 0, run_len = 0;
    if (!firc_listen_addr(l->addr, l->port, l->empty_is_any, &sa, &len)) { return FIRC_OK; }
    if (l->run_on && firc_listen_addr(l->run_addr, l->run_port, l->empty_is_any, &run, &run_len) &&
        run_len == len && memcmp(&run, &sa, len) == 0) {
        return FIRC_OK;
    }
    static const int types[] = {SOCK_STREAM, SOCK_DGRAM};
    for (size_t i = 0; i < (l->udp ? 2u : 1u); i++) {
        int fd = firc_listen_open(types[i], &sa, len, i == 0 ? l->tcp_opts : l->udp_opts);
        if (fd >= 0) {
            close(fd);
            continue;
        }
        int e = -fd;
        if (e == EADDRINUSE && l->own_port_ok && l->run_on && l->port == l->run_port) {
            continue; /* the kernel can't tell our own running socket from another holder here */
        }
        if (e == EADDRNOTAVAIL) {
            *field = l->addr_key;
            snprintf(why, cap, "%s is not an address of this router", l->addr);
        } else if (e == EINVAL) {
            *field = l->addr_key;
            snprintf(why, cap, "%s cannot be listened on: %s", l->addr, strerror(e));
        } else if (e == EADDRINUSE) {
            *field = l->port_key;
            snprintf(why, cap, "%u is already in use on this router", l->port);
        } else {
            *field = l->port_key;
            snprintf(why, cap, "%u cannot be listened on: %s", l->port, strerror(e));
        }
        return FIRC_ERR_INVAL;
    }
    return FIRC_OK;
}

firc_err_t firc_settings_probe_listeners(const firc_app_config_t *next,
                                         const firc_app_config_t *running, const char **field,
                                         char *why, size_t why_cap) {
    const listener_t web = {
        .addr_key = "app.httpWeb.host.address", .port_key = "app.httpWeb.host.port",
        .addr = next->http_web.host.address, .port = next->http_web.host.port,
        .empty_is_any = true, .tcp_opts = FIRC_WEB_LISTEN, .udp = false, .own_port_ok = true,
        .run_on = running->http_web.enabled, .run_addr = running->http_web.host.address,
        .run_port = running->http_web.host.port,
    };
    const listener_t dns = {
        .addr_key = "app.dnsProxy.host.address", .port_key = "app.dnsProxy.host.port",
        .addr = next->dns_proxy.host.address, .port = next->dns_proxy.host.port,
        .empty_is_any = false, .tcp_opts = FIRC_DNS_TCP_LISTEN, .udp_opts = FIRC_DNS_UDP_LISTEN,
        .udp = true, .own_port_ok = false,
        .run_on = true, .run_addr = running->dns_proxy.host.address,
        .run_port = running->dns_proxy.host.port,
    };
    firc_err_t err = next->http_web.enabled ? probe_one(&web, field, why, why_cap) : FIRC_OK;
    return err == FIRC_OK ? probe_one(&dns, field, why, why_cap) : err;
}

static bool restart_under_way(firc_system_ctx_t *ctx);

static void handle_get_settings(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    firc_system_ctx_t *ctx = ud;
    const firc_app_config_t *saved = firc_app_saved_settings(ctx->app);
    cJSON *out = cJSON_CreateObject();
    cJSON *values = cJSON_AddObjectToObject(out, "settings");
    cJSON *classes = cJSON_AddObjectToObject(out, "classes");
    if (values == NULL || classes == NULL ||
        cJSON_AddStringToObject(out, "boot", firc_event_boot()) == NULL ||
        cJSON_AddBoolToObject(out, "restarting", restart_under_way(ctx)) == NULL ||
        !cJSON_AddItemToObject(out, "pendingRestart", pending_json(ctx->app))) {
        cJSON_Delete(out);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
        const firc_setting_t *s = &firc_settings[i];
        cJSON_AddItemToObject(values, s->path, value_json(s, saved));
        cJSON_AddStringToObject(classes, s->path, s->cls == FIRC_SETTING_LIVE ? "live" : "restart");
    }
    firc_http_res_write_json(res, 200, out);
}

static void handle_put_settings(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    firc_system_ctx_t *ctx = ud;
    size_t body_len = 0;
    const uint8_t *body = firc_http_req_body(req, &body_len);
    cJSON *json = body_len > 0 ? cJSON_ParseWithLength((const char *)body, body_len) : NULL;
    const cJSON *changes = cJSON_GetObjectItemCaseSensitive(json, "settings");
    if (!cJSON_IsObject(changes)) {
        cJSON_Delete(json);
        firc_http_res_write_error(res, 400, "the body is {\"settings\": {\"<yaml path>\": <value>}}");
        return;
    }

    firc_app_config_t next;
    memset(&next, 0, sizeof(next));
    firc_err_t err = firc_app_config_copy(&next, firc_app_saved_settings(ctx->app));
    const char *field = NULL, *why = NULL;
    const cJSON *e;
    cJSON_ArrayForEach(e, changes) {
        if (err != FIRC_OK) { break; }
        const firc_setting_t *s = firc_setting_find(e->string);
        if (s == NULL) {
            field = e->string;
            why = "not a setting";
            err = FIRC_ERR_INVAL;
            break;
        }
        err = value_from_json(s, e, &next, &why);
        if (err == FIRC_ERR_INVAL) { field = s->path; }
    }
    if (err == FIRC_OK) { err = firc_app_config_check(&next, &field, &why); }
    char probe_why[160];
    if (err == FIRC_OK) {
        err = firc_settings_probe_listeners(&next, firc_app_running_settings(ctx->app), &field,
                                            probe_why, sizeof(probe_why));
        if (err == FIRC_ERR_INVAL) { why = probe_why; }
    }

    if (err == FIRC_ERR_INVAL) {
        firc_http_res_write_field_error(res, 400, why, field); /* before json goes: field may be its */
    } else if (err != FIRC_OK) {
        firc_http_res_write_error(res, 500, firc_err_str(err));
    } else {
        bool applied[FIRC_SETTINGS_COUNT];
        firc_err_t live_err = FIRC_OK;
        err = firc_app_put_settings(ctx->app, &next, ctx->config_path,
                                    ctx->config_version != NULL ? ctx->config_version : "", applied,
                                    &live_err);
        if (err != FIRC_OK) {
            FIRC_ERROR("settings: firc.conf not written: %s", firc_err_str(err));
            firc_http_res_write_error(res, 500, firc_err_str(err));
        } else if (live_err != FIRC_OK) {
            char msg[160]; /* saved but not running: a 200 would tell the page it applied */
            snprintf(msg, sizeof(msg),
                     "saved to firc.conf, but a live setting could not be applied (%s); it applies "
                     "at the next restart",
                     firc_err_str(live_err));
            firc_http_res_write_error(res, 500, msg);
        } else {
            cJSON *out = cJSON_CreateObject();
            cJSON *arr = cJSON_AddArrayToObject(out, "applied");
            for (size_t i = 0; arr != NULL && i < FIRC_SETTINGS_COUNT; i++) {
                if (applied[i]) { cJSON_AddItemToArray(arr, cJSON_CreateString(firc_settings[i].path)); }
            }
            if (arr == NULL || !cJSON_AddItemToObject(out, "pendingRestart", pending_json(ctx->app))) {
                cJSON_Delete(out);
                firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
            } else {
                firc_http_res_write_json(res, 200, out);
            }
        }
    }
    firc_app_config_clear(&next); /* zeroed if the PUT took it */
    cJSON_Delete(json);
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void spawn_restart(void *ud) {
    firc_system_ctx_t *ctx = ud;
    const char *script = ctx->init_script != NULL ? ctx->init_script : FIRC_INIT_SCRIPT;
    firc_err_t err = firc_spawn_detached(script, "restart");
    if (err != FIRC_OK) {
        FIRC_ERROR("restart: %s restart could not be started: %s", script, firc_err_str(err));
        ctx->restart_started_ms = 0;
        return;
    }
    FIRC_INFO("restart: %s restart is under way", script);
}

static bool restart_under_way(firc_system_ctx_t *ctx) {
    if (ctx->restart_started_ms == 0) { return false; }
    int64_t limit = ctx->restart_timeout_ms > 0 ? ctx->restart_timeout_ms : FIRC_RESTART_TIMEOUT_MS;
    if (mono_ms() - ctx->restart_started_ms < limit) { return true; }
    FIRC_WARN("restart: the one asked for %lld ms ago did not stop this daemon; a new one may be asked for",
              (long long)(mono_ms() - ctx->restart_started_ms));
    ctx->restart_started_ms = 0;
    return false;
}

static void handle_restart(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    firc_system_ctx_t *ctx = ud;
    if (restart_under_way(ctx)) {
        firc_http_res_write_error(res, 409, "a restart is already under way");
        return;
    }
    cJSON *out = cJSON_CreateObject();
    if (out == NULL || cJSON_AddBoolToObject(out, "restarting", true) == NULL) {
        cJSON_Delete(out);
        firc_http_res_write_error(res, 500, firc_err_str(FIRC_ERR_NOMEM));
        return;
    }
    ctx->restart_started_ms = mono_ms();
    firc_http_res_write_json(res, 202, out);
    firc_http_res_after_sent(res, spawn_restart, ctx);
}

void firc_settings_register_routes(firc_httpd_t *h, firc_system_ctx_t *ctx) {
    must_route(h, "GET", "/api/v1/system/settings", handle_get_settings, ctx);
    must_route(h, "PUT", "/api/v1/system/settings", handle_put_settings, ctx);
    must_route(h, "POST", "/api/v1/system/restart", handle_restart, ctx);
}
