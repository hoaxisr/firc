#include "firc/list_catalog.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>

#include "firc/json.h"
#include "firc/loop.h"
#include "firc/sub_fetch.h"

#include "groups_internal.h"

#define SOURCE_URL_PREFIX "https://raw.githubusercontent.com/"
#define ID_MAX 32
#define NAME_MAX_LEN 128
#define PROVIDER_NAME_MAX 32
#define PROVIDERS_MAX 64

static firc_err_t refuse(char *why, size_t cap, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static firc_err_t refuse(char *why, size_t cap, const char *fmt, ...) {
    if (why != NULL && cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(why, cap, fmt, ap);
        va_end(ap);
    }
    return FIRC_ERR_INVAL;
}

bool firc_list_catalog_id_ok(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > ID_MAX) { return false; }
    for (; *s != '\0'; s++) {
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '-')) { return false; }
    }
    return true;
}

static bool name_ok(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > NAME_MAX_LEN) { return false; }
    for (; *s != '\0'; s++) {
        char c = *s;
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                  c == '_' || c == '@' || c == '!' || c == '-';
        if (!ok) { return false; }
    }
    return true;
}

static int count_braces(const char *url) {
    int n = 0;
    for (const char *p = url; (p = strstr(p, "{}")) != NULL; p += 2) { n++; }
    return n;
}

/* a provider's file carries only that provider's sources: its id, or its id and a dash */
static bool belongs_to(const char *id, const char *provider) {
    size_t n = strlen(provider);
    return strncmp(id, provider, n) == 0 && (id[n] == '\0' || id[n] == '-');
}

/* printable, no control byte: the WebUI shows it as text */
static bool provider_name_ok(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > PROVIDER_NAME_MAX) { return false; }
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7f) { return false; }
    }
    return true;
}

static firc_err_t check_providers(const cJSON *providers, cJSON *res, char *why, size_t cap) {
    if (!cJSON_IsArray(providers)) { return refuse(why, cap, "providers is not an array"); }
    if (cJSON_GetArraySize(providers) > PROVIDERS_MAX) {
        return refuse(why, cap, "more than %d providers", PROVIDERS_MAX);
    }
    cJSON *list = cJSON_AddArrayToObject(res, "providers");
    if (list == NULL) { return FIRC_ERR_NOMEM; }
    int at = 0;
    const cJSON *p;
    cJSON_ArrayForEach(p, providers) {
        at++;
        const cJSON *id = cJSON_GetObjectItemCaseSensitive(p, "id");
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(p, "name");
        if (!cJSON_IsString(id) || !firc_list_catalog_id_ok(id->valuestring)) {
            return refuse(why, cap, "provider %d has no valid id", at);
        }
        if (!cJSON_IsString(name) || !provider_name_ok(name->valuestring)) {
            return refuse(why, cap, "provider %s has no valid name", id->valuestring);
        }
        const cJSON *seen;
        cJSON_ArrayForEach(seen, list) {
            if (strcmp(cJSON_GetObjectItemCaseSensitive(seen, "id")->valuestring, id->valuestring) == 0) {
                return refuse(why, cap, "provider %s is listed twice", id->valuestring);
            }
        }
        cJSON *dst = cJSON_CreateObject();
        if (dst == NULL) { return FIRC_ERR_NOMEM; }
        cJSON_AddItemToArray(list, dst);
        if (!cJSON_AddStringToObject(dst, "id", id->valuestring) ||
            !cJSON_AddStringToObject(dst, "name", name->valuestring)) {
            return FIRC_ERR_NOMEM;
        }
    }
    return FIRC_OK;
}

static firc_err_t check_source(const cJSON *src, int at, const char *provider, cJSON *dst, char *why, size_t cap) {
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(src, "id");
    const cJSON *url = cJSON_GetObjectItemCaseSensitive(src, "url");
    const cJSON *names = cJSON_GetObjectItemCaseSensitive(src, "names");
    if (!cJSON_IsString(id) || !firc_list_catalog_id_ok(id->valuestring)) {
        return refuse(why, cap, "source %d has no valid id", at + 1);
    }
    if (provider != NULL && !belongs_to(id->valuestring, provider)) {
        return refuse(why, cap, "source %s is not one of %s", id->valuestring, provider);
    }
    if (!cJSON_IsString(url)) { return refuse(why, cap, "source %d has no url", at + 1); }
    if (!firc_sub_url_is_supported(url->valuestring) ||
        strncmp(url->valuestring, SOURCE_URL_PREFIX, strlen(SOURCE_URL_PREFIX)) != 0) {
        return refuse(why, cap, "source %d has no url on raw.githubusercontent.com", at + 1);
    }
    int braces = count_braces(url->valuestring);
    if (braces == 0) { return refuse(why, cap, "source %d has no {} in its url", at + 1); }
    if (braces > 1) { return refuse(why, cap, "source %d has more than one {} in its url", at + 1); }
    if (!cJSON_IsArray(names)) { return refuse(why, cap, "source %d has no names array", at + 1); }
    int i = 0;
    const cJSON *name;
    cJSON_ArrayForEach(name, names) {
        if (!cJSON_IsString(name) || !name_ok(name->valuestring)) {
            return refuse(why, cap, "name %d of %s is not a rule-set name", i + 1, id->valuestring);
        }
        i++;
    }
    if (!cJSON_AddStringToObject(dst, "id", id->valuestring) ||
        !cJSON_AddStringToObject(dst, "url", url->valuestring)) {
        return FIRC_ERR_NOMEM;
    }
    cJSON *copy = cJSON_Duplicate(names, true);
    if (copy == NULL) { return FIRC_ERR_NOMEM; }
    if (!cJSON_AddItemToObject(dst, "names", copy)) {
        cJSON_Delete(copy);
        return FIRC_ERR_NOMEM;
    }
    return FIRC_OK;
}

firc_err_t firc_list_catalog_parse(const char *body, size_t len, const char *provider, cJSON **out, char *why,
                                   size_t why_cap) {
    *out = NULL;
    cJSON *root = cJSON_ParseWithLength(body, len);
    if (root == NULL) { return refuse(why, why_cap, "not JSON"); }
    const cJSON *sources = cJSON_GetObjectItemCaseSensitive(root, "sources");
    if (!cJSON_IsArray(sources)) {
        cJSON_Delete(root);
        return refuse(why, why_cap, "sources is not an array");
    }
    const cJSON *gen = cJSON_GetObjectItemCaseSensitive(root, "generated");
    cJSON *res = cJSON_CreateObject();
    cJSON *list = res != NULL ? cJSON_AddArrayToObject(res, "sources") : NULL;
    if (list == NULL || !cJSON_AddStringToObject(res, "generated", cJSON_IsString(gen) ? gen->valuestring : "")) {
        cJSON_Delete(res);
        cJSON_Delete(root);
        return FIRC_ERR_NOMEM;
    }
    firc_err_t err = FIRC_OK;
    int at = 0;
    const cJSON *src;
    cJSON_ArrayForEach(src, sources) {
        cJSON *dst = cJSON_CreateObject();
        if (dst == NULL) {
            err = FIRC_ERR_NOMEM;
            break;
        }
        cJSON_AddItemToArray(list, dst);
        err = check_source(src, at++, provider, dst, why, why_cap);
        if (err != FIRC_OK) { break; }
    }
    const cJSON *providers = cJSON_GetObjectItemCaseSensitive(root, "providers");
    if (err == FIRC_OK && provider == NULL && providers != NULL) {
        err = check_providers(providers, res, why, why_cap);
    }
    cJSON_Delete(root);
    if (err != FIRC_OK) {
        cJSON_Delete(res);
        return err;
    }
    *out = res;
    return FIRC_OK;
}

bool firc_list_catalog_provider_url(const char *base, const char *provider, char *buf, size_t cap) {
    if (!firc_list_catalog_id_ok(provider)) { return false; }
    const char *scheme = strstr(base, "://");
    const char *slash = strrchr(base, '/');
    if (scheme == NULL || slash == NULL || slash < scheme + 3) { return false; }
    int n = snprintf(buf, cap, "%.*scatalog/%s.json", (int)(slash - base + 1), base, provider);
    return n > 0 && (size_t)n < cap;
}

#define CATALOG_FRESH_MS ((uint64_t)6 * 3600 * 1000)
#define CATALOG_FAILED_MS ((uint64_t)60 * 1000)
#define CATALOG_WHY_CAP 256
#define CATALOG_REASON_CAP (CURL_ERROR_SIZE + CATALOG_WHY_CAP)

typedef struct catalog_waiter catalog_waiter_t;
typedef struct catalog_fetch catalog_fetch_t;

struct catalog_waiter {
    list_catalog_t *cat;
    catalog_waiter_t *next;
    firc_http_deferred_t *d;
    char provider[ID_MAX + 1]; /* provider to serve once the index is available */
};

struct catalog_fetch {
    list_catalog_t *cat;
    firc_loop_t *loop;
    pthread_t thread;
    char *url;
    char provider[ID_MAX + 1]; /* "" for the index; a copy, so the thread never reads the slot */
    atomic_bool stopping;
    bool posted;
    bool joined;
    cJSON *parsed;
    firc_err_t err;
    char reason[CATALOG_REASON_CAP];
};

/* One per catalog asked for: the index (provider "") and each provider's file, kept apart. */
struct list_catalog {
    firc_groups_ctx_t *ctx;
    list_catalog_t *next;
    char provider[ID_MAX + 1];
    cJSON *copy;
    uint64_t used_ms;
    uint64_t fetched_ms;
    double fetched_at;
    bool failed;
    uint64_t failed_ms;
    char reason[CATALOG_REASON_CAP];
    catalog_fetch_t *fetch;
    catalog_waiter_t *waiters;
};

static uint64_t catalog_now(const firc_groups_ctx_t *ctx) {
    if (ctx->catalog_now_ms != NULL) { return ctx->catalog_now_ms(); }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void fetch_free(catalog_fetch_t *f) {
    free(f->url);
    cJSON_Delete(f->parsed);
    free(f);
}

static bool fetch_progress(void *ud, size_t bytes, size_t total) {
    (void)bytes;
    (void)total;
    catalog_fetch_t *f = ud;
    return !atomic_load(&f->stopping);
}

static void fetch_done(firc_loop_t *loop, void *ud);

static void fetch_drop(void *ud) {
    catalog_fetch_t *f = ud;
    if (!f->joined) {
        pthread_join(f->thread, NULL);
        f->joined = true;
    }
    fetch_free(f);
}

static void *fetch_thread(void *arg) {
    catalog_fetch_t *f = arg;
    char *body = NULL;
    size_t len = 0;
    long status = 0;
    char errbuf[CURL_ERROR_SIZE] = "";
    f->err = firc_sub_fetch_list_opts(f->url, FIRC_LIST_CATALOG_MAX_BYTES, &body, &len, fetch_progress, f, &status,
                                      errbuf, sizeof errbuf);
    if (f->err != FIRC_OK) {
        firc_sub_fetch_reason(f->err, status, errbuf, f->reason, sizeof f->reason);
    } else {
        char why[CATALOG_WHY_CAP] = "";
        f->err = firc_list_catalog_parse(body, len, f->provider[0] != '\0' ? f->provider : NULL, &f->parsed, why,
                                         sizeof why);
        if (f->err == FIRC_ERR_INVAL) {
            snprintf(f->reason, sizeof f->reason, "catalog refused: %s", why);
        } else if (f->err != FIRC_OK) {
            snprintf(f->reason, sizeof f->reason, "%s", firc_err_str(f->err));
        }
    }
    free(body);
    f->posted = true;
    while (firc_loop_post_with_drop(f->loop, fetch_done, f, fetch_drop) != FIRC_OK) {
        if (atomic_load(&f->stopping)) {
            f->posted = false;
            return NULL;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static uint8_t *catalog_answer(const list_catalog_t *cat, int *status, size_t *len) {
    cJSON *obj;
    if (cat->copy != NULL) {
        *status = 200;
        obj = cJSON_CreateObject();
        bool ok = obj != NULL &&
                  cJSON_AddItemReferenceToObject(obj, "generated",
                                                 cJSON_GetObjectItemCaseSensitive(cat->copy, "generated")) &&
                  cJSON_AddNumberToObject(obj, "fetchedAt", cat->fetched_at) != NULL &&
                  cJSON_AddBoolToObject(obj, "stale", cat->failed) != NULL &&
                  cJSON_AddItemReferenceToObject(obj, "sources",
                                                 cJSON_GetObjectItemCaseSensitive(cat->copy, "sources"));
        const cJSON *providers = cJSON_GetObjectItemCaseSensitive(cat->copy, "providers");
        if (ok && providers != NULL) { ok = cJSON_AddItemReferenceToObject(obj, "providers", (cJSON *)providers); }
        if (!ok) {
            cJSON_Delete(obj);
            obj = NULL;
        }
    } else {
        *status = 502;
        obj = firc_json_error(cat->reason);
    }
    char *dump = obj != NULL ? firc_json_dump(obj) : NULL;
    cJSON_Delete(obj);
    if (dump == NULL) {
        static const char fallback[] = "{\"error\":\"failed to encode response\"}";
        *status = 500;
        dump = strdup(fallback);
    }
    *len = dump != NULL ? strlen(dump) : 0;
    return (uint8_t *)dump;
}

static void catalog_serve(firc_groups_ctx_t *ctx, const char *provider, firc_loop_t *loop,
                          firc_http_res_t *res, catalog_waiter_t *w);

static void finish_waiter(catalog_waiter_t *w, int status, uint8_t *body, size_t len) {
    firc_http_deferred_finish(w->d, status, "application/json; charset=utf-8", body, len);
    free(w);
}

static void fetch_done(firc_loop_t *loop, void *ud) {
    catalog_fetch_t *f = ud;
    pthread_join(f->thread, NULL);
    f->joined = true;
    list_catalog_t *cat = f->cat;
    cat->fetch = NULL;
    uint64_t now = catalog_now(cat->ctx);
    cat->used_ms = now;
    if (f->err == FIRC_OK) {
        cJSON_Delete(cat->copy);
        cat->copy = f->parsed;
        f->parsed = NULL;
        cat->fetched_ms = now;
        cat->fetched_at = (double)time(NULL);
        cat->failed = false;
    } else {
        cat->failed = true;
        cat->failed_ms = now;
        snprintf(cat->reason, sizeof cat->reason, "%s", f->reason);
        FIRC_WARN("failed to fetch the list catalog: %s", f->reason);
    }
    fetch_free(f);
    catalog_waiter_t *w = cat->waiters;
    cat->waiters = NULL;
    while (w != NULL) {
        catalog_waiter_t *next = w->next;
        if (w->provider[0] != '\0' && cat->copy != NULL) {
            catalog_serve(cat->ctx, w->provider, loop, NULL, w);
        } else {
            int status;
            size_t len;
            uint8_t *body = catalog_answer(cat, &status, &len);
            finish_waiter(w, status, body, len);
        }
        w = next;
    }
}

static void waiter_left(void *ud) {
    catalog_waiter_t *w = ud;
    for (catalog_waiter_t **link = &w->cat->waiters; *link != NULL; link = &(*link)->next) {
        if (*link == w) {
            *link = w->next;
            break;
        }
    }
    firc_http_deferred_drop(w->d);
    free(w);
}

static bool fetch_start(list_catalog_t *cat, firc_loop_t *loop) {
    catalog_fetch_t *f = calloc(1, sizeof(*f));
    const char *base = cat->ctx->catalog_url != NULL ? cat->ctx->catalog_url : FIRC_LIST_CATALOG_URL;
    char url[512];
    bool url_ok = cat->provider[0] == '\0'
                      ? snprintf(url, sizeof url, "%s", base) < (int)sizeof url
                      : firc_list_catalog_provider_url(base, cat->provider, url, sizeof url);
    if (f != NULL && url_ok) { f->url = strdup(url); }
    if (f == NULL || f->url == NULL) {
        free(f);
        return false;
    }
    snprintf(f->provider, sizeof f->provider, "%s", cat->provider);
    f->cat = cat;
    f->loop = loop;
    atomic_init(&f->stopping, false);
    if (pthread_create(&f->thread, NULL, fetch_thread, f) != 0) {
        fetch_free(f);
        return false;
    }
    cat->fetch = f;
    return true;
}

static void catalog_free(list_catalog_t *cat) {
    cJSON_Delete(cat->copy);
    free(cat);
}

static list_catalog_t *find_catalog(const firc_groups_ctx_t *ctx, const char *provider) {
    for (list_catalog_t *c = ctx->catalog; c != NULL; c = c->next) {
        if (strcmp(c->provider, provider) == 0) { return c; }
    }
    return NULL;
}

/* No upstream request or slot is needed for an id the index did not advertise. */
static bool provider_listed(const cJSON *index, const char *id) {
    const cJSON *source;
    cJSON_ArrayForEach(source, cJSON_GetObjectItemCaseSensitive(index, "sources")) {
        if (strcmp(get_string(source, "id"), id) == 0) { return false; }
    }
    const cJSON *provider;
    cJSON_ArrayForEach(provider, cJSON_GetObjectItemCaseSensitive(index, "providers")) {
        if (strcmp(get_string(provider, "id"), id) == 0) { return true; }
    }
    return false;
}

static void sweep_catalogs(firc_loop_t *loop, void *ud) {
    firc_groups_ctx_t *ctx = ud;
    uint64_t now = catalog_now(ctx);
    bool has_providers = false;
    for (list_catalog_t **link = &ctx->catalog; *link != NULL;) {
        list_catalog_t *c = *link;
        bool optional = c->provider[0] != '\0';
        uint64_t ttl = c->copy != NULL ? CATALOG_FRESH_MS : CATALOG_FAILED_MS;
        if (optional && c->fetch == NULL && now - c->used_ms >= ttl) {
            *link = c->next;
            catalog_free(c);
        } else {
            has_providers |= optional;
            link = &c->next;
        }
    }
    if (!has_providers) {
        firc_loop_del_timer(loop, ctx->catalog_timer);
        ctx->catalog_loop = NULL;
    }
}

/* Reuse an idle slot at capacity. Only overlapping downloads can exhaust all slots. */
static list_catalog_t *catalog_slot(firc_groups_ctx_t *ctx, const char *provider, bool *full) {
    list_catalog_t **oldest = NULL;
    int providers = 0;
    for (list_catalog_t **link = &ctx->catalog; *link != NULL; link = &(*link)->next) {
        list_catalog_t *c = *link;
        if (strcmp(c->provider, provider) == 0) { return c; }
        if (c->provider[0] == '\0') { continue; }
        providers++;
        if (c->fetch == NULL && (oldest == NULL || c->used_ms <= (*oldest)->used_ms)) { oldest = link; }
    }
    if (provider[0] != '\0' && providers >= FIRC_LIST_CATALOG_PROVIDERS_MAX) {
        if (oldest == NULL) {
            *full = true;
            return NULL;
        }
        list_catalog_t *evicted = *oldest;
        *oldest = evicted->next;
        catalog_free(evicted);
    }
    list_catalog_t *cat = calloc(1, sizeof(*cat));
    if (cat == NULL) { return NULL; }
    cat->ctx = ctx;
    snprintf(cat->provider, sizeof cat->provider, "%s", provider);
    cat->next = ctx->catalog;
    ctx->catalog = cat;
    return cat;
}

static void catalog_error(firc_http_res_t *res, catalog_waiter_t *w, int status, const char *why) {
    if (w == NULL) {
        firc_http_res_write_error(res, status, why);
        return;
    }
    cJSON *obj = firc_json_error(why);
    char *body = obj != NULL ? firc_json_dump(obj) : NULL;
    cJSON_Delete(obj);
    finish_waiter(w, status, (uint8_t *)body, body != NULL ? strlen(body) : 0);
}

static void catalog_serve(firc_groups_ctx_t *ctx, const char *provider, firc_loop_t *loop,
                          firc_http_res_t *res, catalog_waiter_t *w) {
    const char *after_index = "";
    if (provider[0] != '\0') {
        const list_catalog_t *index = find_catalog(ctx, "");
        if (index == NULL || index->copy == NULL) {
            after_index = provider;
            provider = "";
        } else if (!provider_listed(index->copy, provider)) {
            catalog_error(res, w, 404, "provider is not in the catalog");
            return;
        }
    }
    bool full = false;
    list_catalog_t *cat = catalog_slot(ctx, provider, &full);
    if (cat == NULL) {
        catalog_error(res, w, full ? 503 : 500, full ? "too many provider catalogs at once" : "out of memory");
        return;
    }
    if (provider[0] != '\0' && ctx->catalog_loop == NULL &&
        firc_loop_add_timer(loop, CATALOG_FAILED_MS, CATALOG_FAILED_MS, sweep_catalogs, ctx,
                            &ctx->catalog_timer) == FIRC_OK) {
        ctx->catalog_loop = loop;
    }
    uint64_t now = catalog_now(ctx);
    cat->used_ms = now;
    bool fresh = cat->copy != NULL && now - cat->fetched_ms < CATALOG_FRESH_MS;
    bool resting = cat->failed && now - cat->failed_ms < CATALOG_FAILED_MS;
    if (cat->fetch == NULL && (fresh || resting)) {
        int status;
        size_t len;
        uint8_t *body = catalog_answer(cat, &status, &len);
        if (w != NULL) {
            finish_waiter(w, status, body, len);
        } else {
            firc_http_res_take(res, status, "application/json; charset=utf-8", body, len);
        }
        return;
    }
    if (cat->fetch == NULL && !fetch_start(cat, loop)) {
        catalog_error(res, w, 500, "failed to start the catalog fetch");
        return;
    }
    if (w == NULL) {
        w = calloc(1, sizeof(*w));
        if (w != NULL) { w->d = firc_http_res_defer(res, waiter_left, w); }
        if (w == NULL || w->d == NULL) {
            free(w);
            catalog_error(res, NULL, 500, "out of memory");
            return;
        }
    }
    snprintf(w->provider, sizeof w->provider, "%s", after_index);
    w->cat = cat;
    w->next = cat->waiters;
    cat->waiters = w;
}

static void handle_catalog(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    const char *provider = firc_http_req_query(req, "provider");
    if (provider != NULL && !firc_list_catalog_id_ok(provider)) {
        firc_http_res_write_error(res, 400, "provider is not a catalog id");
        return;
    }
    catalog_serve(ud, provider != NULL ? provider : "", firc_http_res_loop(res), res, NULL);
}

void firc_list_catalog_register_routes(firc_httpd_t *h, firc_groups_ctx_t *ctx) {
    must_route(h, "GET", "/api/v1/groups/list/catalog", handle_catalog, ctx);
}

static void catalog_close_one(list_catalog_t *cat) {
    catalog_fetch_t *f = cat->fetch;
    if (f != NULL) {
        atomic_store(&f->stopping, true);
        pthread_join(f->thread, NULL);
        f->joined = true;
        if (!f->posted) { fetch_free(f); }
    }
    while (cat->waiters != NULL) {
        catalog_waiter_t *w = cat->waiters;
        cat->waiters = w->next;
        firc_http_deferred_drop(w->d);
        free(w);
    }
    catalog_free(cat);
}

void firc_list_catalog_close(firc_groups_ctx_t *ctx) {
    if (ctx->catalog_loop != NULL) {
        firc_loop_del_timer(ctx->catalog_loop, ctx->catalog_timer);
        ctx->catalog_loop = NULL;
    }
    list_catalog_t *cat = ctx->catalog;
    ctx->catalog = NULL;
    while (cat != NULL) {
        list_catalog_t *next = cat->next;
        catalog_close_one(cat);
        cat = next;
    }
}
