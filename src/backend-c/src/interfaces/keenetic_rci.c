#include "firc/keenetic_rci.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>
#include <curl/curl.h>

#include "firc/log.h"

static bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

/* Trims ASCII whitespace only, so a U+00A0 stays in the label. */
static void copy_trimmed(char *dst, size_t dst_sz, const char *src) {
    dst[0] = '\0';
    if (!src) { return; }

    while (*src && is_space(*src)) { src++; }
    size_t len = strlen(src);
    while (len > 0 && is_space(src[len - 1])) { len--; }
    if (len >= dst_sz) { len = dst_sz - 1; }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static void copy_trimmed_member(char *dst, size_t dst_sz, const cJSON *obj, const char *key) {
    dst[0] = '\0';
    const cJSON *m = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsString(m)) { copy_trimmed(dst, dst_sz, m->valuestring); }
}

firc_err_t firc_kn_parse_interface_list(const char *json, firc_kn_iface_meta_t **out, size_t *out_n) {
    *out = NULL;
    *out_n = 0;
    if (!json) { return FIRC_ERR_INVAL; }

    cJSON *root = cJSON_Parse(json);
    if (!root) { return FIRC_ERR_PROTO; }
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return FIRC_ERR_PROTO;
    }

    size_t cap = 0;
    size_t n = 0;
    firc_kn_iface_meta_t *arr = NULL;

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, root) {
        if (!cJSON_IsObject(entry) || !entry->string) { continue; }

        if (n == cap) {
            size_t new_cap = cap ? cap * 2 : 8;
            firc_kn_iface_meta_t *na = realloc(arr, new_cap * sizeof(*na));
            if (!na) {
                free(arr);
                cJSON_Delete(root);
                return FIRC_ERR_NOMEM;
            }
            arr = na;
            cap = new_cap;
        }

        memset(&arr[n], 0, sizeof(arr[n]));
        snprintf(arr[n].id, sizeof(arr[n].id), "%s", entry->string);
        copy_trimmed_member(arr[n].description, sizeof(arr[n].description), entry, "description");
        copy_trimmed_member(arr[n].interface_name, sizeof(arr[n].interface_name), entry,
                            "interface-name");
        n++;
    }

    cJSON_Delete(root);
    *out = arr;
    *out_n = n;
    return FIRC_OK;
}

char *firc_kn_build_system_name_request(const firc_kn_iface_meta_t *metas, size_t n) {
    cJSON *arr = cJSON_CreateArray();
    if (!arr) { return NULL; }

    for (size_t i = 0; i < n; i++) {
        cJSON *iface = cJSON_CreateObject();
        cJSON *show = cJSON_CreateObject();
        cJSON *item = cJSON_CreateObject();
        if (!iface || !show || !item) {
            cJSON_Delete(iface);
            cJSON_Delete(show);
            cJSON_Delete(item);
            cJSON_Delete(arr);
            return NULL;
        }

        if (!cJSON_AddStringToObject(iface, "name", metas[i].id) ||
            !cJSON_AddStringToObject(iface, "details", "yes") ||
            !cJSON_AddStringToObject(iface, "system-name", "yes")) {
            cJSON_Delete(iface);
            cJSON_Delete(show);
            cJSON_Delete(item);
            cJSON_Delete(arr);
            return NULL;
        }
        cJSON_AddItemToObject(show, "interface", iface);
        cJSON_AddItemToObject(item, "show", show);
        cJSON_AddItemToArray(arr, item);
    }

    char *body = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return body;
}

firc_err_t firc_kn_parse_system_names(const char *json, firc_kn_iface_meta_t *metas, size_t n) {
    if (!json) { return FIRC_ERR_INVAL; }

    cJSON *root = cJSON_Parse(json);
    if (!root) { return FIRC_ERR_PROTO; }
    if (!cJSON_IsArray(root)) {
        cJSON_Delete(root);
        return FIRC_ERR_PROTO;
    }

    size_t i = 0;
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, root) {
        if (i >= n) { break; }

        const cJSON *show = cJSON_GetObjectItemCaseSensitive(item, "show");
        const cJSON *iface = cJSON_GetObjectItemCaseSensitive(show, "interface");
        copy_trimmed_member(metas[i].system_name, sizeof(metas[i].system_name), iface,
                            "system-name");
        i++;
    }

    cJSON_Delete(root);
    return FIRC_OK;
}

firc_err_t firc_kn_build_aliases(const firc_kn_iface_meta_t *metas, size_t n, firc_kn_aliases_t *out) {
    out->items = NULL;
    out->n = 0;
    if (n == 0) { return FIRC_OK; }

    firc_kn_alias_t *arr = calloc(n, sizeof(*arr));
    if (!arr) { return FIRC_ERR_NOMEM; }

    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        char system_name[sizeof(metas[i].system_name)];
        copy_trimmed(system_name, sizeof(system_name), metas[i].system_name);
        if (system_name[0] == '\0') { continue; }

        char alias[sizeof(arr[count].alias)];
        copy_trimmed(alias, sizeof(alias), metas[i].description);
        if (alias[0] == '\0') { copy_trimmed(alias, sizeof(alias), metas[i].interface_name); }
        if (alias[0] == '\0' || strcmp(alias, system_name) == 0) { continue; }

        snprintf(arr[count].system_name, sizeof(arr[count].system_name), "%s", system_name);
        snprintf(arr[count].alias, sizeof(arr[count].alias), "%s", alias);
        count++;
    }

    if (count == 0) {
        free(arr);
        return FIRC_OK;
    }
    out->items = arr;
    out->n = count;
    return FIRC_OK;
}

const char *firc_kn_aliases_lookup(const firc_kn_aliases_t *aliases, const char *system_name) {
    if (!aliases || !aliases->items || !system_name) { return NULL; }
    for (size_t i = 0; i < aliases->n; i++) {
        if (strcmp(aliases->items[i].system_name, system_name) == 0) {
            return aliases->items[i].alias;
        }
    }
    return NULL;
}

void firc_kn_aliases_free(firc_kn_aliases_t *aliases) {
    if (!aliases) { return; }
    free(aliases->items);
    aliases->items = NULL;
    aliases->n = 0;
}

typedef struct rci_buf {
    char *data;
    size_t len;
    size_t cap;
    bool truncated;
} rci_buf_t;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *ud) {
    rci_buf_t *buf = ud;
    size_t n = size * nmemb;
    if (buf->len + n > FIRC_KN_RCI_MAX_BODY_BYTES) {
        buf->truncated = true;
        return 0;
    }
    if (buf->len + n + 1 > buf->cap) {
        size_t new_cap = buf->cap ? buf->cap * 2 : 4096;
        while (new_cap < buf->len + n + 1) { new_cap *= 2; }
        char *na = realloc(buf->data, new_cap);
        if (!na) { return 0; }
        buf->data = na;
        buf->cap = new_cap;
    }
    memcpy(buf->data + buf->len, ptr, n);
    buf->len += n;
    buf->data[buf->len] = '\0';
    return n;
}

/* True at most once an hour across all threads. */
static bool refusal_is_due(void) {
    static _Atomic long last = 0;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { return true; }
    long prev = atomic_load(&last);
    if (prev != 0 && now.tv_sec - prev < 3600) { return false; }
    /* A lost race costs one duplicate line, not worth a lock. */
    return atomic_compare_exchange_strong(&last, &prev, now.tv_sec == 0 ? 1 : now.tv_sec);
}

static firc_err_t rci_call(const char *url, const char *post_body, char **out_body) {
    *out_body = NULL;

    CURL *curl = curl_easy_init();
    if (!curl) { return FIRC_ERR_NOMEM; }

    rci_buf_t buf = {0};
    struct curl_slist *headers = NULL;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, FIRC_KN_RCI_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    if (post_body) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        if (!headers) {
            curl_easy_cleanup(curl);
            return FIRC_ERR_NOMEM;
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(post_body));
    }

    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    if (rc == CURLE_OK) { curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status); }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        free(buf.data);
        if (buf.truncated) {
            FIRC_DEBUG("keenetic rci: %s response exceeded %d bytes", url,
                     FIRC_KN_RCI_MAX_BODY_BYTES);
            return FIRC_ERR_LIMIT;
        }
        FIRC_DEBUG("keenetic rci: %s failed: %s", url, curl_easy_strerror(rc));
        return rc == CURLE_OPERATION_TIMEDOUT ? FIRC_ERR_TIMEOUT : FIRC_ERR_UPSTREAM;
    }
    if (status == 401 || status == 403) {
        /* KeeneticOS 5.2 may demand a token; log 401/403 or device scoping fails open in silence. */
        free(buf.data);
        if (refusal_is_due()) {
            FIRC_WARN("keenetic rci refused %s (HTTP %ld): this firmware wants an authentication token, "
                      "and until firc has one every policy: selector matches no device",
                      url, status);
        }
        return FIRC_ERR_UPSTREAM;
    }
    if (status != 200) {
        free(buf.data);
        FIRC_DEBUG("keenetic rci: %s returned status %ld", url, status);
        return FIRC_ERR_UPSTREAM;
    }
    if (!buf.data) {
        free(buf.data);
        return FIRC_ERR_PROTO;
    }

    *out_body = buf.data;
    return FIRC_OK;
}

firc_err_t firc_kn_rci_get(const char *base_url, const char *path, char **out_body) {
    *out_body = NULL;
    if (!base_url || !path) { return FIRC_ERR_INVAL; }
    size_t base_len = strlen(base_url);
    while (base_len > 0 && base_url[base_len - 1] == '/') { base_len--; }
    char url[512];
    if (snprintf(url, sizeof(url), "%.*s%s", (int)base_len, base_url, path) >= (int)sizeof(url)) {
        return FIRC_ERR_INVAL;
    }
    return rci_call(url, NULL, out_body);
}

/* n == 0 leaves *metas NULL and makes no batch call. */
static firc_err_t fetch_metas(const char *base_url, firc_kn_iface_meta_t **metas_out, size_t *n_out) {
    *metas_out = NULL;
    *n_out = 0;
    if (!base_url) { return FIRC_ERR_INVAL; }

    size_t base_len = strlen(base_url);
    while (base_len > 0 && base_url[base_len - 1] == '/') { base_len--; }

    char list_url[512];
    snprintf(list_url, sizeof(list_url), "%.*s/rci/show/interface", (int)base_len, base_url);

    char *list_body = NULL;
    firc_err_t err = rci_call(list_url, NULL, &list_body);
    if (err != FIRC_OK) { return err; }

    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    err = firc_kn_parse_interface_list(list_body, &metas, &n);
    free(list_body);
    if (err != FIRC_OK) { return err; }

    if (n == 0) {
        free(metas);
        return FIRC_OK;
    }

    char *req_body = firc_kn_build_system_name_request(metas, n);
    if (!req_body) {
        free(metas);
        return FIRC_ERR_NOMEM;
    }

    char batch_url[512];
    snprintf(batch_url, sizeof(batch_url), "%.*s/rci/", (int)base_len, base_url);

    char *batch_body = NULL;
    err = rci_call(batch_url, req_body, &batch_body);
    free(req_body);
    if (err != FIRC_OK) {
        free(metas);
        return err;
    }

    err = firc_kn_parse_system_names(batch_body, metas, n);
    free(batch_body);
    if (err != FIRC_OK) {
        free(metas);
        return err;
    }

    *metas_out = metas;
    *n_out = n;
    return FIRC_OK;
}

firc_err_t firc_kn_get_iface_aliases_from(const char *base_url, firc_kn_aliases_t *out) {
    out->items = NULL;
    out->n = 0;
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    firc_err_t err = fetch_metas(base_url, &metas, &n);
    if (err != FIRC_OK || n == 0) { return err; }
    err = firc_kn_build_aliases(metas, n, out);
    free(metas);
    return err;
}

firc_err_t firc_kn_build_id_map(const firc_kn_iface_meta_t *metas, size_t n, firc_kn_id_map_t *out) {
    out->items = NULL;
    out->n = 0;
    if (n == 0) { return FIRC_OK; }
    firc_kn_id_entry_t *items = calloc(n, sizeof(*items));
    if (items == NULL) { return FIRC_ERR_NOMEM; }
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (metas[i].system_name[0] == '\0' || metas[i].id[0] == '\0') { continue; }
        snprintf(items[k].id, sizeof(items[k].id), "%s", metas[i].id);
        snprintf(items[k].system_name, sizeof(items[k].system_name), "%s", metas[i].system_name);
        k++;
    }
    if (k == 0) {
        free(items);
        return FIRC_OK;
    }
    out->items = items;
    out->n = k;
    return FIRC_OK;
}

firc_err_t firc_kn_get_id_map_from(const char *base_url, firc_kn_id_map_t *out) {
    out->items = NULL;
    out->n = 0;
    firc_kn_iface_meta_t *metas = NULL;
    size_t n = 0;
    firc_err_t err = fetch_metas(base_url, &metas, &n);
    if (err != FIRC_OK || n == 0) { return err; }
    err = firc_kn_build_id_map(metas, n, out);
    free(metas);
    return err;
}

const char *firc_kn_id_map_lookup(const firc_kn_id_map_t *m, const char *rci_id) {
    if (m == NULL || rci_id == NULL) { return NULL; }
    for (size_t i = 0; i < m->n; i++) {
        if (strcmp(m->items[i].id, rci_id) == 0) { return m->items[i].system_name; }
    }
    return NULL;
}

void firc_kn_id_map_free(firc_kn_id_map_t *m) {
    if (m == NULL) { return; }
    free(m->items);
    m->items = NULL;
    m->n = 0;
}

firc_err_t firc_kn_get_iface_aliases(firc_kn_aliases_t *out) {
#ifdef FIRC_ENTWARE_KN
    return firc_kn_get_iface_aliases_from(FIRC_KN_RCI_BASE_URL, out);
#else
    out->items = NULL;
    out->n = 0;
    return FIRC_OK;
#endif
}
