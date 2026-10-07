#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */
#include "firc/sub_fetch.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <curl/curl.h>

#include "firc/log.h"
#include "firc/version.h"

static firc_sub_setsockopt_fn g_setsockopt = setsockopt;

void firc_sub_fetch_set_setsockopt_for_test(firc_sub_setsockopt_fn fn) { g_setsockopt = fn != NULL ? fn : setsockopt; }

typedef struct sock_cfg {
    uint32_t mark;
    bool mark_refused;
} sock_cfg_t;

static int cloexec_cb(void *ud, curl_socket_t fd, curlsocktype purpose)
{
    (void)purpose;
    sock_cfg_t *cfg = ud;
    int fl = fcntl(fd, F_GETFD);
    if (fl >= 0) { (void)fcntl(fd, F_SETFD, fl | FD_CLOEXEC); }
    if (cfg != NULL && cfg->mark != 0 && g_setsockopt(fd, SOL_SOCKET, SO_MARK, &cfg->mark, sizeof cfg->mark) != 0) {
        cfg->mark_refused = true;
        return CURL_SOCKOPT_ERROR;
    }
    return CURL_SOCKOPT_OK;
}

void firc_sub_url_redact(const char *url, char *buf, size_t cap)
{
    if (cap == 0) { return; }
    snprintf(buf, cap, "(bad url)");
    CURLU *cu = curl_url();
    if (cu == NULL) { return; }
    char *scheme = NULL;
    char *host = NULL;
    if (url != NULL && curl_url_set(cu, CURLUPART_URL, url, 0) == CURLUE_OK &&
        curl_url_get(cu, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
        curl_url_get(cu, CURLUPART_HOST, &host, 0) == CURLUE_OK) {
        snprintf(buf, cap, "%s://%s/…", scheme, host);
    }
    curl_free(scheme);
    curl_free(host);
    curl_url_cleanup(cu);
}

void firc_sub_fetch_global_init(void) { curl_global_init(CURL_GLOBAL_DEFAULT); }

void firc_sub_fetch_global_cleanup(void) { curl_global_cleanup(); }

bool firc_sub_url_is_supported(const char *url) {
    CURLU *cu = curl_url();
    if (!cu) { return false; }
    bool ok = false;
    if (curl_url_set(cu, CURLUPART_URL, url, 0) == CURLUE_OK) {
        char *scheme = NULL;
        char *host = NULL;
        curl_url_get(cu, CURLUPART_SCHEME, &scheme, 0);
        curl_url_get(cu, CURLUPART_HOST, &host, 0);
        ok = scheme && host && host[0] != '\0' &&
             (strcasecmp(scheme, "http") == 0 || strcasecmp(scheme, "https") == 0);
        curl_free(scheme);
        curl_free(host);
    }
    curl_url_cleanup(cu);
    return ok;
}

typedef struct fetch_buf {
    char *data;
    size_t len;
    size_t cap;
    bool truncated;
    firc_sub_fetch_progress_fn progress;
    void *progress_ud;
    bool aborted;
} fetch_buf_t;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *ud) {
    fetch_buf_t *buf = ud;
    size_t n = size * nmemb;
    if (buf->len + n > FIRC_SUB_FETCH_MAX_BODY_BYTES) {
        buf->truncated = true;
        return 0; /* abort the transfer */
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

/* called periodically during the transfer; returning non-zero aborts with CURLE_ABORTED_BY_CALLBACK */
static int xferinfo_cb(void *ud, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    (void)ultotal;
    (void)ulnow;
    fetch_buf_t *b = ud;
    if (b->progress == NULL) { return 0; }
    if (!b->progress(b->progress_ud, (size_t)(dlnow < 0 ? 0 : dlnow), (size_t)(dltotal < 0 ? 0 : dltotal))) {
        b->aborted = true;
        return 1;
    }
    return 0;
}

/* fixed array, not a hash set: bounded by FIRC_SUB_FETCH_MAX_REDIRECTS+1 entries, simpler at this size */
typedef struct visited_set {
    char *urls[FIRC_SUB_FETCH_MAX_REDIRECTS + 1];
    size_t n;
} visited_set_t;

static bool visited_contains(const visited_set_t *v, const char *url) {
    for (size_t i = 0; i < v->n; i++) {
        if (strcmp(v->urls[i], url) == 0) { return true; }
    }
    return false;
}

static firc_err_t visited_add(visited_set_t *v, const char *url) {
    if (v->n >= sizeof(v->urls) / sizeof(v->urls[0])) { return FIRC_ERR_LIMIT; }
    char *copy = strdup(url);
    if (!copy) { return FIRC_ERR_NOMEM; }
    v->urls[v->n++] = copy;
    return FIRC_OK;
}

static void visited_clear(visited_set_t *v) {
    for (size_t i = 0; i < v->n; i++) { free(v->urls[i]); }
    v->n = 0;
}

static firc_err_t fetch(const char *url, uint32_t mark, char **out_body, size_t *out_len,
                        firc_sub_fetch_progress_fn progress, void *ud, long *out_http_status) {
    *out_body = NULL;
    *out_len = 0;
    if (out_http_status) { *out_http_status = 0; }

    visited_set_t visited = {0};
    char *current = strdup(url);
    if (!current) { return FIRC_ERR_NOMEM; }

    firc_err_t result = FIRC_ERR_SYS;
    int redirects = 0;
    for (;;) {
        if (!firc_sub_url_is_supported(current)) {
            result = FIRC_ERR_INVAL;
            break;
        }
        if (visited_contains(&visited, current)) {
            result = FIRC_ERR_INVAL; /* redirect loop detected */
            break;
        }
        firc_err_t verr = visited_add(&visited, current);
        if (verr != FIRC_OK) {
            result = verr;
            break;
        }

        CURL *curl = curl_easy_init();
        if (!curl) {
            result = FIRC_ERR_NOMEM;
            break;
        }
        fetch_buf_t buf = {0};
        sock_cfg_t sock = {.mark = mark};
        buf.progress = progress;
        buf.progress_ud = ud;
        curl_easy_setopt(curl, CURLOPT_URL, current);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "firc/" FIRC_VERSION);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)FIRC_SUB_FETCH_TIMEOUT_SECONDS);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, cloexec_cb);
        curl_easy_setopt(curl, CURLOPT_SOCKOPTDATA, &sock);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo_cb);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &buf);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, progress ? 0L : 1L);

        CURLcode rc = curl_easy_perform(curl);
        if (rc != CURLE_OK) {
            long fail_status = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &fail_status);
            if (out_http_status) { *out_http_status = fail_status; }
            free(buf.data);
            curl_easy_cleanup(curl);
            result = sock.mark_refused ? FIRC_ERR_SYS
                     : buf.aborted     ? FIRC_ERR_CANCELED
                     : buf.truncated   ? FIRC_ERR_LIMIT
                                       : FIRC_ERR_IO;
            break;
        }

        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (out_http_status) { *out_http_status = status; }

        if (status == 301 || status == 302) {
            char *location = NULL;
            curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &location);
            if (!location) {
                free(buf.data);
                curl_easy_cleanup(curl);
                result = FIRC_ERR_INVAL; /* bad/missing redirect location */
                break;
            }
            if (!firc_sub_url_is_supported(location)) {
                free(buf.data);
                curl_easy_cleanup(curl);
                result = FIRC_ERR_INVAL;
                break;
            }
            if (visited_contains(&visited, location)) {
                free(buf.data);
                curl_easy_cleanup(curl);
                result = FIRC_ERR_INVAL; /* redirect loop detected */
                break;
            }
            if (redirects >= FIRC_SUB_FETCH_MAX_REDIRECTS) {
                free(buf.data);
                curl_easy_cleanup(curl);
                result = FIRC_ERR_LIMIT; /* too many redirects */
                break;
            }
            char *next = strdup(location);
            free(buf.data);
            curl_easy_cleanup(curl);
            if (!next) {
                result = FIRC_ERR_NOMEM;
                break;
            }
            free(current);
            current = next;
            redirects++;
            continue;
        }

        curl_easy_cleanup(curl);
        if (status < 200 || status >= 300) {
            free(buf.data);
            result = FIRC_ERR_PROTO;
            break;
        }

        if (!buf.data) {
            /* 0-byte body: write_cb was never called, so hand back an allocated empty string, not NULL */
            buf.data = calloc(1, 1);
            if (!buf.data) {
                result = FIRC_ERR_NOMEM;
                break;
            }
        }
        /* a NUL in the body would be invisible to the const-char* parser and silently truncate what gets saved */
        if (memchr(buf.data, '\0', buf.len) != NULL) {
            char shown[160];
            firc_sub_url_redact(current, shown, sizeof shown);
            FIRC_WARN("the list at %s holds a NUL byte and is not text; refused rather "
                      "than read up to it",
                      shown);
            free(buf.data);
            result = FIRC_ERR_PROTO;
            break;
        }
        if (progress) { progress(ud, buf.len, buf.len); }
        *out_body = buf.data;
        *out_len = buf.len;
        result = FIRC_OK;
        break;
    }

    free(current);
    visited_clear(&visited);
    return result;
}

firc_err_t firc_sub_fetch_list(const char *url, char **out_body, size_t *out_len) {
    return firc_sub_fetch_list_ex(url, out_body, out_len, NULL, NULL, NULL);
}

firc_err_t firc_sub_fetch_list_ex(const char *url, char **out_body, size_t *out_len,
                                  firc_sub_fetch_progress_fn progress, void *ud, long *out_http_status) {
    return fetch(url, 0, out_body, out_len, progress, ud, out_http_status);
}

firc_err_t firc_sub_fetch_list_mark_ex(const char *url, uint32_t mark, char **out_body, size_t *out_len,
                                       int *out_http_status, firc_sub_fetch_progress_fn progress, void *ud) {
    long status = 0;
    firc_err_t err = fetch(url, mark, out_body, out_len, progress, ud, &status);
    if (out_http_status != NULL) { *out_http_status = (int)status; }
    return err;
}

firc_err_t firc_sub_fetch_list_mark(const char *url, uint32_t mark, char **out_body, size_t *out_len,
                                    int *out_http_status) {
    return firc_sub_fetch_list_mark_ex(url, mark, out_body, out_len, out_http_status, NULL, NULL);
}
