#include "firc/router_id.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "firc/atomic_write.h"
#include "firc/hash.h"
#include "firc/log.h"
#include "firc/rand.h"

static void hex16(const uint8_t *d, char out[17])
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < 8; i++) {
        out[2 * i] = hx[d[i] >> 4];
        out[2 * i + 1] = hx[d[i] & 15];
    }
    out[16] = '\0';
}

void firc_router_id_from_serial(const char *serial, char out[17])
{
    firc_sha256_ctx_t c;
    firc_sha256_init(&c);
    firc_sha256_update(&c, (const uint8_t *)"firc-hwid", sizeof "firc-hwid");
    firc_sha256_update(&c, (const uint8_t *)serial, strlen(serial));
    uint8_t d[FIRC_SHA256_DIGEST_LEN];
    firc_sha256_final(&c, d);
    hex16(d, out);
}

static void take(char *dst, size_t cap, const cJSON *o, const char *key)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (cJSON_IsString(v) && strlen(v->valuestring) < cap) {
        snprintf(dst, cap, "%s", v->valuestring);
    }
}

static cJSON *ask(firc_router_id_get_fn get, void *ud, const char *path)
{
    char *body = NULL;
    cJSON *o = get(ud, path, &body) == FIRC_OK && body != NULL ? cJSON_Parse(body) : NULL;
    free(body);
    if (o != NULL && !cJSON_IsObject(o)) {
        cJSON_Delete(o);
        return NULL;
    }
    return o;
}

static bool read_once(firc_router_id_get_fn get, void *ud, atomic_bool *stop, firc_router_id_t *out)
{
    cJSON *version = ask(get, ud, "/rci/show/version");
    cJSON *defaults = stop != NULL && atomic_load(stop) ? NULL : ask(get, ud, "/rci/show/defaults");
    take(out->release, sizeof out->release, version, "release");
    take(out->model, sizeof out->model, version, "model");
    const cJSON *serial = cJSON_GetObjectItemCaseSensitive(defaults, "serial");
    if (cJSON_IsString(serial) && serial->valuestring[0] != '\0') {
        firc_router_id_from_serial(serial->valuestring, out->hwid);
    }
    bool answered = version != NULL || defaults != NULL;
    cJSON_Delete(version);
    cJSON_Delete(defaults);
    return answered;
}

firc_err_t firc_router_id_read_rci(firc_router_id_get_fn get, void *ud, int tries, int pause_ms,
                                   firc_router_id_t *out)
{
    memset(out, 0, sizeof *out);
    if (get == NULL) {
        return FIRC_ERR_NOSYS;
    }
    for (int i = 0; i < tries; i++) {
        if (i > 0 && pause_ms > 0) {
            struct timespec ts = {pause_ms / 1000, (long)(pause_ms % 1000) * 1000000L};
            nanosleep(&ts, NULL);
        }
        if (read_once(get, ud, NULL, out)) {
            return FIRC_OK;
        }
    }
    return FIRC_ERR_UPSTREAM;
}

static bool is_id(const char *s)
{
    return strlen(s) == 16 && strspn(s, "0123456789abcdef") == 16;
}

static void make_parents(const char *path)
{
    char p[512];
    if (snprintf(p, sizeof p, "%s", path) >= (int)sizeof p) {
        return;
    }
    char *slash = strrchr(p, '/');
    if (slash == NULL || slash == p) {
        return;
    }
    *slash = '\0';
    for (char *q = p + 1; *q != '\0'; q++) {
        if (*q == '/') {
            *q = '\0';
            (void)mkdir(p, 0700);
            *q = '/';
        }
    }
    (void)mkdir(p, 0700);
}

static void store(const char *path, const char *hwid)
{
    char line[18];
    snprintf(line, sizeof line, "%.16s\n", hwid);
    make_parents(path);
    firc_err_t err = firc_atomic_write(path, line, 17);
    if (err != FIRC_OK) {
        FIRC_WARN("router id: %.120s not written (%s); the id lasts until the next start", path,
                  firc_err_str(err));
    }
}

void firc_router_id_settle(firc_router_id_t *id, const char *path, bool random_ok)
{
    char buf[64] = "";
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    bool had_file = fd >= 0;
    if (had_file) {
        ssize_t r = read(fd, buf, sizeof buf - 1);
        close(fd);
        size_t got = r > 0 ? (size_t)r : 0;
        buf[got] = '\0';
        buf[strcspn(buf, "\n")] = '\0';
        if (is_id(buf)) {
            memcpy(id->hwid, buf, sizeof id->hwid);
            return;
        }
    }
    if (id->hwid[0] == '\0') {
        uint8_t d[8];
        if (!random_ok) {
            return;
        }
        if (firc_random_bytes(d, sizeof d) != FIRC_OK) {
            FIRC_WARN("router id: no random bytes, subscriptions go without X-HWID");
            return;
        }
        hex16(d, id->hwid);
    }
    if (had_file) {
        FIRC_WARN("router id: %.120s holds no id, a new one replaces it", path);
    }
    store(path, id->hwid);
}

struct firc_router_id_retry {
    firc_router_id_get_fn get;
    void *ud;
    int tries, pause_ms;
    pthread_t thread;
    pthread_mutex_t mu;
    firc_router_id_t got;
    bool have, taken;
    atomic_bool stop, done;
    void (*between)(void *ud);
    void *between_ud;
};

static void pause_for(firc_router_id_retry_t *r)
{
    for (int left = r->pause_ms; left > 0 && !atomic_load(&r->stop); left -= 50) {
        struct timespec ts = {0, (long)(left < 50 ? left : 50) * 1000000L};
        nanosleep(&ts, NULL);
    }
}

static void keep(char *dst, size_t cap, const char *src)
{
    if (src[0] != '\0') {
        snprintf(dst, cap, "%s", src);
    }
}

static void *retry_main(void *ud)
{
    firc_router_id_retry_t *r = ud;
    firc_router_id_t best = r->got;
    for (int i = 0; i < r->tries && !atomic_load(&r->stop) && best.hwid[0] == '\0'; i++) {
        if (i > 0) {
            pause_for(r);
        }
        firc_router_id_t id;
        memset(&id, 0, sizeof id);
        if (!atomic_load(&r->stop) && read_once(r->get, r->ud, &r->stop, &id)) {
            keep(best.release, sizeof best.release, id.release);
            keep(best.model, sizeof best.model, id.model);
            keep(best.hwid, sizeof best.hwid, id.hwid);
        }
    }
    if (!atomic_load(&r->stop)) {
        pthread_mutex_lock(&r->mu);
        r->got = best;
        r->have = true;
        pthread_mutex_unlock(&r->mu);
    }
    atomic_store(&r->done, true);
    return NULL;
}

static firc_router_id_retry_t *retry_start_from(firc_router_id_get_fn get, void *ud, int tries, int pause_ms,
                                                 const firc_router_id_t *seed)
{
    firc_router_id_retry_t *r = calloc(1, sizeof *r);
    if (r == NULL) {
        return NULL;
    }
    if (seed != NULL) {
        r->got = *seed;
        r->got.hwid[0] = '\0';
    }
    r->get = get;
    r->ud = ud;
    r->tries = tries;
    r->pause_ms = pause_ms;
    atomic_init(&r->stop, false);
    atomic_init(&r->done, false);
    if (pthread_mutex_init(&r->mu, NULL) != 0) {
        free(r);
        return NULL;
    }
    if (pthread_create(&r->thread, NULL, retry_main, r) != 0) {
        pthread_mutex_destroy(&r->mu);
        free(r);
        return NULL;
    }
    return r;
}

firc_router_id_retry_t *firc_router_id_retry_start(firc_router_id_get_fn get, void *ud, int tries, int pause_ms)
{
    return retry_start_from(get, ud, tries, pause_ms, NULL);
}

static bool retry_take(firc_router_id_retry_t *r, firc_router_id_t *out)
{
    bool fresh = false;
    pthread_mutex_lock(&r->mu);
    if (r->have && !r->taken) {
        *out = r->got;
        r->taken = true;
        fresh = true;
    }
    pthread_mutex_unlock(&r->mu);
    return fresh;
}

bool firc_router_id_retry_done(firc_router_id_retry_t *r)
{
    return atomic_load(&r->done);
}

void firc_router_id_retry_hook_for_test(firc_router_id_retry_t *r, void (*between)(void *ud), void *ud)
{
    r->between = between;
    r->between_ud = ud;
}

bool firc_router_id_retry_poll(firc_router_id_retry_t **r, firc_router_id_t *out)
{
    if (*r == NULL) {
        return false;
    }
    bool ended = atomic_load(&(*r)->done);
    if ((*r)->between != NULL) {
        (*r)->between((*r)->between_ud);
    }
    bool fresh = retry_take(*r, out);
    if (ended && !fresh) {
        firc_router_id_retry_stop(*r);
        *r = NULL;
    }
    return fresh;
}

void firc_router_id_retry_stop(firc_router_id_retry_t *r)
{
    if (r == NULL) {
        return;
    }
    atomic_store(&r->stop, true);
    pthread_join(r->thread, NULL);
    pthread_mutex_destroy(&r->mu);
    free(r);
}

firc_router_id_retry_t *firc_router_id_begin(firc_router_id_get_fn get, void *ud, int tries, int pause_ms,
                                             const char *path, firc_router_id_t *out)
{
    (void)firc_router_id_read_rci(get, ud, 1, 0, out);
    firc_router_id_retry_t *r =
        out->hwid[0] != '\0' || get == NULL ? NULL : retry_start_from(get, ud, tries, pause_ms, out);
    firc_router_id_settle(out, path, r == NULL);
    return r;
}

bool firc_router_id_next(firc_router_id_retry_t **r, const char *path, firc_router_id_t *out)
{
    if (*r == NULL) {
        return false;
    }
    if (firc_router_id_retry_poll(r, out)) {
        firc_router_id_retry_stop(*r);
        *r = NULL;
        bool serial = out->hwid[0] != '\0';
        firc_router_id_settle(out, path, true);
        if (serial) {
            FIRC_INFO("router id: RCI answered; subscriptions now name the firmware and the model");
        } else {
            FIRC_WARN("router id: RCI gave no serial; subscriptions send the stored id");
        }
        return true;
    }
    if (*r != NULL) {
        return false;
    }
    memset(out, 0, sizeof *out);
    firc_router_id_settle(out, path, true);
    FIRC_WARN("router id: RCI gave no answer; subscriptions go without the firmware and the model");
    return true;
}
