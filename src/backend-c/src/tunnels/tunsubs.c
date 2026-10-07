#include "firc/tunsubs.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "firc/atomic_write.h"
#include "firc/hash.h"
#include "firc/log.h"
#include "firc/sub_fetch.h"

#define RETRY_MS 60000
#define IDENT_MAX 32

typedef struct {
    char id[16];
    uint32_t mark;
} user_t;

typedef struct {
    char *url;
    char ident[IDENT_MAX];
    char key[17];
    int interval_s;
    user_t users[FIRC_TUN_MAX];
    size_t n_users;
    char *body;
    size_t len;
    uint8_t sha[FIRC_SHA256_DIGEST_LEN];
    bool have;
    uint8_t cached_sha[FIRC_SHA256_DIGEST_LEN];
    bool cached;
    int64_t last_ok_ms, last_try_ms;
    int64_t done_mono;
    char error[160];
    bool fetching;
    size_t nodes;
    bool kept, was_wanted;
} entry_t;

typedef struct result {
    firc_tunsubs_t *s;
    char *url;
    char ident[IDENT_MAX];
    firc_err_t err;
    bool no_nodes;
    int status;
    char *body;
    size_t len;
    size_t nodes;
    uint8_t sha[FIRC_SHA256_DIGEST_LEN];
    bool wrote;
    firc_err_t write_err;
    int64_t at_ms;
} result_t;

typedef struct job {
    struct job *next;
    uint32_t mark;
    char path[512];
    bool cached;
    uint8_t cached_sha[FIRC_SHA256_DIGEST_LEN];
    result_t *r;
} job_t;

struct firc_tunsubs {
    firc_loop_t *loop;
    char dir[448];
    void (*changed)(void *ud);
    void *ud;
    entry_t **v;
    size_t n;
    firc_tun_body_t *bodies;
    size_t n_bodies;
    int64_t offset_ms;
    pthread_mutex_t mu;
    pthread_cond_t cv;
    job_t *head, *tail;
    bool stop;
    atomic_bool abort;
    pthread_t thread;
    size_t posted;
    bool dead;
};

static int64_t wall_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int64_t mono_ms(const firc_tunsubs_t *s)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + s->offset_ms;
}

static void ident_of(const firc_tunnel_t *t, char out[IDENT_MAX])
{
    switch (t->uplink) {
    case FIRC_UPLINK_IFACE:
        snprintf(out, IDENT_MAX, "iface:%s", t->uplink_ref);
        break;
    case FIRC_UPLINK_TUNNEL:
        snprintf(out, IDENT_MAX, "tunnel:%s", t->uplink_ref);
        break;
    case FIRC_UPLINK_AUTO:
    default:
        snprintf(out, IDENT_MAX, "auto");
        break;
    }
}

static void key_of(const char *url, const char *ident, char key[17])
{
    firc_sha256_ctx_t c;
    firc_sha256_init(&c);
    firc_sha256_update(&c, (const uint8_t *)url, strlen(url));
    firc_sha256_update(&c, (const uint8_t *)"\n", 1);
    firc_sha256_update(&c, (const uint8_t *)ident, strlen(ident));
    uint8_t d[FIRC_SHA256_DIGEST_LEN];
    firc_sha256_final(&c, d);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 8; i++) {
        key[2 * i] = hex[d[i] >> 4];
        key[2 * i + 1] = hex[d[i] & 15];
    }
    key[16] = 0;
}

static void mkdirs(const char *path)
{
    char p[448];
    snprintf(p, sizeof p, "%s", path);
    for (char *q = p + 1; *q != 0; q++) {
        if (*q == '/') {
            *q = 0;
            (void)mkdir(p, 0700);
            *q = '/';
        }
    }
    if (mkdir(p, 0700) == 0) {
        return;
    }
    struct stat st;
    if (errno != EEXIST || stat(p, &st) != 0 || !S_ISDIR(st.st_mode)) {
        FIRC_WARN("tunnel subscriptions: cache directory %s not created: %s", p, strerror(errno));
        return;
    }
    if ((st.st_mode & 077) != 0 && chmod(p, 0700) != 0) {
        FIRC_WARN("tunnel subscriptions: cache directory %s not made private: %s", p, strerror(errno));
    }
}

static size_t count_nodes(const char *url, const char *body, size_t len)
{
    firc_tun_src_t src;
    memset(&src, 0, sizeof src);
    src.kind = FIRC_TUN_SRC_SUB;
    snprintf(src.id, sizeof src.id, "00000000");
    src.sub.url = (char *)url;
    firc_tunnel_t t;
    memset(&t, 0, sizeof t);
    t.src = &src;
    t.n_src = 1;
    t.insecure = true;
    firc_tun_body_t b = {url, 0, body, len};
    firc_tun_nodes_t nodes;
    size_t n = 0;
    if (firc_tun_nodes_build(&t, 0, &b, 1, &nodes) == FIRC_OK) {
        n = nodes.total;
        firc_tun_nodes_free(&nodes);
    }
    return n;
}

static void load_cache(firc_tunsubs_t *s, entry_t *e)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", s->dir, e->key);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT) {
            FIRC_WARN("tunnel subscriptions: cache file %s not opened: %s", e->key, strerror(errno));
        }
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (uint64_t)st.st_size > FIRC_SUB_FETCH_MAX_BODY_BYTES) {
        FIRC_WARN("tunnel subscriptions: cache file %s refused (not a file, or over %zu bytes)", e->key,
                  FIRC_SUB_FETCH_MAX_BODY_BYTES);
        close(fd);
        return;
    }
    size_t len = (size_t)st.st_size;
    char *body = malloc(len + 1);
    size_t got = 0;
    while (body != NULL && got < len) {
        ssize_t r = read(fd, body + got, len - got);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        got += (size_t)r;
    }
    close(fd);
    if (body == NULL || got != len || memchr(body, 0, len) != NULL) {
        FIRC_WARN("tunnel subscriptions: cache file %s not read", e->key);
        free(body);
        return;
    }
    body[len] = 0;
    e->body = body;
    e->len = len;
    e->have = true;
    firc_sha256((const uint8_t *)body, len, e->sha);
    memcpy(e->cached_sha, e->sha, sizeof e->sha);
    e->cached = true;
    e->nodes = count_nodes(e->url, body, len);
}

static void post_result(firc_tunsubs_t *s, result_t *r);

static bool keep_going(void *ud, size_t bytes, size_t total)
{
    (void)bytes;
    (void)total;
    return !atomic_load(&((firc_tunsubs_t *)ud)->abort);
}

static void run_job(firc_tunsubs_t *s, job_t *j)
{
    result_t *r = j->r;
    j->r = NULL;
    r->err = firc_sub_fetch_list_mark_ex(r->url, j->mark, &r->body, &r->len, &r->status, keep_going, s);
    r->at_ms = wall_ms();
    if (r->err == FIRC_OK) {
        r->nodes = count_nodes(r->url, r->body, r->len);
        if (r->nodes == 0) {
            r->err = FIRC_ERR_PROTO;
            r->no_nodes = true;
        }
    }
    if (r->err == FIRC_OK) {
        firc_sha256((const uint8_t *)r->body, r->len, r->sha);
        if (!j->cached || memcmp(j->cached_sha, r->sha, sizeof r->sha) != 0) {
            r->write_err = firc_atomic_write(j->path, r->body, r->len);
            r->wrote = true;
        }
    }
    post_result(s, r);
}

static void free_result(result_t *r)
{
    if (r == NULL) {
        return;
    }
    free(r->url);
    free(r->body);
    free(r);
}

static void free_job(job_t *j)
{
    free_result(j->r);
    free(j);
}

static void *worker(void *ud)
{
    firc_tunsubs_t *s = ud;
    for (;;) {
        pthread_mutex_lock(&s->mu);
        while (!s->stop && s->head == NULL) {
            pthread_cond_wait(&s->cv, &s->mu);
        }
        if (s->stop) {
            pthread_mutex_unlock(&s->mu);
            return NULL;
        }
        job_t *j = s->head;
        s->head = j->next;
        if (s->head == NULL) {
            s->tail = NULL;
        }
        pthread_mutex_unlock(&s->mu);
        run_job(s, j);
        free_job(j);
    }
}

static void destroy(firc_tunsubs_t *s)
{
    pthread_cond_destroy(&s->cv);
    pthread_mutex_destroy(&s->mu);
    free(s);
}

static bool settle(firc_tunsubs_t *s, bool *last)
{
    pthread_mutex_lock(&s->mu);
    s->posted--;
    bool dead = s->dead;
    *last = dead && s->posted == 0;
    pthread_mutex_unlock(&s->mu);
    return dead;
}

static void drop_result(void *ud)
{
    result_t *r = ud;
    firc_tunsubs_t *s = r->s;
    free_result(r);
    bool last = false;
    if (settle(s, &last) && last) {
        destroy(s);
    }
}

static entry_t *find(const firc_tunsubs_t *s, const char *url, const char *ident)
{
    for (size_t i = 0; i < s->n; i++) {
        if (strcmp(s->v[i]->ident, ident) == 0 && strcmp(s->v[i]->url, url) == 0) {
            return s->v[i];
        }
    }
    return NULL;
}

static bool mark_seen(const entry_t *e, size_t upto, uint32_t mark)
{
    for (size_t u = 0; u < upto; u++) {
        if (e->users[u].mark == mark) {
            return true;
        }
    }
    return false;
}

static void rebuild_bodies(firc_tunsubs_t *s)
{
    size_t k = 0;
    for (size_t i = 0; i < s->n; i++) {
        entry_t *e = s->v[i];
        for (size_t u = 0; e->have && u < e->n_users; u++) {
            if (mark_seen(e, u, e->users[u].mark)) {
                continue;
            }
            s->bodies[k].url = e->url;
            s->bodies[k].mark = e->users[u].mark;
            s->bodies[k].body = e->body;
            s->bodies[k].len = e->len;
            k++;
        }
    }
    s->n_bodies = k;
}

static void describe(const result_t *r, char *buf, size_t cap)
{
    if (r->no_nodes) {
        snprintf(buf, cap, "no nodes in the answer");
    } else if (r->err == FIRC_ERR_PROTO && r->status != 0 && (r->status < 200 || r->status >= 300)) {
        snprintf(buf, cap, "HTTP %d", r->status);
    } else if (r->err == FIRC_ERR_SYS) {
        snprintf(buf, cap, "the uplink mark could not be set");
    } else if (r->err == FIRC_ERR_LIMIT) {
        snprintf(buf, cap, "over %zu bytes or too many redirects", FIRC_SUB_FETCH_MAX_BODY_BYTES);
    } else if (r->err == FIRC_ERR_IO) {
        snprintf(buf, cap, "no answer");
    } else {
        snprintf(buf, cap, "%s", firc_err_str(r->err));
    }
}

static void on_result(firc_loop_t *loop, void *ud)
{
    (void)loop;
    result_t *r = ud;
    firc_tunsubs_t *s = r->s;
    bool last = false;
    if (settle(s, &last)) {
        free_result(r);
        if (last) {
            destroy(s);
        }
        return;
    }
    entry_t *e = find(s, r->url, r->ident);
    if (e == NULL) {
        free_result(r);
        return;
    }
    char shown[160];
    firc_sub_url_redact(e->url, shown, sizeof shown);
    e->fetching = false;
    e->last_try_ms = r->at_ms;
    e->done_mono = mono_ms(s);
    if (r->err != FIRC_OK) {
        describe(r, e->error, sizeof e->error);
        FIRC_WARN("tunnel subscription %s: fetch failed: %s", shown, e->error);
        free_result(r);
        return;
    }
    e->error[0] = 0;
    e->last_ok_ms = r->at_ms;
    if (r->wrote && r->write_err != FIRC_OK) {
        FIRC_WARN("tunnel subscription %s: cache not written: %s", shown, firc_err_str(r->write_err));
    } else if (r->wrote) {
        memcpy(e->cached_sha, r->sha, sizeof r->sha);
        e->cached = true;
    }
    bool changed = !e->have || memcmp(e->sha, r->sha, sizeof e->sha) != 0;
    if (!changed) {
        free_result(r);
        return;
    }
    free(e->body);
    e->body = r->body;
    e->len = r->len;
    r->body = NULL;
    memcpy(e->sha, r->sha, sizeof e->sha);
    e->have = true;
    e->nodes = r->nodes;
    free_result(r);
    rebuild_bodies(s);
    FIRC_INFO("tunnel subscription %s: updated, %zu nodes", shown, e->nodes);
    if (s->changed != NULL) {
        s->changed(s->ud);
    }
}

static void post_result(firc_tunsubs_t *s, result_t *r)
{
    pthread_mutex_lock(&s->mu);
    s->posted++;
    pthread_mutex_unlock(&s->mu);
    while (firc_loop_post_with_drop(s->loop, on_result, r, drop_result) != FIRC_OK) {
        if (atomic_load(&s->abort)) {
            pthread_mutex_lock(&s->mu);
            s->posted--;
            pthread_mutex_unlock(&s->mu);
            free_result(r);
            return;
        }
        struct timespec ts = {0, 50 * 1000000L};
        nanosleep(&ts, NULL);
    }
}

firc_tunsubs_t *firc_tunsubs_new(firc_loop_t *loop, const char *cache_dir, void (*changed)(void *ud), void *ud)
{
    firc_tunsubs_t *s = calloc(1, sizeof *s);
    if (s == NULL) {
        return NULL;
    }
    s->loop = loop;
    snprintf(s->dir, sizeof s->dir, "%s", cache_dir);
    s->changed = changed;
    s->ud = ud;
    atomic_init(&s->abort, false);
    if (pthread_mutex_init(&s->mu, NULL) != 0) {
        free(s);
        return NULL;
    }
    if (pthread_cond_init(&s->cv, NULL) != 0) {
        pthread_mutex_destroy(&s->mu);
        free(s);
        return NULL;
    }
    if (pthread_create(&s->thread, NULL, worker, s) != 0) {
        destroy(s);
        return NULL;
    }
    mkdirs(s->dir);
    return s;
}

static void enqueue(firc_tunsubs_t *s, entry_t *e)
{
    if (e->fetching || e->n_users == 0) {
        return;
    }
    job_t *j = calloc(1, sizeof *j);
    result_t *r = calloc(1, sizeof *r);
    char *url = strdup(e->url);
    if (j == NULL || r == NULL || url == NULL) {
        free(j);
        free(r);
        free(url);
        FIRC_ERROR("tunnel subscriptions: out of memory, a fetch is left for the next tick");
        return;
    }
    r->s = s;
    r->url = url;
    memcpy(r->ident, e->ident, sizeof r->ident);
    j->r = r;
    j->mark = e->users[0].mark;
    snprintf(j->path, sizeof j->path, "%s/%s", s->dir, e->key);
    j->cached = e->cached;
    memcpy(j->cached_sha, e->cached_sha, sizeof j->cached_sha);
    e->fetching = true;
    pthread_mutex_lock(&s->mu);
    if (s->tail != NULL) {
        s->tail->next = j;
    } else {
        s->head = j;
    }
    s->tail = j;
    pthread_cond_signal(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

static void free_entry(entry_t *e)
{
    free(e->url);
    free(e->body);
    free(e);
}

static entry_t *new_entry(firc_tunsubs_t *s, const char *url, const char *ident)
{
    entry_t **grown = realloc(s->v, (s->n + 1) * sizeof *grown);
    if (grown == NULL) {
        return NULL;
    }
    s->v = grown;
    entry_t *e = calloc(1, sizeof *e);
    if (e == NULL || (e->url = strdup(url)) == NULL) {
        free(e);
        return NULL;
    }
    snprintf(e->ident, sizeof e->ident, "%s", ident);
    key_of(url, ident, e->key);
    load_cache(s, e);
    s->v[s->n++] = e;
    return e;
}

static void add_user(entry_t *e, const char *id, uint32_t mark, int interval_s)
{
    bool known = false;
    for (size_t i = 0; i < e->n_users; i++) {
        known = known || strcmp(e->users[i].id, id) == 0;
    }
    if (!known && e->n_users < FIRC_TUN_MAX) {
        snprintf(e->users[e->n_users].id, sizeof e->users[0].id, "%s", id);
        e->users[e->n_users].mark = mark;
        e->n_users++;
    }
    if (interval_s > 0 && (e->interval_s == 0 || interval_s < e->interval_s)) {
        e->interval_s = interval_s;
    }
}

void firc_tunsubs_want(firc_tunsubs_t *s, const firc_tunnels_t *t, const uint32_t *marks)
{
    size_t old = s->n;
    for (size_t i = 0; i < old; i++) {
        s->v[i]->was_wanted = s->v[i]->n_users > 0;
        s->v[i]->n_users = 0;
        s->v[i]->interval_s = 0;
        s->v[i]->kept = false;
    }
    for (size_t i = 0; i < t->n; i++) {
        const firc_tunnel_t *tun = &t->t[i];
        char ident[IDENT_MAX];
        ident_of(tun, ident);
        for (size_t k = 0; k < tun->n_src; k++) {
            const firc_tun_src_t *src = &tun->src[k];
            if (src->kind != FIRC_TUN_SRC_SUB || src->sub.url == NULL) {
                continue;
            }
            entry_t *e = find(s, src->sub.url, ident);
            if (e == NULL) {
                e = new_entry(s, src->sub.url, ident);
            }
            if (e != NULL && tun->enable) {
                add_user(e, tun->id, marks[i], src->sub.interval_s);
            } else if (e != NULL) {
                e->kept = true;
            }
        }
    }
    size_t k = 0;
    size_t users = 0;
    for (size_t i = 0; i < s->n; i++) {
        entry_t *e = s->v[i];
        if (e->n_users == 0 && !e->kept) {
            free_entry(e);
            continue;
        }
        s->v[k++] = e;
        users += e->n_users;
        if (!e->was_wanted && e->n_users > 0 && (!e->have || e->interval_s > 0)) {
            enqueue(s, e);
        }
    }
    s->n = k;
    firc_tun_body_t *b = realloc(s->bodies, (users + 1) * sizeof *b);
    if (b != NULL) {
        s->bodies = b;
        rebuild_bodies(s);
    } else {
        s->n_bodies = 0;
    }
}

static bool is_key_name(const char *name)
{
    size_t n = 0;
    for (; name[n] != 0; n++) {
        if (!((name[n] >= '0' && name[n] <= '9') || (name[n] >= 'a' && name[n] <= 'f'))) {
            return false;
        }
    }
    return n == 16;
}

static bool key_kept(const firc_tunnels_t *all, const char *name)
{
    for (size_t i = 0; i < all->n; i++) {
        const firc_tunnel_t *tun = &all->t[i];
        char ident[IDENT_MAX];
        ident_of(tun, ident);
        for (size_t k = 0; k < tun->n_src; k++) {
            if (tun->src[k].kind != FIRC_TUN_SRC_SUB || tun->src[k].sub.url == NULL) {
                continue;
            }
            char key[17];
            key_of(tun->src[k].sub.url, ident, key);
            if (strcmp(key, name) == 0) {
                return true;
            }
        }
    }
    return false;
}

void firc_tunsubs_sweep(firc_tunsubs_t *s, const firc_tunnels_t *all)
{
    if (s == NULL) {
        return;
    }
    DIR *d = opendir(s->dir);
    if (d == NULL) {
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!is_key_name(de->d_name) || key_kept(all, de->d_name)) {
            continue;
        }
        char path[sizeof s->dir + sizeof de->d_name + 1];
        snprintf(path, sizeof path, "%s/%s", s->dir, de->d_name);
        if (unlink(path) == 0) {
            FIRC_INFO("tunnel subscriptions: cache file %s no longer used, removed", de->d_name);
        }
    }
    closedir(d);
}

void firc_tunsubs_due(firc_tunsubs_t *s)
{
    if (s == NULL) {
        return;
    }
    int64_t now = mono_ms(s);
    for (size_t i = 0; i < s->n; i++) {
        entry_t *e = s->v[i];
        bool scheduled = e->interval_s > 0 && now >= e->done_mono + (int64_t)e->interval_s * 1000;
        bool retry = !e->have && e->done_mono != 0 && now >= e->done_mono + RETRY_MS;
        if (!e->fetching && (scheduled || retry)) {
            enqueue(s, e);
        }
    }
}

firc_err_t firc_tunsubs_refresh(firc_tunsubs_t *s, const char *tunnel_id)
{
    bool any = false;
    for (size_t i = 0; i < s->n; i++) {
        entry_t *e = s->v[i];
        for (size_t u = 0; u < e->n_users; u++) {
            if (strcmp(e->users[u].id, tunnel_id) == 0) {
                enqueue(s, e);
                any = true;
                break;
            }
        }
    }
    return any ? FIRC_OK : FIRC_ERR_NOENT;
}

const firc_tun_body_t *firc_tunsubs_bodies(const firc_tunsubs_t *s, size_t *n)
{
    *n = s != NULL ? s->n_bodies : 0;
    return s != NULL ? s->bodies : NULL;
}

size_t firc_tunsubs_held(const firc_tunsubs_t *s, const firc_tunnel_t *uplink_of, const firc_tunnel_t *t,
                         firc_tun_body_t *out, size_t cap)
{
    size_t k = 0;
    if (s == NULL) {
        return 0;
    }
    char ident[IDENT_MAX];
    ident_of(uplink_of, ident);
    for (size_t i = 0; i < t->n_src && k < cap; i++) {
        const firc_tun_src_t *src = &t->src[i];
        if (src->kind != FIRC_TUN_SRC_SUB || src->sub.url == NULL) {
            continue;
        }
        const entry_t *e = find(s, src->sub.url, ident);
        if (e != NULL && e->have) {
            out[k++] = (firc_tun_body_t){.url = e->url, .mark = 0, .body = e->body, .len = e->len};
        }
    }
    return k;
}

size_t firc_tunsubs_state(const firc_tunsubs_t *s, const char *url, uint32_t mark, firc_tun_sub_state_t *out)
{
    const entry_t *e = NULL;
    for (size_t i = 0; i < s->n && e == NULL; i++) {
        if (strcmp(s->v[i]->url, url) == 0 && mark_seen(s->v[i], s->v[i]->n_users, mark)) {
            e = s->v[i];
        }
    }
    if (e == NULL) {
        return 0;
    }
    memset(out, 0, sizeof *out);
    memcpy(out->url_hash, e->key, sizeof out->url_hash);
    out->last_ok_ms = e->last_ok_ms;
    out->last_try_ms = e->last_try_ms;
    snprintf(out->error, sizeof out->error, "%s", e->error);
    out->fetching = e->fetching;
    out->nodes = e->nodes;
    return 1;
}

void firc_tunsubs_advance_for_test(firc_tunsubs_t *s, int64_t ms)
{
    s->offset_ms += ms;
}

void firc_tunsubs_free(firc_tunsubs_t *s)
{
    if (s == NULL) {
        return;
    }
    atomic_store(&s->abort, true);
    pthread_mutex_lock(&s->mu);
    s->stop = true;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
    pthread_join(s->thread, NULL);
    while (s->head != NULL) {
        job_t *j = s->head;
        s->head = j->next;
        free_job(j);
    }
    for (size_t i = 0; i < s->n; i++) {
        free_entry(s->v[i]);
    }
    free(s->v);
    free(s->bodies);
    pthread_mutex_lock(&s->mu);
    s->dead = true;
    bool last = s->posted == 0;
    pthread_mutex_unlock(&s->mu);
    if (last) {
        destroy(s);
    }
}
