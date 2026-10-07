#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */
#include "greatest.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "firc/httpd.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/sub_fetch.h"
#include "firc/tunnels.h"
#include "firc/tunsubs.h"

#define PORT 18140
#define U "11111111-2222-3333-4444-555555555555"
#define URL "http://127.0.0.1:18140/sub?token=s3cr3t"
#define SLOW_URL "http://127.0.0.1:18140/slow?token=s3cr3t"
#define BODY_AB "vless://" U "@a.example:443?security=none#A\nvless://" U "@b.example:443?security=none#B\n"
#define BODY_C "vless://" U "@c.example:443?security=none#C\n"

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_hits;
static int g_status = 200;
static int g_delay_ms;
static char g_body[512] = BODY_AB;

static void h_sub(firc_http_req_t *req, firc_http_res_t *res, void *ud)
{
    (void)req;
    int delay = ud != NULL ? *(int *)ud : 0;
    pthread_mutex_lock(&g_mu);
    g_hits++;
    int status = g_status;
    char body[512];
    snprintf(body, sizeof body, "%s", g_body);
    pthread_mutex_unlock(&g_mu);
    if (delay > 0) {
        struct timespec ts = {delay / 1000, (long)(delay % 1000) * 1000000L};
        nanosleep(&ts, NULL);
    }
    firc_http_res_write(res, status, "text/plain", (const uint8_t *)body, strlen(body));
}

typedef struct {
    firc_loop_t *loop;
    firc_httpd_t *srv;
    pthread_t thread;
} server_t;

static server_t *g_srv;

static void *server_thread(void *ud)
{
    firc_loop_run(((server_t *)ud)->loop);
    return NULL;
}

static bool server_start(void)
{
    server_t *s = calloc(1, sizeof *s);
    if (s == NULL || firc_loop_create(&s->loop) != FIRC_OK || firc_httpd_create(s->loop, &s->srv) != FIRC_OK) {
        return false;
    }
    firc_httpd_route(s->srv, "GET", "/sub", h_sub, NULL);
    firc_httpd_route(s->srv, "GET", "/slow", h_sub, &g_delay_ms);
    if (firc_httpd_listen_tcp(s->srv, "127.0.0.1", PORT) != FIRC_OK) {
        return false;
    }
    pthread_create(&s->thread, NULL, server_thread, s);
    g_srv = s;
    return true;
}

static void server_stop(void)
{
    if (g_srv == NULL) {
        return;
    }
    firc_loop_stop(g_srv->loop);
    pthread_join(g_srv->thread, NULL);
    firc_httpd_destroy(g_srv->srv);
    firc_loop_destroy(g_srv->loop);
    free(g_srv);
    g_srv = NULL;
}

static int hits(void)
{
    pthread_mutex_lock(&g_mu);
    int n = g_hits;
    pthread_mutex_unlock(&g_mu);
    return n;
}

static uint32_t g_marks[8];
static int g_n_marks;
static int g_sockopt_fail;

static int record_sockopt(int fd, int level, int name, const void *val, socklen_t len)
{
    (void)fd;
    if (level == SOL_SOCKET && name == SO_MARK && len == sizeof(uint32_t)) {
        pthread_mutex_lock(&g_mu);
        if (g_n_marks < 8) {
            memcpy(&g_marks[g_n_marks++], val, sizeof(uint32_t));
        }
        pthread_mutex_unlock(&g_mu);
        if (g_sockopt_fail) {
            errno = EPERM;
            return -1;
        }
    }
    return 0;
}

typedef struct {
    firc_loop_t *loop;
    firc_tunsubs_t *subs;
    firc_tunnels_t cfg;
    char dir[64];
    char cache[96];
    int changed;
} fx_t;

static fx_t *g_fx;

static void on_changed(void *ud)
{
    ((fx_t *)ud)->changed++;
}

static void reset_server(void)
{
    pthread_mutex_lock(&g_mu);
    g_hits = 0;
    g_status = 200;
    g_delay_ms = 0;
    snprintf(g_body, sizeof g_body, "%s", BODY_AB);
    g_n_marks = 0;
    g_sockopt_fail = 0;
    pthread_mutex_unlock(&g_mu);
}

static bool fx_up(fx_t *f)
{
    memset(f, 0, sizeof *f);
    reset_server();
    firc_sub_fetch_set_setsockopt_for_test(record_sockopt);
    snprintf(f->dir, sizeof f->dir, "/tmp/firc_tunsubs_XXXXXX");
    if (mkdtemp(f->dir) == NULL) {
        return false;
    }
    snprintf(f->cache, sizeof f->cache, "%s/c/tunnels", f->dir);
    g_fx = f;
    if (firc_loop_create(&f->loop) != FIRC_OK) {
        return false;
    }
    f->subs = firc_tunsubs_new(f->loop, f->cache, on_changed, f);
    return f->subs != NULL;
}

static void fx_down(fx_t *f)
{
    firc_tunsubs_free(f->subs);
    f->subs = NULL;
    if (f->loop != NULL) {
        firc_loop_destroy(f->loop);
        f->loop = NULL;
    }
    firc_tunnels_free(&f->cfg);
    if (f->dir[0] != 0) {
        char cmd[128];
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", f->dir);
        if (system(cmd) != 0) {
        }
        f->dir[0] = 0;
    }
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    g_fx = NULL;
}

static void teardown(void *ud)
{
    (void)ud;
    if (g_fx != NULL) {
        fx_down(g_fx);
    }
    server_stop();
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    firc_log_set_fd(1);
}

static bool load(fx_t *f, const char *tunnels)
{
    char doc[2048];
    snprintf(doc, sizeof doc, "tunnels:\n%s", tunnels);
    firc_tunnels_free(&f->cfg);
    firc_tun_err_t e = {0};
    if (firc_tunnels_load_buffer(&f->cfg, doc, strlen(doc), &e) != FIRC_OK) {
        fprintf(stderr, "config: %s: %s\n", e.where, e.why);
        return false;
    }
    return true;
}

#define TUN(id, n, url, interval)                                                                 \
    "  - id: " id "\n    device: tunvless" n "\n    sources:\n      - id: 0000000" n "\n"           \
    "        subscription: { name: P, url: \"" url "\", interval: " interval " }\n"
#define TUN_UP(id, n, url, up) TUN(id, n, url, "6h") "    uplink: " up "\n"

static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

typedef struct {
    fx_t *f;
    bool (*done)(fx_t *f, void *arg);
    void *arg;
    int64_t deadline;
    bool ok;
} wait_t;

static void wait_cb(firc_loop_t *loop, void *ud)
{
    wait_t *w = ud;
    w->ok = w->done(w->f, w->arg);
    if (w->ok || mono_ms() >= w->deadline) {
        firc_loop_stop(loop);
    }
}

static bool run_until(fx_t *f, bool (*done)(fx_t *f, void *arg), void *arg, int ms)
{
    wait_t w = {f, done, arg, mono_ms() + ms, false};
    int timer = 0;
    firc_loop_add_timer(f->loop, 10, 10, wait_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
    return w.ok;
}

static bool settled_after(fx_t *f, void *arg)
{
    const int *want_hits = arg;
    firc_tun_sub_state_t st;
    return hits() >= *want_hits && firc_tunsubs_state(f->subs, URL, 0, &st) == 1 && !st.fetching &&
           st.last_try_ms > 0;
}

static bool changed_once(fx_t *f, void *arg)
{
    (void)arg;
    return f->changed >= 1;
}

static bool never(fx_t *f, void *arg)
{
    (void)f;
    (void)arg;
    return false;
}

static void idle(fx_t *f, int ms)
{
    (void)run_until(f, never, NULL, ms);
}

static bool hash16(const char *url, const char *ident, char out[17])
{
    char cmd[512];
    snprintf(cmd, sizeof cmd, "printf '%%s\\n%%s' '%s' '%s' | sha256sum", url, ident);
    FILE *p = popen(cmd, "r");
    if (p == NULL) {
        return false;
    }
    bool ok = fread(out, 1, 16, p) == 16;
    out[16] = 0;
    pclose(p);
    return ok;
}

static bool cache_path(fx_t *f, const char *url, const char *ident, char *buf, size_t cap)
{
    char h[17];
    if (!hash16(url, ident, h)) {
        return false;
    }
    snprintf(buf, cap, "%s/%s", f->cache, h);
    return true;
}

static size_t slurp(const char *path, char *buf, size_t cap)
{
    buf[0] = 0;
    FILE *fp = fopen(path, "re");
    if (fp == NULL) {
        return 0;
    }
    size_t n = fread(buf, 1, cap - 1, fp);
    buf[n] = 0;
    fclose(fp);
    return n;
}

static void want(fx_t *f, const uint32_t *marks)
{
    firc_tunsubs_want(f->subs, &f->cfg, marks);
}

/* catches: a body not cached, cached under another key, or a cache readable by others */
TEST the_first_fetch_writes_a_private_cache_file(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    const uint32_t marks[] = {0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    char path[160];
    ASSERT(cache_path(&f, URL, "auto", path, sizeof path));
    struct stat st;
    ASSERT_EQ(0, stat(path, &st));
    ASSERT_EQ_FMT(0600u, (unsigned)(st.st_mode & 0777), "%o");
    ASSERT_EQ(0, stat(f.cache, &st));
    ASSERT_EQ_FMT(0700u, (unsigned)(st.st_mode & 0777), "%o");
    char buf[512];
    slurp(path, buf, sizeof buf);
    ASSERT_STR_EQ(BODY_AB, buf);
    size_t n = 0;
    const firc_tun_body_t *b = firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_STR_EQ(URL, b[0].url);
    ASSERT_EQ_FMT(0u, b[0].mark, "%u");
    ASSERT_EQ_FMT(strlen(BODY_AB), b[0].len, "%zu");
    ASSERT_MEM_EQ(BODY_AB, b[0].body, strlen(BODY_AB));
    firc_tun_sub_state_t ss;
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, URL, 0, &ss), "%zu");
    ASSERT_EQ_FMT((size_t)2, ss.nodes, "%zu");
    char h[17];
    ASSERT(hash16(URL, "auto", h));
    ASSERT_STR_EQ(h, ss.url_hash);
    ASSERT_STR_EQ("", ss.error);
    ASSERT(ss.last_ok_ms > 0 && ss.last_ok_ms == ss.last_try_ms);
    ASSERT_EQ(1, f.changed);
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: the cache rewritten (flash wear) or changed() fired when the body came back the same */
TEST an_unchanged_body_is_not_rewritten(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    const uint32_t marks[] = {0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    char path[160];
    ASSERT(cache_path(&f, URL, "auto", path, sizeof path));
    struct stat a;
    ASSERT_EQ(0, stat(path, &a));
    struct timespec ts = {0, 20 * 1000000L};
    nanosleep(&ts, NULL);
    ASSERT_EQ(FIRC_OK, firc_tunsubs_refresh(f.subs, "t0"));
    int two = 2;
    ASSERT(run_until(&f, settled_after, &two, 3000));
    struct stat b;
    ASSERT_EQ(0, stat(path, &b));
    ASSERT_EQ(a.st_ino, b.st_ino);
    ASSERT_EQ(a.st_mtim.tv_nsec, b.st_mtim.tv_nsec);
    ASSERT_EQ(a.st_mtim.tv_sec, b.st_mtim.tv_sec);
    ASSERT_EQ(1, f.changed);
    pthread_mutex_lock(&g_mu);
    snprintf(g_body, sizeof g_body, "%s", BODY_C);
    pthread_mutex_unlock(&g_mu);
    ASSERT_EQ(FIRC_OK, firc_tunsubs_refresh(f.subs, "t0"));
    int three = 3;
    ASSERT(run_until(&f, settled_after, &three, 3000));
    char buf[512];
    slurp(path, buf, sizeof buf);
    ASSERT_STR_EQ(BODY_C, buf);
    ASSERT_EQ(2, f.changed);
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: a failed refresh dropping the last good body, or no error and last success shown */
TEST a_failed_fetch_keeps_the_body_and_says_why(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    const uint32_t marks[] = {0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    firc_tun_sub_state_t ok;
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, URL, 0, &ok), "%zu");
    pthread_mutex_lock(&g_mu);
    g_status = 503;
    pthread_mutex_unlock(&g_mu);
    struct timespec ts = {0, 20 * 1000000L};
    nanosleep(&ts, NULL);
    ASSERT_EQ(FIRC_OK, firc_tunsubs_refresh(f.subs, "t0"));
    int two = 2;
    ASSERT(run_until(&f, settled_after, &two, 3000));
    firc_tun_sub_state_t bad;
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, URL, 0, &bad), "%zu");
    ASSERT(strstr(bad.error, "503") != NULL);
    ASSERT_EQ(ok.last_ok_ms, bad.last_ok_ms);
    ASSERT(bad.last_try_ms > bad.last_ok_ms);
    ASSERT_EQ_FMT((size_t)2, bad.nodes, "%zu");
    size_t n = 0;
    const firc_tun_body_t *b = firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_MEM_EQ(BODY_AB, b[0].body, strlen(BODY_AB));
    ASSERT_EQ(1, f.changed);
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: a restart without network leaving the tunnel with no nodes although the cache holds them */
TEST a_restart_takes_the_cache_without_network(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    const uint32_t marks[] = {0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    server_stop();
    firc_tunsubs_free(f.subs);
    f.subs = firc_tunsubs_new(f.loop, f.cache, on_changed, &f);
    ASSERT(f.subs != NULL);
    want(&f, marks);
    size_t n = 0;
    const firc_tun_body_t *b = firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_STR_EQ(URL, b[0].url);
    ASSERT_MEM_EQ(BODY_AB, b[0].body, strlen(BODY_AB));
    firc_tun_sub_state_t st;
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, URL, 0, &st), "%zu");
    ASSERT_EQ_FMT((size_t)2, st.nodes, "%zu");
    fx_down(&f);
    PASS();
}

static bool write_padded(const char *path, size_t size)
{
    FILE *fp = fopen(path, "we");
    if (fp == NULL) {
        return false;
    }
    size_t n = strlen(BODY_AB);
    bool ok = fwrite(BODY_AB, 1, n, fp) == n;
    for (; ok && n < size; n++) {
        ok = fputc('\n', fp) != EOF;
    }
    return fclose(fp) == 0 && ok;
}

/* catches: a cache file above the fetch cap read into memory, or one at the cap refused */
TEST an_oversized_cache_file_is_refused(void)
{
    static fx_t f;
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "0s")));
    char path[160];
    ASSERT(cache_path(&f, URL, "auto", path, sizeof path));
    ASSERT(write_padded(path, FIRC_SUB_FETCH_MAX_BODY_BYTES + 1));
    const uint32_t marks[] = {0};
    want(&f, marks);
    size_t n = 7;
    (void)firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    ASSERT(write_padded(path, FIRC_SUB_FETCH_MAX_BODY_BYTES));
    firc_tunsubs_free(f.subs);
    f.subs = firc_tunsubs_new(f.loop, f.cache, on_changed, &f);
    ASSERT(f.subs != NULL);
    want(&f, marks);
    (void)firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    fx_down(&f);
    PASS();
}

static bool hits_at_least(fx_t *f, void *arg)
{
    (void)f;
    return hits() >= *(int *)arg;
}

static bool bodies_at_least(fx_t *f, void *arg)
{
    size_t n = 0;
    (void)firc_tunsubs_bodies(f->subs, &n);
    return n >= *(size_t *)arg;
}

static uint32_t seen_marks(int *n)
{
    pthread_mutex_lock(&g_mu);
    uint32_t seen = 0;
    for (int i = 0; i < g_n_marks; i++) {
        seen |= g_marks[i];
    }
    *n = g_n_marks;
    pthread_mutex_unlock(&g_mu);
    return seen;
}

static bool body_for(fx_t *f, uint32_t mark)
{
    size_t n = 0;
    const firc_tun_body_t *b = firc_tunsubs_bodies(f->subs, &n);
    for (size_t i = 0; i < n; i++) {
        if (b[i].mark == mark && strcmp(b[i].url, URL) == 0) {
            return true;
        }
    }
    return false;
}

/* catches: one fetch shared by two uplinks, so a tunnel takes a body fetched through another's way out */
TEST two_uplinks_fetch_twice_and_cache_apart(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN_UP("t0", "0", URL, "iface:eth8") TUN_UP("t1", "1", URL, "iface:eth9")));
    const uint32_t marks[] = {0x10000, 0x20000};
    want(&f, marks);
    size_t two = 2;
    ASSERT(run_until(&f, bodies_at_least, &two, 3000));
    idle(&f, 200);
    ASSERT_EQ(2, hits());
    int n_marks = 0;
    ASSERT_EQ_FMT(0x30000u, seen_marks(&n_marks), "%x");
    ASSERT_EQ(2, n_marks);
    char p1[160], p2[160];
    ASSERT(cache_path(&f, URL, "iface:eth8", p1, sizeof p1));
    ASSERT(cache_path(&f, URL, "iface:eth9", p2, sizeof p2));
    ASSERT(strcmp(p1, p2) != 0);
    ASSERT_EQ(0, access(p1, F_OK));
    ASSERT_EQ(0, access(p2, F_OK));
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: two tunnels on one uplink fetching twice, or one of them left without the body under its own mark */
TEST one_uplink_fetches_once_for_two_marks(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN_UP("t0", "0", URL, "iface:eth8") TUN_UP("t1", "1", URL, "iface:eth8")));
    const uint32_t marks[] = {0x10000, 0x20000};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    idle(&f, 300);
    ASSERT_EQ(1, hits());
    int n_marks = 0;
    uint32_t seen = seen_marks(&n_marks);
    ASSERT_EQ(1, n_marks);
    ASSERT(seen == 0x10000 || seen == 0x20000);
    size_t n = 0;
    (void)firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    ASSERT(body_for(&f, 0x10000));
    ASSERT(body_for(&f, 0x20000));
    firc_tun_sub_state_t st;
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, URL, 0x20000, &st), "%zu");
    char h[17];
    ASSERT(hash16(URL, "iface:eth8", h));
    ASSERT_STR_EQ(h, st.url_hash);
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: the cache keyed by the mark, which the next start may hand out differently, so a reboot misses it */
TEST a_new_mark_on_the_same_uplink_takes_the_cache(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN_UP("t0", "0", URL, "iface:eth8")));
    const uint32_t first[] = {0x10000};
    want(&f, first);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    server_stop();
    firc_tunsubs_free(f.subs);
    f.subs = firc_tunsubs_new(f.loop, f.cache, on_changed, &f);
    ASSERT(f.subs != NULL);
    const uint32_t second[] = {0x30000};
    want(&f, second);
    ASSERT(body_for(&f, 0x30000));
    fx_down(&f);
    PASS();
}

/* catches: the same subscription fetched once per tunnel instead of once per (url, uplink) */
TEST one_mark_fetches_once_for_two_tunnels(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h") TUN("t1", "1", URL, "12h")));
    const uint32_t marks[] = {0, 0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    idle(&f, 300);
    ASSERT_EQ(1, hits());
    size_t n = 0;
    (void)firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_EQ(FIRC_OK, firc_tunsubs_refresh(f.subs, "t1"));
    int two = 2;
    ASSERT(run_until(&f, hits_at_least, &two, 3000));
    ASSERT_EQ(FIRC_ERR_NOENT, firc_tunsubs_refresh(f.subs, "zz"));
    fx_down(&f);
    server_stop();
    PASS();
}

static void set_body(const char *body)
{
    pthread_mutex_lock(&g_mu);
    snprintf(g_body, sizeof g_body, "%s", body);
    pthread_mutex_unlock(&g_mu);
}

/* catches: a captive portal or empty answer replacing the nodes, rewriting the cache or firing changed() */
TEST an_answer_without_nodes_is_a_failed_refresh(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    const uint32_t marks[] = {0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    set_body("<html><body>Log in to the hotel wifi</body></html>\n");
    struct timespec ts = {0, 20 * 1000000L};
    nanosleep(&ts, NULL);
    ASSERT_EQ(FIRC_OK, firc_tunsubs_refresh(f.subs, "t0"));
    int two = 2;
    ASSERT(run_until(&f, settled_after, &two, 3000));
    firc_tun_sub_state_t st;
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, URL, 0, &st), "%zu");
    ASSERT_STR_EQ("no nodes in the answer", st.error);
    ASSERT(st.last_try_ms > st.last_ok_ms);
    size_t n = 0;
    const firc_tun_body_t *b = firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_MEM_EQ(BODY_AB, b[0].body, strlen(BODY_AB));
    char path[160], buf[512];
    ASSERT(cache_path(&f, URL, "auto", path, sizeof path));
    slurp(path, buf, sizeof buf);
    ASSERT_STR_EQ(BODY_AB, buf);
    ASSERT_EQ(1, f.changed);
    set_body("");
    ASSERT_EQ(FIRC_OK, firc_tunsubs_refresh(f.subs, "t0"));
    int three = 3;
    ASSERT(run_until(&f, settled_after, &three, 3000));
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, URL, 0, &st), "%zu");
    ASSERT_STR_EQ("no nodes in the answer", st.error);
    slurp(path, buf, sizeof buf);
    ASSERT_STR_EQ(BODY_AB, buf);
    ASSERT_EQ(1, f.changed);
    fx_down(&f);
    server_stop();
    PASS();
}

#define BODY_INSECURE "vless://" U "@a.example:443?security=tls&sni=a.example&allowInsecure=1#A\n"

static const firc_tun_node_t *only_node(const firc_tunnel_t *t, const firc_tun_body_t *b, size_t nb,
                                        firc_tun_nodes_t *out)
{
    if (firc_tun_nodes_build(t, 0, b, nb, out) != FIRC_OK || out->n != 1) {
        return NULL;
    }
    return &out->v[0];
}

/* catches: allowInsecure nodes counted as none, so the body is refused even for a tunnel that allows them */
TEST an_insecure_only_body_is_kept_and_left_to_each_tunnel(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    set_body(BODY_INSECURE);
    ASSERT(load(&f, TUN("t0", "0", URL, "6h") "    advanced: { insecure: true }\n" TUN("t1", "1", URL, "6h")));
    const uint32_t marks[] = {0, 0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    firc_tun_sub_state_t st;
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, URL, 0, &st), "%zu");
    ASSERT_STR_EQ("", st.error);
    ASSERT_EQ_FMT((size_t)1, st.nodes, "%zu");
    size_t n = 0;
    const firc_tun_body_t *b = firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_MEM_EQ(BODY_INSECURE, b[0].body, strlen(BODY_INSECURE));
    firc_tun_nodes_t yes, no;
    const firc_tun_node_t *ny = only_node(&f.cfg.t[0], b, n, &yes);
    const firc_tun_node_t *nn = only_node(&f.cfg.t[1], b, n, &no);
    bool ok = ny != NULL && nn != NULL && ny->link != NULL && nn->link == NULL &&
              strstr(nn->skip_reason, "allowInsecure") != NULL;
    firc_tun_nodes_free(&yes);
    firc_tun_nodes_free(&no);
    ASSERT(ok);
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: a cache write that failed never tried again while the body stays the same */
TEST a_failed_cache_write_is_retried(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    char path[160];
    ASSERT(cache_path(&f, URL, "auto", path, sizeof path));
    ASSERT_EQ(0, mkdir(path, 0700));
    const uint32_t marks[] = {0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    struct stat st;
    ASSERT_EQ(0, stat(path, &st));
    ASSERT(S_ISDIR(st.st_mode));
    ASSERT_EQ(0, rmdir(path));
    ASSERT_EQ(FIRC_OK, firc_tunsubs_refresh(f.subs, "t0"));
    int two = 2;
    ASSERT(run_until(&f, settled_after, &two, 3000));
    char buf[512];
    slurp(path, buf, sizeof buf);
    ASSERT_STR_EQ(BODY_AB, buf);
    ASSERT_EQ(1, f.changed);
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: a cache directory left readable by others because it already existed */
TEST an_open_cache_dir_is_made_private(void)
{
    static fx_t f;
    ASSERT(fx_up(&f));
    firc_tunsubs_free(f.subs);
    ASSERT_EQ(0, chmod(f.cache, 0755));
    f.subs = firc_tunsubs_new(f.loop, f.cache, on_changed, &f);
    ASSERT(f.subs != NULL);
    struct stat st;
    ASSERT_EQ(0, stat(f.cache, &st));
    ASSERT_EQ_FMT(0700u, (unsigned)(st.st_mode & 0777), "%o");
    fx_down(&f);
    PASS();
}

/* catches: a cache file that is a symlink followed to whatever it points at */
TEST a_symlinked_cache_file_is_refused(void)
{
    static fx_t f;
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "0s")));
    char real[96];
    snprintf(real, sizeof real, "%s/real", f.dir);
    ASSERT(write_padded(real, strlen(BODY_AB)));
    char path[160];
    ASSERT(cache_path(&f, URL, "auto", path, sizeof path));
    ASSERT_EQ(0, symlink(real, path));
    const uint32_t marks[] = {0};
    want(&f, marks);
    size_t n = 7;
    (void)firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    ASSERT_EQ(0, unlink(path));
    ASSERT(write_padded(path, strlen(BODY_AB)));
    firc_tunsubs_free(f.subs);
    f.subs = firc_tunsubs_new(f.loop, f.cache, on_changed, &f);
    ASSERT(f.subs != NULL);
    want(&f, marks);
    (void)firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    fx_down(&f);
    PASS();
}

/* catches: a rotated URL's cache kept for ever, or the sweep taking a disabled tunnel's cache or a foreign file */
TEST the_sweep_removes_only_unused_cache_files(void)
{
    static fx_t f;
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "0s") TUN_UP("t1", "1", SLOW_URL, "iface:eth8") "    enable: false\n"));
    char kept1[160], kept2[160], stale[160], other[160];
    ASSERT(cache_path(&f, URL, "auto", kept1, sizeof kept1));
    ASSERT(cache_path(&f, SLOW_URL, "iface:eth8", kept2, sizeof kept2));
    ASSERT(cache_path(&f, URL, "iface:eth8", stale, sizeof stale));
    snprintf(other, sizeof other, "%s/notes.txt", f.cache);
    ASSERT(write_padded(kept1, strlen(BODY_AB)));
    ASSERT(write_padded(kept2, strlen(BODY_AB)));
    ASSERT(write_padded(stale, strlen(BODY_AB)));
    ASSERT(write_padded(other, strlen(BODY_AB)));
    firc_tunsubs_sweep(f.subs, &f.cfg);
    ASSERT_EQ(0, access(kept1, F_OK));
    ASSERT_EQ(0, access(kept2, F_OK));
    ASSERT_EQ(0, access(other, F_OK));
    ASSERT_EQ(-1, access(stale, F_OK));
    fx_down(&f);
    PASS();
}

/* catches: a disabled tunnel's body dropped from memory, fetched, handed to the running build, or held under another uplink */
TEST a_disabled_tunnel_keeps_its_body_unfetched_for_display(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    const uint32_t marks[] = {0, 0};
    want(&f, marks);
    ASSERT(run_until(&f, changed_once, NULL, 3000));
    ASSERT(load(&f, TUN("t0", "0", URL, "6h") "    enable: false\n" TUN_UP("t1", "1", URL, "iface:eth9")
                        "    enable: false\n"));
    want(&f, marks);
    size_t n = 1;
    (void)firc_tunsubs_bodies(f.subs, &n);
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    ASSERT_EQ(FIRC_ERR_NOENT, firc_tunsubs_refresh(f.subs, "t0"));
    firc_tun_body_t held[2];
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_held(f.subs, &f.cfg.t[0], &f.cfg.t[1], held, 2), "%zu");
    ASSERT_STR_EQ(URL, held[0].url);
    ASSERT_EQ_FMT(0u, held[0].mark, "%u");
    ASSERT_EQ_FMT(strlen(BODY_AB), held[0].len, "%zu");
    ASSERT_MEM_EQ(BODY_AB, held[0].body, strlen(BODY_AB));
    ASSERT_EQ_FMT((size_t)0, firc_tunsubs_held(f.subs, &f.cfg.t[1], &f.cfg.t[0], held, 2), "%zu");
    firc_tunsubs_free(f.subs);
    f.subs = firc_tunsubs_new(f.loop, f.cache, on_changed, &f);
    ASSERT(f.subs != NULL);
    want(&f, marks);
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_held(f.subs, &f.cfg.t[0], &f.cfg.t[0], held, 2), "%zu");
    idle(&f, 300);
    ASSERT_EQ(1, hits());
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    want(&f, marks);
    int two = 2;
    ASSERT(run_until(&f, hits_at_least, &two, 3000));
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: the longer interval of two tunnels sharing a pair winning, or a manual-only pair fetched on schedule */
TEST the_shortest_interval_wins_and_zero_is_by_hand(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    ASSERT(load(&f, TUN("t0", "0", URL, "12h") TUN("t1", "1", URL, "10m")));
    const uint32_t marks[] = {0, 0};
    want(&f, marks);
    int one = 1;
    ASSERT(run_until(&f, settled_after, &one, 3000));
    firc_tunsubs_advance_for_test(f.subs, 599 * 1000);
    firc_tunsubs_due(f.subs);
    idle(&f, 200);
    ASSERT_EQ(1, hits());
    firc_tunsubs_advance_for_test(f.subs, 2 * 1000);
    firc_tunsubs_due(f.subs);
    int two = 2;
    ASSERT(run_until(&f, settled_after, &two, 3000));
    ASSERT_EQ(2, hits());

    ASSERT(load(&f, TUN("t0", "0", URL, "0s")));
    want(&f, marks);
    firc_tunsubs_advance_for_test(f.subs, (int64_t)400 * 24 * 3600 * 1000);
    firc_tunsubs_due(f.subs);
    idle(&f, 200);
    ASSERT_EQ(2, hits());
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: a pair that never got a body waiting a whole interval (hours) after a failed first fetch */
TEST a_pair_without_a_body_retries_on_the_next_tick(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    pthread_mutex_lock(&g_mu);
    g_status = 500;
    pthread_mutex_unlock(&g_mu);
    ASSERT(load(&f, TUN("t0", "0", URL, "0s")));
    const uint32_t marks[] = {0};
    want(&f, marks);
    int one = 1;
    ASSERT(run_until(&f, settled_after, &one, 3000));
    firc_tunsubs_advance_for_test(f.subs, 59 * 1000);
    firc_tunsubs_due(f.subs);
    idle(&f, 200);
    ASSERT_EQ(1, hits());
    firc_tunsubs_advance_for_test(f.subs, 2 * 1000);
    firc_tunsubs_due(f.subs);
    int two = 2;
    ASSERT(run_until(&f, settled_after, &two, 3000));
    pthread_mutex_lock(&g_mu);
    g_status = 200;
    pthread_mutex_unlock(&g_mu);
    firc_tunsubs_advance_for_test(f.subs, 61 * 1000);
    firc_tunsubs_due(f.subs);
    int three = 3;
    ASSERT(run_until(&f, settled_after, &three, 3000));
    firc_tunsubs_advance_for_test(f.subs, 3600 * 1000);
    firc_tunsubs_due(f.subs);
    idle(&f, 200);
    ASSERT_EQ(3, hits());
    fx_down(&f);
    server_stop();
    PASS();
}

static bool slow_done(fx_t *f, void *arg)
{
    (void)arg;
    firc_tun_sub_state_t st;
    return firc_tunsubs_state(f->subs, SLOW_URL, 0, &st) == 1 && !st.fetching && st.last_ok_ms > 0;
}

/* catches: due or refresh queueing a second fetch of a pair already in flight */
TEST a_pair_in_flight_is_not_queued_again(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    g_delay_ms = 400;
    ASSERT(load(&f, TUN("t0", "0", SLOW_URL, "10m")));
    const uint32_t marks[] = {0};
    want(&f, marks);
    idle(&f, 100);
    firc_tun_sub_state_t st;
    ASSERT_EQ_FMT((size_t)1, firc_tunsubs_state(f.subs, SLOW_URL, 0, &st), "%zu");
    ASSERT(st.fetching);
    firc_tunsubs_advance_for_test(f.subs, 3600 * 1000);
    firc_tunsubs_due(f.subs);
    ASSERT_EQ(FIRC_OK, firc_tunsubs_refresh(f.subs, "t0"));
    firc_tunsubs_due(f.subs);
    ASSERT(run_until(&f, slow_done, NULL, 3000));
    idle(&f, 600);
    ASSERT_EQ(1, hits());
    fx_down(&f);
    server_stop();
    PASS();
}

/* catches: the mark never set on the socket, set when none was asked, or a refused mark fetching unmarked */
TEST the_mark_reaches_the_socket_or_the_fetch_fails(void)
{
    ASSERT(server_start());
    reset_server();
    firc_sub_fetch_set_setsockopt_for_test(record_sockopt);
    char *body = NULL;
    size_t len = 0;
    int status = 0;
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_mark(URL, 0x2a0000, &body, &len, &status));
    free(body);
    ASSERT_EQ(200, status);
    ASSERT_EQ(1, g_n_marks);
    ASSERT_EQ_FMT(0x2a0000u, g_marks[0], "%x");
    ASSERT_EQ(FIRC_OK, firc_sub_fetch_list_mark(URL, 0, &body, &len, &status));
    free(body);
    ASSERT_EQ(1, g_n_marks);
    ASSERT_EQ(2, hits());
    g_sockopt_fail = 1;
    body = NULL;
    ASSERT_EQ(FIRC_ERR_SYS, firc_sub_fetch_list_mark(URL, 0x2a0000, &body, &len, &status));
    ASSERT_EQ(NULL, body);
    ASSERT_EQ(2, g_n_marks);
    ASSERT_EQ(2, hits());
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    server_stop();
    PASS();
}

/* catches: a token in the URL's path or query reaching the log or the shown error */
TEST the_url_is_logged_as_scheme_and_host_only(void)
{
    static fx_t f;
    ASSERT(server_start());
    ASSERT(fx_up(&f));
    char logp[96];
    snprintf(logp, sizeof logp, "%s/log", f.dir);
    int fd = open(logp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    ASSERT(fd >= 0);
    firc_log_level_t old = firc_log_level();
    firc_log_set_level(FIRC_LOG_TRACE);
    firc_log_set_fd(fd);
    pthread_mutex_lock(&g_mu);
    g_status = 500;
    pthread_mutex_unlock(&g_mu);
    ASSERT(load(&f, TUN("t0", "0", URL, "6h")));
    const uint32_t marks[] = {0};
    want(&f, marks);
    int one = 1;
    bool done = run_until(&f, settled_after, &one, 3000);
    firc_tun_sub_state_t st;
    size_t have = firc_tunsubs_state(f.subs, URL, 0, &st);
    firc_log_set_fd(1);
    firc_log_set_level(old);
    close(fd);
    ASSERT(done);
    ASSERT_EQ_FMT((size_t)1, have, "%zu");
    char buf[4096];
    slurp(logp, buf, sizeof buf);
    ASSERT(strstr(buf, "http://127.0.0.1/…") != NULL);
    ASSERT_EQ(NULL, strstr(buf, "s3cr3t"));
    ASSERT_EQ(NULL, strstr(buf, "/sub"));
    ASSERT(st.error[0] != 0);
    ASSERT_EQ(NULL, strstr(st.error, "s3cr3t"));
    ASSERT_EQ(NULL, strstr(st.error, "/sub"));
    char r[64];
    firc_sub_url_redact("https://user:pw@h.example:8443/p/tok?x=1#f", r, sizeof r);
    ASSERT_STR_EQ("https://h.example/…", r);
    firc_sub_url_redact("not a url", r, sizeof r);
    ASSERT_STR_EQ("(bad url)", r);
    fx_down(&f);
    server_stop();
    PASS();
}

SUITE(tunsubs)
{
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(the_first_fetch_writes_a_private_cache_file);
    RUN_TEST(an_unchanged_body_is_not_rewritten);
    RUN_TEST(a_failed_fetch_keeps_the_body_and_says_why);
    RUN_TEST(a_restart_takes_the_cache_without_network);
    RUN_TEST(an_oversized_cache_file_is_refused);
    RUN_TEST(two_uplinks_fetch_twice_and_cache_apart);
    RUN_TEST(one_uplink_fetches_once_for_two_marks);
    RUN_TEST(a_new_mark_on_the_same_uplink_takes_the_cache);
    RUN_TEST(an_answer_without_nodes_is_a_failed_refresh);
    RUN_TEST(an_insecure_only_body_is_kept_and_left_to_each_tunnel);
    RUN_TEST(a_failed_cache_write_is_retried);
    RUN_TEST(an_open_cache_dir_is_made_private);
    RUN_TEST(a_symlinked_cache_file_is_refused);
    RUN_TEST(the_sweep_removes_only_unused_cache_files);
    RUN_TEST(one_mark_fetches_once_for_two_tunnels);
    RUN_TEST(a_disabled_tunnel_keeps_its_body_unfetched_for_display);
    RUN_TEST(the_shortest_interval_wins_and_zero_is_by_hand);
    RUN_TEST(a_pair_without_a_body_retries_on_the_next_tick);
    RUN_TEST(a_pair_in_flight_is_not_queued_again);
    RUN_TEST(the_mark_reaches_the_socket_or_the_fetch_fails);
    RUN_TEST(the_url_is_logged_as_scheme_and_host_only);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    firc_sub_fetch_global_init();
    RUN_SUITE(tunsubs);
    firc_sub_fetch_global_cleanup();
    GREATEST_MAIN_END();
}
