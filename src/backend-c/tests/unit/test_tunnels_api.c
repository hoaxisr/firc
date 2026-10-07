#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */
#include "greatest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "fake_rtnl.h"
#include "firc/app.h"
#include "firc/auth.h"
#include "firc/httpd.h"
#include "firc/jwt.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/models.h"
#include "firc/rtnl.h"
#include "firc/sub_fetch.h"
#include "firc/tunnels.h"
#include "firc/tunnels_api.h"
#include "firc/tunrun.h"
#include "firc/tunsubs.h"

#define API_PORT 18143
#define SUB_PORT 18144
#define FAKE "tests/unit/fixtures/fake_tunvless.sh"
#define U "00000000-0000-4000-8000-000000000001"
#define LINK_A "vless://" U "@a.example.invalid:443?security=none#A"
#define LINK_B "vless://" U "@b.example.invalid:443?security=none#B"
#define SUB_URL "http://127.0.0.1:18144/sub?token=s3cr3t"
#define SUB_BODY                                                                                       \
    "vless://" U "@a.example.invalid:443?security=none#A\nvless://" U "@b.example.invalid:443?security=none#B\n" \
    "vless://" U "@c.example.invalid:443?security=none#C\nvless://" U "@d.example.invalid:443?security=none#D\n"
#define HASH                                                                                           \
    "$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"                                 \
    "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/"

typedef struct {
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    firc_loop_t *loop;
    firc_httpd_t *http;
    firc_tunrun_t *run;
    firc_tunsubs_t *subs;
    firc_config_t cfg;
    firc_app_t *app;
    firc_tunnels_ctx_t ctx;
    firc_auth_ctx_t auth;
    char dir[64];
    char path[128];
    char cache[128];
    char sysfs[128];
    char starts[128];
    char argv[128];
    char shadow[128];
    char passwd[128];
    char state[128];
    char token[FIRC_JWT_MAX_TOKEN];
    const char *initial;
    pthread_t thread;
    firc_loop_t *sub_loop;
    firc_httpd_t *sub_http;
    pthread_t sub_thread;
} hx_t;

static hx_t *g_hx;

static const char *state_dir(void *ud)
{
    return ((hx_t *)ud)->state;
}

static void *loop_main(void *ud)
{
    firc_loop_run(ud);
    return NULL;
}

typedef struct {
    hx_t *h;
    void (*fn)(hx_t *h);
    sem_t done;
} call_t;

static void call_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    call_t *c = ud;
    c->fn(c->h);
    sem_post(&c->done);
}

static void on_loop(hx_t *h, void (*fn)(hx_t *h))
{
    call_t c = {h, fn, {{0}}};
    sem_init(&c.done, 0, 0);
    if (firc_loop_post(h->loop, call_cb, &c) == FIRC_OK) {
        sem_wait(&c.done);
    }
    sem_destroy(&c.done);
}

static void apply_text(hx_t *h, const char *doc)
{
    firc_tunnels_t t = {0};
    firc_tun_err_t e = {0};
    if (firc_tunnels_load_buffer(&t, doc, strlen(doc), &e) != FIRC_OK) {
        fprintf(stderr, "config: %s: %s\n", e.where, e.why);
        return;
    }
    (void)firc_tunnels_save_file(&t, h->path);
    (void)firc_tunrun_apply(h->run, &t);
    firc_tunnels_free(&t);
}

static void bring_up(hx_t *h)
{
    h->run = firc_tunrun_new(h->loop, h->rtnl, 4300u, FAKE);
    h->subs = firc_tunsubs_new(h->loop, h->cache, firc_tunrun_bodies_changed, h->run);
    firc_tunrun_set_subs(h->run, h->subs);
    h->ctx.run = h->run;
    h->ctx.subs = h->subs;
    if (h->initial != NULL) {
        apply_text(h, h->initial);
    }
}

static void bring_down(hx_t *h)
{
    firc_tunnels_api_close(&h->ctx);
    firc_tunrun_set_subs(h->run, NULL);
    firc_tunsubs_free(h->subs);
    firc_tunrun_free(h->run);
}

static void h_sub(firc_http_req_t *req, firc_http_res_t *res, void *ud)
{
    (void)req;
    (void)ud;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)SUB_BODY, strlen(SUB_BODY));
}

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "we");
    if (f != NULL) {
        fputs(text, f);
        fclose(f);
    }
}

static void write_counter(hx_t *h, const char *dev, const char *which, unsigned long long v)
{
    char p[256];
    snprintf(p, sizeof p, "%s/%s", h->sysfs, dev);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/%s/statistics", h->sysfs, dev);
    mkdir(p, 0700);
    snprintf(p, sizeof p, "%s/%s/statistics/%s", h->sysfs, dev, which);
    char text[32];
    snprintf(text, sizeof text, "%llu\n", v);
    write_file(p, text);
}

static void add_group(hx_t *h, const char *name, const char *iface)
{
    firc_group_t *g = firc_group_new();
    g->id = firc_id_random();
    g->enable = false;
    (void)firc_strset(&g->name, name);
    (void)firc_strset(&g->iface, iface);
    (void)firc_app_add_group(h->app, g);
}

static hx_t *hx_start(const char *initial, unsigned link_flags)
{
    hx_t *h = calloc(1, sizeof *h);
    snprintf(h->dir, sizeof h->dir, "/tmp/firc_tunapi_XXXXXX");
    if (mkdtemp(h->dir) == NULL) {
        return NULL;
    }
    snprintf(h->path, sizeof h->path, "%s/tunnels.yaml", h->dir);
    snprintf(h->cache, sizeof h->cache, "%s/cache", h->dir);
    snprintf(h->sysfs, sizeof h->sysfs, "%s/net", h->dir);
    mkdir(h->sysfs, 0700);
    snprintf(h->starts, sizeof h->starts, "%s/starts", h->dir);
    snprintf(h->argv, sizeof h->argv, "%s/argv", h->dir);
    snprintf(h->shadow, sizeof h->shadow, "%s/shadow", h->dir);
    snprintf(h->passwd, sizeof h->passwd, "%s/passwd", h->dir);
    snprintf(h->state, sizeof h->state, "%s/state", h->dir);
    mkdir(h->state, 0700);
    write_file(h->shadow, "admin:" HASH ":19000:0:99999:7:::\n");
    write_file(h->passwd, "");
    setenv("FAKE_STARTS_OUT", h->starts, 1);
    setenv("FAKE_ARGV_OUT", h->argv, 1);
    unsetenv("FAKE_STDIN_OUT");
    h->initial = initial;
    h->kernel = fake_rtnl_start(&h->rtnl);
    if (h->kernel == NULL || firc_loop_create(&h->loop) != FIRC_OK) {
        return NULL;
    }
    fake_rtnl_set_link_flags(h->kernel, link_flags);
    firc_config_init_defaults(&h->cfg);
    firc_app_deps_t deps = {.cfg = &h->cfg, .loop = h->loop};
    h->app = firc_app_create(&deps);
    if (h->app == NULL) {
        return NULL;
    }
    add_group(h, "via-tunnel", "tunvless0");
    add_group(h, "elsewhere", "eth0");
    h->ctx.app = h->app;
    h->ctx.path = h->path;
    h->ctx.binary = FAKE;
    h->ctx.sysfs_net = h->sysfs;
    h->auth.state_dir = state_dir;
    h->auth.ud = h;
    h->auth.shadow_path = h->shadow;
    h->auth.passwd_path = h->passwd;
    if (firc_auth_authenticate_from(h->shadow, h->passwd, h->state, "admin", "hunter2", h->token, sizeof h->token) !=
        FIRC_OK) {
        return NULL;
    }
    if (firc_httpd_create(h->loop, &h->http) != FIRC_OK) {
        return NULL;
    }
    firc_tunnels_register_routes(h->http, &h->ctx);
    firc_httpd_set_middleware(h->http, firc_auth_middleware, &h->auth);
    if (firc_httpd_listen_tcp(h->http, "127.0.0.1", API_PORT) != FIRC_OK) {
        return NULL;
    }
    if (firc_loop_create(&h->sub_loop) != FIRC_OK || firc_httpd_create(h->sub_loop, &h->sub_http) != FIRC_OK) {
        return NULL;
    }
    firc_httpd_route(h->sub_http, "GET", "/sub", h_sub, NULL);
    if (firc_httpd_listen_tcp(h->sub_http, "127.0.0.1", SUB_PORT) != FIRC_OK) {
        return NULL;
    }
    pthread_create(&h->sub_thread, NULL, loop_main, h->sub_loop);
    pthread_create(&h->thread, NULL, loop_main, h->loop);
    on_loop(h, bring_up);
    g_hx = h;
    return h;
}

static void hx_stop(hx_t *h)
{
    if (h == NULL) {
        return;
    }
    on_loop(h, bring_down);
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->http);
    firc_loop_stop(h->sub_loop);
    pthread_join(h->sub_thread, NULL);
    firc_httpd_destroy(h->sub_http);
    firc_loop_destroy(h->sub_loop);
    firc_app_destroy(h->app);
    firc_config_clear(&h->cfg);
    firc_loop_destroy(h->loop);
    firc_rtnl_close(h->rtnl);
    fake_rtnl_stop(h->kernel);
    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", h->dir);
    if (system(cmd) != 0) {
    }
    free(h);
    g_hx = NULL;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

static void teardown(void *ud)
{
    (void)ud;
    hx_stop(g_hx);
    setenv("FAKE_MODE", "ok", 1);
}

static int connect_api(void)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(API_PORT);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0) {
            return fd;
        }
        struct timespec ts = {0, 10000000};
        nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

static int send_request(const char *method, const char *path, const char *body, bool auth)
{
    int fd = connect_api();
    if (fd < 0) {
        return -1;
    }
    size_t len = body != NULL ? strlen(body) : 0;
    size_t cap = len + 4096;
    char *req = malloc(cap);
    char authz[FIRC_JWT_MAX_TOKEN + 40] = "";
    if (auth) {
        snprintf(authz, sizeof authz, "Authorization: Bearer %s\r\n", g_hx->token);
    }
    int n = snprintf(req, cap,
                     "%s %s HTTP/1.1\r\nHost: x\r\n%sContent-Type: application/json\r\nContent-Length: %zu\r\n"
                     "Connection: close\r\n\r\n%s",
                     method, path, authz, len, body != NULL ? body : "");
    ssize_t sent = send(fd, req, (size_t)n, MSG_NOSIGNAL);
    free(req);
    if (sent != n) {
        close(fd);
        return -1;
    }
    return fd;
}

static int read_answer(int fd, char *raw, size_t cap, int wait_s)
{
    struct timeval tv = {wait_s, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    size_t total = 0;
    for (;;) {
        if (total >= cap - 1) {
            break;
        }
        ssize_t n = recv(fd, raw + total, cap - 1 - total, 0);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    raw[total] = 0;
    close(fd);
    int status = 0;
    sscanf(raw, "HTTP/1.1 %d", &status);
    return status;
}

static char g_raw[262144];

static int call_api(const char *method, const char *path, const char *body, cJSON **out)
{
    int fd = send_request(method, path, body, true);
    if (fd < 0) {
        return -1;
    }
    int status = read_answer(fd, g_raw, sizeof g_raw, 15);
    if (out != NULL) {
        const char *b = strstr(g_raw, "\r\n\r\n");
        *out = b != NULL ? cJSON_Parse(b + 4) : NULL;
    }
    return status;
}

static const cJSON *at(const cJSON *o, const char *k)
{
    return cJSON_GetObjectItemCaseSensitive(o, k);
}

static const cJSON *tunnel_named(const cJSON *ans, const char *id)
{
    const cJSON *t;
    cJSON_ArrayForEach(t, at(ans, "tunnels"))
    {
        const cJSON *i = at(t, "id");
        if (cJSON_IsString(i) && strcmp(i->valuestring, id) == 0) {
            return t;
        }
    }
    return NULL;
}

static bool same_json(const cJSON *got, const char *want_text)
{
    cJSON *want = cJSON_Parse(want_text);
    bool same = want != NULL && cJSON_Compare(got, want, true);
    if (!same) {
        char *g = cJSON_PrintUnformatted(got);
        fprintf(stderr, "got:  %s\nwant: %s\n", g != NULL ? g : "(null)", want_text);
        free(g);
    }
    cJSON_Delete(want);
    return same;
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static size_t slurp(const char *path, char *buf, size_t cap)
{
    buf[0] = 0;
    FILE *f = fopen(path, "re");
    if (f == NULL) {
        return 0;
    }
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = 0;
    fclose(f);
    return n;
}

static int lines_of(const char *path, const char *prefix)
{
    char buf[4096];
    slurp(path, buf, sizeof buf);
    int n = 0;
    size_t pl = strlen(prefix);
    for (const char *p = buf; *p != 0;) {
        if (strncmp(p, prefix, pl) == 0) {
            n++;
        }
        const char *nl = strchr(p, '\n');
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    return n;
}

static bool wait_for_status(const char *id, const char *status, int ms)
{
    int64_t end = now_ms() + ms;
    while (now_ms() < end) {
        cJSON *ans = NULL;
        call_api("GET", "/api/v1/tunnels/state", NULL, &ans);
        const cJSON *t = tunnel_named(ans, id);
        bool hit = t != NULL && cJSON_IsString(at(t, "status")) && strcmp(at(t, "status")->valuestring, status) == 0;
        cJSON_Delete(ans);
        if (hit) {
            return true;
        }
        sleep_ms(30);
    }
    return false;
}

#define FULL_TUN                                                                                    \
    "tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"                                    \
    "      - id: 0000000a\n        link: \"" LINK_A "\"\n"                                           \
    "      - id: 0000000b\n        subscription: { name: P, url: \"" SUB_URL "\", interval: 1h }\n"   \
    "    filter: \"^(A|B)$\"\n    order: [\"0000000b:B\"]\n    exclude: [\"0000000b:C\"]\n"          \
    "    active: 2\n    by: site\n    interval: 30s\n    silence: 10s\n"                             \
    "    advanced: { timeout: 5s, insecure: true, ca: /etc/ca.pem }\n"                               \
    "  - id: b\n    device: tunvless1\n    enable: false\n    uplink: \"iface:eth9\"\n"

/* catches: a field missing, renamed or typed differently from the agreed tunnel shape */
TEST get_answers_every_tunnel_in_the_agreed_shape(void)
{
    ASSERT(hx_start(FULL_TUN, 0) != NULL);
    cJSON *ans = NULL;
    ASSERT_EQ(200, call_api("GET", "/api/v1/tunnels", NULL, &ans));
    ASSERT(same_json(ans,
                     "{\"tunnels\":[{\"id\":\"a\",\"device\":\"tunvless0\",\"enable\":true,"
                     "\"uplink\":{\"kind\":\"auto\",\"ref\":\"\"},"
                     "\"sources\":[{\"id\":\"0000000a\",\"kind\":\"link\",\"link\":\"" LINK_A "\"},"
                     "{\"id\":\"0000000b\",\"kind\":\"subscription\",\"name\":\"P\",\"url\":\"" SUB_URL "\","
                     "\"interval\":3600}],"
                     "\"filter\":\"^(A|B)$\",\"order\":[\"0000000b:B\"],\"exclude\":[\"0000000b:C\"],"
                     "\"active\":2,\"by\":\"site\",\"interval\":30,\"silence\":10,"
                     "\"advanced\":{\"timeout\":5,\"insecure\":true,\"ca\":\"/etc/ca.pem\"}},"
                     "{\"id\":\"b\",\"device\":\"tunvless1\",\"enable\":false,"
                     "\"uplink\":{\"kind\":\"iface\",\"ref\":\"eth9\"},\"sources\":[],"
                     "\"filter\":\"\",\"order\":[],\"exclude\":[],"
                     "\"active\":1,\"by\":\"connection\",\"interval\":60,\"silence\":20,"
                     "\"advanced\":{\"timeout\":8,\"insecure\":false,\"ca\":\"\"}}]}"));
    cJSON_Delete(ans);
    PASS();
}

#define PUT_TWO                                                                                     \
    "{\"tunnels\":[{\"id\":\"a\",\"device\":\"tunvless0\",\"sources\":[{\"kind\":\"link\",\"link\":\"" \
    "%s\"}]},{\"id\":\"b\",\"device\":\"tunvless1\",\"enable\":false,\"uplink\":{\"kind\":\"tunnel\","  \
    "\"ref\":\"a\"},\"interval\":45,\"advanced\":{\"timeout\":3}}]}"

/* catches: a PUT not written to disk, written readable by others, or a live node update named as a restart */
TEST put_saves_0600_applies_and_names_the_restarted(void)
{
    ASSERT(hx_start(NULL, 0) != NULL);
    char body[1024];
    snprintf(body, sizeof body, PUT_TWO, LINK_A);
    cJSON *ans = NULL;
    ASSERT_EQ(200, call_api("PUT", "/api/v1/tunnels", body, &ans));
    ASSERT(same_json(at(ans, "restarted"), "[\"tunvless0\"]"));
    ASSERT(same_json(at(ans, "updated"), "[]"));
    const cJSON *b = tunnel_named(ans, "b");
    ASSERT(same_json(at(b, "uplink"), "{\"kind\":\"tunnel\",\"ref\":\"a\"}"));
    ASSERT_EQ(45, at(b, "interval")->valueint);
    ASSERT_EQ(3, at(at(b, "advanced"), "timeout")->valueint);
    const cJSON *src = cJSON_GetArrayItem(at(tunnel_named(ans, "a"), "sources"), 0);
    ASSERT(cJSON_IsString(at(src, "id")) && strlen(at(src, "id")->valuestring) == 8);
    cJSON_Delete(ans);
    struct stat st;
    ASSERT_EQ(0, stat(g_hx->path, &st));
    ASSERT_EQ_FMT(0600u, (unsigned)(st.st_mode & 0777), "%o");
    firc_tunnels_t saved = {0};
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_file(&saved, g_hx->path, NULL));
    ASSERT_EQ_FMT((size_t)2, saved.n, "%zu");
    ASSERT_STR_EQ(LINK_A, saved.t[0].src[0].link);
    ASSERT_EQ(FIRC_UPLINK_TUNNEL, saved.t[1].uplink);
    ASSERT_EQ(45, saved.t[1].interval_s);
    firc_tunnels_free(&saved);
    int64_t end = now_ms() + 2000;
    while (lines_of(g_hx->starts, "tunvless0 ") < 1 && now_ms() < end) {
        sleep_ms(20);
    }
    ASSERT_EQ(1, lines_of(g_hx->starts, "tunvless0 "));

    ASSERT_EQ(200, call_api("PUT", "/api/v1/tunnels", body, &ans));
    ASSERT(same_json(at(ans, "restarted"), "[]"));
    ASSERT(same_json(at(ans, "updated"), "[]"));
    cJSON_Delete(ans);

    snprintf(body, sizeof body, PUT_TWO, LINK_B);
    ASSERT_EQ(200, call_api("PUT", "/api/v1/tunnels", body, &ans));
    ASSERT(same_json(at(ans, "restarted"), "[]"));
    ASSERT(same_json(at(ans, "updated"), "[\"tunvless0\"]"));
    cJSON_Delete(ans);

    char moved[1024];
    snprintf(moved, sizeof moved, PUT_TWO, LINK_B);
    char *at_dev = strstr(moved, "\"tunvless0\"");
    ASSERT(at_dev != NULL);
    at_dev[9] = '5';
    ASSERT_EQ(200, call_api("PUT", "/api/v1/tunnels", moved, &ans));
    ASSERT(same_json(at(ans, "restarted"), "[\"tunvless5\"]"));
    ASSERT(same_json(at(ans, "updated"), "[]"));
    cJSON_Delete(ans);
    PASS();
}

/* catches: a refused set written to disk or applied, or the error not naming the tunnel and field the form shows */
TEST a_refused_put_names_tunnel_and_field_and_keeps_the_file(void)
{
    ASSERT(hx_start(FULL_TUN, 0) != NULL);
    char before[8192];
    slurp(g_hx->path, before, sizeof before);
    ASSERT(strlen(before) > 0);
    cJSON *ans = NULL;
    ASSERT_EQ(400, call_api("PUT", "/api/v1/tunnels",
                            "{\"tunnels\":[{\"id\":\"a\",\"device\":\"tunvless0\",\"sources\":[{\"kind\":\"link\","
                            "\"link\":\"" LINK_A "\"}]},{\"id\":\"b\",\"device\":\"tunvless1\",\"enable\":false,"
                            "\"uplink\":{\"kind\":\"tunnel\",\"ref\":\"zz\"}}]}",
                            &ans));
    ASSERT(same_json(ans, "{\"error\":\"no tunnel with this id\",\"field\":\"uplink\",\"tunnel\":\"b\"}"));
    cJSON_Delete(ans);
    ASSERT_EQ(400, call_api("PUT", "/api/v1/tunnels",
                            "{\"tunnels\":[{\"id\":\"a\",\"device\":\"tunvless0\",\"sources\":[{\"kind\":\"link\","
                            "\"link\":\"" LINK_A "\"},{\"kind\":\"subscription\",\"name\":\"P\",\"url\":\"ftp://x\"}]}]}",
                            &ans));
    ASSERT(same_json(ans, "{\"error\":\"an http:// or https:// URL without whitespace, up to 2048 bytes\","
                          "\"field\":\"sources[1].url\",\"tunnel\":\"a\"}"));
    cJSON_Delete(ans);
    ASSERT_EQ(400, call_api("PUT", "/api/v1/tunnels", "{\"tunnels\":[{\"id\":\"a\",\"device\":\"tunvless0\","
                                                      "\"enable\":false,\"interval\":2}]}",
                            &ans));
    ASSERT(same_json(ans, "{\"error\":\"whole seconds, 5s..24h\",\"field\":\"interval\",\"tunnel\":\"a\"}"));
    cJSON_Delete(ans);
    ASSERT_EQ(400, call_api("PUT", "/api/v1/tunnels", "{\"nope\":[]}", &ans));
    ASSERT_STR_EQ("tunnels", at(ans, "field")->valuestring);
    cJSON_Delete(ans);
    char after[8192];
    slurp(g_hx->path, after, sizeof after);
    ASSERT_STR_EQ(before, after);
    ASSERT_EQ(200, call_api("GET", "/api/v1/tunnels", NULL, &ans));
    ASSERT_EQ(2, cJSON_GetArraySize(at(ans, "tunnels")));
    ASSERT_STR_EQ("iface", at(at(tunnel_named(ans, "b"), "uplink"), "kind")->valuestring);
    cJSON_Delete(ans);
    PASS();
}

#define SUB_TUN                                                                                     \
    "tunnels:\n  - id: s\n    device: tunvless2\n    sources:\n      - id: 0000000b\n"               \
    "        subscription: { name: P, url: \"" SUB_URL "\", interval: 1h }\n"

static bool wait_for_cached(int ms)
{
    int64_t end = now_ms() + ms;
    while (now_ms() < end) {
        cJSON *ans = NULL;
        call_api("GET", "/api/v1/tunnels/state", NULL, &ans);
        const cJSON *sub = cJSON_GetArrayItem(at(tunnel_named(ans, "s"), "subscriptions"), 0);
        bool hit = sub != NULL && cJSON_IsNumber(at(sub, "lastOk")) && at(sub, "lastOk")->valuedouble > 0;
        cJSON_Delete(ans);
        if (hit) {
            return true;
        }
        sleep_ms(30);
    }
    return false;
}

/* catches: preview rows ignoring the draft's filter, order or exclude, fetching, or carrying a link */
TEST preview_follows_the_draft_from_cached_bodies_without_links(void)
{
    ASSERT(hx_start(SUB_TUN, 0) != NULL);
    ASSERT(wait_for_cached(5000));
    cJSON *ans = NULL;
    ASSERT_EQ(200, call_api("POST", "/api/v1/tunnels/preview",
                            "{\"tunnel\":{\"id\":\"s\",\"device\":\"tunvless2\",\"sources\":["
                            "{\"id\":\"0000000b\",\"kind\":\"subscription\",\"name\":\"P\",\"url\":\"" SUB_URL "\"},"
                            "{\"id\":\"0000000e\",\"kind\":\"subscription\",\"name\":\"Q\","
                            "\"url\":\"http://127.0.0.1:18144/other\"}],"
                            "\"filter\":\"^(A|B|C)$\",\"order\":[\"0000000b:C\",\"0000000b:Z\"],"
                            "\"exclude\":[\"0000000b:B\"]}}",
                            &ans));
    ASSERT(strstr(g_raw, "vless://") == NULL);
    ASSERT(strstr(g_raw, U) == NULL);
    ASSERT(strstr(g_raw, "s3cr3t") == NULL);
    ASSERT(same_json(ans,
                     "{\"nodes\":["
                     "{\"key\":\"0000000b:C\",\"name\":\"C\",\"source\":\"P\",\"isNew\":false,\"excluded\":false,"
                     "\"missing\":false,\"overCap\":false,\"skipReason\":\"\"},"
                     "{\"key\":\"0000000b:Z\",\"name\":\"Z\",\"source\":\"P\",\"isNew\":false,\"excluded\":false,"
                     "\"missing\":true,\"overCap\":false,\"skipReason\":\"\"},"
                     "{\"key\":\"0000000b:A\",\"name\":\"A\",\"source\":\"P\",\"isNew\":true,\"excluded\":false,"
                     "\"missing\":false,\"overCap\":false,\"skipReason\":\"\"},"
                     "{\"key\":\"0000000b:B\",\"name\":\"B\",\"source\":\"P\",\"isNew\":true,\"excluded\":true,"
                     "\"missing\":false,\"overCap\":false,\"skipReason\":\"\"}],"
                     "\"matched\":3,\"total\":4,"
                     "\"subscriptions\":[{\"name\":\"P\",\"cached\":true},{\"name\":\"Q\",\"cached\":false}]}"));
    cJSON_Delete(ans);
    ASSERT_EQ(200, call_api("POST", "/api/v1/tunnels/preview",
                            "{\"tunnel\":{\"id\":\"x\",\"device\":\"tunvless6\",\"enable\":true}}", &ans));
    ASSERT(same_json(ans, "{\"nodes\":[],\"matched\":0,\"total\":0,\"subscriptions\":[]}"));
    cJSON_Delete(ans);
    ASSERT_EQ(400, call_api("POST", "/api/v1/tunnels/preview",
                            "{\"tunnel\":{\"id\":\"s\",\"device\":\"tunvless2\",\"filter\":\"(\"}}", &ans));
    ASSERT_STR_EQ("filter", at(ans, "field")->valuestring);
    cJSON_Delete(ans);
    PASS();
}

#define SUB_DRAFT(extra)                                                                            \
    "{\"tunnel\":{\"id\":\"s\",\"device\":\"tunvless2\"," extra "\"sources\":["                       \
    "{\"id\":\"0000000b\",\"kind\":\"subscription\",\"name\":\"P\",\"url\":\"" SUB_URL "\"}]}}"
#define SUB_ROWS                                                                                    \
    "{\"nodes\":["                                                                                   \
    "{\"key\":\"0000000b:A\",\"name\":\"A\",\"source\":\"P\",\"isNew\":true,\"excluded\":false,"         \
    "\"missing\":false,\"overCap\":false,\"skipReason\":\"\"},"                                         \
    "{\"key\":\"0000000b:B\",\"name\":\"B\",\"source\":\"P\",\"isNew\":true,\"excluded\":false,"         \
    "\"missing\":false,\"overCap\":false,\"skipReason\":\"\"},"                                         \
    "{\"key\":\"0000000b:C\",\"name\":\"C\",\"source\":\"P\",\"isNew\":true,\"excluded\":false,"         \
    "\"missing\":false,\"overCap\":false,\"skipReason\":\"\"},"                                         \
    "{\"key\":\"0000000b:D\",\"name\":\"D\",\"source\":\"P\",\"isNew\":true,\"excluded\":false,"         \
    "\"missing\":false,\"overCap\":false,\"skipReason\":\"\"}],"                                        \
    "\"matched\":4,\"total\":4,\"subscriptions\":[{\"name\":\"P\",\"cached\":true}]}"

/* catches: the node table emptied in the editor while the draft names another uplink than the saved one */
TEST preview_with_a_changed_uplink_shows_the_saved_nodes(void)
{
    ASSERT(hx_start(SUB_TUN, 0) != NULL);
    ASSERT(wait_for_cached(5000));
    cJSON *ans = NULL;
    ASSERT_EQ(200, call_api("POST", "/api/v1/tunnels/preview",
                            SUB_DRAFT("\"uplink\":{\"kind\":\"iface\",\"ref\":\"eth9\"},"), &ans));
    ASSERT(same_json(ans, SUB_ROWS));
    cJSON_Delete(ans);
    PASS();
}

/* catches: a disabled tunnel's editor showing no nodes although its subscription's body was held */
TEST preview_of_a_disabled_tunnel_shows_its_held_nodes(void)
{
    ASSERT(hx_start(SUB_TUN, 0) != NULL);
    ASSERT(wait_for_cached(5000));
    ASSERT_EQ(200, call_api("PUT", "/api/v1/tunnels",
                            "{\"tunnels\":[{\"id\":\"s\",\"device\":\"tunvless2\",\"enable\":false,\"sources\":["
                            "{\"id\":\"0000000b\",\"kind\":\"subscription\",\"name\":\"P\",\"url\":\"" SUB_URL
                            "\",\"interval\":3600}]}]}",
                            NULL));
    cJSON *ans = NULL;
    ASSERT_EQ(202, call_api("POST", "/api/v1/tunnels/s/refresh", NULL, &ans));
    ASSERT(cJSON_IsFalse(at(ans, "queued")));
    cJSON_Delete(ans);
    ASSERT_EQ(200, call_api("POST", "/api/v1/tunnels/preview", SUB_DRAFT("\"enable\":false,"), &ans));
    ASSERT(same_json(ans, SUB_ROWS));
    cJSON_Delete(ans);
    PASS();
}

#define STATE_TUNS                                                                                  \
    "tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"                                    \
    "      - id: 0000000a\n        link: \"" LINK_A "\"\n"                                           \
    "      - id: 0000000c\n        link: \"" LINK_B "\"\n"                                           \
    "    exclude: [\"0000000c:B\"]\n"                                                                \
    "  - id: off\n    device: tunvless1\n    enable: false\n"                                       \
    "  - id: w\n    device: tunvless3\n    sources:\n      - id: 0000000d\n"                          \
    "        subscription: { name: Gone, url: \"http://127.0.0.1:1/x?token=s3cr3t\", interval: 1h }\n"

/* catches: a waiting or disabled tunnel missing from the state, node states wrong, or groups not named */
TEST state_lists_every_tunnel_with_its_nodes_groups_and_subscriptions(void)
{
    ASSERT(hx_start(STATE_TUNS, 0) != NULL);
    ASSERT(wait_for_status("a", "up", 3000));
    cJSON *ans = NULL;
    ASSERT_EQ(200, call_api("GET", "/api/v1/tunnels/state", NULL, &ans));
    ASSERT(strstr(g_raw, "vless://") == NULL);
    ASSERT(strstr(g_raw, "s3cr3t") == NULL);
    ASSERT_EQ(3, cJSON_GetArraySize(at(ans, "tunnels")));
    const cJSON *a = cJSON_GetArrayItem(at(ans, "tunnels"), 0);
    ASSERT_STR_EQ("a", at(a, "id")->valuestring);
    ASSERT_STR_EQ("tunvless0", at(a, "device")->valuestring);
    ASSERT_STR_EQ("up", at(a, "status")->valuestring);
    ASSERT(same_json(at(a, "active"), "[\"A\"]"));
    ASSERT(same_json(at(a, "nodes"), "[{\"key\":\"0000000a:A\",\"name\":\"A\",\"source\":\"link\",\"state\":\"active\","
                                     "\"since\":0,\"skipReason\":\"\"},"
                                     "{\"key\":\"0000000c:B\",\"name\":\"B\",\"source\":\"link\","
                                     "\"state\":\"excluded\",\"since\":0,\"skipReason\":\"\"}]"));
    ASSERT(same_json(at(a, "groups"), "[\"via-tunnel\"]"));
    ASSERT(same_json(at(a, "subscriptions"), "[]"));
    ASSERT(cJSON_IsTrue(at(a, "uplinkOk")));
    double since = at(a, "since")->valuedouble;
    double now = (double)time(NULL);
    ASSERT(since > now - 60 && since <= now + 1);
    ASSERT(cJSON_IsNumber(at(a, "backoffS")) && cJSON_IsNumber(at(a, "lastExit")));
    ASSERT_STR_EQ("off", at(cJSON_GetArrayItem(at(ans, "tunnels"), 1), "status")->valuestring);
    const cJSON *w = cJSON_GetArrayItem(at(ans, "tunnels"), 2);
    ASSERT_STR_EQ("w", at(w, "id")->valuestring);
    ASSERT_STR_EQ("waiting", at(w, "status")->valuestring);
    ASSERT(same_json(at(w, "groups"), "[]"));
    const cJSON *sub = cJSON_GetArrayItem(at(w, "subscriptions"), 0);
    ASSERT_STR_EQ("Gone", at(sub, "name")->valuestring);
    ASSERT_EQ(0, at(sub, "nodes")->valueint);
    ASSERT_EQ(0, at(sub, "lastOk")->valueint);
    ASSERT(cJSON_IsNumber(at(sub, "lastTry")) && cJSON_IsString(at(sub, "error")) && cJSON_IsBool(at(sub, "fetching")));
    cJSON_Delete(ans);
    PASS();
}

/* catches: a node reported down missing from the state, or its since not converted to wall time */
TEST a_node_down_shows_as_down_with_its_since(void)
{
    setenv("FAKE_MODE", "down", 1);
    ASSERT(hx_start("tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"
                    "      - id: 0000000a\n        link: \"" LINK_A "\"\n"
                    "      - id: 0000000c\n        link: \"" LINK_B "\"\n",
                    0) != NULL);
    ASSERT(wait_for_status("a", "up", 3000));
    sleep_ms(200);
    cJSON *ans = NULL;
    ASSERT_EQ(200, call_api("GET", "/api/v1/tunnels/state", NULL, &ans));
    const cJSON *b = cJSON_GetArrayItem(at(tunnel_named(ans, "a"), "nodes"), 1);
    ASSERT_STR_EQ("0000000c:B", at(b, "key")->valuestring);
    ASSERT_STR_EQ("down", at(b, "state")->valuestring);
    double now = (double)time(NULL);
    ASSERT(at(b, "since")->valuedouble > now - 30 && at(b, "since")->valuedouble <= now + 1);
    cJSON_Delete(ans);
    PASS();
}

static long long rate_of(const char *which)
{
    cJSON *ans = NULL;
    call_api("GET", "/api/v1/tunnels/state", NULL, &ans);
    const cJSON *v = at(tunnel_named(ans, "a"), which);
    long long r = cJSON_IsNumber(v) ? (long long)v->valuedouble : -1;
    cJSON_Delete(ans);
    return r;
}

/* catches: rates taken over the wrong interval, from the wrong counter, or from a first sample */
TEST rates_are_the_counter_difference_over_the_time_between_polls(void)
{
    ASSERT(hx_start("tunnels:\n  - id: a\n    device: tunvless0\n    enable: false\n", 0) != NULL);
    write_counter(g_hx, "tunvless0", "rx_bytes", 1000);
    write_counter(g_hx, "tunvless0", "tx_bytes", 50);
    int64_t t0 = now_ms();
    ASSERT_EQ(0, rate_of("rxBps"));
    int64_t t1 = now_ms();
    write_counter(g_hx, "tunvless0", "rx_bytes", 1000 + 400000);
    write_counter(g_hx, "tunvless0", "tx_bytes", 50 + 40000);
    sleep_ms(400);
    int64_t t2 = now_ms();
    cJSON *ans = NULL;
    ASSERT_EQ(200, call_api("GET", "/api/v1/tunnels/state", NULL, &ans));
    int64_t t3 = now_ms();
    const cJSON *a = tunnel_named(ans, "a");
    double rx = at(a, "rxBps")->valuedouble;
    double tx = at(a, "txBps")->valuedouble;
    cJSON_Delete(ans);
    double lo_ms = (double)(t2 - t1);
    double hi_ms = (double)(t3 - t0);
    ASSERT(rx >= 400000.0 * 1000.0 / hi_ms - 1 && rx <= 400000.0 * 1000.0 / lo_ms + 1);
    ASSERT(tx >= 40000.0 * 1000.0 / hi_ms - 1 && tx <= 40000.0 * 1000.0 / lo_ms + 1);
    PASS();
}

/* catches: refresh or restart accepted for an unknown tunnel, or a restart that does not start the child again */
TEST refresh_and_restart_answer_202_or_404(void)
{
    ASSERT(hx_start(STATE_TUNS, 0) != NULL);
    ASSERT(wait_for_status("a", "up", 3000));
    cJSON *ans = NULL;
    ASSERT_EQ(404, call_api("POST", "/api/v1/tunnels/zz/refresh", NULL, NULL));
    ASSERT_EQ(202, call_api("POST", "/api/v1/tunnels/w/refresh", NULL, &ans));
    ASSERT(same_json(ans, "{\"queued\":true}"));
    cJSON_Delete(ans);
    ASSERT_EQ(202, call_api("POST", "/api/v1/tunnels/a/refresh", NULL, &ans));
    ASSERT(same_json(ans, "{\"queued\":false}"));
    cJSON_Delete(ans);
    ASSERT_EQ(404, call_api("POST", "/api/v1/tunnels/zz/restart", NULL, NULL));
    ASSERT_EQ(409, call_api("POST", "/api/v1/tunnels/off/restart", NULL, NULL));
    ASSERT_EQ(202, call_api("POST", "/api/v1/tunnels/a/restart", NULL, &ans));
    ASSERT(same_json(ans, "{\"queued\":true}"));
    cJSON_Delete(ans);
    int64_t end = now_ms() + 3000;
    while (lines_of(g_hx->starts, "tunvless0 ") < 2 && now_ms() < end) {
        sleep_ms(20);
    }
    ASSERT_EQ(2, lines_of(g_hx->starts, "tunvless0 "));
    PASS();
}

/* catches: probe rows keyed to the wrong node, an excluded node left unmeasured, links in the answer, or the saved tunnel not used for an id */
TEST probe_answers_per_node_key_without_links(void)
{
    ASSERT(hx_start("tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"
                    "      - id: 0000000a\n        link: \"" LINK_A "\"\n"
                    "      - id: 0000000c\n        link: \"vless://" U "@fail.example.invalid:443?security=none#F\"\n"
                    "      - id: 0000000d\n        link: \"" LINK_B "\"\n"
                    "    exclude: [\"0000000d:B\"]\n",
                    0) != NULL);
    setenv("FAKE_MODE", "probe", 1);
    cJSON *ans = NULL;
    ASSERT_EQ(200, call_api("POST", "/api/v1/tunnels/probe", "{\"id\":\"a\"}", &ans));
    ASSERT(strstr(g_raw, "vless://") == NULL);
    ASSERT(strstr(g_raw, U) == NULL);
    ASSERT(same_json(ans, "{\"nodes\":["
                          "{\"key\":\"0000000a:A\",\"ok\":true,\"handshakeMs\":10,\"firstByteMs\":20,\"why\":\"\"},"
                          "{\"key\":\"0000000c:F\",\"ok\":false,\"handshakeMs\":null,\"firstByteMs\":null,"
                          "\"why\":\"connection refused\"},"
                          "{\"key\":\"0000000d:B\",\"ok\":true,\"handshakeMs\":12,\"firstByteMs\":22,\"why\":\"\"}]}"));
    cJSON_Delete(ans);
    char argv[256];
    slurp(g_hx->argv, argv, sizeof argv);
    ASSERT_STR_EQ("--probe\n-t\n3\n-\n", argv);
    ASSERT_EQ(200, call_api("POST", "/api/v1/tunnels/probe",
                            "{\"tunnel\":{\"id\":\"new\",\"device\":\"tunvless5\",\"sources\":[{\"id\":\"0000000f\","
                            "\"kind\":\"link\",\"link\":\"" LINK_B "\"}]}}",
                            &ans));
    ASSERT(same_json(ans, "{\"nodes\":[{\"key\":\"0000000f:B\",\"ok\":true,\"handshakeMs\":10,\"firstByteMs\":20,"
                          "\"why\":\"\"}]}"));
    cJSON_Delete(ans);
    ASSERT_EQ(404, call_api("POST", "/api/v1/tunnels/probe", "{\"id\":\"zz\"}", NULL));
    PASS();
}

/* catches: a second probe started while one runs, or the first one's child left behind by its client */
TEST a_second_probe_is_refused_while_one_runs(void)
{
    ASSERT(hx_start("tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"
                    "      - id: 0000000a\n        link: \"" LINK_A "\"\n",
                    0) != NULL);
    setenv("FAKE_MODE", "noread", 1);
    int lines_before = lines_of(g_hx->starts, "3 ");
    int fd = send_request("POST", "/api/v1/tunnels/probe", "{\"id\":\"a\"}", true);
    ASSERT(fd >= 0);
    int64_t end = now_ms() + 3000;
    while (lines_of(g_hx->starts, "3 ") == lines_before && now_ms() < end) {
        sleep_ms(20);
    }
    cJSON *ans = NULL;
    ASSERT_EQ(409, call_api("POST", "/api/v1/tunnels/probe", "{\"id\":\"a\"}", &ans));
    cJSON_Delete(ans);
    char buf[256];
    slurp(g_hx->starts, buf, sizeof buf);
    const char *line = strstr(buf, "\n3 ");
    line = line != NULL ? line + 1 : (strncmp(buf, "3 ", 2) == 0 ? buf : NULL);
    ASSERT(line != NULL);
    pid_t pid = (pid_t)atoi(line + 2);
    ASSERT(pid > 0 && kill(pid, 0) == 0);
    close(fd);
    end = now_ms() + 3000;
    while (kill(pid, 0) == 0 && now_ms() < end) {
        sleep_ms(20);
    }
    ASSERT(kill(pid, 0) == -1 && errno == ESRCH);
    setenv("FAKE_MODE", "probe", 1);
    ASSERT_EQ(200, call_api("POST", "/api/v1/tunnels/probe", "{\"id\":\"a\"}", NULL));
    PASS();
}

/* catches: an unmarked probe for a tunnel that must leave by its uplink, or a marked one refused */
TEST a_probe_through_an_uplink_needs_the_saved_mark(void)
{
    ASSERT(hx_start("tunnels:\n  - id: u\n    device: tunvless0\n    uplink: \"iface:lo\"\n    sources:\n"
                    "      - id: 0000000a\n        link: \"" LINK_A "\"\n"
                    "  - id: w\n    device: tunvless1\n    uplink: \"iface:lo\"\n    sources:\n"
                    "      - subscription: { name: Gone, url: \"http://127.0.0.1:1/x\", interval: 1h }\n",
                    IFF_UP | IFF_POINTOPOINT) != NULL);
    ASSERT(wait_for_status("w", "waiting", 3000));
    ASSERT_EQ(409, call_api("POST", "/api/v1/tunnels/probe",
                            "{\"tunnel\":{\"id\":\"w\",\"device\":\"tunvless1\",\"uplink\":{\"kind\":\"iface\","
                            "\"ref\":\"lo\"},\"sources\":[{\"kind\":\"link\",\"link\":\"" LINK_A "\"}]}}",
                            NULL));
    setenv("FAKE_MODE", "probe", 1);
    cJSON *ans = NULL;
    ASSERT_EQ(409, call_api("POST", "/api/v1/tunnels/probe",
                            "{\"tunnel\":{\"id\":\"n\",\"device\":\"tunvless4\",\"uplink\":{\"kind\":\"iface\","
                            "\"ref\":\"lo\"},\"sources\":[{\"kind\":\"link\",\"link\":\"" LINK_A "\"}]}}",
                            &ans));
    ASSERT_STR_EQ("save first", at(ans, "error")->valuestring);
    cJSON_Delete(ans);
    ASSERT_EQ(409, call_api("POST", "/api/v1/tunnels/probe",
                            "{\"tunnel\":{\"id\":\"u\",\"device\":\"tunvless0\",\"uplink\":{\"kind\":\"iface\","
                            "\"ref\":\"ppp7\"},\"sources\":[{\"kind\":\"link\",\"link\":\"" LINK_A "\"}]}}",
                            NULL));
    ASSERT_EQ(200, call_api("POST", "/api/v1/tunnels/probe", "{\"id\":\"u\"}", NULL));
    char argv[256];
    slurp(g_hx->argv, argv, sizeof argv);
    ASSERT(strstr(argv, "\n-m\n0x") != NULL);
    PASS();
}

/* catches: any tunnels route reachable over the WebUI listener without a session, or one not registered at all */
TEST the_routes_need_a_session(void)
{
    ASSERT(hx_start("tunnels:\n  - id: a\n    device: tunvless0\n    enable: false\n", 0) != NULL);
    static const char *const routes[][2] = {
        {"GET", "/api/v1/tunnels"},          {"PUT", "/api/v1/tunnels"},
        {"GET", "/api/v1/tunnels/state"},    {"POST", "/api/v1/tunnels/preview"},
        {"POST", "/api/v1/tunnels/probe"},   {"POST", "/api/v1/tunnels/a/refresh"},
        {"POST", "/api/v1/tunnels/a/restart"},
    };
    for (size_t i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        int fd = send_request(routes[i][0], routes[i][1], "{}", false);
        ASSERT_EQm(routes[i][1], 401, read_answer(fd, g_raw, sizeof g_raw, 5));
        int with = call_api(routes[i][0], routes[i][1], "{}", NULL);
        ASSERTm(routes[i][1], with != 401 && with != 404 && with > 0);
    }
    PASS();
}

static int put_field_error(const char *tunnel_json, cJSON **ans)
{
    char body[2048];
    snprintf(body, sizeof body, "{\"tunnels\":[%s]}", tunnel_json);
    return call_api("PUT", "/api/v1/tunnels", body, ans);
}

/* catches: a JSON value of the wrong type coerced by the YAML parser instead of refused with its field */
TEST wrong_json_types_are_refused_with_their_field(void)
{
    ASSERT(hx_start(NULL, 0) != NULL);
    static const char *const cases[][2] = {
        {"{\"id\":\"a\",\"device\":\"tunvless0\",\"enable\":\"true\"}",
         "{\"error\":\"must be true or false\",\"field\":\"enable\",\"tunnel\":\"a\"}"},
        {"{\"id\":\"a\",\"device\":\"tunvless0\",\"enable\":false,\"active\":\"2\"}",
         "{\"error\":\"must be a number\",\"field\":\"active\",\"tunnel\":\"a\"}"},
        {"{\"id\":5,\"device\":\"tunvless0\",\"enable\":false}",
         "{\"error\":\"must be a string\",\"field\":\"id\",\"tunnel\":null}"},
        {"{\"id\":\"a\",\"device\":\"tunvless0\",\"enable\":false,\"uplink\":\"auto\"}",
         "{\"error\":\"must be an object\",\"field\":\"uplink\",\"tunnel\":\"a\"}"},
        {"{\"id\":\"a\",\"device\":\"tunvless0\",\"enable\":false,\"advanced\":{\"insecure\":\"true\"}}",
         "{\"error\":\"must be true or false\",\"field\":\"advanced.insecure\",\"tunnel\":\"a\"}"},
        {"{\"id\":\"a\",\"device\":\"tunvless0\",\"sources\":[{\"kind\":\"subscription\",\"name\":\"P\","
         "\"url\":\"http://x.example.invalid/\",\"interval\":\"1h\"}]}",
         "{\"error\":\"must be a number\",\"field\":\"sources[0].interval\",\"tunnel\":\"a\"}"},
        {"{\"id\":\"a\",\"device\":\"tunvless0\",\"enable\":false,\"order\":[\"k\",3]}",
         "{\"error\":\"must be a string\",\"field\":\"order[1]\",\"tunnel\":\"a\"}"},
        {"{\"id\":\"a\",\"device\":\"tunvless0\",\"enable\":false,\"exclude\":\"k\"}",
         "{\"error\":\"must be a list\",\"field\":\"exclude\",\"tunnel\":\"a\"}"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        cJSON *ans = NULL;
        ASSERT_EQm(cases[i][0], 400, put_field_error(cases[i][0], &ans));
        ASSERTm(cases[i][0], same_json(ans, cases[i][1]));
        cJSON_Delete(ans);
    }
    ASSERT_EQ(-1, access(g_hx->path, F_OK));
    PASS();
}

/* catches: a GET answer that a PUT does not take back unchanged, or source ids that drift on the way */
TEST a_get_answer_put_back_reads_the_same(void)
{
    ASSERT(hx_start(FULL_TUN, 0) != NULL);
    cJSON *first = NULL;
    ASSERT_EQ(200, call_api("GET", "/api/v1/tunnels", NULL, &first));
    char *body = cJSON_PrintUnformatted(first);
    cJSON *put = NULL;
    ASSERT_EQ(200, call_api("PUT", "/api/v1/tunnels", body, &put));
    free(body);
    ASSERT(same_json(at(put, "restarted"), "[]"));
    cJSON_Delete(put);
    cJSON *second = NULL;
    ASSERT_EQ(200, call_api("GET", "/api/v1/tunnels", NULL, &second));
    ASSERT(cJSON_Compare(first, second, true));
    ASSERT(same_json(cJSON_GetArrayItem(at(tunnel_named(second, "a"), "sources"), 1),
                     "{\"id\":\"0000000b\",\"kind\":\"subscription\",\"name\":\"P\",\"url\":\"" SUB_URL "\","
                     "\"interval\":3600}"));
    cJSON_Delete(first);
    cJSON_Delete(second);
    PASS();
}

SUITE(tunnels_api)
{
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(get_answers_every_tunnel_in_the_agreed_shape);
    RUN_TEST(put_saves_0600_applies_and_names_the_restarted);
    RUN_TEST(a_refused_put_names_tunnel_and_field_and_keeps_the_file);
    RUN_TEST(preview_follows_the_draft_from_cached_bodies_without_links);
    RUN_TEST(preview_with_a_changed_uplink_shows_the_saved_nodes);
    RUN_TEST(preview_of_a_disabled_tunnel_shows_its_held_nodes);
    RUN_TEST(state_lists_every_tunnel_with_its_nodes_groups_and_subscriptions);
    RUN_TEST(a_node_down_shows_as_down_with_its_since);
    RUN_TEST(rates_are_the_counter_difference_over_the_time_between_polls);
    RUN_TEST(refresh_and_restart_answer_202_or_404);
    RUN_TEST(probe_answers_per_node_key_without_links);
    RUN_TEST(a_second_probe_is_refused_while_one_runs);
    RUN_TEST(a_probe_through_an_uplink_needs_the_saved_mark);
    RUN_TEST(the_routes_need_a_session);
    RUN_TEST(wrong_json_types_are_refused_with_their_field);
    RUN_TEST(a_get_answer_put_back_reads_the_same);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    GREATEST_MAIN_BEGIN();
    firc_log_set_level(FIRC_LOG_ERROR);
    setenv("FAKE_MODE", "ok", 1);
    firc_sub_fetch_global_init();
    RUN_SUITE(tunnels_api);
    firc_sub_fetch_global_cleanup();
    GREATEST_MAIN_END();
}
