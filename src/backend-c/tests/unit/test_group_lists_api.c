#include "greatest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "firc/app.h"
#include "firc/groups.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/models.h"
#include "firc/sub_fetch.h"
#include "firc/yamlio.h"

typedef struct harness {
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    firc_config_t cfg;
    firc_app_t *app;
    firc_groups_ctx_t ctx;
    pthread_t thread;

    firc_loop_t *stub_loop;
    firc_httpd_t *stub;
    pthread_t stub_thread;

    char cfg_dir[64];
    char cfg_path[96];
} harness_t;

static void *loop_thread(void *ud) {
    firc_loop_t *loop = ud;
    firc_loop_run(loop);
    return NULL;
}

#define TEST_PORT 18092
#define STUB_PORT 18093

static void h_stub_list(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "one.example\ntwo.example";
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, sizeof(body) - 1);
}

/* 500 names and 40 subnets: more than a preview shows and more than a default page holds. */
static void h_stub_big(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static char body[64 * 1024];
    size_t at = 0;
    for (int i = 0; i < 500; i++) {
        at += (size_t)snprintf(body + at, sizeof(body) - at, "h%04d.example.com\n", i);
    }
    for (int i = 0; i < 40; i++) {
        at += (size_t)snprintf(body + at, sizeof(body) - at, "10.%d.0.0/16\n", i);
    }
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, at);
}

/* A hosts-format line, an AdBlock line and one usable rule. */
static void h_stub_junk(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "0.0.0.0 tracker.example\n"
                               "||ads.example.com^$third-party\n"
                               "good.example.com\n";
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, sizeof(body) - 1);
}

/* A sing-box rule-set: a `domain` rule and an `ip_cidr` rule scoped to udp. */
static void h_stub_singbox(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] =
        "{\"rules\":[{\"domain\":[\"a.com\"]},{\"ip_cidr\":[\"10.0.0.0/8\"],\"network\":\"udp\"}]}";
    firc_http_res_write(res, 200, "application/json", (const uint8_t *)body, sizeof(body) - 1);
}

/* An HTML page where a list was expected, as a GitHub "view file" link answers. */
static void h_stub_html(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "<!DOCTYPE html><html></html>";
    firc_http_res_write(res, 200, "text/html", (const uint8_t *)body, sizeof(body) - 1);
}

/* A sing-box rule-set naming "a.com" as both `domain` and `domain_suffix`. */
static void h_stub_singbox_twins(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "{\"rules\":[{\"domain\":[\"a.com\"],\"domain_suffix\":[\"a.com\"]}]}";
    firc_http_res_write(res, 200, "application/json", (const uint8_t *)body, sizeof(body) - 1);
}

/* The twins list resynced without its `domain_suffix` twin. */
static void h_stub_singbox_twin_gone(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "{\"rules\":[{\"domain\":[\"a.com\"]}]}";
    firc_http_res_write(res, 200, "application/json", (const uint8_t *)body, sizeof(body) - 1);
}

/* A sing-box rule-set with a name constrained by network, counted as `unconstrained`. */
static void h_stub_singbox_names(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    static const char body[] = "{\"rules\":[{\"domain\":[\"a.com\"],\"network\":\"udp\"}]}";
    firc_http_res_write(res, 200, "application/json", (const uint8_t *)body, sizeof(body) - 1);
}

static void h_stub_404(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write_error(res, 404, "nope");
}

/* How long the /slow routes hold a fetch open, so a test can open the stream while it runs. */
#define STUB_SLOW_MS 300

static void stub_sleep(void) {
    struct timespec ts = {.tv_sec = STUB_SLOW_MS / 1000,
                          .tv_nsec = (long)(STUB_SLOW_MS % 1000) * 1000 * 1000};
    nanosleep(&ts, NULL);
}

static void h_stub_slow(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    stub_sleep();
    h_stub_list(req, res, ud);
}

static void h_stub_slow_404(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    stub_sleep();
    h_stub_404(req, res, ud);
}

static atomic_bool g_gate_open;
static atomic_int g_gate_entered;

static void h_stub_gate(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    atomic_fetch_add(&g_gate_entered, 1);
    for (int i = 0; i < 500 && !atomic_load(&g_gate_open); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    h_stub_list(req, res, ud);
}

static void gate_reset(void) {
    atomic_store(&g_gate_open, false);
    atomic_store(&g_gate_entered, 0);
}

static char g_stub_url[128];
static const char *stub_url(const char *path) {
    snprintf(g_stub_url, sizeof(g_stub_url), "http://127.0.0.1:%d%s", STUB_PORT, path);
    return g_stub_url;
}

static harness_t *live_harness;

typedef struct loop_call {
    void (*fn)(void *);
    void *arg;
    sem_t done;
} loop_call_t;

static void loop_call_cb(firc_loop_t *loop, void *ud) {
    (void)loop;
    loop_call_t *c = ud;
    if (c->fn != NULL) { c->fn(c->arg); }
    sem_post(&c->done);
}

static bool on_loop(harness_t *h, void (*fn)(void *), void *arg) {
    loop_call_t c = {.fn = fn, .arg = arg};
    if (sem_init(&c.done, 0, 0) != 0) { return false; }
    if (firc_loop_post(h->loop, loop_call_cb, &c) != FIRC_OK) {
        sem_destroy(&c.done);
        return false;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 10;
    bool ok = sem_timedwait(&c.done, &ts) == 0;
    sem_destroy(&c.done);
    return ok;
}

/* `with_worker` starts the list worker (without it every sync is refused); `with_config` saves. */
static harness_t *harness_start_ex(bool with_worker, bool with_config) {
    harness_t *h = calloc(1, sizeof(*h));
    firc_config_init_defaults(&h->cfg);
    if (firc_loop_create(&h->loop) != FIRC_OK) { return NULL; }
    if (with_config) {
        snprintf(h->cfg_dir, sizeof(h->cfg_dir), "/tmp/firc-glists-api-%d", (int)getpid());
        if (mkdir(h->cfg_dir, 0700) != 0 && errno != EEXIST) { return NULL; }
        snprintf(h->cfg_path, sizeof(h->cfg_path), "%s/firc.conf", h->cfg_dir);
    }
    firc_app_deps_t deps = {.cfg = &h->cfg,
                            .loop = h->loop,
                            .config_path = with_config ? h->cfg_path : NULL,
                            .config_version = with_config ? "0.7.0" : NULL};
    h->app = firc_app_create(&deps);
    if (h->app == NULL) { return NULL; }
    if (with_worker && firc_app_start_list_worker(h->app) != FIRC_OK) { return NULL; }
    h->ctx.app = h->app;
    if (with_config) {
        h->ctx.config_path = h->cfg_path;
        h->ctx.config_version = "0.7.0";
    }

    if (firc_httpd_create(h->loop, &h->tcp) != FIRC_OK) { return NULL; }
    firc_groups_register_routes(h->tcp, &h->ctx);
    if (firc_httpd_listen_tcp(h->tcp, "127.0.0.1", TEST_PORT) != FIRC_OK) { return NULL; }
    pthread_create(&h->thread, NULL, loop_thread, h->loop);

    if (firc_loop_create(&h->stub_loop) != FIRC_OK) { return NULL; }
    if (firc_httpd_create(h->stub_loop, &h->stub) != FIRC_OK) { return NULL; }
    firc_httpd_route(h->stub, "GET", "/list", h_stub_list, NULL);
    firc_httpd_route(h->stub, "GET", "/list2", h_stub_list, NULL);
    firc_httpd_route(h->stub, "GET", "/junk", h_stub_junk, NULL);
    firc_httpd_route(h->stub, "GET", "/singbox", h_stub_singbox, NULL);
    firc_httpd_route(h->stub, "GET", "/singbox-twins", h_stub_singbox_twins, NULL);
    firc_httpd_route(h->stub, "GET", "/singbox-twin-gone", h_stub_singbox_twin_gone, NULL);
    firc_httpd_route(h->stub, "GET", "/html", h_stub_html, NULL);
    firc_httpd_route(h->stub, "GET", "/singbox-names", h_stub_singbox_names, NULL);
    firc_httpd_route(h->stub, "GET", "/big", h_stub_big, NULL);
    firc_httpd_route(h->stub, "GET", "/404", h_stub_404, NULL);
    firc_httpd_route(h->stub, "GET", "/nolist", h_stub_404, NULL);
    firc_httpd_route(h->stub, "GET", "/slow", h_stub_slow, NULL);
    firc_httpd_route(h->stub, "GET", "/slow404", h_stub_slow_404, NULL);
    firc_httpd_route(h->stub, "GET", "/gate", h_stub_gate, NULL);
    if (firc_httpd_listen_tcp(h->stub, "127.0.0.1", STUB_PORT) != FIRC_OK) { return NULL; }
    pthread_create(&h->stub_thread, NULL, loop_thread, h->stub_loop);

    live_harness = h;
    return h;
}

static harness_t *harness_start(void) { return harness_start_ex(false, false); }
static harness_t *harness_start_with_worker(void) { return harness_start_ex(true, false); }
static harness_t *harness_start_saving(void) { return harness_start_ex(true, true); }

static void harness_stop(harness_t *h) {
    if (h == live_harness) { live_harness = NULL; }
    firc_app_stop_list_worker(h->app);
    (void)on_loop(h, NULL, NULL);
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_groups_api_close_streams(&h->ctx);
    firc_httpd_destroy(h->tcp);
    firc_loop_destroy(h->loop);

    firc_loop_stop(h->stub_loop);
    pthread_join(h->stub_thread, NULL);
    firc_httpd_destroy(h->stub);
    firc_loop_destroy(h->stub_loop);

    firc_app_destroy(h->app);
    firc_config_clear(&h->cfg);
    if (h->cfg_dir[0] != '\0') {
        char groups[160];
        snprintf(groups, sizeof(groups), "%s/groups.yaml", h->cfg_dir);
        unlink(groups);
        unlink(h->cfg_path);
        rmdir(h->cfg_dir);
    }
    free(h);
}

static int connect_tcp(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { return fd; }
        struct timespec ts = {0, 10000000};
        nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

static ssize_t recv_response(int fd, char *buf, size_t cap) {
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t total = 0;
    char *body_start = NULL;
    long content_length = -1;
    for (;;) {
        if (total >= cap - 1) { break; }
        ssize_t n = recv(fd, buf + total, cap - 1 - total, 0);
        if (n <= 0) { break; }
        total += (size_t)n;
        buf[total] = '\0';
        if (!body_start) {
            char *marker = strstr(buf, "\r\n\r\n");
            if (marker) {
                body_start = marker + 4;
                char *cl = strstr(buf, "Content-Length:");
                if (cl && cl < marker) { content_length = strtol(cl + 15, NULL, 10); }
            }
        }
        if (body_start && content_length >= 0) {
            size_t body_have = (size_t)(buf + total - body_start);
            if ((long)body_have >= content_length) { break; }
        }
    }
    return (ssize_t)total;
}

static int status_code_of(const char *resp) {
    int code = 0;
    sscanf(resp, "HTTP/1.1 %d", &code);
    return code;
}

static const char *body_of(const char *resp) {
    const char *marker = strstr(resp, "\r\n\r\n");
    return marker ? marker + 4 : "";
}

static int do_request(const char *method, const char *path, const char *body, cJSON **out_json) {
    int fd = connect_tcp(TEST_PORT);
    if (fd < 0) { return -1; }
    char req[8192];
    size_t body_len = body ? strlen(body) : 0;
    int n = snprintf(req, sizeof(req),
                     "%s %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     method, path, body_len, body ? body : "");
    (void)n;
    if (send(fd, req, strlen(req), 0) <= 0) {
        close(fd);
        return -1;
    }
    char resp[65536];
    ssize_t got = recv_response(fd, resp, sizeof(resp));
    close(fd);
    if (got <= 0) { return -1; }
    int status = status_code_of(resp);
    if (out_json) {
        const char *b = body_of(resp);
        *out_json = b[0] ? cJSON_Parse(b) : NULL;
    }
    return status;
}

static const char *jstr(cJSON *obj, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

static cJSON *jobj(cJSON *obj, const char *key) { return cJSON_GetObjectItemCaseSensitive(obj, key); }

static double jnum(cJSON *obj, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsNumber(v) ? v->valuedouble : -1;
}

/* Opens GET `path` and leaves it open: a held response has no Content-Length. */
static int stream_open(const char *path) {
    int fd = connect_tcp(TEST_PORT);
    if (fd < 0) { return -1; }
    char req[512];
    snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path);
    if (send(fd, req, strlen(req), 0) <= 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Reads the chunked answer until the daemon closes it or `budget_ms` runs out. */
static size_t read_stream(int fd, char *buf, size_t cap, int budget_ms) {
    size_t total = 0;
    int waited = 0;
    while (waited < budget_ms && total < cap - 1) {
        struct pollfd p = {fd, POLLIN, 0};
        int r = poll(&p, 1, 20);
        if (r < 0) {
            if (errno == EINTR) { continue; }
            break;
        }
        if (r == 0) {
            waited += 20;
            continue;
        }
        ssize_t n = recv(fd, buf + total, cap - 1 - total, MSG_DONTWAIT);
        if (n <= 0) { break; }
        total += (size_t)n;
    }
    buf[total] = '\0';
    return total;
}

/* Reads until the first `event: progress` (or about 2 s), so the stream is known to be open. */
static bool read_until_progress(int fd, char *head, size_t cap) {
    size_t n = 0;
    head[0] = '\0';
    for (int i = 0; i < 100 && strstr(head, "event: progress") == NULL; i++) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 20) > 0) {
            ssize_t got = recv(fd, head + n, cap - 1 - n, MSG_DONTWAIT);
            if (got <= 0) { break; }
            n += (size_t)got;
        }
        head[n] = '\0';
    }
    return strstr(head, "event: progress") != NULL;
}

/* The parsed `data:` line of the first `event: <name>` in a stream. */
static cJSON *event_data(const char *stream, const char *name) {
    char head[64];
    snprintf(head, sizeof(head), "event: %s\ndata: ", name);
    const char *p = strstr(stream, head);
    if (p == NULL) { return NULL; }
    p += strlen(head);
    const char *end = strstr(p, "\n\n");
    if (end == NULL) { return NULL; }
    return cJSON_ParseWithLength(p, (size_t)(end - p));
}

static int count_events(const char *stream, const char *name) {
    char head[64];
    snprintf(head, sizeof(head), "event: %s\n", name);
    int n = 0;
    for (const char *p = strstr(stream, head); p != NULL; p = strstr(p + 1, head)) { n++; }
    return n;
}

static bool stream_finished(const char *buf, size_t n) {
    return n >= 5 && strcmp(buf + n - 5, "0\r\n\r\n") == 0;
}

/* A group record's `list.sync.state`, or NULL when it has none. */
static const char *list_state_of(cJSON *record) {
    cJSON *sync = jobj(jobj(record, "list"), "sync");
    return cJSON_IsObject(sync) ? jstr(sync, "state") : NULL;
}

static double list_total_of(cJSON *record) { return jnum(jobj(record, "list"), "rulesTotal"); }

/* Polls GET /groups/{id} until its list is neither queued nor fetching; false if it never settles. */
static bool wait_settled(const char *id, int budget_ms) {
    char path[64];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", id);
    for (int waited = 0; waited <= budget_ms; waited += 10) {
        cJSON *rec = NULL;
        if (do_request("GET", path, NULL, &rec) == 200 && rec != NULL) {
            const char *state = list_state_of(rec);
            bool settled = state != NULL && strcmp(state, "queued") != 0 && strcmp(state, "fetching") != 0;
            cJSON_Delete(rec);
            if (settled) { return true; }
        } else {
            cJSON_Delete(rec);
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return false;
}

#define GID "aabbccdd"

static int create_stub_group(const char *path) {
    char body[256];
    snprintf(body, sizeof(body),
             "{\"id\":\"" GID "\",\"name\":\"g\",\"interface\":\"lo\",\"list\":{\"url\":\"%s\"}}",
             stub_url(path));
    return do_request("POST", "/api/v1/groups", body, NULL);
}

/* A group with a list at `url` holding `n_rules` rules, built without the API. */
static firc_group_t *list_group(const char *url, int n_rules) {
    firc_group_t *g = firc_group_new();
    if (g == NULL) { return NULL; }
    g->id = firc_id_random();
    g->enable = true;
    if (firc_strset(&g->name, "g") != FIRC_OK || firc_strset(&g->iface, "lo") != FIRC_OK) {
        firc_group_free(g);
        return NULL;
    }
    g->list = firc_group_list_new();
    if (g->list == NULL) {
        firc_group_free(g);
        return NULL;
    }
    if (firc_strset(&g->list->url, url) != FIRC_OK) {
        firc_group_free(g);
        return NULL;
    }
    g->list->has_body_hash = true;
    for (int i = 0; i < n_rules; i++) {
        char text[32];
        snprintf(text, sizeof(text), "r%d.example.com", i);
        if (firc_sub_rules_push(&g->list->rules, text, "domain", true, firc_id_random()) != FIRC_OK) {
            firc_group_free(g);
            return NULL;
        }
    }
    return g;
}

static void id_of(firc_id_t id, char out[FIRC_ID_STR_LEN]) { firc_id_format(id, out); }

/* Catches: a PUT /groups answer built from the request objects, whose lists have no rules. */
TEST put_groups_answers_the_carried_list(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);

    firc_group_t *ga = list_group("http://127.0.0.1:1/a", 3);
    firc_group_t *gb = list_group("http://127.0.0.1:1/b", 5);
    ASSERT(ga != NULL && gb != NULL);
    char id_a[FIRC_ID_STR_LEN], id_b[FIRC_ID_STR_LEN];
    id_of(ga->id, id_a);
    id_of(gb->id, id_b);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(h->app, ga));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(h->app, gb));

    char body[512];
    snprintf(body, sizeof(body),
            "{\"groups\":[{\"id\":\"%s\",\"name\":\"g\",\"interface\":\"lo\"},"
            "{\"id\":\"%s\",\"name\":\"g\",\"interface\":\"lo\"}]}",
            id_b, id_a);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups", body, &out));
    cJSON *groups = jobj(out, "groups");
    ASSERT(cJSON_IsArray(groups));
    ASSERT_EQ(2, cJSON_GetArraySize(groups));

    bool found_a = false, found_b = false;
    for (int i = 0; i < cJSON_GetArraySize(groups); i++) {
        cJSON *g = cJSON_GetArrayItem(groups, i);
        const char *id = jstr(g, "id");
        cJSON *list = jobj(g, "list");
        ASSERT(cJSON_IsObject(list));
        if (strcmp(id, id_a) == 0) {
            found_a = true;
            ASSERT_EQ_FMTm("group A kept its 3 rules", 3.0, jnum(list, "rulesTotal"), "%f");
        } else if (strcmp(id, id_b) == 0) {
            found_b = true;
            ASSERT_EQ_FMTm("group B kept its 5 rules", 5.0, jnum(list, "rulesTotal"), "%f");
        }
    }
    ASSERTm("both groups were in the answer", found_a && found_b);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a PUT without "list" dropping the list, or "list": null keeping it. */
TEST a_put_without_list_keeps_it_and_null_removes_it(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);

    firc_group_t *g = list_group("http://127.0.0.1:1/x", 2);
    ASSERT(g != NULL);
    char id[FIRC_ID_STR_LEN];
    id_of(g->id, id);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(h->app, g));

    char path[64];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", id);

    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", path, "{\"name\":\"g2\",\"interface\":\"lo\"}", &out));
    cJSON *list = jobj(out, "list");
    ASSERT(cJSON_IsObject(list));
    ASSERT_EQ_FMTm("the list's rules are still there", 2.0, jnum(list, "rulesTotal"), "%f");
    ASSERT_STR_EQ("http://127.0.0.1:1/x", jstr(list, "url"));
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERTm("and so does a fresh GET", cJSON_IsObject(jobj(out, "list")));
    cJSON_Delete(out);

    ASSERT_EQ(200,
             do_request("PUT", path, "{\"name\":\"g2\",\"interface\":\"lo\",\"list\":null}", &out));
    ASSERTm("null in the PUT removes it from the answer", jobj(out, "list") == NULL);
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERTm("and from a fresh GET", jobj(out, "list") == NULL);
    cJSON_Delete(out);

    harness_stop(h);
    PASS();
}

/* Catches: a list url that is not http or https with a host accepted instead of a 400. */
TEST a_list_needs_a_supported_url(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ_FMTm("ftp is not supported", 400,
                   do_request("POST", "/api/v1/groups",
                              "{\"name\":\"g\",\"interface\":\"lo\",\"list\":{\"url\":\"ftp://x\"}}",
                              &out),
                   "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("an empty url", 400,
                   do_request("POST", "/api/v1/groups",
                              "{\"name\":\"g\",\"interface\":\"lo\",\"list\":{\"url\":\"\"}}", &out),
                   "%d");
    cJSON_Delete(out);
    ASSERT_EQ_FMTm("a list that is not an object", 400,
                   do_request("POST", "/api/v1/groups",
                              "{\"name\":\"g\",\"interface\":\"lo\",\"list\":\"nope\"}", &out),
                   "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a new group's list left for the next tick instead of queued for its first sync at once. */
TEST creating_a_group_with_a_list_answers_it_queued(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200,
             do_request("POST", "/api/v1/groups",
                        "{\"name\":\"g\",\"interface\":\"lo\","
                        "\"list\":{\"url\":\"http://127.0.0.1:1/list\"}}",
                        &out));
    cJSON *list = jobj(out, "list");
    ASSERT(cJSON_IsObject(list));
    cJSON *sync = jobj(list, "sync");
    ASSERT(cJSON_IsObject(sync));
    ASSERT_STR_EQ("queued", jstr(sync, "state"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a POST with an id already in use answered 500 instead of 409. */
TEST a_duplicate_group_id_is_409(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups", "{\"name\":\"g1\"}", &out));
    char id[16];
    snprintf(id, sizeof(id), "%s", jstr(out, "id"));
    cJSON_Delete(out);

    char body[64];
    snprintf(body, sizeof(body), "{\"id\":\"%s\",\"name\":\"g2\"}", id);
    ASSERT_EQ_FMT(409, do_request("POST", "/api/v1/groups", body, &out), "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: lastUpdate or overrides read from a request body instead of carried from the live list. */
TEST lastUpdate_in_a_body_is_ignored(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);

    firc_group_t *g = list_group("http://127.0.0.1:1/x", 0);
    ASSERT(g != NULL);
    g->list->last_update = 12345;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           g->list, &(firc_sub_rule_key_t){.text = "kept.example.com"}, "wildcard", NULL));
    firc_id_t gid = g->id;
    char id[FIRC_ID_STR_LEN];
    id_of(gid, id);
    ASSERT_EQ(FIRC_OK, firc_app_add_group(h->app, g));

    char path[64];
    snprintf(path, sizeof(path), "/api/v1/groups/%s", id);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", path,
                             "{\"name\":\"g\",\"interface\":\"lo\","
                             "\"list\":{\"url\":\"http://127.0.0.1:1/y\",\"lastUpdate\":1,"
                             "\"overrides\":[{\"rule\":\"kept.example.com\",\"type\":\"domain\"}]}}",
                             &out));
    cJSON *list = jobj(out, "list");
    ASSERT(cJSON_IsObject(list));
    ASSERT_EQ_FMTm("the pre-PUT value, not the body's 1", 12345.0, jnum(list, "lastUpdate"), "%f");
    cJSON_Delete(out);

    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQ_FMT(12345.0, jnum(jobj(out, "list"), "lastUpdate"), "%f");
    cJSON_Delete(out);

    firc_ruleset_t *rs = firc_app_find_group_by_id(h->app, gid);
    ASSERT(rs != NULL);
    const firc_group_list_t *live = firc_ruleset_group(rs)->list;
    const firc_sub_override_t *ov =
        firc_group_list_find_override(live, &(firc_sub_rule_key_t){.text = "kept.example.com"});
    ASSERT(ov != NULL);
    ASSERT_STR_EQm("the live override, not the body's \"domain\"", "wildcard", ov->type);

    harness_stop(h);
    PASS();
}

typedef struct rule_spec {
    const char *text;
    const char *type;
    bool enable;
} rule_spec_t;

/* A list group with id `id_hex` whose list already holds `rules`, as a sync leaves it. */
static firc_group_t *group_with_rules(const char *id_hex, const rule_spec_t *rules, size_t n) {
    firc_group_t *g = list_group(stub_url("/nolist"), 0);
    if (g == NULL) { return NULL; }
    if (firc_id_parse(id_hex, &g->id) != FIRC_OK) {
        firc_group_free(g);
        return NULL;
    }
    for (size_t i = 0; i < n; i++) {
        if (firc_sub_rules_push(&g->list->rules, rules[i].text, rules[i].type, rules[i].enable,
                                firc_id_random()) != FIRC_OK) {
            firc_group_free(g);
            return NULL;
        }
    }
    return g;
}

typedef struct add_call {
    harness_t *h;
    firc_group_t *g;
    firc_err_t err;
} add_call_t;

static void add_fn(void *arg) {
    add_call_t *a = arg;
    a->err = firc_app_add_group(a->h->app, a->g);
}

/* Calls firc_app_add_group on the loop thread, where every other app writer runs; takes `g`. */
static bool add_on_loop(harness_t *h, firc_group_t *g) {
    if (g == NULL) { return false; }
    add_call_t a = {.h = h, .g = g, .err = FIRC_ERR_STATE};
    return on_loop(h, add_fn, &a) && a.err == FIRC_OK;
}

#define TWO "0a0b0c0d"

static const rule_spec_t two_rules[] = {
    {"a.example.com", "namespace", true},
    {"b.example.com", "namespace", true},
};

static bool add_two_rule_group(harness_t *h) {
    return add_on_loop(h, group_with_rules(TWO, two_rules, 2));
}

/* The id the daemon holds for rule `idx` of group `gid`, read from the page. */
static bool nth_rule_id(const char *gid, int idx, char *out_id, size_t cap) {
    char path[96];
    snprintf(path, sizeof(path), "/api/v1/groups/%s/list/rules", gid);
    cJSON *out = NULL;
    if (do_request("GET", path, NULL, &out) != 200 || out == NULL) {
        cJSON_Delete(out);
        return false;
    }
    const char *id = jstr(cJSON_GetArrayItem(jobj(out, "rules"), idx), "id");
    bool ok = id != NULL;
    if (ok) { snprintf(out_id, cap, "%s", id); }
    cJSON_Delete(out);
    return ok;
}

#define TWO_RULES "/api/v1/groups/" TWO "/list/rules"

/* Catches: a preview serialising every parsed rule instead of counts and a bounded sample. */
TEST the_preview_is_counts_and_a_bounded_sample(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url("/big"));
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQ_FMTm("all of them are counted", 540.0, jnum(out, "total"), "%f");
    cJSON *rules = jobj(out, "rules");
    ASSERT(cJSON_IsArray(rules));
    ASSERT_EQ_FMTm("a sample of a hundred is sent", 100, cJSON_GetArraySize(rules), "%d");
    cJSON *by_type = jobj(out, "byType");
    ASSERT(cJSON_IsObject(by_type));
    ASSERT_EQ_FMTm("every name", 500.0, jnum(by_type, "namespace"), "%f");
    ASSERT_EQ_FMTm("every subnet", 40.0, jnum(by_type, "subnet"), "%f");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: dropped lines unreported, so a hosts-format list previews as empty with no reason. */
TEST the_preview_says_how_many_lines_it_could_not_use(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url("/junk"));
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQ_FMTm("one line was a rule", 1, cJSON_GetArraySize(jobj(out, "rules")), "%d");
    ASSERT_EQ_FMTm("and the other two are counted", 2.0, jnum(out, "dropped"), "%f");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: an HTML page previewed as "0 rules" with no reason. */
TEST the_preview_of_an_html_page_says_so(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url("/html"));
    cJSON *out = NULL;
    ASSERT_EQ(422, do_request("GET", path, NULL, &out));
    ASSERT(strstr(jstr(out, "error"), "raw") != NULL);
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a sing-box preview without the rule spec or the unconstrained count. */
TEST the_preview_of_a_sing_box_list_shows_spec_and_counts(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[256];
    cJSON *out = NULL;
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url("/singbox"));
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    cJSON *r1 = cJSON_GetArrayItem(jobj(out, "rules"), 1);
    ASSERT_STR_EQ("udp", jstr(r1, "proto"));
    ASSERTm("no ports key when none", cJSON_GetObjectItemCaseSensitive(r1, "ports") == NULL);
    ASSERTm("no proto key on a name", cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(jobj(out, "rules"), 0), "proto") == NULL);
    cJSON_Delete(out);
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url("/singbox-names"));
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    ASSERT_EQ_FMT(1.0, jnum(out, "unconstrained"), "%f");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST the_preview_requires_a_url(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT_EQ(400, do_request("GET", "/api/v1/groups/list/preview", NULL, NULL));
    ASSERT_EQ(400, do_request("GET", "/api/v1/groups/list/preview?url=", NULL, NULL));
    harness_stop(h);
    PASS();
}

TEST the_preview_returns_the_parsed_rules(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url("/list"));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", path, NULL, &out));
    cJSON *rules = jobj(out, "rules");
    ASSERT_EQ(2, cJSON_GetArraySize(rules));
    ASSERT_STR_EQ("one.example", jstr(cJSON_GetArrayItem(rules, 0), "rule"));
    ASSERT_STR_EQ("two.example", jstr(cJSON_GetArrayItem(rules, 1), "rule"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST the_preview_fetch_failure_is_502(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url("/404"));
    ASSERT_EQ(502, do_request("GET", path, NULL, NULL));
    harness_stop(h);
    PASS();
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void ms_sleep(int ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000 * 1000};
    nanosleep(&ts, NULL);
}

static int preview_open(const char *list_path) {
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url(list_path));
    return stream_open(path);
}

typedef struct preview_count {
    harness_t *h;
    size_t n;
} preview_count_t;

static void read_preview_count(void *arg) {
    preview_count_t *c = arg;
    c->n = c->h->ctx.n_previews;
}

/* Polls until the daemon holds `want` previews; false after `budget_ms` or if the loop is blocked. */
static bool wait_previews(harness_t *h, size_t want, int budget_ms) {
    int64_t end = mono_ms() + budget_ms;
    do {
        preview_count_t c = {.h = h, .n = (size_t)-1};
        if (!on_loop(h, read_preview_count, &c)) { return false; }
        if (c.n == want) { return true; }
        ms_sleep(10);
    } while (mono_ms() < end);
    return false;
}

static bool wait_gate_entered(int want, int budget_ms) {
    for (int waited = 0; waited < budget_ms; waited += 10) {
        if (atomic_load(&g_gate_entered) >= want) { return true; }
        ms_sleep(10);
    }
    return false;
}

/* Catches: the preview fetch running on the HTTP handler, which blocks DNS on the shared loop. */
TEST a_preview_in_flight_leaves_the_loop_serving(void) {
    gate_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = preview_open("/gate");
    ASSERT(fd >= 0);
    ASSERTm("the stub has the preview's fetch", wait_gate_entered(1, 2000));

    int64_t t0 = mono_ms();
    ASSERT_EQ_FMTm("another request is answered meanwhile", 200,
                   do_request("GET", "/api/v1/groups", NULL, NULL), "%d");
    ASSERTm("and promptly", mono_ms() - t0 < 1000);

    atomic_store(&g_gate_open, true);
    char resp[8192];
    ASSERT(recv_response(fd, resp, sizeof(resp)) > 0);
    close(fd);
    ASSERT_EQ(200, status_code_of(resp));
    cJSON *out = cJSON_Parse(body_of(resp));
    ASSERT(out != NULL);
    ASSERT_EQ_FMT(2.0, jnum(out, "total"), "%f");
    ASSERT_EQ_FMT(0.0, jnum(out, "dropped"), "%f");
    cJSON *rules = jobj(out, "rules");
    ASSERT_EQ(2, cJSON_GetArraySize(rules));
    ASSERT_STR_EQ("one.example", jstr(cJSON_GetArrayItem(rules, 0), "rule"));
    ASSERT_STR_EQ("two.example", jstr(cJSON_GetArrayItem(rules, 1), "rule"));
    ASSERT_EQ_FMT(2.0, jnum(jobj(out, "byType"), "namespace"), "%f");
    cJSON_Delete(out);
    ASSERTm("the slot is given back", wait_previews(h, 0, 2000));
    harness_stop(h);
    PASS();
}

/* Catches: a preview result written to a closed connection, or its slot held until the fetch ends. */
TEST a_client_that_leaves_mid_preview_is_forgotten(void) {
    gate_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int fd = preview_open("/gate");
    ASSERT(fd >= 0);
    ASSERTm("the stub has the preview's fetch", wait_gate_entered(1, 2000));
    close(fd);

    ASSERT_EQ_FMTm("the loop answers after the client left", 200,
                   do_request("GET", "/api/v1/groups", NULL, NULL), "%d");
    ASSERTm("the preview ends with the stub still holding its list", wait_previews(h, 0, 4000));
    atomic_store(&g_gate_open, true);
    harness_stop(h);
    PASS();
}

/* Catches: no bound on previews in flight, or a bound that never gives its slots back. */
TEST previews_past_two_at_once_are_503(void) {
    gate_reset();
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    int a = preview_open("/gate");
    int b = preview_open("/gate");
    ASSERT(a >= 0 && b >= 0);
    ASSERTm("two previews in flight", wait_previews(h, 2, 2000));

    char path[256];
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=%s", stub_url("/list"));
    cJSON *out = NULL;
    ASSERT_EQ_FMTm("the third is refused", 503, do_request("GET", path, NULL, &out), "%d");
    ASSERT_STR_EQ("too many list previews at once", jstr(out, "error"));
    cJSON_Delete(out);

    atomic_store(&g_gate_open, true);
    char resp[8192];
    ASSERT(recv_response(a, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    ASSERT(recv_response(b, resp, sizeof(resp)) > 0);
    ASSERT_EQ(200, status_code_of(resp));
    close(a);
    close(b);
    ASSERT(wait_previews(h, 0, 2000));
    ASSERT_EQ_FMTm("the slots came back", 200, do_request("GET", path, NULL, NULL), "%d");
    harness_stop(h);
    PASS();
}

#define BLACKHOLE_PORT 18094
TEST a_preview_in_flight_at_shutdown_is_ended(void) {
    int hole = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT(hole >= 0);
    int one = 1;
    setsockopt(hole, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(BLACKHOLE_PORT)};
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    ASSERT_EQ(0, bind(hole, (struct sockaddr *)&sa, sizeof(sa)));
    ASSERT_EQ(0, listen(hole, 4));

    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/groups/list/preview?url=http://127.0.0.1:%d/list",
             BLACKHOLE_PORT);
    int fd = stream_open(path);
    ASSERT(fd >= 0);
    ASSERTm("the preview is in flight", wait_previews(h, 1, 2000));

    int64_t t0 = mono_ms();
    harness_stop(h);
    int64_t took = mono_ms() - t0;
    close(hole);
    char buf[64];
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    close(fd);
    ASSERT_EQ_FMTm("the client sees the connection end", (ssize_t)0, n, "%zd");
    ASSERT_LTm("the stop did not wait out the fetch", took, (int64_t)5000);
    PASS();
}

/* Catches: a rule edit that sends or rewrites the whole list. */
TEST a_rule_edit_does_not_carry_the_whole_list(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_two_rule_group(h));
    char second[16];
    ASSERT(nth_rule_id(TWO, 1, second, sizeof(second)));
    char patch[160];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":false}]}", second);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", TWO_RULES, NULL, &out));
    cJSON *rules = jobj(out, "rules");
    ASSERT_EQ(2, cJSON_GetArraySize(rules));
    cJSON *r0 = cJSON_GetArrayItem(rules, 0), *r1 = cJSON_GetArrayItem(rules, 1);
    ASSERTm("the untouched one is untouched", cJSON_IsTrue(jobj(r0, "enable")));
    ASSERTm("and the named one changed", cJSON_IsFalse(jobj(r1, "enable")));
    ASSERT_STR_EQm("the pattern is the list's", "b.example.com", jstr(r1, "rule"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a rule edit that loses the interval, lastUpdate, group enable or another rule's enable. */
TEST a_rule_edit_carries_the_list_through_unchanged(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static const rule_spec_t rules[] = {
        {"a.example.com", "namespace", false},
        {"b.example.com", "namespace", true},
    };
    firc_group_t *g = group_with_rules(TWO, rules, 2);
    ASSERT(g != NULL);
    g->list->interval = 4242;
    g->list->last_update = 1700000000;
    ASSERT(add_on_loop(h, g));

    char second[16];
    ASSERT(nth_rule_id(TWO, 1, second, sizeof(second)));
    char patch[160];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"domain\"}]}", second);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" TWO, NULL, &out));
    ASSERTm("the group stays enabled", cJSON_IsTrue(jobj(out, "enable")));
    ASSERT_EQ_FMTm("the interval", 4242.0, jnum(jobj(out, "list"), "interval"), "%f");
    ASSERT_EQ_FMTm("the last update", 1700000000.0, jnum(jobj(out, "list"), "lastUpdate"), "%f");
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", TWO_RULES, NULL, &out));
    cJSON *got = jobj(out, "rules");
    ASSERTm("a rule nobody edited keeps its enable",
            cJSON_IsFalse(jobj(cJSON_GetArrayItem(got, 0), "enable")));
    ASSERT_STR_EQm("and the edit landed", "domain", jstr(cJSON_GetArrayItem(got, 1), "type"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a PATCH applying good edits before it finds an unknown id. */
TEST a_rule_edit_body_is_all_or_nothing(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_two_rule_group(h));
    char first[16];
    ASSERT(nth_rule_id(TWO, 0, first, sizeof(first)));
    char patch[256];
    snprintf(patch, sizeof(patch),
             "{\"rules\":[{\"id\":\"%s\",\"enable\":false},{\"id\":\"deadbeef\",\"enable\":false}]}",
             first);
    cJSON *out = NULL;
    int code = do_request("PATCH", TWO_RULES, patch, &out);
    cJSON_Delete(out);
    out = NULL;
    snprintf(patch, sizeof(patch),
             "{\"rules\":[{\"id\":\"%s\",\"enable\":false},{\"id\":\"%s\",\"type\":\"subnet6\"}]}",
             first, first);
    int bad_type = do_request("PATCH", TWO_RULES, patch, &out);
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", TWO_RULES, NULL, &out));
    bool untouched = cJSON_IsTrue(jobj(cJSON_GetArrayItem(jobj(out, "rules"), 0), "enable"));
    cJSON_Delete(out);
    harness_stop(h);
    ASSERT_EQ_FMTm("an unknown rule is refused", 404, code, "%d");
    ASSERT_EQ_FMTm("and so is a type that cannot work", 400, bad_type, "%d");
    ASSERTm("and the good entry before either was not applied", untouched);
    PASS();
}

/* Catches: a PATCH skipping the rule checks, editing the pattern, or naming the wrong missing field. */
TEST a_rule_edit_is_checked_the_way_every_other_path_is(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_two_rule_group(h));
    char first[16];
    ASSERT(nth_rule_id(TWO, 0, first, sizeof(first)));

    cJSON *out = NULL;
    char patch[160];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"subnet6\"}]}", first);
    int bad_type = do_request("PATCH", TWO_RULES, patch, &out);
    const char *msg = jstr(out, "error");
    bool named = msg != NULL && strstr(msg, "a.example.com") != NULL;
    cJSON_Delete(out);
    out = NULL;

    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"rule\":\"x.com\"}]}", first);
    int pattern_edit = do_request("PATCH", TWO_RULES, patch, &out);
    cJSON_Delete(out);
    out = NULL;

    int no_id = do_request("PATCH", TWO_RULES, "{\"rules\":[{\"enable\":false}]}", &out);
    cJSON_Delete(out);
    out = NULL;
    int no_rules = do_request("PATCH", TWO_RULES, "{\"edits\":[]}", &out);
    cJSON_Delete(out);
    out = NULL;

    int unknown_rule =
        do_request("PATCH", TWO_RULES, "{\"rules\":[{\"id\":\"deadbeef\",\"enable\":false}]}", &out);
    const char *rule_msg = jstr(out, "error");
    bool says_rule = rule_msg != NULL && strstr(rule_msg, "rule") != NULL;
    cJSON_Delete(out);
    out = NULL;
    int unknown_group = do_request("PATCH", "/api/v1/groups/deadbeef/list/rules",
                                   "{\"rules\":[{\"id\":\"00000011\",\"enable\":false}]}", &out);
    const char *group_msg = jstr(out, "error");
    bool says_group = group_msg != NULL && strstr(group_msg, "group") != NULL;
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", TWO_RULES, NULL, &out));
    cJSON *r0 = cJSON_GetArrayItem(jobj(out, "rules"), 0);
    bool untouched = strcmp(jstr(r0, "type"), "namespace") == 0 &&
                     strcmp(jstr(r0, "rule"), "a.example.com") == 0;
    cJSON_Delete(out);
    harness_stop(h);

    ASSERT_EQ_FMTm("a type that cannot work is refused", 400, bad_type, "%d");
    ASSERTm("and the rule is named", named);
    ASSERT_EQ_FMTm("the pattern is not editable here", 400, pattern_edit, "%d");
    ASSERT_EQ_FMTm("an edit without an id", 400, no_id, "%d");
    ASSERT_EQ_FMTm("a body without rules", 400, no_rules, "%d");
    ASSERT_EQ_FMTm("a rule id nobody has is a 404", 404, unknown_rule, "%d");
    ASSERTm("naming the rule", says_rule);
    ASSERT_EQ_FMTm("and so is a group nobody has", 404, unknown_group, "%d");
    ASSERTm("naming the group, not the rule", says_group);
    ASSERTm("a refused edit changes nothing", untouched);
    PASS();
}

/* Catches: an edit kept only in memory, or overrides written for rules nobody edited. */
TEST patching_a_rule_writes_an_override(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_two_rule_group(h));
    char second[16];
    ASSERT(nth_rule_id(TWO, 1, second, sizeof(second)));
    char patch[192];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":false,\"type\":\"domain\"}]}",
             second);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    ASSERT(on_loop(h, NULL, NULL));

    char *saved = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&h->cfg, "0.7.0", FIRC_CFG_GROUPS, &saved, &len));
    ASSERTm("the file carries an override", strstr(saved, "overrides:") != NULL);
    ASSERTm("naming the edited rule by its text", strstr(saved, "b.example.com") != NULL);
    ASSERTm("with the type the edit gave it", strstr(saved, "type: domain") != NULL);
    ASSERTm("and the enable the edit gave it", strstr(saved, "enable: false") != NULL);
    ASSERT_FALSEm("the rule nobody edited is not in the file", strstr(saved, "a.example.com") != NULL);
    free(saved);
    harness_stop(h);
    PASS();
}

/* Catches: an edit that replaces the overrides instead of adding to them. */
TEST a_second_edit_keeps_the_first(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_two_rule_group(h));
    char first[16], second[16];
    ASSERT(nth_rule_id(TWO, 0, first, sizeof(first)));
    ASSERT(nth_rule_id(TWO, 1, second, sizeof(second)));
    char patch[192];
    cJSON *out = NULL;
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":false}]}", first);
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"domain\"}]}", second);
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    ASSERT(on_loop(h, NULL, NULL));

    char *saved = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&h->cfg, "0.7.0", FIRC_CFG_GROUPS, &saved, &len));
    ASSERTm("the first edit is still there", strstr(saved, "a.example.com") != NULL);
    ASSERTm("with its enable", strstr(saved, "enable: false") != NULL);
    ASSERTm("and so is the second", strstr(saved, "b.example.com") != NULL);
    ASSERTm("with its type", strstr(saved, "type: domain") != NULL);
    free(saved);
    harness_stop(h);
    PASS();
}

/* Catches: a type set back to the guess leaving its override entry for ever. */
TEST setting_the_type_back_to_the_guess_removes_the_override(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_two_rule_group(h));
    char id[16];
    ASSERT(nth_rule_id(TWO, 1, id, sizeof(id)));
    char patch[192];
    cJSON *out = NULL;
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"domain\"}]}", id);
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;
    ASSERT(on_loop(h, NULL, NULL));

    char *saved = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&h->cfg, "0.7.0", FIRC_CFG_GROUPS, &saved, &len));
    ASSERTm("the disagreement is stored", strstr(saved, "type: domain") != NULL);
    free(saved);

    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"namespace\"}]}", id);
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    ASSERT(on_loop(h, NULL, NULL));

    saved = NULL;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&h->cfg, "0.7.0", FIRC_CFG_GROUPS, &saved, &len));
    ASSERTm("and agreeing again leaves nothing behind", strstr(saved, "overrides: []") != NULL);
    ASSERT_FALSEm("no entry for a rule nobody disagrees with", strstr(saved, "b.example.com") != NULL);
    free(saved);
    harness_stop(h);
    PASS();
}

/* Catches: a type edit equal to the guess changing the rule's type. */
TEST agreeing_with_the_guess_leaves_the_rule_alone(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    static const rule_spec_t rules[] = {
        {"a.example.com", "namespace", true},
        {"b.example.com", "domain", true},
    };
    ASSERT(add_on_loop(h, group_with_rules(TWO, rules, 2)));
    char id[16];
    ASSERT(nth_rule_id(TWO, 1, id, sizeof(id)));
    char patch[192];
    cJSON *out = NULL;
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"namespace\"}]}", id);
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(200, do_request("GET", TWO_RULES, NULL, &out));
    ASSERT_STR_EQm("the type was set, though no override was kept", "namespace",
                   jstr(cJSON_GetArrayItem(jobj(out, "rules"), 1), "type"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

#define SINGBOX_GROUP "0d0d0d0d"
#define SINGBOX_RULES "/api/v1/groups/" SINGBOX_GROUP "/list/rules"

/* Adds a fetched sing-box list: `a.com` as `domain` (index 0), `10.0.0.0/8` as udp `subnet` (1). */
static bool add_singbox_group(harness_t *h) {
    firc_group_t *g = list_group(stub_url("/singbox"), 0);
    if (g == NULL || firc_id_parse(SINGBOX_GROUP, &g->id) != FIRC_OK) {
        firc_group_free(g);
        return false;
    }
    g->list->has_body_hash = false;
    firc_id_t id = g->id;
    if (!add_on_loop(h, g)) {
        return false;
    }
    bool changed = false;
    return firc_app_sync_list_now(h->app, id, 1000, NULL, &changed) == FIRC_OK && changed;
}

/* Catches: a type edit measured against a fresh guess instead of the list's own type. */
TEST patching_a_singbox_rule_measures_against_the_lists_type(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_singbox_group(h));
    char id[16];
    ASSERT(nth_rule_id(SINGBOX_GROUP, 0, id, sizeof(id)));

    char patch[160];
    cJSON *out = NULL;
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"namespace\"}]}", id);
    ASSERT_EQ(200, do_request("PATCH", SINGBOX_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", SINGBOX_RULES, NULL, &out));
    ASSERT_STR_EQm("the list said domain, so this is an override and is kept", "namespace",
                   jstr(cJSON_GetArrayItem(jobj(out, "rules"), 0), "type"));
    cJSON_Delete(out);
    out = NULL;

    char *saved = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&h->cfg, "0.7.0", FIRC_CFG_GROUPS, &saved, &len));
    ASSERTm("the override is stored", strstr(saved, "a.com") != NULL);
    free(saved);

    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"domain\"}]}", id);
    ASSERT_EQ(200, do_request("PATCH", SINGBOX_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;

    saved = NULL;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&h->cfg, "0.7.0", FIRC_CFG_GROUPS, &saved, &len));
    ASSERTm("back to the list's own type, the override is cleared", strstr(saved, "a.com") == NULL);
    free(saved);
    harness_stop(h);
    PASS();
}

/* Catches: a rule with a proto spec moved to a type that cannot carry one. */
TEST patching_a_singbox_rule_with_a_spec_to_an_unusable_type_is_400(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_singbox_group(h));
    char id[16];
    ASSERT(nth_rule_id(SINGBOX_GROUP, 1, id, sizeof(id)));

    char patch[160];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"regex\"}]}", id);
    cJSON *out = NULL;
    ASSERT_EQ_FMTm("a spec belongs to a subnet, not a regex that merely compiles", 400,
                   do_request("PATCH", SINGBOX_RULES, patch, &out), "%d");
    cJSON_Delete(out);
    out = NULL;

    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"type\":\"subnet\"}]}", id);
    ASSERT_EQ_FMTm("positive control: the rule and its spec are fine for a type that carries one",
                   200, do_request("PATCH", SINGBOX_RULES, patch, &out), "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a PATCH accepting a `proto` or `ports` edit, which only the list may set. */
TEST a_rule_edit_naming_proto_or_ports_is_refused(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_singbox_group(h));
    char id[16];
    ASSERT(nth_rule_id(SINGBOX_GROUP, 1, id, sizeof(id)));

    char patch[160];
    cJSON *out = NULL;
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"proto\":\"tcp\"}]}", id);
    ASSERT_EQ_FMTm("proto is refused", 400, do_request("PATCH", SINGBOX_RULES, patch, &out), "%d");
    cJSON_Delete(out);
    out = NULL;

    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"ports\":\"80\"}]}", id);
    ASSERT_EQ_FMTm("ports is refused", 400, do_request("PATCH", SINGBOX_RULES, patch, &out), "%d");
    cJSON_Delete(out);
    out = NULL;

    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":false,\"proto\":\"tcp\"}]}", id);
    ASSERT_EQ_FMTm("the whole edit is refused, not just the proto key ignored", 400,
                   do_request("PATCH", SINGBOX_RULES, patch, &out), "%d");
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", SINGBOX_RULES, NULL, &out));
    cJSON *r1 = cJSON_GetArrayItem(jobj(out, "rules"), 1);
    ASSERT_STR_EQm("nothing changed", "udp", jstr(r1, "proto"));
    ASSERTm("still no ports", cJSON_GetObjectItemCaseSensitive(r1, "ports") == NULL);
    ASSERTm("still enabled: the enable half of the last edit never landed either",
            cJSON_IsTrue(jobj(r1, "enable")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

#define TWINS_GROUP "0e0e0e0e"
#define TWINS_RULES "/api/v1/groups/" TWINS_GROUP "/list/rules"

static bool add_singbox_twins_group(harness_t *h) {
    firc_group_t *g = list_group(stub_url("/singbox-twins"), 0);
    if (g == NULL || firc_id_parse(TWINS_GROUP, &g->id) != FIRC_OK) {
        firc_group_free(g);
        return false;
    }
    g->list->has_body_hash = false;
    firc_id_t id = g->id;
    if (!add_on_loop(h, g)) { return false; }
    bool changed = false;
    return firc_app_sync_list_now(h->app, id, 1000, NULL, &changed) == FIRC_OK && changed;
}

/* Catches: a line list's override keyed by list_type, lost once the type is guessed differently. */
TEST a_line_list_override_carries_no_list_type(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_two_rule_group(h));
    char id[16];
    ASSERT(nth_rule_id(TWO, 0, id, sizeof(id)));
    char patch[160];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":false}]}", id);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    ASSERT(on_loop(h, NULL, NULL));

    char *saved = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&h->cfg, "0.7.0", FIRC_CFG_GROUPS, &saved, &len));
    ASSERTm("the override is stored", strstr(saved, "a.example.com") != NULL);
    ASSERT_FALSEm("but carries no list_type: a.example.com has no twin",
                  strstr(saved, "list_type") != NULL);
    free(saved);
    harness_stop(h);
    PASS();
}

/* Catches: an override for one sing-box twin keyed without list_type, reaching both twins. */
TEST a_singbox_twins_override_carries_list_type_and_only_that_twin(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_singbox_twins_group(h));
    char id[16];
    ASSERT(nth_rule_id(TWINS_GROUP, 0, id, sizeof(id)));
    char patch[160];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":false}]}", id);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PATCH", TWINS_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;
    ASSERT(on_loop(h, NULL, NULL));

    char *saved = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&h->cfg, "0.7.0", FIRC_CFG_GROUPS, &saved, &len));
    ASSERTm("the override is stored", strstr(saved, "a.com") != NULL);
    ASSERTm("and carries list_type: a.com has a twin of the other type",
            strstr(saved, "list_type") != NULL);
    free(saved);

    ASSERT_EQ(200, do_request("GET", TWINS_RULES, NULL, &out));
    cJSON *rules = jobj(out, "rules");
    cJSON *r0 = cJSON_GetArrayItem(rules, 0), *r1 = cJSON_GetArrayItem(rules, 1);
    cJSON *patched = strcmp(jstr(r0, "id"), id) == 0 ? r0 : r1;
    cJSON *other = patched == r0 ? r1 : r0;
    ASSERT_FALSEm("the patched twin is off", cJSON_IsTrue(jobj(patched, "enable")));
    ASSERTm("the other twin is untouched", cJSON_IsTrue(jobj(other, "enable")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

typedef struct reapply_probe {
    harness_t *h;
    firc_id_t id;
    bool enabled;
    bool has_typed_override;
} reapply_probe_t;

static void reapply_probe_fn(void *arg) {
    reapply_probe_t *p = arg;
    firc_group_t *g = firc_ruleset_group_mut(firc_app_find_group_by_id(p->h->app, p->id));
    firc_group_list_t *l = g->list;
    firc_sub_apply_overrides(l, &l->rules);
    for (size_t i = 0; i < l->rules.n; i++) {
        if (strcmp(firc_sub_rules_text(&l->rules, i), "a.com") == 0) {
            p->enabled = firc_sub_rules_enable(&l->rules, i);
            break;
        }
    }
    firc_sub_rule_key_t key = {.text = "a.com", .list_type = FIRC_RULE_DOMAIN};
    p->has_typed_override = firc_group_list_find_override(l, &key) != NULL;
}

/* Catches: a rule that lost its twin keying its next edit without list_type, missing its override. */
TEST a_rule_that_loses_its_twin_still_finds_its_typed_override(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_singbox_twins_group(h));

    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", TWINS_RULES, NULL, &out));
    cJSON *rules = jobj(out, "rules");
    cJSON *r0 = cJSON_GetArrayItem(rules, 0), *r1 = cJSON_GetArrayItem(rules, 1);
    cJSON *domain_rule = strcmp(jstr(r0, "type"), "domain") == 0 ? r0 : r1;
    char id[16];
    snprintf(id, sizeof(id), "%s", jstr(domain_rule, "id"));
    cJSON_Delete(out);
    out = NULL;

    char patch[160];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":false}]}", id);
    ASSERT_EQ(200, do_request("PATCH", TWINS_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;

    firc_id_t gid;
    ASSERT_EQ(FIRC_OK, firc_id_parse(TWINS_GROUP, &gid));
    bool changed = false;
    ASSERT_EQ(FIRC_OK,
             firc_app_sync_list_now(h->app, gid, 1000, stub_url("/singbox-twin-gone"), &changed));
    ASSERT(changed);
    char after_id[16];
    ASSERT(nth_rule_id(TWINS_GROUP, 0, after_id, sizeof(after_id)));
    ASSERT_STR_EQm("the id survived the resync (inherited by key)", id, after_id);

    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":true}]}", id);
    ASSERT_EQ(200, do_request("PATCH", TWINS_RULES, patch, &out));
    cJSON_Delete(out);
    out = NULL;

    reapply_probe_t p = {.h = h, .id = gid, .enabled = false, .has_typed_override = true};
    ASSERT(on_loop(h, reapply_probe_fn, &p));
    ASSERTm("re-enabled, and it stays that way once overrides are re-derived "
            "(what a sync or a restart does)",
            p.enabled);
    ASSERT_FALSEm("no typed disabling entry remains for it", p.has_typed_override);

    harness_stop(h);
    PASS();
}

static int g_warn_pipe[2];

static const char *warn_log_capture_sync(harness_t *h, firc_id_t id) {
    static char buf[4096];
    if (pipe(g_warn_pipe) != 0) { return ""; }
    fcntl(g_warn_pipe[0], F_SETFL, fcntl(g_warn_pipe[0], F_GETFL) | O_NONBLOCK);
    fcntl(g_warn_pipe[1], F_SETFL, fcntl(g_warn_pipe[1], F_GETFL) | O_NONBLOCK);
    firc_log_level_t prev = firc_log_level();
    firc_log_set_level(FIRC_LOG_WARN);
    firc_log_set_fd(g_warn_pipe[1]);
    bool changed = false;
    firc_app_sync_list_now(h->app, id, 1000, NULL, &changed);
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_level(prev);
    ssize_t n = read(g_warn_pipe[0], buf, sizeof(buf) - 1);
    buf[n > 0 ? n : 0] = '\0';
    close(g_warn_pipe[0]);
    close(g_warn_pipe[1]);
    return buf;
}

typedef struct warn_capture_args {
    harness_t *h;
    firc_id_t id;
    const char *out;
    sem_t done;
} warn_capture_args_t;

static void *warn_capture_thread(void *arg) {
    warn_capture_args_t *a = arg;
    a->out = warn_log_capture_sync(a->h, a->id);
    sem_post(&a->done);
    return NULL;
}

/* Catches: a blocking read on the capture pipe hanging the suite when no WARN is logged. */
TEST the_warn_capture_does_not_hang_when_nothing_is_dropped(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *g = list_group(stub_url("/list"), 0);
    ASSERT(g != NULL);
    firc_id_t id = g->id;
    ASSERT(add_on_loop(h, g));

    warn_capture_args_t a = {.h = h, .id = id, .out = NULL};
    ASSERT_EQ(0, sem_init(&a.done, 0, 0));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, warn_capture_thread, &a));

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 3;
    bool returned = sem_timedwait(&a.done, &ts) == 0;
    ASSERTm("the capture returned within 3s instead of hanging", returned);
    if (returned) {
        pthread_join(th, NULL);
        ASSERTm("nothing was dropped, so nothing was logged", a.out == NULL || a.out[0] == '\0');
    } else {
        pthread_detach(th);
    }
    sem_destroy(&a.done);
    harness_stop(h);
    PASS();
}

/* Catches: a dropped-count WARN worded for lines only, wrong for sing-box objects and values. */
TEST the_dropped_count_warn_says_entries_not_lines(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    firc_group_t *g = list_group(stub_url("/junk"), 0);
    ASSERT(g != NULL);
    firc_id_t id = g->id;
    ASSERT(add_on_loop(h, g));

    const char *log = warn_log_capture_sync(h, id);
    ASSERTm("the dropped-count WARN fired", strstr(log, "dropped") != NULL);
    ASSERTm("wording true for a line list too: \"entr\", not \"line(s)\"",
            strstr(log, "entr") != NULL);
    ASSERT_FALSEm("the old line-list-only wording is gone", strstr(log, "line(s)") != NULL);
    harness_stop(h);
    PASS();
}

typedef struct arena_probe {
    harness_t *h;
    firc_id_t a, b;
    const char *text_a, *text_b;
    uint64_t seq_a, seq_b;
    firc_sub_sync_state_t state_b;
} arena_probe_t;

static void arena_probe_fn(void *arg) {
    arena_probe_t *p = arg;
    const firc_group_t *ga = firc_ruleset_group(firc_app_find_group_by_id(p->h->app, p->a));
    const firc_group_t *gb = firc_ruleset_group(firc_app_find_group_by_id(p->h->app, p->b));
    p->text_a = ga->list->rules.text;
    p->seq_a = ga->list->sync_seq;
    p->text_b = gb->list->rules.text;
    p->seq_b = gb->list->sync_seq;
    p->state_b = gb->list->sync_state;
}

/* Catches: a rule edit that copies or resyncs every group's list instead of the one edited. */
TEST patching_a_list_rule_touches_no_other_group(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT(add_two_rule_group(h));
    static const rule_spec_t other[] = {{"c.example.net", "namespace", true}};
    ASSERT(add_on_loop(h, group_with_rules("0b0b0b0b", other, 1)));

    arena_probe_t before = {.h = h};
    ASSERT_EQ(FIRC_OK, firc_id_parse(TWO, &before.a));
    ASSERT_EQ(FIRC_OK, firc_id_parse("0b0b0b0b", &before.b));
    arena_probe_t after = before;
    ASSERT(on_loop(h, arena_probe_fn, &before));

    char first[16];
    ASSERT(nth_rule_id(TWO, 0, first, sizeof(first)));
    char patch[192];
    snprintf(patch, sizeof(patch), "{\"rules\":[{\"id\":\"%s\",\"enable\":false,\"type\":\"domain\"}]}",
             first);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PATCH", TWO_RULES, patch, &out));
    cJSON_Delete(out);
    ASSERT(on_loop(h, arena_probe_fn, &after));
    harness_stop(h);

    ASSERTm("the other group's arena did not move", after.text_b == before.text_b);
    ASSERTm("and nothing was queued for it", before.seq_b == after.seq_b);
    ASSERT_EQ_FMTm("it is still idle", FIRC_SUB_SYNC_IDLE, after.state_b, "%d");
    ASSERTm("the edited group's arena was edited in place, not copied", after.text_a == before.text_a);
    ASSERTm("and no sync was queued for it either", before.seq_a == after.seq_a);
    PASS();
}

TEST sync_unknown_group_is_404(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(404, do_request("POST", "/api/v1/groups/aabbccdd/list/sync", NULL, NULL));
    ASSERT_EQ(400, do_request("POST", "/api/v1/groups/nothex!/list/sync", NULL, NULL));
    harness_stop(h);
    PASS();
}

/* Catches: a sync route that blocks for the fetch and answers its outcome instead of 202. */
TEST sync_answers_202_with_the_record_at_queued(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/slow"));
    cJSON *out = NULL;
    ASSERT_EQ(202, do_request("POST", "/api/v1/groups/" GID "/list/sync", "{}", &out));
    ASSERT(out != NULL);
    ASSERT_STR_EQm("it is the group's record", GID, jstr(out, "id"));
    ASSERT_STR_EQm("the job was accepted, not finished", "queued", list_state_of(out));
    ASSERT_EQ_FMTm("and nothing has arrived yet", 0.0, list_total_of(out), "%f");
    cJSON_Delete(out);
    ASSERT(wait_settled(GID, 5000));
    harness_stop(h);
    PASS();
}

/* Catches: a sync that needs a url in the body, which the WebUI's Sync button does not send. */
TEST sync_without_body_uses_the_lists_url(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/list"));
    ASSERT(wait_settled(GID, 5000));
    ASSERT_EQ(202, do_request("POST", "/api/v1/groups/" GID "/list/sync", NULL, NULL));
    ASSERT(wait_settled(GID, 5000));

    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID "/list/rules", NULL, &out));
    cJSON *rules = jobj(out, "rules");
    ASSERT_EQ(2, cJSON_GetArraySize(rules));
    ASSERT_STR_EQ("one.example", jstr(cJSON_GetArrayItem(rules, 0), "rule"));
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID, NULL, &out));
    ASSERT_EQ_FMT(2.0, list_total_of(out), "%f");
    ASSERT_STR_EQm("it used its own url", stub_url("/list"), jstr(jobj(out, "list"), "url"));
    ASSERT_STR_EQm("and finished", "idle", list_state_of(out));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: the body's url stored only after the fetch, so the worker never sees it. */
TEST sync_with_body_url_stores_the_url_before_queuing(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/slow"));
    char body[256];
    snprintf(body, sizeof(body), "{\"url\":\"%s\"}", stub_url("/list2"));
    cJSON *out = NULL;
    ASSERT_EQ(202, do_request("POST", "/api/v1/groups/" GID "/list/sync", body, &out));
    ASSERT_STR_EQm("the answer already carries it", stub_url("/list2"), jstr(jobj(out, "list"), "url"));
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID, NULL, &out));
    ASSERT_STR_EQ(stub_url("/list2"), jstr(jobj(out, "list"), "url"));
    cJSON_Delete(out);
    ASSERT(wait_settled(GID, 5000));
    harness_stop(h);
    PASS();
}

/* Catches: a url change kept only in memory when the sync finds the list unchanged. */
TEST a_url_only_change_is_persisted(void) {
    harness_t *h = harness_start_saving();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/list"));
    ASSERT(wait_settled(GID, 5000));
    char body[256];
    snprintf(body, sizeof(body), "{\"url\":\"%s\"}", stub_url("/list2"));
    ASSERT_EQ(202, do_request("POST", "/api/v1/groups/" GID "/list/sync", body, NULL));
    ASSERT(wait_settled(GID, 5000));

    char groups[160];
    snprintf(groups, sizeof(groups), "%s/groups.yaml", h->cfg_dir);
    char file[8192] = {0};
    FILE *f = fopen(groups, "r");
    ASSERTm("the daemon wrote a groups file", f != NULL);
    size_t got = fread(file, 1, sizeof(file) - 1, f);
    fclose(f);
    file[got] = '\0';
    ASSERTm("the new url is on disk", strstr(file, stub_url("/list2")) != NULL);
    harness_stop(h);
    PASS();
}

/* Catches: a 202 from a daemon whose list worker never started. */
TEST sync_without_a_worker_is_unavailable(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/list"));
    cJSON *out = NULL;
    ASSERT_EQ(503, do_request("POST", "/api/v1/groups/" GID "/list/sync", NULL, &out));
    ASSERT_STR_EQ("sync unavailable", jstr(out, "error"));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: the url checked before the group id. */
TEST a_sync_for_an_unknown_id_is_404_whatever_url_it_names(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    static const char bad_url[] = "{\"url\":\"ftp://example.com/list.txt\"}";
    ASSERT_EQ(404, do_request("POST", "/api/v1/groups/" GID "/list/sync", bad_url, NULL));
    ASSERT_EQ(200, create_stub_group("/list"));
    ASSERT_EQ(400, do_request("POST", "/api/v1/groups/" GID "/list/sync", bad_url, NULL));
    ASSERT(wait_settled(GID, 5000));
    harness_stop(h);
    PASS();
}

/* Catches: an HTML page's reason lost on the way into sync.error. */
TEST a_synced_html_page_ends_in_error_with_the_reason(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/html"));
    ASSERT(wait_settled(GID, 5000));
    cJSON *rec = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID, NULL, &rec));
    ASSERT_STR_EQ("error", list_state_of(rec));
    const char *err = jstr(jobj(jobj(rec, "list"), "sync"), "error");
    ASSERTm("the reason names the raw-file fix", err != NULL && strstr(err, "raw") != NULL);
    cJSON_Delete(rec);
    harness_stop(h);
    PASS();
}

/* Catches: a stream sending only the final state, or `done` before any `progress`. */
TEST the_events_stream_reports_progress_then_done(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/slow"));

    int fd = stream_open("/api/v1/groups/" GID "/list/sync/events");
    ASSERT(fd >= 0);
    char buf[8192];
    size_t n = read_stream(fd, buf, sizeof(buf), 5000);
    close(fd);
    ASSERT(n > 0);
    ASSERT(strstr(buf, "Content-Type: text/event-stream\r\n") != NULL);
    ASSERT(strstr(buf, "Cache-Control: no-cache\r\n") != NULL);

    const char *progress = strstr(buf, "event: progress\n");
    const char *done = strstr(buf, "event: done\n");
    ASSERTm("progress arrived", progress != NULL);
    ASSERTm("done arrived", done != NULL);
    ASSERTm("and progress came first", progress < done);
    ASSERT_EQ_FMTm("exactly one done", 1, count_events(buf, "done"), "%d");
    ASSERT_EQ_FMTm("and no error", 0, count_events(buf, "error"), "%d");

    cJSON *rec = event_data(buf, "done");
    ASSERTm("done carries the record", rec != NULL);
    ASSERT_STR_EQm("the group's", GID, jstr(rec, "id"));
    ASSERT_EQ_FMTm("with the rules that arrived in its list", 2.0, list_total_of(rec), "%f");
    ASSERT_STR_EQ("idle", list_state_of(rec));
    cJSON_Delete(rec);
    ASSERTm("the stream is finished", stream_finished(buf, n));
    harness_stop(h);
    PASS();
}

/* Catches: a failed sync ending the stream with `done`, or with nothing. */
TEST the_events_stream_reports_an_error(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/slow404"));
    int fd = stream_open("/api/v1/groups/" GID "/list/sync/events");
    ASSERT(fd >= 0);
    char buf[8192];
    size_t n = read_stream(fd, buf, sizeof(buf), 5000);
    close(fd);
    ASSERT(n > 0);
    ASSERT_EQ_FMTm("one error", 1, count_events(buf, "error"), "%d");
    ASSERT_EQ_FMTm("and no done", 0, count_events(buf, "done"), "%d");
    cJSON *err = event_data(buf, "error");
    ASSERT(err != NULL);
    const char *text = jstr(err, "error");
    ASSERTm("the error names what the server answered", text != NULL && strstr(text, "404") != NULL);
    cJSON_Delete(err);
    ASSERTm("the stream is finished", stream_finished(buf, n));

    cJSON *rec = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID, NULL, &rec));
    ASSERT_STR_EQm("and the record keeps saying so", "error", list_state_of(rec));
    cJSON_Delete(rec);
    harness_stop(h);
    PASS();
}

/* Catches: a stream for an idle list held open for an event that never comes. */
TEST the_events_stream_for_an_idle_list_answers_one_event_and_closes(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/list"));
    ASSERT(wait_settled(GID, 5000));
    int fd = stream_open("/api/v1/groups/" GID "/list/sync/events");
    ASSERT(fd >= 0);
    char buf[8192];
    size_t n = read_stream(fd, buf, sizeof(buf), 3000);
    close(fd);
    ASSERT(n > 0);
    ASSERT_EQ_FMTm("one done", 1, count_events(buf, "done"), "%d");
    ASSERT_EQ_FMTm("no progress", 0, count_events(buf, "progress"), "%d");
    cJSON *rec = event_data(buf, "done");
    ASSERT(rec != NULL);
    ASSERT_STR_EQ("idle", list_state_of(rec));
    cJSON_Delete(rec);
    ASSERTm("the stream is finished", stream_finished(buf, n));
    harness_stop(h);
    PASS();
}

/* Catches: a stream socket held for an id nothing will ever report on. */
TEST the_events_stream_is_404_for_an_unknown_id(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(404, do_request("GET", "/api/v1/groups/aabbccdd/list/sync/events", NULL, NULL));
    ASSERT_EQ(400, do_request("GET", "/api/v1/groups/nothex!/list/sync/events", NULL, NULL));
    harness_stop(h);
    PASS();
}

/* Catches: a shutdown leaving a stream open, or freeing its entry twice. */
TEST a_stream_still_open_at_shutdown_is_ended(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/slow"));
    int fd = stream_open("/api/v1/groups/" GID "/list/sync/events");
    ASSERT(fd >= 0);
    char head[4096];
    ASSERTm("the stream is open and reporting", read_until_progress(fd, head, sizeof(head)));
    harness_stop(h);
    char rest[4096];
    size_t m = read_stream(fd, rest, sizeof(rest), 3000);
    close(fd);
    ASSERTm("the body is terminated, not truncated", stream_finished(rest, m));
    PASS();
}

/* Catches: a DELETE leaving the stream that watches the group's list open for ever. */
TEST a_delete_ends_the_streams_watching_that_group(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/slow"));
    int fd = stream_open("/api/v1/groups/" GID "/list/sync/events");
    ASSERT(fd >= 0);
    char head[4096];
    ASSERTm("the stream is open and reporting", read_until_progress(fd, head, sizeof(head)));
    ASSERT_EQ(200, do_request("DELETE", "/api/v1/groups/" GID, NULL, NULL));
    char rest[8192];
    size_t m = read_stream(fd, rest, sizeof(rest), 3000);
    close(fd);
    ASSERTm("the stream ended: the body is terminated", stream_finished(rest, m));
    ASSERT_EQ_FMTm("one error, naming the reason", 1, count_events(rest, "error"), "%d");
    ASSERT_EQ_FMTm("and no done for a record that is gone", 0, count_events(rest, "done"), "%d");
    cJSON *payload = event_data(rest, "error");
    ASSERT(payload != NULL);
    ASSERT_STR_EQ("group removed", jstr(payload, "error"));
    cJSON_Delete(payload);
    harness_stop(h);
    PASS();
}

/* Catches: a `"list": null` PUT freeing the watched list without ending its stream. */
TEST a_null_list_ends_the_open_stream(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/slow"));
    int fd = stream_open("/api/v1/groups/" GID "/list/sync/events");
    ASSERT(fd >= 0);
    char head[4096];
    ASSERTm("the stream is open and reporting", read_until_progress(fd, head, sizeof(head)));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("PUT", "/api/v1/groups/" GID,
                              "{\"name\":\"g\",\"interface\":\"lo\",\"list\":null}", &out));
    ASSERTm("the answer has no list", jobj(out, "list") == NULL);
    cJSON_Delete(out);
    char rest[8192];
    size_t m = read_stream(fd, rest, sizeof(rest), 3000);
    close(fd);
    ASSERTm("the stream ended: the body is terminated", stream_finished(rest, m));
    ASSERT_EQ_FMTm("one error", 1, count_events(rest, "error"), "%d");
    ASSERT_EQ_FMTm("and no done", 0, count_events(rest, "done"), "%d");
    cJSON *payload = event_data(rest, "error");
    ASSERT(payload != NULL);
    ASSERT_STR_EQ("list removed", jstr(payload, "error"));
    cJSON_Delete(payload);
    harness_stop(h);
    PASS();
}

/* Catches: a superseded sync result ending the stream while the current sync still runs. */
TEST a_stale_result_changes_nothing_observable(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/slow"));
    ASSERT_EQ(202, do_request("POST", "/api/v1/groups/" GID "/list/sync", NULL, NULL));
    int fd = stream_open("/api/v1/groups/" GID "/list/sync/events");
    ASSERT(fd >= 0);
    char buf[8192];
    size_t n = read_stream(fd, buf, sizeof(buf), 8000);
    close(fd);
    ASSERT(n > 0);
    ASSERT_EQ_FMTm("one done, not two", 1, count_events(buf, "done"), "%d");
    ASSERT_EQ_FMTm("and no error", 0, count_events(buf, "error"), "%d");
    cJSON *rec = event_data(buf, "done");
    ASSERT(rec != NULL);
    ASSERT_EQ_FMT(2.0, list_total_of(rec), "%f");
    ASSERT_STR_EQ("idle", list_state_of(rec));
    cJSON_Delete(rec);
    ASSERT(wait_settled(GID, 5000));
    harness_stop(h);
    PASS();
}

#define NINE "0c0c0c0c"
#define NINE_RULES "/api/v1/groups/" NINE "/list/rules"

static bool add_nine_rule_group(harness_t *h) {
    static const rule_spec_t nine[] = {
        {"a1.example.com", "namespace", true}, {"a2.example.com", "namespace", true},
        {"a3.example.com", "namespace", true}, {"b4.example.com", "namespace", true},
        {"b5.example.com", "namespace", true}, {"b6.example.com", "namespace", true},
        {"c7.example.net", "domain", false},   {"c8.example.net", "domain", true},
        {"c9.example.net", "domain", true},
    };
    return add_on_loop(h, group_with_rules(NINE, nine, 9));
}

TEST a_page_is_a_window_onto_the_list_in_order(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_nine_rule_group(h));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", NINE_RULES "?offset=3&limit=2", NULL, &out));
    ASSERT_EQ_FMT(9.0, jnum(out, "total"), "%f");
    ASSERT_EQ_FMT(9.0, jnum(out, "matched"), "%f");
    ASSERT_EQ_FMT(3.0, jnum(out, "offset"), "%f");
    cJSON *rules = jobj(out, "rules");
    ASSERT_EQ(2, cJSON_GetArraySize(rules));
    ASSERT_STR_EQ("b4.example.com", jstr(cJSON_GetArrayItem(rules, 0), "rule"));
    ASSERT_STR_EQ("b5.example.com", jstr(cJSON_GetArrayItem(rules, 1), "rule"));
    ASSERTm("a rule carries its id", jstr(cJSON_GetArrayItem(rules, 0), "id") != NULL);
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", NINE_RULES, NULL, &out));
    ASSERT_EQ(9, cJSON_GetArraySize(jobj(out, "rules")));
    ASSERT_EQ_FMT(0.0, jnum(out, "offset"), "%f");
    ASSERTm("the seventh keeps its enable",
            cJSON_IsFalse(jobj(cJSON_GetArrayItem(jobj(out, "rules"), 6), "enable")));
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", NINE_RULES "?offset=50", NULL, &out));
    ASSERT_EQ(0, cJSON_GetArraySize(jobj(out, "rules")));
    ASSERT_EQ_FMT(9.0, jnum(out, "total"), "%f");
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", NINE_RULES "?limit=100000", NULL, &out));
    ASSERT_EQ(9, cJSON_GetArraySize(jobj(out, "rules")));
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(404, do_request("GET", "/api/v1/groups/deadbeef/list/rules", NULL, &out));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

TEST a_search_is_done_by_the_daemon(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    ASSERT(add_nine_rule_group(h));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", NINE_RULES "?q=EXAMPLE.NET&offset=1&limit=1", NULL, &out));
    ASSERT_EQ_FMT(9.0, jnum(out, "total"), "%f");
    ASSERT_EQ_FMT(3.0, jnum(out, "matched"), "%f");
    cJSON *rules = jobj(out, "rules");
    ASSERT_EQ(1, cJSON_GetArraySize(rules));
    ASSERT_STR_EQ("c8.example.net", jstr(cJSON_GetArrayItem(rules, 0), "rule"));
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(200, do_request("GET", NINE_RULES "?q=nothing-here", NULL, &out));
    ASSERT_EQ_FMT(0.0, jnum(out, "matched"), "%f");
    ASSERT_EQ(0, cJSON_GetArraySize(jobj(out, "rules")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: a search query cut to a fixed-size buffer. */
TEST a_long_query_is_not_truncated(void) {
    harness_t *h = harness_start();
    ASSERT(h != NULL);
    char long_rule[512] = "^";
    for (int i = 0; i < 290; i++) { strcat(long_rule, "a"); }
    strcat(long_rule, "$");
    ASSERT_EQ(292, (int)strlen(long_rule));
    const rule_spec_t one[] = {{long_rule, "regex", true}};
    ASSERT(add_on_loop(h, group_with_rules(TWO, one, 1)));

    char q[512];
    snprintf(q, sizeof(q), "%s?q=", TWO_RULES);
    for (int i = 0; i < 296; i++) { strcat(q, "a"); }
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", q, NULL, &out));
    ASSERT_EQ_FMT(0.0, jnum(out, "matched"), "%f");
    cJSON_Delete(out);
    out = NULL;

    snprintf(q, sizeof(q), "%s?q=", TWO_RULES);
    for (int i = 0; i < 280; i++) { strcat(q, "A"); }
    ASSERT_EQ(200, do_request("GET", q, NULL, &out));
    ASSERT_EQ_FMT(1.0, jnum(out, "matched"), "%f");
    ASSERT_EQ(1, cJSON_GetArraySize(jobj(out, "rules")));
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: offset or limit parsed loosely instead of refused, or a wrong default page size. */
TEST the_page_refuses_a_number_it_cannot_mean(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/big"));
    ASSERT(wait_settled(GID, 5000));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID "/list/rules?limit=1", NULL, &out));
    ASSERT_EQ_FMTm("fixture: the whole stub list arrived", 540.0, jnum(out, "total"), "%f");
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(400, do_request("GET", "/api/v1/groups/" GID "/list/rules?offset=-1", NULL, &out));
    ASSERT_STR_EQ("invalid offset", jstr(out, "error"));
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(400, do_request("GET", "/api/v1/groups/" GID "/list/rules?limit=-1", NULL, &out));
    ASSERT_STR_EQ("invalid limit", jstr(out, "error"));
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(400, do_request("GET", "/api/v1/groups/" GID "/list/rules?limit=abc", NULL, &out));
    ASSERT_STR_EQ("invalid limit", jstr(out, "error"));
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(400, do_request("GET", "/api/v1/groups/" GID "/list/rules?offset=1x", NULL, &out));
    cJSON_Delete(out);
    out = NULL;

    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID "/list/rules?limit=0", NULL, &out));
    ASSERT_EQ_FMTm("limit=0 is the default page size", 50, cJSON_GetArraySize(jobj(out, "rules")), "%d");
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID "/list/rules", NULL, &out));
    ASSERT_EQ_FMTm("and so is no limit at all", 50, cJSON_GetArraySize(jobj(out, "rules")), "%d");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: `matched` counted over the page, or the offset applied to the rule index. */
TEST an_offset_past_the_last_match_is_an_empty_page_that_still_counts(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    ASSERT_EQ(200, create_stub_group("/big"));
    ASSERT(wait_settled(GID, 5000));
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID "/list/rules?q=h04&offset=99", NULL, &out));
    ASSERT_EQ_FMT(1, cJSON_GetArraySize(jobj(out, "rules")), "%d");
    ASSERT_EQ_FMT(100.0, jnum(out, "matched"), "%f");
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(200, do_request("GET", "/api/v1/groups/" GID "/list/rules?q=h04&offset=100", NULL, &out));
    ASSERT_EQ_FMT(0, cJSON_GetArraySize(jobj(out, "rules")), "%d");
    ASSERT_EQ_FMT(100.0, jnum(out, "matched"), "%f");
    ASSERT_EQ_FMT(540.0, jnum(out, "total"), "%f");
    ASSERT_EQ_FMT(100.0, jnum(out, "offset"), "%f");
    cJSON_Delete(out);
    out = NULL;
    ASSERT_EQ(200,
              do_request("GET", "/api/v1/groups/" GID "/list/rules?q=h04&offset=100000", NULL, &out));
    ASSERT_EQ_FMT(0, cJSON_GetArraySize(jobj(out, "rules")), "%d");
    ASSERT_EQ_FMT(100.0, jnum(out, "matched"), "%f");
    cJSON_Delete(out);
    harness_stop(h);
    PASS();
}

/* Catches: list routes on a group without a list answering as if its list were empty. */
TEST list_routes_on_a_manual_group_are_404(void) {
    harness_t *h = harness_start_with_worker();
    ASSERT(h != NULL);
    cJSON *out = NULL;
    ASSERT_EQ(200, do_request("POST", "/api/v1/groups",
                              "{\"id\":\"" GID "\",\"name\":\"hand\",\"interface\":\"lo\"}", &out));
    ASSERTm("fixture: a group with no list", jobj(out, "list") == NULL);
    cJSON_Delete(out);

    static const struct {
        const char *method, *path, *body;
    } calls[] = {
        {"GET", "/api/v1/groups/" GID "/list/rules", NULL},
        {"PATCH", "/api/v1/groups/" GID "/list/rules", "{\"rules\":[]}"},
        {"POST", "/api/v1/groups/" GID "/list/sync", NULL},
        {"GET", "/api/v1/groups/" GID "/list/sync/events", NULL},
    };
    for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++) {
        out = NULL;
        int code = do_request(calls[i].method, calls[i].path, calls[i].body, &out);
        const char *msg = jstr(out, "error");
        bool says = msg != NULL && strcmp(msg, "group has no list") == 0;
        cJSON_Delete(out);
        if (code != 404 || !says) {
            fprintf(stderr, "%s %s: %d\n", calls[i].method, calls[i].path, code);
        }
        ASSERT_EQ_FMTm("404", 404, code, "%d");
        ASSERTm("saying the group has no list", says);
    }
    harness_stop(h);
    PASS();
}

/* Stops a harness a failed assertion left running, or its port stays bound for later tests. */
static void stop_live_harness(void *ud) {
    (void)ud;
    atomic_store(&g_gate_open, true);
    if (live_harness != NULL) { harness_stop(live_harness); }
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    firc_log_set_level(FIRC_LOG_ERROR);
    firc_sub_fetch_global_init();
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(stop_live_harness, NULL);
    RUN_TEST(put_groups_answers_the_carried_list);
    RUN_TEST(a_put_without_list_keeps_it_and_null_removes_it);
    RUN_TEST(a_list_needs_a_supported_url);
    RUN_TEST(creating_a_group_with_a_list_answers_it_queued);
    RUN_TEST(a_duplicate_group_id_is_409);
    RUN_TEST(lastUpdate_in_a_body_is_ignored);
    RUN_TEST(the_preview_is_counts_and_a_bounded_sample);
    RUN_TEST(the_preview_says_how_many_lines_it_could_not_use);
    RUN_TEST(the_preview_of_an_html_page_says_so);
    RUN_TEST(the_preview_of_a_sing_box_list_shows_spec_and_counts);
    RUN_TEST(the_preview_requires_a_url);
    RUN_TEST(the_preview_returns_the_parsed_rules);
    RUN_TEST(the_preview_fetch_failure_is_502);
    RUN_TEST(a_preview_in_flight_leaves_the_loop_serving);
    RUN_TEST(a_client_that_leaves_mid_preview_is_forgotten);
    RUN_TEST(previews_past_two_at_once_are_503);
    RUN_TEST(a_preview_in_flight_at_shutdown_is_ended);
    RUN_TEST(a_rule_edit_does_not_carry_the_whole_list);
    RUN_TEST(a_rule_edit_carries_the_list_through_unchanged);
    RUN_TEST(a_rule_edit_body_is_all_or_nothing);
    RUN_TEST(a_rule_edit_is_checked_the_way_every_other_path_is);
    RUN_TEST(patching_a_rule_writes_an_override);
    RUN_TEST(a_second_edit_keeps_the_first);
    RUN_TEST(setting_the_type_back_to_the_guess_removes_the_override);
    RUN_TEST(agreeing_with_the_guess_leaves_the_rule_alone);
    RUN_TEST(patching_a_singbox_rule_measures_against_the_lists_type);
    RUN_TEST(patching_a_singbox_rule_with_a_spec_to_an_unusable_type_is_400);
    RUN_TEST(a_rule_edit_naming_proto_or_ports_is_refused);
    RUN_TEST(a_line_list_override_carries_no_list_type);
    RUN_TEST(a_singbox_twins_override_carries_list_type_and_only_that_twin);
    RUN_TEST(a_rule_that_loses_its_twin_still_finds_its_typed_override);
    RUN_TEST(the_warn_capture_does_not_hang_when_nothing_is_dropped);
    RUN_TEST(the_dropped_count_warn_says_entries_not_lines);
    RUN_TEST(patching_a_list_rule_touches_no_other_group);
    RUN_TEST(sync_unknown_group_is_404);
    RUN_TEST(sync_answers_202_with_the_record_at_queued);
    RUN_TEST(sync_without_body_uses_the_lists_url);
    RUN_TEST(sync_with_body_url_stores_the_url_before_queuing);
    RUN_TEST(a_url_only_change_is_persisted);
    RUN_TEST(sync_without_a_worker_is_unavailable);
    RUN_TEST(a_sync_for_an_unknown_id_is_404_whatever_url_it_names);
    RUN_TEST(a_synced_html_page_ends_in_error_with_the_reason);
    RUN_TEST(the_events_stream_reports_progress_then_done);
    RUN_TEST(the_events_stream_reports_an_error);
    RUN_TEST(the_events_stream_for_an_idle_list_answers_one_event_and_closes);
    RUN_TEST(the_events_stream_is_404_for_an_unknown_id);
    RUN_TEST(a_stream_still_open_at_shutdown_is_ended);
    RUN_TEST(a_delete_ends_the_streams_watching_that_group);
    RUN_TEST(a_null_list_ends_the_open_stream);
    RUN_TEST(a_stale_result_changes_nothing_observable);
    RUN_TEST(a_page_is_a_window_onto_the_list_in_order);
    RUN_TEST(a_search_is_done_by_the_daemon);
    RUN_TEST(a_long_query_is_not_truncated);
    RUN_TEST(the_page_refuses_a_number_it_cannot_mean);
    RUN_TEST(an_offset_past_the_last_match_is_an_empty_page_that_still_counts);
    RUN_TEST(list_routes_on_a_manual_group_are_404);
    GREATEST_MAIN_END();
}
