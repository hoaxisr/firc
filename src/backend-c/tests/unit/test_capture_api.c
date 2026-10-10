#include "greatest.h"

#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "fake_iptables.h"
#include "fake_nflog.h"
#include "firc/capture.h"
#include "firc/netfilter_cleaner.h"
#include "firc/staticfiles.h"
#include "firc/system.h"
#include "firc/taprules.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>

/* sun_path holds 108 bytes: a longer path is cut on the way in and two tests share a socket. */
static char g_sock_path[108];
static uint16_t g_tcp_port;
#define SOCK_PATH g_sock_path
#define TCP_PORT g_tcp_port
#define CAPTURE_PATH "/api/v1/system/capture"

typedef struct {
    firc_config_t cfg;
    firc_fakeip_t *pool;
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
    firc_app_t *app;
    firc_loop_t *loop;
    firc_httpd_t *unix_srv;
    firc_httpd_t *tcp;
    firc_capture_ctx_t ctx;
    firc_system_ctx_t system_ctx;
    firc_static_ctx_t static_ctx;
    pthread_t th;
} rig_t;

static fake_nflog_t *g_kernel[2];

static firc_nflog_t *tap_fake_open(uint16_t group, uint16_t copy_range) {
    int w = group == FIRC_TAP_GROUP_NEW ? 0 : 1;
    fake_nflog_stop(g_kernel[w]);
    int fd = -1;
    g_kernel[w] = fake_nflog_start(&fd);
    if (g_kernel[w] == NULL) { return NULL; }
    return firc_nflog_open_fd(fd, group, copy_range);
}

static void kernels_stop(void) {
    for (int w = 0; w < 2; w++) {
        fake_nflog_stop(g_kernel[w]);
        g_kernel[w] = NULL;
    }
}

static int64_t fixed_now(void *ud) {
    (void)ud;
    return 1000;
}

static void *loop_thread(void *ud) {
    firc_loop_run((firc_loop_t *)ud);
    return NULL;
}

#define RIG_STEP(cond, what)                                                                     \
    do {                                                                                         \
        if (!(cond)) {                                                                           \
            fprintf(stderr, "rig_up: %s\n", what);                                               \
            return false;                                                                        \
        }                                                                                        \
    } while (0)

static void next_socket(void) {
    static int nth = 0;
    nth++;
    snprintf(g_sock_path, sizeof(g_sock_path), "/tmp/firc_capture_api_test.%d.%d.sock",
             (int)getpid(), nth);
    g_tcp_port = (uint16_t)(18199 + nth);
}

static firc_nflog_t *tap_open_refused(uint16_t group, uint16_t copy_range) {
    (void)group;
    (void)copy_range;
    return NULL;
}

/* Binds, then turns the fd into /dev/null, which epoll refuses (EPERM). */
static firc_nflog_t *tap_open_unwatchable(uint16_t group, uint16_t copy_range) {
    firc_nflog_t *n = tap_fake_open(group, copy_range);
    if (n == NULL) { return NULL; }
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0 || dup2(null_fd, firc_nflog_fd(n)) < 0) { abort(); }
    close(null_fd);
    return n;
}

/* Replaces the settings' `link` with `n` copies of `names`, before the loop starts serving. */
static bool set_link(firc_app_config_t *cfg, const char *const *names, size_t n) {
    for (size_t i = 0; i < cfg->n_link; i++) { free(cfg->link[i]); }
    free(cfg->link);
    cfg->link = NULL;
    cfg->n_link = 0;
    if (n == 0) { return true; }
    cfg->link = calloc(n, sizeof(char *));
    if (cfg->link == NULL) { return false; }
    for (size_t i = 0; i < n; i++) {
        cfg->link[i] = strdup(names[i]);
        if (cfg->link[i] == NULL) { return false; }
        cfg->n_link = i + 1;
    }
    return true;
}

typedef struct {
    bool no_pool;
    bool set_link;
    const char *const *link;
    size_t n_link;
    firc_nflog_t *(*nflog_open)(uint16_t, uint16_t);
} rig_opts_t;

static bool rig_up_full(rig_t *r, const rig_opts_t *o) {
    next_socket();
    memset(r, 0, sizeof(*r));
    firc_config_init_defaults(&r->cfg);
    bool with_pool = !o->no_pool;
    if (o->set_link) { RIG_STEP(set_link(&r->cfg.app, o->link, o->n_link), "link"); }
    if (with_pool) {
        firc_fakeip_cfg_t pc = {0};
        pc.v4.base.len = 4; pc.v4.base.b[0] = 198; pc.v4.base.b[1] = 18;
        pc.v4.pool_cidr = 15; pc.v4.chunk_cidr = 24;
        pc.v6.base.len = 16; pc.v6.base.b[0] = 0xfd; pc.v6.base.b[1] = 0x37;
        pc.v6.pool_cidr = 48; pc.v6.chunk_cidr = 64;
        pc.max_names = 64; pc.idle_secs = 86400; pc.clamp_secs = 300;
        RIG_STEP(firc_fakeip_new(&pc, &r->pool) == FIRC_OK, "pool");
    }

    r->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    r->ipt = firc_ipt_new(firc_fake_ipt_as_executable(r->fake), firc_fake_ipt_as_xt(r->fake));
    firc_netfilter_register_base_chains(r->ipt, NULL);
    RIG_STEP(firc_loop_create(&r->loop) == FIRC_OK, "loop");

    firc_app_deps_t deps = {.cfg = &r->cfg,
                            .ipt4 = r->ipt,
                            .pool = r->pool,
                            .loop = r->loop,
                            .nflog_open = o->nflog_open != NULL ? o->nflog_open
                                                                : tap_fake_open};
    r->app = firc_app_create(&deps);
    RIG_STEP(r->app != NULL, "app");

    r->ctx.app = r->app;
    r->ctx.now = fixed_now;

    unlink(SOCK_PATH);
    RIG_STEP(firc_httpd_create(r->loop, &r->unix_srv) == FIRC_OK, "unix server");
    firc_capture_register_routes(r->unix_srv, &r->ctx);
    RIG_STEP(firc_httpd_listen_unix(r->unix_srv, SOCK_PATH) == FIRC_OK, "listen unix");

    RIG_STEP(firc_httpd_create(r->loop, &r->tcp) == FIRC_OK, "tcp server");
    r->system_ctx.app = r->app;
    firc_system_register_routes(r->tcp, &r->system_ctx);
    firc_capture_register_routes(r->tcp, &r->ctx);
    r->static_ctx.root = "/nonexistent";
    firc_httpd_set_not_found(r->tcp, firc_static_handler, &r->static_ctx);
    RIG_STEP(firc_httpd_listen_tcp(r->tcp, "127.0.0.1", TCP_PORT) == FIRC_OK, "listen tcp");

    return pthread_create(&r->th, NULL, loop_thread, r->loop) == 0;
}

static bool rig_up(rig_t *r) {
    static const rig_opts_t plain = {0};
    return rig_up_full(r, &plain);
}

static void rig_down(rig_t *r) {
    firc_loop_stop(r->loop);
    pthread_join(r->th, NULL);
    firc_httpd_destroy(r->unix_srv);
    firc_httpd_destroy(r->tcp);
    firc_app_destroy(r->app);
    kernels_stop();
    firc_ipt_free(r->ipt);
    firc_fakeip_free(r->pool);
    firc_loop_destroy(r->loop);
    firc_config_clear(&r->cfg);
    unlink(SOCK_PATH);
}

static int connect_unix(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa = {0};
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", SOCK_PATH);
    for (int i = 0; i < 100; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { return fd; }
        struct timespec ts = {0, 10000000};
        nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

static int connect_tcp(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(TCP_PORT);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    for (int i = 0; i < 100; i++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { return fd; }
        struct timespec ts = {0, 10000000};
        nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

/* One blocking request and response on `fd`. */
static int request_on(int fd, const char *method, const char *path, char *out, size_t cap) {
    if (fd < 0) { return -1; }
    char req[1024];
    int n = snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                     method, path);
    if (n < 0 || write(fd, req, (size_t)n) != n) {
        close(fd);
        return -1;
    }
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t total = 0;
    for (;;) {
        ssize_t got = read(fd, out + total, cap - 1 - total);
        if (got <= 0) { break; }
        total += (size_t)got;
        if (total >= cap - 1) { break; }
    }
    close(fd);
    out[total] = '\0';
    int code = 0;
    sscanf(out, "HTTP/1.1 %d", &code);
    return code;
}

static int req_unix(const char *method, const char *path, char *out, size_t cap) {
    return request_on(connect_unix(), method, path, out, cap);
}

static int req_tcp(const char *method, const char *path, char *out, size_t cap) {
    return request_on(connect_tcp(), method, path, out, cap);
}

/* The token out of a start's response body. */
static bool token_of(const char *resp, char *out, size_t cap) {
    const char *p = strstr(resp, "\"token\":\"");
    if (p == NULL) { return false; }
    p += strlen("\"token\":\"");
    const char *end = strchr(p, '"');
    if (end == NULL || (size_t)(end - p) >= cap) { return false; }
    memcpy(out, p, (size_t)(end - p));
    out[end - p] = '\0';
    return true;
}

static int stop_with(const char *token, char *out, size_t cap) {
    char path[128];
    if (snprintf(path, sizeof(path), CAPTURE_PATH "?token=%.64s", token) < 0) { return -1; }
    return req_unix("DELETE", path, out, cap);
}

static bool running(firc_app_t *app) {
    firc_capture_status_t st;
    firc_app_capture_status(app, &st);
    return st.running;
}

TEST a_capture_starts_and_answers_its_token(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096];

    ASSERT_EQ_FMT(200, req_unix("GET", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERTm("nothing runs to begin with", strstr(buf, "\"running\":false") != NULL);
    ASSERT_FALSEm("and a stopped capture has no deadline to show",
                  strstr(buf, "endsAt") != NULL || strstr(buf, "secondsLeft") != NULL);

    ASSERT_EQ_FMT(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERTm("the daemon runs it", running(r.app));
    ASSERTm("and says so", strstr(buf, "\"running\":true") != NULL);
    char token[64];
    ASSERTm("and hands the starter a token to stop it with", token_of(buf, token, sizeof(token)));
    ASSERT_EQ_FMTm("sixteen hex characters", (size_t)FIRC_TAP_TOKEN_CHARS, strlen(token), "%zu");

    uint16_t g = 0;
    uint32_t range = 0;
    ASSERT(g_kernel[0] != NULL && g_kernel[1] != NULL);
    ASSERT(fake_nflog_is_bound(g_kernel[0], &g));
    ASSERT_EQ_FMT(FIRC_TAP_GROUP_NEW, (int)g, "%d");
    ASSERT(fake_nflog_mode(g_kernel[0], NULL, &range));
    ASSERT_EQ_FMT(FIRC_TAP_HEAD_RANGE, range, "%u");
    ASSERT(fake_nflog_is_bound(g_kernel[1], &g));
    ASSERT_EQ_FMT(FIRC_TAP_GROUP_HELLO, (int)g, "%d");
    ASSERT(fake_nflog_mode(g_kernel[1], NULL, &range));
    ASSERT_EQ_FMT((uint32_t)FIRC_TAP_COPY_RANGE, range, "%u");

    ASSERT_EQ_FMT(200, stop_with(token, buf, sizeof(buf)), "%d");
    ASSERT_FALSEm("and the token stops it", running(r.app));
    ASSERTm("the stop answers the status", strstr(buf, "\"running\":false") != NULL);
    rig_down(&r);
    PASS();
}

TEST a_second_start_is_refused_while_one_runs(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096], token[64], second[4096];
    ASSERT_EQ_FMT(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERT(token_of(buf, token, sizeof(token)));

    ASSERT_EQ_FMTm("refused, not taken over", 409,
                   req_unix("POST", CAPTURE_PATH, second, sizeof(second)), "%d");
    ASSERT_FALSEm("and the refusal hands out no token", strstr(second, "\"token\"") != NULL);
    ASSERT_EQ_FMT(200, stop_with(token, buf, sizeof(buf)), "%d");
    ASSERT_FALSE(running(r.app));
    ASSERT_EQ_FMT(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    rig_down(&r);
    PASS();
}

/* Catches: a request body that changes the capture's five-minute length. */
TEST a_capture_is_five_minutes(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096];
    int fd = connect_unix();
    ASSERT(fd >= 0);
    static const char req[] = "POST " CAPTURE_PATH " HTTP/1.1\r\nHost: x\r\nContent-Type: "
                              "application/json\r\nContent-Length: 16\r\nConnection: "
                              "close\r\n\r\n{\"seconds\":9999}";
    ASSERT_EQ((ssize_t)(sizeof(req) - 1), write(fd, req, sizeof(req) - 1));
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t total = 0;
    for (ssize_t got; (got = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0;) {
        total += (size_t)got;
    }
    close(fd);
    buf[total] = '\0';
    ASSERTm("started", strstr(buf, "HTTP/1.1 200") == buf);
    ASSERTm("it ends five minutes after it started", strstr(buf, "\"endsAt\":1300") != NULL);
    ASSERTm("and has all five of them left", strstr(buf, "\"secondsLeft\":300") != NULL);
    rig_down(&r);
    PASS();
}

TEST stopping_needs_the_token(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096];
    ASSERT_EQ_FMT(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERT_EQ_FMTm("a stop with no token is refused", 400,
                   req_unix("DELETE", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERTm("and the capture runs on", running(r.app));
    rig_down(&r);
    PASS();
}

/* Catches: a stop without the starter's token ending the capture. */
TEST another_clients_stop_does_not_end_it(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096], token[64];
    ASSERT_EQ_FMT(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERT(token_of(buf, token, sizeof(token)));

    char wrong[64];
    snprintf(wrong, sizeof(wrong), "%s", token);
    size_t last = strlen(wrong) - 1;
    wrong[last] = (char)(wrong[last] == 'f' ? 'e' : wrong[last] + 1);
    ASSERT_EQ_FMTm("one character out is not this capture's token", 409,
                   stop_with(wrong, buf, sizeof(buf)), "%d");
    char half[64];
    snprintf(half, sizeof(half), "%.8s", token);
    ASSERT_EQ_FMTm("half the token is not the token", 409, stop_with(half, buf, sizeof(buf)),
                   "%d");
    ASSERTm("neither of those stopped it", running(r.app));

    ASSERT_EQ_FMT(200, stop_with(token, buf, sizeof(buf)), "%d");
    ASSERT_FALSE(running(r.app));

    ASSERT_EQ_FMT(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    char second[64];
    ASSERT(token_of(buf, second, sizeof(second)));
    ASSERTm("two captures, two tokens", strcmp(token, second) != 0);
    ASSERT_EQ_FMTm("the previous capture's token is not this one's", 409,
                   stop_with(token, buf, sizeof(buf)), "%d");
    ASSERT(running(r.app));
    rig_down(&r);
    PASS();
}

/* Catches: a token with a position that carries no randomness. */
TEST every_place_in_the_token_is_random(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096];
    enum { ROUNDS = 8 };
    char seen[ROUNDS][64];
    for (int i = 0; i < ROUNDS; i++) {
        ASSERT_EQ(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)));
        ASSERT(token_of(buf, seen[i], sizeof(seen[i])));
        ASSERT_EQ(200, stop_with(seen[i], buf, sizeof(buf)));
    }
    for (size_t pos = 0; pos < FIRC_TAP_TOKEN_CHARS; pos++) {
        bool varies = false;
        for (int i = 1; i < ROUNDS && !varies; i++) { varies = seen[i][pos] != seen[0][pos]; }
        char why[64];
        snprintf(why, sizeof(why), "character %zu was '%c' in all %d tokens", pos, seen[0][pos],
                 ROUNDS);
        ASSERTm(why, varies);
    }
    rig_down(&r);
    PASS();
}

/* Catches: a stop with no capture running answered as an error. */
TEST stopping_nothing_is_not_an_error(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096];
    ASSERT_EQ_FMT(200, stop_with("0123456789abcdef", buf, sizeof(buf)), "%d");
    ASSERTm("and it says nothing runs", strstr(buf, "\"running\":false") != NULL);
    rig_down(&r);
    PASS();
}

/* Catches: a capture with no LAN interface, or a bad name, not a 400, or binding anything. */
TEST no_lan_interface_is_refused(void) {
    char buf[4096];
    static const char *const bad[] = {"br0\n-j ACCEPT"};
    const rig_opts_t cases[] = {
        {.set_link = true, .link = NULL, .n_link = 0},
        {.set_link = true, .link = bad, .n_link = 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rig_t r;
        ASSERT(rig_up_full(&r, &cases[i]));
        int code = req_unix("POST", CAPTURE_PATH, buf, sizeof(buf));
        ASSERT_EQ_FMTm(i == 0 ? "an empty link list" : "a name that is not an interface name",
                       400, code, "%d");
        ASSERTm("says which setting", strstr(buf, "link") != NULL);
        ASSERT_FALSE(running(r.app));
        ASSERT_FALSEm("no NFLOG group was bound", g_kernel[0] != NULL || g_kernel[1] != NULL);
        rig_down(&r);
    }

    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT_EQ_FMT(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    rig_down(&r);
    PASS();
}

/* Catches: a capture without a pool refused without saying the pool is missing. */
TEST a_daemon_with_no_pool_says_so(void) {
    rig_t r;
    static const rig_opts_t no_pool = {.no_pool = true};
    ASSERT(rig_up_full(&r, &no_pool));
    char buf[4096];
    ASSERT_EQ_FMTm("not 500: the operator can act on this one", 503,
                   req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERTm("and it names the pool", strstr(buf, "pool") != NULL);
    ASSERT_FALSE(running(r.app));
    rig_down(&r);
    PASS();
}

/* Catches: an NFLOG group that cannot be bound not a 503 naming NFLOG. */
TEST a_group_that_cannot_be_bound_says_so(void) {
    rig_t r;
    static const rig_opts_t refused = {.nflog_open = tap_open_refused};
    ASSERT(rig_up_full(&r, &refused));
    char buf[4096];
    ASSERT_EQ_FMT(503, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERTm("it names NFLOG", strstr(buf, "NFLOG") != NULL);
    ASSERTm("and the bind", strstr(buf, "bind") != NULL);
    ASSERT_FALSEm("and not the pool", strstr(buf, "pool") != NULL);
    ASSERT_FALSE(running(r.app));
    rig_down(&r);
    PASS();
}

/* Catches: a 503 that blames only the bind when the loop refused to watch the socket. */
TEST a_socket_the_loop_will_not_watch_is_named_in_the_503(void) {
    rig_t r;
    static const rig_opts_t unwatchable = {.nflog_open = tap_open_unwatchable};
    ASSERT(rig_up_full(&r, &unwatchable));
    char buf[4096];
    ASSERT_EQ_FMT(503, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERTm(buf, strstr(buf, "event loop would not watch") != NULL);
    ASSERTm(buf, strstr(buf, "the daemon's log says which") != NULL);
    ASSERT_FALSE(running(r.app));
    rig_down(&r);
    PASS();
}

/* Catches: a kernel refusing the capture rules not a 501 naming every module they need. */
TEST a_kernel_that_refuses_the_rules_is_named(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_fake_ipt_refuse_rules_containing(r.fake, "-m string");
    char buf[4096];
    ASSERT_EQ_FMT(501, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERTm("and names every module the rules need", strstr(buf, FIRC_TAP_LAN_MODULES) != NULL);
    ASSERT_FALSE(running(r.app));

    firc_fake_ipt_refuse_rules_containing(r.fake, NULL);
    ASSERT_EQ_FMT(200, req_unix("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    rig_down(&r);
    PASS();
}

/* Catches: the status missing how long is left, or carrying the token. */
TEST the_status_says_how_long_is_left(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096], token[64];
    ASSERT_EQ_FMT(200, req_tcp("POST", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERT(token_of(buf, token, sizeof(token)));

    ASSERT_EQ_FMT(200, req_tcp("GET", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERTm("it runs", strstr(buf, "\"running\":true") != NULL);
    ASSERTm("until when", strstr(buf, "\"endsAt\":1300") != NULL);
    /* A range, never tighten to 300: the monotonic clock truncates, so a read across a second gives 299. */
    ASSERTm("and how long it has left", strstr(buf, "\"secondsLeft\":300") != NULL ||
                                            strstr(buf, "\"secondsLeft\":299") != NULL);
    ASSERT_FALSEm("no token in the status", strstr(buf, "token") != NULL);

    char path[128];
    snprintf(path, sizeof(path), CAPTURE_PATH "?token=%s", token);
    ASSERT_EQ_FMT(200, req_tcp("DELETE", path, buf, sizeof(buf)), "%d");
    ASSERT_FALSE(running(r.app));
    rig_down(&r);
    PASS();
}

#define OLD_WINDOW_PATH "/api/v1/system/bypass"
TEST the_bypass_route_is_gone(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[4096];
    ASSERT_EQ_FMT(200, req_tcp("GET", CAPTURE_PATH, buf, sizeof(buf)), "%d");
    ASSERT_EQ_FMT(404, req_tcp("GET", OLD_WINDOW_PATH, buf, sizeof(buf)), "%d");
    ASSERT_EQ_FMT(404, req_tcp("POST", OLD_WINDOW_PATH, buf, sizeof(buf)), "%d");
    ASSERT_FALSE(running(r.app));
    rig_down(&r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_capture_starts_and_answers_its_token);
    RUN_TEST(a_second_start_is_refused_while_one_runs);
    RUN_TEST(a_capture_is_five_minutes);
    RUN_TEST(stopping_needs_the_token);
    RUN_TEST(another_clients_stop_does_not_end_it);
    RUN_TEST(every_place_in_the_token_is_random);
    RUN_TEST(stopping_nothing_is_not_an_error);
    RUN_TEST(no_lan_interface_is_refused);
    RUN_TEST(a_daemon_with_no_pool_says_so);
    RUN_TEST(a_group_that_cannot_be_bound_says_so);
    RUN_TEST(a_socket_the_loop_will_not_watch_is_named_in_the_503);
    RUN_TEST(a_kernel_that_refuses_the_rules_is_named);
    RUN_TEST(the_status_says_how_long_is_left);
    RUN_TEST(the_bypass_route_is_gone);
    GREATEST_MAIN_END();
}
