#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier): pipe2() */
#include "greatest.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "firc/events.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/tunaddr.h"
#include "firc/tunsup.h"

#define FAKE "tests/unit/fixtures/fake_tunvless.sh"
#define BIG_N 300
#define BIG_LEN 3000

static char g_dir[64];
static char g_argv[128];
static char g_stdin[128];
static char g_starts[128];
static char g_log[128];
static char g_fds[128];
static char g_path[1024];

typedef struct rec {
    firc_tunsup_t *s;
    firc_loop_t *loop;
    int backoffs[64];
    int n_backoffs;
    int want_backoffs;
    int want_starts;
    char starting[8][16];
    int n_starting;
    int ticks;
    int64_t stop_elapsed_ms;
    const firc_tunnels_t *next;
    const uint32_t *next_marks;
    firc_err_t apply_rc;
    char snap_starts[1024];
    firc_tun_state_t snap[4];
    size_t n_snap;
    const firc_tunnels_t *off;
    firc_tun_status_t seen[2];
    int n_off;
    int n_ev;
    uint64_t seq_before;
    uint64_t started_after;
    const firc_tunnels_t *next2;
    int down_pos[16];
    int n_down;
    int act_pos[8];
    size_t n_act;
    firc_err_t cmd_rc;
    firc_err_t cmd_rc2;
    bool in_turn;
    int map_count[8];
    int map_expect[8];
    bool map_drift[8];
    int n_map;
    char up_hist[16][64];
    int n_up_hist;
    const char *up_on;
    int n_ready;
    int n_nn;
    int n_nup;
    uint64_t seq_seen[2];
    int64_t at[2][8];
    int n_at[2];
    int want_k;
    int want_at;
    bool (*cond)(const struct rec *r);
} rec_t;

static rec_t *g_open;
static int g_log_fd = -1;

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void env_setup(const char *mode)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/firc_tunsup_XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        abort();
    }
    snprintf(g_argv, sizeof g_argv, "%s/argv", g_dir);
    snprintf(g_stdin, sizeof g_stdin, "%s/stdin", g_dir);
    snprintf(g_starts, sizeof g_starts, "%s/starts", g_dir);
    snprintf(g_log, sizeof g_log, "%s/log", g_dir);
    snprintf(g_fds, sizeof g_fds, "%s/fds", g_dir);
    setenv("FAKE_FDS_OUT", g_fds, 1);
    unsetenv("FAKE_STUBBORN_DEV");
    unsetenv("FAKE_RESET");
    setenv("FAKE_ARGV_OUT", g_argv, 1);
    setenv("FAKE_STDIN_OUT", g_stdin, 1);
    setenv("FAKE_STARTS_OUT", g_starts, 1);
    setenv("FAKE_MODE", mode, 1);
    unsetenv("FAKE_SLEEP");
    unsetenv("FAKE_INBOUNDS_COUNT");
    unsetenv("FAKE_NOACK");
    unsetenv("FAKE_EVENTS");
    unsetenv("FAKE_AFTER");
    unsetenv("FAKE_ACK_COUNT");
    unsetenv("FAKE_MAPCOUNT");
    unsetenv("FAKE_MISS");
    unsetenv("FAKE_CLOSED");
    unsetenv("FAKE_TCPPORT");
    unsetenv("FAKE_STDIN_DIR");
    for (int i = 1; i <= 8; i++) {
        char name[16];
        snprintf(name, sizeof name, "FAKE_RUN_%d", i);
        unsetenv(name);
    }
}

static void env_teardown(void)
{
    if (g_dir[0] == 0) {
        return;
    }
    unlink(g_fds);
    unlink(g_argv);
    unlink(g_stdin);
    unlink(g_starts);
    unlink(g_log);
    rmdir(g_dir);
    g_dir[0] = 0;
}

static bool journal_has(firc_log_level_t level, const char *source, const char *text)
{
    static firc_event_t ev[256];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, 256, &next, &dropped);
    for (size_t i = 0; i < n; i++) {
        if (ev[i].kind == FIRC_EVENT_LOG && ev[i].u.log.level == level && strcmp(ev[i].u.log.source, source) == 0 &&
            strcmp(ev[i].u.log.text, text) == 0) {
            return true;
        }
    }
    return false;
}

static size_t read_file(const char *path, char *buf, size_t cap)
{
    buf[0] = 0;
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = 0;
    fclose(f);
    return n;
}

static int count_starts(const char *text, const char *device)
{
    int n = 0;
    size_t dl = strlen(device);
    for (const char *p = text; *p != 0;) {
        if (strncmp(p, device, dl) == 0 && p[dl] == ' ') {
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

static pid_t nth_pid(const char *text, const char *device, int nth)
{
    size_t dl = strlen(device);
    int seen = 0;
    for (const char *p = text; *p != 0;) {
        if (strncmp(p, device, dl) == 0 && p[dl] == ' ') {
            if (seen == nth) {
                return (pid_t)atoi(p + dl + 1);
            }
            seen++;
        }
        const char *nl = strchr(p, '\n');
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    return -1;
}

static bool gone(pid_t pid)
{
    return pid > 0 && kill(pid, 0) == -1 && errno == ESRCH;
}

static bool no_children(void)
{
    errno = 0;
    return waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD;
}

static firc_tun_src_t g_src[8192];
static size_t g_src_used;

static void tun_init(firc_tunnel_t *t, const char *id, int n, char **links, size_t n_links)
{
    if (g_src_used + n_links > sizeof g_src / sizeof *g_src) {
        g_src_used = 0;
    }
    firc_tun_src_t *src = &g_src[g_src_used];
    g_src_used += n_links;
    for (size_t i = 0; i < n_links; i++) {
        memset(&src[i], 0, sizeof src[i]);
        src[i].kind = FIRC_TUN_SRC_LINK;
        src[i].link = links[i];
    }
    memset(t, 0, sizeof *t);
    snprintf(t->id, sizeof t->id, "%s", id);
    snprintf(t->device, sizeof t->device, "tunvless%d", n);
    t->enable = true;
    t->uplink = FIRC_UPLINK_AUTO;
    t->src = src;
    t->n_src = n_links;
    t->active = 1;
    snprintf(t->by, sizeof t->by, "latency");
    t->interval_s = 30;
    t->silence_s = 10;
    t->timeout_s = 5;
}

static void on_event(const firc_tun_state_t *st, const firc_tev_t *ev, void *ud)
{
    rec_t *r = ud;
    if (st->status == FIRC_TUN_ST_UP && r->n_up_hist < 16) {
        char *h = r->up_hist[r->n_up_hist++];
        h[0] = 0;
        for (size_t i = 0; i < st->n_active && i < 8; i++) {
            snprintf(h + strlen(h), 64 - strlen(h), "%s%s", i > 0 ? "," : "", st->active[i]);
        }
    }
    if (ev != NULL) {
        r->n_ev++;
        r->n_ready += ev->kind == FIRC_TEV_READY ? 1 : 0;
        r->n_nn += ev->kind == FIRC_TEV_NO_NODE ? 1 : 0;
        r->n_nup += ev->kind == FIRC_TEV_NODE_UP ? 1 : 0;
        if (ev->kind == FIRC_TEV_NODE_DOWN && r->n_down < 16) {
            r->down_pos[r->n_down++] = ev->pos;
        }
        if (ev->kind == FIRC_TEV_MAP && r->n_map < 8) {
            r->map_count[r->n_map] = ev->count;
            r->map_expect[r->n_map] = ev->expect;
            r->map_drift[r->n_map] = ev->drift;
            r->n_map++;
        }
        if (ev->kind == FIRC_TEV_ACTIVE) {
            r->n_act = ev->n_active;
            for (size_t i = 0; i < ev->n_active && i < 8; i++) {
                r->act_pos[i] = ev->active_pos[i];
            }
        }
        return;
    }
    if (st->status == FIRC_TUN_ST_OFF) {
        r->n_off++;
    }
    if (st->status == FIRC_TUN_ST_BACKOFF && r->n_backoffs < 64) {
        r->backoffs[r->n_backoffs++] = st->backoff_s;
        if (st->backoff_s == 6 && getenv("FAKE_RESET") != NULL) {
            setenv("FAKE_MODE", "late", 1);
            setenv("FAKE_SLEEP", "1", 1);
        }
    }
    if (st->status == FIRC_TUN_ST_STARTING && r->n_starting < 8) {
        snprintf(r->starting[r->n_starting++], 16, "%s", st->device);
    }
}

static void stop_cb(firc_loop_t *loop, void *ud)
{
    (void)ud;
    firc_loop_stop(loop);
}

static void tick_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    ((rec_t *)ud)->ticks++;
}

static void apply_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->seq_before = firc_tunsup_start_seq(r->s);
    r->apply_rc = firc_tunsup_apply(r->s, r->next, r->next_marks);
}

static void apply2_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->apply_rc = firc_tunsup_apply(r->s, r->next2, NULL);
    r->started_after = firc_tunsup_started(r->s, "a");
}

static void snap_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    read_file(g_starts, r->snap_starts, sizeof r->snap_starts);
    r->n_snap = firc_tunsup_states(r->s, r->snap, 4);
}

static void stop_sup_cb(firc_loop_t *loop, void *ud)
{
    rec_t *r = ud;
    int64_t t0 = now_ms();
    firc_tunsup_stop(r->s, 1000);
    r->stop_elapsed_ms = now_ms() - t0;
    firc_loop_stop(loop);
}

static void rec_open(rec_t *r)
{
    memset(r, 0, sizeof *r);
    if (firc_loop_create(&r->loop) != FIRC_OK) {
        abort();
    }
    r->s = firc_tunsup_new(r->loop, FAKE, on_event, r);
    g_open = r;
}

static void run_ms(rec_t *r, uint64_t ms)
{
    int id = 0;
    firc_loop_add_timer(r->loop, ms, 0, stop_cb, NULL, &id);
    firc_loop_run(r->loop);
    firc_loop_del_timer(r->loop, id);
}

static void enough_backoffs_cb(firc_loop_t *loop, void *ud)
{
    if (((rec_t *)ud)->n_backoffs >= ((rec_t *)ud)->want_backoffs) {
        firc_loop_stop(loop);
    }
}

static void run_until_backoffs(rec_t *r, int n, uint64_t deadline_ms)
{
    r->want_backoffs = n;
    int id = 0;
    firc_loop_add_timer(r->loop, 10, 10, enough_backoffs_cb, r, &id);
    run_ms(r, deadline_ms);
    firc_loop_del_timer(r->loop, id);
}

static void enough_starts_cb(firc_loop_t *loop, void *ud)
{
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    if (count_starts(buf, "tunvless0") >= ((rec_t *)ud)->want_starts) {
        firc_loop_stop(loop);
    }
}

static void run_until_starts(rec_t *r, int n, uint64_t deadline_ms)
{
    r->want_starts = n;
    int id = 0;
    firc_loop_add_timer(r->loop, 10, 10, enough_starts_cb, r, &id);
    run_ms(r, deadline_ms);
    firc_loop_del_timer(r->loop, id);
}

static void rec_close(rec_t *r)
{
    if (r->s != NULL) {
        firc_tunsup_stop(r->s, 1000);
        firc_tunsup_free(r->s);
        r->s = NULL;
    }
    if (r->loop != NULL) {
        firc_loop_destroy(r->loop);
        r->loop = NULL;
    }
    if (g_open == r) {
        g_open = NULL;
    }
}

static void teardown(void *ud)
{
    (void)ud;
    alarm(0);
    firc_tun_addr_set_ifaddrs_for_test(NULL, 0);
    if (g_open != NULL) {
        rec_close(g_open);
    }
    if (g_log_fd >= 0) {
        firc_log_set_fd(STDOUT_FILENO);
        close(g_log_fd);
        g_log_fd = -1;
    }
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
    env_teardown();
}

static void log_to_file(void)
{
    g_log_fd = open(g_log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    firc_log_set_fd(g_log_fd);
}

static void log_done(void)
{
    firc_log_set_fd(STDOUT_FILENO);
    close(g_log_fd);
    g_log_fd = -1;
}

static int count_of(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = strstr(hay, needle); p != NULL; p = strstr(p + 1, needle)) {
        n++;
    }
    return n;
}

static firc_tun_state_t state_of(const firc_tunsup_t *s, const char *id)
{
    firc_tun_state_t st[8];
    firc_tun_state_t none;
    memset(&none, 0, sizeof none);
    none.status = (firc_tun_status_t)-1;
    size_t n = firc_tunsup_states(s, st, 8);
    for (size_t i = 0; i < n && i < 8; i++) {
        if (strcmp(st[i].id, id) == 0) {
            return st[i];
        }
    }
    return none;
}

static char **big_links(void)
{
    char **l = calloc(BIG_N, sizeof *l);
    for (int i = 0; i < BIG_N; i++) {
        l[i] = malloc(BIG_LEN + 1);
        memcpy(l[i], "vless://", 8);
        memset(l[i] + 8, 'a' + i % 26, BIG_LEN - 8);
        l[i][BIG_LEN] = 0;
    }
    return l;
}

static void free_links(char **l)
{
    for (int i = 0; i < BIG_N; i++) {
        free(l[i]);
    }
    free(l);
}

TEST ok_child_up_links_on_stdin(void)
{
    /* catches: links not delivered on stdin, or the list not ended by an empty line */
    env_setup("ok");
    char *links[] = {"vless://u1@h1:443?type=tcp#one", "vless://u2@h2:443?type=tcp#two"};
    firc_tunnel_t t;
    tun_init(&t, "a", 3, links, 2);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT(r.s != NULL);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 1000);
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_STR_EQ("tunvless3", st.device);
    ASSERT_EQ(1, st.n_active);
    ASSERT_STR_EQ("A", st.active[0]);
    ASSERT(st.uplink_ok);
    char buf[256];
    read_file(g_stdin, buf, sizeof buf);
    ASSERT_STR_EQ("vless://u1@h1:443?type=tcp#one\nvless://u2@h2:443?type=tcp#two\n\n", buf);
    ASSERT_EQ(0, r.n_off);
    firc_tunsup_stop(r.s, 1000);
    ASSERT_EQ(1, r.n_off);
    ASSERT_EQ(FIRC_TUN_ST_OFF, state_of(r.s, "a").status);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST argv_full_and_no_link(void)
{
    /* catches: a wrong flag, address or mark format, --fp missing, or a link on the command line */
    env_setup("ok");
    char *links[] = {"vless://secret@h1:443#one"};
    firc_tunnel_t t;
    tun_init(&t, "a", 3, links, 1);
    t.active = 2;
    t.interval_s = 45;
    t.silence_s = 12;
    t.timeout_s = 7;
    t.insecure = true;
    snprintf(t.ca, sizeof t.ca, "/opt/etc/ca.pem");
    snprintf(t.fingerprint, sizeof t.fingerprint, "firefox");
    firc_tunnels_t set = {.t = &t, .n = 1};
    uint32_t marks[] = {0x1a};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, marks));
    run_ms(&r, 700);
    char buf[512];
    read_file(g_argv, buf, sizeof buf);
    ASSERT_STR_EQ("--control\n-d\ntunvless3\n-a\n203.0.113.4/32\n-A\n2\n--by\nlatency\n--interval\n45\n"
                  "--silence\n12\n-t\n7\n-m\n0x1a\n--insecure\n--ca\n/opt/etc/ca.pem\n--fp\nfirefox\n",
                  buf);
    ASSERT(strstr(buf, "vless://") == NULL);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST argv_with_every_option_set(void)
{
    /* catches: an option dropped or reordered when all are set, or an argv array one slot short under sanitize */
    env_setup("ok");
    char *links[] = {"vless://secret@h1:443#one"};
    firc_tunnel_t t;
    tun_init(&t, "a", 3, links, 1);
    t.active = 2;
    t.insecure = true;
    t.kernel_tcp = true;
    snprintf(t.ca, sizeof t.ca, "/opt/etc/ca.pem");
    snprintf(t.fingerprint, sizeof t.fingerprint, "chrome");
    firc_tunnels_t set = {.t = &t, .n = 1};
    uint32_t marks[] = {0x1a};
    static rec_t r;
    rec_open(&r);
    const uint8_t pool[4] = {198, 18, 0, 0};
    firc_tunsup_set_tcp_pool(r.s, pool, 15);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, marks));
    run_ms(&r, 700);
    char buf[512];
    read_file(g_argv, buf, sizeof buf);
    ASSERT_STR_EQ("--control\n-d\ntunvless3\n-a\n203.0.113.4/32\n-A\n2\n--by\nlatency\n--interval\n30\n"
                  "--silence\n10\n-t\n5\n-m\n0x1a\n--insecure\n--ca\n/opt/etc/ca.pem\n--fp\nchrome\n"
                  "--tcp-port\n3603\n--tcp-pool\n198.18.0.0/15\n",
                  buf);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST argv_minimal_without_options(void)
{
    /* catches: -m, --insecure, --ca or --fp passed when not set */
    env_setup("ok");
    char *links[] = {"vless://secret@h1:443#one"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    uint32_t marks[] = {0};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, marks));
    run_ms(&r, 700);
    char buf[512];
    read_file(g_argv, buf, sizeof buf);
    ASSERT_STR_EQ("--control\n-d\ntunvless0\n-a\n203.0.113.1/32\n-A\n1\n--by\nlatency\n--interval\n30\n"
                  "--silence\n10\n-t\n5\n",
                  buf);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_kernel_tcp_tunnel_is_spawned_with_its_port_and_pool(void)
{
    /* catches: --tcp-port or --tcp-pool missing, a wrong port, or a wrong pool text */
    env_setup("ok");
    char *links[] = {"vless://secret@h1:443#one"};
    firc_tunnel_t t;
    tun_init(&t, "a", 7, links, 1);
    t.kernel_tcp = true;
    firc_tunnels_t set = {.t = &t, .n = 1};
    uint32_t marks[] = {0};
    static rec_t r;
    rec_open(&r);
    const uint8_t pool[4] = {198, 18, 0, 0};
    firc_tunsup_set_tcp_pool(r.s, pool, 15);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, marks));
    run_ms(&r, 700);
    char buf[512];
    read_file(g_argv, buf, sizeof buf);
    ASSERT_STR_EQ("--control\n-d\ntunvless7\n-a\n203.0.113.8/32\n-A\n1\n--by\nlatency\n--interval\n30\n"
                  "--silence\n10\n-t\n5\n--tcp-port\n3607\n--tcp-pool\n198.18.0.0/15\n",
                  buf);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_kernel_tcp_tunnel_without_a_pool_gets_only_its_port(void)
{
    /* catches: a --tcp-pool with an unset pool passed to the child */
    env_setup("ok");
    char *links[] = {"vless://secret@h1:443#one"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    t.kernel_tcp = true;
    firc_tunnels_t set = {.t = &t, .n = 1};
    uint32_t marks[] = {0};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, marks));
    run_ms(&r, 700);
    char buf[512];
    read_file(g_argv, buf, sizeof buf);
    ASSERT_STR_EQ("--control\n-d\ntunvless0\n-a\n203.0.113.1/32\n-A\n1\n--by\nlatency\n--interval\n30\n"
                  "--silence\n10\n-t\n5\n--tcp-port\n3600\n",
                  buf);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST stderr_logged_by_level_without_links(void)
{
    /* catches: child stderr dropped, logged at the wrong level, or a link in the log */
    env_setup("ok");
    log_to_file();
    ASSERT(g_log_fd >= 0);
    char *links[] = {"vless://secret@h1:443#one"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 700);
    rec_close(&r);
    setenv("FAKE_MODE", "badconf", 1);
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 700);
    rec_close(&r);
    log_done();
    char buf[8192];
    read_file(g_log, buf, sizeof buf);
    ASSERT(strstr(buf, "INF tunvless0: up\n") != NULL);
    ASSERT(strstr(buf, "WRN tunvless0: bad option\n") != NULL);
    ASSERT(strstr(buf, "vless://") == NULL);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST crash_restarts_with_growing_backoff(void)
{
    /* catches: no restart after a crash, a backoff that does not double, or the exit journalled as fircd's */
    env_setup("crash");
    firc_event_reset_for_test();
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 4000);
    char buf[256];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_BACKOFF, st.status);
    ASSERT_EQ(6, st.backoff_s);
    ASSERT_EQ(1, st.last_exit);
    ASSERT_EQ(2, r.n_backoffs);
    ASSERT_EQ(3, r.backoffs[0]);
    ASSERT_EQ(6, r.backoffs[1]);
    ASSERT(journal_has(FIRC_LOG_WARN, "tunvless0", "exited (1), restart in 3 s"));
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static int journal_count_from(firc_log_level_t level, const char *source, const char *prefix)
{
    static firc_event_t ev[512];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, 512, &next, &dropped);
    int c = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].kind == FIRC_EVENT_LOG && ev[i].u.log.level == level && strcmp(ev[i].u.log.source, source) == 0 &&
            strncmp(ev[i].u.log.text, prefix, strlen(prefix)) == 0) {
            c++;
        }
    }
    return c;
}

/* Catches: a crash-looping child warned at every restart, so one tunnel fills the warning ring. */
TEST twenty_restarts_leave_one_warning(void)
{
    env_setup("crash");
    firc_event_reset_for_test();
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 1);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    char buf[4096];
    for (int i = 0; i < 100; i++) {
        run_ms(&r, 50);
        read_file(g_starts, buf, sizeof buf);
        if (count_starts(buf, "tunvless0") >= 21) { break; }
    }
    ASSERT(count_starts(buf, "tunvless0") >= 21);
    rec_close(&r);
    ASSERT_EQ(1, journal_count_from(FIRC_LOG_WARN, "tunvless0", "exited (1), restart in "));
    ASSERT(journal_count_from(FIRC_LOG_DEBUG, "tunvless0", "exited (1), restart in ") >= 19);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST backoff_doubles_up_to_sixty(void)
{
    /* catches: a backoff that keeps doubling past 60 s or skips a step */
    env_setup("crash");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 10);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_until_backoffs(&r, 8, 10000);
    ASSERT(r.n_backoffs >= 8);
    const int want[] = {3, 6, 12, 24, 48, 60, 60, 60};
    for (int i = 0; i < 8; i++) {
        ASSERT_EQ(want[i], r.backoffs[i]);
    }
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST backoff_resets_after_stable_run(void)
{
    /* catches: the backoff not reset after a child that stayed up 60 s */
    env_setup("crash");
    setenv("FAKE_RESET", "1", 1);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 10);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_until_backoffs(&r, 3, 10000);
    unsetenv("FAKE_RESET");
    ASSERT(r.n_backoffs >= 3);
    ASSERT_EQ(3, r.backoffs[0]);
    ASSERT_EQ(6, r.backoffs[1]);
    ASSERT_EQ(3, r.backoffs[2]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST badconf_not_restarted(void)
{
    /* Catches: a tight restart loop on a config error, or the stop it needs the operator for said below ERROR. */
    env_setup("badconf");
    firc_event_reset_for_test();
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 10);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 1000);
    char buf[256];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(1, count_starts(buf, "tunvless0"));
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_BAD_CONFIG, st.status);
    ASSERT_EQ(2, st.last_exit);
    ASSERT(journal_has(FIRC_LOG_ERROR, "tunvless0", "configuration refused, not restarted"));
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST flood_line_dropped_loop_responsive(void)
{
    /* catches: an oversize line blocking or crashing the supervisor */
    env_setup("flood");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    firc_loop_add_timer(r.loop, 10, 10, tick_cb, &r, NULL);
    run_ms(&r, 1000);
    ASSERT(r.ticks >= 50);
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_EQ(1, st.n_active);
    ASSERT_STR_EQ("B", st.active[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST noread_child_never_blocks_loop(void)
{
    /* catches: a blocking write to a child that does not read its stdin */
    env_setup("noread");
    alarm(20);
    char **links = big_links();
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, BIG_N);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    firc_loop_add_timer(r.loop, 10, 10, tick_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 1000, 0, stop_sup_cb, &r, NULL);
    firc_loop_run(r.loop);
    alarm(0);
    ASSERT(r.ticks >= 50);
    ASSERT(r.stop_elapsed_ms <= 1200);
    ASSERT(no_children());
    rec_close(&r);
    free_links(links);
    env_teardown();
    PASS();
}

TEST closed_stdin_counts_as_failed_start(void)
{
    /* catches: EPIPE on the node list ignored, leaving a child without nodes running */
    env_setup("closein");
    char **links = big_links();
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, BIG_N);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 1000);
    char buf[256];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(1, count_starts(buf, "tunvless0"));
    ASSERT(gone(nth_pid(buf, "tunvless0", 0)));
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_BACKOFF, st.status);
    ASSERT_EQ(3, st.backoff_s);
    rec_close(&r);
    free_links(links);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST stop_kills_child_ignoring_term(void)
{
    /* catches: stop never escalating to SIGKILL, or not waiting the grace first */
    env_setup("stubborn");
    alarm(20);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 500);
    int64_t t0 = now_ms();
    firc_tunsup_stop(r.s, 300);
    int64_t el = now_ms() - t0;
    alarm(0);
    ASSERT(el >= 300);
    ASSERT(el <= 550);
    ASSERT(no_children());
    rec_close(&r);
    env_teardown();
    PASS();
}

TEST apply_unchanged_keeps_child(void)
{
    /* catches: every apply restarting every tunnel */
    env_setup("ok");
    char *links[] = {"vless://u@h:443#x"};
    char *links2[] = {strdup("vless://u@h:443#x")};
    firc_tunnel_t t, t2;
    tun_init(&t, "a", 0, links, 1);
    tun_init(&t2, "a", 0, links2, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    firc_tunnels_t set2 = {.t = &t2, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    r.next = &set2;
    firc_loop_add_timer(r.loop, 500, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 1000, 0, snap_cb, &r, NULL);
    run_ms(&r, 1100);
    ASSERT_EQ(FIRC_OK, r.apply_rc);
    ASSERT_EQ(1, count_starts(r.snap_starts, "tunvless0"));
    ASSERT_EQ(1, r.n_snap);
    ASSERT_EQ(FIRC_TUN_ST_UP, r.snap[0].status);
    rec_close(&r);
    free(links2[0]);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST apply_changed_restarts_only_that(void)
{
    /* catches: a changed tunnel left running, or its neighbour restarted with it */
    env_setup("ok");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t[2], t2[2];
    tun_init(&t[0], "a", 0, links, 1);
    tun_init(&t[1], "b", 1, links, 1);
    tun_init(&t2[0], "a", 0, links, 1);
    tun_init(&t2[1], "b", 1, links, 1);
    t2[1].active = 2;
    firc_tunnels_t set = {.t = t, .n = 2};
    firc_tunnels_t set2 = {.t = t2, .n = 2};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    r.next = &set2;
    firc_loop_add_timer(r.loop, 500, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 1500, 0, snap_cb, &r, NULL);
    run_ms(&r, 1600);
    ASSERT_EQ(FIRC_OK, r.apply_rc);
    ASSERT_EQ(1, count_starts(r.snap_starts, "tunvless0"));
    ASSERT_EQ(2, count_starts(r.snap_starts, "tunvless1"));
    ASSERT(gone(nth_pid(r.snap_starts, "tunvless1", 0)));
    ASSERT_EQ(0, kill(nth_pid(r.snap_starts, "tunvless0", 0), 0));
    ASSERT_EQ(0, kill(nth_pid(r.snap_starts, "tunvless1", 1), 0));
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "a").status);
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "b").status);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST apply_disabled_and_absent_stopped(void)
{
    /* catches: a disabled or removed tunnel left running */
    env_setup("ok");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t[2], t2;
    tun_init(&t[0], "a", 0, links, 1);
    tun_init(&t[1], "b", 1, links, 1);
    tun_init(&t2, "a", 0, links, 1);
    t2.enable = false;
    firc_tunnels_t set = {.t = t, .n = 2};
    firc_tunnels_t set2 = {.t = &t2, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    r.next = &set2;
    firc_loop_add_timer(r.loop, 500, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 1000, 0, snap_cb, &r, NULL);
    run_ms(&r, 1100);
    ASSERT_EQ(FIRC_OK, r.apply_rc);
    ASSERT(gone(nth_pid(r.snap_starts, "tunvless0", 0)));
    ASSERT(gone(nth_pid(r.snap_starts, "tunvless1", 0)));
    ASSERT_EQ(1, count_starts(r.snap_starts, "tunvless0"));
    ASSERT_EQ(1, r.n_snap);
    ASSERT_STR_EQ("a", r.snap[0].id);
    ASSERT_EQ(FIRC_TUN_ST_OFF, r.snap[0].status);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void disable_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->seen[0] = state_of(r->s, "a").status;
    r->apply_rc = firc_tunsup_apply(r->s, r->off, NULL);
    r->seen[1] = state_of(r->s, "a").status;
}

static void enable_ok_cb(firc_loop_t *loop, void *ud)
{
    setenv("FAKE_MODE", "ok", 1);
    apply_cb(loop, ud);
}

TEST bad_config_waits_for_a_changed_apply(void)
{
    /* catches: a disabled tunnel spawned anyway, or a refused config never retried after a change */
    env_setup("badconf");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t, off, on;
    tun_init(&t, "a", 0, links, 1);
    tun_init(&off, "a", 0, links, 1);
    off.enable = false;
    tun_init(&on, "a", 0, links, 1);
    on.active = 2;
    firc_tunnels_t set = {.t = &t, .n = 1};
    firc_tunnels_t set_off = {.t = &off, .n = 1};
    firc_tunnels_t set_on = {.t = &on, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    r.off = &set_off;
    r.next = &set_on;
    firc_loop_add_timer(r.loop, 400, 0, disable_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 700, 0, enable_ok_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 1400, 0, snap_cb, &r, NULL);
    run_ms(&r, 1500);
    ASSERT_EQ(FIRC_TUN_ST_BAD_CONFIG, r.seen[0]);
    ASSERT_EQ(FIRC_TUN_ST_OFF, r.seen[1]);
    ASSERT_EQ(FIRC_OK, r.apply_rc);
    ASSERT_EQ(2, count_starts(r.snap_starts, "tunvless0"));
    ASSERT_EQ(1, r.n_snap);
    ASSERT_EQ(FIRC_TUN_ST_UP, r.snap[0].status);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST uplink_tunnel_started_after_its_uplink(void)
{
    /* catches: a tunnel started before the tunnel it runs over */
    env_setup("ok");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t[3];
    tun_init(&t[0], "a", 0, links, 1);
    t[0].uplink = FIRC_UPLINK_TUNNEL;
    snprintf(t[0].uplink_ref, sizeof t[0].uplink_ref, "c");
    tun_init(&t[1], "b", 1, links, 1);
    t[1].uplink = FIRC_UPLINK_TUNNEL;
    snprintf(t[1].uplink_ref, sizeof t[1].uplink_ref, "a");
    tun_init(&t[2], "c", 2, links, 1);
    firc_tunnels_t set = {.t = t, .n = 3};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    ASSERT_EQ(3, r.n_starting);
    ASSERT_STR_EQ("tunvless2", r.starting[0]);
    ASSERT_STR_EQ("tunvless0", r.starting[1]);
    ASSERT_STR_EQ("tunvless1", r.starting[2]);
    run_ms(&r, 300);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void *spawn_thread(void *ud)
{
    const char *script = ud;
    int out[2];
    if (pipe2(out, O_CLOEXEC) != 0) {
        return NULL;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, out[1], STDOUT_FILENO);
    char *argv[] = {(char *)script, NULL};
    pid_t pid = 0;
    int rc = posix_spawn(&pid, script, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(out[1]);
    char buf[64];
    while (rc == 0 && read(out[0], buf, sizeof buf) > 0) {
    }
    close(out[0]);
    if (rc == 0) {
        waitpid(pid, NULL, 0);
    }
    return NULL;
}

#define FD_CAP 4096

static void open_fds(bool open[FD_CAP])
{
    memset(open, 0, FD_CAP * sizeof open[0]);
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return;
    }
    int self = dirfd(d);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        int n = atoi(e->d_name);
        if (e->d_name[0] != '.' && n != self && n >= 0 && n < FD_CAP) {
            open[n] = true;
        }
    }
    closedir(d);
}

static int fresh_pipes(const bool before[FD_CAP], const bool now[FD_CAP])
{
    int n = 0;
    for (int fd = 3; fd < FD_CAP; fd++) {
        if (!now[fd] || before[fd]) {
            continue;
        }
        char link[64];
        char target[128];
        snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
        ssize_t len = readlink(link, target, sizeof target - 1);
        if (len > 0 && strncmp(target, "pipe:", 5) == 0) {
            n++;
        }
    }
    return n;
}

static int child_fds_not_inherited(const char *ls, const bool before[FD_CAP], int *seen)
{
    int bad = 0;
    *seen = 0;
    for (const char *p = ls; *p != 0;) {
        const char *nl = strchr(p, '\n');
        size_t len = nl != NULL ? (size_t)(nl - p) : strlen(p);
        const char *arrow = strstr(p, " -> ");
        if (arrow != NULL && arrow < p + len) {
            const char *q = arrow;
            while (q > p && q[-1] != ' ') {
                q--;
            }
            int fd = atoi(q);
            (*seen)++;
            if (fd >= 3 && strncmp(arrow + 4, "/proc/", 6) != 0 && (fd >= FD_CAP || !before[fd])) {
                fprintf(stderr, "child fd not inherited by the test: %.*s\n", (int)len, p);
                bad++;
            }
        }
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    return bad;
}

TEST child_inherits_no_helper_pipe(void)
{
    /* catches: an iptables helper's pipe ends leaking into a tunnel spawned meanwhile */
    env_setup("fds");
    static bool before[FD_CAP];
    static bool during[FD_CAP];
    open_fds(before);
    char save[192];
    snprintf(save, sizeof save, "%s/iptables-save", g_dir);
    FILE *f = fopen(save, "w");
    ASSERT(f != NULL);
    fputs("#!/bin/sh\nsleep 1\n", f);
    fclose(f);
    chmod(save, 0755);
    const char *old = getenv("PATH");
    snprintf(g_path, sizeof g_path, "%s", old != NULL ? old : "/usr/bin:/bin");
    char path[1280];
    snprintf(path, sizeof path, "%s:%s", g_dir, g_path);
    setenv("PATH", path, 1);
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, spawn_thread, save));
    struct timespec ts = {0, 300 * 1000000L};
    nanosleep(&ts, NULL);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    open_fds(during);
    ASSERT(fresh_pipes(before, during) > 0);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 300);
    pthread_join(th, NULL);
    setenv("PATH", g_path, 1);
    unlink(save);
    char buf[8192];
    read_file(g_fds, buf, sizeof buf);
    int seen = 0;
    ASSERT_EQ(0, child_fds_not_inherited(buf, before, &seen));
    ASSERT(seen >= 3);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST each_tag_is_relayed_at_its_level_without_it(void)
{
    /* catches: a tag relayed at the wrong level or left in the text, a sub-tag cut, a near-tag taken as one, or the device lost as the source */
    env_setup("warnsp");
    firc_event_reset_for_test();
    log_to_file();
    ASSERT(g_log_fd >= 0);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 500);
    rec_close(&r);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    log_done();
    char buf[8192];
    read_file(g_log, buf, sizeof buf);
    ASSERT(strstr(buf, "WRN tunvless0: tunnel: device tunvless0 was not created\n") != NULL);
    ASSERT(strstr(buf, "INF tunvless0: tunvless[warn]ing: not a warn tag\n") != NULL);
    ASSERT(strstr(buf, "ERR tunvless0: no usable VLESS node\n") != NULL);
    ASSERT(strstr(buf, "DBG tunvless0: tun: rx 40\n") != NULL);
    ASSERT(strstr(buf, "INF tunvless0: tunvless: by hand\n") != NULL);
    ASSERT(journal_has(FIRC_LOG_ERROR, "tunvless0", "no usable VLESS node"));
    ASSERT(journal_has(FIRC_LOG_WARN, "tunvless0", "tunnel: device tunvless0 was not created"));
    ASSERT(strstr(buf, "tunvless[error]") == NULL);
    ASSERT(strstr(buf, "tunvless[debug]") == NULL);
    ASSERT(strstr(buf, "tunvless[warn] ") == NULL);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST empty_dev_or_node_ignored_once_logged(void)
{
    /* catches: events with an empty dev or node delivered, or warned on every line */
    env_setup("emptyev");
    log_to_file();
    ASSERT(g_log_fd >= 0);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 500);
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_EQ(1, st.n_active);
    ASSERT_STR_EQ("A", st.active[0]);
    ASSERT_EQ(1, r.n_ev);
    rec_close(&r);
    log_done();
    char buf[8192];
    read_file(g_log, buf, sizeof buf);
    ASSERT_EQ(1, count_of(buf, "unreadable event"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST oversize_lines_warned_per_stream(void)
{
    /* catches: one shared flag hiding an oversize line on the other stream */
    env_setup("flood2");
    log_to_file();
    ASSERT(g_log_fd >= 0);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 500);
    rec_close(&r);
    log_done();
    char buf[8192];
    read_file(g_log, buf, sizeof buf);
    ASSERT_EQ(1, count_of(buf, "oversize stdout line"));
    ASSERT_EQ(1, count_of(buf, "oversize stderr line"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST device_swap_waits_for_the_old_holder(void)
{
    /* catches: a device claimed by a new child while another slot's old child still holds it */
    env_setup("ok");
    setenv("FAKE_STUBBORN_DEV", "tunvless1", 1);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t[2], t2[2];
    tun_init(&t[0], "a", 0, links, 1);
    tun_init(&t[1], "b", 1, links, 1);
    tun_init(&t2[0], "a", 1, links, 1);
    tun_init(&t2[1], "b", 0, links, 1);
    firc_tunnels_t set = {.t = t, .n = 2};
    firc_tunnels_t set2 = {.t = t2, .n = 2};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 100);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    r.next = &set2;
    firc_loop_add_timer(r.loop, 400, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 750, 0, snap_cb, &r, NULL);
    run_ms(&r, 1800);
    ASSERT_EQ(FIRC_OK, r.apply_rc);
    ASSERT_EQ(1, count_starts(r.snap_starts, "tunvless1"));
    ASSERT_EQ(1, count_starts(r.snap_starts, "tunvless0"));
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    ASSERT_EQ(2, count_starts(buf, "tunvless1"));
    firc_tun_state_t a = state_of(r.s, "a");
    firc_tun_state_t b = state_of(r.s, "b");
    ASSERT_STR_EQ("tunvless1", a.device);
    ASSERT_STR_EQ("tunvless0", b.device);
    ASSERT_EQ(FIRC_TUN_ST_UP, a.status);
    ASSERT_EQ(FIRC_TUN_ST_UP, b.status);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void apply_again_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->apply_rc = firc_tunsup_apply(r->s, r->off, NULL);
}

TEST repeated_apply_keeps_the_kill_deadline(void)
{
    /* catches: every apply during a stop postponing the SIGKILL */
    env_setup("stubborn");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t, t2, t3;
    tun_init(&t, "a", 0, links, 1);
    tun_init(&t2, "a", 0, links, 1);
    t2.active = 2;
    tun_init(&t3, "a", 0, links, 1);
    t3.active = 3;
    firc_tunnels_t set = {.t = &t, .n = 1};
    firc_tunnels_t set2 = {.t = &t2, .n = 1};
    firc_tunnels_t set3 = {.t = &t3, .n = 1};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 100);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    r.next = &set2;
    r.off = &set3;
    firc_loop_add_timer(r.loop, 300, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 650, 0, apply_again_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 950, 0, snap_cb, &r, NULL);
    run_ms(&r, 1000);
    ASSERT_EQ(FIRC_OK, r.apply_rc);
    ASSERT(gone(nth_pid(r.snap_starts, "tunvless0", 0)));
    ASSERT_EQ(2, count_starts(r.snap_starts, "tunvless0"));
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

typedef struct {
    char id[8][16];
    pid_t pid[8];
    int n;
    int alive;
} reaps_t;

static reaps_t g_reaps;

static void on_reap_rec(const char *id, pid_t pid, void *ud)
{
    (void)ud;
    if (g_reaps.n < 8) {
        snprintf(g_reaps.id[g_reaps.n], 16, "%s", id);
        g_reaps.pid[g_reaps.n] = pid;
        g_reaps.n++;
    }
    if (kill(pid, 0) == 0) {
        g_reaps.alive++;
    }
}

/* catches: a reap hook that fires before the child is gone, skips retired or stopped children, or names the wrong one */
TEST reap_hook_names_each_child_once_reaped(void)
{
    env_setup("ok");
    char *links[] = {"vless://u@h:1#a"};
    firc_tunnel_t t[2];
    tun_init(&t[0], "a", 0, links, 1);
    tun_init(&t[1], "b", 1, links, 1);
    firc_tunnels_t both = {.t = t, .n = 2};
    firc_tunnels_t only_b = {.t = &t[1], .n = 1};
    memset(&g_reaps, 0, sizeof g_reaps);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_on_reap(r.s, on_reap_rec, NULL);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &both, NULL));
    r.next = &only_b;
    firc_loop_add_timer(r.loop, 300, 0, apply_cb, &r, NULL);
    run_ms(&r, 1000);
    char buf[1024];
    read_file(g_starts, buf, sizeof buf);
    pid_t pa = nth_pid(buf, "tunvless0", 0);
    pid_t pb = nth_pid(buf, "tunvless1", 0);
    ASSERT(pa > 0 && pb > 0);
    ASSERT_EQ(1, g_reaps.n);
    ASSERT_STR_EQ("a", g_reaps.id[0]);
    ASSERT_EQ(pa, g_reaps.pid[0]);
    ASSERT_FALSE(firc_tunsup_holds(r.s, "a", 0));
    ASSERT(firc_tunsup_holds(r.s, "b", 0));
    ASSERT_FALSE(firc_tunsup_holds(r.s, "b", 0x10000));
    firc_tunsup_stop(r.s, 1000);
    ASSERT_EQ(2, g_reaps.n);
    ASSERT_STR_EQ("b", g_reaps.id[1]);
    ASSERT_EQ(pb, g_reaps.pid[1]);
    ASSERT_EQ(0, g_reaps.alive);
    rec_close(&r);
    PASS();
}

static firc_tunnel_t g_t1, g_t2;
static firc_tunnels_t g_set1 = {.t = &g_t1, .n = 1};
static firc_tunnels_t g_set2 = {.t = &g_t2, .n = 1};

static void two_lists(char **l1, size_t n1, char **l2, size_t n2)
{
    tun_init(&g_t1, "a", 0, l1, n1);
    tun_init(&g_t2, "a", 0, l2, n2);
}

static double cpu_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

TEST a_node_change_goes_down_the_open_stdin_without_a_restart(void)
{
    /* catches: a node-only change restarting the child, stdin closed after the first list, or the ack not stopping the clock */
    env_setup("nodes");
    char *l1[] = {"vless://u@h1:1#x"};
    char *l2[] = {"vless://u@h1:1#x", "vless://u@h2:1#y"};
    two_lists(l1, 1, l2, 2);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 300, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 1300, 0, snap_cb, &r, NULL);
    run_ms(&r, 1400);
    ASSERT_EQ(FIRC_OK, r.apply_rc);
    ASSERT_EQ(1, count_starts(r.snap_starts, "tunvless0"));
    char buf[512];
    read_file(g_stdin, buf, sizeof buf);
    ASSERT_STR_EQ("vless://u@h1:1#x\n\nnodes\nvless://u@h1:1#x\nvless://u@h2:1#y\n\n", buf);
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "a").status);
    ASSERT(firc_tunsup_started(r.s, "a") <= r.seq_before);
    ASSERT(firc_tunsup_updated(r.s, "a") > r.seq_before);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST an_unanswered_node_list_restarts_the_child(void)
{
    /* catches: a child that never takes the new list left running on the old one, or the restart journalled as fircd's */
    env_setup("nodes");
    firc_event_reset_for_test();
    setenv("FAKE_NOACK", "1", 1);
    log_to_file();
    char *l1[] = {"vless://u@h1:1#x"};
    char *l2[] = {"vless://u@h2:1#y"};
    two_lists(l1, 1, l2, 1);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 300, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 700, 0, snap_cb, &r, NULL);
    run_ms(&r, 1400);
    ASSERT_EQ(1, count_starts(r.snap_starts, "tunvless0"));
    char buf[1024];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    ASSERT(gone(nth_pid(buf, "tunvless0", 0)));
    ASSERT(firc_tunsup_started(r.s, "a") > r.seq_before);
    read_file(g_stdin, buf, sizeof buf);
    ASSERT_STR_EQ("vless://u@h2:1#y\n\n", buf);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "WRN tunvless0: tunvless did not take the node list in 10 s, restarting\n"));
    ASSERT(journal_has(FIRC_LOG_WARN, "tunvless0", "tunvless did not take the node list in 10 s, restarting"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST the_ack_clock_starts_once_the_child_is_ready(void)
{
    /* catches: a list sent during a slow start restarting a child that would read it once up */
    env_setup("nodes");
    setenv("FAKE_SLEEP", "0.8", 1);
    char *l1[] = {"vless://u@h1:1#x"};
    char *l2[] = {"vless://u@h2:1#y"};
    two_lists(l1, 1, l2, 1);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 100, 0, apply_cb, &r, NULL);
    run_ms(&r, 1700);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(1, count_starts(buf, "tunvless0"));
    read_file(g_stdin, buf, sizeof buf);
    ASSERT_STR_EQ("vless://u@h1:1#x\n\nnodes\nvless://u@h2:1#y\n\n", buf);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_child_that_closed_stdin_is_restarted_for_new_nodes(void)
{
    /* catches: a closed stdin spinning the loop, or a new list dropped on a child that cannot read it */
    env_setup("closeafter");
    char *l1[] = {"vless://u@h1:1#x"};
    char *l2[] = {"vless://u@h2:1#y"};
    two_lists(l1, 1, l2, 1);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    run_ms(&r, 300);
    double c0 = cpu_s();
    run_ms(&r, 500);
    double spent = cpu_s() - c0;
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 10, 0, apply_cb, &r, NULL);
    run_ms(&r, 800);
    ASSERT(spent < 0.25);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    ASSERT(gone(nth_pid(buf, "tunvless0", 0)));
    ASSERT(firc_tunsup_started(r.s, "a") > r.seq_before);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_full_pin_table_restarts_the_child_once(void)
{
    /* catches: pins_full ignored, or logged and acted on more than once */
    env_setup("pins");
    log_to_file();
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    run_ms(&r, 1200);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    ASSERT(gone(nth_pid(buf, "tunvless0", 0)));
    ASSERT_EQ(0, kill(nth_pid(buf, "tunvless0", 1), 0));
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "WRN tunvless0: pin table full, restarting\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST indexes_name_positions_in_the_list_last_sent(void)
{
    /* catches: tunvless's node numbers read as list positions, repeats counted twice, or an unknown number guessed */
    env_setup("nodes");
    setenv("FAKE_EVENTS",
           "{\"type\":\"active\",\"nodes\":[\"x\"],\"index\":[0]}\n"
           "{\"type\":\"node_down\",\"node\":\"y\",\"index\":1,\"why\":\"t\"}",
           1);
    setenv("FAKE_AFTER",
           "{\"type\":\"node_down\",\"node\":\"x\",\"index\":0,\"why\":\"t\"}\n"
           "{\"type\":\"node_down\",\"node\":\"z\",\"index\":2,\"why\":\"t\"}\n"
           "{\"type\":\"node_down\",\"node\":\"q\",\"index\":9,\"why\":\"t\"}\n"
           "{\"type\":\"active\",\"nodes\":[\"z\",\"y\"],\"index\":[2,1]}",
           1);
    char *l1[] = {"vless://u@h0:1#x", "vless://u@h0:1#x", "vless://u@h1:1#y"};
    char *l2[] = {"vless://u@h2:1#z", "vless://u@h1:1#y", "vless://u@h0:1#x"};
    two_lists(l1, 3, l2, 3);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 400, 0, apply_cb, &r, NULL);
    run_ms(&r, 900);
    ASSERT_EQ(4, r.n_down);
    ASSERT_EQ(2, r.down_pos[0]);
    ASSERT_EQ(2, r.down_pos[1]);
    ASSERT_EQ(0, r.down_pos[2]);
    ASSERT_EQ(-1, r.down_pos[3]);
    ASSERT_EQ(2, r.n_act);
    ASSERT_EQ(0, r.act_pos[0]);
    ASSERT_EQ(1, r.act_pos[1]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST an_empty_active_list_means_no_live_node(void)
{
    /* catches: the empty active list after the last node died read as malformed or as still up */
    env_setup("nodes");
    log_to_file();
    setenv("FAKE_EVENTS", "{\"type\":\"active\",\"nodes\":[\"x\"],\"index\":[0]}\n{\"type\":\"active\",\"nodes\":[],\"index\":[]}",
           1);
    char *l1[] = {"vless://u@h0:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    run_ms(&r, 600);
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, st.status);
    ASSERT_EQ(0, st.n_active);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT(strstr(log, "unreadable event") == NULL);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_node_table_past_its_cap_restarts_instead(void)
{
    /* catches: fircd's copy of tunvless's node numbers growing without bound over live updates */
    env_setup("nodes");
    enum { MANY = 4100 };
    static char text[MANY][32];
    static char *many[MANY];
    for (int i = 0; i < MANY; i++) {
        snprintf(text[i], sizeof text[i], "vless://u@h%d:1#n%d", i, i);
        many[i] = text[i];
    }
    char *l1[] = {"vless://u@h0:1#x"};
    two_lists(l1, 1, many, MANY);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 300, 0, apply_cb, &r, NULL);
    run_until_starts(&r, 2, 10000);
    run_ms(&r, 300);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    ASSERT(firc_tunsup_started(r.s, "a") > r.seq_before);
    ASSERT(firc_tunsup_updated(r.s, "a") <= r.seq_before);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST the_index_map_starts_again_with_each_child(void)
{
    /* catches: a restarted child's node numbers read against the table of the child before it */
    env_setup("nodes");
    setenv("FAKE_NOACK", "1", 1);
    setenv("FAKE_EVENTS", "{\"type\":\"node_down\",\"node\":\"y\",\"index\":0,\"why\":\"t\"}", 1);
    char *l1[] = {"vless://u@h0:1#x"};
    char *l2[] = {"vless://u@h1:1#y", "vless://u@h0:1#x"};
    two_lists(l1, 1, l2, 2);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 300, 0, apply_cb, &r, NULL);
    run_ms(&r, 1400);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    ASSERT_EQ(2, r.n_down);
    ASSERT_EQ(0, r.down_pos[1]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_short_ack_stops_trusting_node_numbers(void)
{
    /* catches: node numbers trusted after tunvless took fewer nodes than were sent, or the drift logged each time */
    env_setup("nodes");
    log_to_file();
    setenv("FAKE_ACK_COUNT", "1", 1);
    setenv("FAKE_AFTER", "{\"type\":\"node_down\",\"node\":\"x\",\"index\":0,\"why\":\"t\"}", 1);
    char *l1[] = {"vless://u@h0:1#x"};
    char *l2[] = {"vless://u@h1:1#y", "vless://u@h0:1#x"};
    char *l3[] = {"vless://u@h0:1#x", "vless://u@h1:1#y"};
    two_lists(l1, 1, l2, 2);
    static firc_tunnel_t t3;
    tun_init(&t3, "a", 0, l3, 2);
    static firc_tunnels_t set3 = {.t = &t3, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    r.next = &g_set2;
    r.next2 = &set3;
    firc_loop_add_timer(r.loop, 300, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 600, 0, apply2_cb, &r, NULL);
    run_ms(&r, 900);
    ASSERT_EQ(2, r.n_down);
    ASSERT_EQ(-1, r.down_pos[0]);
    ASSERT_EQ(-1, r.down_pos[1]);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(1, count_starts(buf, "tunvless0"));
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "WRN tunvless0: tunvless took 1 of 2 nodes, node states go by name until it restarts\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_terminating_child_has_no_ack_clock(void)
{
    /* catches: a child already being restarted warned about and restarted again for an unanswered list */
    env_setup("nodes");
    setenv("FAKE_NOACK", "1", 1);
    setenv("FAKE_STUBBORN_DEV", "tunvless0", 1);
    log_to_file();
    char *l1[] = {"vless://u@h0:1#x"};
    char *l2[] = {"vless://u@h1:1#y"};
    two_lists(l1, 1, l2, 1);
    static firc_tunnel_t t3;
    tun_init(&t3, "a", 0, l2, 1);
    t3.active = 2;
    static firc_tunnels_t set3 = {.t = &t3, .n = 1};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    r.next = &g_set2;
    r.next2 = &set3;
    firc_loop_add_timer(r.loop, 300, 0, apply_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 600, 0, apply2_cb, &r, NULL);
    run_ms(&r, 1100);
    ASSERT(r.started_after > r.seq_before);
    ASSERT_EQ(r.started_after, firc_tunsup_started(r.s, "a"));
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(0, count_of(log, "did not take the node list"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void ready_cb(firc_loop_t *loop, void *ud)
{
    if (firc_tunsup_ready(((rec_t *)ud)->s, "a")) {
        firc_loop_stop(loop);
    }
}

static bool run_until_ready(rec_t *r, uint64_t deadline_ms)
{
    int id = 0;
    firc_loop_add_timer(r->loop, 10, 10, ready_cb, r, &id);
    run_ms(r, deadline_ms);
    firc_loop_del_timer(r->loop, id);
    return firc_tunsup_ready(r->s, "a");
}

static void pause_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool file_has_within(const char *path, const char *needle, size_t cap, int ms)
{
    char *buf = malloc(cap);
    bool has = false;
    for (int64_t end = now_ms() + ms; !has; pause_ms(10)) {
        read_file(path, buf, cap);
        has = strstr(buf, needle) != NULL;
        if (now_ms() >= end) {
            break;
        }
    }
    free(buf);
    return has;
}

static const char k_one_map[] = "map\n198.18.0.1 192.0.2.1\n\n";

static void command_now_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    size_t one = 1;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_MAP, k_one_map, sizeof k_one_map - 1, &one, 1);
    r->in_turn = file_has_within(g_stdin, k_one_map, 4096, 2000);
}

TEST a_command_to_an_idle_child_is_written_before_the_loop_turns(void)
{
    /* catches: the write left to the next EPOLLOUT, so a command reaches tunvless only after the loop turns */
    env_setup("ktcp");
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, command_now_cb, &r, NULL);
    run_ms(&r, 50);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    ASSERT(r.in_turn);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

#define BIG_LINES 4096

static char g_big[BIG_LINES * 40];
static size_t g_big_len;
static const char k_after[] = "map\n198.18.255.1 -\n\n";

static size_t file_size(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0 ? (size_t)sb.st_size : 0;
}

static void partial_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    size_t lines = BIG_LINES;
    size_t one = 1;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_MAP, g_big, g_big_len, &lines, 1);
    for (int64_t end = now_ms() + 5000; file_size(g_stdin) < 60000 && now_ms() < end;) {
        pause_ms(10);
    }
    r->in_turn = file_size(g_stdin) < g_big_len;
    r->cmd_rc2 = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_MAP, k_after, sizeof k_after - 1, &one, 1);
}

TEST a_partial_write_keeps_the_tail_in_order(void)
{
    /* catches: the unwritten tail of a command lost, or a later command written ahead of it */
    env_setup("ktcp");
    g_big_len = (size_t)snprintf(g_big, sizeof g_big, "map\n");
    for (unsigned i = 0; i < BIG_LINES; i++) {
        g_big_len += (size_t)snprintf(g_big + g_big_len, sizeof g_big - g_big_len, "198.18.%u.%u 203.0.113.%u\n",
                                      i / 256, i % 256, i % 200);
    }
    g_big_len += (size_t)snprintf(g_big + g_big_len, sizeof g_big - g_big_len, "\n");
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, partial_cb, &r, NULL);
    run_ms(&r, 50);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    ASSERT_EQ(FIRC_OK, r.cmd_rc2);
    ASSERTm("fixture: the pipe held only part of the big command", r.in_turn);
    static char want[sizeof g_big + 64];
    snprintf(want, sizeof want, "vless://u@h1:1#x\n\n%s%s", g_big, k_after);
    static char got[sizeof want];
    for (int64_t end = now_ms() + 8000; now_ms() < end;) {
        run_ms(&r, 50);
        read_file(g_stdin, got, sizeof got);
        if (strlen(got) >= strlen(want)) {
            break;
        }
    }
    ASSERT_STR_EQ(want, got);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static const char k_three[] = "map\n198.18.0.1 192.0.2.1\n198.18.0.2 192.0.2.2\n198.18.0.3 -\n\n";

static void map_then_nodes_cb(firc_loop_t *loop, void *ud)
{
    rec_t *r = ud;
    size_t three = 3;
    size_t one = 1;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_MAP, k_three, sizeof k_three - 1, &three, 1);
    apply_cb(loop, ud);
    r->cmd_rc2 = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_MAP, k_one_map, sizeof k_one_map - 1, &one, 1);
}

TEST map_acks_do_not_consume_nodes_acks(void)
{
    /* catches: one ack queue for both kinds, so a map ack is matched against the node list, or map acks paired out of order */
    env_setup("ktcp");
    log_to_file();
    char *l1[] = {"vless://u@h1:1#x"};
    char *l2[] = {"vless://u@h1:1#x", "vless://u@h2:1#y"};
    two_lists(l1, 1, l2, 2);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 10, 0, map_then_nodes_cb, &r, NULL);
    run_ms(&r, 800);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    ASSERT_EQ(FIRC_OK, r.cmd_rc2);
    ASSERT_EQ(FIRC_OK, r.apply_rc);
    ASSERT_EQ(2, r.n_map);
    ASSERT_EQ(3, r.map_count[0]);
    ASSERT_EQ(3, r.map_expect[0]);
    ASSERT_FALSE(r.map_drift[0]);
    ASSERT_EQ(1, r.map_count[1]);
    ASSERT_EQ(1, r.map_expect[1]);
    ASSERT_FALSE(r.map_drift[1]);
    char buf[512];
    read_file(g_stdin, buf, sizeof buf);
    ASSERT_STR_EQ("vless://u@h1:1#x\n\nmap\n198.18.0.1 192.0.2.1\n198.18.0.2 192.0.2.2\n198.18.0.3 -\n\n"
                  "nodes\nvless://u@h1:1#x\nvless://u@h2:1#y\n\nmap\n198.18.0.1 192.0.2.1\n\n",
                  buf);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(0, count_of(log, "node states go by name"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void short_map_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    size_t three = 3;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_MAP, k_three, sizeof k_three - 1, &three, 1);
}

TEST a_short_map_ack_is_flagged_as_drift(void)
{
    /* catches: a map ack passed on without comparing its count with the lines sent, or one that leaves the ack clock running */
    env_setup("ktcp");
    setenv("FAKE_MAPCOUNT", "2", 1);
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, short_map_cb, &r, NULL);
    run_ms(&r, 1200);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    char starts[512];
    read_file(g_starts, starts, sizeof starts);
    ASSERT_EQ(1, count_starts(starts, "tunvless0"));
    ASSERT_EQ(1, r.n_map);
    ASSERT_EQ(2, r.map_count[0]);
    ASSERT_EQ(3, r.map_expect[0]);
    ASSERT(r.map_drift[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void one_map_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    size_t one = 1;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_MAP, k_one_map, sizeof k_one_map - 1, &one, 1);
}

TEST an_unanswered_map_restarts_the_child_after_10_s(void)
{
    /* catches: a map command left out of the ack clock, the clock run shorter than 10 s, or its count left for the next child */
    env_setup("ktcp");
    setenv("FAKE_NOACK", "1", 1);
    log_to_file();
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 50);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, one_map_cb, &r, NULL);
    run_ms(&r, 350);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(1, count_starts(buf, "tunvless0"));
    unsetenv("FAKE_NOACK");
    run_ms(&r, 900);
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    ASSERT(gone(nth_pid(buf, "tunvless0", 0)));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, short_map_cb, &r, NULL);
    run_ms(&r, 400);
    ASSERT_EQ(1, r.n_map);
    ASSERT_EQ(3, r.map_expect[0]);
    ASSERT_FALSE(r.map_drift[0]);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "WRN tunvless0: tunvless did not take the address map in 10 s, restarting\n"));
    ASSERT_EQ(0, count_of(log, "did not take the node list"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static const char k_inb_line[] = "127.0.0.1:1081 - - -\n";

static void inbounds_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_INBOUNDS, k_inb_line, sizeof k_inb_line - 1, NULL, 0);
}

TEST inbounds_command_reaches_the_child(void)
{
    /* catches: the verb or the closing empty line left off, the text altered, or the command not written */
    env_setup("ktcp");
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_cb, &r, NULL);
    run_ms(&r, 300);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    char buf[512];
    read_file(g_stdin, buf, sizeof buf);
    ASSERT(strstr(buf, "inbounds\n127.0.0.1:1081 - - -\n\n") != NULL);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void inbounds_then_wake_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_INBOUNDS, k_inb_line, sizeof k_inb_line - 1, NULL, 0);
    r->cmd_rc2 = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_WAKE, "L1\nL2\n", 6, NULL, 0);
}

TEST wake_command_is_the_verb_the_links_and_the_empty_line(void)
{
    /* catches: wake sent unframed, framed as inbounds (counted in inb_sent), or its links indexed as inbound links */
    env_setup("ktcp");
    log_to_file();
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_then_wake_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 200, 0, inbounds_cb, &r, NULL);
    run_ms(&r, 500);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    ASSERT_EQ(FIRC_OK, r.cmd_rc2);
    rec_close(&r);
    log_done();
    char buf[1024];
    read_file(g_stdin, buf, sizeof buf);
    ASSERT(strstr(buf, "inbounds\n127.0.0.1:1081 - - -\n\nwake\nL1\nL2\n\ninbounds\n127.0.0.1:1081 - - -\n\n") != NULL);
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(0, count_of(log, "inbound lines"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void inbounds_empty_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_INBOUNDS, "", 0, NULL, 0);
}

TEST an_empty_inbounds_command_is_the_verb_and_the_empty_line(void)
{
    /* catches: an empty list written as nothing, so tunvless keeps the old inbounds, and a count mismatch warned for it */
    env_setup("ktcp");
    log_to_file();
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_empty_cb, &r, NULL);
    run_ms(&r, 300);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    char buf[512];
    read_file(g_stdin, buf, sizeof buf);
    ASSERT(strstr(buf, "inbounds\n\n") != NULL);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(0, count_of(log, "inbound lines"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST an_inbounds_ack_count_mismatch_is_warned_once(void)
{
    /* catches: a short ack unnoticed, or the warning repeated on every ack */
    env_setup("ktcp");
    setenv("FAKE_INBOUNDS_COUNT", "0", 1);
    log_to_file();
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 150, 0, inbounds_cb, &r, NULL);
    run_ms(&r, 500);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "WRN tunvless0: tunvless took 0 inbound lines of 1 sent\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void restart_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->cmd_rc2 = firc_tunsup_restart(r->s, "a");
}

TEST a_restarted_child_s_inbounds_mismatch_is_warned_again(void)
{
    /* catches: the warned flag or the sent count kept across a child restart */
    env_setup("ktcp");
    setenv("FAKE_INBOUNDS_COUNT", "0", 1);
    log_to_file();
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_cb, &r, NULL);
    run_ms(&r, 300);
    firc_loop_add_timer(r.loop, 10, 0, restart_cb, &r, NULL);
    run_ms(&r, 100);
    ASSERT_EQ(FIRC_OK, r.cmd_rc2);
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_cb, &r, NULL);
    run_ms(&r, 300);
    rec_close(&r);
    log_done();
    char log[8192];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(2, count_of(log, "WRN tunvless0: tunvless took 0 inbound lines of 1 sent\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static firc_tun_ifaddr_t ifa4(const char *name, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    firc_tun_ifaddr_t e;
    memset(&e, 0, sizeof e);
    snprintf(e.name, sizeof e.name, "%s", name);
    e.family = AF_INET;
    e.addr[0] = a;
    e.addr[1] = b;
    e.addr[2] = c;
    e.addr[3] = d;
    return e;
}

TEST an_address_held_elsewhere_stops_the_spawn(void)
{
    /* catches: a child spawned onto an address another interface holds, or the refusal said on every apply */
    env_setup("ok");
    log_to_file();
    firc_tun_ifaddr_t held[] = {ifa4("ezcfg0", 203, 0, 113, 4)};
    firc_tun_addr_set_ifaddrs_for_test(held, 1);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t, t2;
    tun_init(&t, "a", 3, links, 1);
    tun_init(&t2, "a", 3, links, 1);
    t2.active = 2;
    firc_tunnels_t set = {.t = &t, .n = 1};
    firc_tunnels_t set2 = {.t = &t2, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 300);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set2, NULL));
    run_ms(&r, 300);
    char buf[256];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(0, count_starts(buf, "tunvless3"));
    ASSERT_EQ(FIRC_TUN_ST_BAD_CONFIG, state_of(r.s, "a").status);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "ERR tunvless3: 203.0.113.4 is already on ezcfg0\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_restart_request_rechecks_bad_config(void)
{
    /* catches: a re-check on restart that nothing performs, or the refusal never said again after a start */
    env_setup("ok");
    log_to_file();
    firc_tun_ifaddr_t held[] = {ifa4("ezcfg0", 203, 0, 113, 4)};
    firc_tun_ifaddr_t freed[] = {ifa4("br0", 192, 168, 1, 1)};
    firc_tun_addr_set_ifaddrs_for_test(held, 1);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 3, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 200);
    ASSERT_EQ(FIRC_TUN_ST_BAD_CONFIG, state_of(r.s, "a").status);
    firc_tun_addr_set_ifaddrs_for_test(freed, 1);
    firc_loop_add_timer(r.loop, 10, 0, restart_cb, &r, NULL);
    run_ms(&r, 700);
    ASSERT_EQ(FIRC_OK, r.cmd_rc2);
    char buf[256];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(1, count_starts(buf, "tunvless3"));
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "a").status);
    firc_tun_addr_set_ifaddrs_for_test(held, 1);
    firc_loop_add_timer(r.loop, 10, 0, restart_cb, &r, NULL);
    run_ms(&r, 700);
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(1, count_starts(buf, "tunvless3"));
    ASSERT_EQ(FIRC_TUN_ST_BAD_CONFIG, state_of(r.s, "a").status);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(2, count_of(log, "ERR tunvless3: 203.0.113.4 is already on ezcfg0\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_v6_holder_is_named_by_its_v6(void)
{
    /* catches: an address held only in IPv6 named by the IPv4 the holder does not have */
    env_setup("ok");
    log_to_file();
    firc_tun_ifaddr_t held[1];
    memset(held, 0, sizeof held);
    snprintf(held[0].name, sizeof held[0].name, "br0");
    held[0].family = AF_INET6;
    static const uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xcb, 0x00, 0x71, 0x04};
    memcpy(held[0].addr, v6, 16);
    firc_tun_addr_set_ifaddrs_for_test(held, 1);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 3, links, 1);
    firc_tunnels_t set = {.t = &t, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 300);
    ASSERT_EQ(FIRC_TUN_ST_BAD_CONFIG, state_of(r.s, "a").status);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "ERR tunvless3: 2001:db8::cb00:7104 is already on br0\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST an_unreadable_address_list_warns_once_and_starts(void)
{
    /* catches: a skipped check said nowhere or on every spawn, or a tunnel kept down when the list cannot be read */
    env_setup("ok");
    log_to_file();
    firc_tun_addr_fail_ifaddrs_for_test(true);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t, t2;
    tun_init(&t, "a", 3, links, 1);
    tun_init(&t2, "a", 3, links, 1);
    t2.active = 2;
    firc_tunnels_t set = {.t = &t, .n = 1};
    firc_tunnels_t set2 = {.t = &t2, .n = 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 700);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set2, NULL));
    run_ms(&r, 1200);
    char buf[256];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless3"));
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "a").status);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "WRN tunvless3: cannot read the interface addresses, 203.0.113.4 not checked\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST an_inbounds_ack_count_mismatch_stops_trusting_node_numbers(void)
{
    /* catches: node numbers still mapped to list positions after tunvless refused an inbound line */
    env_setup("nodes");
    setenv("FAKE_AFTER", "{\"type\":\"node_down\",\"node\":\"x\",\"index\":0,\"why\":\"t\"}", 1);
    char *l1[] = {"vless://u@h0:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_cb, &r, NULL);
    run_ms(&r, 200);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    setenv("FAKE_INBOUNDS_COUNT", "0", 1);
    firc_loop_add_timer(r.loop, 10, 0, restart_cb, &r, NULL);
    run_ms(&r, 100);
    ASSERT_EQ(FIRC_OK, r.cmd_rc2);
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_cb, &r, NULL);
    run_ms(&r, 200);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    ASSERT_EQ(2, r.n_down);
    ASSERT_EQ(0, r.down_pos[0]);
    ASSERT_EQ(-1, r.down_pos[1]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static const char k_inb_extra[] =
    "127.0.0.1:1081 - - vless://u@h9:1#e\n127.0.0.1:1083 a%20b - vless://u@h0:1#x\n127.0.0.1:1082 - - -\n";

static void inbounds_extra_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_INBOUNDS, k_inb_extra, sizeof k_inb_extra - 1, NULL, 0);
}

TEST an_inbound_link_takes_a_node_number(void)
{
    /* catches: a link tunvless adds for an inbound left out of the index map, shifting every later node's position */
    env_setup("nodes");
    setenv("FAKE_AFTER", "{\"type\":\"node_down\",\"node\":\"z\",\"index\":2,\"why\":\"t\"}", 1);
    char *l1[] = {"vless://u@h0:1#x"};
    char *l2[] = {"vless://u@h0:1#x", "vless://u@h2:1#z"};
    two_lists(l1, 1, l2, 2);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_extra_cb, &r, NULL);
    run_ms(&r, 200);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    r.next = &g_set2;
    firc_loop_add_timer(r.loop, 10, 0, apply_cb, &r, NULL);
    run_ms(&r, 300);
    ASSERT_EQ(2, r.n_down);
    ASSERT_EQ(-1, r.down_pos[0]);
    ASSERT_EQ(1, r.down_pos[1]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static char *g_many;
static size_t g_many_len;

static void inbounds_many_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_INBOUNDS, g_many, g_many_len, NULL, 0);
}

TEST a_full_node_index_from_inbounds_is_warned_once(void)
{
    /* catches: inbound links past the index cap dropped silently, so later node numbers are trusted although shifted */
    env_setup("nodes");
    log_to_file();
    g_many = malloc(4200 * 64);
    ASSERT(g_many != NULL);
    g_many_len = 0;
    for (int i = 0; i < 4200; i++) {
        g_many_len += (size_t)snprintf(g_many + g_many_len, 64, "127.0.0.1:1081 - - vless://u@h%d:1#n\n", i);
    }
    char *l1[] = {"vless://u@h0:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_many_cb, &r, NULL);
    firc_loop_add_timer(r.loop, 300, 0, inbounds_many_cb, &r, NULL);
    run_ms(&r, 1500);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    rec_close(&r);
    log_done();
    free(g_many);
    g_many = NULL;
    char log[8192];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "WRN tunvless0: node index full, node states go by name until it restarts\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void inbounds_null_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_INBOUNDS, NULL, 0, NULL, 0);
}

TEST a_null_inbounds_text_is_the_empty_command(void)
{
    /* catches: a NULL text with no lines handed to memcpy instead of written as the empty command */
    env_setup("ktcp");
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    ASSERT(run_until_ready(&r, 2000));
    firc_loop_add_timer(r.loop, 10, 0, inbounds_null_cb, &r, NULL);
    run_ms(&r, 300);
    ASSERT_EQ(FIRC_OK, r.cmd_rc);
    char buf[512];
    read_file(g_stdin, buf, sizeof buf);
    ASSERT(strstr(buf, "inbounds\n\n") != NULL);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void inbounds_early_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_INBOUNDS, k_inb_line, sizeof k_inb_line - 1, NULL, 0);
}

TEST inbounds_before_ready_is_refused(void)
{
    /* catches: an inbounds command queued to a child still starting */
    env_setup("ktcp");
    setenv("FAKE_SLEEP", "0.6", 1);
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    firc_loop_add_timer(r.loop, 100, 0, inbounds_early_cb, &r, NULL);
    run_ms(&r, 200);
    ASSERT_EQ(FIRC_ERR_STATE, r.cmd_rc);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void early_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    rec_t *r = ud;
    size_t one = 1;
    r->in_turn = firc_tunsup_ready(r->s, "a");
    r->cmd_rc = firc_tunsup_command(r->s, "a", FIRC_TUN_CMD_MAP, k_one_map, sizeof k_one_map - 1, &one, 1);
    r->cmd_rc2 = firc_tunsup_command(r->s, "zz", FIRC_TUN_CMD_CLOSE, k_one_map, sizeof k_one_map - 1, NULL, 0);
}

TEST a_command_before_ready_is_refused(void)
{
    /* catches: a command queued to a child still starting, which reads nothing until its first list is up */
    env_setup("ktcp");
    setenv("FAKE_SLEEP", "0.6", 1);
    char *l1[] = {"vless://u@h1:1#x"};
    two_lists(l1, 1, l1, 1);
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &g_set1, NULL));
    firc_loop_add_timer(r.loop, 100, 0, early_cb, &r, NULL);
    run_ms(&r, 200);
    ASSERT_FALSE(r.in_turn);
    ASSERT_EQ(FIRC_ERR_STATE, r.cmd_rc);
    ASSERT_EQ(FIRC_ERR_STATE, r.cmd_rc2);
    ASSERT(run_until_ready(&r, 2000));
    run_ms(&r, 200);
    char buf[512];
    read_file(g_stdin, buf, sizeof buf);
    ASSERT_STR_EQ("vless://u@h1:1#x\n\n", buf);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

#define EV_NN "{\"type\":\"no_node\",\"retry\":5}"
#define EV_NN6 "{\"type\":\"no_node\",\"retry\":6}"
#define EV_NN60 "{\"type\":\"no_node\",\"retry\":60}"
#define EV_NN600 "{\"type\":\"no_node\",\"retry\":600}"
#define EV_RD "{\"type\":\"ready\",\"dev\":\"tunvless0\"}"
#define EV_A "{\"type\":\"active\",\"nodes\":[\"A\"],\"index\":[0]}"
#define EV_B "{\"type\":\"active\",\"nodes\":[\"B\"],\"index\":[1]}"
#define EV_C "{\"type\":\"active\",\"nodes\":[\"C\"],\"index\":[2]}"
#define EV_AB "{\"type\":\"active\",\"nodes\":[\"A\",\"B\"],\"index\":[0,1]}"
#define EV_NONE "{\"type\":\"active\",\"nodes\":[],\"index\":[]}"

static char *g_abc[] = {"vless://u@h0:1#A", "vless://u@h1:1#B", "vless://u@h2:1#C"};
static firc_tunnel_t g_abc_t;
static firc_tunnels_t g_abc_set;

static firc_err_t links_open(rec_t *r, char **links, size_t n, int active, int second_ms)
{
    tun_init(&g_abc_t, "a", 0, links, n);
    g_abc_t.active = active;
    g_abc_set.t = &g_abc_t;
    g_abc_set.n = 1;
    rec_open(r);
    firc_tunsup_set_second_ms_for_test(r->s, second_ms);
    return firc_tunsup_apply(r->s, &g_abc_set, NULL);
}

static firc_err_t abc_open(rec_t *r, int active, int second_ms)
{
    return links_open(r, g_abc, 3, active, second_ms);
}

static int starts_now(void)
{
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    return count_starts(buf, "tunvless0");
}

static bool up_held(const rec_t *r, const char *list)
{
    for (int i = 0; i < r->n_up_hist; i++) {
        if (strcmp(r->up_hist[i], list) == 0) {
            return true;
        }
    }
    return false;
}

TEST a_starved_child_that_found_a_later_node_is_restarted_once(void)
{
    env_setup("runs");
    log_to_file();
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n" EV_C, 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_starts(&r, 2, 3000);
    run_ms(&r, 400);
    ASSERT_EQ(2, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_EQ(1, st.n_active);
    ASSERT_STR_EQ("A", st.active[0]);
    ASSERT(up_held(&r, "A"));
    ASSERT_FALSE(up_held(&r, "C"));
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "INF tunvless0: nodes answer again, starting over from the first\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_failover_without_no_node_is_not_restarted(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_RD "\n" EV_A "\n" EV_NONE "\n" EV_B, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_ms(&r, 800);
    ASSERT_EQ(1, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_EQ(1, st.n_active);
    ASSERT_STR_EQ("B", st.active[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_starved_child_back_on_the_head_is_not_restarted(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_RD "\n" EV_A "\n" EV_NN "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_ms(&r, 800);
    ASSERT_EQ(1, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_STR_EQ("A", st.active[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_starved_child_with_half_the_head_is_restarted(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n" EV_A, 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_AB, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 2, 1000));
    run_until_starts(&r, 2, 3000);
    run_ms(&r, 400);
    ASSERT_EQ(2, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_EQ(2, st.n_active);
    ASSERT_STR_EQ("A", st.active[0]);
    ASSERT_STR_EQ("B", st.active[1]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_starved_child_on_the_second_node_is_restarted(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n" EV_B, 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_starts(&r, 2, 3000);
    run_ms(&r, 400);
    ASSERT_EQ(2, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_STR_EQ("A", st.active[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void until_up_cb(firc_loop_t *loop, void *ud)
{
    rec_t *r = ud;
    firc_tun_state_t st = state_of(r->s, "a");
    if (starts_now() >= r->want_starts && st.status == FIRC_TUN_ST_UP &&
        (r->up_on == NULL || (st.n_active > 0 && strcmp(st.active[0], r->up_on) == 0))) {
        firc_loop_stop(loop);
    }
}

static void run_until_up_on_start(rec_t *r, int n, uint64_t deadline_ms)
{
    r->want_starts = n;
    int id = 0;
    firc_loop_add_timer(r->loop, 5, 5, until_up_cb, r, &id);
    run_ms(r, deadline_ms);
    firc_loop_del_timer(r->loop, id);
}

TEST a_second_recovery_inside_the_floor_is_not_restarted(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n" EV_C, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 5));
    run_until_up_on_start(&r, 2, 3000);
    run_ms(&r, 100);
    ASSERT_EQ(2, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_STR_EQ("C", st.active[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_recovery_after_the_floor_is_restarted_again(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n" EV_C, 1);
    setenv("FAKE_RUN_2", EV_NN "\n" EV_RD "\n" EV_C "\nsleep 2.3\n" EV_NN "\n" EV_B, 1);
    setenv("FAKE_RUN_3", EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 2));
    run_until_up_on_start(&r, 3, 10000);
    run_ms(&r, 100);
    ASSERT_EQ(3, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_STR_EQ("A", st.active[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_no_node_from_a_run_that_ended_does_not_restart_the_next(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\nexit 1", 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_B, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 50));
    run_until_starts(&r, 2, 3000);
    run_ms(&r, 500);
    ASSERT_EQ(2, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_STR_EQ("B", st.active[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_recovery_swallowed_by_the_floor_clears_the_starving(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n" EV_C, 1);
    setenv("FAKE_RUN_2", EV_NN "\n" EV_RD "\n" EV_C "\nsleep 2.3\n" EV_NONE "\n" EV_B, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 2));
    r.up_on = "B";
    run_until_up_on_start(&r, 2, 10000);
    run_ms(&r, 100);
    ASSERT_EQ(2, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_STR_EQ("B", st.active[0]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_tunnel_with_fewer_links_than_slots_is_not_restarted(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, links_open(&r, g_abc, 1, 2, 1000));
    run_until_up_on_start(&r, 1, 3000);
    run_ms(&r, 300);
    ASSERT_EQ(1, starts_now());
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "a").status);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST duplicate_links_do_not_hide_the_head(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n" EV_AB, 1);
    static char *aab[] = {"vless://u@h0:1#A", "vless://u@h0:1#A", "vless://u@h1:1#B"};
    static rec_t r;
    ASSERT_EQ(FIRC_OK, links_open(&r, aab, 3, 2, 1000));
    run_until_up_on_start(&r, 1, 3000);
    run_ms(&r, 300);
    ASSERT_EQ(1, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_EQ(2, st.n_active);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST an_unnumbered_node_is_not_the_head(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN "\n" EV_RD "\n{\"type\":\"active\",\"nodes\":[\"A\"]}", 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_up_on_start(&r, 2, 3000);
    run_ms(&r, 300);
    ASSERT_EQ(2, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void until_starved_cb(firc_loop_t *loop, void *ud)
{
    rec_t *r = ud;
    if (starts_now() >= r->want_starts && state_of(r->s, "a").status == FIRC_TUN_ST_NO_NODE) {
        firc_loop_stop(loop);
    }
}

static void run_until_starved_on_start(rec_t *r, int n, uint64_t deadline_ms)
{
    r->want_starts = n;
    int id = 0;
    firc_loop_add_timer(r->loop, 5, 5, until_starved_cb, r, &id);
    run_ms(r, deadline_ms);
    firc_loop_del_timer(r->loop, id);
}

TEST a_starved_child_is_restarted_on_demand(void)
{
    env_setup("runs");
    log_to_file();
    setenv("FAKE_RUN_1", EV_NN60, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "a").status);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    run_until_starts(&r, 2, 3000);
    run_ms(&r, 300);
    ASSERT_EQ(2, starts_now());
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "INF tunvless0: the network changed, starting over\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_child_with_a_node_is_not_restarted_on_demand(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_up_on_start(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "a").status);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    run_ms(&r, 300);
    ASSERT_EQ(1, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_child_that_has_not_starved_is_not_restarted_on_demand(void)
{
    env_setup("runs");
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_starts(&r, 1, 3000);
    run_ms(&r, 100);
    ASSERT_EQ(1, starts_now());
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    run_ms(&r, 300);
    ASSERT_EQ(1, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_starved_child_that_lost_its_node_again_is_restarted_on_demand(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_RD "\n" EV_A "\n" EV_NN60, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "a").status);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    run_until_starts(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST an_active_that_arrives_while_terminating_does_not_restart_again(void)
{
    env_setup("runs");
    log_to_file();
    setenv("FAKE_STUBBORN_DEV", "tunvless0", 1);
    setenv("FAKE_RUN_1",
           EV_NN60 "\nsleep 1\n" EV_RD "\n{\"type\":\"active\",\"nodes\":[\"B\",\"C\"],\"index\":[1,2]}\n" EV_NN60
                   "\n{\"type\":\"node_up\",\"node\":\"B\",\"index\":1}\n{\"type\":\"node_down\",\"node\":\"C\","
                   "\"why\":\"x\",\"index\":2}",
           1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 400));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    r.up_on = "A";
    run_until_up_on_start(&r, 2, 6000);
    ASSERT_EQ(2, starts_now());
    ASSERT_EQ(1, r.n_ready);
    ASSERT_EQ(1, r.n_nn);
    ASSERT_EQ(0, r.n_nup);
    ASSERT_EQ(0, r.n_down);
    ASSERT(r.n_up_hist > 0);
    for (int i = 0; i < r.n_up_hist; i++) {
        ASSERT_STR_EQ("A", r.up_hist[i]);
    }
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "INF tunvless0: the network changed, starting over\n"));
    ASSERT_EQ(0, count_of(log, "nodes answer again"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_starved_child_in_backoff_is_not_restarted_on_demand(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN60 "\nexit 1", 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_B, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 300));
    run_until_backoffs(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_BACKOFF, state_of(r.s, "a").status);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    run_ms(&r, 300);
    ASSERT_EQ(1, starts_now());
    run_until_starts(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void run_to(rec_t *r, int64_t since, int64_t ms)
{
    int64_t left = since + ms - now_ms();
    if (left > 0) {
        run_ms(r, (uint64_t)left);
    }
}

TEST a_burst_of_network_changes_restarts_once_after_it_settles(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN60, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 750));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "a").status);
    firc_tunsup_net_changed(r.s);
    run_ms(&r, 300);
    firc_tunsup_net_changed(r.s);
    run_ms(&r, 300);
    firc_tunsup_net_changed(r.s);
    int64_t last = now_ms();
    run_ms(&r, 300);
    int quiet_starts = starts_now();
    if (now_ms() - last >= 1400) {
        SKIPm("the look after the burst came too late");
    }
    ASSERT_EQ(1, quiet_starts);
    run_until_starts(&r, 2, 4000);
    ASSERT_EQ(2, starts_now());
    ASSERT(now_ms() - last >= 1480);
    run_ms(&r, 600);
    ASSERT_EQ(2, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_child_about_to_look_again_is_left_alone(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 2000));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "a").status);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    run_ms(&r, 200);
    ASSERT_EQ(1, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN6, 1);
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 2000));
    run_until_starved_on_start(&r, 1, 3000);
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, st.status);
    size_t n = firc_tunsup_restart_starved(r.s);
    if (now_ms() - st.since_ms >= 1800) {
        SKIPm("the demand came too long after no_node");
    }
    ASSERT_EQ(1, n);
    run_until_starts(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static int64_t start_gap(rec_t *r, int n, int64_t since, uint64_t deadline_ms)
{
    run_until_starts(r, n, deadline_ms);
    return now_ms() - since;
}

static const char *const g_ab_ids[2] = {"a", "b"};

static void watch_sync(rec_t *r)
{
    for (int k = 0; k < 2; k++) {
        r->seq_seen[k] = firc_tunsup_started(r->s, g_ab_ids[k]);
        r->n_at[k] = 0;
    }
}

static void seq_cb(firc_loop_t *loop, void *ud)
{
    rec_t *r = ud;
    int64_t now = now_ms();
    for (int k = 0; k < 2; k++) {
        uint64_t q = firc_tunsup_started(r->s, g_ab_ids[k]);
        if (q != r->seq_seen[k] && r->n_at[k] < 8) {
            r->at[k][r->n_at[k]++] = now;
        }
        r->seq_seen[k] = q;
    }
    if (r->want_k >= 0 && r->n_at[r->want_k] >= r->want_at) {
        firc_loop_stop(loop);
    }
}

static void watch_restarts(rec_t *r)
{
    watch_sync(r);
    r->want_k = -1;
    int id = 0;
    firc_loop_add_timer(r->loop, 2, 2, seq_cb, r, &id);
}

static int64_t run_until_restart(rec_t *r, int k, int n, uint64_t deadline_ms)
{
    r->want_k = k;
    r->want_at = n;
    if (r->n_at[k] < n) {
        run_ms(r, deadline_ms);
    }
    r->want_k = -1;
    return r->n_at[k] >= n ? r->at[k][n - 1] : -1;
}

static void cond_cb(firc_loop_t *loop, void *ud)
{
    rec_t *r = ud;
    if (r->cond(r)) {
        firc_loop_stop(loop);
    }
}

static void run_until_cond(rec_t *r, bool (*cond)(const rec_t *r), uint64_t deadline_ms)
{
    r->cond = cond;
    int id = 0;
    firc_loop_add_timer(r->loop, 5, 5, cond_cb, r, &id);
    if (!cond(r)) {
        run_ms(r, deadline_ms);
    }
    firc_loop_del_timer(r->loop, id);
}

TEST the_floor_doubles_while_the_tunnel_stays_starved(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 40));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t b = now_ms();
    watch_restarts(&r);
    run_until_starved_on_start(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    ASSERT(now_ms() - b < 25 * 40);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    int64_t at = run_until_restart(&r, 0, 1, 60 * 40);
    ASSERT(at > 0);
    ASSERT(at - b >= 29 * 40 && at - b <= 45 * 40);
    b = at;
    run_until_starved_on_start(&r, 3, 3000);
    run_to(&r, b, 31 * 40);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    at = run_until_restart(&r, 0, 2, 90 * 40);
    ASSERT(at > 0);
    ASSERT(at - b >= 59 * 40 && at - b <= 75 * 40);
    run_until_starts(&r, 4, 3000);
    ASSERT_EQ(4, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST the_floor_stops_at_three_hundred(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 4));
    static const int64_t gap[] = {0, 40, 70, 130, 250};
    int64_t b = 0;
    for (int k = 0; k < 5; k++) {
        run_until_starved_on_start(&r, k + 1, 3000);
        ASSERT_EQ(k + 1, starts_now());
        run_to(&r, b, gap[k] * 4);
        ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
        b = now_ms();
    }
    run_until_starved_on_start(&r, 6, 3000);
    ASSERT_EQ(6, starts_now());
    run_to(&r, b, 240 * 4);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    int64_t late = start_gap(&r, 7, b, 3000);
    ASSERT_EQ(7, starts_now());
    ASSERT(late >= 299 * 4 && late <= 400 * 4);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void until_starved_after_a_cb(firc_loop_t *loop, void *ud)
{
    rec_t *r = ud;
    if (starts_now() >= r->want_starts && up_held(r, "A") && state_of(r->s, "a").status == FIRC_TUN_ST_NO_NODE) {
        firc_loop_stop(loop);
    }
}

TEST after_a_node_the_floor_starts_from_thirty_again(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_3", EV_RD "\n" EV_A "\nsleep 2\n" EV_NN600, 1);
    setenv("FAKE_RUN_4", EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 50));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t b = now_ms();
    run_until_starved_on_start(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    run_to(&r, b, 31 * 50);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    b = now_ms();
    r.want_starts = 3;
    int id = 0;
    firc_loop_add_timer(r.loop, 5, 5, until_starved_after_a_cb, &r, &id);
    run_ms(&r, 6000);
    firc_loop_del_timer(r.loop, id);
    ASSERT_EQ(3, starts_now());
    ASSERT(up_held(&r, "A"));
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "a").status);
    ASSERT(now_ms() - b < 55 * 50);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    b = now_ms();
    run_until_starved_on_start(&r, 4, 3000);
    ASSERT_EQ(4, starts_now());
    run_to(&r, b, 15 * 50);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    int64_t gap = start_gap(&r, 5, b, 60 * 50);
    ASSERT_EQ(5, starts_now());
    ASSERT(gap >= 29 * 50 && gap <= 45 * 50);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_stopped_supervisor_drops_the_settle(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN60, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 100));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "a").status);
    firc_tunsup_net_changed(r.s);
    firc_tunsup_stop(r.s, 1000);
    firc_tunsup_free(r.s);
    r.s = NULL;
    run_ms(&r, 600);
    ASSERT_EQ(1, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static void until_both_cb(firc_loop_t *loop, void *ud)
{
    rec_t *r = ud;
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    if (count_starts(buf, "tunvless0") >= r->want_starts && count_starts(buf, "tunvless1") >= r->want_starts &&
        state_of(r->s, "a").status == FIRC_TUN_ST_NO_NODE && state_of(r->s, "b").status == FIRC_TUN_ST_NO_NODE) {
        firc_loop_stop(loop);
    }
}

static void run_until_both_starved(rec_t *r, int n, uint64_t deadline_ms)
{
    r->want_starts = n;
    int id = 0;
    firc_loop_add_timer(r->loop, 5, 5, until_both_cb, r, &id);
    run_ms(r, deadline_ms);
    firc_loop_del_timer(r->loop, id);
}

TEST two_starved_tunnels_are_both_restarted(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN60, 1);
    firc_tunnel_t t[2];
    tun_init(&t[0], "a", 0, g_abc, 3);
    tun_init(&t[1], "b", 1, g_abc, 3);
    firc_tunnels_t set = {.t = t, .n = 2};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_until_both_starved(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "a").status);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "b").status);
    ASSERT_EQ(2, firc_tunsup_restart_starved(r.s));
    run_until_both_starved(&r, 2, 3000);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(2, count_starts(buf, "tunvless0"));
    ASSERT_EQ(2, count_starts(buf, "tunvless1"));
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_retired_starved_tunnel_is_not_restarted(void)
{
    env_setup("runs");
    log_to_file();
    setenv("FAKE_STUBBORN_DEV", "tunvless0", 1);
    setenv("FAKE_RUN_1", EV_NN60, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, state_of(r.s, "a").status);
    firc_tunnels_t none = {.t = NULL, .n = 0};
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &none, NULL));
    run_ms(&r, 100);
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    ASSERT_EQ(0, kill(nth_pid(buf, "tunvless0", 0), 0));
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    run_ms(&r, 300);
    ASSERT_EQ(1, starts_now());
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(0, count_of(log, "the network changed"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_node_held_for_a_moment_does_not_reset_the_floor(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_RD "\n" EV_A "\n" EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 50));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t b = now_ms();
    watch_restarts(&r);
    run_until_starved_on_start(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    ASSERT(up_held(&r, "A"));
    run_to(&r, b, 15 * 50);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    int64_t at = run_until_restart(&r, 0, 1, 60 * 50);
    ASSERT(at > 0);
    ASSERT(at - b >= 29 * 50 && at - b <= 45 * 50);
    b = at;
    run_until_starved_on_start(&r, 3, 3000);
    ASSERT(up_held(&r, "A"));
    run_to(&r, b, 31 * 50);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    at = run_until_restart(&r, 0, 2, 90 * 50);
    ASSERT(at > 0);
    ASSERT(at - b >= 59 * 50 && at - b <= 75 * 50);
    run_until_starts(&r, 4, 3000);
    ASSERT_EQ(4, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_change_refused_by_the_floor_is_served_when_it_ends(void)
{
    env_setup("runs");
    log_to_file();
    setenv("FAKE_RUN_1", EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 30));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t b = now_ms();
    watch_restarts(&r);
    run_until_starved_on_start(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    run_to(&r, b, 10 * 30);
    firc_tunsup_net_changed(r.s);
    run_to(&r, b, 20 * 30);
    ASSERT_EQ(0, r.n_at[0]);
    ASSERT_EQ(2, starts_now());
    int64_t at = run_until_restart(&r, 0, 1, 50 * 30);
    ASSERT(at > 0);
    ASSERT(at - b >= 29 * 30);
    ASSERT(at - b <= 55 * 30);
    run_to(&r, b, 100 * 30);
    ASSERT_EQ(1, r.n_at[0]);
    ASSERT_EQ(3, starts_now());
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(2, count_of(log, "INF tunvless0: the network changed, starting over\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static int b_starts(void)
{
    char buf[512];
    read_file(g_starts, buf, sizeof buf);
    return count_starts(buf, "tunvless1");
}

static bool a_up_twice(const rec_t *r)
{
    return starts_now() >= 2 && state_of(r->s, "a").status == FIRC_TUN_ST_UP;
}

static bool b_starved_once(const rec_t *r)
{
    return b_starts() >= 1 && state_of(r->s, "b").status == FIRC_TUN_ST_NO_NODE;
}

static bool b_up_once(const rec_t *r)
{
    return b_starts() >= 1 && state_of(r->s, "b").status == FIRC_TUN_ST_UP;
}

static bool b_starved(const rec_t *r)
{
    return state_of(r->s, "b").status == FIRC_TUN_ST_NO_NODE;
}

static bool both_starved_again(const rec_t *r)
{
    return b_starts() >= 2 && state_of(r->s, "a").status == FIRC_TUN_ST_NO_NODE &&
           state_of(r->s, "b").status == FIRC_TUN_ST_NO_NODE;
}

static firc_tunnel_t g_ab_t[2];

static firc_err_t ab_open(rec_t *r, int second_ms)
{
    tun_init(&g_ab_t[0], "a", 0, g_abc, 3);
    tun_init(&g_ab_t[1], "b", 1, g_abc, 3);
    firc_tunnels_t one = {.t = g_ab_t, .n = 1};
    rec_open(r);
    firc_tunsup_set_second_ms_for_test(r->s, second_ms);
    return firc_tunsup_apply(r->s, &one, NULL);
}

static firc_err_t ab_add_b(rec_t *r)
{
    firc_tunnels_t two = {.t = g_ab_t, .n = 2};
    return firc_tunsup_apply(r->s, &two, NULL);
}

TEST one_change_does_not_keep_two_dead_tunnels_restarting(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_A "\nsleep 1\n" EV_NN600, 1);
    setenv("FAKE_RUN_3", EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, ab_open(&r, 80));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t t0 = now_ms();
    watch_restarts(&r);
    run_until_cond(&r, a_up_twice, 3000);
    ASSERT(a_up_twice(&r));
    ASSERT_EQ(FIRC_OK, ab_add_b(&r));
    run_until_cond(&r, b_starved_once, 3000);
    ASSERT(b_starved_once(&r));
    run_to(&r, t0, 6 * 80);
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "a").status);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t t1 = now_ms();
    watch_sync(&r);
    run_until_cond(&r, both_starved_again, 3000);
    ASSERT(both_starved_again(&r));
    run_to(&r, t0, 16 * 80);
    ASSERT(now_ms() - t0 <= 24 * 80);
    firc_tunsup_net_changed(r.s);
    int64_t ra = run_until_restart(&r, 0, 1, 60 * 80);
    int64_t rb = run_until_restart(&r, 1, 1, 60 * 80);
    ASSERT(ra > 0 && rb > 0);
    ASSERT(ra - t0 >= 29 * 80 && ra - t0 <= 40 * 80);
    ASSERT(rb - t1 >= 29 * 80 && rb - t1 <= 40 * 80);
    run_to(&r, rb, 70 * 80);
    ASSERT_EQ(1, r.n_at[0]);
    ASSERT_EQ(1, r.n_at[1]);
    ASSERT_EQ(3, starts_now());
    ASSERT_EQ(3, b_starts());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_tunnel_that_starved_after_the_change_is_not_served_by_it(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", EV_NN600, 1);
    setenv("FAKE_RUN_3", EV_RD "\n" EV_A "\nsleep 0.6\n" EV_NN600, 1);
    setenv("FAKE_RUN_4", EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, ab_open(&r, 40));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t t0 = now_ms();
    run_until_starved_on_start(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    ASSERT_EQ(FIRC_OK, ab_add_b(&r));
    watch_restarts(&r);
    run_until_cond(&r, b_up_once, 3000);
    ASSERT(b_up_once(&r));
    run_to(&r, t0, 8 * 40);
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "b").status);
    firc_tunsup_net_changed(r.s);
    run_until_cond(&r, b_starved, 3000);
    ASSERT(b_starved(&r));
    ASSERT(now_ms() - t0 <= 27 * 40);
    int64_t ra = run_until_restart(&r, 0, 1, 40 * 40);
    ASSERT(ra > 0);
    ASSERT(ra - t0 >= 29 * 40 && ra - t0 <= 45 * 40);
    run_ms(&r, 8 * 40);
    ASSERT_EQ(1, r.n_at[0]);
    ASSERT_EQ(0, r.n_at[1]);
    ASSERT_EQ(1, b_starts());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

static bool nn_reached(const rec_t *r)
{
    return r->n_nn >= r->want_starts;
}

static void run_until_nn(rec_t *r, int n, uint64_t deadline_ms)
{
    r->want_starts = n;
    run_until_cond(r, nn_reached, deadline_ms);
}

static enum greatest_test_res floor_after_a_hold(const char *run2, const char *run3, size_t want)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", run2, 1);
    setenv("FAKE_RUN_3", run3, 1);
    setenv("FAKE_RUN_4", EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 20));
    run_until_nn(&r, 1, 3000);
    ASSERT_EQ(1, r.n_nn);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    run_until_nn(&r, 2, 4000);
    ASSERT_EQ(2, r.n_nn);
    ASSERT(up_held(&r, "A"));
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t b = now_ms();
    run_until_nn(&r, 3, 3000);
    ASSERT_EQ(3, r.n_nn);
    run_to(&r, b, 31 * 20);
    ASSERT_EQ(want, firc_tunsup_restart_starved(r.s));
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_node_after_the_change_cancels_what_it_owed(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", EV_NN600 "\nsleep 0.6\n" EV_RD "\n" EV_A "\nsleep 0.2\n" EV_NN600, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 40));
    run_until_nn(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t t0 = now_ms();
    watch_restarts(&r);
    run_until_nn(&r, 2, 3000);
    ASSERT_EQ(2, r.n_nn);
    run_to(&r, t0, 8 * 40);
    firc_tunsup_net_changed(r.s);
    run_until_nn(&r, 3, 3000);
    ASSERT_EQ(3, r.n_nn);
    ASSERT(up_held(&r, "A"));
    ASSERT(now_ms() - t0 <= 27 * 40);
    run_to(&r, t0, 40 * 40);
    ASSERT_EQ(0, r.n_at[0]);
    ASSERT_EQ(2, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_hold_counts_from_the_first_node_of_the_run(void)
{
    CHECK_CALL(floor_after_a_hold(EV_RD "\n" EV_A "\nsleep 0.4\n" EV_AB "\nsleep 0.4\n" EV_NN600, EV_NN600, 1));
    PASS();
}

TEST a_short_hold_ended_by_an_exit_does_not_reset_the_floor(void)
{
    CHECK_CALL(floor_after_a_hold(EV_RD "\n" EV_A "\nsleep 0.1\nexit 1", "sleep 0.8\n" EV_NN600, 0));
    PASS();
}

TEST a_long_hold_ended_by_an_exit_resets_the_floor(void)
{
    CHECK_CALL(floor_after_a_hold(EV_RD "\n" EV_A "\nsleep 0.8\nexit 1", EV_NN600, 1));
    PASS();
}

TEST an_empty_active_ends_the_hold(void)
{
    CHECK_CALL(floor_after_a_hold(EV_RD "\n" EV_A "\nsleep 0.1\n" EV_NONE "\nsleep 0.8\n" EV_NN600, EV_NN600, 0));
    PASS();
}

TEST a_run_started_on_demand_still_expects_the_head(void)
{
    env_setup("runs");
    log_to_file();
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_C, 1);
    setenv("FAKE_RUN_3", EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    r.up_on = "A";
    run_until_up_on_start(&r, 3, 6000);
    run_ms(&r, 300);
    ASSERT_EQ(3, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_STR_EQ("A", st.active[0]);
    ASSERT_FALSE(up_held(&r, "C"));
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(1, count_of(log, "INF tunvless0: nodes answer again, starting over from the first\n"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_run_started_on_demand_that_takes_the_head_stays(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_A, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 1000));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    r.up_on = "A";
    run_until_up_on_start(&r, 2, 3000);
    run_ms(&r, 300);
    ASSERT_EQ(2, starts_now());
    ASSERT_EQ(FIRC_TUN_ST_UP, state_of(r.s, "a").status);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_run_started_on_demand_with_part_of_the_head_stays(void)
{
    env_setup("runs");
    log_to_file();
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", EV_RD "\n" EV_A "\nsleep 0.2\n" EV_AB, 1);
    setenv("FAKE_RUN_3", EV_RD "\n" EV_AB, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 2, 1000));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    r.up_on = "A";
    run_until_up_on_start(&r, 2, 3000);
    run_ms(&r, 800);
    ASSERT_EQ(2, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_EQ(2, st.n_active);
    ASSERT_STR_EQ("A", st.active[0]);
    ASSERT_STR_EQ("B", st.active[1]);
    rec_close(&r);
    log_done();
    char log[4096];
    read_file(g_log, log, sizeof log);
    ASSERT_EQ(0, count_of(log, "nodes answer again"));
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_run_started_on_demand_that_starves_itself_needs_the_whole_head(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", EV_NN600 "\n" EV_RD "\n" EV_A, 1);
    setenv("FAKE_RUN_3", EV_RD "\n" EV_AB, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 2, 1000));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    run_until_starts(&r, 3, 3000);
    run_ms(&r, 800);
    ASSERT_EQ(3, starts_now());
    firc_tun_state_t st = state_of(r.s, "a");
    ASSERT_EQ(FIRC_TUN_ST_UP, st.status);
    ASSERT_EQ(2, st.n_active);
    ASSERT_STR_EQ("B", st.active[1]);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST a_run_started_on_demand_waits_for_its_own_no_node(void)
{
    env_setup("runs");
    setenv("FAKE_RUN_1", EV_NN600, 1);
    setenv("FAKE_RUN_2", EV_RD, 1);
    static rec_t r;
    ASSERT_EQ(FIRC_OK, abc_open(&r, 1, 40));
    run_until_starved_on_start(&r, 1, 3000);
    ASSERT_EQ(1, firc_tunsup_restart_starved(r.s));
    int64_t b = now_ms();
    run_until_starts(&r, 2, 3000);
    ASSERT_EQ(2, starts_now());
    run_to(&r, b, 31 * 40);
    ASSERT_EQ(0, firc_tunsup_restart_starved(r.s));
    run_ms(&r, 300);
    ASSERT_EQ(2, starts_now());
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(ok_child_up_links_on_stdin);
    RUN_TEST(reap_hook_names_each_child_once_reaped);
    RUN_TEST(argv_full_and_no_link);
    RUN_TEST(argv_with_every_option_set);
    RUN_TEST(argv_minimal_without_options);
    RUN_TEST(a_kernel_tcp_tunnel_is_spawned_with_its_port_and_pool);
    RUN_TEST(a_kernel_tcp_tunnel_without_a_pool_gets_only_its_port);
    RUN_TEST(stderr_logged_by_level_without_links);
    RUN_TEST(crash_restarts_with_growing_backoff);
    RUN_TEST(backoff_doubles_up_to_sixty);
    RUN_TEST(twenty_restarts_leave_one_warning);
    RUN_TEST(backoff_resets_after_stable_run);
    RUN_TEST(badconf_not_restarted);
    RUN_TEST(flood_line_dropped_loop_responsive);
    RUN_TEST(noread_child_never_blocks_loop);
    RUN_TEST(closed_stdin_counts_as_failed_start);
    RUN_TEST(stop_kills_child_ignoring_term);
    RUN_TEST(apply_unchanged_keeps_child);
    RUN_TEST(apply_changed_restarts_only_that);
    RUN_TEST(apply_disabled_and_absent_stopped);
    RUN_TEST(bad_config_waits_for_a_changed_apply);
    RUN_TEST(uplink_tunnel_started_after_its_uplink);
    RUN_TEST(child_inherits_no_helper_pipe);
    RUN_TEST(each_tag_is_relayed_at_its_level_without_it);
    RUN_TEST(empty_dev_or_node_ignored_once_logged);
    RUN_TEST(oversize_lines_warned_per_stream);
    RUN_TEST(device_swap_waits_for_the_old_holder);
    RUN_TEST(repeated_apply_keeps_the_kill_deadline);
    RUN_TEST(a_node_change_goes_down_the_open_stdin_without_a_restart);
    RUN_TEST(an_unanswered_node_list_restarts_the_child);
    RUN_TEST(the_ack_clock_starts_once_the_child_is_ready);
    RUN_TEST(a_child_that_closed_stdin_is_restarted_for_new_nodes);
    RUN_TEST(a_full_pin_table_restarts_the_child_once);
    RUN_TEST(indexes_name_positions_in_the_list_last_sent);
    RUN_TEST(an_empty_active_list_means_no_live_node);
    RUN_TEST(a_node_table_past_its_cap_restarts_instead);
    RUN_TEST(the_index_map_starts_again_with_each_child);
    RUN_TEST(a_short_ack_stops_trusting_node_numbers);
    RUN_TEST(a_terminating_child_has_no_ack_clock);
    RUN_TEST(a_command_to_an_idle_child_is_written_before_the_loop_turns);
    RUN_TEST(a_partial_write_keeps_the_tail_in_order);
    RUN_TEST(map_acks_do_not_consume_nodes_acks);
    RUN_TEST(a_short_map_ack_is_flagged_as_drift);
    RUN_TEST(an_unanswered_map_restarts_the_child_after_10_s);
    RUN_TEST(a_command_before_ready_is_refused);
    RUN_TEST(inbounds_command_reaches_the_child);
    RUN_TEST(wake_command_is_the_verb_the_links_and_the_empty_line);
    RUN_TEST(an_empty_inbounds_command_is_the_verb_and_the_empty_line);
    RUN_TEST(an_inbounds_ack_count_mismatch_is_warned_once);
    RUN_TEST(an_inbounds_ack_count_mismatch_stops_trusting_node_numbers);
    RUN_TEST(inbounds_before_ready_is_refused);
    RUN_TEST(a_restarted_child_s_inbounds_mismatch_is_warned_again);
    RUN_TEST(a_null_inbounds_text_is_the_empty_command);
    RUN_TEST(an_inbound_link_takes_a_node_number);
    RUN_TEST(a_full_node_index_from_inbounds_is_warned_once);
    RUN_TEST(a_starved_child_that_found_a_later_node_is_restarted_once);
    RUN_TEST(a_failover_without_no_node_is_not_restarted);
    RUN_TEST(a_starved_child_back_on_the_head_is_not_restarted);
    RUN_TEST(a_starved_child_with_half_the_head_is_restarted);
    RUN_TEST(a_starved_child_on_the_second_node_is_restarted);
    RUN_TEST(a_second_recovery_inside_the_floor_is_not_restarted);
    RUN_TEST(a_recovery_after_the_floor_is_restarted_again);
    RUN_TEST(a_no_node_from_a_run_that_ended_does_not_restart_the_next);
    RUN_TEST(a_recovery_swallowed_by_the_floor_clears_the_starving);
    RUN_TEST(a_tunnel_with_fewer_links_than_slots_is_not_restarted);
    RUN_TEST(duplicate_links_do_not_hide_the_head);
    RUN_TEST(an_unnumbered_node_is_not_the_head);
    RUN_TEST(a_starved_child_is_restarted_on_demand);
    RUN_TEST(a_child_with_a_node_is_not_restarted_on_demand);
    RUN_TEST(a_child_that_has_not_starved_is_not_restarted_on_demand);
    RUN_TEST(a_starved_child_that_lost_its_node_again_is_restarted_on_demand);
    RUN_TEST(an_active_that_arrives_while_terminating_does_not_restart_again);
    RUN_TEST(a_starved_child_in_backoff_is_not_restarted_on_demand);
    RUN_TEST(a_burst_of_network_changes_restarts_once_after_it_settles);
    RUN_TEST(a_child_about_to_look_again_is_left_alone);
    RUN_TEST(the_floor_doubles_while_the_tunnel_stays_starved);
    RUN_TEST(the_floor_stops_at_three_hundred);
    RUN_TEST(after_a_node_the_floor_starts_from_thirty_again);
    RUN_TEST(a_stopped_supervisor_drops_the_settle);
    RUN_TEST(two_starved_tunnels_are_both_restarted);
    RUN_TEST(a_retired_starved_tunnel_is_not_restarted);
    RUN_TEST(a_node_held_for_a_moment_does_not_reset_the_floor);
    RUN_TEST(a_change_refused_by_the_floor_is_served_when_it_ends);
    RUN_TEST(one_change_does_not_keep_two_dead_tunnels_restarting);
    RUN_TEST(a_tunnel_that_starved_after_the_change_is_not_served_by_it);
    RUN_TEST(a_node_after_the_change_cancels_what_it_owed);
    RUN_TEST(a_hold_counts_from_the_first_node_of_the_run);
    RUN_TEST(a_short_hold_ended_by_an_exit_does_not_reset_the_floor);
    RUN_TEST(a_long_hold_ended_by_an_exit_resets_the_floor);
    RUN_TEST(an_empty_active_ends_the_hold);
    RUN_TEST(a_run_started_on_demand_still_expects_the_head);
    RUN_TEST(a_run_started_on_demand_that_takes_the_head_stays);
    RUN_TEST(a_run_started_on_demand_with_part_of_the_head_stays);
    RUN_TEST(a_run_started_on_demand_that_starves_itself_needs_the_whole_head);
    RUN_TEST(a_run_started_on_demand_waits_for_its_own_no_node);
    RUN_TEST(an_address_held_elsewhere_stops_the_spawn);
    RUN_TEST(a_restart_request_rechecks_bad_config);
    RUN_TEST(a_v6_holder_is_named_by_its_v6);
    RUN_TEST(an_unreadable_address_list_warns_once_and_starts);
    GREATEST_MAIN_END();
}
